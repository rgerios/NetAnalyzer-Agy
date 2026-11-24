import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import zlib from 'node:zlib';
import { GetObjectCommand, ListObjectsV2Command, type S3Client } from '@aws-sdk/client-s3';
import type { AwsSourceConfig } from '../shared/aws.ts';
import { applyAwsSave, AwsConfigError, detectAwsType, normalizeAwsConfig, toPublicAwsConfig } from '../server/awsConfig.ts';
import { createAwsIngestor } from '../server/awsIngest.ts';
import { parseAlbLogs, parseFlowLogs, parseWafLogs, tokenizeQuoted } from '../server/awsParsers.ts';
import { createAwsSampleDataset } from '../server/awsSampleData.ts';
import { describeAwsError, listNewObjects, normalizePrefix } from '../server/awsS3.ts';
import { buildBehaviorReport, remoteIpOf } from '../server/behaviorEngine.ts';
import { buildAccessReport } from '../server/accessReport.ts';
import type { FirewallSiteRecord, SyslogEvent } from '../server/types.ts';

const NOW = Date.parse('2026-11-23T15:00:00Z');
const sec = (iso: string) => Math.floor(Date.parse(iso) / 1000);

const FLOW_HEADER = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status';
const flowLine = (over: Partial<Record<string, string>> = {}) => {
  const f = {
    version: '2', acc: '123456789012', eni: 'eni-0abc', src: '10.0.1.25', dst: '142.250.219.14', sp: '51234', dp: '443',
    proto: '6', pk: '12', by: '4800', start: String(sec('2026-11-23T14:59:00Z')), end: String(sec('2026-11-23T14:59:59Z')),
    action: 'ACCEPT', status: 'OK', ...over,
  };
  return `${f.version} ${f.acc} ${f.eni} ${f.src} ${f.dst} ${f.sp} ${f.dp} ${f.proto} ${f.pk} ${f.by} ${f.start} ${f.end} ${f.action} ${f.status}`;
};

describe('VPC Flow Logs', () => {
  it('converte ACCEPT/REJECT, protocolo, portas e bytes', () => {
    const text = [FLOW_HEADER, flowLine(), flowLine({ src: '185.220.101.34', dst: '10.0.1.25', sp: '40000', dp: '22', action: 'REJECT', by: '40' })].join('\n');
    const { events, skipped } = parseFlowLogs(text, { nowMs: NOW });
    assert.equal(skipped, 0);
    assert.equal(events.length, 2);
    const [a, b] = events;
    assert.equal(a.action, 'allow');
    assert.equal(a.srcIp, '10.0.1.25');
    assert.equal(a.dstPort, 443);
    assert.equal(a.protocol, 'tcp');
    assert.equal(a.bytesSent, 4800);
    assert.equal(a.serialNumber, '123456789012');
    assert.equal(a.source, 's3');
    assert.equal(b.action, 'drop');
    assert.equal(b.dstPort, 22);
    assert.equal(b.srcIp, '185.220.101.34');
  });

  it('usa a hora real do fluxo; só eventos recentes entram como "agora"', () => {
    const old = flowLine({ start: String(sec('2026-11-23T08:00:00Z')) });
    const recent = flowLine({ start: String(sec('2026-11-23T14:55:00Z')) });
    const { events } = parseFlowLogs([FLOW_HEADER, old, recent].join('\n'), { nowMs: NOW });
    assert.equal(events[0].timestamp, '2026-11-23T08:00:00.000Z');
    assert.equal(events[0].ingestedAt, '2026-11-23T08:00:00.000Z');
    assert.equal(events[1].ingestedAt, new Date(NOW).toISOString());
  });

  it('ignora NODATA/SKIPDATA e linhas inválidas; respeita cabeçalho personalizado', () => {
    const custom =
      'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status pkt-srcaddr pkt-dstaddr flow-direction';
    const row = `${flowLine()} 203.0.113.9 10.0.1.25 ingress`;
    const nodata = '2 123456789012 eni-0abc - - - - - - - 1700000000 1700000060 - NODATA - - -';
    const { events, skipped } = parseFlowLogs([custom, row, nodata, 'lixo'].join('\n'), { nowMs: NOW });
    assert.equal(events.length, 1);
    assert.equal(skipped, 1);
    assert.equal(events[0].srcIp, '203.0.113.9'); // pkt-srcaddr tem prioridade (atrás de NAT)
    assert.equal(events[0].dstZone, 'ingress');
  });

  it('funciona sem cabeçalho (formato padrão v2) e com protocolos UDP/ICMP', () => {
    const { events } = parseFlowLogs([flowLine({ proto: '17', dp: '53' }), flowLine({ proto: '1', sp: '-', dp: '-' })].join('\n'), { nowMs: NOW });
    assert.equal(events[0].protocol, 'udp');
    assert.equal(events[1].protocol, 'icmp');
    assert.equal(events[1].dstPort, null);
  });
});

describe('AWS WAF', () => {
  const rec = (over: Record<string, unknown> = {}) =>
    JSON.stringify({
      timestamp: NOW - 60_000,
      webaclId: 'arn:aws:wafv2:sa-east-1:123456789012:regional/webacl/prod-acl/abc',
      terminatingRuleId: 'AWSManagedRulesSQLiRuleSet',
      terminatingRuleType: 'MANAGED_RULE_GROUP',
      action: 'BLOCK',
      httpSourceId: '123456789012-app/prod-alb/50dc',
      httpRequest: {
        clientIp: '45.155.205.91', country: 'RU', uri: '/login', args: 'q=1', httpMethod: 'POST',
        headers: [{ name: 'Host', value: 'app.rgerios.corp' }],
      },
      ...over,
    });

  it('mapeia BLOCK/ALLOW, regra, host e cliente', () => {
    const { events, skipped } = parseWafLogs([rec(), rec({ action: 'ALLOW', terminatingRuleId: 'Default_Action' }), '{quebrado'].join('\n'), { nowMs: NOW });
    assert.equal(skipped, 1);
    assert.equal(events.length, 2);
    assert.equal(events[0].action, 'deny');
    assert.equal(events[0].severity, 'warning');
    assert.equal(events[0].srcIp, '45.155.205.91');
    assert.equal(events[0].dstIp, 'app.rgerios.corp');
    assert.equal(events[0].ruleRef, 'AWSManagedRulesSQLiRuleSet');
    assert.match(events[0].message, /POST \/login\?q=1/);
    assert.equal(events[1].action, 'allow');
  });
});

describe('ALB', () => {
  const line =
    'https 2026-11-23T14:58:00.123456Z app/prod-alb/50dc6c495c0c9188 200.147.88.12:51234 10.0.1.11:8080 0.001 0.020 0.000 200 200 512 9000 ' +
    '"GET https://app.rgerios.corp:443/api/orders?x=1 HTTP/2.0" "Mozilla/5.0 (X11)" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 ' +
    'arn:aws:elasticloadbalancing:sa-east-1:123456789012:targetgroup/web/6d0e "Root=1-67891233-abc" "app.rgerios.corp" "arn:aws:acm:cert" 0 2026-11-23T14:58:00.100000Z "forward" "-" "-" "10.0.1.11:8080" "200" "-" "-"';

  it('separa campos entre aspas e extrai cliente, host, porta e bytes', () => {
    assert.equal(tokenizeQuoted('a "b c" d').join('|'), 'a|b c|d');
    const { events, skipped } = parseAlbLogs(line, { nowMs: NOW });
    assert.equal(skipped, 0);
    const e = events[0];
    assert.equal(e.srcIp, '200.147.88.12');
    assert.equal(e.srcPort, 51234);
    assert.equal(e.dstIp, 'app.rgerios.corp');
    assert.equal(e.dstPort, 443);
    assert.equal(e.bytesSent, 512);
    assert.equal(e.bytesRcvd, 9000);
    assert.equal(e.action, 'allow');
    assert.equal(e.meta?.path, '/api/orders');
    assert.match(e.message, /GET app\.rgerios\.corp\/api\/orders/);
  });

  it('5xx vira severidade de alerta; 403 do WAF vira bloqueio; lixo é ignorado', () => {
    const e500 = line.replace(' 200 200 512', ' 502 502 512');
    const waf403 = line.replace(' 200 200 512', ' 403 - 512').replace('"forward"', '"waf,forward"');
    const { events, skipped } = parseAlbLogs([e500, waf403, 'isso nao e alb'].join('\n'), { nowMs: NOW });
    assert.equal(skipped, 1);
    assert.equal(events[0].severity, 'warning');
    assert.equal(events[1].action, 'deny');
  });
});

describe('detecção de tipo e configuração', () => {
  it('detecta o tipo pelo conteúdo', () => {
    assert.equal(detectAwsType(`${FLOW_HEADER}\n${flowLine()}`), 'vpcflow');
    assert.equal(detectAwsType(flowLine()), 'vpcflow');
    assert.equal(detectAwsType('{"timestamp":1}'), 'waf');
    assert.equal(detectAwsType('https 2026-11-23T14:58:00.1Z app/x 1.2.3.4:1 -'), 'alb');
    assert.equal(detectAwsType('texto qualquer'), null);
  });

  it('valida, criptografa o secret e nunca o devolve na visão pública', () => {
    const base = normalizeAwsConfig(undefined);
    const saved = applyAwsSave(
      base,
      {
        region: 'sa-east-1',
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        pollSeconds: 90,
        sources: [{ type: 'vpcflow', name: 'Flow', bucket: 's3://meu-bucket-logs/qualquer', prefix: '/AWSLogs/123/vpcflowlogs/sa-east-1' }],
      },
      (p) => `enc(${p})`
    );
    assert.equal(saved.secretEncrypted?.startsWith('enc('), true);
    assert.equal(saved.sources[0].bucket, 'meu-bucket-logs');
    assert.equal(saved.sources[0].prefix, 'AWSLogs/123/vpcflowlogs/sa-east-1/');
    const pub = toPublicAwsConfig(saved);
    assert.equal(pub.hasSecret, true);
    assert.ok(!JSON.stringify(pub).includes('wJalr'));
    assert.ok(!JSON.stringify(pub).includes('enc('));

    // salvar de novo sem secret mantém o anterior
    const again = applyAwsSave(saved, { region: 'us-east-1' }, (p) => `enc(${p})`);
    assert.equal(again.secretEncrypted, saved.secretEncrypted);
  });

  it('rejeita entradas inválidas', () => {
    const base = normalizeAwsConfig(undefined);
    const enc = (p: string) => p;
    assert.throws(() => applyAwsSave(base, { region: 'brasil' }, enc), AwsConfigError);
    assert.throws(() => applyAwsSave(base, { accessKeyId: 'abc' }, enc), AwsConfigError);
    assert.throws(() => applyAwsSave(base, { roleArn: 'arn:aws:s3:::x' }, enc), AwsConfigError);
    assert.throws(() => applyAwsSave(base, { pollSeconds: 5 }, enc), AwsConfigError);
    assert.throws(() => applyAwsSave(base, { sources: [{ type: 'waf', bucket: '..' }] }, enc), AwsConfigError);
  });

  it('mudar bucket/prefixo reinicia o ponto de leitura; só editar o nome mantém', () => {
    const enc = (p: string) => p;
    let cfg = applyAwsSave(normalizeAwsConfig(undefined), { sources: [{ id: 'a', type: 'alb', bucket: 'bucket-x', prefix: 'p/' }] }, enc);
    cfg.sources[0].cursor = { lastModifiedMs: 5, recentKeys: ['k'] };
    cfg = applyAwsSave(cfg, { sources: [{ id: 'a', type: 'alb', bucket: 'bucket-x', prefix: 'p/', name: 'Novo nome' }] }, enc);
    assert.ok(cfg.sources[0].cursor);
    cfg = applyAwsSave(cfg, { sources: [{ id: 'a', type: 'alb', bucket: 'bucket-x', prefix: 'outro/' }] }, enc);
    assert.equal(cfg.sources[0].cursor, undefined);
  });

  it('normaliza prefixos e descreve erros comuns da AWS', () => {
    assert.equal(normalizePrefix('/a/b'), 'a/b/');
    assert.equal(normalizePrefix(''), '');
    assert.match(describeAwsError({ name: 'AccessDenied' }), /s3:ListBucket/);
    assert.match(describeAwsError({ name: 'NoSuchBucket' }), /Bucket não encontrado/);
    assert.match(describeAwsError({ name: 'PermanentRedirect' }), /região/);
  });
});

// ---------- S3 simulado ----------

interface FakeObject { key: string; lm: number; body: Buffer }

function fakeS3(objects: FakeObject[]): { client: S3Client; listed: string[] } {
  const listed: string[] = [];
  const client = {
    async send(cmd: unknown) {
      if (cmd instanceof ListObjectsV2Command) {
        const { Prefix, StartAfter } = cmd.input;
        listed.push(String(Prefix));
        const items = objects
          .filter((o) => o.key.startsWith(Prefix ?? '') && (!StartAfter || o.key > StartAfter))
          .sort((a, b) => a.key.localeCompare(b.key))
          .map((o) => ({ Key: o.key, LastModified: new Date(o.lm), Size: o.body.length }));
        return { Contents: items, IsTruncated: false };
      }
      if (cmd instanceof GetObjectCommand) {
        const o = objects.find((x) => x.key === cmd.input.Key);
        if (!o) throw Object.assign(new Error('nope'), { name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } });
        return { ContentLength: o.body.length, Body: { transformToByteArray: async () => new Uint8Array(o.body) } };
      }
      throw new Error('comando inesperado');
    },
  } as unknown as S3Client;
  return { client, listed };
}

function makeSite(sources: AwsSourceConfig[]): FirewallSiteRecord {
  return {
    id: 'aws-1', vendor: 'aws', name: 'Conta', syslogs: [],
    connection: { host: '', port: 443, protocol: 'https', username: '', ignoreTlsErrors: true, aws: { region: 'sa-east-1', accessKeyId: 'AKIAXXXXXXXXXXXXXXXX', secretEncrypted: 'enc', roleArn: '', externalId: '', pollSeconds: 60, sources } },
  } as unknown as FirewallSiteRecord;
}

const baseSource = (over: Partial<AwsSourceConfig> = {}): AwsSourceConfig => ({
  id: 's1', type: 'vpcflow', name: 'Flow', enabled: true, bucket: 'logs', prefix: 'AWSLogs/1/vpcflowlogs/sa-east-1/', region: 'sa-east-1',
  dateLayout: true, lookbackHours: 6, ...over,
});

describe('ingestão do S3 (cliente simulado)', () => {
  const gz = (text: string) => zlib.gzipSync(Buffer.from(text));
  const key = (day: string, name: string) => `AWSLogs/1/vpcflowlogs/sa-east-1/${day}/${name}.log.gz`;

  it('baixa só objetos novos, descompacta, converte e não repete na rodada seguinte', async () => {
    const objects: FakeObject[] = [
      { key: key('2026/11/23', 'a'), lm: NOW - 40 * 60_000, body: gz([FLOW_HEADER, flowLine(), flowLine({ dp: '80' })].join('\n')) },
      { key: key('2026/11/23', 'b'), lm: NOW - 20 * 60_000, body: gz([FLOW_HEADER, flowLine({ dp: '53', proto: '17' })].join('\n')) },
      { key: key('2026/11/22', 'velho'), lm: NOW - 30 * 3_600_000, body: gz([FLOW_HEADER, flowLine()].join('\n')) },
      { key: 'outro/prefixo/x.log.gz', lm: NOW - 10 * 60_000, body: gz('xx') },
    ];
    const { client, listed } = fakeS3(objects);
    const site = makeSite([baseSource()]);
    const appended: SyslogEvent[][] = [];
    const ing = createAwsIngestor({
      decryptSecret: () => 'secret',
      append: (_s, ev) => { appended.push(ev); return ev.length; },
      persist: () => undefined,
      log: { info: () => undefined, error: () => undefined },
      makeClient: () => client,
    });
    const src = site.connection.aws!.sources[0];

    const r1 = await ing.syncSource(site, src, { nowMs: NOW });
    assert.equal(r1.files, 2); // o de 30 h atrás está fora da janela inicial de 6 h
    assert.equal(r1.events, 3);
    assert.equal(appended.flat().length, 3);
    assert.ok(listed.some((p) => p.endsWith('/2026/11/23/')));
    assert.equal(src.status?.filesRead, 2);
    assert.equal(src.status?.lastError, null);
    assert.equal(src.cursor?.lastModifiedMs, NOW - 20 * 60_000);

    const r2 = await ing.syncSource(site, src, { nowMs: NOW + 60_000 });
    assert.equal(r2.files, 0); // nada novo: sem duplicar
    assert.equal(appended.flat().length, 3);

    // chega um arquivo novo
    objects.push({ key: key('2026/11/23', 'c'), lm: NOW + 30_000, body: gz([FLOW_HEADER, flowLine({ dp: '22', action: 'REJECT' })].join('\n')) });
    const r3 = await ing.syncSource(site, src, { nowMs: NOW + 120_000 });
    assert.equal(r3.files, 1);
    assert.equal(r3.events, 1);
    assert.equal(appended.flat().at(-1)?.action, 'drop');
  });

  it('em falha de acesso grava o erro na fonte, sem perder o ponto de leitura', async () => {
    const client = {
      async send() {
        throw Object.assign(new Error('denied'), { name: 'AccessDenied', $metadata: { httpStatusCode: 403 } });
      },
    } as unknown as S3Client;
    const site = makeSite([baseSource()]);
    const ing = createAwsIngestor({
      decryptSecret: () => 'secret',
      append: () => 0,
      persist: () => undefined,
      log: { info: () => undefined, error: () => undefined },
      makeClient: () => client,
    });
    const src = site.connection.aws!.sources[0];
    await assert.rejects(() => ing.syncSource(site, src, { nowMs: NOW }), /Acesso negado/);
    assert.match(src.status?.lastError ?? '', /Acesso negado/);
    assert.equal(src.status?.running, false);
  });

  it('modo sem partição por data usa a última chave', async () => {
    const objects: FakeObject[] = [
      { key: 'flat/001.log', lm: NOW - 60_000, body: Buffer.from([FLOW_HEADER, flowLine()].join('\n')) },
      { key: 'flat/002.log', lm: NOW - 30_000, body: Buffer.from([FLOW_HEADER, flowLine({ dp: '80' })].join('\n')) },
    ];
    const { client } = fakeS3(objects);
    const src = baseSource({ prefix: 'flat/', dateLayout: false });
    const site = makeSite([src]);
    let total = 0;
    const ing = createAwsIngestor({
      decryptSecret: () => 's', append: (_s, ev) => { total += ev.length; return ev.length; }, persist: () => undefined,
      log: { info: () => undefined, error: () => undefined }, makeClient: () => client,
    });
    await ing.syncSource(site, src, { nowMs: NOW });
    assert.equal(total, 2);
    assert.equal(src.cursor?.lastKey, 'flat/002.log');
    const again = await listNewObjects(client, src, NOW + 1000, 10);
    assert.equal(again.objects.length, 0);
  });

  it('dueSources respeita o intervalo e as fontes desativadas', () => {
    const site = makeSite([
      baseSource({ id: 'a' }),
      baseSource({ id: 'b', enabled: false }),
      baseSource({ id: 'c', status: { running: false, lastRunAt: new Date(NOW - 10_000).toISOString(), lastOkAt: null, lastError: null, filesRead: 0, eventsRead: 0, bytesRead: 0, lastObjectAt: null, pendingFiles: 0 } }),
    ]);
    const ing = createAwsIngestor({ decryptSecret: () => 's', append: () => 0, persist: () => undefined, log: { info: () => undefined, error: () => undefined } });
    assert.deepEqual(ing.dueSources(site, NOW).map((s) => s.id), ['a']);
  });
});

describe('Behavior e acessos de entrada (AWS)', () => {
  const ev = (over: Partial<SyslogEvent>): SyslogEvent => ({ srcIp: '45.155.205.91', dstIp: 'app.rgerios.corp', action: 'deny', bytesSent: 10, bytesRcvd: 20, ingestedAt: new Date(NOW).toISOString(), timestamp: new Date(NOW).toISOString(), ...over } as SyslogEvent);

  it('remoteIpOf: destino público tem prioridade; entrada só com inbound', () => {
    assert.deepEqual(remoteIpOf(ev({ dstIp: '8.8.8.8', srcIp: '10.0.0.5' }), false), { ip: '8.8.8.8', peer: '10.0.0.5' });
    assert.equal(remoteIpOf(ev({}), false), null);
    assert.deepEqual(remoteIpOf(ev({}), true), { ip: '45.155.205.91', peer: 'app.rgerios.corp' });
    assert.equal(remoteIpOf(ev({ srcIp: '10.0.0.9' }), true), null);
  });

  it('o mapa conta o cliente público como remoto no modo entrada e ignora no modo normal', () => {
    const intel = { lookup: (ip: string) => ({ country: ip.startsWith('45.') ? 'RU' : null, asn: null, asnOrg: null, threats: [] }), status: () => ({}) } as never;
    const origin = { country: 'BR', ip: null, source: 'region' as const };
    const events = [ev({}), ev({}), ev({ srcIp: '200.1.1.1' })];
    const inbound = buildBehaviorReport({ events, minutes: 60, intel, origin, dataSource: 'memory', truncated: false, inbound: true });
    assert.equal(inbound.totals.connections, 3);
    assert.equal(inbound.countries[0].code, 'RU');
    assert.equal(inbound.countries[0].connections, 2);
    const normal = buildBehaviorReport({ events, minutes: 60, intel, origin, dataSource: 'memory', truncated: false });
    assert.equal(normal.totals.connections, 0);
  });

  it('o relatório de acessos agrupa países pelo cliente quando é entrada', () => {
    const intel = { lookup: (ip: string) => ({ country: ip.startsWith('45.') ? 'RU' : null, asn: null, asnOrg: null, threats: [] }) } as never;
    const agg = {
      groups: [{ src: '45.155.205.91', dst: 'app.rgerios.corp', proto: 'tcp', port: '443', app: '', blocked: true, c: 5, up: 100, down: 900 }],
      hours: [], totalEvents: 5, timedOut: false,
    };
    const common = { agg, vendor: 'aws' as const, minutes: 60, sinceIso: null, dataSource: 'memory' as const, intel };
    assert.equal(buildAccessReport({ ...common, inbound: true }).countries[0]?.code, 'RU');
    assert.equal(buildAccessReport(common).countries.length, 0);
  });
});

describe('amostra do ambiente AWS', () => {
  it('gera os três tipos de log pelos parsers reais, com varreduras bloqueadas e fontes de exemplo', () => {
    const { events, sources } = createAwsSampleDataset(NOW);
    assert.ok(events.length > 800);
    const cats = new Set(events.map((e) => e.categoryName));
    assert.ok(cats.has('VPC Flow Logs') && cats.has('AWS WAF') && cats.has('Application Load Balancer'));
    assert.ok(events.some((e) => e.action === 'drop' && e.dstPort === 22));
    assert.ok(events.some((e) => e.action === 'deny' && e.categoryName === 'AWS WAF'));
    assert.ok(events.every((e) => e.source === 'sample'));
    assert.equal(sources.length, 3);
    // ordem cronológica (a ingestão espera o mais antigo primeiro)
    for (let i = 1; i < events.length; i += 1) assert.ok(events[i].timestamp >= events[i - 1].timestamp);
  });
});

describe('categorias não disparam alertas indevidos', () => {
  it('ALB e WAF liberado não usam os códigos de IPS (512) nem de antivírus (2048)', () => {
    const { events } = createAwsSampleDataset(NOW);
    const alb = events.filter((e) => e.categoryName === 'Application Load Balancer');
    assert.ok(alb.length > 0 && alb.every((e) => e.categoryCode === '1024'));
    const wafAllowed = events.filter((e) => e.categoryName === 'AWS WAF' && e.action === 'allow');
    assert.ok(wafAllowed.length > 0 && wafAllowed.every((e) => e.categoryCode === '1024'));
    const wafBlocked = events.filter((e) => e.categoryName === 'AWS WAF' && e.action === 'deny');
    assert.ok(wafBlocked.every((e) => e.categoryCode === '512'));
    assert.ok(events.every((e) => e.categoryCode !== '2048'));
  });
});
