import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DescribeLogStreamsCommand, FilterLogEventsCommand, type CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import type { AwsSourceConfig } from '../shared/aws.ts';
import { applyAwsSave, AwsConfigError, detectAwsType, normalizeAwsConfig } from '../server/awsConfig.ts';
import { testCloudWatchSource } from '../server/awsCloudWatch.ts';
import { createAwsIngestor } from '../server/awsIngest.ts';
import { parseAlbLogs, pathGroupOf, uaFamilyOf } from '../server/awsParsers.ts';
import { buildHttpInsights, rowsFromAlbEvents } from '../server/httpInsights.ts';
import type { FirewallSiteRecord, SyslogEvent } from '../server/types.ts';

const NOW = Date.parse('2026-11-24T11:10:00Z');

/** Evento real do CloudWatch (access log do ALB em JSON). */
const REAL = {
  request_line: 'POST https://vendas.rgerios.corp:8050/app/Services/MobileService.svc/EnviarImagem HTTP/1.1',
  user_agent: 'okhttp/5.3.2',
  trace_id: 'Root=1-67000000-000000000000000000000002',
  domain_name: 'vendas.rgerios.corp',
  chosen_cert_arn: 'arn:aws:acm:sa-east-1:111122223333:certificate/00000000-0000-4000-8000-000000000000',
  actions_executed: 'waf,forward',
  redirect_url: '-',
  error_reason: '-',
  target_port_list: '10.20.0.11:443',
  target_status_code_list: '200',
  classification: '-',
  classification_reason: '-',
  transformed_host: '-',
  transformed_uri: '-',
  request_transform_status: '-',
  type: 'https',
  time: '2026-11-24T11:04:52.317513Z',
  elb: 'app/alb-demo/0123456789abcdef',
  client_port: '203.0.113.25:64002',
  target_port: '10.20.0.11:443',
  request_processing_time: '0.102',
  target_processing_time: '2.013',
  response_processing_time: '0.000',
  elb_status_code: '200',
  target_status_code: '200',
  received_bytes: '1166508',
  sent_bytes: '988',
  ssl_cipher: 'TLS_AES_128_GCM_SHA256',
  ssl_protocol: 'TLSv1.3',
  target_group_arn: 'arn:aws:elasticloadbalancing:sa-east-1:111122223333:targetgroup/TG-vendas/aaaaaaaaaaaaaaaa',
  matched_rule_priority: '0',
  request_creation_time: '2026-11-24T11:04:50.202000Z',
  conn_trace_id: 'TID_00000000000000000000000000000001',
  ip_address: '192.0.2.27',
};
const line = (over: Record<string, string> = {}) => JSON.stringify({ ...REAL, ...over });

describe('ALB em JSON (CloudWatch): extração máxima', () => {
  it('extrai cliente, listener, host, método, caminho, bytes, latência, TLS, WAF e target', () => {
    const { events, skipped } = parseAlbLogs(line(), { nowMs: NOW });
    assert.equal(skipped, 0);
    const e = events[0];
    assert.equal(e.srcIp, '203.0.113.25');
    assert.equal(e.srcPort, 64002);
    assert.equal(e.dstIp, 'vendas.rgerios.corp');
    assert.equal(e.dstPort, 8050); // porta do listener, vinda da URL
    assert.equal(e.bytesSent, 1166508); // o cliente enviou (upload)
    assert.equal(e.bytesRcvd, 988);
    assert.equal(e.action, 'allow'); // waf,forward: avaliado e encaminhado
    assert.equal(e.dstZone, '10.20.0.11'); // target
    assert.equal(e.firewallHost, 'alb-demo');
    assert.equal(e.appName, null); // o endpoint fica em meta e na mensagem
    assert.match(e.message, /ALB 200 POST vendas\.rgerios\.corp\/app/);
    assert.equal(e.timestamp, '2026-11-24T11:04:52.317Z');

    const m = e.meta!;
    assert.equal(m.method, 'POST');
    assert.equal(m.host, 'vendas.rgerios.corp');
    assert.equal(m.path, '/app/Services/MobileService.svc/EnviarImagem');
    assert.equal(m.status, 200);
    assert.equal(m.targetStatus, '200');
    assert.equal(m.userAgent, 'okhttp/5.3.2');
    assert.equal(m.uaFamily, 'okhttp (app Android)');
    assert.equal(m.tlsVersion, 'TLSv1.3');
    assert.equal(m.tlsCipher, 'TLS_AES_128_GCM_SHA256');
    assert.equal(m.wafActions, 'waf,forward');
    assert.equal(m.targetIp, '10.20.0.11');
    assert.equal(m.targetPort, 443);
    assert.equal(m.targetGroup, 'TG-vendas');
    assert.equal(m.nodeIp, '192.0.2.27');
    assert.equal(m.reqTime, 0.102);
    assert.equal(m.targetTime, 2.013);
    assert.equal(m.totalTime, 2.115);
    assert.equal(m.traceId, 'Root=1-67000000-000000000000000000000002');
    assert.equal(m.connTraceId, 'TID_00000000000000000000000000000001');
    assert.equal(m.rulePriority, '0');
    assert.equal(m.elb, 'app/alb-demo/0123456789abcdef');
    assert.ok(!('errorReason' in m) && !('redirectUrl' in m)); // "-" não vira campo
  });

  it('o mesmo pedido em texto (S3) e em JSON (CloudWatch) dá os mesmos dados', () => {
    const text =
      'https 2026-11-24T11:04:52.317513Z app/alb-demo/0123456789abcdef 203.0.113.25:64002 10.20.0.11:443 0.102 2.013 0.000 200 200 1166508 988 ' +
      '"POST https://vendas.rgerios.corp:8050/app/Services/MobileService.svc/EnviarImagem HTTP/1.1" "okhttp/5.3.2" TLS_AES_128_GCM_SHA256 TLSv1.3 ' +
      'arn:aws:elasticloadbalancing:sa-east-1:111122223333:targetgroup/TG-vendas/aaaaaaaaaaaaaaaa "Root=1-67000000-000000000000000000000002" "vendas.rgerios.corp" ' +
      '"arn:aws:acm:sa-east-1:111122223333:certificate/b177" 0 2026-11-24T11:04:50.202000Z "waf,forward" "-" "-" "10.20.0.11:443" "200" "-" "-"';
    const a = parseAlbLogs(text, { nowMs: NOW }).events[0];
    const b = parseAlbLogs(line(), { nowMs: NOW }).events[0];
    for (const k of ['srcIp', 'srcPort', 'dstIp', 'dstPort', 'bytesSent', 'bytesRcvd', 'action', 'dstZone'] as const) {
      assert.equal(a[k], b[k], k);
    }
    for (const k of ['method', 'host', 'path', 'status', 'uaFamily', 'tlsVersion', 'wafActions', 'targetIp', 'targetGroup', 'totalTime']) {
      assert.equal(a.meta![k], b.meta![k], k);
    }
  });

  it('bloqueio do WAF, erro 5xx, requisição lenta e linha inválida', () => {
    const blocked = parseAlbLogs(line({ actions_executed: 'waf', elb_status_code: '403', target_status_code: '-', target_port: '-', target_port_list: '-' }), { nowMs: NOW }).events[0];
    assert.equal(blocked.action, 'deny');
    assert.equal(blocked.severity, 'notice');
    assert.equal(blocked.meta!.targetIp, undefined);
    const e502 = parseAlbLogs(line({ elb_status_code: '502', target_status_code: '-', error_reason: 'TargetConnectionError' }), { nowMs: NOW }).events[0];
    assert.equal(e502.severity, 'warning');
    assert.equal(e502.meta!.errorReason, 'TargetConnectionError');
    const slow = parseAlbLogs(line({ target_processing_time: '12.5' }), { nowMs: NOW }).events[0];
    assert.equal(slow.severity, 'notice');
    const skipped: string[] = [];
    const r = parseAlbLogs('{"type":"https","sem":"horario"}\n{quebrado', { nowMs: NOW, onSkip: (l) => skipped.push(l) });
    assert.equal(r.events.length, 0);
    assert.equal(skipped.length, 2);
  });

  it('detecta o JSON do ALB (e não confunde com o WAF)', () => {
    assert.equal(detectAwsType(line()), 'alb');
    assert.equal(detectAwsType('{"timestamp":1,"httpRequest":{"clientIp":"1.1.1.1"}}'), 'waf');
  });

  it('agrupa caminhos com ids e identifica navegadores, apps e ferramentas', () => {
    assert.equal(pathGroupOf('/api/orders/12345/items/9'), '/api/orders/{id}/items/{id}');
    assert.equal(pathGroupOf('/f/3f2504e0-4f89-11d3-9a0c-0305e82c3301'), '/f/{uuid}');
    assert.equal(pathGroupOf('/t/abcdef0123456789abcdef'), '/t/{hash}');
    assert.equal(pathGroupOf('/app/Services/MobileService.svc'), '/app/Services/MobileService.svc');
    assert.equal(uaFamilyOf('okhttp/5.3.2'), 'okhttp (app Android)');
    assert.equal(uaFamilyOf('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'), 'Chrome');
    assert.equal(uaFamilyOf('Mozilla/5.0 (Windows) Chrome/120 Safari/537 Edg/120'), 'Edge');
    assert.equal(uaFamilyOf('MyApp/3.1 CFNetwork/1494 Darwin/23'), 'App iOS (CFNetwork)');
    assert.equal(uaFamilyOf('Googlebot/2.1 (+http://www.google.com/bot.html)'), 'Robô / crawler');
    assert.equal(uaFamilyOf('python-requests/2.31'), 'Python');
    assert.equal(uaFamilyOf('-'), 'Desconhecido'.length ? uaFamilyOf('-') : '');
    assert.equal(uaFamilyOf(''), 'Desconhecido');
  });
});

describe('análise de aplicação (ALB)', () => {
  const events: SyslogEvent[] = [];
  const add = (over: Record<string, string>, n: number) => {
    for (let i = 0; i < n; i += 1) events.push(...parseAlbLogs(line(over), { nowMs: NOW }).events);
  };
  add({}, 10);
  add({ request_line: 'GET https://vendas.rgerios.corp:8050/api/pedidos/777 HTTP/1.1', received_bytes: '300', sent_bytes: '5000', target_processing_time: '0.05', user_agent: 'Mozilla/5.0 Chrome/120 Safari/537' }, 20);
  add({ request_line: 'GET https://vendas.rgerios.corp:8050/api/pedidos/888 HTTP/1.1', elb_status_code: '500', target_status_code: '500', target_processing_time: '4', user_agent: 'Mozilla/5.0 Chrome/120 Safari/537', target_port: '192.168.0.138:443' }, 5);
  add({ elb_status_code: '403', actions_executed: 'waf', target_port: '-', target_port_list: '-', ssl_protocol: 'TLSv1.2' }, 3);

  it('agrega status, latência, endpoints (ids agrupados), WAF, navegadores, TLS e targets', () => {
    const ins = buildHttpInsights({ ...rowsFromAlbEvents(events), minutes: 60, dataSource: 'memory', truncated: false });
    assert.equal(ins.requests, 38);
    assert.equal(ins.status.s2xx, 30);
    assert.equal(ins.status.s4xx, 3);
    assert.equal(ins.status.s5xx, 5);
    assert.equal(ins.status.top[0].code, '200');
    // /api/pedidos/777 e /888 viram um endpoint só
    const pedidos = ins.endpoints.find((e) => e.path === '/api/pedidos/{id}');
    assert.equal(pedidos?.requests, 25);
    assert.equal(pedidos?.errors5xx, 5);
    // o mais lento por média é o upload de imagem (≈2,1 s); depois o endpoint que também teve erros de 4 s
    assert.match(ins.slowest[0].path, /EnviarImagem/);
    assert.ok(Math.abs(ins.slowest[0].avgMs - 2115) <= 1);
    assert.equal(ins.slowest[1].path, '/api/pedidos/{id}');
    assert.ok(ins.slowest[1].avgMs >= 800);
    // o mais pesado em bytes é o upload (≈1,1 MB × 13)
    assert.match(ins.heaviest[0].path, /EnviarImagem/);
    assert.equal(ins.heaviest[0].bytesIn, 13 * 1166508);
    assert.equal(ins.waf.evaluated, 38);
    assert.equal(ins.waf.blocked, 3);
    assert.equal(ins.waf.forwarded, 35);
    assert.equal(ins.latency.maxMs, 4102);
    assert.ok(ins.latency.slow >= 5 + 13);
    assert.equal(ins.userAgents[0].name, 'Chrome');
    assert.equal(ins.userAgents.find((u) => u.name === 'Chrome')?.errors, 5);
    assert.deepEqual(ins.tls.map((t) => t.version), ['TLSv1.3', 'TLSv1.2']);
    assert.equal(ins.targets.length, 2);
    assert.equal(ins.targets.find((t) => t.ip === '192.168.0.138')?.errors5xx, 5);
    assert.equal(ins.hosts[0].host, 'vendas.rgerios.corp');
    assert.equal(ins.errors[0].errors5xx, 5);
  });

  it('ignora eventos que não são do ALB', () => {
    const ins = buildHttpInsights({ ...rowsFromAlbEvents([{ srcIp: '1.1.1.1', action: 'allow' } as SyslogEvent]), minutes: 60, dataSource: 'memory', truncated: false });
    assert.equal(ins.requests, 0);
    assert.equal(ins.endpoints.length, 0);
  });
});

// ---------- CloudWatch simulado ----------

interface Page { events: Array<{ eventId: string; timestamp: number; message: string; logStreamName: string }> }

function fakeLogs(pages: () => Page[], streams: string[] = []): { client: CloudWatchLogsClient; calls: Array<Record<string, unknown>> } {
  const calls: Array<Record<string, unknown>> = [];
  const client = {
    async send(cmd: unknown) {
      if (cmd instanceof FilterLogEventsCommand) {
        calls.push(cmd.input as Record<string, unknown>);
        const all = pages();
        const idx = cmd.input.nextToken ? Number(cmd.input.nextToken) : 0;
        const prefix = cmd.input.logStreamNamePrefix;
        const events = all[idx].events.filter(
          (e) => (!prefix || e.logStreamName.startsWith(prefix)) && e.timestamp >= (cmd.input.startTime ?? 0)
        );
        return { events, nextToken: idx + 1 < all.length ? String(idx + 1) : undefined };
      }
      if (cmd instanceof DescribeLogStreamsCommand) return { logStreams: streams.map((s) => ({ logStreamName: s })) };
      throw new Error('comando inesperado');
    },
  } as unknown as CloudWatchLogsClient;
  return { client, calls };
}

const cwSource = (over: Partial<AwsSourceConfig> = {}): AwsSourceConfig => ({
  id: 'cw1', type: 'alb', name: 'ALB (CloudWatch)', enabled: true, kind: 'cloudwatch', logGroup: 'Logs_ALB-Apps', streamPrefix: 'ALB_Access_Logs/',
  bucket: '', prefix: '', region: 'sa-east-1', dateLayout: false, lookbackHours: 6, ...over,
});

function cwSite(sources: AwsSourceConfig[]): FirewallSiteRecord {
  return {
    id: 'aws-1', vendor: 'aws', name: 'Conta', syslogs: [],
    connection: { host: '', port: 443, protocol: 'https', username: '', ignoreTlsErrors: true, aws: { region: 'sa-east-1', accessKeyId: 'AKIAXXXXXXXXXXXXXXXX', secretEncrypted: 'enc', roleArn: '', externalId: '', pollSeconds: 60, sources } },
  } as unknown as FirewallSiteRecord;
}

describe('leitura do CloudWatch Logs', () => {
  const ev = (id: string, tsIso: string, stream: string, over: Record<string, string> = {}) => ({
    eventId: id, timestamp: Date.parse(tsIso), logStreamName: stream, message: line({ time: tsIso, ...over }),
  });
  const ACCESS = 'ALB_Access_Logs/app/alb-demo/0123456789abcdef';
  const CONN = 'ALB_Connection_Logs/app/alb-demo/0123456789abcdef';

  it('lê só o stream de access logs, em várias páginas, e não repete na rodada seguinte', async () => {
    const data: Page[] = [
      { events: [ev('e1', '2026-11-24T11:05:00.000Z', ACCESS), ev('e2', '2026-11-24T11:05:01.000Z', ACCESS), ev('x1', '2026-11-24T11:05:01.500Z', CONN)] },
      { events: [ev('e3', '2026-11-24T11:06:00.000Z', ACCESS)] },
    ];
    const { client, calls } = fakeLogs(() => data);
    const appended: SyslogEvent[] = [];
    const site = cwSite([cwSource()]);
    const ing = createAwsIngestor({
      decryptSecret: () => 's', append: (_s, e) => { appended.push(...e); return e.length; }, persist: () => undefined,
      log: { info: () => undefined, error: () => undefined }, makeLogsClient: () => client,
    });
    const src = site.connection.aws!.sources[0];

    const r1 = await ing.syncSource(site, src, { nowMs: NOW });
    assert.equal(r1.events, 3); // o stream de conexão foi filtrado pelo prefixo
    assert.equal(r1.files, 2); // páginas
    assert.equal(calls[0].logGroupName, 'Logs_ALB-Apps');
    assert.equal(calls[0].logStreamNamePrefix, 'ALB_Access_Logs/');
    assert.ok(appended.every((e) => e.source === 'cloudwatch' && e.meta?.method === 'POST'));
    assert.equal(src.cursor?.lastModifiedMs, Date.parse('2026-11-24T11:06:00.000Z'));
    assert.equal(src.status?.lastError, null);

    // mesma resposta de novo (a folga de tempo reenvia os eventos recentes): nada é duplicado
    const r2 = await ing.syncSource(site, src, { nowMs: NOW + 60_000 });
    assert.equal(r2.events, 0);
    assert.equal(appended.length, 3);

    // chega um evento novo
    data[1].events.push(ev('e4', '2026-11-24T11:07:00.000Z', ACCESS, { elb_status_code: '502' }));
    const r3 = await ing.syncSource(site, src, { nowMs: NOW + 120_000 });
    assert.equal(r3.events, 1);
    assert.equal(appended.at(-1)?.meta?.status, 502);
  });

  it('erros de acesso viram mensagem clara na fonte', async () => {
    const client = {
      async send() {
        throw Object.assign(new Error('x'), { name: 'ResourceNotFoundException', $metadata: { httpStatusCode: 400 } });
      },
    } as unknown as CloudWatchLogsClient;
    const site = cwSite([cwSource()]);
    const ing = createAwsIngestor({ decryptSecret: () => 's', append: () => 0, persist: () => undefined, log: { info: () => undefined, error: () => undefined }, makeLogsClient: () => client });
    const src = site.connection.aws!.sources[0];
    await assert.rejects(() => ing.syncSource(site, src, { nowMs: NOW }), /Log group não encontrado/);
    assert.match(src.status?.lastError ?? '', /Log group não encontrado/);
  });

  it('o teste da fonte reconhece o formato; sem eventos mostra os streams existentes', async () => {
    const ok = fakeLogs(() => [{ events: [ev('e1', '2026-11-24T11:05:00.000Z', ACCESS)] }]);
    const good = await testCloudWatchSource(ok.client, cwSource());
    assert.equal(good.ok, true);
    assert.equal(good.sampleEvents, 1);
    assert.deepEqual(good.sampleKeys, [ACCESS]);

    const empty = fakeLogs(() => [{ events: [] }], [CONN, ACCESS]);
    const none = await testCloudWatchSource(empty.client, cwSource({ streamPrefix: 'errado/' }));
    assert.equal(none.ok, false);
    assert.match(none.message, /prefixo/);
    assert.deepEqual(none.sampleKeys, [CONN, ACCESS]);

    const wrongType = await testCloudWatchSource(ok.client, cwSource({ type: 'vpcflow' }));
    assert.equal(wrongType.ok, false);
  });

  it('configuração: fonte CloudWatch dispensa bucket, valida o log group e reinicia o cursor ao mudar o prefixo', () => {
    const enc = (p: string) => p;
    let cfg = applyAwsSave(normalizeAwsConfig(undefined), { sources: [{ id: 'c', type: 'alb', kind: 'cloudwatch', logGroup: 'Logs_ALB-Apps', streamPrefix: 'ALB_Access_Logs/' }] }, enc);
    const s = cfg.sources[0];
    assert.equal(s.kind, 'cloudwatch');
    assert.equal(s.bucket, '');
    assert.equal(s.logGroup, 'Logs_ALB-Apps');
    assert.equal(s.dateLayout, false);
    s.cursor = { lastModifiedMs: 5, recentKeys: ['a'] };
    cfg = applyAwsSave(cfg, { sources: [{ id: 'c', type: 'alb', kind: 'cloudwatch', logGroup: 'Logs_ALB-Apps', streamPrefix: 'ALB_Access_Logs/', name: 'Outro nome' }] }, enc);
    assert.ok(cfg.sources[0].cursor);
    cfg = applyAwsSave(cfg, { sources: [{ id: 'c', type: 'alb', kind: 'cloudwatch', logGroup: 'Logs_ALB-Apps', streamPrefix: 'ALB_Connection_Logs/' }] }, enc);
    assert.equal(cfg.sources[0].cursor, undefined);
    assert.throws(() => applyAwsSave(cfg, { sources: [{ type: 'alb', kind: 'cloudwatch', logGroup: 'grupo com espaço' }] }, enc), AwsConfigError);
    assert.throws(() => applyAwsSave(cfg, { sources: [{ type: 'alb', kind: 'cloudwatch' }] }, enc), AwsConfigError);
  });
});

describe('Análise do ALB ignora eventos do WAF', () => {
  it('requisições do WAF (mesmos campos method/host) não entram nos endpoints do ALB', async () => {
    const { parseWafLogs } = await import('../server/awsParsers.ts');
    const waf = parseWafLogs(
      JSON.stringify({ timestamp: NOW - 1000, action: 'ALLOW', terminatingRuleId: 'R', httpRequest: { clientIp: '1.2.3.4', country: 'US', uri: '/x', httpMethod: 'POST', host: 'a.example.com' } }),
      { nowMs: NOW }
    ).events;
    const alb = parseAlbLogs(line(), { nowMs: NOW }).events;
    const rows = rowsFromAlbEvents([...waf, ...alb]);
    const ins = buildHttpInsights({ ...rows, minutes: 60, dataSource: 'memory', truncated: false });
    assert.equal(ins.requests, 1);
    assert.equal(ins.endpoints.every((e) => e.host !== 'a.example.com'), true);
  });
});
