import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { facetsFromEvents, summarizeCategories, facetSql } from '../server/facets.ts';
import { parseFlowLogs } from '../server/awsParsers.ts';

const HEADER = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status';
const row = (src: string, dp: string, action: string, bytes: number) =>
  `2 123456789012 eni-0abc ${src} 10.0.1.25 40000 ${dp} 6 10 ${bytes} 1795500000 1795500060 ${action} OK`;

describe('Facetas AWS', () => {
  const { events } = parseFlowLogs(
    [HEADER, row('185.220.101.34', '22', 'REJECT', 40), row('185.220.101.34', '3389', 'REJECT', 40), row('8.8.8.8', '443', 'ACCEPT', 5000)].join('\n'),
    { nowMs: 1795500100_000 }
  );
  it('agrega rejeitados e volume por origem', () => {
    const r = facetsFromEvents(events, 'vpcflow');
    assert.equal(r.totals.events, 3);
    assert.equal(r.totals.blocked, 2);
    const rej = r.facets.find((f) => f.id === 'rejSrc')!;
    assert.deepEqual(rej.items.map((i) => [i.key, i.count]), [['185.220.101.34', 2]]);
    const ports = r.facets.find((f) => f.id === 'rejPorts')!;
    assert.equal(ports.items.length, 2);
    const vol = r.facets.find((f) => f.id === 'topSrcBytes')!;
    assert.equal(vol.items[0].key, '8.8.8.8');
  });
  it('resume por recurso', () => {
    const s = summarizeCategories(events);
    assert.equal(s[0].category, 'VPC Flow Logs');
    assert.equal(s[0].blocked, 2);
  });
  it('rejeita campo de faceta inseguro', () => {
    assert.throws(() => facetSql("meta:x'; drop" as never));
  });
});

import { parseWafLogs, pathGroupOf } from '../server/awsParsers.ts';
describe('WAF real (ALB)', () => {
  it('agrupa URI codificada e extrai JA4', () => {
    assert.equal(
      pathGroupOf('/coletas/2026-11-24%2F6f0b52f2-c2ec-42a6-a20c-0e03b22c4ff2%2FReposicao%2Ffoto_fa776fdfe2c840dcb668ce2464f470f4.jpg'),
      '/coletas/{data}/{uuid}/Reposicao/{arquivo}.jpg'
    );
    const rec = { timestamp: 1795531290208, action: 'ALLOW', terminatingRuleId: 'AllowCorpHosts', ja4Fingerprint: 't13d1713h1_x', httpRequest: { clientIp: '203.0.113.28', country: 'US', uri: '/a', httpMethod: 'GET', scheme: 'https' } };
    const { events } = parseWafLogs(JSON.stringify(rec), { nowMs: 1795531300000 });
    assert.equal(events[0].meta?.ja4, 't13d1713h1_x');
    assert.equal(events[0].meta?.scheme, 'https');
  });
});

import { DescribeLogGroupsCommand, DescribeLogStreamsCommand, type CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { listLogGroups, listStreamPrefixes } from '../server/awsCloudWatch.ts';
describe('Descoberta CloudWatch', () => {
  const client = {
    send: async (cmd: unknown) => {
      if (cmd instanceof DescribeLogGroupsCommand) {
        return { logGroups: [{ logGroupName: 'Logs_ALB-Apps', storedBytes: 10, retentionInDays: 30 }, { logGroupName: '/aws/waf/x' }] };
      }
      if (cmd instanceof DescribeLogStreamsCommand) {
        return {
          logStreams: [
            { logStreamName: 'ALB_Access_Logs/a', lastEventTimestamp: 2000 },
            { logStreamName: 'ALB_Access_Logs/b', lastEventTimestamp: 3000 },
            { logStreamName: 'eni-0abc-all', lastEventTimestamp: 1000 },
          ],
        };
      }
      return {};
    },
  } as unknown as CloudWatchLogsClient;
  it('lista e filtra log groups', async () => {
    assert.deepEqual((await listLogGroups(client)).map((g) => g.name), ['/aws/waf/x', 'Logs_ALB-Apps']);
    assert.deepEqual((await listLogGroups(client, 'alb')).map((g) => g.name), ['Logs_ALB-Apps']);
  });
  it('agrupa streams por prefixo', async () => {
    const p = await listStreamPrefixes(client, 'Logs_ALB-Apps');
    assert.deepEqual(p.map((x) => [x.prefix, x.streams]), [['ALB_Access_Logs/', 2], ['eni-0abc-all', 1]]);
  });
});

import { bucketSecondsFor, timelineFromEvents } from '../server/facets.ts';
describe('Barras da linha do tempo', () => {
  it('períodos curtos usam barras finas', () => {
    assert.equal(bucketSecondsFor(30), 60);
    assert.equal(bucketSecondsFor(60), 120);
    assert.equal(bucketSecondsFor(180), 300);
    assert.equal(bucketSecondsFor(360), 600);
    assert.equal(bucketSecondsFor(1440), 3600);
  });
  it('agrupa eventos por intervalo', () => {
    const base = parseFlowLogs(
      [HEADER, row('1.1.1.1', '22', 'REJECT', 40), row('8.8.8.8', '443', 'ACCEPT', 10)].join('\n'),
      { nowMs: 1795500100_000 }
    ).events;
    const tl = timelineFromEvents(base, 60);
    assert.equal(tl.reduce((n, p) => n + p.allowed + p.blocked, 0), 2);
  });
});

import { accountIdOf } from '../server/awsIngest.ts';
describe('ID da conta AWS nos logs', () => {
  it('extrai do WAF, do ALB e do Flow Logs', () => {
    const waf = parseWafLogs(JSON.stringify({ timestamp: 1795531290208, action: 'ALLOW', webaclId: 'arn:aws:wafv2:sa-east-1:111122223333:regional/webacl/x/1', httpRequest: { clientIp: '1.2.3.4', httpMethod: 'GET', uri: '/' } }), { nowMs: 1795531300000 }).events[0];
    assert.equal(accountIdOf(waf), '111122223333');
    const flow = parseFlowLogs([HEADER, row('1.1.1.1', '22', 'REJECT', 40)].join('\n'), { nowMs: 1795500100_000 }).events[0];
    assert.equal(accountIdOf(flow), '123456789012');
  });
});

describe('WAF: segredos nunca são guardados', () => {
  const rec = {
    timestamp: 1795536587131, action: 'ALLOW', terminatingRuleId: 'AllowCorpHosts',
    requestBodySize: 805482, requestBodySizeInspectedByWAF: 8192, oversizeFields: ['REQUEST_BODY'],
    httpRequest: {
      clientIp: '198.51.100.20', country: 'BR', httpMethod: 'POST', uri: '/x', args: 'a=1&token=SEGREDO123&Filtro=abc',
      headers: [
        { name: 'Authorization', value: 'Basic dXN1YXJpbzpzZW5oYQ==' },
        { name: 'Cookie', value: 'ASP.NET_SessionId=SESSAO999; Login=ABCDEF' },
        { name: 'X-Sentry-Auth', value: 'Sentry sentry_key=CHAVE777' },
        { name: 'Content-Type', value: 'application/json; charset=utf-8' },
        { name: 'Referer', value: 'https://a.example.com/p?session=ZZZ&x=1' },
        { name: 'User-Agent', value: 'okhttp/5.3.2' },
      ],
    },
  };
  it('redige credenciais na linha guardada e extrai só o esquema de autenticação', () => {
    const ev = parseWafLogs(JSON.stringify(rec), { nowMs: 1795536600000 }).events[0];
    for (const secret of ['dXN1YXJpbzpzZW5oYQ==', 'SESSAO999', 'CHAVE777', 'SEGREDO123', 'ZZZ']) {
      assert.equal(ev.raw.includes(secret), false, `vazou ${secret} no raw`);
      assert.equal(JSON.stringify(ev.meta).includes(secret), false, `vazou ${secret} no meta`);
      assert.equal(ev.message.includes(secret), false, `vazou ${secret} na mensagem`);
    }
    assert.equal(ev.meta?.authScheme, 'Basic');
    assert.equal(ev.meta?.contentType, 'JSON');
    assert.equal(ev.meta?.oversize, 'REQUEST_BODY');
    assert.equal(ev.meta?.bodySize, 805482);
    assert.match(ev.raw, /Filtro=abc/);
  });
});

import { parseAlbLogs } from '../server/awsParsers.ts';
describe('ALB: connection log (TLS)', () => {
  const ok = { leaf_client_cert_subject: '-', time: '2026-11-24T16:04:27.189923Z', client_ip: '203.0.113.28', client_port: '26043', listener_port: '443', tls_protocol: 'TLSv1.3', tls_cipher: 'TLS_AES_128_GCM_SHA256', tls_handshake_latency: '0.113', tls_verify_status: 'Success', conn_trace_id: 'TID_1', tls_keyexchange: 'X25519MLKEM768', elb: 'app/alb-demo/b402', ip_address: '192.0.2.27' };
  const bad = { ...ok, client_ip: '192.0.2.21', tls_protocol: '-', tls_cipher: '-', tls_handshake_latency: '-', tls_verify_status: '-', tls_keyexchange: '-' };
  it('lê handshake, troca de chaves pós-quântica e conexões sem TLS', () => {
    const { events, skipped } = parseAlbLogs([JSON.stringify(ok), JSON.stringify(bad)].join('\n'), { nowMs: Date.parse('2026-11-24T16:10:00Z') });
    assert.equal(skipped, 0);
    assert.equal(events[0].meta?.connection, true);
    assert.equal(events[0].meta?.tlsHandshakeMs, 113);
    assert.equal(events[0].meta?.postQuantum, true);
    assert.equal(events[0].meta?.hsBucket, '100–200 ms');
    assert.equal(events[0].action, 'allow');
    assert.equal(events[1].action, 'deny');
    assert.equal(events[1].srcIp, '192.0.2.21');
  });
  it('não entra na análise HTTP do ALB e aparece na faceta de conexões', () => {
    const { events } = parseAlbLogs([JSON.stringify(ok), JSON.stringify(bad)].join('\n'), { nowMs: Date.parse('2026-11-24T16:10:00Z') });
    assert.equal(rowsFromAlbEventsForTest(events).groups.length, 0);
    const f = facetsFromEvents(events, 'albconn');
    assert.equal(f.totals.events, 2);
    assert.equal(f.totals.blocked, 1);
    assert.equal(f.facets.find((x) => x.id === 'kex')?.items[0].key, 'X25519MLKEM768');
  });
});
import { rowsFromAlbEvents as rowsFromAlbEventsForTest } from '../server/httpInsights.ts';

import { detectSecrets } from '../server/awsParsers.ts';
describe('Detecção de credenciais expostas', () => {
  const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  it('classifica Basic fraca, Basic, segredo na URL, JWT com dados pessoais e cookie', () => {
    assert.equal(detectSecrets([{ name: 'Authorization', value: `Basic ${Buffer.from('ana:1234').toString('base64')}` }], '', 'https')?.top, 'Basic Auth com senha fraca');
    assert.equal(detectSecrets([{ name: 'Authorization', value: `Basic ${Buffer.from('ana:Xk9#mQ2$vL7pZ').toString('base64')}` }], '', 'https')?.top, 'Basic Auth');
    assert.equal(detectSecrets([], 'a=1&access_token=abc', 'https')?.top, 'Segredo na URL');
    const jwt = `Bearer h.${b64u({ nome: 'Fulano', sub: '1' })}.s`;
    const j = detectSecrets([{ name: 'Authorization', value: jwt }], '', 'https');
    assert.deepEqual(j?.types, ['JWT com dados pessoais', 'JWT Bearer']);
    assert.equal(j?.risk, 'medium');
    assert.equal(detectSecrets([{ name: 'Cookie', value: 'ASP.NET_SessionId=x' }], '', 'https')?.risk, 'info');
    assert.equal(detectSecrets([{ name: 'Authorization', value: 'Bearer h.e30.s' }], '', 'http')?.top, 'Credencial em HTTP sem TLS');
    assert.equal(detectSecrets([{ name: 'User-Agent', value: 'x' }], 'a=1&b=2', 'https'), null);
  });
  it('o evento do WAF guarda só tipo, gravidade e endpoint (nunca o valor)', () => {
    const rec = {
      timestamp: 1795536587131, action: 'ALLOW', terminatingRuleId: 'R',
      httpRequest: { clientIp: '1.2.3.4', httpMethod: 'POST', host: 'api.example.com', uri: '/v1/pedidos/123456', scheme: 'https',
        headers: [{ name: 'Host', value: 'api.example.com' }, { name: 'Authorization', value: `Basic ${Buffer.from('bob:12345').toString('base64')}` }] },
    };
    const ev = parseWafLogs(JSON.stringify(rec), { nowMs: 1795536600000 }).events[0];
    assert.equal(ev.meta?.secretTop, 'Basic Auth com senha fraca');
    assert.equal(ev.meta?.secretRisk, 'critical');
    assert.equal(ev.meta?.secretEndpoint, 'POST api.example.com/v1/pedidos/{id}');
    assert.equal(JSON.stringify(ev).includes(Buffer.from('bob:12345').toString('base64')), false);
  });
});
