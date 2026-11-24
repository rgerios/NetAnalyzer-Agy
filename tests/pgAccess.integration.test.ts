import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import pg from 'pg';
import { PostgresStore } from '../server/database.ts';
import { parseAlbLogs } from '../server/awsParsers.ts';
import { buildHttpInsights, rowsFromAlbEvents } from '../server/httpInsights.ts';
import type { SyslogEvent } from '../server/types.ts';

/** Integração: agregação do relatório de acessos no PostgreSQL (só roda com TEST_DATABASE_URL). */
const URL = process.env.TEST_DATABASE_URL;
const SITE = 'it-access-site';

function ev(id: string, over: Partial<SyslogEvent>): SyslogEvent {
  const at = new Date(Date.now() - 600_000).toISOString();
  return {
    id, timestamp: at, firewallHost: 'fw', serialNumber: 'sn', priority: 6, severity: 'info', categoryCode: '1', categoryName: 'x',
    messageId: 'm', action: 'allow', srcIp: '10.0.0.1', srcPort: 1, srcZone: 'X0', dstIp: '8.8.8.8', dstPort: 443, dstZone: 'X1',
    natSrcIp: null, natSrcPort: null, natDstIp: null, natDstPort: null, protocol: 'tcp', ruleRef: null, natRuleRef: null,
    bytesSent: 100, bytesRcvd: 900, appName: null, user: null, message: 'm', raw: 'r', source: 'udp', ingestedAt: at,
    ...over,
  } as SyslogEvent;
}

describe('agregação do relatório de acessos (PostgreSQL)', { skip: !URL }, () => {
  let store: PostgresStore;
  let pool: pg.Pool;

  before(async () => {
    store = new PostgresStore(URL);
    await store.init();
    pool = new pg.Pool({ connectionString: URL });
    await pool.query('DELETE FROM sites WHERE id = $1', [SITE]);
    await pool.query(
      `INSERT INTO sites (id, vendor, name, connection_json, appliance_json, telemetry_json, alert_settings_json, created_at, updated_at)
       VALUES ($1, 'sonicwall', 'Teste', '{}', '{}', '{}', '{}', now(), now())`,
      [SITE]
    );
  });

  after(async () => {
    await pool.query('DELETE FROM sites WHERE id = $1', [SITE]);
    await pool.end();
    await store.close();
  });

  it('agrupa por origem/destino/serviço, soma bytes e ignora eventos de sistema', async () => {
    await store.insertSyslogs(
      SITE,
      'sonicwall',
      [
        ev('a1', {}),
        ev('a2', {}),
        ev('a3', { action: 'drop', bytesSent: 0, bytesRcvd: 0, dstIp: '1.1.1.1', srcIp: '10.0.0.2' }),
        ev('a4', { action: 'system', srcIp: '-', dstIp: '-' }),
      ],
      (e) => Date.parse(e.ingestedAt)
    );
    const r = await store.aggregateAccess(SITE, new Date(Date.now() - 3600_000).toISOString());
    assert.equal(r.timedOut, false);
    assert.equal(r.totalEvents, 3);
    const g = r.groups.find((x) => x.src === '10.0.0.1' && x.dst === '8.8.8.8');
    assert.ok(g);
    assert.equal(g.c, 2);
    assert.equal(g.up, 200);
    assert.equal(g.down, 1800);
    assert.equal(r.groups.find((x) => x.dst === '1.1.1.1')?.blocked, true);
    assert.ok(r.hours.length >= 1);
  });

  it('timeout 0 (segundo plano) roda sem limite de tempo e devolve o mesmo resultado', async () => {
    const r = await store.aggregateAccess(SITE, new Date(Date.now() - 3600_000).toISOString(), undefined, 0);
    assert.equal(r.timedOut, false);
    assert.equal(r.totalEvents, 3);
  });

  it('filtra syslogs por porta de destino e agrega o ranking de portas', async () => {
    await pool.query('DELETE FROM syslogs WHERE site_id = $1', [SITE]);
    await store.insertSyslogs(
      SITE,
      'sonicwall',
      [
        ev('p1', { dstPort: 443 }),
        ev('p2', { dstPort: 443, srcIp: '10.0.0.2' }),
        ev('p3', { dstPort: 443, action: 'drop' }),
        ev('p4', { dstPort: 22, action: 'drop' }),
        ev('p5', { dstPort: 8080 }),
        ev('p6', { dstPort: null }),
        ev('p7', { dstPort: 443, action: 'system' }),
      ],
      (e) => Date.parse(e.ingestedAt)
    );
    const since = new Date(Date.now() - 3600_000).toISOString();
    const only443 = await store.querySyslogs(SITE, { dstPorts: [[443, 443]], sinceIso: since, limit: 50, offset: 0 });
    assert.equal(only443.matched, 4); // inclui o evento de sistema: o filtro e so por porta
    const range = await store.querySyslogs(SITE, { dstPorts: [[22, 22], [8000, 8100]], sinceIso: since, limit: 50, offset: 0 });
    assert.deepEqual(range.events.map((e) => e.dstPort).sort(), [22, 8080]);
    const none = await store.querySyslogs(SITE, { dstPorts: [[9999, 9999]], sinceIso: since, limit: 50, offset: 0 });
    assert.equal(none.matched, 0);
    const all = await store.querySyslogs(SITE, { dstPorts: [], sinceIso: since, limit: 50, offset: 0 });
    assert.equal(all.matched, 7);

    const agg = await store.aggregatePorts(SITE, since, 10);
    assert.equal(agg.timedOut, false);
    assert.equal(agg.events, 5); // sem o evento de sistema e sem o evento sem porta
    assert.deepEqual(agg.ports.map((p) => p.port), [443, 22, 8080]);
    const https = agg.ports[0];
    assert.equal(https.connections, 3);
    assert.equal(https.blocked, 1);
    assert.equal(https.sources, 2);
    assert.equal(https.proto, 'tcp');
    assert.equal(https.bytes, 3 * 1000);
  });

  it('agrega o Behavior no banco sobre o período inteiro, sem teto de eventos', async () => {
    await pool.query('DELETE FROM syslogs WHERE site_id = $1', [SITE]);
    const batch: SyslogEvent[] = [];
    for (let i = 0; i < 300; i += 1) batch.push(ev(`b${i}`, { srcIp: `10.0.0.${i % 5}`, dstIp: i % 3 === 0 ? '1.1.1.1' : '8.8.8.8', dstPort: i % 3 === 0 ? 53 : 443, protocol: i % 3 === 0 ? 'udp' : 'tcp' }));
    batch.push(ev('bblk', { action: 'drop', dstIp: '45.155.205.91', dstPort: 22 }), ev('bsys', { action: 'system', dstIp: '8.8.8.8' }), ev('bnull', { dstIp: '-' }));
    await store.insertSyslogs(SITE, 'sonicwall', batch, (e) => Date.parse(e.ingestedAt));
    const since = new Date(Date.now() - 3600_000).toISOString();
    const r = await store.aggregateBehavior(SITE, since);
    assert.equal(r.timedOut, false);
    assert.equal(r.capped, false);
    assert.equal(r.groups.reduce((n, g) => n + g.c, 0), 301); // sem sistema nem destino '-'
    const ssh = r.groups.find((g) => g.dst === '45.155.205.91');
    assert.equal(ssh?.blocked, true);
    assert.equal(ssh?.port, '22');
    assert.ok(ssh?.last);
    const dns = r.groups.filter((g) => g.dst === '1.1.1.1');
    assert.ok(dns.every((g) => g.proto === 'udp' && g.port === '53'));
    assert.equal(dns.reduce((n, g) => n + g.c, 0), 100);
    const capped = await store.aggregateBehavior(SITE, since, 2);
    assert.equal(capped.groups.length, 2);
    assert.equal(capped.capped, true);
  });

  it('extrai o FQDN e a categoria do texto original do log no banco (Acessos e radar)', async () => {
    await pool.query('DELETE FROM syslogs WHERE site_id = $1', [SITE]);
    await store.insertSyslogs(
      SITE,
      'sonicwall',
      [
        ev('h1', { dstIp: '13.107.42.16', raw: 'id=firewall src=10.0.0.1 dst=13.107.42.16 dstname=windowsupdate.microsoft.com proto=tcp/https' }),
        ev('h2', { dstIp: '13.107.42.16', raw: 'id=firewall src=10.0.0.1 dst=13.107.42.16 dstname=windowsupdate.microsoft.com proto=tcp/https' }),
        ev('h3', { dstIp: '142.250.1.1', raw: 'date=2026-11-24 srcip=10.0.0.2 dstip=142.250.1.1 hostname="www.google.com" appcat="Web.Client" catdesc="Search Engines"' }),
        ev('h4', { dstIp: '203.0.113.5', raw: 'src=10.0.0.3 url="https://cdn.exemplo.net/a/b?x=1" catdesc="Software Update"' }),
        ev('h5', { dstIp: '198.51.100.7', raw: 'src=10.0.0.4 dst=198.51.100.7 sem pistas aqui' }),
        ev('h6', { dstIp: '198.51.100.8', srcZone: 'LAN', user: 'maria', raw: 'src=10.0.0.9 dst=198.51.100.8 dstname=erro-sem-ponto' }),
      ],
      (e) => Date.parse(e.ingestedAt)
    );
    const since = new Date(Date.now() - 3600_000).toISOString();

    const acc = await store.aggregateAccess(SITE, since);
    const hostOf = (dst: string) => acc.groups.find((g) => g.dst === dst)?.host;
    assert.equal(hostOf('13.107.42.16'), 'windowsupdate.microsoft.com');
    assert.equal(acc.groups.filter((g) => g.dst === '13.107.42.16').reduce((n, g) => n + g.c, 0), 2);
    assert.equal(hostOf('142.250.1.1'), 'www.google.com'); // aspas
    assert.equal(hostOf('203.0.113.5'), 'https://cdn.exemplo.net/a/b?x=1'); // url (o servidor limpa depois)
    assert.equal(hostOf('198.51.100.7'), '');

    const radar = await store.aggregateRadar(SITE, since);
    assert.equal(radar.timedOut, false);
    assert.equal(radar.capped, false);
    assert.equal(radar.rows.reduce((n, r) => n + r.c, 0), 6);
    const g = radar.rows.find((r) => r.dst === '142.250.1.1');
    assert.equal(g?.host, 'www.google.com');
    assert.equal(g?.appCategory, 'Web.Client'); // appcat vence catdesc
    assert.equal(radar.rows.find((r) => r.dst === '203.0.113.5')?.appCategory, 'Software Update'); // com espaço, entre aspas
    const m = radar.rows.find((r) => r.dst === '198.51.100.8');
    assert.equal(m?.srcZone, 'LAN');
    assert.equal(m?.user, 'maria');

    const only = await store.aggregateRadar(SITE, since, { srcLike: '10.0.0.1' });
    assert.ok(only.rows.length > 0 && only.rows.every((r) => r.src.includes('10.0.0.1')));
    const capped = await store.aggregateRadar(SITE, since, { groupLimit: 2 });
    assert.equal(capped.rows.length, 2);
    assert.equal(capped.capped, true);
  });

  it('agrega a análise de aplicação do ALB no banco com o mesmo resultado da memória', async () => {
    await pool.query('DELETE FROM syslogs WHERE site_id = $1', [SITE]);
    const base = {
      request_line: 'POST https://vendas.rgerios.corp:8050/app/Services/MobileService.svc/EnviarImagem HTTP/1.1', user_agent: 'okhttp/5.3.2',
      domain_name: 'vendas.rgerios.corp', actions_executed: 'waf,forward', target_port: '10.20.0.11:443', type: 'https', elb: 'app/alb-demo/b402',
      client_port: '203.0.113.25:64002', request_processing_time: '0.100', target_processing_time: '2.000', response_processing_time: '0.000',
      elb_status_code: '200', target_status_code: '200', received_bytes: '1000000', sent_bytes: '900', ssl_cipher: 'TLS_AES_128_GCM_SHA256',
      ssl_protocol: 'TLSv1.3', target_group_arn: 'arn:aws:elasticloadbalancing:sa-east-1:1:targetgroup/TG-vendas/abc',
    };
    const t = () => new Date(Date.now() - 600_000).toISOString();
    const lines: string[] = [];
    for (let i = 0; i < 12; i += 1) lines.push(JSON.stringify({ ...base, time: t() }));
    for (let i = 0; i < 8; i += 1) lines.push(JSON.stringify({ ...base, time: t(), request_line: `GET https://vendas.rgerios.corp:8050/api/pedidos/${1000 + i} HTTP/1.1`, user_agent: 'Mozilla/5.0 Chrome/120 Safari/537', target_processing_time: '0.050', received_bytes: '300', sent_bytes: '4000' }));
    for (let i = 0; i < 3; i += 1) lines.push(JSON.stringify({ ...base, time: t(), elb_status_code: '502', target_port: '192.168.0.138:443', ssl_protocol: 'TLSv1.2' }));
    lines.push(JSON.stringify({ ...base, time: t(), elb_status_code: '403', actions_executed: 'waf', target_port: '-' }));
    const events = parseAlbLogs(lines.join('\n')).events;
    assert.equal(events.length, 24);
    await store.insertSyslogs(SITE, 'aws', events, (e) => Date.parse(e.ingestedAt));

    const since = new Date(Date.now() - 3600_000).toISOString();
    const db = await store.aggregateHttpInsights(SITE, since);
    assert.equal(db.timedOut, false);
    assert.equal(db.capped, false);
    const viaDb = buildHttpInsights({ groups: db.groups, clients: db.clients, extras: db.extras, minutes: 60, dataSource: 'database', truncated: false });
    const viaMem = buildHttpInsights({ ...rowsFromAlbEvents(events, 3600), minutes: 60, dataSource: 'memory', truncated: false });
    assert.equal(viaDb.requests, 24);
    for (const k of ['requests', 'status', 'waf', 'bytes', 'endpoints', 'slowest', 'heaviest', 'errors', 'userAgents', 'tls', 'targets', 'hosts', 'distribution', 'timeBreakdown', 'clientSlow', 'tlsReuse'] as const) {
      assert.deepEqual(viaDb[k], viaMem[k], k);
    }
    assert.equal(viaDb.latency.avgMs, viaMem.latency.avgMs);
    assert.deepEqual(viaDb.latency, viaMem.latency);
    assert.deepEqual(viaDb.slowRequests.map((r) => r.totalMs), viaMem.slowRequests.map((r) => r.totalMs));
    assert.equal(viaDb.timeline.reduce((n, p) => n + p.requests, 0), 24);
    assert.equal(viaDb.endpoints.find((e) => e.path === '/api/pedidos/{id}')?.requests, 8);
    const capped = await store.aggregateHttpInsights(SITE, since, 1);
    assert.equal(capped.groups.length, 1);
    assert.equal(capped.capped, true);
  });

  it('redige segredos gravados antes da correção (raw, mensagem e texto de busca), uma única vez', async () => {
    const raw = '{"httpRequest":{"headers":[{"name":"Authorization","value":"Basic U0VDUkVUT1VTVUFSSU8="},{"name":"Cookie","value":"sid=COOKIE123"},{"name":"X-Sentry-Auth","value":"Sentry sentry_key=KEY999"}],"args":"a=1&token=TOK777"}}';
    const bad = ev('secret-1', {
      categoryName: 'AWS WAF', message: 'WAF ALLOW GET /x?a=1&token=TOK777', raw,
    });
    await store.insertSyslogs(SITE, 'aws', [bad], (e) => Date.parse(e.ingestedAt));
    await pool.query(`UPDATE sites SET vendor = 'aws' WHERE id = $1`, [SITE]);
    await pool.query(`DELETE FROM app_settings WHERE key = 'aws_secrets_redacted_v1'`);
    const n = await store.redactStoredSecrets();
    assert.ok(n >= 1);
    const row = await pool.query(`SELECT payload_json->>'raw' AS raw, payload_json->>'message' AS msg, search_text FROM syslogs WHERE site_id = $1 AND id = 'secret-1'`, [SITE]);
    const all = `${row.rows[0].raw}|${row.rows[0].msg}|${row.rows[0].search_text}`;
    for (const secret of ['U0VDUkVUT1VTVUFSSU8', 'COOKIE123', 'KEY999', 'TOK777']) assert.equal(all.includes(secret), false, secret);
    assert.match(row.rows[0].raw, /redigido/);
    assert.equal(await store.redactStoredSecrets(), 0, 'segunda execução não faz nada');
    await pool.query(`UPDATE sites SET vendor = 'sonicwall' WHERE id = $1`, [SITE]);
  });
});
