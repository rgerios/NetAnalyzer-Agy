import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { classifyDestination } from '../shared/destinations.ts';
import { aggregateEventsInMemory, buildAccessReport } from '../server/accessReport.ts';
import {
  buildDestinationNodes,
  buildDestinationNodesFromRows,
  buildSourceNodes,
  buildSourceNodesFromRows,
  eventMatchesDestination,
  filterRowsByDestination,
  filterRowsByPort,
  filterRowsBySource,
  normalizeDestinationFilter,
  rowFromDb,
  rowsFromEvents,
} from '../server/destinationsEngine.ts';
import { parsePortFilter } from '../shared/ports.ts';
import type { SyslogEvent } from '../server/types.ts';

const NOW = Date.now();
const ev = (over: Partial<SyslogEvent>): SyslogEvent =>
  ({
    srcIp: '10.0.0.5', srcZone: 'X0', dstIp: '13.107.42.16', dstPort: 443, protocol: 'tcp/https', action: 'allow',
    bytesSent: 100, bytesRcvd: 900, appName: null, user: null,
    raw: 'src=10.0.0.5 dst=13.107.42.16 dstname=windowsupdate.microsoft.com',
    ingestedAt: new Date(NOW - 1000).toISOString(), timestamp: new Date(NOW - 1000).toISOString(), ...over,
  }) as SyslogEvent;

const intel = { lookup: () => ({ country: null, asn: null, asnOrg: null, threats: [] }) } as never;

describe('FQDN do log no relatório de Acessos', () => {
  it('a agregação em memória leva o host do log e o relatório classifica por ele', () => {
    const events = [
      ...Array.from({ length: 10 }, () => ev({})),
      ...Array.from({ length: 4 }, () => ev({ dstIp: '203.0.113.9', raw: 'src=10.0.0.5 dst=203.0.113.9' })),
    ];
    const agg = aggregateEventsInMemory(events);
    const withHost = agg.groups.find((g) => g.dst === '13.107.42.16');
    assert.equal(withHost?.host, 'windowsupdate.microsoft.com');
    assert.equal(agg.groups.find((g) => g.dst === '203.0.113.9')?.host, '');

    const report = buildAccessReport({ agg, vendor: 'sonicwall', minutes: 60, sinceIso: null, dataSource: 'memory', intel });
    const expected = classifyDestination({ host: 'windowsupdate.microsoft.com', service: 'HTTPS', appCategory: null, scope: 'public' });
    assert.notEqual(expected, 'Outros');
    const row = report.destinations.find((d) => d.ip === '13.107.42.16');
    assert.equal(row?.host, 'windowsupdate.microsoft.com');
    assert.equal(row?.category, expected);
    assert.equal(report.categories.find((c) => c.name === expected)?.connections, 10);
  });

  it('o host do log vence o DNS reverso; sem host, o DNS reverso continua valendo', () => {
    const agg = aggregateEventsInMemory([ev({}), ev({ dstIp: '203.0.113.9', raw: '' })]);
    const report = buildAccessReport({
      agg, vendor: 'sonicwall', minutes: 60, sinceIso: null, dataSource: 'memory', intel,
      lookupHost: (ip) => (ip === '203.0.113.9' ? 'cdn.exemplo.net' : 'errado.rdns.net'),
    });
    assert.equal(report.destinations.find((d) => d.ip === '13.107.42.16')?.host, 'windowsupdate.microsoft.com');
    assert.equal(report.destinations.find((d) => d.ip === '203.0.113.9')?.host, 'cdn.exemplo.net');
  });

  it('no AWS o destino já é um nome e entra na classificação', () => {
    const agg = {
      groups: [{ src: '200.147.88.12', dst: 'outlook.office365.com', proto: 'tcp', port: '443', app: '', blocked: false, host: '', c: 3, up: 1, down: 2 }],
      hours: [], totalEvents: 3, timedOut: false,
    };
    const report = buildAccessReport({ agg, vendor: 'aws', minutes: 60, sinceIso: null, dataSource: 'memory', intel, inbound: true });
    assert.notEqual(report.destinations[0].category, 'Outros');
  });
});

describe('Destinos e Origens a partir de conexões agregadas', () => {
  const events = [
    ...Array.from({ length: 12 }, (_v, i) => ev({ srcIp: `10.0.0.${i % 4}`, user: i % 2 ? 'ana' : null })),
    ...Array.from({ length: 5 }, () => ev({ dstIp: '1.1.1.1', dstPort: 53, protocol: 'udp/dns', raw: 'dst=1.1.1.1 appcat="Web.Client"' })),
    ...Array.from({ length: 3 }, () => ev({ dstIp: '45.155.205.91', dstPort: 22, action: 'drop', raw: '' })),
    ev({ dstIp: '10.9.9.9', dstPort: 445, raw: '' }),
    ev({ action: 'system', dstIp: '-' }),
  ];

  it('mesmos nós e contagens pelos dois caminhos', () => {
    const viaEvents = buildDestinationNodes(events);
    const viaRows = buildDestinationNodesFromRows(rowsFromEvents(events));
    assert.equal(viaRows.analyzed, viaEvents.analyzed);
    const slim = (n: (typeof viaRows.nodes)[number]) => [n.id, n.connections, n.blocked, n.bytes, n.sources, n.category];
    assert.deepEqual(viaRows.nodes.map(slim).sort(), viaEvents.nodes.map(slim).sort());

    const sEvents = buildSourceNodes(events);
    const sRows = buildSourceNodesFromRows(rowsFromEvents(events));
    assert.equal(sRows.analyzed, sEvents.analyzed);
    const sSlim = (n: (typeof sRows.nodes)[number]) => [n.ip, n.connections, n.blocked, n.destinations, n.zone, n.user];
    assert.deepEqual(sRows.nodes.map(sSlim).sort(), sEvents.nodes.map(sSlim).sort());
  });

  it('linhas do banco viram o formato interno (host limpo, porta numérica, categoria)', () => {
    const r = rowFromDb({
      src: '10.0.0.5', srcZone: '-', user: '', dst: '1.1.1.1', host: 'https://dns.cloudflare.com/x', appCategory: 'Web.Client',
      proto: 'udp/dns', port: '53', app: '', blocked: false, c: 9, bytes: 123, last: '2026-11-24T10:00:00.000Z',
    });
    assert.equal(r.host, 'dns.cloudflare.com');
    assert.equal(r.port, 53);
    assert.equal(r.srcZone, '');
    assert.equal(r.appCategory, 'Web.Client');
    const none = rowFromDb({ ...{ src: 'a', srcZone: '', user: '', dst: '8.8.8.8', host: '', appCategory: '', proto: '', port: '', app: '', blocked: false, c: 1, bytes: 0, last: null } });
    assert.equal(none.host, null);
    assert.equal(none.port, null);
    assert.equal(none.appCategory, null);
  });

  it('os filtros sobre linhas decidem como os filtros sobre eventos', () => {
    const rows = rowsFromEvents(events);
    const total = (rs: typeof rows) => rs.reduce((n, r) => n + r.c, 0);
    const lookup = (ip: string) => (ip === '1.1.1.1' ? 'one.one.one.one' : null);

    for (const [text, ips] of [['microsoft', ''], ['one.one', ''], ['45.155', ''], ['', '1.1.1.1,45.155.205.91']] as const) {
      const f = normalizeDestinationFilter(text, ips)!;
      const byEvents = events.filter((e) => e.action !== 'system' && e.dstIp !== '-' && eventMatchesDestination(e, f, lookup)).length;
      assert.equal(total(filterRowsByDestination(rows, f, lookup)), byEvents, `filtro "${text}" "${ips}"`);
    }
    assert.equal(total(filterRowsBySource(rows, '10.0.0.1')), events.filter((e) => e.action !== 'system' && e.srcIp.includes('10.0.0.1')).length);
    assert.equal(total(filterRowsByPort(rows, parsePortFilter('22,53'))), 8);
    assert.equal(total(filterRowsByPort(rows, parsePortFilter(''))), total(rows));
  });
});
