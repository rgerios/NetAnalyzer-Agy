import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildBehaviorReport, groupsFromEvents } from '../server/behaviorEngine.ts';
import { buildPortStats, buildPortStatsFromGroups, filterEventsByPort, filterGroupsByPort, isPublicDestination } from '../server/portsEngine.ts';
import { parsePortFilter } from '../shared/ports.ts';
import type { SyslogEvent } from '../server/types.ts';

const NOW = Date.now();
const ev = (over: Partial<SyslogEvent>): SyslogEvent =>
  ({
    srcIp: '10.0.0.5', dstIp: '8.8.8.8', dstPort: 443, protocol: 'tcp', action: 'allow', bytesSent: 100, bytesRcvd: 400,
    ingestedAt: new Date(NOW - 1000).toISOString(), timestamp: new Date(NOW - 1000).toISOString(), ...over,
  }) as SyslogEvent;

const COUNTRY: Record<string, string> = { '8.8.8.8': 'US', '1.1.1.1': 'AU', '45.155.205.91': 'RU', '200.147.88.12': 'BR' };
const intel = {
  lookup: (ip: string) => ({
    country: COUNTRY[ip] ?? null, asn: null, asnOrg: null,
    threats: ip === '45.155.205.91' ? [{ list: 'FireHOL', category: 'blacklist' as const }] : [],
  }),
  status: () => ({}),
} as never;
const origin = { country: 'BR', ip: null, source: 'fallback' as const };

const events: SyslogEvent[] = [
  ...Array.from({ length: 40 }, (_v, i) => ev({ srcIp: `10.0.0.${i % 7}` })),
  ...Array.from({ length: 12 }, () => ev({ dstIp: '1.1.1.1', dstPort: 53, protocol: 'udp' })),
  ...Array.from({ length: 9 }, () => ev({ dstIp: '45.155.205.91', dstPort: 22, action: 'drop' })),
  ...Array.from({ length: 5 }, () => ev({ dstIp: '10.1.1.1', dstPort: 445 })), // interno: fora do mapa
  ev({ dstIp: '200.147.88.12', dstPort: null }),
  ev({ action: 'system', dstIp: '8.8.8.8' }),
  ev({ dstIp: '-' }),
];

describe('Behavior agregado (banco) equivale à leitura de eventos', () => {
  it('agrupa por origem/destino/protocolo/porta/bloqueio e ignora sistema e destino vazio', () => {
    const groups = groupsFromEvents(events);
    assert.equal(groups.reduce((n, g) => n + g.c, 0), events.length - 2);
    const ssh = groups.find((g) => g.dst === '45.155.205.91');
    assert.equal(ssh?.c, 9);
    assert.equal(ssh?.blocked, true);
    assert.equal(ssh?.bytes, 9 * 500);
    assert.ok(ssh?.last);
  });

  it('mesmos totais, países, IPs e ameaças pelos dois caminhos', () => {
    const base = { minutes: 60, intel, origin, dataSource: 'memory' as const, truncated: false };
    const viaEvents = buildBehaviorReport({ ...base, events });
    const viaGroups = buildBehaviorReport({ ...base, groups: groupsFromEvents(events), recentEvents: events });
    assert.deepEqual(viaGroups.totals, viaEvents.totals);
    assert.equal(viaGroups.analyzedEvents, viaEvents.analyzedEvents);
    assert.deepEqual(
      viaGroups.countries.map((c) => [c.code, c.connections, c.blocked, c.bytes, c.ips, c.threatIps]),
      viaEvents.countries.map((c) => [c.code, c.connections, c.blocked, c.bytes, c.ips, c.threatIps])
    );
    assert.deepEqual(
      viaGroups.ips.map((i) => [i.ip, i.connections, i.blocked, i.bytes]),
      viaEvents.ips.map((i) => [i.ip, i.connections, i.blocked, i.bytes])
    );
    assert.equal(viaGroups.totals.connections, 40 + 12 + 9 + 1);
    assert.equal(viaGroups.totals.threatConnections, 9);
    assert.equal(viaGroups.flowsTotal, viaEvents.flowsTotal);
  });

  it('conta as conexões mesmo quando o período tem muito mais eventos que antes cabiam na leitura', () => {
    const many = Array.from({ length: 50_000 }, (_v, i) => ev({ srcIp: `10.0.${i % 50}.1` }));
    const groups = groupsFromEvents(many);
    assert.ok(groups.length <= 50);
    const rep = buildBehaviorReport({ groups, recentEvents: [], minutes: 1440, intel, origin, dataSource: 'database', truncated: false });
    assert.equal(rep.totals.connections, 50_000);
  });

  it('ranking e filtro de portas dão o mesmo resultado com eventos e com grupos', () => {
    const groups = groupsFromEvents(events);
    const a = buildPortStats(events, 25, isPublicDestination);
    const b = buildPortStatsFromGroups(groups, 25, (g) => g.dst !== '10.1.1.1');
    assert.deepEqual(b.ports, a.ports);
    assert.equal(b.counted, a.counted);
    const spec = parsePortFilter('22,53')!;
    assert.equal(filterGroupsByPort(groups, spec).reduce((n, g) => n + g.c, 0), filterEventsByPort(events, spec).length);
    assert.equal(filterGroupsByPort(groups, parsePortFilter('')).length, groups.length);
  });

  it('modo entrada (AWS): o cliente público é o remoto, também via grupos', () => {
    const inboundEv = [ev({ srcIp: '45.155.205.91', dstIp: 'app.rgerios.corp', action: 'deny' }), ev({ srcIp: '200.147.88.12', dstIp: 'app.rgerios.corp' })];
    const rep = buildBehaviorReport({ groups: groupsFromEvents(inboundEv), recentEvents: inboundEv, minutes: 60, intel, origin, dataSource: 'memory', truncated: false, inbound: true });
    assert.equal(rep.totals.connections, 2);
    assert.equal(rep.totals.threatConnections, 1);
    assert.deepEqual(rep.countries.map((c) => c.code).sort(), ['BR', 'RU']);
  });
});
