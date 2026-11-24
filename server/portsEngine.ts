import { hasPortFilter, portMatches, wellKnownService, type PortFilterSpec, type PortStat } from '../shared/ports.ts';
import type { BehaviorGroup } from './behaviorEngine.ts';
import { ipScope, isIpAddress } from '../shared/destinations.ts';
import { isBlockedAction } from './engineHelpers.ts';
import type { SyslogEvent } from './types.ts';

const MAX_TRACKED_IPS = 2000;

export function filterEventsByPort(events: SyslogEvent[], spec: PortFilterSpec | null | undefined): SyslogEvent[] {
  if (!spec || !hasPortFilter(spec)) return events;
  return events.filter((ev) => portMatches(spec, ev.dstPort));
}

interface Acc {
  connections: number;
  blocked: number;
  bytes: number;
  protos: Map<string, number>;
  src: Set<string>;
  dst: Set<string>;
}

/** Portas de destino mais usadas nos eventos informados (ordenadas por conexões). */
export function buildPortStats(
  events: SyslogEvent[],
  limit = 20,
  include?: (ev: SyslogEvent) => boolean
): { ports: PortStat[]; counted: number } {
  const byPort = new Map<number, Acc>();
  let counted = 0;
  for (const ev of events) {
    const port = ev.dstPort;
    if (port === null || port === undefined || !Number.isInteger(port) || port < 0 || port > 65535) continue;
    if (ev.action === 'system') continue;
    if (include && !include(ev)) continue;
    counted += 1;
    let a = byPort.get(port);
    if (!a) {
      a = { connections: 0, blocked: 0, bytes: 0, protos: new Map(), src: new Set(), dst: new Set() };
      byPort.set(port, a);
    }
    a.connections += 1;
    if (isBlockedAction(ev.action)) a.blocked += 1;
    a.bytes += (ev.bytesSent || 0) + (ev.bytesRcvd || 0);
    const proto = (ev.protocol || '').toLowerCase().split('/')[0] || 'tcp';
    a.protos.set(proto, (a.protos.get(proto) ?? 0) + 1);
    if (ev.srcIp && a.src.size < MAX_TRACKED_IPS) a.src.add(ev.srcIp);
    if (ev.dstIp && a.dst.size < MAX_TRACKED_IPS) a.dst.add(ev.dstIp);
  }
  const ports = [...byPort.entries()]
    .map(([port, a]): PortStat => {
      let proto = 'tcp';
      let best = -1;
      for (const [p, n] of a.protos) if (n > best) { proto = p; best = n; }
      return {
        port,
        proto,
        service: wellKnownService(port),
        connections: a.connections,
        blocked: a.blocked,
        bytes: a.bytes,
        sources: a.src.size,
        destinations: a.dst.size,
      };
    })
    .sort((x, y) => y.connections - x.connections || x.port - y.port)
    .slice(0, limit);
  return { ports, counted };
}

/** Destino é um IP público (o que o mapa Behavior considera tráfego externo). */
export function isPublicDestination(ev: SyslogEvent): boolean {
  const dst = (ev.dstIp || '').trim();
  return !!dst && dst !== '-' && isIpAddress(dst) && ipScope(dst) === 'public';
}

const groupPort = (g: BehaviorGroup): number | null => {
  if (!/^\d{1,5}$/.test(g.port)) return null;
  const n = Number(g.port);
  return n <= 65535 ? n : null;
};

export function filterGroupsByPort(groups: BehaviorGroup[], spec: PortFilterSpec | null | undefined): BehaviorGroup[] {
  if (!spec || !hasPortFilter(spec)) return groups;
  return groups.filter((g) => portMatches(spec, groupPort(g)));
}

/** Ranking de portas a partir de conexões já agregadas (mesmo resultado de `buildPortStats` sobre eventos). */
export function buildPortStatsFromGroups(
  groups: BehaviorGroup[],
  limit = 20,
  include?: (g: BehaviorGroup) => boolean
): { ports: PortStat[]; counted: number } {
  const byPort = new Map<number, Acc>();
  let counted = 0;
  for (const g of groups) {
    const port = groupPort(g);
    if (port === null) continue;
    if (include && !include(g)) continue;
    counted += g.c;
    let a = byPort.get(port);
    if (!a) {
      a = { connections: 0, blocked: 0, bytes: 0, protos: new Map(), src: new Set(), dst: new Set() };
      byPort.set(port, a);
    }
    a.connections += g.c;
    if (g.blocked) a.blocked += g.c;
    a.bytes += g.bytes;
    const proto = g.proto || 'tcp';
    a.protos.set(proto, (a.protos.get(proto) ?? 0) + g.c);
    if (g.src && a.src.size < MAX_TRACKED_IPS) a.src.add(g.src);
    if (g.dst && a.dst.size < MAX_TRACKED_IPS) a.dst.add(g.dst);
  }
  const ports = [...byPort.entries()]
    .map(([port, a]): PortStat => {
      let proto = 'tcp';
      let best = -1;
      for (const [p, n] of a.protos) if (n > best) { proto = p; best = n; }
      return {
        port,
        proto,
        service: wellKnownService(port),
        connections: a.connections,
        blocked: a.blocked,
        bytes: a.bytes,
        sources: a.src.size,
        destinations: a.dst.size,
      };
    })
    .sort((x, y) => y.connections - x.connections || x.port - y.port)
    .slice(0, limit);
  return { ports, counted };
}
