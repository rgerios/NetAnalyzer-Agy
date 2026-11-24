import { ipScope, isIpAddress } from '../shared/destinations.ts';
import type {
  BehaviorCountry,
  BehaviorFlow,
  BehaviorIp,
  BehaviorOrigin,
  BehaviorReport,
  BehaviorThreatCategory,
} from '../shared/behavior.ts';
import type { Intel, IntelLookup } from './intel.ts';
import type { SyslogEvent } from './types.ts';

const MAX_IPS_TRACKED = 30_000;
// Na primeira carga mostra o último minuto (ajustável, útil para demonstração com logs antigos)
const DEFAULT_FLOW_WINDOW_MS = Math.max(1000, Number(process.env.BEHAVIOR_FLOW_WINDOW_MS) || 60_000);
const MAX_FLOWS = 500;
const FALLBACK_ORIGIN = 'BR';

interface IpAcc {
  ip: string;
  lookup: IntelLookup;
  connections: number;
  blocked: number;
  bytes: number;
  sources: Map<string, number>;
  lastSeen: string | null;
}

/**
 * Conexões já agregadas por origem, destino e porta. O banco faz essa agregação sobre TODO o período
 * (sem o teto de leitura de eventos); sem banco, `groupsFromEvents` faz o mesmo em memória.
 */
export interface BehaviorGroup {
  src: string;
  dst: string;
  proto: string;
  port: string;
  blocked: boolean;
  c: number;
  bytes: number;
  /** Última vez em que o grupo apareceu (ISO). */
  last: string | null;
}

export function groupsFromEvents(events: SyslogEvent[]): BehaviorGroup[] {
  const map = new Map<string, BehaviorGroup>();
  for (const ev of events) {
    if (ev.action === 'system') continue;
    const dst = (ev.dstIp || '').trim();
    if (!dst || dst === '-') continue;
    const src = (ev.srcIp || '').trim();
    const blocked = isBlocked(ev.action);
    const proto = (ev.protocol || '').toLowerCase().split('/')[0];
    const port = ev.dstPort === null || ev.dstPort === undefined ? '' : String(ev.dstPort);
    const key = `${src}|${dst}|${proto}|${port}|${blocked ? 1 : 0}`;
    const seen = ev.ingestedAt || ev.timestamp || null;
    let g = map.get(key);
    if (!g) {
      g = { src, dst, proto, port, blocked, c: 0, bytes: 0, last: null };
      map.set(key, g);
    }
    g.c += 1;
    g.bytes += (ev.bytesSent || 0) + (ev.bytesRcvd || 0);
    if (seen && (!g.last || seen > g.last)) g.last = seen;
  }
  return [...map.values()];
}

/**
 * IP público da conexão e o "outro lado". Normalmente é o destino; com `inbound` (AWS), quando o
 * destino não é um IP público, usa a origem (o cliente que chegou da internet).
 */
export function remoteOfPair(srcIp: string, dstIp: string, inbound: boolean): { ip: string; peer: string } | null {
  const dst = (dstIp || '').trim();
  if (dst && dst !== '-' && isIpAddress(dst) && ipScope(dst) === 'public') return { ip: dst, peer: srcIp };
  if (inbound) {
    const src = (srcIp || '').trim();
    if (src && src !== '-' && isIpAddress(src) && ipScope(src) === 'public') return { ip: src, peer: dstIp };
  }
  return null;
}

export function remoteIpOf(ev: SyslogEvent, inbound: boolean): { ip: string; peer: string } | null {
  return remoteOfPair(ev.srcIp, ev.dstIp, inbound);
}

const isBlocked = (action: string) => action === 'drop' || action === 'deny' || action === 'reset';

export function buildBehaviorReport(params: {
  /** Eventos brutos (modo sem banco e testes). Ignorado se `groups` for informado. */
  events?: SyslogEvent[];
  /** Conexões agregadas (agregação do banco sobre o período inteiro). */
  groups?: BehaviorGroup[];
  /** Eventos recentes para as partículas do tempo real (padrão: `events`). */
  recentEvents?: SyslogEvent[];
  minutes: number;
  intel: Intel;
  origin: BehaviorOrigin;
  /** Só devolve em `flows` as conexões ingeridas depois deste instante (ISO). */
  since?: string;
  dataSource: 'memory' | 'database';
  truncated: boolean;
  /** AWS: o tráfego vem da internet para a nuvem, então o IP público é a origem. */
  inbound?: boolean;
}): BehaviorReport {
  const { intel } = params;
  const inbound = params.inbound === true;
  const groups = params.groups ?? groupsFromEvents(params.events ?? []);
  const recentSource = params.recentEvents ?? params.events ?? [];
  const ips = new Map<string, IpAcc>();
  const lookups = new Map<string, IntelLookup>();
  const countries = new Map<string, BehaviorCountry & { ipSet: Set<string>; threatSet: Set<string> }>();
  const recent: Array<BehaviorFlow & { ms: number }> = [];
  const sinceMs = params.since ? Date.parse(params.since) : NaN;
  const flowCutoff = Number.isFinite(sinceMs) ? sinceMs : Date.now() - DEFAULT_FLOW_WINDOW_MS;
  let analyzed = 0;
  let blockedTotal = 0;
  let threatConnections = 0;
  let unknownConnections = 0;
  let connectionsTotal = 0;

  const lookupOf = (ip: string): IntelLookup => {
    let l = lookups.get(ip);
    if (!l) {
      l = intel.lookup(ip);
      lookups.set(ip, l);
    }
    return l;
  };

  for (const g of groups) {
    const remote = remoteOfPair(g.src, g.dst, inbound);
    if (!remote) continue;
    const dst = remote.ip;
    const lookup = lookupOf(dst);
    const blocked = g.blocked;
    const threat = lookup.threats.length > 0;

    analyzed += g.c;
    connectionsTotal += g.c;
    if (blocked) blockedTotal += g.c;
    if (threat) threatConnections += g.c;

    let acc = ips.get(dst);
    if (!acc && ips.size < MAX_IPS_TRACKED) {
      acc = { ip: dst, lookup, connections: 0, blocked: 0, bytes: 0, sources: new Map(), lastSeen: null };
      ips.set(dst, acc);
    }
    if (acc) {
      acc.connections += g.c;
      if (blocked) acc.blocked += g.c;
      acc.bytes += g.bytes;
      if (remote.peer && (acc.sources.has(remote.peer) || acc.sources.size < 50)) {
        acc.sources.set(remote.peer, (acc.sources.get(remote.peer) ?? 0) + g.c);
      }
      if (g.last && (!acc.lastSeen || g.last > acc.lastSeen)) acc.lastSeen = g.last;
    }

    if (!lookup.country) {
      unknownConnections += g.c;
    } else {
      let c = countries.get(lookup.country);
      if (!c) {
        c = {
          code: lookup.country,
          connections: 0,
          blocked: 0,
          bytes: 0,
          ips: 0,
          threatIps: 0,
          ipSet: new Set(),
          threatSet: new Set(),
        };
        countries.set(lookup.country, c);
      }
      c.connections += g.c;
      if (blocked) c.blocked += g.c;
      c.bytes += g.bytes;
      c.ipSet.add(dst);
      if (threat) c.threatSet.add(dst);
    }
  }

  // Partículas do tempo real: cada uma é uma conexão recente de verdade
  for (const ev of recentSource) {
    if (ev.action === 'system') continue;
    const remote = remoteOfPair(ev.srcIp, ev.dstIp, inbound);
    if (!remote) continue;
    const seen = ev.ingestedAt || ev.timestamp || null;
    const ms = seen ? Date.parse(seen) : NaN;
    if (!Number.isFinite(ms) || ms <= flowCutoff || recent.length >= 20_000) continue;
    const lookup = lookupOf(remote.ip);
    if (!lookup.country) continue;
    recent.push({
      at: seen as string,
      country: lookup.country,
      blocked: isBlocked(ev.action),
      threat: lookup.threats.length > 0,
      ms,
    });
  }

  const countryList: BehaviorCountry[] = [...countries.values()]
    .map(({ ipSet, threatSet, ...c }) => ({ ...c, ips: ipSet.size, threatIps: threatSet.size }))
    .sort((a, b) => b.connections - a.connections);

  const toIp = (a: IpAcc): BehaviorIp => ({
    ip: a.ip,
    country: a.lookup.country,
    asn: a.lookup.asn,
    asnOrg: a.lookup.asnOrg,
    connections: a.connections,
    blocked: a.blocked,
    bytes: a.bytes,
    threats: [...new Set(a.lookup.threats.map((t) => t.list))],
    categories: [...new Set(a.lookup.threats.map((t) => t.category))] as BehaviorThreatCategory[],
    topSources: [...a.sources.entries()]
      .sort((x, y) => y[1] - x[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count })),
    lastSeen: a.lastSeen,
  });

  const all = [...ips.values()].sort((a, b) => b.connections - a.connections);
  recent.sort((a, b) => a.ms - b.ms);
  const flowsSampleEvery = Math.max(1, Math.ceil(recent.length / MAX_FLOWS));
  const flows: BehaviorFlow[] = recent
    .filter((_, i) => i % flowsSampleEvery === 0)
    .map(({ ms: _ms, ...f }) => f);

  return {
    generatedAt: new Date().toISOString(),
    minutes: params.minutes,
    origin: params.origin,
    analyzedEvents: analyzed,
    publicIps: ips.size,
    totals: {
      connections: connectionsTotal,
      blocked: blockedTotal,
      countries: countryList.length,
      threatConnections,
      unknownConnections,
    },
    countries: countryList,
    ips: all.slice(0, 150).map(toIp),
    threats: all.filter((a) => a.lookup.threats.length > 0).slice(0, 100).map(toIp),
    flows,
    flowsTotal: recent.length,
    flowsSampleEvery,
    intel: intelStatus(intel),
    dataSource: params.dataSource,
    truncated: params.truncated,
  };
}

const intelStatus = (intel: Intel) => intel.status();

// --- País do firewall, descoberto automaticamente -----------------------------------------------------

/**
 * Descobre onde o firewall está sem configuração: 1) IP público de uma interface WAN; 2) IP de origem
 * traduzido (NAT) mais frequente nos logs, que é o IP público que a internet enxerga; 3) Brasil.
 */
export function detectOrigin(events: SyslogEvent[], wanIps: string[], intel: Intel): BehaviorOrigin {
  for (const ip of wanIps) {
    if (isIpAddress(ip) && ipScope(ip) === 'public') {
      const country = intel.lookup(ip).country;
      if (country) return { country, ip, source: 'wan' };
    }
  }
  const counts = new Map<string, number>();
  for (const ev of events) {
    const ip = (ev.natSrcIp || '').trim();
    if (!ip || !isIpAddress(ip) || ipScope(ip) !== 'public') continue;
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  for (const [ip] of sorted.slice(0, 5)) {
    const country = intel.lookup(ip).country;
    if (country) return { country, ip, source: 'nat' };
  }
  return { country: FALLBACK_ORIGIN, ip: null, source: 'fallback' };
}
