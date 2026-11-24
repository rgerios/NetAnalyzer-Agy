import {
  classifyDestination,
  cleanHost,
  extractDestinationHints,
  ipScope,
  isIpAddress,
  registrableDomain,
  serviceLabel,
  type DestinationNode,
  type DestinationsReport,
} from '../shared/destinations.ts';
import { subnetGroup, type SourceNode, type SourcesReport } from '../shared/sources.ts';
import { portMatches, hasPortFilter, type PortFilterSpec } from '../shared/ports.ts';
import type { SyslogEvent } from './types.ts';

interface Accumulator {
  id: string;
  host: string | null;
  hostSource: 'log' | 'rdns' | null;
  ips: Map<string, number>;
  scope: ReturnType<typeof ipScope>;
  connections: number;
  blocked: number;
  bytes: number;
  sources: Map<string, number>;
  services: Map<string, number>;
  appCategories: Map<string, number>;
  lastSeen: string | null;
}

const MAX_SOURCES_TRACKED = 2000;

const bump = (map: Map<string, number>, key: string) => map.set(key, (map.get(key) ?? 0) + 1);
const topKey = (map: Map<string, number>): string | null => {
  let best: string | null = null;
  let bestCount = -1;
  for (const [k, v] of map) if (v > bestCount) [best, bestCount] = [k, v];
  return best;
};


/**
 * Conexões já agregadas (origem, destino, serviço, bloqueio…). O banco entrega as linhas somadas sobre
 * o período inteiro; sem banco, `rowsFromEvents` faz o mesmo com os eventos em memória.
 */
export interface RadarRow {
  src: string;
  srcZone: string;
  user: string;
  dst: string;
  /** FQDN que o firewall registrou no log (já limpo). */
  host: string | null;
  appCategory: string | null;
  proto: string;
  port: number | null;
  app: string;
  blocked: boolean;
  c: number;
  bytes: number;
  last: string | null;
}

const isBlockedAction = (a: string) => a === 'drop' || a === 'deny' || a === 'reset';

export function rowsFromEvents(events: SyslogEvent[]): RadarRow[] {
  const map = new Map<string, RadarRow>();
  for (const ev of events) {
    if (!isTrafficEvent(ev)) continue;
    const hints = extractDestinationHints(ev.raw);
    const blocked = isBlockedAction(ev.action);
    const src = (ev.srcIp || '').trim();
    const dst = ev.dstIp.trim();
    const zone = ev.srcZone && ev.srcZone !== '-' ? ev.srcZone : '';
    const user = ev.user || '';
    const app = ev.appName || '';
    const key = `${src}|${zone}|${user}|${dst}|${hints.host ?? ''}|${hints.appCategory ?? ''}|${ev.protocol}|${ev.dstPort ?? ''}|${app}|${blocked ? 1 : 0}`;
    let r = map.get(key);
    if (!r) {
      r = {
        src, srcZone: zone, user, dst, host: hints.host, appCategory: hints.appCategory,
        proto: ev.protocol, port: ev.dstPort, app, blocked, c: 0, bytes: 0, last: null,
      };
      map.set(key, r);
    }
    r.c += 1;
    r.bytes += (ev.bytesSent || 0) + (ev.bytesRcvd || 0);
    const seen = ev.ingestedAt || ev.timestamp || null;
    if (seen && (!r.last || seen > r.last)) r.last = seen;
  }
  return [...map.values()];
}

/** Linha devolvida pelo banco (`aggregateRadar`) para o formato interno. */
export function rowFromDb(r: {
  src: string; srcZone: string; user: string; dst: string; host: string; appCategory: string;
  proto: string; port: string; app: string; blocked: boolean; c: number; bytes: number; last: string | null;
}): RadarRow {
  const port = /^\d{1,5}$/.test(r.port) ? Number(r.port) : null;
  return {
    src: r.src,
    srcZone: r.srcZone && r.srcZone !== '-' ? r.srcZone : '',
    user: r.user,
    dst: r.dst,
    host: r.host ? cleanHost(r.host) : null,
    appCategory: r.appCategory || null,
    proto: r.proto,
    port,
    app: r.app,
    blocked: r.blocked,
    c: r.c,
    bytes: r.bytes,
    last: r.last,
  };
}

const bumpN = (map: Map<string, number>, key: string, n: number) => map.set(key, (map.get(key) ?? 0) + n);

function isTrafficRow(r: RadarRow): boolean {
  const ip = (r.dst || '').trim();
  return Boolean(ip) && ip !== '-' && isIpAddress(ip);
}

function isTrafficEvent(ev: SyslogEvent): boolean {
  if (ev.action === 'system') return false;
  const ip = (ev.dstIp || '').trim();
  return Boolean(ip) && ip !== '-' && isIpAddress(ip);
}

/**
 * Agrupa as conexões por destino (FQDN quando conhecido, senão IP). `lookupHost` devolve o FQDN
 * em cache do DNS reverso para um IP público, ou nada se ainda não foi resolvido.
 */
export function buildDestinationNodes(
  events: SyslogEvent[],
  options: { lookupHost?: (ip: string) => string | null | undefined; maxNodes?: number } = {}
): { nodes: DestinationNode[]; omitted: { destinations: number; connections: number }; analyzed: number } {
  return buildDestinationNodesFromRows(rowsFromEvents(events), options);
}

export function buildDestinationNodesFromRows(
  rows: RadarRow[],
  options: { lookupHost?: (ip: string) => string | null | undefined; maxNodes?: number } = {}
): { nodes: DestinationNode[]; omitted: { destinations: number; connections: number }; analyzed: number } {
  const maxNodes = options.maxNodes ?? 150;
  const acc = new Map<string, Accumulator>();
  let analyzed = 0;

  for (const r of rows) {
    if (!isTrafficRow(r)) continue;
    analyzed += r.c;
    const ip = r.dst.trim();
    const scope = ipScope(ip);
    let host = r.host;
    let hostSource: 'log' | 'rdns' | null = host ? 'log' : null;
    if (!host && scope === 'public') {
      const cached = options.lookupHost?.(ip);
      if (cached) {
        host = cached;
        hostSource = 'rdns';
      }
    }
    const id = host ?? ip.toLowerCase();
    let a = acc.get(id);
    if (!a) {
      a = {
        id,
        host,
        hostSource,
        ips: new Map(),
        scope,
        connections: 0,
        blocked: 0,
        bytes: 0,
        sources: new Map(),
        services: new Map(),
        appCategories: new Map(),
        lastSeen: null,
      };
      acc.set(id, a);
    }
    a.connections += r.c;
    if (r.blocked) a.blocked += r.c;
    a.bytes += r.bytes;
    bumpN(a.ips, ip, r.c);
    if (r.src && (a.sources.has(r.src) || a.sources.size < MAX_SOURCES_TRACKED)) bumpN(a.sources, r.src, r.c);
    bumpN(a.services, serviceLabel(r.proto, r.port, r.app || null), r.c);
    if (r.appCategory) bumpN(a.appCategories, r.appCategory, r.c);
    if (r.last && (!a.lastSeen || r.last > a.lastSeen)) a.lastSeen = r.last;
  }

  const all: DestinationNode[] = [...acc.values()].map((a) => {
    const topService = topKey(a.services) ?? 'Outro';
    const host = a.host;
    return {
      id: a.id,
      label: host ?? a.id,
      host,
      hostSource: a.hostSource,
      ip: topKey(a.ips) ?? '',
      ips: [...a.ips.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5).map(([ip]) => ip),
      group: host ? registrableDomain(host) : null,
      scope: a.scope,
      category: classifyDestination({
        host,
        service: topService,
        appCategory: topKey(a.appCategories),
        scope: a.scope,
      }),
      connections: a.connections,
      blocked: a.blocked,
      bytes: a.bytes,
      sources: a.sources.size,
      topSources: [...a.sources.entries()]
        .sort((x, y) => y[1] - x[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
      services: [...a.services.entries()]
        .sort((x, y) => y[1] - x[1])
        .slice(0, 5)
        .map(([name, count]) => ({ name, count })),
      lastSeen: a.lastSeen,
    };
  });

  all.sort((x, y) => y.connections - x.connections || y.bytes - x.bytes);
  const nodes = all.slice(0, maxNodes);
  const rest = all.slice(maxNodes);
  return {
    nodes,
    omitted: { destinations: rest.length, connections: rest.reduce((s, n) => s + n.connections, 0) },
    analyzed,
  };
}

export function buildDestinationsReport(params: {
  events?: SyslogEvent[];
  /** Conexões já agregadas (agregação do banco). Têm prioridade sobre `events`. */
  rows?: RadarRow[];
  minutes: number;
  windowSize: number;
  lookupHost?: (ip: string) => string | null | undefined;
  resolver: { enabled: boolean; resolved: number; pending: number };
  maxNodes?: number;
}): DestinationsReport {
  const { nodes, omitted, analyzed } = buildDestinationNodesFromRows(params.rows ?? rowsFromEvents(params.events ?? []), {
    lookupHost: params.lookupHost,
    maxNodes: params.maxNodes,
  });
  return {
    generatedAt: new Date().toISOString(),
    minutes: params.minutes,
    analyzedEvents: analyzed,
    windowSize: params.windowSize,
    totalConnections: nodes.reduce((s, n) => s + n.connections, 0) + omitted.connections,
    resolver: params.resolver,
    nodes,
    omitted,
  };
}

/** IPs de origem aceitos no filtro: só caracteres de IPv4/IPv6 (ou prefixos deles). */
export function normalizeSourceFilter(raw: unknown): string | null {
  const value = String(raw ?? '').trim().toLowerCase();
  if (!value) return '';
  if (value.length > 45 || !/^[0-9a-f:.]+$/.test(value)) return null;
  return value;
}

/** Mantém só os eventos cujo IP de origem contém o texto do filtro (mesma regra da tela de Syslogs). */
export function filterEventsBySource(events: SyslogEvent[], srcIp: string): SyslogEvent[] {
  if (!srcIp) return events;
  return events.filter((ev) => (ev.srcIp || '').toLowerCase().includes(srcIp));
}

// ---------------------------------------------------------------------------
// Filtro por destino (nome, domínio ou IP) e consumo por origem
// ---------------------------------------------------------------------------

export interface DestinationFilter {
  /** Nome/domínio (contém) ou IP/prefixo digitado. */
  text: string;
  /** IPs exatos do destino clicado (os IPs mais frequentes do balão). */
  ips: string[];
}

const IP_LIKE = /^[0-9a-f:.]+$/;

/**
 * Valida o filtro de destino vindo da URL: texto só com caracteres de nome de host/IP e até 10 IPs.
 * Devolve null se algo for inválido (a rota responde 400).
 */
export function normalizeDestinationFilter(rawText: unknown, rawIps: unknown): DestinationFilter | null {
  const text = String(rawText ?? '').trim().toLowerCase();
  if (text && (text.length > 253 || !/^[a-z0-9._:-]+$/.test(text))) return null;
  const ips: string[] = [];
  for (const part of String(rawIps ?? '').split(',')) {
    const ip = normalizeSourceFilter(part);
    if (ip === null) return null;
    if (ip && !ips.includes(ip)) ips.push(ip);
  }
  if (ips.length > 10) return null;
  return { text, ips };
}

export function hasDestinationFilter(f: DestinationFilter): boolean {
  return Boolean(f.text) || f.ips.length > 0;
}

/**
 * O evento é do destino filtrado? Regras:
 * - texto parecido com IP: o IP do evento contém o texto (ou está na lista de IPs);
 * - texto de nome: se o evento tem nome conhecido (log ou DNS reverso) compara o nome (contém);
 *   sem nome, cai nos IPs exatos do destino clicado.
 * Quem tem nome conhecido não casa por IP: IPs de CDN são compartilhados por vários domínios.
 */
export function eventMatchesDestination(
  ev: SyslogEvent,
  filter: DestinationFilter,
  lookupHost?: (ip: string) => string | null | undefined
): boolean {
  if (!hasDestinationFilter(filter)) return true;
  const ip = (ev.dstIp || '').trim().toLowerCase();
  if (!ip) return false;
  const textIsIp = filter.text !== '' && IP_LIKE.test(filter.text);
  if (textIsIp) return ip.includes(filter.text) || filter.ips.includes(ip);
  if (filter.text) {
    let host = extractDestinationHints(ev.raw).host;
    if (!host && ipScope(ip) === 'public') host = lookupHost?.(ip) ?? null;
    if (host) return host.includes(filter.text);
  }
  return filter.ips.includes(ip);
}

export function filterEventsByDestination(
  events: SyslogEvent[],
  filter: DestinationFilter,
  lookupHost?: (ip: string) => string | null | undefined
): SyslogEvent[] {
  if (!hasDestinationFilter(filter)) return events;
  return events.filter((ev) => eventMatchesDestination(ev, filter, lookupHost));
}


export function filterRowsBySource(rows: RadarRow[], srcIp: string): RadarRow[] {
  if (!srcIp) return rows;
  return rows.filter((r) => (r.src || '').toLowerCase().includes(srcIp));
}

/** Mesma regra de `eventMatchesDestination`, sobre conexões agregadas. */
export function rowMatchesDestination(
  r: RadarRow,
  filter: DestinationFilter,
  lookupHost?: (ip: string) => string | null | undefined
): boolean {
  if (!hasDestinationFilter(filter)) return true;
  const ip = (r.dst || '').trim().toLowerCase();
  if (!ip) return false;
  const textIsIp = filter.text !== '' && IP_LIKE.test(filter.text);
  if (textIsIp) return ip.includes(filter.text) || filter.ips.includes(ip);
  if (filter.text) {
    let host = r.host;
    if (!host && ipScope(ip) === 'public') host = lookupHost?.(ip) ?? null;
    if (host) return host.includes(filter.text);
  }
  return filter.ips.includes(ip);
}

export function filterRowsByDestination(
  rows: RadarRow[],
  filter: DestinationFilter,
  lookupHost?: (ip: string) => string | null | undefined
): RadarRow[] {
  if (!hasDestinationFilter(filter)) return rows;
  return rows.filter((r) => rowMatchesDestination(r, filter, lookupHost));
}

export function filterRowsByPort(rows: RadarRow[], spec: PortFilterSpec | null | undefined): RadarRow[] {
  if (!spec || !hasPortFilter(spec)) return rows;
  return rows.filter((r) => portMatches(spec, r.port));
}

interface SourceAccumulator {
  ip: string;
  connections: number;
  blocked: number;
  bytes: number;
  dests: Map<string, number>;
  categories: Map<string, number>;
  services: Map<string, number>;
  zones: Map<string, number>;
  users: Map<string, number>;
  lastSeen: string | null;
}

const MAX_DESTS_TRACKED = 2000;

/**
 * Agrupa as conexões pelo IP de origem: quem consome mais, para onde fala e que tipo de destino
 * acessa. O destino de cada conexão é resolvido igual ao do radar de destinos (FQDN ou IP).
 */
export function buildSourceNodes(
  events: SyslogEvent[],
  options: { lookupHost?: (ip: string) => string | null | undefined; maxNodes?: number } = {}
): { nodes: SourceNode[]; omitted: { sources: number; connections: number }; analyzed: number } {
  return buildSourceNodesFromRows(rowsFromEvents(events), options);
}

export function buildSourceNodesFromRows(
  rows: RadarRow[],
  options: { lookupHost?: (ip: string) => string | null | undefined; maxNodes?: number } = {}
): { nodes: SourceNode[]; omitted: { sources: number; connections: number }; analyzed: number } {
  const maxNodes = options.maxNodes ?? 150;
  const acc = new Map<string, SourceAccumulator>();
  let analyzed = 0;

  for (const r of rows) {
    if (!isTrafficRow(r)) continue;
    const src = (r.src || '').trim();
    if (!src || src === '-' || !isIpAddress(src)) continue;
    analyzed += r.c;

    const dstIp = r.dst.trim();
    const scope = ipScope(dstIp);
    let host = r.host;
    if (!host && scope === 'public') host = options.lookupHost?.(dstIp) ?? null;
    const destId = host ?? dstIp.toLowerCase();
    const service = serviceLabel(r.proto, r.port, r.app || null);

    let a = acc.get(src);
    if (!a) {
      a = {
        ip: src,
        connections: 0,
        blocked: 0,
        bytes: 0,
        dests: new Map(),
        categories: new Map(),
        services: new Map(),
        zones: new Map(),
        users: new Map(),
        lastSeen: null,
      };
      acc.set(src, a);
    }
    a.connections += r.c;
    if (r.blocked) a.blocked += r.c;
    a.bytes += r.bytes;
    if (a.dests.has(destId) || a.dests.size < MAX_DESTS_TRACKED) bumpN(a.dests, destId, r.c);
    bumpN(a.categories, classifyDestination({ host, service, appCategory: r.appCategory, scope }), r.c);
    bumpN(a.services, service, r.c);
    if (r.srcZone) bumpN(a.zones, r.srcZone, r.c);
    if (r.user) bumpN(a.users, r.user, r.c);
    if (r.last && (!a.lastSeen || r.last > a.lastSeen)) a.lastSeen = r.last;
  }

  const top = (map: Map<string, number>, n: number) =>
    [...map.entries()].sort((x, y) => y[1] - x[1]).slice(0, n);

  const all: SourceNode[] = [...acc.values()].map((a) => {
    const user = topKey(a.users);
    return {
      id: a.ip,
      ip: a.ip,
      label: a.ip,
      user,
      zone: topKey(a.zones) ?? '-',
      group: subnetGroup(a.ip),
      scope: ipScope(a.ip),
      connections: a.connections,
      blocked: a.blocked,
      bytes: a.bytes,
      destinations: a.dests.size,
      topDestinations: top(a.dests, 5).map(([label, count]) => ({ label, count })),
      categories: top(a.categories, 4).map(([name, count]) => ({ name, count })),
      services: top(a.services, 5).map(([name, count]) => ({ name, count })),
      lastSeen: a.lastSeen,
    };
  });

  all.sort((x, y) => y.connections - x.connections || y.bytes - x.bytes);
  const nodes = all.slice(0, maxNodes);
  const rest = all.slice(maxNodes);
  return {
    nodes,
    omitted: { sources: rest.length, connections: rest.reduce((s, n) => s + n.connections, 0) },
    analyzed,
  };
}

export function buildSourcesReport(params: {
  events?: SyslogEvent[];
  rows?: RadarRow[];
  minutes: number;
  windowSize: number;
  lookupHost?: (ip: string) => string | null | undefined;
  maxNodes?: number;
}): SourcesReport {
  const { nodes, omitted, analyzed } = buildSourceNodesFromRows(params.rows ?? rowsFromEvents(params.events ?? []), {
    lookupHost: params.lookupHost,
    maxNodes: params.maxNodes,
  });
  return {
    generatedAt: new Date().toISOString(),
    minutes: params.minutes,
    analyzedEvents: analyzed,
    windowSize: params.windowSize,
    totalConnections: nodes.reduce((s, n) => s + n.connections, 0) + omitted.connections,
    nodes,
    omitted,
  };
}
