/**
 * Análise de aplicação dos access logs do ALB: status, latência, endpoints, navegadores, TLS, WAF e
 * targets. O banco devolve linhas já agregadas; sem banco, `rowsFromAlbEvents` faz o mesmo em memória.
 */
import { resolveEventTimeMs } from './engineHelpers.ts';
import type { HttpEndpointRow, HttpInsights, HttpSlowRequest, HttpTargetRow } from '../shared/httpInsights.ts';
import type { SyslogEvent } from './types.ts';

/** Limites (s) do histograma de tempo: 8 faixas, a última é "5 s ou mais". */
export const HIST_EDGES_S = [0.05, 0.1, 0.25, 0.5, 1, 2, 5];
export const HIST_LABELS = ['< 50 ms', '50–100 ms', '100–250 ms', '250–500 ms', '0,5–1 s', '1–2 s', '2–5 s', '≥ 5 s'];

export const histBucketOf = (seconds: number): number => {
  for (let i = 0; i < HIST_EDGES_S.length; i += 1) if (seconds < HIST_EDGES_S[i]) return i;
  return HIST_EDGES_S.length;
};

/** Agregado por endpoint, status, target e WAF. */
export interface HttpGroup {
  host: string;
  method: string;
  path: string;
  status: string;
  targetIp: string;
  targetGroup: string;
  waf: string;
  c: number;
  /** Soma e máximo do tempo total (segundos). */
  sumTime: number;
  maxTime: number;
  slow: number;
  up: number;
  down: number;
  /** Soma de cada etapa (segundos): cliente → ALB, target e resposta. */
  sumReq: number;
  sumTgt: number;
  sumResp: number;
  /** Requisições com envio do corpo ≥ 1 s. */
  clientSlow: number;
  /** Histogramas (8 faixas) do tempo total e do tempo do target. */
  hist: number[];
  tHist: number[];
}

/** Agregado por navegador e TLS. */
export interface HttpClientGroup {
  ua: string;
  tls: string;
  cipher: string;
  c: number;
  errors: number;
}

export interface HttpExtras {
  slowRequests: HttpSlowRequest[];
  timeline: Array<{ t: string; requests: number; errors5xx: number; sumTgt: number; maxTime: number }>;
  tlsReused: number;
}

export const SLOW_THRESHOLD_S = 2;
export const CLIENT_SLOW_S = 1;
export const emptyHist = (): number[] => new Array(HIST_EDGES_S.length + 1).fill(0);

const num = (v: unknown): number => {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
};
const str = (v: unknown): string => (typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v));

/** Percentil estimado pelo histograma (interpola dentro da faixa; a última usa o máximo observado). */
export function percentileFromHist(hist: number[], p: number, maxSeconds: number): number {
  const total = hist.reduce((a, b) => a + b, 0);
  if (total === 0) return 0;
  const target = p * total;
  let cum = 0;
  for (let i = 0; i < hist.length; i += 1) {
    if (hist[i] === 0) continue;
    if (cum + hist[i] >= target) {
      const lo = i === 0 ? 0 : HIST_EDGES_S[i - 1];
      const hi = i < HIST_EDGES_S.length ? HIST_EDGES_S[i] : Math.max(maxSeconds, lo);
      return lo + (hi - lo) * ((target - cum) / hist[i]);
    }
    cum += hist[i];
  }
  return maxSeconds;
}

const SLOW_LIST = 10;

/** Eventos do ALB (os que têm metadados HTTP) → linhas agregadas, no mesmo formato do banco. */
export function rowsFromAlbEvents(
  events: SyslogEvent[],
  bucketSec = 3600
): { groups: HttpGroup[]; clients: HttpClientGroup[]; extras: HttpExtras } {
  const groups = new Map<string, HttpGroup>();
  const clients = new Map<string, HttpClientGroup>();
  const tl = new Map<string, HttpExtras['timeline'][number]>();
  const slowList: Array<HttpSlowRequest & { total: number }> = [];
  let tlsReused = 0;
  for (const ev of events) {
    const m = ev.meta;
    // só o access log do ALB: o WAF também grava método e host, mas não status, tempos nem bytes
    if (!m || m.method === undefined || ev.categoryName !== 'Application Load Balancer') continue;
    const status = str(m.status);
    const total = num(m.totalTime);
    const reqT = num(m.reqTime);
    const tgtT = num(m.targetTime);
    const respT = num(m.respTime);
    const key = [m.host, m.method, m.pathGroup ?? m.path, status, m.targetIp, m.targetGroup, m.wafActions].map(str).join('|');
    let g = groups.get(key);
    if (!g) {
      g = {
        host: str(m.host), method: str(m.method), path: str(m.pathGroup ?? m.path), status, targetIp: str(m.targetIp),
        targetGroup: str(m.targetGroup), waf: str(m.wafActions), c: 0, sumTime: 0, maxTime: 0, slow: 0, up: 0, down: 0,
        sumReq: 0, sumTgt: 0, sumResp: 0, clientSlow: 0, hist: emptyHist(), tHist: emptyHist(),
      };
      groups.set(key, g);
    }
    g.c += 1;
    g.sumTime += total;
    g.maxTime = Math.max(g.maxTime, total);
    if (total >= SLOW_THRESHOLD_S) g.slow += 1;
    g.up += ev.bytesSent || 0;
    g.down += ev.bytesRcvd || 0;
    g.sumReq += reqT;
    g.sumTgt += tgtT;
    g.sumResp += respT;
    if (reqT >= CLIENT_SLOW_S) g.clientSlow += 1;
    g.hist[histBucketOf(total)] += 1;
    g.tHist[histBucketOf(tgtT)] += 1;
    if (m.tlsReused === true) tlsReused += 1;

    const ck = `${str(m.uaFamily)}|${str(m.tlsVersion)}|${str(m.tlsCipher)}`;
    let c = clients.get(ck);
    if (!c) {
      c = { ua: str(m.uaFamily), tls: str(m.tlsVersion), cipher: str(m.tlsCipher), c: 0, errors: 0 };
      clients.set(ck, c);
    }
    c.c += 1;
    if (num(status) >= 500) c.errors += 1;

    const ms0 = resolveEventTimeMs(ev);
    if (Number.isFinite(ms0)) {
      const t = new Date(Math.floor(ms0 / (bucketSec * 1000)) * bucketSec * 1000).toISOString();
      const b = tl.get(t) ?? { t, requests: 0, errors5xx: 0, sumTgt: 0, maxTime: 0 };
      b.requests += 1;
      if (num(status) >= 500) b.errors5xx += 1;
      b.sumTgt += tgtT;
      b.maxTime = Math.max(b.maxTime, total);
      tl.set(t, b);
    }
    slowList.push({
      at: new Date(ms0).toISOString(), method: str(m.method), host: str(m.host), path: str(m.path),
      client: ev.srcIp, status, totalMs: Math.round(total * 1000), requestMs: Math.round(reqT * 1000),
      targetMs: Math.round(tgtT * 1000), targetIp: str(m.targetIp), traceId: str(m.traceId), total,
    });
    if (slowList.length > 200) {
      slowList.sort((a, b) => b.total - a.total);
      slowList.length = SLOW_LIST;
    }
  }
  slowList.sort((a, b) => b.total - a.total);
  return {
    groups: [...groups.values()],
    clients: [...clients.values()],
    extras: {
      slowRequests: slowList.slice(0, SLOW_LIST).map(({ total: _t, ...r }) => r),
      timeline: [...tl.values()].sort((a, b) => a.t.localeCompare(b.t)),
      tlsReused,
    },
  };
}

const ms = (seconds: number) => Math.round(seconds * 1000);

export function buildHttpInsights(params: {
  groups: HttpGroup[];
  clients: HttpClientGroup[];
  extras?: HttpExtras;
  minutes: number;
  dataSource: 'memory' | 'database';
  truncated: boolean;
}): HttpInsights {
  const { groups, clients } = params;
  const extras: HttpExtras = params.extras ?? { slowRequests: [], timeline: [], tlsReused: 0 };
  let requests = 0;
  let sumTime = 0;
  let maxTime = 0;
  let slow = 0;
  let bytesIn = 0;
  let bytesOut = 0;
  let sumReq = 0;
  let sumTgt = 0;
  let sumResp = 0;
  let clientSlow = 0;
  const hist = emptyHist();
  const tHist = emptyHist();
  const status = { s2xx: 0, s3xx: 0, s4xx: 0, s5xx: 0, other: 0 };
  const codes = new Map<string, number>();
  const waf = { evaluated: 0, forwarded: 0, blocked: 0 };

  interface EpAcc extends Omit<HttpEndpointRow, 'p95Ms'> { sum: number; hist: number[] }
  const endpoints = new Map<string, EpAcc>();
  interface TgAcc { ip: string; group: string; requests: number; errors5xx: number; sum: number }
  const targets = new Map<string, TgAcc>();
  const hosts = new Map<string, number>();

  for (const g of groups) {
    requests += g.c;
    sumTime += g.sumTime;
    maxTime = Math.max(maxTime, g.maxTime);
    slow += g.slow;
    bytesIn += g.up;
    bytesOut += g.down;
    sumReq += g.sumReq;
    sumTgt += g.sumTgt;
    sumResp += g.sumResp;
    clientSlow += g.clientSlow;
    g.hist.forEach((n, i) => { hist[i] += n; });
    g.tHist.forEach((n, i) => { tHist[i] += n; });
    const code = num(g.status);
    if (code >= 200 && code < 300) status.s2xx += g.c;
    else if (code >= 300 && code < 400) status.s3xx += g.c;
    else if (code >= 400 && code < 500) status.s4xx += g.c;
    else if (code >= 500) status.s5xx += g.c;
    else status.other += g.c;
    if (g.status) codes.set(g.status, (codes.get(g.status) ?? 0) + g.c);

    const w = g.waf.toLowerCase();
    if (w.includes('waf')) {
      waf.evaluated += g.c;
      if (w.includes('forward')) waf.forwarded += g.c;
      else waf.blocked += g.c;
    }

    const ek = `${g.host}|${g.method}|${g.path}`;
    let e = endpoints.get(ek);
    if (!e) {
      e = { host: g.host, method: g.method, path: g.path, requests: 0, errors4xx: 0, errors5xx: 0, avgMs: 0, maxMs: 0, slow: 0, bytesIn: 0, bytesOut: 0, sum: 0, hist: emptyHist() };
      endpoints.set(ek, e);
    }
    e.requests += g.c;
    if (code >= 400 && code < 500) e.errors4xx += g.c;
    if (code >= 500) e.errors5xx += g.c;
    e.sum += g.sumTime;
    e.maxMs = Math.max(e.maxMs, ms(g.maxTime));
    e.slow += g.slow;
    e.bytesIn += g.up;
    e.bytesOut += g.down;
    g.hist.forEach((n, i) => { e.hist[i] += n; });

    if (g.host) hosts.set(g.host, (hosts.get(g.host) ?? 0) + g.c);
    if (g.targetIp) {
      const tk = `${g.targetIp}|${g.targetGroup}`;
      let t = targets.get(tk);
      if (!t) {
        t = { ip: g.targetIp, group: g.targetGroup, requests: 0, errors5xx: 0, sum: 0 };
        targets.set(tk, t);
      }
      t.requests += g.c;
      if (code >= 500) t.errors5xx += g.c;
      t.sum += g.sumTime;
    }
  }

  const all: HttpEndpointRow[] = [...endpoints.values()].map(({ sum, hist: h, ...rest }) => ({
    ...rest,
    avgMs: rest.requests > 0 ? ms(sum / rest.requests) : 0,
    p95Ms: ms(percentileFromHist(h, 0.95, rest.maxMs / 1000)),
  }));
  const byRequests = [...all].sort((a, b) => b.requests - a.requests);
  const slowest = all.filter((e) => e.requests >= 3).sort((a, b) => b.avgMs - a.avgMs).slice(0, 10);
  const heaviest = [...all].sort((a, b) => b.bytesIn + b.bytesOut - (a.bytesIn + a.bytesOut)).slice(0, 10);
  const errors = all.filter((e) => e.errors5xx + e.errors4xx > 0).sort((a, b) => b.errors5xx - a.errors5xx || b.errors4xx - a.errors4xx).slice(0, 10);

  const ua = new Map<string, { requests: number; errors: number }>();
  const tls = new Map<string, number>();
  const ciphers = new Map<string, number>();
  let tlsTotal = 0;
  for (const c of clients) {
    const name = c.ua || 'Desconhecido';
    const u = ua.get(name) ?? { requests: 0, errors: 0 };
    u.requests += c.c;
    u.errors += c.errors;
    ua.set(name, u);
    if (c.tls) {
      tls.set(c.tls, (tls.get(c.tls) ?? 0) + c.c);
      tlsTotal += c.c;
    }
    if (c.cipher) ciphers.set(c.cipher, (ciphers.get(c.cipher) ?? 0) + c.c);
  }
  const top = <T>(m: Map<string, T>, count: (v: T) => number, n: number) => [...m.entries()].sort((a, b) => count(b[1]) - count(a[1])).slice(0, n);

  const targetRows: HttpTargetRow[] = [...targets.values()]
    .map((t) => ({ ip: t.ip, group: t.group, requests: t.requests, errors5xx: t.errors5xx, avgMs: t.requests > 0 ? ms(t.sum / t.requests) : 0 }))
    .sort((a, b) => b.requests - a.requests)
    .slice(0, 12);

  return {
    generatedAt: new Date().toISOString(),
    minutes: params.minutes,
    requests,
    dataSource: params.dataSource,
    truncated: params.truncated,
    status: { ...status, top: top(codes, (v) => v, 8).map(([code, count]) => ({ code, count })) },
    latency: {
      avgMs: requests > 0 ? ms(sumTime / requests) : 0,
      maxMs: ms(maxTime),
      slow,
      slowThresholdMs: SLOW_THRESHOLD_S * 1000,
      p50Ms: ms(percentileFromHist(hist, 0.5, maxTime)),
      p95Ms: ms(percentileFromHist(hist, 0.95, maxTime)),
      p99Ms: ms(percentileFromHist(hist, 0.99, maxTime)),
      targetAvgMs: requests > 0 ? ms(sumTgt / requests) : 0,
      targetP95Ms: ms(percentileFromHist(tHist, 0.95, maxTime)),
    },
    timeBreakdown: {
      requestMs: requests > 0 ? ms(sumReq / requests) : 0,
      targetMs: requests > 0 ? ms(sumTgt / requests) : 0,
      responseMs: requests > 0 ? ms(sumResp / requests) : 0,
    },
    clientSlow,
    distribution: HIST_LABELS.map((label, i) => ({ label, requests: hist[i] })),
    slowRequests: extras.slowRequests,
    timeline: extras.timeline.map((b) => ({
      t: b.t, requests: b.requests, errors5xx: b.errors5xx, avgTargetMs: b.requests > 0 ? ms(b.sumTgt / b.requests) : 0, maxMs: ms(b.maxTime),
    })),
    tlsReuse: { reused: extras.tlsReused, total: tlsTotal },
    waf,
    bytes: { in: bytesIn, out: bytesOut },
    endpoints: byRequests.slice(0, 20),
    slowest,
    heaviest,
    errors,
    userAgents: top(ua, (v) => v.requests, 10).map(([name, v]) => ({ name, ...v })),
    tls: top(tls, (v) => v, 6).map(([version, n]) => ({ version, requests: n })),
    ciphers: top(ciphers, (v) => v, 6).map(([name, n]) => ({ name, requests: n })),
    targets: targetRows,
    hosts: top(hosts, (v) => v, 8).map(([host, n]) => ({ host, requests: n })),
  };
}
