/** Filtros próprios dos access logs do ALB: método, endpoint, host, target group, IP do target e status HTTP. */
import type { SyslogEvent } from './types.ts';

export interface HttpFilter {
  /** Métodos exatos (GET, POST…). */
  methods: string[];
  /** Trecho do caminho (aceita também o agrupado, ex.: {id}). */
  endpoint: string;
  host: string;
  targetGroup: string;
  targetIp: string;
  /** Códigos exatos ("502") ou classes ("5xx"). */
  statuses: string[];
  /** WAF: trecho do Rule ID (inclui a regra interna do grupo gerenciado). */
  ruleId: string;
  /** WAF: nome do Web ACL. */
  webAcl: string;
  /** WAF: ações exatas (ALLOW, BLOCK, COUNT, CAPTCHA, CHALLENGE). */
  wafActions: string[];
}

const MAX = 200;
const text = (v: unknown): string => (typeof v === 'string' ? v.trim().toLowerCase().slice(0, MAX) : '');
const list = (v: unknown): string[] =>
  (typeof v === 'string' ? v : '')
    .split(/[,\s]+/)
    .map((x) => x.trim())
    .filter(Boolean)
    .slice(0, 12);

/** Lê os parâmetros da consulta; devolve null quando nenhum filtro de HTTP foi informado. */
export function parseHttpFilter(query: Record<string, unknown>): HttpFilter | null {
  const f: HttpFilter = {
    methods: list(query.method).map((m) => m.toUpperCase()).filter((m) => /^[A-Z]{3,8}$/.test(m)),
    endpoint: text(query.endpoint),
    host: text(query.host),
    targetGroup: text(query.targetGroup),
    targetIp: text(query.targetIp),
    statuses: list(query.status).map((s) => s.toLowerCase()).filter((s) => /^[1-5]\d{2}$|^[1-5]xx$/.test(s)),
    ruleId: text(query.ruleId),
    webAcl: text(query.webAcl),
    wafActions: list(query.wafAction).map((a) => a.toUpperCase()).filter((a) => /^(ALLOW|BLOCK|COUNT|CAPTCHA|CHALLENGE)$/.test(a)),
  };
  const any =
    f.methods.length || f.endpoint || f.host || f.targetGroup || f.targetIp || f.statuses.length || f.ruleId || f.webAcl || f.wafActions.length;
  return any ? f : null;
}

const str = (v: unknown): string => (v === undefined || v === null ? '' : String(v));

export const statusMatches = (status: string, tokens: string[]): boolean =>
  tokens.some((t) => (t.endsWith('xx') ? status.startsWith(t[0]) : status === t));

/** Mesma regra que o banco aplica, para o modo sem PostgreSQL. */
export function httpFilterMatches(ev: SyslogEvent, f: HttpFilter): boolean {
  const m = ev.meta;
  if (!m || m.method === undefined) return false;
  if (f.methods.length && !f.methods.includes(str(m.method).toUpperCase())) return false;
  if (f.endpoint) {
    const hit = [m.path, m.pathGroup, m.uri, m.uriGroup].some((v) => str(v).toLowerCase().includes(f.endpoint));
    if (!hit) return false;
  }
  if (f.host && !str(m.host).toLowerCase().includes(f.host)) return false;
  if (f.targetGroup && !str(m.targetGroup).toLowerCase().includes(f.targetGroup)) return false;
  if (f.targetIp && !str(m.targetIp).toLowerCase().includes(f.targetIp)) return false;
  if (f.statuses.length && !statusMatches(str(m.status), f.statuses)) return false;
  if (f.ruleId && !(str(m.ruleId).toLowerCase().includes(f.ruleId) || str(m.innerRule).toLowerCase().includes(f.ruleId))) return false;
  if (f.webAcl && !str(m.webAcl).toLowerCase().includes(f.webAcl)) return false;
  if (f.wafActions.length && !f.wafActions.includes(str(m.wafAction).toUpperCase())) return false;
  return true;
}
