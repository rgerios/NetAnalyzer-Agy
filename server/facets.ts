import { resolveEventTimeMs } from './engineHelpers.ts';
/**
 * Facetas por tipo de log da AWS (VPC Flow Logs e WAF): "top N" de cada campo importante, com contagem,
 * bloqueios e bytes. O banco agrega sobre o período inteiro; sem banco, a mesma regra roda em memória.
 */
import type { AwsLogKind, FacetItem, FacetReport, FacetResult, FacetTimelinePoint, FacetTotals } from '../shared/awsFacets.ts';
import type { SyslogEvent } from './types.ts';

export type FacetField =
  | 'srcIp'
  | 'dstIp'
  | 'dstPort'
  | 'protocol'
  | 'interface'
  | 'srcZone'
  | 'dstZone'
  | 'appName'
  | 'ruleRef'
  | `meta:${string}`;

export interface FacetSpec {
  id: string;
  title: string;
  hint?: string;
  field: FacetField;
  /** Só conta eventos bloqueados ou só os permitidos (vazio = todos). */
  where?: 'blocked' | 'allowed';
  /** Ordena por contagem ou por bytes. */
  metric?: 'count' | 'bytes';
  /** O valor é um IP: a tela mostra o país. */
  ip?: boolean;
  /** O valor é um código de país. */
  country?: boolean;
  /** O valor é uma porta: a tela mostra o nome do serviço. */
  port?: boolean;
}

/** Largura de cada barra da linha do tempo conforme o período (períodos curtos pedem barras finas). */
export function bucketSecondsFor(minutes: number): number {
  if (minutes <= 0) return 6 * 3600;
  if (minutes <= 30) return 60;
  if (minutes <= 60) return 120;
  if (minutes <= 180) return 300;
  if (minutes <= 360) return 600;
  if (minutes <= 1440) return 3600;
  return 3 * 3600;
}

export const KIND_CATEGORY: Record<'alb' | AwsLogKind, string> = {
  alb: 'Application Load Balancer',
  albconn: 'Application Load Balancer',
  vpcflow: 'VPC Flow Logs',
  waf: 'AWS WAF',
};

/** Filtro extra por tipo: o connection log do ALB divide a categoria com o access log. */
export const KIND_SQL_FILTER: Partial<Record<AwsLogKind, string>> = {
  albconn: `payload_json#>>'{meta,connection}' = 'true'`,
};

export const FACETS: Record<AwsLogKind, FacetSpec[]> = {
  albconn: [
    { id: 'tlsv', title: 'Versões de TLS', field: 'meta:tlsVersion' },
    { id: 'kex', title: 'Troca de chaves', hint: 'X25519MLKEM768 é híbrida pós-quântica (clientes modernos, como Chrome e Cloudflare)', field: 'meta:tlsKeyExchange' },
    { id: 'cipher', title: 'Cifras TLS', field: 'meta:tlsCipher' },
    { id: 'hs', title: 'Latência do handshake TLS', hint: 'Tempo para estabelecer o TLS; tende a refletir a distância do cliente', field: 'meta:hsBucket' },
    { id: 'noTls', title: 'Origens sem handshake concluído', hint: 'Conexões que abriram e não negociaram TLS: sondagens, scanners ou clientes que desistiram', field: 'srcIp', where: 'blocked', ip: true },
    { id: 'conns', title: 'Quem mais abre conexões', field: 'srcIp', ip: true },
    { id: 'ports', title: 'Portas do listener', field: 'dstPort', port: true },
    { id: 'nodes', title: 'Nós do ALB', hint: 'Distribuição entre os IPs do balanceador (zonas de disponibilidade)', field: 'meta:nodeIp' },
    { id: 'verify', title: 'Verificação do certificado do cliente', field: 'meta:tlsVerify' },
  ],
  vpcflow: [
    { id: 'rejSrc', title: 'Origens rejeitadas', hint: 'IPs barrados pelo Security Group ou NACL (varreduras e tentativas de acesso)', field: 'srcIp', where: 'blocked', ip: true },
    { id: 'rejPorts', title: 'Portas mais rejeitadas', hint: 'Serviços que a internet tenta alcançar sem permissão', field: 'dstPort', where: 'blocked', port: true },
    { id: 'accPorts', title: 'Portas mais acessadas (aceitas)', field: 'dstPort', where: 'allowed', port: true },
    { id: 'topSrcBytes', title: 'Origens por volume', hint: 'Quem mais enviou dados (fluxos aceitos)', field: 'srcIp', where: 'allowed', metric: 'bytes', ip: true },
    { id: 'topDstBytes', title: 'Destinos por volume', field: 'dstIp', where: 'allowed', metric: 'bytes', ip: true },
    { id: 'enis', title: 'Interfaces (ENI)', field: 'interface' },
    { id: 'proto', title: 'Protocolos', field: 'protocol' },
    { id: 'dir', title: 'Direção do fluxo', field: 'meta:flowDirection' },
    { id: 'svc', title: 'Serviços AWS de destino', hint: 'Quando o log informa pkt-dst-aws-service', field: 'appName' },
    { id: 'subnets', title: 'Sub-redes', field: 'srcZone' },
    { id: 'az', title: 'Zonas de disponibilidade', field: 'meta:azId' },
  ],
  waf: [
    { id: 'actions', title: 'Ações do WAF', field: 'meta:wafAction' },
    { id: 'rules', title: 'Regras que mais bloquearam', field: 'ruleRef', where: 'blocked' },
    { id: 'inner', title: 'Regras dentro dos grupos gerenciados', hint: 'A regra específica que disparou dentro do grupo', field: 'meta:innerRule', where: 'blocked' },
    { id: 'ips', title: 'IPs bloqueados', field: 'srcIp', where: 'blocked', ip: true },
    { id: 'countries', title: 'Países dos bloqueios', field: 'srcZone', where: 'blocked', country: true },
    { id: 'uris', title: 'URIs mais atacadas', field: 'meta:uriGroup', where: 'blocked' },
    { id: 'methods', title: 'Métodos HTTP', field: 'meta:method' },
    { id: 'secTop', title: 'Credenciais expostas por tipo', hint: 'Detectadas nos cabeçalhos e na URL; o valor nunca é guardado', field: 'meta:secretTop' },
    { id: 'secRisk', title: 'Credenciais expostas por gravidade', field: 'meta:secretRisk' },
    { id: 'secEndpoint', title: 'Endpoints com credencial exposta', field: 'meta:secretEndpoint' },
    { id: 'auth', title: 'Autenticação usada', hint: 'Esquema do cabeçalho Authorization (o valor nunca é guardado). Basic envia usuário e senha a cada requisição', field: 'meta:authScheme' },
    { id: 'ctype', title: 'Tipos de conteúdo', field: 'meta:contentType' },
    { id: 'oversize', title: 'Corpo acima do limite inspecionado', hint: 'O WAF inspeciona só os primeiros 8 KB do corpo: uploads maiores passam sem inspeção do corpo', field: 'meta:oversize' },
    { id: 'ja4', title: 'Impressões TLS (JA4)', hint: 'Identifica o cliente pela forma do handshake: robôs mudam o User-Agent, mas não o JA4', field: 'meta:ja4' },
    { id: 'uas', title: 'Clientes bloqueados', field: 'meta:uaFamily', where: 'blocked' },
    { id: 'hosts', title: 'Hosts protegidos', field: 'dstIp' },
    { id: 'ruleTypes', title: 'Tipos de regra', field: 'meta:ruleType' },
    { id: 'acls', title: 'Web ACLs', field: 'interface' },
    { id: 'resp', title: 'Códigos de resposta enviados', field: 'meta:responseCode' },
  ],
};

const META_KEY = /^[A-Za-z0-9_]{1,40}$/;

/** Expressão SQL de um campo (só chaves conhecidas ou meta:nome seguro: sem texto livre do usuário). */
export function facetSql(field: FacetField): string {
  switch (field) {
    case 'srcIp': return `payload_json->>'srcIp'`;
    case 'dstIp': return `payload_json->>'dstIp'`;
    case 'dstPort': return `payload_json->>'dstPort'`;
    case 'protocol': return `split_part(COALESCE(payload_json->>'protocol', ''), '/', 1)`;
    case 'interface': return `payload_json->>'firewallHost'`;
    case 'srcZone': return `payload_json->>'srcZone'`;
    case 'dstZone': return `payload_json->>'dstZone'`;
    case 'appName': return `payload_json->>'appName'`;
    case 'ruleRef': return `payload_json->>'ruleRef'`;
    default: {
      const key = field.slice(5);
      if (!field.startsWith('meta:') || !META_KEY.test(key)) throw new Error(`Campo de faceta inválido: ${field}`);
      return `payload_json#>>'{meta,${key}}'`;
    }
  }
}

export function facetValue(ev: SyslogEvent, field: FacetField): string {
  let v: unknown;
  switch (field) {
    case 'srcIp': v = ev.srcIp; break;
    case 'dstIp': v = ev.dstIp; break;
    case 'dstPort': v = ev.dstPort; break;
    case 'protocol': v = (ev.protocol || '').toLowerCase().split('/')[0]; break;
    case 'interface': v = ev.firewallHost; break;
    case 'srcZone': v = ev.srcZone; break;
    case 'dstZone': v = ev.dstZone; break;
    case 'appName': v = ev.appName; break;
    case 'ruleRef': v = ev.ruleRef; break;
    default: v = ev.meta?.[field.slice(5)];
  }
  if (v === null || v === undefined) return '';
  return String(v);
}

export const isBlockedAction = (a: string): boolean => a === 'drop' || a === 'deny' || a === 'reset';

export type { FacetItem, FacetResult, FacetTotals, FacetTimelinePoint, FacetReport, AwsLogKind };

const ITEM_LIMIT = 12;
const usable = (v: string) => v !== '' && v !== '-';

/** Mesma agregação que o banco faz, sobre eventos em memória. */
export function facetsFromEvents(events: SyslogEvent[], kind: AwsLogKind, bucketSec = 3600): { totals: FacetTotals; timeline: FacetTimelinePoint[]; facets: FacetResult[] } {
  const category = KIND_CATEGORY[kind];
  const list = events.filter((e) => e.categoryName === category && e.action !== 'system' && (kind !== 'albconn' || e.meta?.connection === true));
  const totals: FacetTotals = { events: 0, blocked: 0, allowed: 0, bytes: 0, packets: 0 };
  const hours = new Map<string, FacetTimelinePoint>();
  for (const e of list) {
    const blocked = isBlockedAction(e.action);
    totals.events += 1;
    if (blocked) totals.blocked += 1;
    else totals.allowed += 1;
    totals.bytes += (e.bytesSent || 0) + (e.bytesRcvd || 0);
    totals.packets += Number(e.meta?.packets) || 0;
    const ms = resolveEventTimeMs(e);
    if (Number.isFinite(ms)) {
      const t = new Date(Math.floor(ms / (bucketSec * 1000)) * bucketSec * 1000).toISOString();
      const h = hours.get(t) ?? { t, allowed: 0, blocked: 0 };
      if (blocked) h.blocked += 1;
      else h.allowed += 1;
      hours.set(t, h);
    }
  }
  const facets: FacetResult[] = FACETS[kind].map((spec) => {
    const acc = new Map<string, FacetItem>();
    for (const e of list) {
      const blocked = isBlockedAction(e.action);
      if (spec.where === 'blocked' && !blocked) continue;
      if (spec.where === 'allowed' && blocked) continue;
      const key = facetValue(e, spec.field);
      if (!usable(key)) continue;
      const it = acc.get(key) ?? { key, count: 0, blocked: 0, bytes: 0 };
      it.count += 1;
      if (blocked) it.blocked += 1;
      it.bytes += (e.bytesSent || 0) + (e.bytesRcvd || 0);
      acc.set(key, it);
    }
    const metric = spec.metric ?? 'count';
    const items = [...acc.values()].sort((a, b) => (metric === 'bytes' ? b.bytes - a.bytes : b.count - a.count) || b.count - a.count).slice(0, ITEM_LIMIT);
    return { id: spec.id, title: spec.title, hint: spec.hint, metric, ip: spec.ip, country: spec.country, port: spec.port, items };
  });
  return { totals, timeline: [...hours.values()].sort((a, b) => a.t.localeCompare(b.t)), facets };
}

export const ITEM_LIMIT_FOR_DB = ITEM_LIMIT;
export const facetIsUsable = usable;

/** Linha do tempo (permitidos x bloqueados) somando os três recursos AWS. */
/**
 * Preenche com zeros os intervalos sem eventos, para o eixo do gráfico cobrir exatamente o período
 * escolhido (até "agora"). Sem período definido (minutes = 0) a série fica como veio.
 */
export function padTimeline<T extends { t: string }>(
  points: T[],
  minutes: number,
  bucketSec: number,
  empty: (t: string) => T,
  nowMs = Date.now()
): T[] {
  if (minutes <= 0) return points;
  const step = bucketSec * 1000;
  const byTime = new Map(points.map((p) => [Date.parse(p.t), p]));
  const out: T[] = [];
  for (let ms = Math.floor((nowMs - minutes * 60_000) / step) * step; ms <= nowMs; ms += step) {
    out.push(byTime.get(ms) ?? empty(new Date(ms).toISOString()));
  }
  return out;
}

export function timelineFromEvents(events: SyslogEvent[], bucketSec: number): FacetTimelinePoint[] {
  const cats = Object.values(KIND_CATEGORY);
  const map = new Map<string, FacetTimelinePoint>();
  for (const e of events) {
    if (e.action === 'system' || !cats.includes(e.categoryName)) continue;
    const ms = resolveEventTimeMs(e);
    if (!Number.isFinite(ms)) continue;
    const t = new Date(Math.floor(ms / (bucketSec * 1000)) * bucketSec * 1000).toISOString();
    const p = map.get(t) ?? { t, allowed: 0, blocked: 0 };
    if (isBlockedAction(e.action)) p.blocked += 1;
    else p.allowed += 1;
    map.set(t, p);
  }
  return [...map.values()].sort((a, b) => a.t.localeCompare(b.t));
}

/** Resumo por recurso (ALB, VPC Flow Logs, WAF) para os cartões da Visão Geral. */
export interface CategorySummary {
  category: string;
  events: number;
  blocked: number;
  errors5xx: number;
  bytes: number;
  lastAt: string | null;
}

export function summarizeCategories(events: SyslogEvent[]): CategorySummary[] {
  const map = new Map<string, CategorySummary>();
  for (const e of events) {
    if (e.action === 'system') continue;
    const cat = e.categoryName;
    if (!Object.values(KIND_CATEGORY).includes(cat)) continue;
    const s = map.get(cat) ?? { category: cat, events: 0, blocked: 0, errors5xx: 0, bytes: 0, lastAt: null };
    s.events += 1;
    if (isBlockedAction(e.action)) s.blocked += 1;
    if (Number(e.meta?.status) >= 500) s.errors5xx += 1;
    s.bytes += (e.bytesSent || 0) + (e.bytesRcvd || 0);
    const seen = e.ingestedAt || e.timestamp || null;
    if (seen && (!s.lastAt || seen > s.lastAt)) s.lastAt = seen;
    map.set(cat, s);
  }
  return [...map.values()];
}
