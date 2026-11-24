/**
 * Conversão dos logs da AWS (VPC Flow Logs, WAF e ALB) para o evento comum da plataforma,
 * para que Behavior, Acessos e Consumo, Destinos, portas e alertas funcionem como com os firewalls.
 */
import crypto from 'node:crypto';
import type { AwsSourceType } from '../shared/aws.ts';
import type { SyslogAction, SyslogEvent, SyslogSeverity } from '../shared/types.ts';

export interface AwsParseOptions {
  /** Instante de referência (testes). */
  nowMs?: number;
  /** Região padrão quando o log não informa. */
  region?: string;
  /** Chamado com cada linha que não pôde ser interpretada. */
  onSkip?: (line: string) => void;
}

export interface AwsParseResult {
  events: SyslogEvent[];
  /** Linhas que não puderam ser interpretadas. */
  skipped: number;
}

// ---------------------------------------------------------------------------
// Redação de segredos: logs de aplicação trazem tokens, senhas e cookies nos cabeçalhos e na query string.
// Nada disso deve ser gravado no banco nem aparecer na tela.
// ---------------------------------------------------------------------------

const SENSITIVE_HEADER = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-amz-security-token|x-sentry-auth)$|token|secret|passw|signature|session/i;
const SENSITIVE_PARAM = /token|key|pass|pwd|secret|auth|sig|session|cred|code|otp|bearer/i;
export const REDACTED = '[redigido]';

/** Mantém os nomes dos parâmetros e troca o valor dos que parecem segredo. */
export function redactQuery(text: string): string {
  return text.replace(/([?&;]|^)([^=&\s"'?;]{1,60})=([^&\s"';]*)/g, (m, sep: string, key: string, value: string) =>
    SENSITIVE_PARAM.test(key) && value ? `${sep}${key}=${REDACTED}` : m
  );
}

/** Redige segredos em texto já gravado (JSON possivelmente truncado): cabeçalhos sensíveis e query strings. */
export function redactRawString(text: string): string {
  const headerValue = /("name"\s*:\s*"(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-amz-security-token|x-sentry-auth|[^"]*(?:token|secret|passw|signature|session)[^"]*)"\s*,\s*"value"\s*:\s*")((?:[^"\\]|\\.)*)/gi;
  return redactQuery(text.replace(headerValue, `$1${REDACTED}`));
}

/** Esquema da autenticação sem expor o valor: Bearer, Basic, AWS SigV4, Sentry. */
function authSchemeOf(headers: Array<{ name?: string; value?: string }>): string {
  for (const h of headers) {
    const n = (h.name || '').toLowerCase();
    const v = (h.value || '').trim();
    if (n === 'authorization' && v) {
      const word = v.split(/\s+/)[0];
      return /^AWS4-/i.test(word) ? 'AWS SigV4' : /^bearer$/i.test(word) ? 'Bearer' : /^basic$/i.test(word) ? 'Basic' : word.slice(0, 20);
    }
    if (n === 'x-sentry-auth') return 'Sentry';
    if (n === 'x-api-key') return 'API key';
  }
  return 'Nenhuma';
}

/** Nível de cada tipo de exposição: critical/high = a aplicação deve corrigir; medium = boa prática; info = ajuste do log. */
export const SECRET_TYPES: Record<string, 'critical' | 'high' | 'medium' | 'info'> = {
  'Credencial em HTTP sem TLS': 'critical',
  'Basic Auth com senha fraca': 'critical',
  'Basic Auth': 'high',
  'Segredo na URL': 'high',
  'JWT com dados pessoais': 'medium',
  'Cookie de sessão': 'info',
  'JWT Bearer': 'info',
  'Chave de API': 'info',
  'Assinatura SigV4': 'info',
};
const RISK_ORDER = ['critical', 'high', 'medium', 'info'] as const;

const b64 = (s: string): string => {
  try {
    return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return '';
  }
};

const weakPassword = (pw: string): boolean => pw.length < 8 || /^\d+$/.test(pw) || /^(senha|password|admin|123456|qwerty)/i.test(pw);

/**
 * Detecta credenciais trafegando em cabeçalhos e na URL. Devolve só o TIPO e o nível: o valor nunca é guardado.
 * Basic Auth e segredo na URL são falhas da aplicação; cookie e JWT em cabeçalho são normais e só pedem redação no log.
 */
export function detectSecrets(
  headers: Array<{ name?: string; value?: string }>,
  query: string,
  scheme: string | undefined
): { types: string[]; top: string; risk: string } | null {
  const found = new Set<string>();
  for (const h of headers) {
    const n = (h.name || '').toLowerCase();
    const v = (h.value || '').trim();
    if (!v) continue;
    if (n === 'authorization') {
      const [word, rest = ''] = v.split(/\s+/);
      if (/^basic$/i.test(word)) {
        const dec = b64(rest);
        const pw = dec.includes(':') ? dec.slice(dec.indexOf(':') + 1) : '';
        found.add(pw && weakPassword(pw) ? 'Basic Auth com senha fraca' : 'Basic Auth');
      } else if (/^bearer$/i.test(word)) {
        found.add('JWT Bearer');
        const payload = b64(rest.split('.')[1] ?? '');
        if (/"[^"]*(nome|name|email|cpf|cnpj|phone|telefone|document)[^"]*"\s*:/i.test(payload)) found.add('JWT com dados pessoais');
      } else if (/^AWS4-/i.test(word)) {
        found.add('Assinatura SigV4');
      }
      if (String(scheme).toLowerCase() === 'http') found.add('Credencial em HTTP sem TLS');
    } else if (n === 'cookie' && /(session|login|auth|token|sid)[^=]*=/i.test(v)) {
      found.add('Cookie de sessão');
    } else if (n === 'x-api-key' || n === 'x-sentry-auth' || n === 'x-auth-token') {
      found.add('Chave de API');
    }
  }
  if (query && /(?:^|[?&;])[^=&]*(token|key|pass|pwd|secret|auth|sig|session|cred|otp|bearer)[^=&]*=[^&\s]+/i.test(query)) {
    found.add('Segredo na URL');
  }
  if (found.size === 0) return null;
  const types = [...found].sort((a, b) => RISK_ORDER.indexOf(SECRET_TYPES[a]) - RISK_ORDER.indexOf(SECRET_TYPES[b]));
  return { types, top: types[0], risk: SECRET_TYPES[types[0]] };
}

const contentTypeFamily = (ct: string | undefined): string => {
  const t = (ct || '').toLowerCase().split(';')[0].trim();
  if (!t) return '';
  if (t.includes('json')) return 'JSON';
  if (t.startsWith('image/')) return 'Imagem';
  if (t.includes('x-www-form-urlencoded') || t.includes('multipart')) return 'Formulário';
  if (t.includes('xml')) return 'XML';
  if (t.startsWith('text/')) return 'Texto';
  return t.slice(0, 40);
};

/** Registro do WAF em JSON seguro para guardar: cabeçalhos sensíveis redigidos, query e referer sem segredos. */
function sanitizeWafRecord(rec: Record<string, unknown>): string {
  const clone = JSON.parse(JSON.stringify(rec)) as {
    httpRequest?: { headers?: Array<{ name?: string; value?: string }>; args?: string };
  };
  const req = clone.httpRequest;
  if (req?.headers) {
    for (const h of req.headers) {
      const name = h.name || '';
      if (SENSITIVE_HEADER.test(name)) {
        const word = name.toLowerCase() === 'authorization' ? (h.value || '').trim().split(/\s+/)[0] : '';
        h.value = word && word.length < 24 ? `${word} ${REDACTED}` : REDACTED;
      } else if (/^referer$|^origin$/i.test(name) && h.value) {
        h.value = redactQuery(h.value);
      } else if (h.value && h.value.length > 300) {
        h.value = `${h.value.slice(0, 300)}…`;
      }
    }
  }
  if (req?.args) req.args = redactQuery(req.args);
  return JSON.stringify(clone);
}

const LIVE_WINDOW_MS = 15 * 60 * 1000;
const RAW_MAX = 1500;

function stamp(ms: number, nowMs: number): { timestamp: string; ingestedAt: string } {
  const iso = new Date(ms).toISOString();
  // Eventos recentes entram como "agora" (aparecem como novos); a carga antiga mantém a hora real
  return { timestamp: iso, ingestedAt: nowMs - ms < LIVE_WINDOW_MS ? new Date(nowMs).toISOString() : iso };
}

const PROTOCOLS: Record<string, string> = { '1': 'icmp', '6': 'tcp', '17': 'udp', '58': 'icmp', '47': 'gre', '50': 'esp' };

function base(partial: Partial<SyslogEvent> & Pick<SyslogEvent, 'timestamp' | 'ingestedAt' | 'srcIp' | 'dstIp' | 'raw' | 'message'>): SyslogEvent {
  return {
    id: crypto.randomUUID(),
    firewallHost: 'aws',
    serialNumber: '-',
    priority: 6,
    severity: 'info',
    categoryCode: '1024',
    categoryName: 'AWS',
    messageId: 'aws',
    action: 'allow',
    srcPort: null,
    srcZone: '-',
    dstPort: null,
    dstZone: '-',
    natSrcIp: null,
    natSrcPort: null,
    natDstIp: null,
    natDstPort: null,
    protocol: 'tcp',
    ruleRef: null,
    natRuleRef: null,
    bytesSent: 0,
    bytesRcvd: 0,
    appName: null,
    user: null,
    source: 's3',
    ...partial,
  } as SyslogEvent;
}

const sev = (action: SyslogAction): { severity: SyslogSeverity; priority: number } =>
  action === 'allow' ? { severity: 'info', priority: 6 } : { severity: 'notice', priority: 5 };

const intOrNull = (v: string | undefined): number | null => {
  if (v === undefined || v === '-' || v === '') return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : null;
};

const num = (v: string | undefined): number => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
};

// ---------------------------------------------------------------------------
// VPC Flow Logs (texto separado por espaço, com cabeçalho nos arquivos do S3)
// ---------------------------------------------------------------------------

const FLOW_DEFAULT_FIELDS = [
  'version', 'account_id', 'interface_id', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol',
  'packets', 'bytes', 'start', 'end', 'action', 'log_status',
];

const normField = (f: string): string => f.trim().replace(/^\$\{|\}$/g, '').toLowerCase().replace(/-/g, '_');

export function parseFlowLogs(text: string, opts: AwsParseOptions = {}): AwsParseResult {
  const nowMs = opts.nowMs ?? Date.now();
  const events: SyslogEvent[] = [];
  let skipped = 0;
  let fields = FLOW_DEFAULT_FIELDS;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^version\s/i.test(line)) {
      fields = line.split(/\s+/).map(normField);
      continue;
    }
    const cols = line.split(/\s+/);
    if (cols.length < fields.length - 2 || cols.length < 12) {
      skipped += 1;
      opts.onSkip?.(line);
      continue;
    }
    const f: Record<string, string> = {};
    fields.forEach((name, i) => {
      f[name] = cols[i] ?? '-';
    });

    if (f.log_status && f.log_status !== 'OK') continue; // NODATA / SKIPDATA não são tráfego
    const startS = Number(f.start);
    if (!Number.isFinite(startS) || startS <= 0) {
      skipped += 1;
      opts.onSkip?.(line);
      continue;
    }
    // Atrás de NAT/ELB o endereço real do pacote vem em pkt-srcaddr / pkt-dstaddr
    const srcIp = (f.pkt_srcaddr && f.pkt_srcaddr !== '-' ? f.pkt_srcaddr : f.srcaddr) || '-';
    const dstIp = (f.pkt_dstaddr && f.pkt_dstaddr !== '-' ? f.pkt_dstaddr : f.dstaddr) || '-';
    if (srcIp === '-' || dstIp === '-') {
      skipped += 1;
      opts.onSkip?.(line);
      continue;
    }
    const action: SyslogAction = f.action === 'ACCEPT' ? 'allow' : 'drop';
    const proto = PROTOCOLS[f.protocol] ?? (f.protocol && f.protocol !== '-' ? f.protocol : 'tcp');
    const { timestamp, ingestedAt } = stamp(startS * 1000, nowMs);
    const { severity, priority } = sev(action);
    const srcPort = intOrNull(f.srcport);
    const dstPort = intOrNull(f.dstport);
    const service = f.pkt_dst_aws_service && f.pkt_dst_aws_service !== '-' ? f.pkt_dst_aws_service : null;
    const endS = Number(f.end);
    const meta: Record<string, string | number | boolean> = {};
    const putMeta = (k: string, v: string | number | undefined) => {
      if (v !== undefined && v !== '' && v !== '-') meta[k] = v;
    };
    putMeta('packets', num(f.packets) || undefined);
    putMeta('vpcId', f.vpc_id);
    putMeta('subnetId', f.subnet_id);
    putMeta('instanceId', f.instance_id);
    putMeta('flowDirection', f.flow_direction);
    putMeta('tcpFlags', f.tcp_flags);
    putMeta('trafficPath', f.traffic_path);
    putMeta('azId', f.az_id);
    putMeta('region', f.region);
    putMeta('srcAwsService', f.pkt_src_aws_service);
    putMeta('dstAwsService', f.pkt_dst_aws_service);
    putMeta('natSrcAddr', f.pkt_srcaddr !== f.srcaddr ? f.srcaddr : undefined);
    putMeta('natDstAddr', f.pkt_dstaddr !== f.dstaddr ? f.dstaddr : undefined);
    if (Number.isFinite(endS) && endS >= startS) putMeta('durationSec', endS - startS);

    events.push(
      base({
        timestamp,
        ingestedAt,
        firewallHost: f.interface_id && f.interface_id !== '-' ? f.interface_id : 'vpc',
        serialNumber: f.account_id && f.account_id !== '-' ? f.account_id : '-',
        priority,
        severity,
        categoryCode: '1024',
        categoryName: 'VPC Flow Logs',
        messageId: 'vpcflow',
        action,
        srcIp,
        srcPort,
        srcZone: f.subnet_id && f.subnet_id !== '-' ? f.subnet_id : '-',
        dstIp,
        dstPort,
        dstZone: f.flow_direction && f.flow_direction !== '-' ? f.flow_direction : '-',
        protocol: proto,
        // Cada registro é unidirecional (origem → destino)
        bytesSent: num(f.bytes),
        bytesRcvd: 0,
        appName: service,
        meta,
        message: `VPC Flow ${f.action} ${srcIp}${srcPort !== null ? `:${srcPort}` : ''} → ${dstIp}${dstPort !== null ? `:${dstPort}` : ''} ${proto}`,
        raw: line.slice(0, RAW_MAX),
      })
    );
  }
  return { events, skipped };
}

// ---------------------------------------------------------------------------
// AWS WAF (JSON por linha)
// ---------------------------------------------------------------------------

interface WafRecord {
  timestamp?: number;
  ruleGroupList?: Array<{ ruleGroupId?: string; terminatingRule?: { ruleId?: string; action?: string } | null; nonTerminatingMatchingRules?: Array<{ ruleId?: string }> }>;
  rateBasedRuleList?: Array<{ rateBasedRuleName?: string; rateBasedRuleId?: string }>;
  nonTerminatingMatchingRules?: Array<{ ruleId?: string; action?: string }>;
  labels?: Array<{ name?: string }>;
  ja3Fingerprint?: string;
  ja4Fingerprint?: string;
  captchaResponse?: unknown;
  webaclId?: string;
  terminatingRuleId?: string;
  terminatingRuleType?: string;
  action?: string;
  httpSourceName?: string;
  httpSourceId?: string;
  responseCodeSent?: number | null;
  httpRequest?: {
    clientIp?: string;
    country?: string;
    uri?: string;
    args?: string;
    httpVersion?: string;
    scheme?: string;
    httpMethod?: string;
    headers?: Array<{ name?: string; value?: string }>;
  };
}

export function parseWafLogs(text: string, opts: AwsParseOptions = {}): AwsParseResult {
  const nowMs = opts.nowMs ?? Date.now();
  const events: SyslogEvent[] = [];
  let skipped = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    let rec: WafRecord;
    try {
      rec = JSON.parse(line) as WafRecord;
    } catch {
      skipped += 1;
      opts.onSkip?.(line);
      continue;
    }
    const req = rec.httpRequest;
    const clientIp = (req?.clientIp || '').trim();
    if (!clientIp || !rec.timestamp) {
      skipped += 1;
      opts.onSkip?.(line);
      continue;
    }
    const wafAction = String(rec.action || 'ALLOW').toUpperCase();
    const blocked = wafAction === 'BLOCK' || wafAction === 'CAPTCHA' || wafAction === 'CHALLENGE';
    const action: SyslogAction = blocked ? 'deny' : 'allow';
    const host = (req?.headers || []).find((h) => (h.name || '').toLowerCase() === 'host')?.value?.trim();
    const dst = host || rec.httpSourceId || rec.webaclId || 'waf';
    const { timestamp, ingestedAt } = stamp(rec.timestamp, nowMs);
    const rule = rec.terminatingRuleId || 'Default_Action';
    const safeArgs = req?.args ? redactQuery(req.args) : '';
    const uri = `${req?.uri || '/'}${safeArgs ? `?${safeArgs}` : ''}`;
    const aclName = (rec.webaclId || '').split('/').slice(-2, -1)[0] || rec.webaclId || 'waf';
    const headerOf = (name: string) => (req?.headers || []).find((h) => (h.name || '').toLowerCase() === name)?.value?.trim();
    const ua = headerOf('user-agent') ?? '';
    const inner = (rec.ruleGroupList || []).find((g) => g.terminatingRule?.ruleId);
    const meta: Record<string, string | number | boolean> = {};
    const putMeta = (k: string, v: string | number | undefined | null) => {
      if (v !== undefined && v !== null && v !== '' && v !== '-') meta[k] = v;
    };
    putMeta('wafAction', wafAction);
    putMeta('ruleId', rec.terminatingRuleId);
    putMeta('ruleType', rec.terminatingRuleType);
    putMeta('innerRule', inner ? `${inner.ruleGroupId ?? ''}/${inner.terminatingRule?.ruleId ?? ''}`.replace(/^\//, '') : undefined);
    putMeta('webAcl', aclName);
    putMeta('source', rec.httpSourceName);
    putMeta('sourceId', rec.httpSourceId);
    putMeta('accountId', /:(\d{12}):/.exec(rec.webaclId ?? '')?.[1] ?? /^(\d{12})-/.exec(rec.httpSourceId ?? '')?.[1]);
    putMeta('country', req?.country);
    putMeta('method', req?.httpMethod);
    putMeta('host', host);
    putMeta('uri', (req?.uri || '/').slice(0, 200));
    putMeta('uriGroup', pathGroupOf(req?.uri || '/'));
    if (safeArgs) putMeta('args', safeArgs.slice(0, 200));
    putMeta('httpVersion', req?.httpVersion);
    putMeta('userAgent', ua.slice(0, 160));
    putMeta('uaFamily', ua ? uaFamilyOf(ua) : undefined);
    putMeta('referer', redactQuery(headerOf('referer') ?? '').slice(0, 160));
    putMeta('authScheme', authSchemeOf(req?.headers || []));
    const secrets = detectSecrets(req?.headers || [], req?.args || '', req?.scheme);
    if (secrets) {
      putMeta('secretTop', secrets.top);
      putMeta('secretTypes', secrets.types.join(','));
      putMeta('secretRisk', secrets.risk);
      putMeta('secretEndpoint', `${req?.httpMethod ?? ''} ${host ?? ''}${pathGroupOf(req?.uri || '/')}`.trim().slice(0, 200));
    }
    putMeta('contentType', contentTypeFamily(headerOf('content-type')));
    putMeta('bodySize', (rec as { requestBodySize?: number }).requestBodySize);
    putMeta('bodyInspected', (rec as { requestBodySizeInspectedByWAF?: number }).requestBodySizeInspectedByWAF);
    putMeta('oversize', ((rec as { oversizeFields?: string[] }).oversizeFields || []).join(','));
    putMeta('responseCode', rec.responseCodeSent ?? undefined);
    putMeta('ruleGroups', (rec.ruleGroupList || []).map((g) => g.ruleGroupId).filter(Boolean).join(','));
    putMeta('rateBased', (rec.rateBasedRuleList || []).map((r) => r.rateBasedRuleName || r.rateBasedRuleId).filter(Boolean).join(','));
    putMeta('countedRules', (rec.nonTerminatingMatchingRules || []).map((r) => r.ruleId).filter(Boolean).join(','));
    putMeta('labels', (rec.labels || []).map((l) => l.name).filter(Boolean).join(','));
    putMeta('ja3', rec.ja3Fingerprint);
    putMeta('ja4', rec.ja4Fingerprint);
    putMeta('scheme', req?.scheme);
    putMeta('requestId', (req as { requestId?: string } | undefined)?.requestId);

    events.push(
      base({
        timestamp,
        ingestedAt,
        firewallHost: aclName,
        serialNumber: rec.httpSourceName || '-',
        priority: blocked ? 4 : 6,
        severity: blocked ? 'warning' : 'info',
        // 512 = IPS para o motor de alertas: só os bloqueios do WAF contam como intrusão
        categoryCode: blocked ? '512' : '1024',
        categoryName: 'AWS WAF',
        messageId: 'waf',
        action,
        srcIp: clientIp,
        srcZone: req?.country || '-',
        dstIp: dst,
        dstPort: null,
        protocol: 'tcp',
        ruleRef: rule,
        appName: null,
        meta,
        message: `WAF ${wafAction} · regra ${rule}${rec.terminatingRuleType ? ` (${rec.terminatingRuleType})` : ''} · ${req?.httpMethod || ''} ${uri.slice(0, 160)}`.trim(),
        raw: sanitizeWafRecord(rec as unknown as Record<string, unknown>).slice(0, RAW_MAX),
      })
    );
  }
  return { events, skipped };
}

// ---------------------------------------------------------------------------
// ALB (texto com aspas)
// ---------------------------------------------------------------------------

export function tokenizeQuoted(line: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] === ' ') {
      i += 1;
      continue;
    }
    if (line[i] === '"') {
      let j = i + 1;
      while (j < line.length && line[j] !== '"') j += 1;
      out.push(line.slice(i + 1, j));
      i = j + 1;
    } else {
      let j = i;
      while (j < line.length && line[j] !== ' ') j += 1;
      out.push(line.slice(i, j));
      i = j;
    }
  }
  return out;
}

function splitHostPort(value: string): { host: string; port: number | null } {
  const idx = value.lastIndexOf(':');
  if (idx <= 0) return { host: value, port: null };
  const port = Number(value.slice(idx + 1));
  return Number.isInteger(port) ? { host: value.slice(0, idx), port } : { host: value, port: null };
}

/** Nomes dos campos do access log do ALB, na ordem das colunas do texto. */
const ALB_COLUMNS = [
  'type', 'time', 'elb', 'client_port', 'target_port', 'request_processing_time', 'target_processing_time',
  'response_processing_time', 'elb_status_code', 'target_status_code', 'received_bytes', 'sent_bytes', 'request_line',
  'user_agent', 'ssl_cipher', 'ssl_protocol', 'target_group_arn', 'trace_id', 'domain_name', 'chosen_cert_arn',
  'matched_rule_priority', 'request_creation_time', 'actions_executed', 'redirect_url', 'error_reason',
  'target_port_list', 'target_status_code_list', 'classification', 'classification_reason', 'conn_trace_id',
];

type AlbFields = Record<string, string>;

/** Caminho com ids, UUIDs e tokens trocados por marcadores, para agrupar endpoints parecidos. */
export function pathGroupOf(rawPath: string): string {
  let path = rawPath;
  try {
    path = decodeURIComponent(rawPath);
  } catch {
    /* mantém o original */
  }
  return path
    .split('/')
    .map((seg) => {
      if (!seg) return seg;
      if (/^\d+$/.test(seg)) return '{id}';
      if (/^\d{4}-\d{2}-\d{2}$/.test(seg)) return '{data}';
      if (/^[A-Za-z0-9_-]*[0-9a-f]{16,}[A-Za-z0-9_-]*\.[A-Za-z0-9]{2,5}$/i.test(seg)) return `{arquivo}.${seg.split('.').pop()}`;
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return '{uuid}';
      if (/^[0-9a-f]{16,}$/i.test(seg)) return '{hash}';
      if (/^[A-Za-z0-9_-]{24,}$/.test(seg)) return '{token}';
      return seg;
    })
    .join('/')
    .slice(0, 200);
}

/** Família do cliente a partir do user-agent (navegador, app, ferramenta ou robô). */
export function uaFamilyOf(ua: string): string {
  const u = ua.trim();
  if (!u) return 'Desconhecido';
  if (/bot|spider|crawl|slurp|facebookexternalhit/i.test(u)) return 'Robô / crawler';
  if (/okhttp/i.test(u)) return 'okhttp (app Android)';
  if (/CFNetwork|Darwin/i.test(u)) return 'App iOS (CFNetwork)';
  if (/PostmanRuntime/i.test(u)) return 'Postman';
  if (/curl\//i.test(u)) return 'curl';
  if (/python-requests|aiohttp|httpx|urllib/i.test(u)) return 'Python';
  if (/Go-http-client/i.test(u)) return 'Go';
  if (/Java\/|Apache-HttpClient|Jakarta/i.test(u)) return 'Java';
  if (/Edg\//.test(u)) return 'Edge';
  if (/OPR\/|Opera/.test(u)) return 'Opera';
  if (/Chrome\//.test(u)) return 'Chrome';
  if (/Firefox\//.test(u)) return 'Firefox';
  if (/Safari\//.test(u)) return 'Safari';
  if (/Mozilla\//.test(u)) return 'Navegador (outro)';
  return u.split(/[\/ ]/)[0].slice(0, 40) || 'Outro';
}

/** Linha do ALB (texto do S3 ou JSON do CloudWatch) → campos nomeados. */
function albFieldsOf(line: string): AlbFields | null {
  if (line.startsWith('{')) {
    try {
      const obj = JSON.parse(line) as Record<string, unknown>;
      const f: AlbFields = {};
      for (const [k, v] of Object.entries(obj)) f[k.toLowerCase()] = v === null || v === undefined ? '' : String(v);
      // variações de nome que alguns formatos usam
      f.client_port ||= f.client || (f.client_ip && f.client_ip_port ? `${f.client_ip}:${f.client_ip_port}` : f.client_ip) || '';
      f.request_line ||= f.request || '';
      return f.time ? f : null;
    } catch {
      return null;
    }
  }
  const t = tokenizeQuoted(line);
  if (t.length < 13 || !/^(http|https|h2|grpcs?|ws|wss)$/i.test(t[0])) return null;
  const f: AlbFields = {};
  ALB_COLUMNS.forEach((name, i) => {
    if (t[i] !== undefined) f[name] = t[i];
  });
  return f;
}

const dash = (v: string | undefined): string => (v && v !== '-' ? v : '');
const seconds = (v: string | undefined): number | null => {
  const n = Number(v);
  return v && v !== '-' && Number.isFinite(n) && n >= 0 ? n : null;
};

const hsBucketOf = (ms: number): string =>
  ms < 50 ? '< 50 ms' : ms < 100 ? '50–100 ms' : ms < 200 ? '100–200 ms' : ms < 500 ? '200–500 ms' : '≥ 500 ms';

/** Connection log do ALB (handshake TLS por conexão): não tem request_line, tem tls_handshake_latency. */
function isAlbConnection(f: AlbFields): boolean {
  return !f.request_line && ('tls_handshake_latency' in f || 'tls_verify_status' in f) && !!f.client_ip;
}

function albConnectionEvent(f: AlbFields, rawLine: string, nowMs: number): SyslogEvent | null {
  const ms = Date.parse(f.time);
  if (!Number.isFinite(ms) || !f.client_ip) return null;
  const { timestamp, ingestedAt } = stamp(ms, nowMs);
  const verify = dash(f.tls_verify_status);
  const proto = dash(f.tls_protocol);
  const hsSec = seconds(f.tls_handshake_latency);
  const hsMs = hsSec === null ? null : Math.round(hsSec * 1000);
  // sem protocolo TLS negociado = handshake não concluído (sondagem, scanner, cliente que desistiu) ou falha de verificação
  const failed = !proto || (verify !== '' && verify.toLowerCase() !== 'success');
  const kex = dash(f.tls_keyexchange);
  const meta: Record<string, string | number | boolean> = { connection: true };
  const put = (k: string, v: string | number | boolean | null | undefined) => {
    if (v !== null && v !== undefined && v !== '') meta[k] = v;
  };
  put('tlsVersion', proto);
  put('tlsCipher', dash(f.tls_cipher));
  put('tlsKeyExchange', kex);
  if (/mlkem|kyber/i.test(kex)) put('postQuantum', true);
  put('tlsVerify', verify || (failed ? 'Sem TLS' : ''));
  put('tlsHandshakeMs', hsMs);
  put('hsBucket', hsMs === null ? '' : hsBucketOf(hsMs));
  put('listenerPort', num(f.listener_port) || '');
  put('connTraceId', dash(f.conn_trace_id));
  put('elb', f.elb);
  put('nodeIp', dash(f.ip_address));
  const elbName = (f.elb || '').split('/')[1] || f.elb || 'alb';
  return base({
    timestamp,
    ingestedAt,
    firewallHost: elbName,
    serialNumber: '-',
    priority: failed ? 5 : 6,
    severity: failed ? 'notice' : 'info',
    categoryCode: '1024',
    categoryName: 'Application Load Balancer',
    messageId: 'alb-conn',
    action: failed ? 'deny' : 'allow',
    srcIp: f.client_ip,
    srcPort: num(f.client_port) || null,
    dstIp: dash(f.ip_address) || elbName,
    dstPort: num(f.listener_port) || null,
    dstZone: '-',
    protocol: 'tcp',
    appName: null,
    user: null,
    meta,
    message: failed
      ? `ALB conexão sem handshake TLS concluído${verify && verify.toLowerCase() !== 'success' ? ` (${verify})` : ''} · porta ${f.listener_port || '-'}`
      : `ALB conexão ${proto} ${kex ? `(${kex}) ` : ''}${hsMs !== null ? `handshake ${hsMs} ms` : ''} · porta ${f.listener_port || '-'}`.trim(),
    raw: rawLine.slice(0, RAW_MAX),
  });
}

function albEvent(f: AlbFields, rawLine: string, nowMs: number): SyslogEvent | null {
  if (isAlbConnection(f)) return albConnectionEvent(f, rawLine, nowMs);
  const ms = Date.parse(f.time);
  const client = splitHostPort(f.client_port || '');
  if (!Number.isFinite(ms) || !client.host) return null;

  const status = Number(f.elb_status_code);
  const reqMatch = /^(\S+)\s+(\S+)(?:\s+(\S+))?/.exec(f.request_line || '');
  const method = reqMatch?.[1] ?? '';
  let host = '';
  let port: number | null = /^(https|h2|grpcs?|wss)$/i.test(f.type || '') ? 443 : 80;
  let path = '';
  let hasQuery = false;
  if (reqMatch) {
    try {
      const u = new URL(reqMatch[2]);
      host = u.hostname;
      if (u.port) port = Number(u.port);
      path = u.pathname || '/';
      hasQuery = u.search.length > 1;
    } catch {
      path = reqMatch[2];
    }
  }
  const domain = dash(f.domain_name);
  const target = splitHostPort(dash(f.target_port) || dash(f.target_port_list).split(' ')[0]);
  const actions = (f.actions_executed || '').toLowerCase();
  const blocked = actions.includes('waf') && (status === 403 || !actions.includes('forward'));
  const action: SyslogAction = blocked ? 'deny' : 'allow';
  const serverError = status >= 500;
  const reqT = seconds(f.request_processing_time);
  const tgtT = seconds(f.target_processing_time);
  const respT = seconds(f.response_processing_time);
  const totalT = (reqT ?? 0) + (tgtT ?? 0) + (respT ?? 0);
  const slow = totalT >= 10;
  const { timestamp, ingestedAt } = stamp(ms, nowMs);
  const elbName = (f.elb || '').split('/')[1] || f.elb || 'alb';
  const targetGroup = /targetgroup\/([^/]+)\//.exec(f.target_group_arn || '')?.[1] ?? '';
  const ua = dash(f.user_agent);
  const targetStatus = dash(f.target_status_code);

  const meta: Record<string, string | number | boolean> = {};
  const put = (k: string, v: string | number | boolean | null | undefined) => {
    if (v !== null && v !== undefined && v !== '') meta[k] = v;
  };
  put('method', method);
  put('host', host || domain);
  put('path', path.slice(0, 200));
  put('pathGroup', path ? pathGroupOf(path) : '');
  if (hasQuery) put('hasQuery', true);
  put('status', Number.isFinite(status) ? status : '');
  put('targetStatus', targetStatus);
  put('userAgent', ua.slice(0, 160));
  put('uaFamily', uaFamilyOf(ua));
  put('tlsVersion', dash(f.ssl_protocol));
  put('tlsCipher', dash(f.ssl_cipher));
  if ((f.chosen_cert_arn || '') === 'session-reused') put('tlsReused', true);
  put('wafActions', dash(f.actions_executed));
  put('targetIp', target.host);
  put('targetPort', target.port);
  put('targetGroup', targetGroup);
  put('elb', f.elb);
  put('accountId', /:(\d{12}):/.exec(f.target_group_arn || '')?.[1] ?? /:(\d{12}):/.exec(f.chosen_cert_arn || '')?.[1]);
  put('nodeIp', dash(f.ip_address));
  put('reqTime', reqT);
  put('targetTime', tgtT);
  put('respTime', respT);
  put('totalTime', totalT > 0 ? Math.round(totalT * 1000) / 1000 : '');
  put('traceId', dash(f.trace_id));
  put('connTraceId', dash(f.conn_trace_id));
  put('rulePriority', dash(f.matched_rule_priority));
  put('errorReason', dash(f.error_reason));
  put('redirectUrl', dash(f.redirect_url));
  put('classification', dash(f.classification));
  put('classificationReason', dash(f.classification_reason));
  put('listenerType', dash(f.type));
  if (reqMatch && /[?&]/.test(reqMatch[2])) {
    const q = reqMatch[2].slice(reqMatch[2].indexOf('?'));
    const sec = detectSecrets([], q, undefined);
    if (sec) {
      put('secretTop', sec.top);
      put('secretTypes', sec.types.join(','));
      put('secretRisk', sec.risk);
      put('secretEndpoint', `${method} ${host || domain}${path ? pathGroupOf(path) : ''}`.slice(0, 200));
    }
  }

  return base({
    timestamp,
    ingestedAt,
    firewallHost: elbName,
    serialNumber: '-',
    priority: serverError ? 4 : blocked || slow ? 5 : 6,
    severity: serverError ? 'warning' : blocked || slow ? 'notice' : 'info',
    categoryCode: '1024',
    categoryName: 'Application Load Balancer',
    messageId: 'alb',
    action,
    srcIp: client.host,
    srcPort: client.port,
    dstIp: host || domain || (target.host ? target.host : elbName),
    dstPort: port,
    dstZone: target.host || '-',
    protocol: 'tcp',
    bytesSent: num(f.received_bytes),
    bytesRcvd: num(f.sent_bytes),
    // o endpoint fica em meta e na mensagem; appName vazio mantém o ranking de serviços limpo (HTTPS, 8050/tcp…)
    appName: null,
    user: null,
    meta,
    message: `ALB ${Number.isFinite(status) ? status : '-'} ${method} ${host || domain}${path.slice(0, 120)}${totalT > 0 ? ` (${totalT.toFixed(2)} s)` : ''}`.trim(),
    raw: redactQuery(rawLine).slice(0, RAW_MAX),
  });
}

export function parseAlbLogs(text: string, opts: AwsParseOptions = {}): AwsParseResult {
  const nowMs = opts.nowMs ?? Date.now();
  const events: SyslogEvent[] = [];
  let skipped = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const fields = albFieldsOf(line);
    const ev = fields ? albEvent(fields, line, nowMs) : null;
    if (!ev) {
      skipped += 1;
      opts.onSkip?.(line);
      continue;
    }
    events.push(ev);
  }
  return { events, skipped };
}

export function parseAwsObject(type: AwsSourceType, text: string, opts: AwsParseOptions = {}): AwsParseResult {
  if (type === 'vpcflow') return parseFlowLogs(text, opts);
  if (type === 'waf') return parseWafLogs(text, opts);
  return parseAlbLogs(text, opts);
}
