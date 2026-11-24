/**
 * Dados de demonstração do ambiente AWS: gera linhas nos formatos reais (VPC Flow Logs, WAF e ALB)
 * e as converte pelos mesmos parsers usados na ingestão do S3.
 */
import type { AwsSourceConfig } from '../shared/aws.ts';
import type { SyslogEvent } from '../shared/types.ts';
import { parseAlbLogs, parseFlowLogs, parseWafLogs } from './awsParsers.ts';
import { emptyStatus } from './awsIngest.ts';

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ACCOUNT = '123456789012';
const ENI_WEB = 'eni-0a1b2c3d4e5f60718';
const ENI_APP = 'eni-0f9e8d7c6b5a40312';

const OUTBOUND: Array<{ ip: string; port: number; proto: number; w: number }> = [
  { ip: '142.250.219.14', port: 443, proto: 6, w: 30 }, // Google
  { ip: '13.107.42.16', port: 443, proto: 6, w: 24 }, // Microsoft
  { ip: '157.240.222.60', port: 443, proto: 6, w: 12 }, // Meta
  { ip: '8.8.8.8', port: 53, proto: 17, w: 14 },
  { ip: '1.1.1.1', port: 53, proto: 17, w: 6 },
  { ip: '170.114.52.2', port: 443, proto: 6, w: 8 }, // Zoom
  { ip: '34.120.177.193', port: 443, proto: 6, w: 6 },
  { ip: '200.147.88.12', port: 443, proto: 6, w: 5 },
  { ip: '185.199.108.153', port: 443, proto: 6, w: 7 }, // GitHub
  { ip: '129.6.15.28', port: 123, proto: 17, w: 3 }, // NTP
  { ip: '151.101.1.69', port: 80, proto: 6, w: 4 },
];

const SCANNERS = ['185.220.101.34', '45.155.205.91', '194.26.135.72', '103.145.13.7', '89.248.165.52', '198.235.24.130', '5.188.206.18'];
const CLIENTS = ['200.147.88.12', '177.54.10.8', '189.6.100.21', '201.17.5.9', '8.8.4.4', '52.95.110.1', '203.0.113.77', '91.121.5.5', '104.28.5.9', '185.220.101.34', '45.155.205.91'];

const WAF_RULES = ['AWSManagedRulesCommonRuleSet', 'AWSManagedRulesSQLiRuleSet', 'AWSManagedRulesKnownBadInputsRuleSet', 'RateLimit-Login', 'Block-Bad-Bots'];
const WAF_URIS = ['/login', '/wp-login.php', '/api/v1/users', '/admin', '/.env', '/search?q=1%27%20OR%201=1', '/api/orders', '/index.php'];
const ALB_PATHS = ['/', '/api/v1/orders', '/api/v1/users/me', '/static/app.js', '/login', '/health', '/checkout', '/api/v1/products'];

function pick<T>(r: () => number, arr: T[]): T {
  return arr[Math.floor(r() * arr.length)];
}

function pickWeighted<T extends { w: number }>(r: () => number, arr: T[]): T {
  const total = arr.reduce((n, x) => n + x.w, 0);
  let x = r() * total;
  for (const item of arr) {
    x -= item.w;
    if (x <= 0) return item;
  }
  return arr[0];
}

export function createAwsSampleDataset(nowMs = Date.now()): { events: SyslogEvent[]; sources: AwsSourceConfig[] } {
  const r = rng(20261123);
  const spanMs = 6 * 3_600_000;
  const rand = (lo: number, hi: number) => Math.floor(lo + r() * (hi - lo));
  const at = () => nowMs - Math.floor(r() * spanMs);

  const flow: string[] = [
    'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status',
  ];
  // saída das instâncias para a internet
  for (let i = 0; i < 520; i += 1) {
    const d = pickWeighted(r, OUTBOUND);
    const t = Math.floor(at() / 1000);
    const src = `10.0.${r() < 0.7 ? 1 : 2}.${rand(10, 60)}`;
    const bytes = d.port === 53 ? rand(70, 300) : rand(2_000, 900_000);
    flow.push(`2 ${ACCOUNT} ${r() < 0.6 ? ENI_APP : ENI_WEB} ${src} ${d.ip} ${rand(32768, 61000)} ${d.port} ${d.proto} ${rand(2, 400)} ${bytes} ${t} ${t + 60} ACCEPT OK`);
  }
  // varreduras vindas da internet (rejeitadas pelo Security Group)
  for (let i = 0; i < 150; i += 1) {
    const t = Math.floor(at() / 1000);
    const port = pick(r, [22, 22, 3389, 3389, 23, 445, 8080, 5900, 1433, 6379, 9200]);
    flow.push(`2 ${ACCOUNT} ${ENI_WEB} ${pick(r, SCANNERS)} 10.0.1.${rand(10, 30)} ${rand(30000, 65000)} ${port} 6 ${rand(1, 4)} ${rand(40, 200)} ${t} ${t + 60} REJECT OK`);
  }
  // acessos legítimos aos servidores web
  for (let i = 0; i < 120; i += 1) {
    const t = Math.floor(at() / 1000);
    flow.push(`2 ${ACCOUNT} ${ENI_WEB} ${pick(r, CLIENTS)} 10.0.1.${rand(10, 14)} ${rand(30000, 65000)} 443 6 ${rand(5, 60)} ${rand(4_000, 300_000)} ${t} ${t + 60} ACCEPT OK`);
  }

  const waf: string[] = [];
  for (let i = 0; i < 130; i += 1) {
    const blocked = r() < 0.6;
    const ip = blocked ? pick(r, SCANNERS.concat(CLIENTS.slice(-4))) : pick(r, CLIENTS);
    waf.push(
      JSON.stringify({
        timestamp: at(),
        formatVersion: 1,
        webaclId: `arn:aws:wafv2:sa-east-1:${ACCOUNT}:regional/webacl/prod-web-acl/6f7e8d9c`,
        terminatingRuleId: blocked ? pick(r, WAF_RULES) : 'Default_Action',
        terminatingRuleType: blocked ? 'MANAGED_RULE_GROUP' : 'REGULAR',
        action: blocked ? 'BLOCK' : 'ALLOW',
        httpSourceName: 'ALB',
        httpSourceId: `${ACCOUNT}-app/prod-alb/50dc6c495c0c9188`,
        httpRequest: {
          clientIp: ip,
          country: 'XX',
          uri: pick(r, WAF_URIS),
          args: '',
          httpVersion: 'HTTP/2.0',
          httpMethod: pick(r, ['GET', 'GET', 'POST']),
          headers: [
            { name: 'Host', value: 'app.rgerios.corp' },
            { name: 'User-Agent', value: pick(r, ['okhttp/5.3.2', 'python-requests/2.32.5', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36', 'curl/8.4.0']) },
            { name: 'Content-Type', value: pick(r, ['application/json', 'image/jpeg', 'application/x-www-form-urlencoded']) },
            ...(r() < 0.4 ? [{ name: 'Authorization', value: pick(r, ['Bearer eyJhbGciOiJIUzI1NiJ9.exemplo.assinatura', 'Basic dXN1YXJpbzpzZW5oYQ==']) }] : []),
          ],
        },
        ...(r() < 0.12 ? { requestBodySize: 800_000, requestBodySizeInspectedByWAF: 8192, oversizeFields: ['REQUEST_BODY'] } : {}),
        ja4Fingerprint: pick(r, ['t13d1714h1_5b57614c22b0_fadfdae04b4e', 't13d1713h1_ab0a1bf427ad_8537cf56674e', 't13d1518h2_8daaf6152771_a6157d7ae51a']),
      })
    );
  }

  const alb: string[] = [];
  const UAS = [
    'okhttp/5.3.2', 'okhttp/5.3.2', 'okhttp/4.12.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'MeuApp/3.4 CFNetwork/1494.0.7 Darwin/23.4.0', 'python-requests/2.31.0', 'Googlebot/2.1 (+http://www.google.com/bot.html)',
  ];
  const ENDPOINTS: Array<{ method: string; path: () => string; w: number; slow: number; up: [number, number]; down: [number, number] }> = [
    { method: 'GET', path: () => `/api/v1/pedidos/${rand(1000, 99999)}`, w: 30, slow: 0.05, up: [300, 700], down: [2_000, 20_000] },
    { method: 'POST', path: () => '/app/Services/MobileService.svc/EnviarImagem', w: 14, slow: 0.35, up: [600_000, 1_900_000], down: [300, 1_200] },
    { method: 'GET', path: () => '/app/Services/MobileService.svc/ListarItens', w: 16, slow: 0.2, up: [400, 900], down: [20_000, 400_000] },
    { method: 'GET', path: () => '/static/app.js', w: 12, slow: 0.01, up: [300, 500], down: [90_000, 250_000] },
    { method: 'POST', path: () => '/api/v1/login', w: 8, slow: 0.08, up: [400, 900], down: [800, 3_000] },
    { method: 'GET', path: () => `/api/v1/produtos/${rand(10, 9999)}/estoque`, w: 12, slow: 0.4, up: [300, 600], down: [1_000, 9_000] },
    { method: 'GET', path: () => '/health', w: 6, slow: 0, up: [200, 300], down: [100, 200] },
  ];
  const TARGETS = ['10.20.0.11', '192.168.0.138', '192.168.0.139'];
  for (let i = 0; i < 360; i += 1) {
    const ms = at();
    const ep = pickWeighted(r, ENDPOINTS);
    const target = pick(r, TARGETS);
    const blockedByWaf = r() < 0.06;
    const roll = r();
    const status = blockedByWaf ? 403 : roll < 0.85 ? 200 : roll < 0.92 ? pick(r, [301, 304]) : roll < 0.96 ? pick(r, [401, 404]) : target === '192.168.0.139' ? 502 : 500;
    const client = blockedByWaf ? pick(r, SCANNERS) : pick(r, CLIENTS);
    const target_t = blockedByWaf ? '-' : (r() < ep.slow ? 1.5 + r() * 9 : 0.01 + r() * 0.25).toFixed(3);
    const iso = new Date(ms).toISOString();
    // uploads grandes em rede móvel: o cliente demora para terminar de enviar o corpo
    const reqT = ep.up[0] > 500_000 && r() < 0.3 ? (3 + r() * 3).toFixed(3) : `0.00${rand(1, 9)}`;
    const up = rand(ep.up[0], ep.up[1]);
    const down = blockedByWaf ? 560 : rand(ep.down[0], ep.down[1]);
    const ua = pick(r, UAS);
    const tls = r() < 0.9 ? 'TLSv1.3 TLS_AES_128_GCM_SHA256' : 'TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256';
    alb.push(
      `https ${iso} app/alb-demo/0123456789abcdef ${client}:${rand(30000, 65000)} ${blockedByWaf ? '-' : `${target}:443`} ${reqT} ${target_t} 0.000 ${status} ${blockedByWaf ? '-' : status} ${up} ${down} ` +
        `"${ep.method} https://vendas.rgerios.corp:8050${ep.path()} HTTP/1.1" "${ua}" ${tls.split(' ')[1]} ${tls.split(' ')[0]} ` +
        `arn:aws:elasticloadbalancing:sa-east-1:${ACCOUNT}:targetgroup/TG-vendas/aaaaaaaaaaaaaaaa "Root=1-${rand(10000000, 99999999).toString(16)}" "vendas.rgerios.corp" ` +
        `"arn:aws:acm:sa-east-1:${ACCOUNT}:certificate/abc" 0 ${iso} "${blockedByWaf ? 'waf' : 'waf,forward'}" "-" "-" "${blockedByWaf ? '-' : `${target}:443`}" "${blockedByWaf ? '-' : status}" "-" "-"`
    );
  }

  // connection logs (handshake TLS por conexão)
  const conn: string[] = [];
  for (let i = 0; i < 160; i += 1) {
    const noTls = r() < 0.08;
    const modern = r() < 0.4;
    conn.push(
      JSON.stringify({
        leaf_client_cert_subject: '-',
        time: new Date(at()).toISOString(),
        client_ip: pick(r, CLIENTS),
        client_port: String(rand(1000, 65000)),
        listener_port: r() < 0.7 ? '443' : '8050',
        tls_protocol: noTls ? '-' : 'TLSv1.3',
        tls_cipher: noTls ? '-' : 'TLS_AES_128_GCM_SHA256',
        tls_handshake_latency: noTls ? '-' : (0.05 + r() * 0.2).toFixed(3),
        tls_verify_status: noTls ? '-' : 'Success',
        conn_trace_id: `TID_${rand(10000000, 99999999).toString(16)}`,
        tls_keyexchange: noTls ? '-' : modern ? 'X25519MLKEM768' : 'x25519',
        elb: 'app/alb-demo/0123456789abcdef',
        ip_address: pick(r, ['198.51.100.26', '192.0.2.27']),
      })
    );
  }

  const parsed = [
    ...parseFlowLogs(flow.join('\n'), { nowMs }).events,
    ...parseAlbLogs(conn.join('\n'), { nowMs }).events,
    ...parseWafLogs(waf.join('\n'), { nowMs }).events,
    ...parseAlbLogs(alb.join('\n'), { nowMs }).events,
  ].map((e) => ({ ...e, source: 'sample' as const }));
  parsed.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const base = (id: string, type: AwsSourceConfig['type'], name: string, prefix: string, files: number, events: number): AwsSourceConfig => ({
    id,
    type,
    name,
    enabled: false,
    bucket: 'logs-exemplo-prod',
    prefix,
    region: 'sa-east-1',
    dateLayout: true,
    lookbackHours: 6,
    status: {
      ...emptyStatus(),
      lastRunAt: new Date(nowMs - 40_000).toISOString(),
      lastOkAt: new Date(nowMs - 40_000).toISOString(),
      lastObjectAt: new Date(nowMs - 4 * 60_000).toISOString(),
      filesRead: files,
      eventsRead: events,
      bytesRead: files * 180_000,
    },
  });
  const sources: AwsSourceConfig[] = [
    base('s-flow', 'vpcflow', 'VPC Flow Logs (produção)', `AWSLogs/${ACCOUNT}/vpcflowlogs/sa-east-1/`, 412, 790),
    base('s-waf', 'waf', 'WAF prod-web-acl', `AWSLogs/${ACCOUNT}/WAFLogs/sa-east-1/prod-web-acl/`, 96, waf.length),
    base('s-alb', 'alb', 'ALB prod-alb', `AWSLogs/${ACCOUNT}/elasticloadbalancing/sa-east-1/`, 130, alb.length),
  ];
  return { events: parsed, sources };
}
