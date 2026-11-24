/** Análise por porta de destino: filtro ("443", "80,443", "8000-8100") e ranking das mais acessadas. */

export interface PortStat {
  port: number;
  /** Protocolo dominante (tcp/udp/icmp…). */
  proto: string;
  /** Nome do serviço conhecido (HTTPS, SSH, RDP…), se houver. */
  service: string;
  connections: number;
  blocked: number;
  bytes: number;
  sources: number;
  destinations: number;
}

export interface PortsReport {
  minutes: number;
  /** Eventos com porta de destino considerados. */
  events: number;
  ports: PortStat[];
  dataSource: 'memory' | 'database';
  truncated: boolean;
}

export type PortRange = [number, number];

export interface PortFilterSpec {
  ranges: PortRange[];
  /** Texto normalizado, para devolver na resposta e voltar para a URL. */
  text: string;
}

const MAX_ITEMS = 20;

/**
 * Lê o filtro de portas. Aceita números, listas separadas por vírgula ou espaço e intervalos (a-b).
 * Vazio = sem filtro (ranges vazio). Devolve null se algo for inválido.
 */
export function parsePortFilter(raw: unknown): PortFilterSpec | null {
  const text = String(raw ?? '').trim();
  if (!text) return { ranges: [], text: '' };
  if (text.length > 200) return null;
  const items = text.split(/[\s,;]+/).filter(Boolean);
  if (items.length === 0) return { ranges: [], text: '' };
  if (items.length > MAX_ITEMS) return null;
  const ranges: PortRange[] = [];
  for (const item of items) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(item);
    if (!m) return null;
    const from = Number(m[1]);
    const to = m[2] !== undefined ? Number(m[2]) : from;
    if (from > 65535 || to > 65535 || from > to) return null;
    ranges.push([from, to]);
  }
  return { ranges, text: ranges.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(',') };
}

export function hasPortFilter(spec: PortFilterSpec | null | undefined): boolean {
  return !!spec && spec.ranges.length > 0;
}

export function portMatches(spec: PortFilterSpec, port: number | null | undefined): boolean {
  if (spec.ranges.length === 0) return true;
  if (port === null || port === undefined) return false;
  return spec.ranges.some(([a, b]) => port >= a && port <= b);
}

const SERVICES: Record<number, string> = {
  20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
  80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
  143: 'IMAP', 161: 'SNMP', 162: 'SNMP-trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IKE',
  514: 'Syslog', 587: 'SMTP-submission', 636: 'LDAPS', 853: 'DNS-over-TLS', 993: 'IMAPS', 995: 'POP3S',
  1194: 'OpenVPN', 1433: 'SQL Server', 1521: 'Oracle', 1723: 'PPTP', 1900: 'SSDP', 3128: 'Proxy', 3268: 'LDAP-GC',
  3306: 'MySQL', 3389: 'RDP', 3478: 'STUN', 4500: 'IPsec NAT-T', 5060: 'SIP', 5061: 'SIP-TLS', 5222: 'XMPP',
  5353: 'mDNS', 5432: 'PostgreSQL', 5900: 'VNC', 5938: 'TeamViewer', 6379: 'Redis', 8000: 'HTTP-alt', 8080: 'HTTP-alt',
  8443: 'HTTPS-alt', 8883: 'MQTT-TLS', 9200: 'Elasticsearch', 9418: 'Git', 27017: 'MongoDB', 51820: 'WireGuard',
};

export function wellKnownService(port: number): string {
  return SERVICES[port] ?? '';
}
