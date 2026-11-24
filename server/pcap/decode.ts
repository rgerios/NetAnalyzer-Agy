/**
 * Decodificação de quadros: Ethernet/VLAN, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP e, por cima,
 * DNS, HTTP, TLS e SSH. O objetivo é depurar conectividade e firewall, não substituir o Wireshark.
 */
import type { RawPacket } from './reader.ts';
import { fmt4, fmt6, fmtMac } from './ipaddr.ts';

export interface TcpInfo {
  sport: number;
  dport: number;
  seq: number;
  ack: number;
  flags: number;
  win: number;
  hdrLen: number;
  payLen: number;
  mss?: number;
  wscale?: number;
  sackPermitted?: boolean;
}

export interface UdpInfo {
  sport: number;
  dport: number;
  len: number;
}

export interface IcmpInfo {
  v6: boolean;
  type: number;
  code: number;
  id?: number;
  seq?: number;
}

export interface ArpInfo {
  op: number;
  senderMac: string;
  senderIp: string;
  targetMac: string;
  targetIp: string;
}

export interface DnsInfo {
  id: number;
  response: boolean;
  opcode: number;
  rcode: number;
  qname?: string;
  qtype?: number;
  answers: string[];
  answerIps: string[];
  /** Quem pergunta/responde (para casar consulta e resposta). */
  truncated?: boolean;
}

export interface HttpInfo {
  isRequest: boolean;
  method?: string;
  uri?: string;
  host?: string;
  status?: number;
  version: string;
  firstLine: string;
  headers: string[];
}

export interface TlsInfo {
  contentType: number;
  version: number;
  handshakeType?: number;
  sni?: string;
}

export interface DecodedPacket {
  no: number;
  file: number;
  ts: number;
  rel: number;
  wireLen: number;
  capLen: number;
  data: Buffer;
  linkType: number;

  ethSrc?: string;
  ethDst?: string;
  ethType?: number;
  vlan?: number;

  ipVer?: 4 | 6;
  ipSrc?: string;
  ipDst?: string;
  ipProto?: number;
  ttl?: number;
  ipTotalLen?: number;
  ipId?: number;
  ipDf?: boolean;
  ipMf?: boolean;
  ipFragOffset?: number;

  tcp?: TcpInfo;
  udp?: UdpInfo;
  icmp?: IcmpInfo;
  arp?: ArpInfo;
  dns?: DnsInfo;
  http?: HttpInfo;
  tls?: TlsInfo;
  ssh?: string;

  /** Offset do payload da camada 4 dentro de `data` (-1 se não houver). */
  payOff: number;
  payLen: number;

  proto: string;
  info: string;
  /** Preenchidos pela análise. */
  stream?: number;
  udpStream?: number;
  expert: string[];
}

const IP_PROTOS: Record<number, string> = {
  1: 'ICMP', 2: 'IGMP', 4: 'IPIP', 6: 'TCP', 17: 'UDP', 41: 'IPv6-in-IP', 47: 'GRE', 50: 'ESP', 51: 'AH',
  58: 'ICMPv6', 88: 'EIGRP', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 115: 'L2TP', 132: 'SCTP',
};

export const TCP_FLAG_BITS: Array<[number, string]> = [
  [0x100, 'NS'], [0x80, 'CWR'], [0x40, 'ECE'], [0x20, 'URG'], [0x10, 'ACK'], [0x08, 'PSH'], [0x04, 'RST'], [0x02, 'SYN'], [0x01, 'FIN'],
];

export function tcpFlagNames(flags: number): string[] {
  return TCP_FLAG_BITS.filter(([bit]) => flags & bit).map(([, n]) => n).reverse();
}

const UDP_SERVICES: Record<number, string> = {
  53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 123: 'NTP', 137: 'NBNS', 138: 'NBDS', 161: 'SNMP', 162: 'SNMP',
  500: 'ISAKMP', 514: 'Syslog', 1900: 'SSDP', 4500: 'UDPENCAP', 5353: 'MDNS', 51820: 'WireGuard',
};

const ICMP_TYPES: Record<number, string> = {
  0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo (ping) request',
  9: 'Router advertisement', 10: 'Router solicitation', 11: 'Time-to-live exceeded', 12: 'Parameter problem',
  13: 'Timestamp request', 14: 'Timestamp reply',
};

const ICMP_UNREACH_CODES: Record<number, string> = {
  0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable',
  4: 'Fragmentation needed (DF set)', 5: 'Source route failed', 9: 'Network administratively prohibited',
  10: 'Host administratively prohibited', 13: 'Communication administratively prohibited',
};

const ICMP6_TYPES: Record<number, string> = {
  1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem',
  128: 'Echo (ping) request', 129: 'Echo (ping) reply', 133: 'Router solicitation', 134: 'Router advertisement',
  135: 'Neighbor solicitation', 136: 'Neighbor advertisement',
};

export const DNS_TYPES: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 43: 'DS', 46: 'RRSIG',
  48: 'DNSKEY', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY',
};

export const DNS_RCODES: Record<number, string> = {
  0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name (NXDOMAIN)', 4: 'Not implemented', 5: 'Refused',
};

const TLS_HANDSHAKE: Record<number, string> = {
  1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions', 11: 'Certificate',
  12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify',
  16: 'Client Key Exchange', 20: 'Finished',
};

const TLS_CONTENT: Record<number, string> = {
  20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 24: 'Heartbeat',
};

export function tlsVersionName(v: number): string {
  switch (v) {
    case 0x0300: return 'SSL 3.0';
    case 0x0301: return 'TLS 1.0';
    case 0x0302: return 'TLS 1.1';
    case 0x0303: return 'TLS 1.2';
    case 0x0304: return 'TLS 1.3';
    default: return `0x${v.toString(16)}`;
  }
}

export function emptyPacket(raw: RawPacket, file: number): DecodedPacket {
  return {
    no: 0,
    file,
    ts: raw.ts,
    rel: 0,
    wireLen: raw.wireLen,
    capLen: raw.data.length,
    data: raw.data,
    linkType: raw.linkType,
    payOff: -1,
    payLen: 0,
    proto: 'Desconhecido',
    info: '',
    expert: [],
  };
}

export function decodePacket(raw: RawPacket, file: number): DecodedPacket {
  const p = emptyPacket(raw, file);
  try {
    decodeLink(p);
  } catch {
    // quadro cortado ou malformado: mantém o que já foi decodificado
    if (!p.info) p.info = 'Pacote malformado ou truncado';
  }
  return p;
}

function decodeLink(p: DecodedPacket): void {
  const d = p.data;
  switch (p.linkType) {
    case 1: // Ethernet
      return decodeEthernet(p, 0);
    case 0: // BSD loopback (família em 4 bytes, ordem do host)
    case 108: {
      if (d.length < 4) return;
      const fam = d.readUInt32LE(0);
      const famBE = d.readUInt32BE(0);
      const f = fam <= 0xff ? fam : famBE;
      if (f === 2) return decodeIPv4(p, 4);
      if (f === 24 || f === 28 || f === 30) return decodeIPv6(p, 4);
      p.info = `Loopback (família ${f})`;
      return;
    }
    case 101: // RAW
    case 228: // IPv4
    case 229: // IPv6
    case 12:
    case 14: {
      const ver = d[0] >> 4;
      if (ver === 4) return decodeIPv4(p, 0);
      if (ver === 6) return decodeIPv6(p, 0);
      return;
    }
    case 113: { // Linux cooked v1
      if (d.length < 16) return;
      return decodeEtherType(p, d.readUInt16BE(14), 16);
    }
    case 276: { // Linux cooked v2
      if (d.length < 20) return;
      return decodeEtherType(p, d.readUInt16BE(0), 20);
    }
    default:
      p.proto = `LinkType ${p.linkType}`;
      p.info = 'Tipo de enlace não suportado';
  }
}

function decodeEthernet(p: DecodedPacket, off: number): void {
  const d = p.data;
  if (d.length < off + 14) return;
  p.ethDst = fmtMac(d, off);
  p.ethSrc = fmtMac(d, off + 6);
  let type = d.readUInt16BE(off + 12);
  let o = off + 14;
  while ((type === 0x8100 || type === 0x88a8) && d.length >= o + 4) {
    if (p.vlan === undefined) p.vlan = d.readUInt16BE(o) & 0x0fff;
    type = d.readUInt16BE(o + 2);
    o += 4;
  }
  p.ethType = type;
  p.proto = 'Ethernet';
  p.info = `Ethertype 0x${type.toString(16).padStart(4, '0')}`;
  decodeEtherType(p, type, o);
}

function decodeEtherType(p: DecodedPacket, type: number, off: number): void {
  if (p.ethType === undefined) p.ethType = type;
  if (type === 0x0800) decodeIPv4(p, off);
  else if (type === 0x86dd) decodeIPv6(p, off);
  else if (type === 0x0806) decodeArp(p, off);
  else if (type === 0x88cc) { p.proto = 'LLDP'; p.info = 'LLDP'; }
  else if (type === 0x8863 || type === 0x8864) { p.proto = 'PPPoE'; p.info = 'PPP-over-Ethernet'; }
}

function decodeArp(p: DecodedPacket, off: number): void {
  const d = p.data;
  if (d.length < off + 28) return;
  const op = d.readUInt16BE(off + 6);
  const arp = {
    op,
    senderMac: fmtMac(d, off + 8),
    senderIp: fmt4(d, off + 14),
    targetMac: fmtMac(d, off + 18),
    targetIp: fmt4(d, off + 24),
  };
  p.arp = arp;
  p.proto = 'ARP';
  p.info =
    op === 1
      ? `Who has ${arp.targetIp}? Tell ${arp.senderIp}`
      : op === 2
        ? `${arp.senderIp} is at ${arp.senderMac}`
        : `ARP opcode ${op}`;
}

function decodeIPv4(p: DecodedPacket, off: number): void {
  const d = p.data;
  if (d.length < off + 20) return;
  const ihl = (d[off] & 0x0f) * 4;
  if ((d[off] >> 4) !== 4 || ihl < 20) return;
  p.ipVer = 4;
  p.ipTotalLen = d.readUInt16BE(off + 2);
  p.ipId = d.readUInt16BE(off + 4);
  const fo = d.readUInt16BE(off + 6);
  p.ipDf = (fo & 0x4000) !== 0;
  p.ipMf = (fo & 0x2000) !== 0;
  p.ipFragOffset = (fo & 0x1fff) * 8;
  p.ttl = d[off + 8];
  p.ipProto = d[off + 9];
  p.ipSrc = fmt4(d, off + 12);
  p.ipDst = fmt4(d, off + 16);
  p.proto = IP_PROTOS[p.ipProto] ?? 'IPv4';
  p.info = `${p.ipSrc} → ${p.ipDst} (${IP_PROTOS[p.ipProto] ?? `protocolo ${p.ipProto}`})`;
  const end = Math.min(d.length, off + (p.ipTotalLen || d.length - off));
  if (p.ipFragOffset > 0) {
    p.proto = 'IPv4';
    p.info = `Fragmento IPv4 (offset ${p.ipFragOffset}) ${p.ipSrc} → ${p.ipDst}`;
    return;
  }
  decodeL4(p, p.ipProto, off + ihl, end);
  if (p.ipMf && p.info) p.info += ' [fragmentado]';
}

function decodeIPv6(p: DecodedPacket, off: number): void {
  const d = p.data;
  if (d.length < off + 40) return;
  p.ipVer = 6;
  const payloadLen = d.readUInt16BE(off + 4);
  p.ipTotalLen = payloadLen + 40;
  let next = d[off + 6];
  p.ttl = d[off + 7];
  p.ipSrc = fmt6(d, off + 8);
  p.ipDst = fmt6(d, off + 24);
  let o = off + 40;
  const end = Math.min(d.length, off + 40 + payloadLen);
  // cabeçalhos de extensão
  for (let guard = 0; guard < 8; guard += 1) {
    if (next === 0 || next === 43 || next === 60) {
      if (o + 2 > end) break;
      const len = (d[o + 1] + 1) * 8;
      next = d[o];
      o += len;
    } else if (next === 44) {
      if (o + 8 > end) break;
      p.ipMf = (d.readUInt16BE(o + 2) & 1) !== 0;
      p.ipFragOffset = (d.readUInt16BE(o + 2) >> 3) * 8;
      next = d[o];
      o += 8;
    } else break;
  }
  p.ipProto = next;
  p.proto = IP_PROTOS[next] ?? 'IPv6';
  p.info = `${p.ipSrc} → ${p.ipDst} (${IP_PROTOS[next] ?? `protocolo ${next}`})`;
  if (p.ipFragOffset && p.ipFragOffset > 0) return;
  decodeL4(p, next, o, end);
}

function decodeL4(p: DecodedPacket, proto: number, off: number, end: number): void {
  if (proto === 6) decodeTcp(p, off, end);
  else if (proto === 17) decodeUdp(p, off, end);
  else if (proto === 1) decodeIcmp(p, off, end, false);
  else if (proto === 58) decodeIcmp(p, off, end, true);
  else if (proto === 50) {
    p.info = `ESP (IPsec) ${p.ipSrc} → ${p.ipDst}` + (end - off >= 8 ? ` SPI=0x${p.data.readUInt32BE(off).toString(16)}` : '');
  }
}

function decodeTcp(p: DecodedPacket, off: number, end: number): void {
  const d = p.data;
  if (end - off < 20) return;
  const hdrLen = (d[off + 12] >> 4) * 4;
  const flags = ((d[off + 12] & 1) << 8) | d[off + 13];
  const tcp: TcpInfo = {
    sport: d.readUInt16BE(off),
    dport: d.readUInt16BE(off + 2),
    seq: d.readUInt32BE(off + 4),
    ack: d.readUInt32BE(off + 8),
    flags,
    win: d.readUInt16BE(off + 14),
    hdrLen,
    payLen: Math.max(0, end - off - hdrLen),
  };
  // opções
  let o = off + 20;
  const optEnd = Math.min(end, off + hdrLen);
  while (o < optEnd) {
    const kind = d[o];
    if (kind === 0) break;
    if (kind === 1) { o += 1; continue; }
    const len = d[o + 1];
    if (!len || len < 2) break;
    if (kind === 2 && len === 4) tcp.mss = d.readUInt16BE(o + 2);
    else if (kind === 3 && len === 3) tcp.wscale = d[o + 2];
    else if (kind === 4) tcp.sackPermitted = true;
    o += len;
  }
  p.tcp = tcp;
  p.payOff = off + hdrLen;
  p.payLen = tcp.payLen;
  p.proto = 'TCP';
  const names = tcpFlagNames(flags & 0x1ff);
  let info = `${tcp.sport} → ${tcp.dport} [${names.join(', ')}] Seq=${tcp.seq} Ack=${tcp.ack} Win=${tcp.win} Len=${tcp.payLen}`;
  if (tcp.mss) info += ` MSS=${tcp.mss}`;
  if (tcp.wscale !== undefined) info += ` WS=${2 ** tcp.wscale}`;
  p.info = info;
  if (tcp.payLen > 0) decodeTcpPayload(p);
}

function decodeTcpPayload(p: DecodedPacket): void {
  const d = p.data;
  const tcp = p.tcp!;
  const start = p.payOff;
  const end = Math.min(d.length, start + tcp.payLen);
  if (start >= end) return;

  // DNS sobre TCP (2 bytes de tamanho antes da mensagem)
  if ((tcp.sport === 53 || tcp.dport === 53) && end - start > 14) {
    const len = d.readUInt16BE(start);
    if (len === end - start - 2) {
      const dns = parseDns(d, start + 2, end);
      if (dns) return applyDns(p, dns);
    }
  }

  const b0 = d[start];
  // TLS: tipo (20..24), versão 3.x
  if (b0 >= 20 && b0 <= 24 && end - start >= 5 && d[start + 1] === 3 && d[start + 2] <= 4) {
    const tls = parseTls(d, start, end);
    if (tls) {
      p.tls = tls;
      p.proto = 'TLS';
      const what =
        tls.contentType === 22 && tls.handshakeType !== undefined
          ? (TLS_HANDSHAKE[tls.handshakeType] ?? `Handshake ${tls.handshakeType}`) + (tls.sni ? ` (SNI=${tls.sni})` : '')
          : (TLS_CONTENT[tls.contentType] ?? `Registro ${tls.contentType}`);
      p.info = `${what} · ${tlsVersionName(tls.version)}`;
      return;
    }
  }

  const head = d.toString('latin1', start, Math.min(end, start + 8));
  if (head.startsWith('SSH-')) {
    p.ssh = d.toString('latin1', start, Math.min(end, start + 80)).split(/\r?\n/)[0];
    p.proto = 'SSH';
    p.info = `Banner: ${p.ssh}`;
    return;
  }

  const http = parseHttp(d, start, end);
  if (http) {
    p.http = http;
    p.proto = 'HTTP';
    p.info = http.firstLine.slice(0, 160);
  }
}

function parseTls(d: Buffer, start: number, end: number): TlsInfo | null {
  const contentType = d[start];
  const version = d.readUInt16BE(start + 1);
  const tls: TlsInfo = { contentType, version };
  if (contentType === 22 && end - start >= 9) {
    tls.handshakeType = d[start + 5];
    if (tls.handshakeType === 1) tls.sni = parseClientHelloSni(d, start + 5, end);
  }
  return tls;
}

function parseClientHelloSni(d: Buffer, hs: number, end: number): string | undefined {
  try {
    // tipo(1) tamanho(3) versão(2) random(32)
    let o = hs + 4 + 2 + 32;
    if (o + 1 > end) return undefined;
    o += 1 + d[o]; // session id
    if (o + 2 > end) return undefined;
    o += 2 + d.readUInt16BE(o); // cipher suites
    if (o + 1 > end) return undefined;
    o += 1 + d[o]; // compression
    if (o + 2 > end) return undefined;
    const extEnd = Math.min(end, o + 2 + d.readUInt16BE(o));
    o += 2;
    while (o + 4 <= extEnd) {
      const type = d.readUInt16BE(o);
      const len = d.readUInt16BE(o + 2);
      if (type === 0 && o + 9 <= extEnd) {
        const nameLen = d.readUInt16BE(o + 7);
        return d.toString('ascii', o + 9, Math.min(extEnd, o + 9 + nameLen));
      }
      o += 4 + len;
    }
  } catch {
    // ignora
  }
  return undefined;
}

const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'HEAD ', 'DELETE ', 'PATCH ', 'OPTIONS ', 'CONNECT ', 'TRACE '];

function parseHttp(d: Buffer, start: number, end: number): HttpInfo | null {
  const text = d.toString('latin1', start, Math.min(end, start + 2048));
  const isReq = HTTP_METHODS.some((m) => text.startsWith(m));
  const isResp = text.startsWith('HTTP/1.');
  if (!isReq && !isResp) return null;
  const headEnd = text.indexOf('\r\n\r\n');
  const lines = (headEnd >= 0 ? text.slice(0, headEnd) : text).split(/\r?\n/);
  const firstLine = lines[0];
  const headers = lines.slice(1).filter(Boolean).slice(0, 40);
  const host = headers.find((h) => /^host:/i.test(h))?.split(':').slice(1).join(':').trim();
  if (isReq) {
    const m = /^(\S+) (\S+) (HTTP\/\d\.\d)/.exec(firstLine);
    if (!m) return null;
    return { isRequest: true, method: m[1], uri: m[2], host, version: m[3], firstLine, headers };
  }
  const m = /^(HTTP\/\d\.\d) (\d{3})/.exec(firstLine);
  if (!m) return null;
  return { isRequest: false, status: Number(m[2]), version: m[1], firstLine, headers };
}

function decodeUdp(p: DecodedPacket, off: number, end: number): void {
  const d = p.data;
  if (end - off < 8) return;
  const udp: UdpInfo = { sport: d.readUInt16BE(off), dport: d.readUInt16BE(off + 2), len: d.readUInt16BE(off + 4) };
  p.udp = udp;
  p.payOff = off + 8;
  p.payLen = Math.max(0, Math.min(end, off + udp.len) - (off + 8));
  const svc = UDP_SERVICES[udp.dport] ?? UDP_SERVICES[udp.sport];
  p.proto = svc ?? 'UDP';
  p.info = `${udp.sport} → ${udp.dport} Len=${p.payLen}`;
  if ((udp.sport === 53 || udp.dport === 53 || udp.sport === 5353 || udp.dport === 5353) && p.payLen >= 12) {
    const dns = parseDns(d, p.payOff, p.payOff + p.payLen);
    if (dns) {
      applyDns(p, dns);
      if (udp.sport === 5353 || udp.dport === 5353) p.proto = 'MDNS';
      return;
    }
  }
  if ((udp.sport === 443 || udp.dport === 443) && p.payLen > 0) {
    p.proto = 'QUIC';
    p.info = `${udp.sport} → ${udp.dport} Len=${p.payLen} (UDP/443, provável QUIC/HTTP3)`;
  } else if (udp.sport === 500 || udp.dport === 500 || udp.sport === 4500 || udp.dport === 4500) {
    p.info = `${udp.sport} → ${udp.dport} Len=${p.payLen} (IPsec/IKE)`;
  }
}

function applyDns(p: DecodedPacket, dns: DnsInfo): void {
  p.dns = dns;
  p.proto = 'DNS';
  const t = dns.qtype !== undefined ? (DNS_TYPES[dns.qtype] ?? `TYPE${dns.qtype}`) : '';
  if (dns.response) {
    const rc = dns.rcode !== 0 ? ` ${DNS_RCODES[dns.rcode] ?? `rcode ${dns.rcode}`}` : '';
    const ans = dns.answers.length ? ` → ${dns.answers.slice(0, 4).join(', ')}${dns.answers.length > 4 ? '…' : ''}` : '';
    p.info = `Resposta 0x${dns.id.toString(16)} ${t} ${dns.qname ?? ''}${rc}${ans}`.replace(/\s+/g, ' ');
  } else {
    p.info = `Consulta 0x${dns.id.toString(16)} ${t} ${dns.qname ?? ''}`.replace(/\s+/g, ' ');
  }
}

function readDnsName(d: Buffer, start: number, msgStart: number, end: number): { name: string; next: number } | null {
  const labels: string[] = [];
  let o = start;
  let next = -1;
  for (let hops = 0; hops < 40; hops += 1) {
    if (o >= end) return null;
    const len = d[o];
    if (len === 0) {
      if (next < 0) next = o + 1;
      return { name: labels.join('.') || '.', next };
    }
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= end) return null;
      if (next < 0) next = o + 2;
      o = msgStart + (((len & 0x3f) << 8) | d[o + 1]);
      continue;
    }
    if (len > 63 || o + 1 + len > end) return null;
    labels.push(d.toString('ascii', o + 1, o + 1 + len));
    o += 1 + len;
  }
  return null;
}

function parseDns(d: Buffer, start: number, end: number): DnsInfo | null {
  if (end - start < 12) return null;
  const id = d.readUInt16BE(start);
  const flags = d.readUInt16BE(start + 2);
  const qd = d.readUInt16BE(start + 4);
  const an = d.readUInt16BE(start + 6);
  if (qd > 8 || an > 64) return null;
  const opcode = (flags >> 11) & 0xf;
  if (opcode > 5) return null;
  const dns: DnsInfo = { id, response: (flags & 0x8000) !== 0, opcode, rcode: flags & 0xf, answers: [], answerIps: [] };
  let o = start + 12;
  for (let i = 0; i < qd; i += 1) {
    const n = readDnsName(d, o, start, end);
    if (!n || n.next + 4 > end) return dns.qname ? dns : null;
    if (i === 0) {
      dns.qname = n.name;
      dns.qtype = d.readUInt16BE(n.next);
    }
    o = n.next + 4;
  }
  for (let i = 0; i < an; i += 1) {
    const n = readDnsName(d, o, start, end);
    if (!n || n.next + 10 > end) break;
    const type = d.readUInt16BE(n.next);
    const rdlen = d.readUInt16BE(n.next + 8);
    const rd = n.next + 10;
    if (rd + rdlen > end) break;
    if (type === 1 && rdlen === 4) {
      const ip = fmt4(d, rd);
      dns.answers.push(ip);
      dns.answerIps.push(ip);
    } else if (type === 28 && rdlen === 16) {
      const ip = fmt6(d, rd);
      dns.answers.push(ip);
      dns.answerIps.push(ip);
    } else if (type === 5 || type === 2 || type === 12) {
      const t = readDnsName(d, rd, start, end);
      dns.answers.push(t ? `${DNS_TYPES[type]} ${t.name}` : DNS_TYPES[type]);
    } else if (type === 15 && rdlen > 2) {
      const t = readDnsName(d, rd + 2, start, end);
      dns.answers.push(t ? `MX ${t.name}` : 'MX');
    } else {
      dns.answers.push(DNS_TYPES[type] ?? `TYPE${type}`);
    }
    o = rd + rdlen;
  }
  return dns;
}

function decodeIcmp(p: DecodedPacket, off: number, end: number, v6: boolean): void {
  const d = p.data;
  if (end - off < 4) return;
  const type = d[off];
  const code = d[off + 1];
  const icmp: IcmpInfo = { v6, type, code };
  const isEcho = v6 ? type === 128 || type === 129 : type === 0 || type === 8;
  if (isEcho && end - off >= 8) {
    icmp.id = d.readUInt16BE(off + 4);
    icmp.seq = d.readUInt16BE(off + 6);
  }
  p.icmp = icmp;
  p.proto = v6 ? 'ICMPv6' : 'ICMP';
  const name = (v6 ? ICMP6_TYPES : ICMP_TYPES)[type] ?? `Tipo ${type}`;
  let info = name;
  if (!v6 && type === 3) info += `: ${ICMP_UNREACH_CODES[code] ?? `código ${code}`}`;
  else if (code) info += ` (código ${code})`;
  if (isEcho) info += ` id=0x${(icmp.id ?? 0).toString(16)} seq=${icmp.seq}`;
  // erros ICMP carregam o cabeçalho IP original: mostra o destino original
  if (!v6 && (type === 3 || type === 11) && end - off >= 8 + 20) {
    const inner = off + 8;
    if ((d[inner] >> 4) === 4) info += ` (pacote original: ${fmt4(d, inner + 12)} → ${fmt4(d, inner + 16)})`;
  }
  p.info = info;
}

/** Dados auxiliares para a tela de detalhe e o "seguir stream". */
export function payloadOf(p: DecodedPacket): Buffer {
  if (p.payOff < 0 || p.payLen <= 0) return Buffer.alloc(0);
  return p.data.subarray(p.payOff, Math.min(p.data.length, p.payOff + p.payLen));
}
