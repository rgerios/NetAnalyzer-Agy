/**
 * Filtros de exibição no estilo Wireshark (subconjunto): campos, operadores de comparação,
 * `contains`/`matches`, conjuntos `in {…}`, CIDR em campos de IP e lógica `&&`/`||`/`!`
 * (ou `and`/`or`/`not`). Erros de sintaxe e campos desconhecidos viram mensagens em português.
 */
import type { DecodedPacket } from './decode.ts';
import { payloadOf } from './decode.ts';
import { ipMatches, parseIpMatcher, type IpMatcher } from './ipaddr.ts';

export class FilterError extends Error {
  pos: number;
  constructor(message: string, pos = 0) {
    super(message);
    this.pos = pos;
  }
}

type Val = number | string | boolean;
type FieldType = 'num' | 'str' | 'ip' | 'mac' | 'bool' | 'proto';

interface FieldDef {
  t: FieldType;
  get: (p: DecodedPacket) => Val[] | undefined;
  /** Para campos de protocolo: bytes consultados por `contains`/`matches`. */
  raw?: (p: DecodedPacket) => Buffer | undefined;
  doc?: string;
}

const present = (cond: boolean): Val[] | undefined => (cond ? [true] : undefined);

const FLAG = (bit: number) => (p: DecodedPacket): Val[] | undefined => (p.tcp ? [(p.tcp.flags & bit) !== 0] : undefined);
const has = (p: DecodedPacket, name: string) => p.expert.includes(name);

function proto(test: (p: DecodedPacket) => boolean, raw?: (p: DecodedPacket) => Buffer | undefined): FieldDef {
  return { t: 'proto', get: (p) => present(test(p)), raw };
}

const payloadRaw = (p: DecodedPacket): Buffer | undefined => {
  const b = payloadOf(p);
  return b.length ? b : undefined;
};

export const FIELDS: Record<string, FieldDef> = {
  frame: proto(() => true, (p) => p.data),
  'frame.number': { t: 'num', get: (p) => [p.no] },
  'frame.len': { t: 'num', get: (p) => [p.wireLen] },
  'frame.cap_len': { t: 'num', get: (p) => [p.capLen] },
  'frame.time_epoch': { t: 'num', get: (p) => [p.ts] },
  'frame.time_relative': { t: 'num', get: (p) => [p.rel] },

  eth: proto((p) => p.ethSrc !== undefined),
  'eth.src': { t: 'mac', get: (p) => (p.ethSrc ? [p.ethSrc] : undefined) },
  'eth.dst': { t: 'mac', get: (p) => (p.ethDst ? [p.ethDst] : undefined) },
  'eth.addr': { t: 'mac', get: (p) => (p.ethSrc && p.ethDst ? [p.ethSrc, p.ethDst] : undefined) },
  'eth.type': { t: 'num', get: (p) => (p.ethType !== undefined ? [p.ethType] : undefined) },
  vlan: proto((p) => p.vlan !== undefined),
  'vlan.id': { t: 'num', get: (p) => (p.vlan !== undefined ? [p.vlan] : undefined) },

  ip: proto((p) => p.ipVer === 4),
  'ip.src': { t: 'ip', get: (p) => (p.ipVer === 4 && p.ipSrc ? [p.ipSrc] : undefined) },
  'ip.dst': { t: 'ip', get: (p) => (p.ipVer === 4 && p.ipDst ? [p.ipDst] : undefined) },
  'ip.addr': { t: 'ip', get: (p) => (p.ipVer === 4 && p.ipSrc && p.ipDst ? [p.ipSrc, p.ipDst] : undefined) },
  'ip.proto': { t: 'num', get: (p) => (p.ipVer === 4 && p.ipProto !== undefined ? [p.ipProto] : undefined) },
  'ip.ttl': { t: 'num', get: (p) => (p.ipVer === 4 && p.ttl !== undefined ? [p.ttl] : undefined) },
  'ip.len': { t: 'num', get: (p) => (p.ipVer === 4 && p.ipTotalLen !== undefined ? [p.ipTotalLen] : undefined) },
  'ip.id': { t: 'num', get: (p) => (p.ipVer === 4 && p.ipId !== undefined ? [p.ipId] : undefined) },
  'ip.flags.df': { t: 'bool', get: (p) => (p.ipVer === 4 ? [!!p.ipDf] : undefined) },
  'ip.flags.mf': { t: 'bool', get: (p) => (p.ipVer === 4 ? [!!p.ipMf] : undefined) },
  'ip.frag_offset': { t: 'num', get: (p) => (p.ipVer === 4 ? [p.ipFragOffset ?? 0] : undefined) },
  ipv6: proto((p) => p.ipVer === 6),
  'ipv6.src': { t: 'ip', get: (p) => (p.ipVer === 6 && p.ipSrc ? [p.ipSrc] : undefined) },
  'ipv6.dst': { t: 'ip', get: (p) => (p.ipVer === 6 && p.ipDst ? [p.ipDst] : undefined) },
  'ipv6.addr': { t: 'ip', get: (p) => (p.ipVer === 6 && p.ipSrc && p.ipDst ? [p.ipSrc, p.ipDst] : undefined) },
  'ipv6.hlim': { t: 'num', get: (p) => (p.ipVer === 6 && p.ttl !== undefined ? [p.ttl] : undefined) },

  tcp: proto((p) => !!p.tcp, payloadRaw),
  'tcp.srcport': { t: 'num', get: (p) => (p.tcp ? [p.tcp.sport] : undefined) },
  'tcp.dstport': { t: 'num', get: (p) => (p.tcp ? [p.tcp.dport] : undefined) },
  'tcp.port': { t: 'num', get: (p) => (p.tcp ? [p.tcp.sport, p.tcp.dport] : undefined) },
  'tcp.seq': { t: 'num', get: (p) => (p.tcp ? [p.tcp.seq] : undefined) },
  'tcp.ack': { t: 'num', get: (p) => (p.tcp ? [p.tcp.ack] : undefined) },
  'tcp.len': { t: 'num', get: (p) => (p.tcp ? [p.tcp.payLen] : undefined) },
  'tcp.hdr_len': { t: 'num', get: (p) => (p.tcp ? [p.tcp.hdrLen] : undefined) },
  'tcp.window_size': { t: 'num', get: (p) => (p.tcp ? [p.tcp.win] : undefined) },
  'tcp.stream': { t: 'num', get: (p) => (p.stream !== undefined ? [p.stream] : undefined) },
  'tcp.flags': { t: 'num', get: (p) => (p.tcp ? [p.tcp.flags] : undefined) },
  'tcp.flags.syn': { t: 'bool', get: FLAG(0x02) },
  'tcp.flags.ack': { t: 'bool', get: FLAG(0x10) },
  'tcp.flags.fin': { t: 'bool', get: FLAG(0x01) },
  'tcp.flags.reset': { t: 'bool', get: FLAG(0x04) },
  'tcp.flags.push': { t: 'bool', get: FLAG(0x08) },
  'tcp.flags.urg': { t: 'bool', get: FLAG(0x20) },
  'tcp.flags.ece': { t: 'bool', get: FLAG(0x40) },
  'tcp.flags.cwr': { t: 'bool', get: FLAG(0x80) },
  'tcp.options.mss_val': { t: 'num', get: (p) => (p.tcp?.mss !== undefined ? [p.tcp.mss] : undefined) },
  'tcp.analysis.flags': { t: 'bool', get: (p) => (p.tcp && p.expert.length ? [true] : undefined) },
  'tcp.analysis.retransmission': { t: 'bool', get: (p) => present(has(p, 'retransmission')) },
  'tcp.analysis.out_of_order': { t: 'bool', get: (p) => present(has(p, 'out_of_order')) },
  'tcp.analysis.zero_window': { t: 'bool', get: (p) => present(has(p, 'zero_window')) },
  'tcp.analysis.duplicate_ack': { t: 'bool', get: (p) => present(has(p, 'dup_ack')) },

  udp: proto((p) => !!p.udp, payloadRaw),
  'udp.srcport': { t: 'num', get: (p) => (p.udp ? [p.udp.sport] : undefined) },
  'udp.dstport': { t: 'num', get: (p) => (p.udp ? [p.udp.dport] : undefined) },
  'udp.port': { t: 'num', get: (p) => (p.udp ? [p.udp.sport, p.udp.dport] : undefined) },
  'udp.length': { t: 'num', get: (p) => (p.udp ? [p.udp.len] : undefined) },
  'udp.stream': { t: 'num', get: (p) => (p.udpStream !== undefined ? [p.udpStream] : undefined) },

  icmp: proto((p) => !!p.icmp && !p.icmp.v6),
  'icmp.type': { t: 'num', get: (p) => (p.icmp && !p.icmp.v6 ? [p.icmp.type] : undefined) },
  'icmp.code': { t: 'num', get: (p) => (p.icmp && !p.icmp.v6 ? [p.icmp.code] : undefined) },
  icmpv6: proto((p) => !!p.icmp && p.icmp.v6),
  'icmpv6.type': { t: 'num', get: (p) => (p.icmp?.v6 ? [p.icmp.type] : undefined) },
  'icmpv6.code': { t: 'num', get: (p) => (p.icmp?.v6 ? [p.icmp.code] : undefined) },

  arp: proto((p) => !!p.arp),
  'arp.opcode': { t: 'num', get: (p) => (p.arp ? [p.arp.op] : undefined) },
  'arp.src.proto_ipv4': { t: 'ip', get: (p) => (p.arp ? [p.arp.senderIp] : undefined) },
  'arp.dst.proto_ipv4': { t: 'ip', get: (p) => (p.arp ? [p.arp.targetIp] : undefined) },
  'arp.src.hw_mac': { t: 'mac', get: (p) => (p.arp ? [p.arp.senderMac] : undefined) },
  'arp.dst.hw_mac': { t: 'mac', get: (p) => (p.arp ? [p.arp.targetMac] : undefined) },

  dns: proto((p) => !!p.dns, payloadRaw),
  'dns.id': { t: 'num', get: (p) => (p.dns ? [p.dns.id] : undefined) },
  'dns.flags.response': { t: 'bool', get: (p) => (p.dns ? [p.dns.response] : undefined) },
  'dns.flags.rcode': { t: 'num', get: (p) => (p.dns ? [p.dns.rcode] : undefined) },
  'dns.qry.name': { t: 'str', get: (p) => (p.dns?.qname ? [p.dns.qname] : undefined) },
  'dns.qry.type': { t: 'num', get: (p) => (p.dns?.qtype !== undefined ? [p.dns.qtype] : undefined) },
  'dns.a': { t: 'ip', get: (p) => (p.dns?.answerIps.length ? p.dns.answerIps : undefined) },
  'dns.count.answers': { t: 'num', get: (p) => (p.dns ? [p.dns.answers.length] : undefined) },

  http: proto((p) => !!p.http, payloadRaw),
  'http.request': { t: 'bool', get: (p) => present(!!p.http?.isRequest) },
  'http.response': { t: 'bool', get: (p) => present(!!p.http && !p.http.isRequest) },
  'http.request.method': { t: 'str', get: (p) => (p.http?.method ? [p.http.method] : undefined) },
  'http.request.uri': { t: 'str', get: (p) => (p.http?.uri ? [p.http.uri] : undefined) },
  'http.host': { t: 'str', get: (p) => (p.http?.host ? [p.http.host] : undefined) },
  'http.response.code': { t: 'num', get: (p) => (p.http?.status !== undefined ? [p.http.status] : undefined) },

  tls: proto((p) => !!p.tls, payloadRaw),
  ssl: proto((p) => !!p.tls, payloadRaw),
  'tls.record.content_type': { t: 'num', get: (p) => (p.tls ? [p.tls.contentType] : undefined) },
  'tls.record.version': { t: 'num', get: (p) => (p.tls ? [p.tls.version] : undefined) },
  'tls.handshake.type': { t: 'num', get: (p) => (p.tls?.handshakeType !== undefined ? [p.tls.handshakeType] : undefined) },
  'tls.handshake.extensions_server_name': { t: 'str', get: (p) => (p.tls?.sni ? [p.tls.sni] : undefined) },
  ssh: proto((p) => !!p.ssh),
};

export const FIELD_NAMES = Object.keys(FIELDS);

// ---------------------------------------------------------------------------
// Tokenização
// ---------------------------------------------------------------------------

type Tok =
  | { t: 'word'; v: string; pos: number }
  | { t: 'str'; v: string; pos: number }
  | { t: 'op'; v: string; pos: number };

const WORD_RE = /[A-Za-z0-9_.:/*+\-]/;

function unescapeStr(s: string): string {
  return s.replace(/\\(x[0-9a-fA-F]{2}|.)/g, (_m, g: string) => {
    if (g.startsWith('x') && g.length === 3) return String.fromCharCode(parseInt(g.slice(1), 16));
    if (g === 'n') return '\n';
    if (g === 'r') return '\r';
    if (g === 't') return '\t';
    return g;
  });
}

function tokenize(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) {
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let raw = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          raw += src[j] + src[j + 1];
          j += 2;
        } else {
          raw += src[j];
          j += 1;
        }
      }
      if (j >= src.length) throw new FilterError('Aspas não fechadas.', i);
      out.push({ t: 'str', v: unescapeStr(raw), pos: i });
      i = j + 1;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (['&&', '||', '==', '!=', '>=', '<='].includes(two)) {
      out.push({ t: 'op', v: two, pos: i });
      i += 2;
      continue;
    }
    if ('()!<>{}~,='.includes(c)) {
      out.push({ t: 'op', v: c === '=' ? '==' : c, pos: i });
      i += 1;
      continue;
    }
    if (WORD_RE.test(c)) {
      let j = i;
      while (j < src.length && WORD_RE.test(src[j])) j += 1;
      out.push({ t: 'word', v: src.slice(i, j), pos: i });
      i = j;
      continue;
    }
    throw new FilterError(`Caractere inesperado "${c}".`, i);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Parser + compilação
// ---------------------------------------------------------------------------

export type PacketTest = (p: DecodedPacket) => boolean;

const CMP_WORDS: Record<string, string> = {
  eq: '==', ne: '!=', gt: '>', ge: '>=', lt: '<', le: '<=', contains: 'contains', matches: 'matches', in: 'in',
};

function suggestFields(name: string): string[] {
  const head = name.split('.')[0];
  const same = FIELD_NAMES.filter((f) => f === head || f.startsWith(`${head}.`));
  const near = FIELD_NAMES.filter((f) => f.includes(name) || name.includes(f));
  return [...new Set([...near, ...same])].slice(0, 6);
}

class Parser {
  private i = 0;
  private toks: Tok[];
  constructor(toks: Tok[]) {
    this.toks = toks;
  }

  parse(): PacketTest {
    const t = this.or();
    if (this.i < this.toks.length) {
      const tok = this.toks[this.i];
      throw new FilterError(`Trecho inesperado "${tok.v}". Faltou && / || entre as condições?`, tok.pos);
    }
    return t;
  }

  private peek(): Tok | undefined {
    return this.toks[this.i];
  }

  private isLogic(tok: Tok | undefined, sym: string, word: string): boolean {
    return !!tok && ((tok.t === 'op' && tok.v === sym) || (tok.t === 'word' && tok.v.toLowerCase() === word));
  }

  private or(): PacketTest {
    let left = this.and();
    while (this.isLogic(this.peek(), '||', 'or')) {
      this.i += 1;
      const l = left;
      const r = this.and();
      left = (p) => l(p) || r(p);
    }
    return left;
  }

  private and(): PacketTest {
    let left = this.not();
    while (this.isLogic(this.peek(), '&&', 'and')) {
      this.i += 1;
      const l = left;
      const r = this.not();
      left = (p) => l(p) && r(p);
    }
    return left;
  }

  private not(): PacketTest {
    if (this.isLogic(this.peek(), '!', 'not')) {
      this.i += 1;
      const inner = this.not();
      return (p) => !inner(p);
    }
    return this.primary();
  }

  private primary(): PacketTest {
    const tok = this.peek();
    if (!tok) throw new FilterError('Expressão incompleta: esperava um campo ou protocolo.', 0);
    if (tok.t === 'op' && tok.v === '(') {
      this.i += 1;
      const inner = this.or();
      const close = this.peek();
      if (!close || close.t !== 'op' || close.v !== ')') throw new FilterError('Faltou fechar o parêntese ")".', tok.pos);
      this.i += 1;
      return inner;
    }
    if (tok.t !== 'word') throw new FilterError(`Esperava um campo (ex.: ip.addr), encontrei "${tok.v}".`, tok.pos);
    this.i += 1;
    const name = tok.v.toLowerCase();
    const def = FIELDS[name];
    if (!def) {
      const sug = suggestFields(name);
      throw new FilterError(
        `Campo desconhecido "${tok.v}".` + (sug.length ? ` Parecidos: ${sug.join(', ')}.` : ''),
        tok.pos
      );
    }
    const next = this.peek();
    let op: string | null = null;
    if (next && next.t === 'op' && ['==', '!=', '>', '>=', '<', '<=', '~'].includes(next.v)) op = next.v === '~' ? 'matches' : next.v;
    else if (next && next.t === 'word' && CMP_WORDS[next.v.toLowerCase()]) op = CMP_WORDS[next.v.toLowerCase()];
    if (!op) {
      // presença do campo/protocolo
      if (def.t === 'bool') return (p) => (def.get(p) ?? []).some((v) => v === true);
      return (p) => def.get(p) !== undefined;
    }
    const opTok = next as Tok;
    this.i += 1;
    if (op === 'in') return this.compileIn(name, def, opTok);
    const rhs = this.peek();
    if (!rhs || (rhs.t !== 'word' && rhs.t !== 'str')) {
      throw new FilterError(`Faltou o valor depois de "${opTok.v}".`, opTok.pos);
    }
    this.i += 1;
    return compileCompare(name, def, op, rhs.v, rhs.pos);
  }

  private compileIn(name: string, def: FieldDef, opTok: Tok): PacketTest {
    const open = this.peek();
    if (!open || open.t !== 'op' || open.v !== '{') throw new FilterError('Depois de "in" use chaves: {80 443}.', opTok.pos);
    this.i += 1;
    const items: Array<{ v: string; pos: number }> = [];
    for (;;) {
      const t = this.peek();
      if (!t) throw new FilterError('Faltou fechar a chave "}".', open.pos);
      this.i += 1;
      if (t.t === 'op' && t.v === '}') break;
      if (t.t === 'op' && t.v === ',') continue;
      if (t.t === 'op') throw new FilterError(`Item inválido "${t.v}" dentro de {…}.`, t.pos);
      items.push({ v: t.v, pos: t.pos });
    }
    if (!items.length) throw new FilterError('Conjunto vazio em "in {}".', open.pos);
    const tests = items.map((it) => {
      if (def.t === 'num' && it.v.includes('..')) {
        const [a, b] = it.v.split('..');
        const lo = parseNum(a);
        const hi = parseNum(b);
        if (lo === null || hi === null) throw new FilterError(`Intervalo inválido "${it.v}".`, it.pos);
        return (p: DecodedPacket) => (def.get(p) ?? []).some((v) => typeof v === 'number' && v >= lo && v <= hi);
      }
      return compileCompare(name, def, '==', it.v, it.pos);
    });
    return (p) => tests.some((t) => t(p));
  }
}

function parseNum(text: string): number | null {
  if (/^0x[0-9a-fA-F]+$/.test(text)) return parseInt(text, 16);
  if (/^-?\d+(\.\d+)?$/.test(text)) return Number(text);
  return null;
}

function bufferContains(buf: Buffer | undefined, needle: string): boolean {
  if (!buf) return false;
  return buf.indexOf(Buffer.from(needle, 'latin1')) >= 0 || buf.toString('latin1').toLowerCase().includes(needle.toLowerCase());
}

function compileCompare(name: string, def: FieldDef, op: string, rhs: string, pos: number): PacketTest {
  if (def.t === 'proto') {
    if (op === 'contains') {
      const raw = def.raw;
      if (!raw) throw new FilterError(`"${name} contains" não é suportado.`, pos);
      return (p) => def.get(p) !== undefined && bufferContains(raw(p), rhs);
    }
    if (op === 'matches') {
      const raw = def.raw;
      if (!raw) throw new FilterError(`"${name} matches" não é suportado.`, pos);
      const re = compileRegex(rhs, pos);
      return (p) => {
        if (def.get(p) === undefined) return false;
        const b = raw(p);
        return !!b && re.test(b.toString('latin1'));
      };
    }
    throw new FilterError(`O protocolo "${name}" só aceita "contains" ou "matches". Use um campo (ex.: ${name}.port).`, pos);
  }

  const negate = op === '!=';
  const get = def.get;

  if (def.t === 'bool') {
    if (op !== '==' && op !== '!=') throw new FilterError(`O campo ${name} é verdadeiro/falso: use == 1 ou == 0.`, pos);
    const want = /^(1|true|yes)$/i.test(rhs) ? true : /^(0|false|no)$/i.test(rhs) ? false : null;
    if (want === null) throw new FilterError(`Valor "${rhs}" inválido para ${name}: use 1 ou 0.`, pos);
    return (p) => {
      const v = get(p);
      if (!v) return false;
      const eq = v.some((x) => x === want);
      return negate ? !eq : eq;
    };
  }

  if (def.t === 'num') {
    const n = parseNum(rhs);
    if (n === null) throw new FilterError(`Valor "${rhs}" inválido para ${name} (esperado número).`, pos);
    switch (op) {
      case '==': return (p) => get(p)?.some((v) => v === n) ?? false;
      case '!=': return (p) => { const v = get(p); return !!v && v.every((x) => x !== n); };
      case '>': return (p) => get(p)?.some((v) => (v as number) > n) ?? false;
      case '>=': return (p) => get(p)?.some((v) => (v as number) >= n) ?? false;
      case '<': return (p) => get(p)?.some((v) => (v as number) < n) ?? false;
      case '<=': return (p) => get(p)?.some((v) => (v as number) <= n) ?? false;
      default: throw new FilterError(`Operador "${op}" não se aplica ao campo numérico ${name}.`, pos);
    }
  }

  if (def.t === 'ip') {
    if (op !== '==' && op !== '!=') throw new FilterError(`Em campos de IP use == ou != (aceita CIDR, ex.: 10.0.0.0/8).`, pos);
    const m: IpMatcher | null = parseIpMatcher(rhs);
    if (!m) throw new FilterError(`Endereço IP inválido: "${rhs}".`, pos);
    return (p) => {
      const v = get(p);
      if (!v) return false;
      const any = v.some((x) => ipMatches(String(x), m));
      return negate ? !any : any;
    };
  }

  if (def.t === 'mac') {
    if (op !== '==' && op !== '!=') throw new FilterError('Em campos MAC use == ou !=.', pos);
    const want = rhs.toLowerCase().replace(/-/g, ':');
    return (p) => {
      const v = get(p);
      if (!v) return false;
      const any = v.some((x) => String(x) === want);
      return negate ? !any : any;
    };
  }

  // texto
  const low = rhs.toLowerCase();
  switch (op) {
    case '==': return (p) => get(p)?.some((v) => String(v).toLowerCase() === low) ?? false;
    case '!=': return (p) => { const v = get(p); return !!v && v.every((x) => String(x).toLowerCase() !== low); };
    case 'contains': return (p) => get(p)?.some((v) => String(v).toLowerCase().includes(low)) ?? false;
    case 'matches': {
      const re = compileRegex(rhs, pos);
      return (p) => get(p)?.some((v) => re.test(String(v))) ?? false;
    }
    default: throw new FilterError(`Operador "${op}" não se aplica ao campo de texto ${name}.`, pos);
  }
}

function compileRegex(src: string, pos: number): RegExp {
  try {
    return new RegExp(src, 'i');
  } catch {
    throw new FilterError(`Expressão regular inválida: "${src}".`, pos);
  }
}

/** Compila o filtro; vazio = aceita tudo (devolve null). */
export function compileFilter(text: string): PacketTest | null {
  const src = text.trim();
  if (!src) return null;
  return new Parser(tokenize(src)).parse();
}

/** Exemplos prontos para a interface. */
export const FILTER_EXAMPLES: Array<{ label: string; filter: string; hint: string }> = [
  { label: 'Handshakes TCP novos (SYN)', filter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0', hint: 'Tentativas de abrir conexão' },
  { label: 'Resets (RST)', filter: 'tcp.flags.reset == 1', hint: 'Conexões recusadas ou derrubadas' },
  { label: 'Retransmissões TCP', filter: 'tcp.analysis.retransmission', hint: 'Pacotes reenviados: perda ou bloqueio' },
  { label: 'Problemas TCP (qualquer)', filter: 'tcp.analysis.flags', hint: 'Retransmissão, janela zero, duplicados…' },
  { label: 'Tráfego de um IP', filter: 'ip.addr == 192.168.1.10', hint: 'Origem ou destino' },
  { label: 'Rede inteira (CIDR)', filter: 'ip.addr == 10.0.0.0/8', hint: 'Aceita máscara' },
  { label: 'Web (80/443)', filter: 'tcp.port in {80 443}', hint: 'Conjunto de portas' },
  { label: 'DNS com erro', filter: 'dns.flags.rcode != 0', hint: 'NXDOMAIN, SERVFAIL, REFUSED' },
  { label: 'Consultas DNS por nome', filter: 'dns.qry.name contains "microsoft"', hint: 'Texto no nome consultado' },
  { label: 'SNI TLS', filter: 'tls.handshake.extensions_server_name contains "google"', hint: 'Domínio no Client Hello' },
  { label: 'ICMP inalcançável', filter: 'icmp.type == 3', hint: 'Destino/porta/rede inalcançável' },
  { label: 'HTTP erros (>= 400)', filter: 'http.response.code >= 400', hint: 'Respostas de erro' },
  { label: 'Excluir ruído', filter: '!(arp || dns || icmp || udp.port in {137 138 5353 1900})', hint: 'Esconde broadcasts comuns' },
  { label: 'Texto no payload', filter: 'tcp contains "password"', hint: 'Busca bytes no payload TCP' },
];
