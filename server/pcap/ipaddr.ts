/** Utilidades de endereço IPv4/IPv6 e MAC para o analisador de PCAP. */

export function fmtMac(buf: Buffer, off: number): string {
  let out = '';
  for (let i = 0; i < 6; i += 1) {
    out += (i ? ':' : '') + buf[off + i].toString(16).padStart(2, '0');
  }
  return out;
}

export function fmt4(buf: Buffer, off: number): string {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

/** IPv6 em notação comprimida (RFC 5952). */
export function fmt6(buf: Buffer, off: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i += 1) groups.push(buf.readUInt16BE(off + i * 2));
  return compress6(groups);
}

function compress6(groups: number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(':');
  const head = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':');
  const tail = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(':');
  return `${head}::${tail}`;
}

export interface ParsedIp {
  ver: 4 | 6;
  value: bigint;
}

export function parseIp(text: string): ParsedIp | null {
  const t = text.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    const parts = t.split('.').map(Number);
    if (parts.some((p) => p > 255)) return null;
    return {
      ver: 4,
      value: BigInt(((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]),
    };
  }
  if (t.includes(':') && /^[0-9a-fA-F:.]+$/.test(t)) {
    const v = parseIp6(t);
    return v === null ? null : { ver: 6, value: v };
  }
  return null;
}

function parseIp6(text: string): bigint | null {
  let t = text;
  // sufixo IPv4 embutido (::ffff:1.2.3.4)
  const m = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(t);
  if (m) {
    const v4 = parseIp(m[2]);
    if (!v4) return null;
    const hi = Number((v4.value >> 16n) & 0xffffn).toString(16);
    const lo = Number(v4.value & 0xffffn).toString(16);
    t = `${m[1]}${hi}:${lo}`;
  }
  const halves = t.split('::');
  if (halves.length > 2) return null;
  const parse = (s: string): number[] | null => {
    if (!s) return [];
    const out: number[] = [];
    for (const p of s.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return null;
      out.push(parseInt(p, 16));
    }
    return out;
  };
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  if (!head || !tail) return null;
  let groups: number[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array<number>(fill).fill(0), ...tail];
  } else {
    groups = head;
    if (groups.length !== 8) return null;
  }
  let v = 0n;
  for (const g of groups) v = (v << 16n) | BigInt(g);
  return v;
}

export interface IpMatcher {
  ver: 4 | 6;
  network: bigint;
  mask: bigint;
}

/** "10.0.0.1", "10.0.0.0/8", "2001:db8::/32". */
export function parseIpMatcher(text: string): IpMatcher | null {
  const [addr, bitsText] = text.split('/');
  const ip = parseIp(addr);
  if (!ip) return null;
  const total = ip.ver === 4 ? 32 : 128;
  let bits = total;
  if (bitsText !== undefined) {
    if (!/^\d{1,3}$/.test(bitsText)) return null;
    bits = Number(bitsText);
    if (bits > total) return null;
  }
  const full = (1n << BigInt(total)) - 1n;
  const mask = bits === 0 ? 0n : (full << BigInt(total - bits)) & full;
  return { ver: ip.ver, network: ip.value & mask, mask };
}

export function ipMatches(addr: string, matcher: IpMatcher): boolean {
  const ip = parseIp(addr);
  if (!ip || ip.ver !== matcher.ver) return false;
  return (ip.value & matcher.mask) === matcher.network;
}

export function isPrivateOrLocal(addr: string): boolean {
  return (
    /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|22[4-9]\.|23\d\.|255\.)/.test(addr) ||
    /^(fe80|fc|fd|ff|::1$)/i.test(addr)
  );
}
