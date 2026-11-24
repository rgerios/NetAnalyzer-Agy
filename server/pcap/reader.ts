/**
 * Leitor de arquivos de captura: libpcap clássico (tcpdump) e pcapng (Wireshark),
 * nos dois sentidos de bytes, com resolução de tempo em micro ou nanossegundos.
 */

export interface RawPacket {
  /** Segundos desde a época (com fração). */
  ts: number;
  wireLen: number;
  data: Buffer;
  linkType: number;
}

export interface ReadResult {
  format: 'pcap' | 'pcapng';
  packets: RawPacket[];
  linkType: number;
  truncated: boolean;
  /** Pacotes que passaram do teto informado e não foram carregados. */
  skipped: number;
}

export class PcapFormatError extends Error {}

const YIELD_EVERY = 20_000;
const yieldLoop = () => new Promise<void>((resolve) => setImmediate(resolve));

function tsFrom(sec: number, frac: number, unitsPerSec: number): number {
  return sec + frac / unitsPerSec;
}

export async function readCapture(buf: Buffer, maxPackets: number): Promise<ReadResult> {
  if (buf.length < 12) throw new PcapFormatError('Arquivo vazio ou pequeno demais para ser uma captura.');
  const magicLE = buf.readUInt32LE(0);
  if (magicLE === 0x0a0d0d0a) return readPcapng(buf, maxPackets);
  if (magicLE === 0xa1b2c3d4 || magicLE === 0xd4c3b2a1 || magicLE === 0xa1b23c4d || magicLE === 0x4d3cb2a1) {
    return readClassic(buf, magicLE, maxPackets);
  }
  if (buf[0] === 0x1f && buf[1] === 0x8b) {
    throw new PcapFormatError('O arquivo está compactado (gzip). Descompacte e envie o .pcap/.pcapng.');
  }
  throw new PcapFormatError('Formato não reconhecido: envie um arquivo .pcap ou .pcapng (Wireshark/tcpdump).');
}

async function readClassic(buf: Buffer, magicLE: number, maxPackets: number): Promise<ReadResult> {
  const le = magicLE === 0xa1b2c3d4 || magicLE === 0xa1b23c4d;
  const nano = magicLE === 0xa1b23c4d || magicLE === 0x4d3cb2a1;
  if (buf.length < 24) throw new PcapFormatError('Cabeçalho pcap incompleto.');
  const u32 = (o: number) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const linkType = u32(20) & 0x0fffffff;
  const units = nano ? 1e9 : 1e6;
  const packets: RawPacket[] = [];
  let off = 24;
  let truncated = false;
  let skipped = 0;
  let n = 0;
  while (off + 16 <= buf.length) {
    const sec = u32(off);
    const frac = u32(off + 4);
    const incl = u32(off + 8);
    const orig = u32(off + 12);
    off += 16;
    if (incl > 262_144 * 4 || off + incl > buf.length) {
      truncated = true;
      break;
    }
    if (packets.length < maxPackets) {
      packets.push({ ts: tsFrom(sec, frac, units), wireLen: orig, data: buf.subarray(off, off + incl), linkType });
    } else {
      skipped += 1;
    }
    off += incl;
    n += 1;
    if (n % YIELD_EVERY === 0) await yieldLoop();
  }
  if (off < buf.length && !truncated && buf.length - off > 0 && buf.length - off < 16) truncated = true;
  return { format: 'pcap', packets, linkType, truncated, skipped };
}

interface IfaceInfo {
  linkType: number;
  unitsPerSec: number;
}

async function readPcapng(buf: Buffer, maxPackets: number): Promise<ReadResult> {
  let le = true;
  let off = 0;
  const ifaces: IfaceInfo[] = [];
  const packets: RawPacket[] = [];
  let truncated = false;
  let skipped = 0;
  let firstLink = -1;
  let n = 0;

  while (off + 12 <= buf.length) {
    // O tipo do bloco SHB é simétrico; o sentido de bytes vem do "byte-order magic".
    const typeLE = buf.readUInt32LE(off);
    if (typeLE === 0x0a0d0d0a) {
      if (off + 12 > buf.length) break;
      const bom = buf.readUInt32LE(off + 8);
      if (bom === 0x1a2b3c4d) le = true;
      else if (bom === 0x4d3c2b1a) le = false;
      else throw new PcapFormatError('pcapng inválido (byte-order magic desconhecido).');
      ifaces.length = 0; // nova seção: interfaces recomeçam
    }
    const u32 = (o: number) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
    const u16 = (o: number) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
    const type = u32(off);
    const total = u32(off + 4);
    if (total < 12 || total % 4 !== 0 || off + total > buf.length) {
      truncated = true;
      break;
    }
    const body = off + 8;
    const bodyEnd = off + total - 4;

    if (type === 0x00000001) {
      // Interface Description Block
      const linkType = u16(body);
      let unitsPerSec = 1e6;
      let o = body + 8;
      while (o + 4 <= bodyEnd) {
        const code = u16(o);
        const len = u16(o + 2);
        if (code === 0) break;
        if (code === 9 && len >= 1) {
          const v = buf[o + 4];
          unitsPerSec = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** v;
        }
        o += 4 + Math.ceil(len / 4) * 4;
      }
      ifaces.push({ linkType, unitsPerSec });
      if (firstLink < 0) firstLink = linkType;
    } else if (type === 0x00000006) {
      // Enhanced Packet Block
      const ifId = u32(body);
      const hi = u32(body + 4);
      const lo = u32(body + 8);
      const cap = u32(body + 12);
      const orig = u32(body + 16);
      const dataOff = body + 20;
      const iface = ifaces[ifId];
      if (iface && dataOff + cap <= bodyEnd) {
        if (packets.length < maxPackets) {
          const ticks = (BigInt(hi) << 32n) | BigInt(lo);
          const units = BigInt(Math.round(iface.unitsPerSec));
          const sec = Number(ticks / units);
          const frac = Number(ticks % units) / iface.unitsPerSec;
          packets.push({ ts: sec + frac, wireLen: orig, data: buf.subarray(dataOff, dataOff + cap), linkType: iface.linkType });
        } else {
          skipped += 1;
        }
      }
    } else if (type === 0x00000003) {
      // Simple Packet Block (sem hora)
      const orig = u32(body);
      const cap = Math.min(orig, bodyEnd - (body + 4));
      const iface = ifaces[0];
      if (iface) {
        if (packets.length < maxPackets) {
          packets.push({ ts: 0, wireLen: orig, data: buf.subarray(body + 4, body + 4 + cap), linkType: iface.linkType });
        } else {
          skipped += 1;
        }
      }
    }
    off += total;
    n += 1;
    if (n % YIELD_EVERY === 0) await yieldLoop();
  }
  if (off < buf.length && !truncated) truncated = true;
  return { format: 'pcapng', packets, linkType: firstLink < 0 ? 1 : firstLink, truncated, skipped };
}
