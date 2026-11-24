/**
 * Sessões de análise de PCAP em memória: um conjunto de arquivos mesclado por horário.
 * Têm tempo de vida limitado e teto de pacotes para não esgotar a memória do servidor.
 */
import crypto from 'node:crypto';
import type {
  PcapFileInfo,
  PcapPacketRow,
  PcapPacketsPage,
  PcapSessionInfo,
  PcapSummary,
} from '../../shared/pcap.ts';
import { analyzeSession, severityOf, summarize, type SessionIndex } from './analysis.ts';
import { decodePacket, type DecodedPacket } from './decode.ts';
import { compileFilter } from './filter.ts';
import { PcapFormatError, readCapture } from './reader.ts';

export interface PcapLimits {
  maxPackets: number;
  maxSessions: number;
  idleMs: number;
}

const YIELD_EVERY = 20_000;
const yieldLoop = () => new Promise<void>((resolve) => setImmediate(resolve));

interface FilePart {
  info: PcapFileInfo;
  packets: DecodedPacket[];
}

export class PcapSession {
  readonly id = crypto.randomBytes(9).toString('base64url');
  parts: FilePart[] = [];
  packets: DecodedPacket[] = [];
  index: SessionIndex = { tcp: new Map(), udpStreams: 0, dnsUnanswered: [], arpUnanswered: [] };
  touched = Date.now();
  private cache = new Map<string, Int32Array>();

  private limits: PcapLimits;

  constructor(limits: PcapLimits) {
    this.limits = limits;
  }

  info(): PcapSessionInfo {
    return {
      id: this.id,
      files: this.parts.map((p) => p.info),
      totalPackets: this.packets.length,
      firstTs: this.packets.length ? this.packets[0].ts : 0,
      lastTs: this.packets.length ? this.packets[this.packets.length - 1].ts : 0,
      maxPackets: this.limits.maxPackets,
    };
  }

  private loaded(): number {
    return this.parts.reduce((n, p) => n + p.packets.length, 0);
  }

  async addFile(name: string, buf: Buffer): Promise<PcapFileInfo> {
    const room = Math.max(0, this.limits.maxPackets - this.loaded());
    const read = await readCapture(buf, room);
    const fileIdx = this.parts.length;
    const decoded: DecodedPacket[] = [];
    let n = 0;
    for (const raw of read.packets) {
      decoded.push(decodePacket(raw, fileIdx));
      n += 1;
      if (n % YIELD_EVERY === 0) await yieldLoop();
    }
    const info: PcapFileInfo = {
      name,
      bytes: buf.length,
      packets: decoded.length,
      linkType: read.linkType,
      format: read.format,
      skipped: read.skipped,
      truncated: read.truncated,
    };
    this.parts.push({ info, packets: decoded });
    await this.rebuild();
    return info;
  }

  async removeFile(idx: number): Promise<boolean> {
    if (idx < 0 || idx >= this.parts.length) return false;
    this.parts.splice(idx, 1);
    this.parts.forEach((part, i) => part.packets.forEach((p) => { p.file = i; }));
    await this.rebuild();
    return true;
  }

  private async rebuild(): Promise<void> {
    const all: DecodedPacket[] = [];
    for (const part of this.parts) for (const p of part.packets) all.push(p);
    all.sort((a, b) => a.ts - b.ts); // estável: preserva a ordem dentro do arquivo
    const t0 = all.length ? all[0].ts : 0;
    for (let i = 0; i < all.length; i += 1) {
      all[i].no = i + 1;
      all[i].rel = all[i].ts - t0;
    }
    await yieldLoop();
    this.packets = all;
    this.index = analyzeSession(all);
    this.cache.clear();
    this.touched = Date.now();
  }

  /** Índices (posições em `packets`) que casam com o filtro. Lança FilterError se inválido. */
  match(filter: string): Int32Array {
    const key = filter.trim();
    const cached = this.cache.get(key);
    if (cached) return cached;
    const test = compileFilter(key);
    const out: number[] = [];
    if (!test) {
      for (let i = 0; i < this.packets.length; i += 1) out.push(i);
    } else {
      for (let i = 0; i < this.packets.length; i += 1) if (test(this.packets[i])) out.push(i);
    }
    const arr = Int32Array.from(out);
    if (this.cache.size >= 6) this.cache.delete(this.cache.keys().next().value as string);
    this.cache.set(key, arr);
    return arr;
  }

  page(filter: string, offset: number, limit: number): PcapPacketsPage {
    const idx = this.match(filter);
    const rows: PcapPacketRow[] = [];
    for (let i = offset; i < Math.min(idx.length, offset + limit); i += 1) {
      rows.push(toRow(this.packets[idx[i]]));
    }
    return { total: this.packets.length, matched: idx.length, offset, rows };
  }

  summary(filter: string): PcapSummary {
    const idx = this.match(filter);
    const subset: DecodedPacket[] = new Array(idx.length);
    for (let i = 0; i < idx.length; i += 1) subset[i] = this.packets[idx[i]];
    return summarize(subset, this.index);
  }

  packetByNo(no: number): DecodedPacket | undefined {
    const p = this.packets[no - 1];
    return p && p.no === no ? p : undefined;
  }

  /** pcap clássico (little-endian, µs) com os pacotes do filtro; exige o mesmo tipo de enlace. */
  exportPcap(filter: string): Buffer {
    const idx = this.match(filter);
    const link = this.parts.length ? this.parts[0].info.linkType : 1;
    if (this.parts.some((p) => p.info.linkType !== link)) {
      throw new PcapFormatError('Os arquivos têm tipos de enlace diferentes; não dá para gerar um único .pcap.');
    }
    const chunks: Buffer[] = [];
    const head = Buffer.alloc(24);
    head.writeUInt32LE(0xa1b2c3d4, 0);
    head.writeUInt16LE(2, 4);
    head.writeUInt16LE(4, 6);
    head.writeUInt32LE(262144, 16);
    head.writeUInt32LE(link, 20);
    chunks.push(head);
    for (let i = 0; i < idx.length; i += 1) {
      const p = this.packets[idx[i]];
      const rec = Buffer.alloc(16);
      const sec = Math.floor(p.ts);
      rec.writeUInt32LE(sec >>> 0, 0);
      rec.writeUInt32LE(Math.round((p.ts - sec) * 1e6) % 1_000_000, 4);
      rec.writeUInt32LE(p.data.length, 8);
      rec.writeUInt32LE(p.wireLen, 12);
      chunks.push(rec, p.data);
    }
    return Buffer.concat(chunks);
  }
}

export function toRow(p: DecodedPacket): PcapPacketRow {
  return {
    no: p.no,
    t: p.rel,
    src: p.ipSrc ?? p.arp?.senderIp ?? p.ethSrc ?? '',
    dst: p.ipDst ?? p.arp?.targetIp ?? p.ethDst ?? '',
    proto: p.proto,
    len: p.wireLen,
    info: p.info,
    sev: severityOf(p),
    stream: p.stream,
    file: p.file,
  };
}

export class PcapSessionStore {
  private sessions = new Map<string, PcapSession>();
  private timer: NodeJS.Timeout;
  private limits: PcapLimits;

  constructor(limits: PcapLimits) {
    this.limits = limits;
    this.timer = setInterval(() => this.sweep(), 60_000);
    this.timer.unref();
  }

  create(): PcapSession {
    while (this.sessions.size >= this.limits.maxSessions) {
      let oldest: PcapSession | null = null;
      for (const s of this.sessions.values()) if (!oldest || s.touched < oldest.touched) oldest = s;
      if (!oldest) break;
      this.sessions.delete(oldest.id);
    }
    const s = new PcapSession(this.limits);
    this.sessions.set(s.id, s);
    return s;
  }

  get(id: string): PcapSession | undefined {
    const s = this.sessions.get(id);
    if (s) s.touched = Date.now();
    return s;
  }

  delete(id: string): boolean {
    return this.sessions.delete(id);
  }

  private sweep(): void {
    const now = Date.now();
    for (const s of this.sessions.values()) {
      if (now - s.touched > this.limits.idleMs) this.sessions.delete(s.id);
    }
  }

  stop(): void {
    clearInterval(this.timer);
  }
}
