import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { analyzeSession, summarize } from '../server/pcap/analysis.ts';
import { decodePacket } from '../server/pcap/decode.ts';
import { buildDetail } from '../server/pcap/detail.ts';
import { compileFilter, FilterError } from '../server/pcap/filter.ts';
import { parseIpMatcher, ipMatches, fmt6 } from '../server/pcap/ipaddr.ts';
import { readCapture } from '../server/pcap/reader.ts';
import { PcapSession } from '../server/pcap/session.ts';

// ---------- construtores de pacotes sintéticos ----------

const mac = (n: number) => Buffer.from([0, 0x11, 0x22, 0x33, 0x44, n]);
const ip4 = (s: string) => Buffer.from(s.split('.').map(Number));

function eth(type: number, payload: Buffer): Buffer {
  const h = Buffer.alloc(14);
  mac(1).copy(h, 0);
  mac(2).copy(h, 6);
  h.writeUInt16BE(type, 12);
  return Buffer.concat([h, payload]);
}

function ipv4(src: string, dst: string, proto: number, payload: Buffer, opts: { ttl?: number } = {}): Buffer {
  const h = Buffer.alloc(20);
  h[0] = 0x45;
  h.writeUInt16BE(20 + payload.length, 2);
  h.writeUInt16BE(0x1234, 4);
  h.writeUInt16BE(0x4000, 6);
  h[8] = opts.ttl ?? 64;
  h[9] = proto;
  ip4(src).copy(h, 12);
  ip4(dst).copy(h, 16);
  return Buffer.concat([h, payload]);
}

function tcp(sport: number, dport: number, seq: number, ack: number, flags: number, payload: Buffer = Buffer.alloc(0), win = 64240): Buffer {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt32BE(seq >>> 0, 4);
  h.writeUInt32BE(ack >>> 0, 8);
  h[12] = 5 << 4;
  h[13] = flags & 0xff;
  h.writeUInt16BE(win, 14);
  return Buffer.concat([h, payload]);
}

function udp(sport: number, dport: number, payload: Buffer): Buffer {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([h, payload]);
}

function dnsQuery(id: number, name: string): Buffer {
  const parts = name.split('.').flatMap((l) => [Buffer.from([l.length]), Buffer.from(l)]);
  const q = Buffer.concat([...parts, Buffer.from([0, 0, 1, 0, 1])]);
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(0x0100, 2);
  h.writeUInt16BE(1, 4);
  return Buffer.concat([h, q]);
}

function dnsResponse(id: number, name: string, rcode: number, answer?: string): Buffer {
  const q = dnsQuery(id, name);
  q.writeUInt16BE(0x8180 | rcode, 2);
  if (!answer) return q;
  q.writeUInt16BE(1, 6);
  const rr = Buffer.alloc(16);
  rr.writeUInt16BE(0xc00c, 0);
  rr.writeUInt16BE(1, 2);
  rr.writeUInt16BE(1, 4);
  rr.writeUInt32BE(60, 6);
  rr.writeUInt16BE(4, 10);
  ip4(answer).copy(rr, 12);
  return Buffer.concat([q, rr]);
}

function clientHello(sni: string): Buffer {
  const name = Buffer.from(sni);
  const sniExt = Buffer.concat([Buffer.from([0, 0]), u16(name.length + 5), u16(name.length + 3), Buffer.from([0]), u16(name.length), name]);
  const exts = Buffer.concat([u16(sniExt.length), sniExt]);
  const body = Buffer.concat([
    Buffer.from([3, 3]), Buffer.alloc(32), Buffer.from([0]), u16(2), Buffer.from([0x13, 0x01]), Buffer.from([1, 0]), exts,
  ]);
  const hs = Buffer.concat([Buffer.from([1, 0]), u16(body.length), body]);
  return Buffer.concat([Buffer.from([22, 3, 1]), u16(hs.length), hs]);
}
const u16 = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };

const SYN = 0x02, ACK = 0x10, RST = 0x04, PSH = 0x08, FIN = 0x01;

interface Cap { ts: number; frame: Buffer }
const frame = (ts: number, l4: Buffer, src: string, dst: string, proto: number): Cap => ({
  ts, frame: eth(0x0800, ipv4(src, dst, proto, l4)),
});

function pcapFile(caps: Cap[], opts: { nano?: boolean; be?: boolean } = {}): Buffer {
  const be = !!opts.be;
  const w32 = (b: Buffer, v: number, o: number) => (be ? b.writeUInt32BE(v >>> 0, o) : b.writeUInt32LE(v >>> 0, o));
  const head = Buffer.alloc(24);
  w32(head, opts.nano ? 0xa1b23c4d : 0xa1b2c3d4, 0);
  (be ? head.writeUInt16BE(2, 4) : head.writeUInt16LE(2, 4));
  (be ? head.writeUInt16BE(4, 6) : head.writeUInt16LE(4, 6));
  w32(head, 65535, 16);
  w32(head, 1, 20);
  const parts: Buffer[] = [head];
  for (const c of caps) {
    const r = Buffer.alloc(16);
    const sec = Math.floor(c.ts);
    w32(r, sec, 0);
    w32(r, Math.round((c.ts - sec) * (opts.nano ? 1e9 : 1e6)), 4);
    w32(r, c.frame.length, 8);
    w32(r, c.frame.length, 12);
    parts.push(r, c.frame);
  }
  return Buffer.concat(parts);
}

function pcapngFile(caps: Cap[]): Buffer {
  const block = (type: number, body: Buffer) => {
    const pad = (4 - (body.length % 4)) % 4;
    const total = 12 + body.length + pad;
    const b = Buffer.alloc(total);
    b.writeUInt32LE(type, 0);
    b.writeUInt32LE(total, 4);
    body.copy(b, 8);
    b.writeUInt32LE(total, total - 4);
    return b;
  };
  const shb = Buffer.alloc(16);
  shb.writeUInt32LE(0x1a2b3c4d, 0);
  shb.writeUInt16LE(1, 4);
  shb.writeBigInt64LE(-1n, 8);
  const idb = Buffer.alloc(8);
  idb.writeUInt16LE(1, 0);
  idb.writeUInt32LE(65535, 4);
  const out = [block(0x0a0d0d0a, shb), block(1, idb)];
  for (const c of caps) {
    const body = Buffer.alloc(20 + c.frame.length);
    const ticks = BigInt(Math.round(c.ts * 1e6));
    body.writeUInt32LE(0, 0);
    body.writeUInt32LE(Number(ticks >> 32n), 4);
    body.writeUInt32LE(Number(ticks & 0xffffffffn), 8);
    body.writeUInt32LE(c.frame.length, 12);
    body.writeUInt32LE(c.frame.length, 16);
    c.frame.copy(body, 20);
    out.push(block(6, body));
  }
  return Buffer.concat(out);
}

async function load(caps: Cap[]): Promise<PcapSession> {
  const s = new PcapSession({ maxPackets: 100000, maxSessions: 3, idleMs: 1000 });
  await s.addFile('t.pcap', pcapFile(caps));
  return s;
}

const count = (s: PcapSession, f: string) => s.match(f).length;

// ---------- cenário: handshake, dados, retransmissão, RST, SYN sem resposta ----------

function scenario(): Cap[] {
  const C = '10.0.0.5', S = '203.0.113.10';
  const d = Buffer.from('GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n');
  return [
    frame(1.0, tcp(50000, 443, 100, 0, SYN), C, S, 6),
    frame(1.01, tcp(443, 50000, 900, 101, SYN | ACK), S, C, 6),
    frame(1.02, tcp(50000, 443, 101, 901, ACK), C, S, 6),
    frame(1.03, tcp(50000, 80, 101, 901, PSH | ACK, d), C, S, 6),
    frame(1.5, tcp(50000, 80, 101, 901, PSH | ACK, d), C, S, 6), // retransmissão
    frame(1.6, tcp(80, 50000, 901, 101 + d.length, RST | ACK), S, C, 6),
    frame(2.0, tcp(50001, 8443, 1, 0, SYN), C, '198.51.100.7', 6), // SYN sem resposta
    frame(5.0, tcp(50001, 8443, 1, 0, SYN), C, '198.51.100.7', 6), // retransmissão do SYN
    frame(2.1, tcp(50002, 22, 1, 0, SYN), C, '198.51.100.8', 6), // recusada
    frame(2.11, tcp(22, 50002, 0, 2, RST | ACK), '198.51.100.8', C, 6),
    frame(3.0, udp(40000, 53, dnsQuery(0xabcd, 'example.org')), C, '8.8.8.8', 17),
    frame(3.05, udp(53, 40000, dnsResponse(0xabcd, 'example.org', 0, '93.184.216.34')), '8.8.8.8', C, 17),
    frame(3.1, udp(40001, 53, dnsQuery(0x1111, 'nao-existe.test')), C, '8.8.8.8', 17),
    frame(3.15, udp(53, 40001, dnsResponse(0x1111, 'nao-existe.test', 3)), '8.8.8.8', C, 17),
    frame(3.2, udp(40002, 53, dnsQuery(0x2222, 'sem-resposta.test')), C, '8.8.8.8', 17),
    frame(4.0, tcp(50003, 443, 1, 0, PSH | ACK, clientHello('www.google.com')), C, '142.250.1.1', 6),
  ];
}

describe('leitor de capturas', () => {
  it('lê pcap little-endian com microssegundos', async () => {
    const r = await readCapture(pcapFile(scenario()), 1000);
    assert.equal(r.format, 'pcap');
    assert.equal(r.packets.length, 16);
    assert.ok(Math.abs(r.packets[1].ts - 1.01) < 1e-6);
  });
  it('lê pcap big-endian com nanossegundos', async () => {
    const r = await readCapture(pcapFile(scenario(), { be: true, nano: true }), 1000);
    assert.equal(r.packets.length, 16);
    assert.ok(Math.abs(r.packets[3].ts - 1.03) < 1e-6);
  });
  it('lê pcapng', async () => {
    const r = await readCapture(pcapngFile(scenario()), 1000);
    assert.equal(r.format, 'pcapng');
    assert.equal(r.packets.length, 16);
    assert.ok(Math.abs(r.packets[2].ts - 1.02) < 1e-5);
  });
  it('respeita o teto de pacotes e rejeita formatos inválidos', async () => {
    const r = await readCapture(pcapFile(scenario()), 5);
    assert.equal(r.packets.length, 5);
    assert.equal(r.skipped, 11);
    await assert.rejects(() => readCapture(Buffer.from('isto nao e uma captura de rede'), 10), /Formato não reconhecido/);
    await assert.rejects(() => readCapture(Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 10), /gzip/);
  });
  it('sinaliza arquivo cortado', async () => {
    const full = pcapFile(scenario());
    const r = await readCapture(full.subarray(0, full.length - 10), 1000);
    assert.equal(r.truncated, true);
    assert.equal(r.packets.length, 15);
  });
});

describe('decodificação', () => {
  it('decodifica TCP, DNS, TLS (SNI) e HTTP', async () => {
    const s = await load(scenario());
    const byNo = (n: number) => s.packetByNo(n)!;
    assert.equal(byNo(1).tcp?.flags, SYN);
    assert.match(byNo(1).info, /\[SYN\]/);
    const http = s.packets.find((p) => p.http);
    assert.equal(http?.http?.method, 'GET');
    assert.equal(http?.http?.host, 'example.org');
    const dns = s.packets.find((p) => p.dns && !p.dns.response);
    assert.equal(dns?.dns?.qname, 'example.org');
    const resp = s.packets.find((p) => p.dns?.response && p.dns.answerIps.length);
    assert.deepEqual(resp?.dns?.answerIps, ['93.184.216.34']);
    const tls = s.packets.find((p) => p.tls?.sni);
    assert.equal(tls?.tls?.sni, 'www.google.com');
    assert.match(tls!.info, /Client Hello/);
  });

  it('monta o detalhe com camadas e hex', async () => {
    const s = await load(scenario());
    const d = buildDetail(s.packetByNo(1)!);
    assert.ok(d.layers.some((l) => l.title.startsWith('Transmission Control Protocol')));
    assert.ok(d.hex.length > 40);
  });

  it('formata IPv6 de forma comprimida', () => {
    const b = Buffer.alloc(16);
    b[0] = 0x20; b[1] = 0x01; b[2] = 0x0d; b[3] = 0xb8; b[15] = 1;
    assert.equal(fmt6(b, 0), '2001:db8::1');
  });
});

describe('filtros estilo Wireshark', () => {
  it('comparações, CIDR, conjuntos e lógica', async () => {
    const s = await load(scenario());
    assert.equal(count(s, ''), 16);
    assert.equal(count(s, 'dns'), 5);
    assert.equal(count(s, 'ip.addr == 8.8.8.8'), 5);
    assert.equal(count(s, 'ip.addr == 203.0.113.0/24'), 6);
    assert.equal(count(s, 'ip.addr != 8.8.8.8 && udp'), 0);
    assert.equal(count(s, 'tcp.port in {80 443}'), 7);
    assert.equal(count(s, 'tcp.port == 22 or tcp.port == 8443'), 4);
    assert.equal(count(s, 'tcp.flags.syn == 1 && tcp.flags.ack == 0'), 4);
    assert.equal(count(s, 'tcp.flags.reset'), 2);
    assert.equal(count(s, '!(tcp)'), 5);
    assert.equal(count(s, 'not tcp and not dns'), 0);
    assert.equal(count(s, 'frame.number >= 15'), 2);
    assert.equal(count(s, 'frame.len > 110'), 1);
  });

  it('campos de aplicação e contains/matches', async () => {
    const s = await load(scenario());
    assert.equal(count(s, 'dns.qry.name == "example.org"'), 2);
    assert.equal(count(s, 'dns.qry.name contains "EXAMPLE"'), 2);
    assert.equal(count(s, 'dns.flags.rcode != 0'), 1);
    assert.equal(count(s, 'dns.flags.rcode == 3'), 1);
    assert.equal(count(s, 'http.request.method == "GET"'), 2);
    assert.equal(count(s, 'http.host matches "^example\\\\.org$"'), 2);
    assert.equal(count(s, 'tls.handshake.extensions_server_name contains "google"'), 1);
    assert.equal(count(s, 'tcp contains "index.html"'), 2);
    assert.equal(count(s, 'dns.a == 93.184.216.0/24'), 1);
  });

  it('erros de sintaxe viram mensagens claras', () => {
    assert.throws(() => compileFilter('ip.adr == 1.2.3.4'), (e: unknown) => e instanceof FilterError && /Campo desconhecido/.test(e.message));
    assert.throws(() => compileFilter('tcp.port == abc'), /número/);
    assert.throws(() => compileFilter('ip.addr == 999.1.1.1'), /IP inválido/);
    assert.throws(() => compileFilter('(tcp'), /parêntese/);
    assert.throws(() => compileFilter('tcp.port =='), /valor/);
    assert.throws(() => compileFilter('tcp udp'), /Trecho inesperado/);
    assert.throws(() => compileFilter('dns.qry.name contains "x'), /Aspas/);
    assert.equal(compileFilter('   '), null);
  });

  it('CIDR de IPv4 e IPv6', () => {
    const v4 = parseIpMatcher('10.0.0.0/8')!;
    assert.ok(ipMatches('10.200.1.1', v4));
    assert.ok(!ipMatches('11.0.0.1', v4));
    const v6 = parseIpMatcher('2001:db8::/32')!;
    assert.ok(ipMatches('2001:db8:1::5', v6));
    assert.ok(!ipMatches('2001:db9::1', v6));
  });
});

describe('análise de problemas', () => {
  it('marca retransmissão, RST e fluxos', async () => {
    const s = await load(scenario());
    assert.equal(count(s, 'tcp.analysis.retransmission'), 2); // dados + SYN
    assert.equal(s.index.tcp.size, 5);
    const finding = (id: string) => s.summary('').findings.find((f) => f.id === id);
    assert.ok(finding('syn-no-reply'), 'SYN sem resposta');
    assert.match(finding('syn-no-reply')!.detail, /198\.51\.100\.7:8443/);
    assert.ok(finding('refused'), 'conexão recusada');
    assert.ok(finding('retransmissions'));
    assert.ok(finding('dns-errors'));
    assert.ok(finding('dns-no-answer'));
    assert.equal(finding('dns-no-answer')!.count, 1);
    assert.ok(finding('tls-no-hello'));
    assert.match(finding('tls-no-hello')!.detail, /www\.google\.com/);
  });

  it('o filtro sugerido em cada achado realmente isola pacotes', async () => {
    const s = await load(scenario());
    for (const f of s.summary('').findings) {
      if (!f.filter) continue;
      assert.ok(count(s, f.filter) > 0, `filtro do achado ${f.id} não casou: ${f.filter}`);
    }
  });

  it('sumariza conversas, protocolos e estado do TCP', async () => {
    const s = await load(scenario());
    const sum = s.summary('');
    assert.equal(sum.matched, 16);
    assert.ok(sum.protocols.some((p) => p.proto === 'DNS' && p.packets === 5));
    const states = sum.conversations.filter((c) => c.kind === 'tcp').map((c) => c.state);
    assert.ok(states.includes('SYN sem resposta'));
    assert.ok(states.includes('Recusada (RST em resposta ao SYN)'));
    assert.equal(sum.timeline.length, 60);
    // o resumo respeita o filtro
    const dnsOnly = s.summary('dns');
    assert.equal(dnsOnly.matched, 5);
    assert.ok(dnsOnly.findings.some((f) => f.id === 'dns-errors'));
    assert.ok(!dnsOnly.findings.some((f) => f.id === 'syn-no-reply'));
  });

  it('detecta janela zero e ACKs duplicados', async () => {
    const C = '10.0.0.5', S = '203.0.113.10';
    const data = Buffer.alloc(100, 0x41);
    const caps = [
      frame(1.0, tcp(1000, 80, 1, 1, ACK, data), C, S, 6),
      frame(1.001, tcp(1000, 80, 101, 1, ACK, data), C, S, 6),
      frame(1.002, tcp(80, 1000, 1, 1, ACK), S, C, 6),
      frame(1.003, tcp(80, 1000, 1, 1, ACK), S, C, 6),
      frame(1.004, tcp(80, 1000, 1, 1, ACK, Buffer.alloc(0), 0), S, C, 6),
    ];
    const s = await load(caps);
    assert.equal(count(s, 'tcp.analysis.duplicate_ack'), 1);
    assert.equal(count(s, 'tcp.analysis.zero_window'), 1);
  });
});

describe('sessão com vários arquivos', () => {
  it('mescla por horário, renumera e exporta o filtro como pcap', async () => {
    const all = scenario();
    const a = pcapFile(all.filter((_c, i) => i % 2 === 0));
    const b = pcapngFile(all.filter((_c, i) => i % 2 === 1));
    const s = new PcapSession({ maxPackets: 1000, maxSessions: 3, idleMs: 1000 });
    await s.addFile('a.pcap', a);
    await s.addFile('b.pcapng', b);
    assert.equal(s.parts.length, 2);
    assert.equal(s.packets.length, 16);
    for (let i = 1; i < s.packets.length; i += 1) assert.ok(s.packets[i].ts >= s.packets[i - 1].ts);
    assert.equal(s.packets[0].no, 1);
    assert.equal(s.packets[15].no, 16);

    const exported = s.exportPcap('dns');
    const back = await readCapture(exported, 1000);
    assert.equal(back.packets.length, 5);
    assert.equal(decodePacket(back.packets[0], 0).dns?.qname, 'example.org');

    assert.equal(await s.removeFile(1), true);
    assert.equal(s.packets.length, 8);
    assert.equal(s.packets[7].no, 8);
  });

  it('respeita o teto de pacotes da sessão', async () => {
    const s = new PcapSession({ maxPackets: 10, maxSessions: 3, idleMs: 1000 });
    const info = await s.addFile('x.pcap', pcapFile(scenario()));
    assert.equal(info.packets, 10);
    assert.equal(info.skipped, 6);
  });

  it('analyzeSession/summarize funcionam sem pacotes', () => {
    const idx = analyzeSession([]);
    const sum = summarize([], idx);
    assert.equal(sum.matched, 0);
    assert.equal(sum.findings.length, 0);
  });
});
