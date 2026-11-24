/**
 * Análise da sessão: fluxos TCP/UDP, sinais de problema (retransmissão, RST, janela zero…),
 * conversas, endpoints, linha do tempo e "achados" com dica de causa provável e filtro pronto.
 */
import type {
  PcapConversation,
  PcapEndpoint,
  PcapFinding,
  PcapSeverity,
  PcapStreamView,
  PcapSummary,
} from '../../shared/pcap.ts';
import { DNS_RCODES, payloadOf, type DecodedPacket } from './decode.ts';
import { isPrivateOrLocal } from './ipaddr.ts';

export interface TcpStream {
  id: number;
  a: string;
  aPort: number;
  b: string;
  bPort: number;
  /** Chave "ip:porta" do primeiro emissor visto (direção 0). */
  aKey: string;
  clientDir: 0 | 1 | null;
  packets: number;
  bytes: number;
  startTs: number;
  lastTs: number;
  syn: boolean;
  synCount: number;
  synack: boolean;
  fin: boolean;
  rst: number;
  rstDir: 0 | 1 | null;
  retrans: number;
  hello: boolean;
  serverHello: boolean;
  tlsAlerts: number;
  sni?: string;
  dirs: [DirState, DirState];
}

interface DirState {
  nextSeq?: number;
  seen: Set<number>;
  lastAck?: number;
  lastWin?: number;
  lastTs: number;
}

export interface SessionIndex {
  tcp: Map<number, TcpStream>;
  udpStreams: number;
  dnsUnanswered: number[];
  arpUnanswered: number[];
}

const seqLt = (a: number, b: number): boolean => ((a - b) | 0) < 0;
const seqGt = (a: number, b: number): boolean => ((a - b) | 0) > 0;

export function analyzeSession(packets: DecodedPacket[]): SessionIndex {
  const tcpByKey = new Map<string, TcpStream>();
  const udpByKey = new Map<string, number>();
  const index: SessionIndex = { tcp: new Map(), udpStreams: 0, dnsUnanswered: [], arpUnanswered: [] };
  const pendingDns = new Map<string, number>();
  const pendingArp = new Map<string, number>();

  for (const p of packets) {
    p.stream = undefined;
    p.udpStream = undefined;
    p.expert = [];

    if (p.tcp && p.ipSrc && p.ipDst) {
      const t = p.tcp;
      const s = `${p.ipSrc}:${t.sport}`;
      const d = `${p.ipDst}:${t.dport}`;
      const key = s < d ? `${s}|${d}` : `${d}|${s}`;
      let st = tcpByKey.get(key);
      if (!st) {
        st = {
          id: tcpByKey.size,
          a: p.ipSrc, aPort: t.sport, b: p.ipDst, bPort: t.dport, aKey: s,
          clientDir: null, packets: 0, bytes: 0, startTs: p.rel, lastTs: p.rel,
          syn: false, synCount: 0, synack: false, fin: false, rst: 0, rstDir: null, retrans: 0,
          hello: false, serverHello: false, tlsAlerts: 0,
          dirs: [
            { seen: new Set(), lastTs: 0 },
            { seen: new Set(), lastTs: 0 },
          ],
        };
        tcpByKey.set(key, st);
        index.tcp.set(st.id, st);
      }
      p.stream = st.id;
      const dir: 0 | 1 = s === st.aKey ? 0 : 1;
      const ds = st.dirs[dir];
      const opp = st.dirs[dir === 0 ? 1 : 0];
      st.packets += 1;
      st.bytes += p.wireLen;
      st.lastTs = p.rel;

      const isSyn = (t.flags & 0x02) !== 0;
      const isAck = (t.flags & 0x10) !== 0;
      const isRst = (t.flags & 0x04) !== 0;
      const isFin = (t.flags & 0x01) !== 0;

      if (isSyn && !isAck) {
        if (st.syn && st.clientDir === dir) {
          p.expert.push('retransmission');
          st.retrans += 1;
        }
        st.syn = true;
        st.synCount += 1;
        st.clientDir = dir;
      } else if (isSyn && isAck) {
        st.synack = true;
      }
      if (isFin) st.fin = true;
      if (isRst) {
        st.rst += 1;
        if (st.rstDir === null) st.rstDir = dir;
        p.expert.push('rst');
      }
      if (t.win === 0 && !isSyn && !isRst) p.expert.push('zero_window');

      const segLen = t.payLen + (isSyn ? 1 : 0) + (isFin ? 1 : 0);
      if (segLen > 0 && !(isSyn && !isAck && p.expert.includes('retransmission'))) {
        const key2 = t.seq * 65536 + Math.min(segLen, 65535);
        const endSeq = (t.seq + segLen) >>> 0;
        if (ds.seen.has(key2)) {
          p.expert.push('retransmission');
          st.retrans += 1;
        } else if (ds.nextSeq !== undefined && seqLt(t.seq, ds.nextSeq)) {
          if (p.rel - ds.lastTs < 0.003) p.expert.push('out_of_order');
          else {
            p.expert.push('retransmission');
            st.retrans += 1;
          }
        }
        ds.seen.add(key2);
        if (ds.nextSeq === undefined || seqGt(endSeq, ds.nextSeq)) ds.nextSeq = endSeq;
        ds.lastTs = p.rel;
      } else if (t.payLen === 0 && isAck && !isSyn && !isFin && !isRst) {
        if (
          ds.lastAck === t.ack && ds.lastWin === t.win &&
          opp.nextSeq !== undefined && seqLt(t.ack, opp.nextSeq)
        ) {
          p.expert.push('dup_ack');
        }
      }
      if (isAck && t.payLen === 0) {
        ds.lastAck = t.ack;
        ds.lastWin = t.win;
      }

      if (p.tls) {
        if (p.tls.handshakeType === 1) {
          st.hello = true;
          if (p.tls.sni) st.sni = p.tls.sni;
        } else if (p.tls.handshakeType === 2) st.serverHello = true;
        if (p.tls.contentType === 21) st.tlsAlerts += 1;
      }
    } else if (p.udp && p.ipSrc && p.ipDst) {
      const s = `${p.ipSrc}:${p.udp.sport}`;
      const d = `${p.ipDst}:${p.udp.dport}`;
      const key = s < d ? `${s}|${d}` : `${d}|${s}`;
      let id = udpByKey.get(key);
      if (id === undefined) {
        id = udpByKey.size;
        udpByKey.set(key, id);
      }
      p.udpStream = id;
    }

    // DNS: consulta sem resposta
    if (p.dns && p.udp && p.ipSrc && p.ipDst) {
      if (!p.dns.response) {
        pendingDns.set(`${p.ipSrc}:${p.udp.sport}|${p.dns.id}|${p.dns.qname}`, p.no);
      } else {
        pendingDns.delete(`${p.ipDst}:${p.udp.dport}|${p.dns.id}|${p.dns.qname}`);
      }
    }
    // ARP: requisição sem resposta
    if (p.arp) {
      if (p.arp.op === 1) {
        const k = `${p.arp.senderIp}>${p.arp.targetIp}`;
        if (!pendingArp.has(k)) pendingArp.set(k, p.no);
      } else if (p.arp.op === 2) {
        pendingArp.delete(`${p.arp.targetIp}>${p.arp.senderIp}`);
      }
    }
  }
  index.udpStreams = udpByKey.size;
  index.dnsUnanswered = [...pendingDns.values()].sort((x, y) => x - y);
  index.arpUnanswered = [...pendingArp.values()].sort((x, y) => x - y);
  return index;
}

export function severityOf(p: DecodedPacket): PcapSeverity | undefined {
  if (p.expert.includes('rst') || p.expert.includes('zero_window')) return 'error';
  if (p.expert.length) return 'warn';
  if (p.dns && p.dns.response && p.dns.rcode !== 0) return 'warn';
  if (p.icmp && !p.icmp.v6 && (p.icmp.type === 3 || p.icmp.type === 11)) return 'warn';
  if (p.icmp && p.icmp.v6 && (p.icmp.type === 1 || p.icmp.type === 3)) return 'warn';
  if (p.tls?.contentType === 21) return 'warn';
  return undefined;
}

const STATE_LABEL = (st: TcpStream): string => {
  if (st.syn && !st.synack) return st.rst > 0 ? 'Recusada (RST em resposta ao SYN)' : 'SYN sem resposta';
  if (st.synack && st.rst > 0) return 'Resetada (RST)';
  if (st.synack && st.fin) return 'Encerrada (FIN)';
  if (st.synack) return 'Estabelecida';
  return st.rst > 0 ? 'Captura parcial (termina em RST)' : 'Captura parcial (sem handshake)';
};

const MAX_LIST = 40;
const list = (ids: number[]) => ids.slice(0, MAX_LIST).join(' ');

export function summarize(subset: DecodedPacket[], index: SessionIndex): PcapSummary {
  const protocols = new Map<string, { packets: number; bytes: number }>();
  const convs = new Map<string, PcapConversation & { _s: number }>();
  const ends = new Map<string, PcapEndpoint>();
  let bytes = 0;
  const first = subset.length ? subset[0].ts : 0;
  const last = subset.length ? subset[subset.length - 1].ts : 0;
  const duration = Math.max(0, last - first);

  const tcpIds = new Set<number>();
  const counts = {
    retrans: 0, ooo: 0, dup: 0, zero: 0, rst: 0, frag: 0, tlsAlert: 0,
    dnsErr: new Map<number, number>(), icmpUnreach: new Map<number, number>(), icmpTtl: 0, tcpPkts: 0,
  };

  const bucketCount = 60;
  const bucketSize = duration > 0 ? duration / bucketCount : 1;
  const buckets = Array.from({ length: bucketCount }, (_v, i) => ({ t: i * bucketSize, packets: 0, bytes: 0, problems: 0 }));

  for (const p of subset) {
    bytes += p.wireLen;
    const pr = protocols.get(p.proto) ?? { packets: 0, bytes: 0 };
    pr.packets += 1;
    pr.bytes += p.wireLen;
    protocols.set(p.proto, pr);

    const bi = Math.min(bucketCount - 1, bucketSize > 0 ? Math.floor((p.ts - first) / bucketSize) : 0);
    buckets[bi].packets += 1;
    buckets[bi].bytes += p.wireLen;
    const sev = severityOf(p);
    if (sev === 'error' || sev === 'warn') buckets[bi].problems += 1;

    if (p.ipSrc && p.ipDst) {
      const tx = ends.get(p.ipSrc) ?? newEndpoint(p.ipSrc);
      tx.packets += 1; tx.bytes += p.wireLen; tx.txPackets += 1; tx.txBytes += p.wireLen;
      ends.set(p.ipSrc, tx);
      const rx = ends.get(p.ipDst) ?? newEndpoint(p.ipDst);
      rx.packets += 1; rx.bytes += p.wireLen; rx.rxPackets += 1; rx.rxBytes += p.wireLen;
      ends.set(p.ipDst, rx);
    }

    // conversas
    let ck: string | null = null;
    let kind: PcapConversation['kind'] = 'other';
    let a = p.ipSrc ?? p.ethSrc ?? '?';
    let b = p.ipDst ?? p.ethDst ?? '?';
    let aPort: number | undefined;
    let bPort: number | undefined;
    if (p.tcp && p.stream !== undefined) {
      const st = index.tcp.get(p.stream);
      ck = `t${p.stream}`;
      kind = 'tcp';
      if (st) { a = st.a; b = st.b; aPort = st.aPort; bPort = st.bPort; }
      tcpIds.add(p.stream);
      counts.tcpPkts += 1;
    } else if (p.udp && p.udpStream !== undefined) {
      ck = `u${p.udpStream}`;
      kind = 'udp';
      a = p.ipSrc ?? a; b = p.ipDst ?? b; aPort = p.udp.sport; bPort = p.udp.dport;
    } else if (p.icmp && p.ipSrc && p.ipDst) {
      const [x, y] = p.ipSrc < p.ipDst ? [p.ipSrc, p.ipDst] : [p.ipDst, p.ipSrc];
      ck = `i${x}|${y}`;
      kind = 'icmp';
      a = x; b = y;
    } else if (p.ipSrc && p.ipDst) {
      const [x, y] = p.ipSrc < p.ipDst ? [p.ipSrc, p.ipDst] : [p.ipDst, p.ipSrc];
      ck = `o${x}|${y}|${p.proto}`;
      a = x; b = y;
    }
    if (ck) {
      let c = convs.get(ck);
      if (!c) {
        c = {
          kind, a, b, aPort, bPort, packets: 0, bytes: 0, start: p.rel, duration: 0,
          stream: p.stream, state: undefined, filter: '', _s: p.ts,
        };
        convs.set(ck, c);
      }
      c.packets += 1;
      c.bytes += p.wireLen;
      c.duration = Math.max(c.duration, p.ts - c._s);
    }

    for (const e of p.expert) {
      if (e === 'retransmission') counts.retrans += 1;
      else if (e === 'out_of_order') counts.ooo += 1;
      else if (e === 'dup_ack') counts.dup += 1;
      else if (e === 'zero_window') counts.zero += 1;
      else if (e === 'rst') counts.rst += 1;
    }
    if (p.dns?.response && p.dns.rcode !== 0) {
      counts.dnsErr.set(p.dns.rcode, (counts.dnsErr.get(p.dns.rcode) ?? 0) + 1);
    }
    if (p.icmp && !p.icmp.v6 && p.icmp.type === 3) {
      counts.icmpUnreach.set(p.icmp.code, (counts.icmpUnreach.get(p.icmp.code) ?? 0) + 1);
    } else if (p.icmp && !p.icmp.v6 && p.icmp.type === 11) counts.icmpTtl += 1;
    if (p.tls?.contentType === 21) counts.tlsAlert += 1;
    if (p.ipMf || (p.ipFragOffset ?? 0) > 0) counts.frag += 1;
  }

  // estados e filtros das conversas
  const conversations = [...convs.values()]
    .map((c) => {
      const { _s, ...rest } = c;
      void _s;
      if (rest.kind === 'tcp' && rest.stream !== undefined) {
        const st = index.tcp.get(rest.stream);
        if (st) rest.state = STATE_LABEL(st);
        rest.filter = `tcp.stream == ${rest.stream}`;
      } else if (rest.kind === 'udp') {
        rest.filter = `ip.addr == ${rest.a} && udp.port == ${rest.aPort} && udp.port == ${rest.bPort}`;
      } else {
        rest.filter = `ip.addr == ${rest.a} && ip.addr == ${rest.b}`;
      }
      return rest as PcapConversation;
    })
    .sort((x, y) => y.bytes - x.bytes)
    .slice(0, 200);

  // ----- achados -----
  const findings: PcapFinding[] = [];
  const streamsInSubset = [...tcpIds].map((id) => index.tcp.get(id)).filter((s): s is TcpStream => !!s);

  const noReply = streamsInSubset.filter((s) => s.syn && !s.synack && s.rst === 0);
  if (noReply.length) {
    const dsts = topCounts(noReply.map((s) => `${s.clientDir === 1 ? s.a : s.b}:${s.clientDir === 1 ? s.aPort : s.bPort}`));
    findings.push({
      id: 'syn-no-reply',
      severity: 'critical',
      title: `${noReply.length} tentativa(s) de conexão TCP sem resposta`,
      detail: `O SYN foi enviado e nenhum SYN/ACK nem RST voltou. Destinos mais tentados: ${dsts}.`,
      hint: 'Costuma indicar pacote descartado (DROP) por firewall/ACL, rota ausente ou de retorno assimétrico, ou host desligado. Compare a captura dos dois lados do firewall: se o SYN sai de um lado e não aparece no outro, o bloqueio está entre eles.',
      count: noReply.length,
      filter: `tcp.stream in {${list(noReply.map((s) => s.id))}}`,
    });
  }
  const refused = streamsInSubset.filter((s) => s.syn && !s.synack && s.rst > 0);
  if (refused.length) {
    findings.push({
      id: 'refused',
      severity: 'warning',
      title: `${refused.length} conexão(ões) recusada(s) (RST ao SYN)`,
      detail: `Algo respondeu ao SYN com RST: ${topCounts(refused.map((s) => `${s.clientDir === 1 ? s.a : s.b}:${s.clientDir === 1 ? s.aPort : s.bPort}`))}.`,
      hint: 'Porta fechada no destino, serviço parado, ou firewall configurado para rejeitar (REJECT/reset) em vez de descartar. Verifique de qual endereço veio o RST: se for um IP do próprio firewall, é regra de bloqueio.',
      count: refused.length,
      filter: `tcp.stream in {${list(refused.map((s) => s.id))}}`,
    });
  }
  const midRst = streamsInSubset.filter((s) => s.synack && s.rst > 0);
  if (midRst.length) {
    findings.push({
      id: 'rst-established',
      severity: 'warning',
      title: `${midRst.length} conexão(ões) estabelecida(s) terminaram com RST`,
      detail: `Total de ${counts.rst} pacote(s) RST no recorte.`,
      hint: 'RST no meio da sessão pode ser aplicação encerrando de forma abrupta, timeout de sessão no firewall/NAT, inspeção (IPS/AV) derrubando ou pacote fora de estado.',
      count: midRst.length,
      filter: 'tcp.flags.reset == 1',
    });
  }
  if (counts.retrans > 0) {
    const pct = counts.tcpPkts ? (counts.retrans / counts.tcpPkts) * 100 : 0;
    findings.push({
      id: 'retransmissions',
      severity: pct >= 2 ? 'warning' : 'info',
      title: `${counts.retrans} retransmissão(ões) TCP (${pct.toFixed(1)}% dos pacotes TCP)`,
      detail: 'Segmentos reenviados porque a confirmação não chegou a tempo.',
      hint: 'Acima de ~2% indica perda de pacotes, congestionamento, MTU/MSS inadequado ou descarte intermitente no caminho. Observe se se concentram em um destino ou em um sentido.',
      count: counts.retrans,
      filter: 'tcp.analysis.retransmission',
    });
  }
  if (counts.zero > 0) {
    findings.push({
      id: 'zero-window',
      severity: 'warning',
      title: `${counts.zero} anúncio(s) de janela zero`,
      detail: 'O receptor avisou que não consegue mais receber dados.',
      hint: 'Receptor lento ou sobrecarregado (aplicação não lê o socket). Não é problema de rede/firewall.',
      count: counts.zero,
      filter: 'tcp.analysis.zero_window',
    });
  }
  if (counts.dup > 0) {
    findings.push({
      id: 'dup-ack',
      severity: counts.dup > 50 ? 'warning' : 'info',
      title: `${counts.dup} ACK(s) duplicado(s)`,
      detail: 'Confirmações repetidas, sinal clássico de pacote perdido no caminho.',
      count: counts.dup,
      filter: 'tcp.analysis.duplicate_ack',
    });
  }
  if (counts.ooo > 0) {
    findings.push({
      id: 'out-of-order',
      severity: 'info',
      title: `${counts.ooo} pacote(s) fora de ordem`,
      detail: 'Pacotes chegaram em ordem diferente da enviada.',
      hint: 'Comum com múltiplos caminhos/links ou balanceamento; só preocupa se for frequente.',
      count: counts.ooo,
      filter: 'tcp.analysis.out_of_order',
    });
  }
  const noClientReply = streamsInSubset.filter((s) => s.hello && !s.serverHello && s.rst === 0 && s.tlsAlerts === 0);
  if (noClientReply.length) {
    findings.push({
      id: 'tls-no-hello',
      severity: 'warning',
      title: `${noClientReply.length} handshake(s) TLS sem Server Hello`,
      detail: `Client Hello enviado e sem resposta. Domínios (SNI): ${topCounts(noClientReply.map((s) => s.sni ?? '(sem SNI)'))}.`,
      hint: 'Pode ser bloqueio por categoria/SNI no firewall, inspeção SSL com problema, MTU (Client Hello grande fragmentando) ou servidor inacessível.',
      count: noClientReply.length,
      filter: `tcp.stream in {${list(noClientReply.map((s) => s.id))}}`,
    });
  }
  if (counts.tlsAlert > 0) {
    findings.push({
      id: 'tls-alert',
      severity: 'warning',
      title: `${counts.tlsAlert} alerta(s) TLS`,
      detail: 'Um dos lados enviou um alerta TLS (certificado inválido, versão/cifra incompatível, handshake falhou…).',
      hint: 'Com inspeção SSL ativa no firewall, certificado da CA do firewall não confiável no cliente é a causa mais comum.',
      count: counts.tlsAlert,
      filter: 'tls.record.content_type == 21',
    });
  }
  if (counts.dnsErr.size) {
    const total = [...counts.dnsErr.values()].reduce((x, y) => x + y, 0);
    const parts = [...counts.dnsErr.entries()].map(([rc, n]) => `${DNS_RCODES[rc] ?? `rcode ${rc}`}: ${n}`).join(' · ');
    findings.push({
      id: 'dns-errors',
      severity: 'warning',
      title: `${total} resposta(s) DNS com erro`,
      detail: parts,
      hint: 'NXDOMAIN = nome não existe; SERVFAIL = servidor DNS falhou ao resolver; REFUSED = servidor recusou (ACL ou recursão desligada).',
      count: total,
      filter: 'dns.flags.rcode != 0',
    });
  }
  const dnsNoAnswer = index.dnsUnanswered.filter((no) => subset.some((p) => p.no === no));
  if (dnsNoAnswer.length) {
    findings.push({
      id: 'dns-no-answer',
      severity: 'warning',
      title: `${dnsNoAnswer.length} consulta(s) DNS sem resposta`,
      detail: 'A consulta saiu e nenhuma resposta correspondente apareceu na captura.',
      hint: 'Servidor DNS inalcançável, UDP/53 bloqueado ou resposta descartada no caminho de volta. Se a captura foi feita só de um lado, a resposta pode estar do outro.',
      count: dnsNoAnswer.length,
      filter: `frame.number in {${list(dnsNoAnswer)}}`,
    });
  }
  if (counts.icmpUnreach.size) {
    const total = [...counts.icmpUnreach.values()].reduce((x, y) => x + y, 0);
    const prohibited = [9, 10, 13].reduce((acc, c) => acc + (counts.icmpUnreach.get(c) ?? 0), 0);
    findings.push({
      id: 'icmp-unreachable',
      severity: prohibited ? 'critical' : 'warning',
      title: `${total} ICMP "destino inalcançável"`,
      detail: [...counts.icmpUnreach.entries()].map(([c, n]) => `código ${c}: ${n}`).join(' · '),
      hint: prohibited
        ? 'Códigos 9/10/13 significam "administrativamente proibido": um firewall/ACL está bloqueando de forma explícita.'
        : 'Código 3 = porta fechada; 0/1 = sem rota para a rede/host; 4 = precisa fragmentar com DF ligado (problema de MTU).',
      count: total,
      filter: 'icmp.type == 3',
    });
  }
  if (counts.icmpTtl > 0) {
    findings.push({
      id: 'icmp-ttl',
      severity: 'info',
      title: `${counts.icmpTtl} ICMP "TTL excedido"`,
      detail: 'Pacotes morreram no caminho por TTL baixo (traceroute) ou loop de roteamento.',
      count: counts.icmpTtl,
      filter: 'icmp.type == 11',
    });
  }
  const arpNo = index.arpUnanswered.filter((no) => subset.some((p) => p.no === no));
  if (arpNo.length) {
    findings.push({
      id: 'arp-no-reply',
      severity: 'warning',
      title: `${arpNo.length} requisição(ões) ARP sem resposta`,
      detail: 'Ninguém respondeu "quem tem o IP…?".',
      hint: 'Host desligado, IP errado, VLAN/porta incorreta, ou o gateway não está no mesmo domínio de broadcast.',
      count: arpNo.length,
      filter: `frame.number in {${list(arpNo)}}`,
    });
  }
  if (counts.frag > 0) {
    findings.push({
      id: 'fragments',
      severity: 'info',
      title: `${counts.frag} pacote(s) IP fragmentado(s)`,
      detail: 'Fragmentação costuma indicar MTU/MSS inadequado no caminho (VPN, túneis, PPPoE).',
      hint: 'Ajuste o MSS (clamp) no firewall/túnel ou verifique o MTU.',
      count: counts.frag,
      filter: 'ip.flags.mf == 1 || ip.frag_offset > 0',
    });
  }

  // concentração de tráfego
  const topEnd = [...ends.values()].sort((x, y) => y.bytes - x.bytes)[0];
  if (topEnd && bytes > 0 && topEnd.bytes / bytes > 0.5 && subset.length > 100) {
    findings.push({
      id: 'top-talker',
      severity: 'info',
      title: `${topEnd.ip} concentra ${((topEnd.bytes / bytes) * 100).toFixed(0)}% do tráfego`,
      detail: `${topEnd.packets} pacotes, ${topEnd.bytes} bytes${isPrivateOrLocal(topEnd.ip) ? ' (endereço interno)' : ''}.`,
      count: topEnd.packets,
      filter: `ip.addr == ${topEnd.ip}`,
    });
  }

  const order = { critical: 0, warning: 1, info: 2 } as const;
  findings.sort((x, y) => order[x.severity] - order[y.severity] || y.count - x.count);

  return {
    matched: subset.length,
    bytes,
    firstTs: first,
    lastTs: last,
    duration,
    avgPps: duration > 0 ? subset.length / duration : subset.length,
    avgBps: duration > 0 ? (bytes * 8) / duration : bytes * 8,
    protocols: [...protocols.entries()].map(([proto, v]) => ({ proto, ...v })).sort((x, y) => y.packets - x.packets),
    conversations,
    endpoints: [...ends.values()].sort((x, y) => y.bytes - x.bytes).slice(0, 100),
    timeline: buckets,
    findings,
  };
}

function newEndpoint(ip: string): PcapEndpoint {
  return { ip, packets: 0, bytes: 0, txPackets: 0, rxPackets: 0, txBytes: 0, rxBytes: 0 };
}

function topCounts(items: string[], max = 3): string {
  const m = new Map<string, number>();
  for (const i of items) m.set(i, (m.get(i) ?? 0) + 1);
  return [...m.entries()]
    .sort((x, y) => y[1] - x[1])
    .slice(0, max)
    .map(([k, n]) => (n > 1 ? `${k} (${n}×)` : k))
    .join(', ');
}

const STREAM_CAP = 256 * 1024;

function toText(buf: Buffer): string {
  let out = '';
  for (let i = 0; i < buf.length; i += 1) {
    const c = buf[i];
    out += c === 10 || c === 13 || c === 9 || (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
  }
  return out;
}

/** Conteúdo TCP de um fluxo, na ordem de captura (sem reordenar nem remontar retransmissões). */
export function followTcpStream(packets: DecodedPacket[], index: SessionIndex, id: number): PcapStreamView | null {
  const st = index.tcp.get(id);
  if (!st) return null;
  const segments: PcapStreamView['segments'] = [];
  let clientBytes = 0;
  let serverBytes = 0;
  let total = 0;
  let truncated = false;
  const clientKey = st.clientDir === 1 ? `${st.b}:${st.bPort}` : st.aKey;
  for (const p of packets) {
    if (p.stream !== id || !p.tcp || p.payLen <= 0) continue;
    if (p.expert.includes('retransmission')) continue;
    const pay = payloadOf(p);
    if (!pay.length) continue;
    const dir: 0 | 1 = `${p.ipSrc}:${p.tcp.sport}` === clientKey ? 0 : 1;
    if (dir === 0) clientBytes += pay.length; else serverBytes += pay.length;
    if (total >= STREAM_CAP) { truncated = true; continue; }
    const room = STREAM_CAP - total;
    const slice = pay.length > room ? pay.subarray(0, room) : pay;
    if (pay.length > room) truncated = true;
    total += slice.length;
    const last = segments[segments.length - 1];
    const text = toText(slice);
    if (last && last.dir === dir) {
      last.text += text;
      last.bytes += slice.length;
    } else {
      segments.push({ dir, text, bytes: slice.length });
    }
  }
  const [ca, cb] = st.clientDir === 1 ? [`${st.b}:${st.bPort}`, `${st.a}:${st.aPort}`] : [`${st.a}:${st.aPort}`, `${st.b}:${st.bPort}`];
  return { stream: id, a: ca, b: cb, segments, clientBytes, serverBytes, truncated };
}
