/** Árvore de camadas e hexdump de um pacote para a tela de detalhe. */
import type { PcapLayer, PcapPacketDetail } from '../../shared/pcap.ts';
import { DNS_RCODES, DNS_TYPES, tcpFlagNames, tlsVersionName, type DecodedPacket } from './decode.ts';

const MAX_HEX = 16 * 1024;

export function buildDetail(p: DecodedPacket): PcapPacketDetail {
  const layers: PcapLayer[] = [];

  layers.push({
    title: `Frame ${p.no}: ${p.wireLen} bytes no fio, ${p.capLen} capturados`,
    fields: [
      { k: 'Arquivo', v: String(p.file + 1) },
      { k: 'Hora', v: new Date(p.ts * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC') },
      { k: 'Segundos desde o primeiro pacote', v: p.rel.toFixed(6) },
      { k: 'Tamanho no fio', v: `${p.wireLen} bytes` },
      { k: 'Tamanho capturado', v: `${p.capLen} bytes${p.capLen < p.wireLen ? ' (cortado pelo snaplen)' : ''}` },
      { k: 'Protocolo', v: p.proto },
    ],
  });

  if (p.ethSrc) {
    layers.push({
      title: `Ethernet II, Src: ${p.ethSrc}, Dst: ${p.ethDst}`,
      fields: [
        { k: 'Destino', v: p.ethDst ?? '' },
        { k: 'Origem', v: p.ethSrc },
        { k: 'Tipo', v: `0x${(p.ethType ?? 0).toString(16).padStart(4, '0')}` },
        ...(p.vlan !== undefined ? [{ k: 'VLAN ID', v: String(p.vlan) }] : []),
      ],
    });
  }

  if (p.ipVer === 4) {
    layers.push({
      title: `Internet Protocol v4, Src: ${p.ipSrc}, Dst: ${p.ipDst}`,
      fields: [
        { k: 'Origem', v: p.ipSrc ?? '' },
        { k: 'Destino', v: p.ipDst ?? '' },
        { k: 'Protocolo', v: String(p.ipProto) },
        { k: 'TTL', v: String(p.ttl) },
        { k: 'Identificação', v: `0x${(p.ipId ?? 0).toString(16)}` },
        { k: 'Flags', v: [p.ipDf ? 'Don\'t Fragment' : '', p.ipMf ? 'More Fragments' : ''].filter(Boolean).join(', ') || '—' },
        { k: 'Offset do fragmento', v: String(p.ipFragOffset ?? 0) },
        { k: 'Tamanho total', v: String(p.ipTotalLen) },
      ],
    });
  } else if (p.ipVer === 6) {
    layers.push({
      title: `Internet Protocol v6, Src: ${p.ipSrc}, Dst: ${p.ipDst}`,
      fields: [
        { k: 'Origem', v: p.ipSrc ?? '' },
        { k: 'Destino', v: p.ipDst ?? '' },
        { k: 'Próximo cabeçalho', v: String(p.ipProto) },
        { k: 'Hop limit', v: String(p.ttl) },
      ],
    });
  }

  if (p.arp) {
    layers.push({
      title: `Address Resolution Protocol (${p.arp.op === 1 ? 'request' : p.arp.op === 2 ? 'reply' : `opcode ${p.arp.op}`})`,
      fields: [
        { k: 'Remetente MAC', v: p.arp.senderMac },
        { k: 'Remetente IP', v: p.arp.senderIp },
        { k: 'Alvo MAC', v: p.arp.targetMac },
        { k: 'Alvo IP', v: p.arp.targetIp },
      ],
    });
  }

  if (p.tcp) {
    const t = p.tcp;
    layers.push({
      title: `Transmission Control Protocol, Src Port: ${t.sport}, Dst Port: ${t.dport}, Seq: ${t.seq}, Ack: ${t.ack}, Len: ${t.payLen}`,
      fields: [
        { k: 'Porta de origem', v: String(t.sport) },
        { k: 'Porta de destino', v: String(t.dport) },
        ...(p.stream !== undefined ? [{ k: 'Índice do stream', v: String(p.stream) }] : []),
        { k: 'Número de sequência', v: String(t.seq) },
        { k: 'Número de confirmação', v: String(t.ack) },
        { k: 'Flags', v: `0x${t.flags.toString(16).padStart(3, '0')} (${tcpFlagNames(t.flags).join(', ') || 'nenhuma'})` },
        { k: 'Janela', v: String(t.win) },
        { k: 'Tamanho do cabeçalho', v: `${t.hdrLen} bytes` },
        { k: 'Tamanho do payload', v: `${t.payLen} bytes` },
        ...(t.mss !== undefined ? [{ k: 'MSS', v: String(t.mss) }] : []),
        ...(t.wscale !== undefined ? [{ k: 'Window scale', v: `${t.wscale} (×${2 ** t.wscale})` }] : []),
        ...(t.sackPermitted ? [{ k: 'SACK', v: 'permitido' }] : []),
        ...(p.expert.length ? [{ k: 'Análise', v: p.expert.join(', ') }] : []),
      ],
    });
  } else if (p.udp) {
    layers.push({
      title: `User Datagram Protocol, Src Port: ${p.udp.sport}, Dst Port: ${p.udp.dport}`,
      fields: [
        { k: 'Porta de origem', v: String(p.udp.sport) },
        { k: 'Porta de destino', v: String(p.udp.dport) },
        { k: 'Tamanho', v: String(p.udp.len) },
        ...(p.udpStream !== undefined ? [{ k: 'Índice do stream', v: String(p.udpStream) }] : []),
      ],
    });
  } else if (p.icmp) {
    layers.push({
      title: `${p.icmp.v6 ? 'ICMPv6' : 'Internet Control Message Protocol'}`,
      fields: [
        { k: 'Tipo', v: String(p.icmp.type) },
        { k: 'Código', v: String(p.icmp.code) },
        ...(p.icmp.id !== undefined ? [{ k: 'Identificador', v: `0x${p.icmp.id.toString(16)}` }] : []),
        ...(p.icmp.seq !== undefined ? [{ k: 'Sequência', v: String(p.icmp.seq) }] : []),
        { k: 'Resumo', v: p.info },
      ],
    });
  }

  if (p.dns) {
    const d = p.dns;
    layers.push({
      title: `Domain Name System (${d.response ? 'resposta' : 'consulta'})`,
      fields: [
        { k: 'ID da transação', v: `0x${d.id.toString(16)}` },
        { k: 'Tipo', v: d.response ? 'Resposta' : 'Consulta' },
        { k: 'Código de resposta', v: `${d.rcode} (${DNS_RCODES[d.rcode] ?? 'desconhecido'})` },
        ...(d.qname ? [{ k: 'Pergunta', v: `${d.qname} (${DNS_TYPES[d.qtype ?? 0] ?? `tipo ${d.qtype}`})` }] : []),
        ...d.answers.map((a, i) => ({ k: `Resposta ${i + 1}`, v: a })),
      ],
    });
  }
  if (p.http) {
    layers.push({
      title: `Hypertext Transfer Protocol: ${p.http.firstLine.slice(0, 80)}`,
      fields: [
        { k: p.http.isRequest ? 'Requisição' : 'Resposta', v: p.http.firstLine },
        ...p.http.headers.map((h) => {
          const i = h.indexOf(':');
          return i > 0 ? { k: h.slice(0, i), v: h.slice(i + 1).trim() } : { k: 'Cabeçalho', v: h };
        }),
      ],
    });
  }
  if (p.tls) {
    layers.push({
      title: `Transport Layer Security (${p.info})`,
      fields: [
        { k: 'Tipo de registro', v: String(p.tls.contentType) },
        { k: 'Versão do registro', v: tlsVersionName(p.tls.version) },
        ...(p.tls.handshakeType !== undefined ? [{ k: 'Tipo de handshake', v: String(p.tls.handshakeType) }] : []),
        ...(p.tls.sni ? [{ k: 'Server Name (SNI)', v: p.tls.sni }] : []),
      ],
    });
  }
  if (p.ssh) layers.push({ title: 'SSH', fields: [{ k: 'Banner', v: p.ssh }] });

  const hex = p.data.subarray(0, MAX_HEX).toString('hex');
  return { no: p.no, len: p.wireLen, capLen: p.capLen, stream: p.stream, expert: p.expert, layers, hex };
}
