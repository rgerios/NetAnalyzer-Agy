/** Tipos compartilhados da aba "Análise PCAP" (servidor e interface). */

export interface PcapFileInfo {
  name: string;
  bytes: number;
  packets: number;
  linkType: number;
  format: 'pcap' | 'pcapng';
  /** Pacotes ignorados por exceder o teto de memória da sessão. */
  skipped: number;
  /** Arquivo cortado no meio (captura interrompida). */
  truncated: boolean;
}

export interface PcapSessionInfo {
  id: string;
  files: PcapFileInfo[];
  totalPackets: number;
  firstTs: number;
  lastTs: number;
  maxPackets: number;
}

export type PcapSeverity = 'error' | 'warn' | 'note';

export interface PcapPacketRow {
  no: number;
  /** Segundos desde o primeiro pacote da sessão. */
  t: number;
  src: string;
  dst: string;
  proto: string;
  len: number;
  info: string;
  sev?: PcapSeverity;
  stream?: number;
  file: number;
}

export interface PcapPacketsPage {
  total: number;
  matched: number;
  offset: number;
  rows: PcapPacketRow[];
}

export interface PcapLayerField {
  k: string;
  v: string;
}

export interface PcapLayer {
  title: string;
  fields: PcapLayerField[];
}

export interface PcapPacketDetail {
  no: number;
  len: number;
  capLen: number;
  stream?: number;
  expert: string[];
  layers: PcapLayer[];
  /** Quadro inteiro em hexadecimal (até 16 KB). */
  hex: string;
}

export type PcapFindingSeverity = 'critical' | 'warning' | 'info';

export interface PcapFinding {
  id: string;
  severity: PcapFindingSeverity;
  title: string;
  detail: string;
  hint?: string;
  count: number;
  /** Filtro estilo Wireshark que isola os pacotes do achado. */
  filter?: string;
}

export interface PcapConversation {
  kind: 'tcp' | 'udp' | 'icmp' | 'other';
  a: string;
  b: string;
  aPort?: number;
  bPort?: number;
  packets: number;
  bytes: number;
  start: number;
  duration: number;
  stream?: number;
  state?: string;
  filter: string;
}

export interface PcapEndpoint {
  ip: string;
  packets: number;
  bytes: number;
  txPackets: number;
  rxPackets: number;
  txBytes: number;
  rxBytes: number;
}

export interface PcapSummary {
  matched: number;
  bytes: number;
  firstTs: number;
  lastTs: number;
  duration: number;
  avgPps: number;
  avgBps: number;
  protocols: Array<{ proto: string; packets: number; bytes: number }>;
  conversations: PcapConversation[];
  endpoints: PcapEndpoint[];
  timeline: Array<{ t: number; packets: number; bytes: number; problems: number }>;
  findings: PcapFinding[];
}

export interface PcapStreamSegment {
  /** 0 = quem iniciou a conexão (cliente), 1 = resposta. */
  dir: 0 | 1;
  text: string;
  bytes: number;
}

export interface PcapStreamView {
  stream: number;
  a: string;
  b: string;
  segments: PcapStreamSegment[];
  clientBytes: number;
  serverBytes: number;
  truncated: boolean;
}

export interface PcapUploadResult {
  session: PcapSessionInfo;
  added: PcapFileInfo;
}
