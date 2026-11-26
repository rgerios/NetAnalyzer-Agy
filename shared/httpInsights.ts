/** Análise de aplicação a partir dos access logs do ALB (tipos compartilhados). */

export interface HttpEndpointRow {
  host: string;
  method: string;
  /** Caminho com ids trocados por marcadores ({id}, {uuid}…). */
  path: string;
  requests: number;
  errors4xx: number;
  errors5xx: number;
  avgMs: number;
  maxMs: number;
  slow: number;
  /** Percentil 95 do tempo total (estimado pelo histograma). */
  p95Ms: number;
  bytesIn: number;
  bytesOut: number;
}

export interface HttpSlowRequest {
  at: string;
  method: string;
  host: string;
  path: string;
  client: string;
  status: string;
  totalMs: number;
  requestMs: number;
  targetMs: number;
  targetIp: string;
  traceId: string;
}

export interface HttpTargetRow {
  ip: string;
  group: string;
  requests: number;
  errors5xx: number;
  avgMs: number;
}

export interface HttpInsights {
  generatedAt: string;
  minutes: number;
  requests: number;
  dataSource: 'memory' | 'database';
  truncated: boolean;
  status: { s2xx: number; s3xx: number; s4xx: number; s5xx: number; other: number; top: Array<{ code: string; count: number }> };
  latency: {
    avgMs: number;
    maxMs: number;
    slow: number;
    slowThresholdMs: number;
    p50Ms: number;
    p95Ms: number;
    p99Ms: number;
    /** Só o tempo da aplicação (target). */
    targetAvgMs: number;
    targetP95Ms: number;
  };
  /** Média por requisição de cada etapa: cliente → ALB, aplicação (target) e resposta. */
  timeBreakdown: { requestMs: number; targetMs: number; responseMs: number };
  /** Requisições cujo envio do corpo pelo cliente levou 1 s ou mais (uploads em rede lenta). */
  clientSlow: number;
  /** Quantas requisições por faixa de tempo total. */
  distribution: Array<{ label: string; requests: number }>;
  /** As requisições individuais mais lentas, com o Trace ID para investigar. */
  slowRequests: HttpSlowRequest[];
  /** Volume, erros 5xx e latência por intervalo. */
  timeline: Array<{ t: string; requests: number; errors5xx: number; avgTargetMs: number; p95Ms: number; maxMs: number }>;
  tlsReuse: { reused: number; total: number };
  waf: { evaluated: number; forwarded: number; blocked: number };
  bytes: { in: number; out: number };
  endpoints: HttpEndpointRow[];
  slowest: HttpEndpointRow[];
  heaviest: HttpEndpointRow[];
  errors: HttpEndpointRow[];
  userAgents: Array<{ name: string; requests: number; errors: number }>;
  tls: Array<{ version: string; requests: number }>;
  ciphers: Array<{ name: string; requests: number }>;
  targets: HttpTargetRow[];
  hosts: Array<{ host: string; requests: number }>;
}
