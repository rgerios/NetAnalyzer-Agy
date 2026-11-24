/** Facetas por tipo de log da AWS (VPC Flow Logs e WAF): tipos compartilhados. */

export type AwsLogKind = 'vpcflow' | 'waf' | 'albconn';

export interface FacetItem {
  key: string;
  count: number;
  blocked: number;
  bytes: number;
  country?: string | null;
}

export interface FacetResult {
  id: string;
  title: string;
  hint?: string;
  metric: 'count' | 'bytes';
  ip?: boolean;
  country?: boolean;
  port?: boolean;
  items: FacetItem[];
}

export interface FacetTotals {
  events: number;
  blocked: number;
  allowed: number;
  bytes: number;
  packets: number;
}

export interface FacetTimelinePoint {
  t: string;
  allowed: number;
  blocked: number;
}

export interface FacetReport {
  kind: AwsLogKind;
  minutes: number;
  generatedAt: string;
  dataSource: 'memory' | 'database';
  totals: FacetTotals;
  timeline: FacetTimelinePoint[];
  facets: FacetResult[];
}

