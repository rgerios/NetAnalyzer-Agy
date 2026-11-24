/** Leitura somente leitura de log groups do CloudWatch Logs (alternativa ao S3). */
import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
  DescribeLogStreamsCommand,
  FilterLogEventsCommand,
} from '@aws-sdk/client-cloudwatch-logs';
import { fromTemporaryCredentials } from '@aws-sdk/credential-providers';
import type { AwsSourceConfig, AwsTestResult } from '../shared/aws.ts';
import type { AwsClientConfig } from './awsS3.ts';
import { describeAwsError } from './awsS3.ts';
import { parseAwsObject } from './awsParsers.ts';

export function buildLogsClient(cfg: AwsClientConfig, region?: string): CloudWatchLogsClient {
  const base = { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey };
  const credentials = cfg.roleArn
    ? fromTemporaryCredentials({
        masterCredentials: base,
        params: {
          RoleArn: cfg.roleArn,
          RoleSessionName: 'fwaudit-ingest',
          ...(cfg.externalId ? { ExternalId: cfg.externalId } : {}),
          DurationSeconds: 3600,
        },
        clientConfig: { region: cfg.region },
      })
    : base;
  return new CloudWatchLogsClient({ region: region || cfg.region, credentials, maxAttempts: 4 });
}

export interface CwEvent {
  id: string;
  ts: number;
  message: string;
  stream: string;
}

/** Folga para eventos que o CloudWatch entrega com atraso (a duplicação é descartada pelo id). */
export const CW_OVERLAP_MS = 45_000;
const PAGE_LIMIT = 10_000;
const MAX_PAGES = 60;

/**
 * Eventos novos do log group desde o último ponto lido, do mais antigo para o mais novo.
 * `streamPrefix` separa tipos de log que compartilham o mesmo grupo (ex.: "ALB_Access_Logs/").
 */
export async function readNewEvents(
  client: CloudWatchLogsClient,
  src: AwsSourceConfig,
  nowMs: number,
  opts: { maxEvents: number; deadlineMs: number }
): Promise<{ events: CwEvent[]; truncated: boolean; pages: number }> {
  const cursor = src.cursor;
  const known = new Set(cursor?.recentKeys ?? []);
  const startTime = cursor
    ? Math.max(0, cursor.lastModifiedMs - CW_OVERLAP_MS)
    : nowMs - Math.max(1, src.lookbackHours) * 3_600_000;
  const events: CwEvent[] = [];
  let token: string | undefined;
  let pages = 0;
  let truncated = false;

  for (; pages < MAX_PAGES; ) {
    if (Date.now() > opts.deadlineMs) {
      truncated = true;
      break;
    }
    const res = await client.send(
      new FilterLogEventsCommand({
        logGroupName: src.logGroup,
        logStreamNamePrefix: src.streamPrefix || undefined,
        startTime,
        endTime: nowMs + 60_000,
        limit: PAGE_LIMIT,
        nextToken: token,
      })
    );
    pages += 1;
    for (const e of res.events ?? []) {
      if (!e.eventId || !e.message || e.timestamp === undefined) continue;
      if (known.has(e.eventId)) continue;
      events.push({ id: e.eventId, ts: e.timestamp, message: e.message, stream: e.logStreamName ?? '' });
    }
    token = res.nextToken;
    if (!token) break;
    if (events.length >= opts.maxEvents) {
      truncated = true;
      break;
    }
  }
  if (pages >= MAX_PAGES && token) truncated = true;
  events.sort((a, b) => a.ts - b.ts);
  return { events, truncated, pages };
}

/** Mensagens do CloudWatch em um bloco de texto que os analisadores da AWS entendem. */
export function eventsToText(events: CwEvent[]): string {
  return events.map((e) => e.message.replace(/\r?\n+$/, '')).join('\n');
}

/** Valida credenciais, log group e prefixo, e tenta reconhecer o formato de uma amostra. */
export async function testCloudWatchSource(client: CloudWatchLogsClient, src: AwsSourceConfig): Promise<AwsTestResult> {
  const nowMs = Date.now();
  try {
    const res = await client.send(
      new FilterLogEventsCommand({
        logGroupName: src.logGroup,
        logStreamNamePrefix: src.streamPrefix || undefined,
        startTime: nowMs - Math.max(24, src.lookbackHours) * 3_600_000,
        endTime: nowMs + 60_000,
        limit: 200,
      })
    );
    const found = res.events ?? [];
    const streams = [...new Set(found.map((e) => e.logStreamName ?? '').filter(Boolean))];
    if (found.length === 0) {
      // sem eventos: mostra os streams que existem, para corrigir o prefixo
      let names: string[] = [];
      try {
        const d = await client.send(new DescribeLogStreamsCommand({ logGroupName: src.logGroup, orderBy: 'LastEventTime', descending: true, limit: 5 }));
        names = (d.logStreams ?? []).map((s) => s.logStreamName ?? '').filter(Boolean);
      } catch {
        // a permissão de listar streams é opcional
      }
      return {
        ok: false,
        message: `Conectou ao log group, mas não há eventos nas últimas ${Math.max(24, src.lookbackHours)} h${src.streamPrefix ? ` com o prefixo "${src.streamPrefix}"` : ''}. Confira o prefixo do stream.`,
        sampleKeys: names,
        sampleEvents: 0,
      };
    }
    const parsed = parseAwsObject(src.type, found.map((e) => (e.message ?? '').trim()).join('\n'), { nowMs });
    return {
      ok: parsed.events.length > 0,
      message:
        parsed.events.length > 0
          ? `Tudo certo: ${found.length}${found.length === 200 ? '+' : ''} evento(s) recente(s); ${parsed.events.length.toLocaleString('pt-BR')} reconhecido(s) como ${src.type === 'vpcflow' ? 'VPC Flow Logs' : src.type === 'waf' ? 'AWS WAF' : 'ALB'}.`
          : `Há eventos, mas nenhum foi reconhecido como ${src.type === 'vpcflow' ? 'VPC Flow Logs' : src.type === 'waf' ? 'AWS WAF' : 'ALB (access log)'}. Confira o tipo da fonte e o prefixo do stream (para o ALB, use o stream "ALB_Access_Logs/").`,
      sampleKeys: streams.slice(0, 5),
      sampleEvents: parsed.events.length,
      sampleKey: (found[0].message ?? '').slice(0, 160),
    };
  } catch (err) {
    return { ok: false, message: describeAwsError(err), sampleKeys: [], sampleEvents: 0 };
  }
}

export interface CwGroupInfo {
  name: string;
  storedBytes: number;
  retentionDays: number | null;
}

/** Lista os log groups da região (até 200), opcionalmente filtrando por trecho do nome. */
export async function listLogGroups(client: CloudWatchLogsClient, search = ''): Promise<CwGroupInfo[]> {
  const out: CwGroupInfo[] = [];
  const term = search.trim().toLowerCase();
  let token: string | undefined;
  for (let page = 0; page < 8 && out.length < 200; page += 1) {
    const res = await client.send(new DescribeLogGroupsCommand({ nextToken: token, limit: 50 }));
    for (const g of res.logGroups ?? []) {
      const name = g.logGroupName ?? '';
      if (!name || (term && !name.toLowerCase().includes(term))) continue;
      out.push({ name, storedBytes: g.storedBytes ?? 0, retentionDays: g.retentionInDays ?? null });
    }
    token = res.nextToken;
    if (!token) break;
  }
  return out.sort((a, b) => a.name.localeCompare(b.name)).slice(0, 200);
}

export interface CwPrefixInfo {
  /** Prefixo sugerido (até a última "/"; sem barra, o próprio nome do stream). */
  prefix: string;
  streams: number;
  lastEventAt: string | null;
  example: string;
}

/** Streams mais recentes do grupo, agrupados por prefixo (ex.: ALB_Access_Logs/, WAF/, eni-…). */
export async function listStreamPrefixes(client: CloudWatchLogsClient, logGroup: string): Promise<CwPrefixInfo[]> {
  const map = new Map<string, CwPrefixInfo>();
  let token: string | undefined;
  for (let page = 0; page < 4; page += 1) {
    const res = await client.send(
      new DescribeLogStreamsCommand({ logGroupName: logGroup, orderBy: 'LastEventTime', descending: true, nextToken: token, limit: 50 })
    );
    for (const st of res.logStreams ?? []) {
      const name = st.logStreamName ?? '';
      if (!name) continue;
      const i = name.lastIndexOf('/');
      const prefix = i >= 0 ? name.slice(0, i + 1) : name;
      const at = st.lastEventTimestamp ? new Date(st.lastEventTimestamp).toISOString() : null;
      const cur = map.get(prefix) ?? { prefix, streams: 0, lastEventAt: null, example: name };
      cur.streams += 1;
      if (at && (!cur.lastEventAt || at > cur.lastEventAt)) cur.lastEventAt = at;
      map.set(prefix, cur);
    }
    token = res.nextToken;
    if (!token) break;
  }
  return [...map.values()].sort((a, b) => (b.lastEventAt ?? '').localeCompare(a.lastEventAt ?? ''));
}
