/**
 * Ingestão contínua dos logs da AWS: a cada ciclo lista os objetos novos de cada fonte (S3),
 * baixa, converte em eventos e entrega ao motor. O ponto de leitura é guardado por fonte, então
 * reiniciar a plataforma não repete nem perde arquivos.
 */
import type { AwsSourceConfig, AwsSourceCursor, AwsSourceStatus } from '../shared/aws.ts';
import type { S3Client } from '@aws-sdk/client-s3';
import { buildLogsClient, CW_OVERLAP_MS, eventsToText, readNewEvents } from './awsCloudWatch.ts';
import type { CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { buildS3Client, describeAwsError, getObjectText, listNewObjects, type AwsClientConfig } from './awsS3.ts';
import { parseAwsObject } from './awsParsers.ts';
import type { FirewallSiteRecord } from './types.ts';
import type { SyslogEvent } from '../shared/types.ts';

export const DEFAULT_AWS_POLL_SECONDS = 60;
const MAX_FILES_PER_RUN = 100;
const MAX_RUN_MS = 50_000;
const APPEND_CHUNK = 20_000;
const CW_MAX_EVENTS_PER_RUN = 100_000;
const CW_MAX_RECENT_IDS = 8_000;

export interface AwsIngestDeps {
  decryptSecret: (encrypted?: string) => string;
  /** Eventos em ordem cronológica (mais antigo primeiro). */
  append: (site: FirewallSiteRecord, events: SyslogEvent[]) => number;
  /** Pede para gravar o estado (cursores e contadores). */
  persist: () => void;
  log: { info: (m: string) => void; error: (m: string, detail?: string) => void };
  /** Linha de log que o analisador não entendeu. */
  recordSkipped?: (line: string) => void;
  /** Fábrica do cliente S3 (testes injetam um falso). */
  makeClient?: (cfg: AwsClientConfig, region?: string) => S3Client;
  /** Fábrica do cliente do CloudWatch Logs (testes injetam um falso). */
  makeLogsClient?: (cfg: AwsClientConfig, region?: string) => CloudWatchLogsClient;
}

export function emptyStatus(): AwsSourceStatus {
  return {
    running: false,
    lastRunAt: null,
    lastOkAt: null,
    lastError: null,
    filesRead: 0,
    eventsRead: 0,
    bytesRead: 0,
    lastObjectAt: null,
    pendingFiles: 0,
  };
}

/** ID da conta AWS (12 dígitos) que aparece nos próprios logs: flow logs, ARNs do ALB e do WAF. */
export function accountIdOf(ev: SyslogEvent): string {
  const m = ev.meta?.accountId;
  if (typeof m === 'string' && /^\d{12}$/.test(m)) return m;
  return ev.categoryName === 'VPC Flow Logs' && /^\d{12}$/.test(ev.serialNumber) ? ev.serialNumber : '';
}

export function clientConfigFor(site: FirewallSiteRecord, decrypt: (e?: string) => string): AwsClientConfig | null {
  const aws = site.connection.aws;
  if (!aws || !aws.accessKeyId) return null;
  const secret = decrypt(aws.secretEncrypted);
  if (!secret) return null;
  return {
    region: aws.region || 'us-east-1',
    accessKeyId: aws.accessKeyId,
    secretAccessKey: secret,
    roleArn: aws.roleArn || undefined,
    externalId: aws.externalId || undefined,
  };
}

export function createAwsIngestor(deps: AwsIngestDeps) {
  /** Guarda o ID da conta da primeira vez que um log o revela (aparece em "Conta Ativa"). */
  function learnAccount(site: FirewallSiteRecord, events: SyslogEvent[]): void {
    if (/^\d{12}$/.test(site.appliance?.serialNumber ?? '') && site.appliance?.dataSource !== 'sample') return;
    for (const ev of events) {
      const id = accountIdOf(ev);
      if (!id) continue;
      const region = site.connection.aws?.region || '-';
      site.appliance = { ...site.appliance, model: 'AWS', serialNumber: id, firmware: region, host: region, lastSyncAt: new Date().toISOString(), dataSource: 'api' };
      return;
    }
  }
  const appendEvents = (site: FirewallSiteRecord, events: SyslogEvent[]): number => {
    learnAccount(site, events);
    return deps.append(site, events);
  };

  const running = new Set<string>();

  async function syncSource(
    site: FirewallSiteRecord,
    src: AwsSourceConfig,
    opts: { nowMs?: number; maxFiles?: number; maxMs?: number } = {}
  ): Promise<{ files: number; events: number; bytes: number; pending: number }> {
    const lock = `${site.id}:${src.id}`;
    if (running.has(lock)) throw new Error('Esta fonte já está sendo sincronizada.');
    const cfg = clientConfigFor(site, deps.decryptSecret);
    const status = (src.status ??= emptyStatus());
    status.lastRunAt = new Date().toISOString();
    if (!cfg) {
      status.lastError = 'Credenciais AWS não configuradas (Access Key e Secret).';
      deps.persist();
      throw new Error(status.lastError);
    }
    const isCw = src.kind === 'cloudwatch';
    if (isCw ? !src.logGroup : !src.bucket) {
      status.lastError = isCw ? 'Informe o log group do CloudWatch.' : 'Informe o bucket do S3.';
      throw new Error(status.lastError);
    }

    running.add(lock);
    status.running = true;
    const startedMs = Date.now();
    const budget = opts.maxMs ?? MAX_RUN_MS;
    let files = 0;
    let events = 0;
    let bytes = 0;
    let pending = 0;
    try {
      if (isCw) {
        const logs = (deps.makeLogsClient ?? buildLogsClient)(cfg, src.region || cfg.region);
        const r = await syncCloudWatch(site, src, logs, opts.nowMs ?? Date.now(), startedMs + budget);
        status.filesRead += r.pages;
        status.eventsRead += r.events;
        status.bytesRead += r.bytes;
        status.pendingFiles = r.truncated ? 1 : 0;
        status.lastError = null;
        status.lastOkAt = new Date().toISOString();
        if (r.events > 0) deps.log.info(`AWS ${src.name}: ${r.events} evento(s) do CloudWatch${r.truncated ? ' (há mais na fila)' : ''}`);
        return { files: r.pages, events: r.events, bytes: r.bytes, pending: r.truncated ? 1 : 0 };
      }
      const client = (deps.makeClient ?? buildS3Client)(cfg, src.region || cfg.region);
      const nowMs = opts.nowMs ?? Date.now();
      const listed = await listNewObjects(client, src, nowMs, opts.maxFiles ?? MAX_FILES_PER_RUN);
      pending = listed.pending;
      let cursor: AwsSourceCursor = src.cursor
        ? { ...src.cursor, recentKeys: [...src.cursor.recentKeys] }
        : { lastModifiedMs: 0, recentKeys: [] };

      for (const obj of listed.objects) {
        if (Date.now() - startedMs > budget) {
          pending += listed.objects.length - files;
          break;
        }
        let parsedEvents: SyslogEvent[] = [];
        try {
          const { text, bytes: dl } = await getObjectText(client, src.bucket, obj.key);
          bytes += dl;
          parsedEvents = parseAwsObject(src.type, text, { nowMs: Date.now(), region: src.region, onSkip: deps.recordSkipped }).events;
        } catch (err) {
          const e = err as { name?: string; $metadata?: unknown };
          // Falha de AWS/rede: interrompe e tenta de novo no próximo ciclo. Arquivo corrompido: pula.
          if (e?.$metadata || e?.name === 'TimeoutError' || /ECONN|ENOTFOUND|ETIMEDOUT/.test(String((err as Error).message))) {
            throw err;
          }
          deps.log.error(`Arquivo ${obj.key} ignorado (conteúdo inválido)`, err instanceof Error ? err.message : String(err));
        }
        if (parsedEvents.length) {
          parsedEvents.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
          for (let i = 0; i < parsedEvents.length; i += APPEND_CHUNK) {
            appendEvents(site, parsedEvents.slice(i, i + APPEND_CHUNK));
          }
          events += parsedEvents.length;
        }
        files += 1;

        // avança o ponto de leitura depois de cada arquivo
        cursor.lastModifiedMs = Math.max(cursor.lastModifiedMs, obj.lastModifiedMs);
        cursor.recentKeys.push(obj.key);
        cursor.recentKeys = cursor.recentKeys.slice(-5000);
        if (!src.dateLayout && (!cursor.lastKey || obj.key > cursor.lastKey)) cursor.lastKey = obj.key;
        status.lastObjectAt = new Date(obj.lastModifiedMs).toISOString();
        src.cursor = cursor;
      }

      status.filesRead += files;
      status.eventsRead += events;
      status.bytesRead += bytes;
      status.pendingFiles = pending;
      status.lastError = null;
      status.lastOkAt = new Date().toISOString();
      if (files > 0) deps.log.info(`AWS ${src.name}: ${files} arquivo(s), ${events} evento(s)${pending ? `, ${pending} pendente(s)` : ''}`);
      return { files, events, bytes, pending };
    } catch (err) {
      status.lastError = describeAwsError(err);
      status.filesRead += files;
      status.eventsRead += events;
      status.bytesRead += bytes;
      deps.log.error(`AWS ${src.name}: falha na sincronização`, status.lastError);
      throw new Error(status.lastError);
    } finally {
      status.running = false;
      running.delete(lock);
      deps.persist();
    }
  }


  /** Lê os eventos novos do log group, converte e entrega ao motor. */
  async function syncCloudWatch(
    site: FirewallSiteRecord,
    src: AwsSourceConfig,
    logs: CloudWatchLogsClient,
    nowMs: number,
    deadlineMs: number
  ): Promise<{ pages: number; events: number; bytes: number; truncated: boolean }> {
    const status = (src.status ??= emptyStatus());
    const read = await readNewEvents(logs, src, nowMs, { maxEvents: CW_MAX_EVENTS_PER_RUN, deadlineMs });
    let events = 0;
    let bytes = 0;
    if (read.events.length > 0) {
      const text = eventsToText(read.events);
      bytes = Buffer.byteLength(text);
      const parsed = parseAwsObject(src.type, text, { nowMs: Date.now(), region: src.region, onSkip: deps.recordSkipped }).events.map((e) => ({
        ...e,
        source: 'cloudwatch' as const,
      }));
      parsed.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
      for (let i = 0; i < parsed.length; i += APPEND_CHUNK) appendEvents(site, parsed.slice(i, i + APPEND_CHUNK));
      events = parsed.length;

      // avança o ponto de leitura: último horário e ids recentes (para não repetir na folga)
      const lastTs = read.events[read.events.length - 1].ts;
      const prev = src.cursor;
      const keepFrom = lastTs - CW_OVERLAP_MS;
      const ids = new Set<string>(prev?.recentKeys ?? []);
      for (const e of read.events) if (e.ts >= keepFrom) ids.add(e.id);
      src.cursor = {
        lastModifiedMs: Math.max(prev?.lastModifiedMs ?? 0, lastTs),
        recentKeys: [...ids].slice(-CW_MAX_RECENT_IDS),
      };
      status.lastObjectAt = new Date(lastTs).toISOString();
    }
    return { pages: read.pages, events, bytes, truncated: read.truncated };
  }

  async function syncSite(site: FirewallSiteRecord, onlyId?: string): Promise<void> {
    const aws = site.connection.aws;
    if (!aws) return;
    for (const src of aws.sources) {
      if (onlyId && src.id !== onlyId) continue;
      if (!onlyId && !src.enabled) continue;
      try {
        await syncSource(site, src);
      } catch {
        // o erro já ficou no status da fonte
      }
    }
  }

  /** Fontes que já passaram do intervalo de leitura. */
  function dueSources(site: FirewallSiteRecord, nowMs: number): AwsSourceConfig[] {
    const aws = site.connection.aws;
    if (!aws) return [];
    const interval = Math.max(15, aws.pollSeconds || DEFAULT_AWS_POLL_SECONDS) * 1000;
    return aws.sources.filter((s) => {
      if (!s.enabled || running.has(`${site.id}:${s.id}`)) return false;
      const last = Date.parse(s.status?.lastRunAt || '');
      return !Number.isFinite(last) || nowMs - last >= interval;
    });
  }

  async function runDue(site: FirewallSiteRecord): Promise<void> {
    for (const src of dueSources(site, Date.now())) {
      try {
        await syncSource(site, src);
      } catch {
        // registrado no status
      }
    }
  }

  return { syncSource, syncSite, runDue, dueSources, isRunning: (siteId: string, srcId: string) => running.has(`${siteId}:${srcId}`) };
}
