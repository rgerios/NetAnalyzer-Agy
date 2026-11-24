/** Configuração do ambiente AWS: normalização, gravação (com secret criptografado) e visão pública. */
import crypto from 'node:crypto';
import {
  AWS_SOURCE_LABELS,
  type AwsConfigSaveBody,
  type AwsSiteConfigPublic,
  type AwsSourceConfig,
  type AwsSourceCursor,
  type AwsSourceStatus,
  type AwsSourceType,
} from '../shared/aws.ts';
import { DEFAULT_AWS_POLL_SECONDS, emptyStatus } from './awsIngest.ts';
import { normalizePrefix } from './awsS3.ts';
import type { AwsSiteConfigStored } from './types.ts';

const TYPES: AwsSourceType[] = ['vpcflow', 'waf', 'alb'];
const REGION_RE = /^[a-z]{2}(-[a-z]+)+-\d$/;
const BUCKET_RE = /^[a-z0-9][a-z0-9.\-_]{1,62}$/i;

export function defaultAwsConfig(): AwsSiteConfigStored {
  return {
    region: 'us-east-1',
    accessKeyId: '',
    roleArn: '',
    externalId: '',
    pollSeconds: DEFAULT_AWS_POLL_SECONDS,
    sources: [],
  };
}

const str = (v: unknown, max = 300): string => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function normCursor(raw: unknown): AwsSourceCursor | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const c = raw as Partial<AwsSourceCursor>;
  if (!Number.isFinite(c.lastModifiedMs)) return undefined;
  return {
    lastModifiedMs: Number(c.lastModifiedMs),
    recentKeys: Array.isArray(c.recentKeys) ? c.recentKeys.filter((k) => typeof k === 'string').slice(-5000) : [],
    lastKey: typeof c.lastKey === 'string' ? c.lastKey : undefined,
  };
}

function normStatus(raw: unknown): AwsSourceStatus {
  const base = emptyStatus();
  if (!raw || typeof raw !== 'object') return base;
  const s = raw as Partial<AwsSourceStatus>;
  const n = (v: unknown) => (Number.isFinite(v) ? Number(v) : 0);
  return {
    running: false, // nunca persiste "em execução": após reiniciar nada está rodando
    lastRunAt: typeof s.lastRunAt === 'string' ? s.lastRunAt : null,
    lastOkAt: typeof s.lastOkAt === 'string' ? s.lastOkAt : null,
    lastError: typeof s.lastError === 'string' ? s.lastError : null,
    filesRead: n(s.filesRead),
    eventsRead: n(s.eventsRead),
    bytesRead: n(s.bytesRead),
    lastObjectAt: typeof s.lastObjectAt === 'string' ? s.lastObjectAt : null,
    pendingFiles: n(s.pendingFiles),
  };
}

export function normalizeSource(raw: Partial<AwsSourceConfig> & { id?: string }, fallbackRegion: string, prev?: AwsSourceConfig): AwsSourceConfig {
  const type: AwsSourceType = TYPES.includes(raw.type as AwsSourceType) ? (raw.type as AwsSourceType) : prev?.type ?? 'vpcflow';
  const region = str(raw.region, 30) || prev?.region || fallbackRegion;
  const lookback = Number(raw.lookbackHours ?? prev?.lookbackHours ?? 6);
  const kind = raw.kind === 'cloudwatch' || (raw.kind === undefined && prev?.kind === 'cloudwatch') ? 'cloudwatch' : 's3';
  const isCw = kind === 'cloudwatch';
  const bucket = isCw ? '' : str(raw.bucket, 63).replace(/^s3:\/\//i, '').split('/')[0];
  return {
    kind,
    logGroup: isCw ? str(raw.logGroup ?? prev?.logGroup, 512) : undefined,
    streamPrefix: isCw ? str(raw.streamPrefix ?? prev?.streamPrefix, 200) : undefined,
    id: str(raw.id, 40) || prev?.id || `src-${crypto.randomUUID().slice(0, 8)}`,
    type,
    name: str(raw.name, 80) || prev?.name || AWS_SOURCE_LABELS[type],
    enabled: raw.enabled === undefined ? (prev?.enabled ?? true) : Boolean(raw.enabled),
    bucket,
    prefix: isCw ? '' : normalizePrefix(str(raw.prefix, 400)),
    region: REGION_RE.test(region) ? region : fallbackRegion,
    dateLayout: isCw ? false : raw.dateLayout === undefined ? (prev?.dateLayout ?? true) : Boolean(raw.dateLayout),
    lookbackHours: Number.isFinite(lookback) ? Math.min(168, Math.max(1, Math.floor(lookback))) : 6,
    cursor: prev?.cursor,
    status: prev?.status ?? emptyStatus(),
  };
}

/** Lê o que veio do armazenamento (arquivo/banco), tolerando campos ausentes. */
export function normalizeAwsConfig(raw: unknown): AwsSiteConfigStored {
  const base = defaultAwsConfig();
  if (!raw || typeof raw !== 'object') return base;
  const r = raw as Partial<AwsSiteConfigStored>;
  const region = REGION_RE.test(str(r.region, 30)) ? str(r.region, 30) : base.region;
  const poll = Number(r.pollSeconds);
  return {
    region,
    accessKeyId: str(r.accessKeyId, 128),
    secretEncrypted: typeof r.secretEncrypted === 'string' && r.secretEncrypted ? r.secretEncrypted : undefined,
    roleArn: str(r.roleArn, 200),
    externalId: str(r.externalId, 100),
    pollSeconds: Number.isFinite(poll) ? Math.min(3600, Math.max(15, Math.floor(poll))) : DEFAULT_AWS_POLL_SECONDS,
    sources: Array.isArray(r.sources)
      ? r.sources.map((s) => {
          const n = normalizeSource(s as AwsSourceConfig, region);
          return { ...n, cursor: normCursor((s as AwsSourceConfig).cursor), status: normStatus((s as AwsSourceConfig).status) };
        })
      : [],
  };
}

export class AwsConfigError extends Error {}

/** Aplica o que o usuário salvou na tela. Mantém cursores/estado das fontes existentes. */
export function applyAwsSave(
  current: AwsSiteConfigStored,
  body: AwsConfigSaveBody,
  encrypt: (plain: string) => string
): AwsSiteConfigStored {
  const next: AwsSiteConfigStored = { ...current, sources: [...current.sources] };

  if (body.region !== undefined) {
    const region = str(body.region, 30);
    if (!REGION_RE.test(region)) throw new AwsConfigError('Região inválida (ex.: sa-east-1, us-east-1).');
    next.region = region;
  }
  if (body.accessKeyId !== undefined) {
    const key = str(body.accessKeyId, 128);
    if (key && !/^[A-Z0-9]{16,128}$/.test(key)) throw new AwsConfigError('Access Key ID inválida (letras maiúsculas e números, ex.: AKIA…).');
    next.accessKeyId = key;
  }
  if (typeof body.secretAccessKey === 'string' && body.secretAccessKey.trim()) {
    const secret = body.secretAccessKey.trim();
    if (secret.length < 20 || secret.length > 128) throw new AwsConfigError('Secret Access Key com tamanho inesperado.');
    next.secretEncrypted = encrypt(secret);
  }
  if (body.roleArn !== undefined) {
    const arn = str(body.roleArn, 200);
    if (arn && !/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(arn)) throw new AwsConfigError('ARN do papel (Role) inválido.');
    next.roleArn = arn;
  }
  if (body.externalId !== undefined) next.externalId = str(body.externalId, 100);
  if (body.pollSeconds !== undefined) {
    const p = Number(body.pollSeconds);
    if (!Number.isFinite(p) || p < 15 || p > 3600) throw new AwsConfigError('O intervalo de leitura deve ficar entre 15 e 3600 segundos.');
    next.pollSeconds = Math.floor(p);
  }

  if (Array.isArray(body.sources)) {
    if (body.sources.length > 30) throw new AwsConfigError('Máximo de 30 fontes por conta.');
    const byId = new Map(current.sources.map((s) => [s.id, s]));
    next.sources = body.sources.map((raw) => {
      const prev = raw.id ? byId.get(String(raw.id)) : undefined;
      const s = normalizeSource(raw, next.region, prev);
      if (s.kind === 'cloudwatch') {
        if (!s.logGroup || !/^[\w.\-/#]{1,512}$/.test(s.logGroup)) throw new AwsConfigError(`Log group inválido na fonte "${s.name}".`);
        if (s.streamPrefix && !/^[\w.\-/#:]{1,200}$/.test(s.streamPrefix)) throw new AwsConfigError(`Prefixo de stream inválido na fonte "${s.name}".`);
      } else if (!s.bucket || !BUCKET_RE.test(s.bucket)) {
        throw new AwsConfigError(`Bucket inválido na fonte "${s.name}".`);
      }
      // mudou o local de leitura: recomeça pela janela inicial
      if (
        prev &&
        (prev.kind !== s.kind || prev.logGroup !== s.logGroup || prev.streamPrefix !== s.streamPrefix || prev.bucket !== s.bucket ||
          prev.prefix !== s.prefix || prev.dateLayout !== s.dateLayout || prev.type !== s.type)
      ) {
        s.cursor = undefined;
      }
      return s;
    });
  }
  return next;
}

export function toPublicAwsConfig(stored: AwsSiteConfigStored | undefined): AwsSiteConfigPublic {
  const c = stored ?? defaultAwsConfig();
  return {
    region: c.region,
    accessKeyId: c.accessKeyId,
    hasSecret: Boolean(c.secretEncrypted),
    roleArn: c.roleArn,
    externalId: c.externalId,
    pollSeconds: c.pollSeconds,
    sources: c.sources.map((s) => ({ ...s, cursor: undefined })),
  };
}

/** Descobre o tipo de log pelo conteúdo (colar/enviar arquivo manualmente). */
export function detectAwsType(text: string): AwsSourceType | null {
  const head = text.slice(0, 4000).split(/\r?\n/).find((l) => l.trim()) ?? '';
  const line = head.trim();
  if (line.startsWith('{')) return /"elb_status_code"|"request_line"|"target_processing_time"|"tls_handshake_latency"/.test(line) ? 'alb' : 'waf';
  if (/^(http|https|h2|grpcs?|ws|wss)\s+\d{4}-\d{2}-\d{2}T/i.test(line)) return 'alb';
  if (/^version\s+account-id/i.test(line) || /^\d+\s+\d{12}\s+\S+\s+\S+\s+\S+\s+\d+/.test(line)) return 'vpcflow';
  return null;
}
