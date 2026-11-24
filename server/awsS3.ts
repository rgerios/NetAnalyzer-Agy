/** Acesso somente leitura ao S3 para a ingestão de logs da AWS. */
import { promisify } from 'node:util';
import zlib from 'node:zlib';
import { GetObjectCommand, ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { fromTemporaryCredentials } from '@aws-sdk/credential-providers';
import type { AwsSourceConfig, AwsTestResult } from '../shared/aws.ts';
import { parseAwsObject } from './awsParsers.ts';

const gunzip = promisify(zlib.gunzip);

export interface AwsClientConfig {
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  roleArn?: string;
  externalId?: string;
}

export interface S3ObjectRef {
  key: string;
  lastModifiedMs: number;
  size: number;
}

/** Cliente S3. Com `roleArn` assume o papel da conta do cliente (STS) usando as chaves como base. */
export function buildS3Client(cfg: AwsClientConfig, region?: string): S3Client {
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
  return new S3Client({ region: region || cfg.region, credentials, maxAttempts: 4 });
}

const pad = (n: number) => String(n).padStart(2, '0');

function dayPrefixes(prefix: string, fromMs: number, toMs: number): string[] {
  const out: string[] = [];
  const start = new Date(fromMs);
  const d = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
  const end = Date.UTC(new Date(toMs).getUTCFullYear(), new Date(toMs).getUTCMonth(), new Date(toMs).getUTCDate());
  for (let guard = 0; d.getTime() <= end && guard < 40; guard += 1) {
    out.push(`${prefix}${d.getUTCFullYear()}/${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())}/`);
    d.setUTCDate(d.getUTCDate() + 1);
  }
  return out;
}

export function normalizePrefix(prefix: string): string {
  const p = (prefix || '').trim().replace(/^\/+/, '');
  return p && !p.endsWith('/') ? `${p}/` : p;
}

const OVERLAP_MS = 15 * 60 * 1000;
const MAX_PAGES_PER_PREFIX = 60;

/**
 * Objetos novos desde o último ponto lido, do mais antigo para o mais novo.
 * Em layout por data lista só os dias necessários; sem layout usa a última chave (StartAfter).
 */
export async function listNewObjects(
  client: S3Client,
  src: AwsSourceConfig,
  nowMs: number,
  maxFiles: number
): Promise<{ objects: S3ObjectRef[]; pending: number }> {
  const cursor = src.cursor;
  const sinceMs = cursor ? cursor.lastModifiedMs : nowMs - Math.max(1, src.lookbackHours) * 3_600_000;
  const known = new Set(cursor?.recentKeys ?? []);
  const prefix = normalizePrefix(src.prefix);
  const found: S3ObjectRef[] = [];

  const scan = async (listPrefix: string, startAfter?: string) => {
    let token: string | undefined;
    for (let page = 0; page < MAX_PAGES_PER_PREFIX; page += 1) {
      const res = await client.send(
        new ListObjectsV2Command({
          Bucket: src.bucket,
          Prefix: listPrefix,
          ContinuationToken: token,
          StartAfter: token ? undefined : startAfter,
        })
      );
      for (const o of res.Contents ?? []) {
        if (!o.Key || o.Key.endsWith('/') || !o.LastModified) continue;
        const lm = o.LastModified.getTime();
        if (known.has(o.Key)) continue;
        if (lm < sinceMs - (cursor ? OVERLAP_MS : 0)) continue;
        found.push({ key: o.Key, lastModifiedMs: lm, size: o.Size ?? 0 });
      }
      if (!res.IsTruncated || !res.NextContinuationToken) break;
      token = res.NextContinuationToken;
    }
  };

  if (src.dateLayout) {
    for (const p of dayPrefixes(prefix, sinceMs - 3 * 3_600_000, nowMs + 3_600_000)) await scan(p);
  } else {
    await scan(prefix, cursor?.lastKey);
  }

  found.sort((a, b) => a.lastModifiedMs - b.lastModifiedMs || a.key.localeCompare(b.key));
  // sem duplicatas (mesmo prefixo listado duas vezes)
  const unique: S3ObjectRef[] = [];
  const seen = new Set<string>();
  for (const o of found) {
    if (seen.has(o.key)) continue;
    seen.add(o.key);
    unique.push(o);
  }
  return { objects: unique.slice(0, maxFiles), pending: Math.max(0, unique.length - maxFiles) };
}

export interface ObjectText {
  text: string;
  /** Bytes baixados (compactados). */
  bytes: number;
}

export async function getObjectText(
  client: S3Client,
  bucket: string,
  key: string,
  maxDownloadBytes = 200 * 1024 * 1024
): Promise<ObjectText> {
  const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  if (res.ContentLength && res.ContentLength > maxDownloadBytes) {
    throw new Error(`Objeto ${key} excede ${Math.round(maxDownloadBytes / 1048576)} MB.`);
  }
  const body = res.Body;
  if (!body) throw new Error(`Objeto ${key} sem conteúdo.`);
  const raw = Buffer.from(await body.transformToByteArray());
  const isGzip = raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b;
  const buf = isGzip ? await gunzip(raw, { maxOutputLength: 1024 * 1024 * 1024 }) : raw;
  return { text: buf.toString('utf8'), bytes: raw.length };
}

/** Mensagem clara para os erros mais comuns de configuração. */
export function describeAwsError(err: unknown): string {
  const e = err as { name?: string; Code?: string; message?: string; $metadata?: { httpStatusCode?: number } };
  const code = e?.name || e?.Code || '';
  const status = e?.$metadata?.httpStatusCode;
  switch (code) {
    case 'AccessDenied':
    case 'AccessDeniedException':
      return 'Acesso negado (AccessDenied): a chave não tem permissão neste bucket/prefixo. Precisa de s3:ListBucket e s3:GetObject (S3) ou logs:FilterLogEvents (CloudWatch).';
    case 'NoSuchBucket':
      return 'Bucket não encontrado (NoSuchBucket): confira o nome do bucket.';
    case 'InvalidAccessKeyId':
      return 'Access Key inválida (InvalidAccessKeyId).';
    case 'SignatureDoesNotMatch':
      return 'Secret Access Key incorreta (SignatureDoesNotMatch).';
    case 'ExpiredToken':
    case 'ExpiredTokenException':
      return 'Credenciais expiradas.';
    case 'ResourceNotFoundException':
      return 'Log group não encontrado (ResourceNotFoundException): confira o nome e a região.';
    case 'ThrottlingException':
    case 'Throttling':
      return 'O CloudWatch limitou as requisições (throttling). A leitura tenta de novo no próximo ciclo.';
    case 'InvalidParameterException':
      return `Parâmetro inválido para o CloudWatch: ${e?.message || 'confira o log group e o prefixo do stream'}.`;
    case 'PermanentRedirect':
    case 'AuthorizationHeaderMalformed':
      return 'A região do bucket não confere com a informada. Ajuste a região da fonte.';
    default:
      if (status === 301) return 'A região do bucket não confere com a informada. Ajuste a região da fonte.';
      return `${code ? `${code}: ` : ''}${e?.message || 'falha ao acessar o S3.'}`;
  }
}

/** Valida credenciais, bucket e prefixo e tenta ler um objeto de amostra no formato escolhido. */
export async function testSource(client: S3Client, src: AwsSourceConfig): Promise<AwsTestResult> {
  const nowMs = Date.now();
  try {
    const probe: AwsSourceConfig = { ...src, cursor: undefined, lookbackHours: Math.max(src.lookbackHours, 24) };
    const { objects } = await listNewObjects(client, probe, nowMs, 20);
    let keys = objects.map((o) => o.key);
    if (keys.length === 0) {
      // Sem objetos no layout/período: mostra o que existe no prefixo para ajudar a corrigir
      const res = await client.send(new ListObjectsV2Command({ Bucket: src.bucket, Prefix: normalizePrefix(src.prefix), MaxKeys: 5 }));
      keys = (res.Contents ?? []).map((o) => o.Key ?? '').filter(Boolean);
      return {
        ok: keys.length > 0,
        message: keys.length
          ? `Conectou, mas não há objetos recentes${src.dateLayout ? ' no layout AAAA/MM/DD' : ''} nas últimas ${probe.lookbackHours} h. Veja se o prefixo ou a opção de data estão corretos.`
          : 'Conectou ao bucket, mas não encontrou nenhum objeto neste prefixo.',
        sampleKeys: keys.slice(0, 5),
        sampleEvents: 0,
      };
    }
    const sample = objects.find((o) => o.size > 0 && o.size <= 8 * 1024 * 1024) ?? objects[0];
    const { text } = await getObjectText(client, src.bucket, sample.key, 8 * 1024 * 1024);
    const parsed = parseAwsObject(src.type, text, { nowMs });
    return {
      ok: parsed.events.length > 0,
      message:
        parsed.events.length > 0
          ? `Tudo certo: ${objects.length}${objects.length === 20 ? '+' : ''} objeto(s) recente(s); o arquivo de amostra tem ${parsed.events.length.toLocaleString('pt-BR')} evento(s) reconhecido(s).`
          : `Conectou e baixou um arquivo, mas nenhuma linha foi reconhecida como ${src.type === 'vpcflow' ? 'VPC Flow Logs' : src.type === 'waf' ? 'AWS WAF (JSON)' : 'ALB'}. Confira o tipo da fonte.`,
      sampleKeys: keys.slice(0, 5),
      sampleEvents: parsed.events.length,
      sampleKey: sample.key,
    };
  } catch (err) {
    return { ok: false, message: describeAwsError(err), sampleKeys: [], sampleEvents: 0 };
  }
}
