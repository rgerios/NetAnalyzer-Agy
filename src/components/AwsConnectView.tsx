import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cloud,
  Copy,
  Loader2,
  Pause,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Trash2,
  X,
  XCircle,
  FlaskConical,
} from 'lucide-react';
import type { FirewallVendor } from '../types.ts';
import {
  AWS_REGION_COUNTRY,
  AWS_SOURCE_LABELS,
  type AwsConfigSaveBody,
  type AwsSiteConfigPublic,
  type AwsSourceConfig,
  type AwsSourceType,
  type AwsTestResult,
} from '../../shared/aws.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface AwsConnectViewProps {
  vendor: FirewallVendor;
  onDataChanged: () => void;
}

const REGIONS = Object.keys(AWS_REGION_COUNTRY).sort();

const PREFIX_HINT: Record<AwsSourceType, string> = {
  vpcflow: 'AWSLogs/<conta>/vpcflowlogs/<região>/',
  waf: 'AWSLogs/<conta>/WAFLogs/<região>/<web-acl>/',
  alb: 'AWSLogs/<conta>/elasticloadbalancing/<região>/',
};

const TYPE_HELP: Record<AwsSourceType, string> = {
  vpcflow: 'Texto separado por espaço, com ou sem cabeçalho (formato padrão ou personalizado).',
  waf: 'JSON, uma requisição por linha (entrega do WAF em S3).',
  alb: 'Access logs do Application Load Balancer (texto, .gz).',
};

function timeAgo(iso: string | null): string {
  if (!iso) return 'nunca';
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 60) return `há ${s}s`;
  if (s < 3600) return `há ${Math.round(s / 60)} min`;
  if (s < 86400) return `há ${Math.round(s / 3600)} h`;
  return `há ${Math.round(s / 86400)} d`;
}

const inputCls =
  'w-full px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]';
const btnCls =
  'inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] disabled:opacity-50';
const primaryCls =
  'inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50';

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  const body = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(body.error || `Erro ${res.status}`);
  return body;
}

function emptySource(region: string): AwsSourceConfig {
  return {
    id: '',
    kind: 's3',
    type: 'vpcflow',
    name: '',
    enabled: true,
    bucket: '',
    prefix: '',
    region,
    dateLayout: true,
    lookbackHours: 6,
    logGroup: '',
    streamPrefix: '',
  };
}

const isCw = (s: AwsSourceConfig) => s.kind === 'cloudwatch';
const locationOf = (s: AwsSourceConfig) =>
  isCw(s) ? `CloudWatch: ${s.logGroup}${s.streamPrefix ? ` · streams ${s.streamPrefix}*` : ''}` : `s3://${s.bucket}/${s.prefix}`;

export function AwsConnectView({ vendor, onDataChanged }: AwsConnectViewProps) {
  const [config, setConfig] = useState<AwsSiteConfigPublic | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // credenciais (rascunho)
  const [region, setRegion] = useState('us-east-1');
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secret, setSecret] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [externalId, setExternalId] = useState('');
  const [pollSeconds, setPollSeconds] = useState('60');
  const [savingCreds, setSavingCreds] = useState(false);

  // edição de fonte
  const [editing, setEditing] = useState<AwsSourceConfig | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, AwsTestResult>>({});
  const [savingSource, setSavingSource] = useState(false);
  const [showGuide, setShowGuide] = useState(false);
  const [copied, setCopied] = useState(false);
  const [groups, setGroups] = useState<Array<{ name: string; storedBytes: number; retentionDays: number | null }>>([]);
  const [prefixes, setPrefixes] = useState<Array<{ prefix: string; streams: number; lastEventAt: string | null; example: string }>>([]);
  const [discovering, setDiscovering] = useState<'groups' | 'streams' | null>(null);
  const [discoverMsg, setDiscoverMsg] = useState<string | null>(null);

  const apply = useCallback((c: AwsSiteConfigPublic, keepDraft = false) => {
    setConfig(c);
    if (!keepDraft) {
      setRegion(c.region);
      setAccessKeyId(c.accessKeyId);
      setRoleArn(c.roleArn);
      setExternalId(c.externalId);
      setPollSeconds(String(c.pollSeconds));
    }
  }, []);

  const load = useCallback(
    async (keepDraft = true) => {
      try {
        apply(await api<AwsSiteConfigPublic>(vendorApiUrl(vendor, '/cloud/config')), keepDraft);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Falha ao carregar a configuração.');
      }
    },
    [vendor, apply]
  );

  useEffect(() => {
    void load(false);
  }, [load]);

  // acompanha o andamento das leituras
  const anyRunning = config?.sources.some((s) => s.status?.running) ?? false;
  useEffect(() => {
    const id = window.setInterval(() => void load(true), anyRunning ? 2000 : 15000);
    return () => window.clearInterval(id);
  }, [load, anyRunning]);

  const credsBody = (): AwsConfigSaveBody => ({
    region,
    accessKeyId: accessKeyId.trim(),
    ...(secret.trim() ? { secretAccessKey: secret.trim() } : {}),
    roleArn: roleArn.trim(),
    externalId: externalId.trim(),
    pollSeconds: Number(pollSeconds) || 60,
  });

  const saveCredentials = async () => {
    setSavingCreds(true);
    setError(null);
    setNotice(null);
    try {
      apply(
        await api<AwsSiteConfigPublic>(vendorApiUrl(vendor, '/cloud/config'), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credsBody()),
        })
      );
      setSecret('');
      setNotice('Credenciais salvas. O Secret fica criptografado no servidor e não volta para a tela.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao salvar.');
    } finally {
      setSavingCreds(false);
    }
  };

  const saveSources = async (sources: AwsSourceConfig[]) => {
    apply(
      await api<AwsSiteConfigPublic>(vendorApiUrl(vendor, '/cloud/config'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sources }),
      }),
      true
    );
  };

  const submitSource = async () => {
    if (!editing || !config) return;
    setSavingSource(true);
    setError(null);
    try {
      const exists = config.sources.some((s) => s.id === editing.id);
      const next = exists ? config.sources.map((s) => (s.id === editing.id ? editing : s)) : [...config.sources, editing];
      await saveSources(next);
      setEditing(null);
      setNotice('Fonte salva. A leitura começa no próximo ciclo (ou clique em "Ler agora").');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao salvar a fonte.');
    } finally {
      setSavingSource(false);
    }
  };

  const toggleSource = async (src: AwsSourceConfig) => {
    if (!config) return;
    try {
      await saveSources(config.sources.map((s) => (s.id === src.id ? { ...s, enabled: !s.enabled } : s)));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao atualizar a fonte.');
    }
  };

  const removeSource = async (src: AwsSourceConfig) => {
    if (!config || !window.confirm(`Remover a fonte "${src.name}"? Os logs já importados continuam na plataforma.`)) return;
    try {
      await saveSources(config.sources.filter((s) => s.id !== src.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao remover a fonte.');
    }
  };

  /** Busca log groups ou prefixos de stream na AWS, com as credenciais já salvas. */
  const discover = async (what: 'groups' | 'streams', src: AwsSourceConfig) => {
    setDiscovering(what);
    setDiscoverMsg(null);
    try {
      const body = await api<{ groups?: typeof groups; prefixes?: typeof prefixes }>(vendorApiUrl(vendor, '/cloud/discover'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: secret.trim() || !config?.hasSecret ? credsBody() : undefined, what, logGroup: src.logGroup, region: src.region }),
      });
      if (what === 'groups') {
        setGroups(body.groups ?? []);
        setDiscoverMsg(`${(body.groups ?? []).length} log group(s) encontrado(s) em ${src.region}. Clique no campo para escolher.`);
      } else {
        setPrefixes(body.prefixes ?? []);
        setDiscoverMsg(`${(body.prefixes ?? []).length} prefixo(s) de stream encontrado(s). Clique no campo para escolher.`);
      }
    } catch (err) {
      setDiscoverMsg(err instanceof Error ? err.message : 'Falha ao consultar a AWS.');
    } finally {
      setDiscovering(null);
    }
  };

  const testSource = async (src: AwsSourceConfig) => {
    setTesting(src.id || 'novo');
    setError(null);
    try {
      const result = await api<AwsTestResult>(vendorApiUrl(vendor, '/cloud/test'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: credsBody(), source: src }),
      });
      setTestResults((r) => ({ ...r, [src.id || 'novo']: result }));
    } catch (err) {
      setTestResults((r) => ({
        ...r,
        [src.id || 'novo']: { ok: false, message: err instanceof Error ? err.message : 'Falha no teste.', sampleKeys: [], sampleEvents: 0 },
      }));
    } finally {
      setTesting(null);
    }
  };

  const syncNow = async (sourceId?: string) => {
    setError(null);
    try {
      apply(
        await api<AwsSiteConfigPublic>(vendorApiUrl(vendor, '/cloud/sync'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sourceId }),
        }),
        true
      );
      onDataChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao iniciar a leitura.');
    }
  };

  const policy = useMemo(() => {
    const sources = config?.sources ?? [];
    const buckets = [...new Set(sources.filter((s) => !isCw(s)).map((s) => s.bucket).filter(Boolean))];
    const groups = [...new Set(sources.filter(isCw).map((s) => `arn:aws:logs:${s.region}:*:log-group:${s.logGroup}:*`))];
    const statements: Array<Record<string, unknown>> = [];
    if (buckets.length > 0 || groups.length === 0) {
      const list = buckets.length ? buckets : ['NOME-DO-BUCKET'];
      statements.push(
        { Effect: 'Allow', Action: ['s3:ListBucket'], Resource: list.map((b) => `arn:aws:s3:::${b}`) },
        { Effect: 'Allow', Action: ['s3:GetObject'], Resource: list.map((b) => `arn:aws:s3:::${b}/AWSLogs/*`) }
      );
    }
    if (groups.length > 0) {
      statements.push({ Effect: 'Allow', Action: ['logs:FilterLogEvents', 'logs:DescribeLogStreams'], Resource: groups });
    }
    return JSON.stringify({ Version: '2012-10-17', Statement: statements }, null, 2);
  }, [config?.sources]);

  const copyPolicy = async () => {
    try {
      await navigator.clipboard.writeText(policy);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-5">
        <h2 className="text-sm font-semibold text-[var(--fw-heading)] flex items-center gap-2">
          <Cloud className="w-4 h-4" aria-hidden="true" /> Contas e fontes de log (AWS S3)
        </h2>
        <p className="text-xs text-[var(--fw-text-muted)] mt-1 max-w-3xl">
          A plataforma lê, com uma chave <strong>somente leitura</strong>, os logs que a AWS grava no S3 ou no CloudWatch Logs (VPC Flow Logs, AWS WAF e ALB),
          converte para o mesmo formato dos firewalls e alimenta ALB, VPC Flow Logs, WAF, Behavior, Destinos, Acessos e Consumo, portas e alertas. Só arquivos novos
          são baixados, e o ponto de leitura é guardado.
        </p>
        <p className="text-[11px] text-[var(--fw-text-subtle)] mt-2">
          O atraso é o da própria AWS: de 1 a 10 minutos nos Flow Logs e cerca de 5 minutos no ALB.
        </p>
      </div>

      {(error || notice) && (
        <div
          className={`px-3 py-2 rounded-md border text-xs flex items-start gap-2 ${
            error ? 'bg-red-50 border-red-200 text-red-800' : 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
          }`}
        >
          {error ? <XCircle className="w-3.5 h-3.5 mt-0.5" /> : <CheckCircle2 className="w-3.5 h-3.5 mt-0.5" />}
          <span className="flex-1">{error || notice}</span>
          <button type="button" onClick={() => (error ? setError(null) : setNotice(null))} aria-label="Fechar aviso">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      <section className="bg-white border border-[var(--fw-border)] rounded-lg p-5 space-y-4" aria-label="Credenciais da AWS">
        <h3 className="text-sm font-semibold text-[var(--fw-heading)]">Credenciais</h3>
        <p className="text-[11px] text-[var(--fw-text-muted)] -mt-2">Salvas uma vez e usadas por todas as fontes abaixo (S3 e CloudWatch). Ao adicionar uma fonte você não precisa informá-las de novo.</p>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
            Região principal
            <select value={region} onChange={(e) => setRegion(e.target.value)} className={inputCls}>
              {REGIONS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
            Access Key ID
            <input value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} placeholder="AKIA…" spellCheck={false} className={`${inputCls} font-mono`} />
          </label>
          <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
            Secret Access Key
            <input
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={config?.hasSecret ? '•••••••• (salva; digite para trocar)' : 'Cole a chave secreta'}
              autoComplete="off"
              className={`${inputCls} font-mono`}
            />
          </label>
          <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
            Role ARN <span className="text-[var(--fw-text-subtle)]">(opcional, outra conta)</span>
            <input value={roleArn} onChange={(e) => setRoleArn(e.target.value)} placeholder="arn:aws:iam::123456789012:role/FwAuditLeitura" spellCheck={false} className={`${inputCls} font-mono`} />
          </label>
          <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
            External ID <span className="text-[var(--fw-text-subtle)]">(opcional)</span>
            <input value={externalId} onChange={(e) => setExternalId(e.target.value)} spellCheck={false} className={`${inputCls} font-mono`} />
          </label>
          <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
            Intervalo de leitura (segundos)
            <input type="number" min={15} max={3600} value={pollSeconds} onChange={(e) => setPollSeconds(e.target.value)} className={`${inputCls} font-mono`} />
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={() => void saveCredentials()} disabled={savingCreds} className={primaryCls}>
            {savingCreds ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null} Salvar credenciais
          </button>
          <span className="text-[11px] text-[var(--fw-text-muted)]">
            {config?.hasSecret ? 'Secret Access Key salva e criptografada.' : 'Nenhuma Secret Access Key salva ainda.'}
          </span>
        </div>
      </section>

      <section className="bg-white border border-[var(--fw-border)] rounded-lg p-5 space-y-4" aria-label="Fontes de log">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)]">Fontes de log</h3>
          <div className="flex items-center gap-2">
            {config && config.sources.length > 0 && (
              <button type="button" onClick={() => void syncNow()} className={btnCls}>
                <RefreshCw className={`w-3.5 h-3.5 ${anyRunning ? 'animate-spin' : ''}`} /> Ler todas agora
              </button>
            )}
            <button type="button" onClick={() => setEditing(emptySource(config?.region ?? region))} className={primaryCls}>
              <Plus className="w-3.5 h-3.5" /> Adicionar fonte
            </button>
          </div>
        </div>

        {config && config.sources.length === 0 && !editing && (
          <p className="text-xs text-[var(--fw-text-muted)] py-4 text-center">
            Nenhuma fonte cadastrada. Clique em <strong>Adicionar fonte</strong> e informe o bucket onde a AWS grava seus logs.
          </p>
        )}

        <ul className="space-y-3">
          {config?.sources.map((s) => {
            const st = s.status;
            const running = st?.running;
            const failing = !!st?.lastError;
            const tr = testResults[s.id];
            return (
              <li key={s.id} className="rounded-lg border border-[var(--fw-border)] p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-[var(--fw-heading)]">{s.name}</span>
                      <span className="text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded bg-[var(--fw-surface-alt)] text-[var(--fw-text-body)]">
                        {AWS_SOURCE_LABELS[s.type]}
                      </span>
                      <span
                        className="text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded"
                        style={{
                          background: running ? 'rgba(59,130,246,0.15)' : failing ? 'rgba(239,68,68,0.14)' : s.enabled ? 'rgba(34,197,94,0.15)' : 'rgba(148,163,184,0.2)',
                          color: running ? '#2563eb' : failing ? '#dc2626' : s.enabled ? '#15803d' : '#64748b',
                        }}
                      >
                        {running ? 'Lendo…' : failing ? 'Erro' : s.enabled ? 'Ativa' : 'Pausada'}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] font-mono text-[var(--fw-text-muted)] break-all">
                      {locationOf(s)} · {s.region}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button type="button" onClick={() => void syncNow(s.id)} disabled={!!running} className={btnCls} title="Lê os arquivos novos agora">
                      <RefreshCw className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} /> Ler agora
                    </button>
                    <button type="button" onClick={() => void testSource(s)} disabled={testing === s.id} className={btnCls} title="Valida acesso e formato">
                      {testing === s.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />} Testar
                    </button>
                    <button type="button" onClick={() => void toggleSource(s)} className={btnCls} title={s.enabled ? 'Pausar leitura' : 'Retomar leitura'}>
                      {s.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    </button>
                    <button type="button" onClick={() => setEditing({ ...s })} className={btnCls} aria-label="Editar fonte">
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button type="button" onClick={() => void removeSource(s)} className={`${btnCls} text-red-700`} aria-label="Remover fonte">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <dl className="mt-3 grid grid-cols-2 md:grid-cols-5 gap-x-4 gap-y-1 text-[11px]">
                  {[
                    ['Última leitura', timeAgo(st?.lastRunAt ?? null)],
                    ['Último arquivo', timeAgo(st?.lastObjectAt ?? null)],
                    [isCw(s) ? 'Lotes lidos' : 'Arquivos lidos', (st?.filesRead ?? 0).toLocaleString('pt-BR')],
                    ['Eventos', (st?.eventsRead ?? 0).toLocaleString('pt-BR')],
                    ['Baixado', formatBytes(st?.bytesRead ?? 0)],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <dt className="text-[var(--fw-text-subtle)]">{k}</dt>
                      <dd className="text-[var(--fw-heading)] tabular-nums font-medium">{v}</dd>
                    </div>
                  ))}
                </dl>
                {(st?.pendingFiles ?? 0) > 0 && (
                  <p className="mt-2 text-[11px] text-amber-700">
                    {st?.pendingFiles.toLocaleString('pt-BR')} {isCw(s) ? 'lote(s)' : 'arquivo(s)'} ainda na fila: a leitura continua nos próximos ciclos.
                  </p>
                )}
                {failing && (
                  <p className="mt-2 text-xs text-red-700 flex items-start gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" /> {st?.lastError}
                  </p>
                )}
                {tr && (
                  <div className={`mt-2 text-xs rounded-md border px-3 py-2 ${tr.ok ? 'border-emerald-300 bg-emerald-50 text-emerald-900' : 'border-red-200 bg-red-50 text-red-800'}`}>
                    <p>{tr.message}</p>
                    {tr.sampleKeys.length > 0 && (
                      <ul className="mt-1 font-mono text-[10px] break-all opacity-80">
                        {tr.sampleKeys.slice(0, 3).map((k) => (
                          <li key={k}>{k}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>

        {editing && (
          <div className="rounded-lg border-2 border-[var(--fw-accent)] p-4 space-y-3 bg-[var(--fw-surface-soft)]">
            <h4 className="text-sm font-semibold text-[var(--fw-heading)]">{editing.id ? 'Editar fonte' : 'Nova fonte'}</h4>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                Origem dos logs
                <select
                  value={editing.kind ?? 's3'}
                  onChange={(e) => setEditing({ ...editing, kind: e.target.value as 's3' | 'cloudwatch' })}
                  className={inputCls}
                >
                  <option value="s3">S3 (bucket)</option>
                  <option value="cloudwatch">CloudWatch Logs (log group)</option>
                </select>
              </label>
              <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                Tipo de log
                <select
                  value={editing.type}
                  onChange={(e) => setEditing({ ...editing, type: e.target.value as AwsSourceType })}
                  className={inputCls}
                >
                  {(Object.keys(AWS_SOURCE_LABELS) as AwsSourceType[]).map((t) => (
                    <option key={t} value={t}>
                      {AWS_SOURCE_LABELS[t]}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                Nome
                <input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder={AWS_SOURCE_LABELS[editing.type]} className={inputCls} />
              </label>
              <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                Região do bucket
                <select value={editing.region} onChange={(e) => setEditing({ ...editing, region: e.target.value })} className={inputCls}>
                  {REGIONS.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </label>
              {isCw(editing) ? (
                <>
                  <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                    Log group
                    <div className="flex gap-1.5">
                      <input list="aws-cw-groups" value={editing.logGroup ?? ''} onChange={(e) => setEditing({ ...editing, logGroup: e.target.value })} placeholder="Logs_ALB-Apps" spellCheck={false} className={`${inputCls} font-mono`} />
                      <button type="button" onClick={() => void discover('groups', editing)} disabled={discovering !== null} title="Buscar log groups na AWS" aria-label="Atualizar lista de log groups" className={btnCls}>
                        <RefreshCw className={`w-3.5 h-3.5 ${discovering === 'groups' ? 'animate-spin' : ''}`} />
                      </button>
                    </div>
                    <datalist id="aws-cw-groups">
                      {groups.map((g) => (
                        <option key={g.name} value={g.name} />
                      ))}
                    </datalist>
                  </label>
                  <label className="text-xs text-[var(--fw-text-muted)] space-y-1 sm:col-span-2">
                    Prefixo do stream <span className="text-[var(--fw-text-subtle)]">(separa os tipos de log do mesmo grupo)</span>
                    <div className="flex gap-1.5">
                      <input list="aws-cw-prefixes" value={editing.streamPrefix ?? ''} onChange={(e) => setEditing({ ...editing, streamPrefix: e.target.value })} placeholder={editing.type === 'alb' ? 'ALB_Access_Logs/' : 'deixe vazio para ler todos'} spellCheck={false} className={`${inputCls} font-mono`} />
                      <button type="button" onClick={() => void discover('streams', editing)} disabled={discovering !== null || !editing.logGroup} title={editing.logGroup ? 'Buscar prefixos de stream deste log group' : 'Escolha o log group primeiro'} aria-label="Atualizar lista de prefixos de stream" className={btnCls}>
                        <RefreshCw className={`w-3.5 h-3.5 ${discovering === 'streams' ? 'animate-spin' : ''}`} />
                      </button>
                    </div>
                    <datalist id="aws-cw-prefixes">
                      {prefixes.map((p) => (
                        <option key={p.prefix} value={p.prefix} label={`${p.streams} stream(s)${p.lastEventAt ? ` · último evento ${new Date(p.lastEventAt).toLocaleString('pt-BR')}` : ''}`} />
                      ))}
                    </datalist>
                  </label>
                  {discoverMsg && <p className="sm:col-span-2 text-[11px] text-[var(--fw-text-muted)]">{discoverMsg}</p>}
                </>
              ) : (
                <>
              <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                Bucket
                <input value={editing.bucket} onChange={(e) => setEditing({ ...editing, bucket: e.target.value })} placeholder="meu-bucket-de-logs" spellCheck={false} className={`${inputCls} font-mono`} />
              </label>
              <label className="text-xs text-[var(--fw-text-muted)] space-y-1 sm:col-span-2">
                Prefixo
                <input value={editing.prefix} onChange={(e) => setEditing({ ...editing, prefix: e.target.value })} placeholder={PREFIX_HINT[editing.type]} spellCheck={false} className={`${inputCls} font-mono`} />
              </label>
                </>
              )}
              <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                Carga inicial (horas)
                <input
                  type="number"
                  min={1}
                  max={168}
                  value={editing.lookbackHours}
                  onChange={(e) => setEditing({ ...editing, lookbackHours: Number(e.target.value) || 6 })}
                  className={inputCls}
                />
              </label>
              {!isCw(editing) && (
                <label className="flex items-center gap-2 text-xs text-[var(--fw-text-body)] mt-5">
                  <input type="checkbox" checked={editing.dateLayout} onChange={(e) => setEditing({ ...editing, dateLayout: e.target.checked })} />
                  Arquivos organizados por data (AAAA/MM/DD), padrão da AWS
                </label>
              )}
              <label className="flex items-center gap-2 text-xs text-[var(--fw-text-body)] mt-5">
                <input type="checkbox" checked={editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} />
                Leitura ativa
              </label>
            </div>
            <p className="text-[11px] text-[var(--fw-text-muted)]">{TYPE_HELP[editing.type]}</p>

            {testResults[editing.id || 'novo'] && (
              <div
                className={`text-xs rounded-md border px-3 py-2 ${
                  testResults[editing.id || 'novo'].ok ? 'border-emerald-300 bg-emerald-50 text-emerald-900' : 'border-red-200 bg-red-50 text-red-800'
                }`}
              >
                {testResults[editing.id || 'novo'].message}
              </div>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <button type="button" onClick={() => void testSource(editing)} disabled={testing !== null || (isCw(editing) ? !editing.logGroup : !editing.bucket)} className={btnCls}>
                {testing !== null ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />} Testar antes de salvar
              </button>
              <button type="button" onClick={() => void submitSource()} disabled={savingSource || (isCw(editing) ? !editing.logGroup : !editing.bucket)} className={primaryCls}>
                {savingSource ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null} Salvar fonte
              </button>
              <button type="button" onClick={() => setEditing(null)} className={btnCls}>
                Cancelar
              </button>
            </div>
            <p className="text-[11px] text-[var(--fw-text-subtle)]">O teste usa as credenciais digitadas acima, mesmo sem salvá-las.</p>
          </div>
        )}
      </section>

      <section className="bg-white border border-[var(--fw-border)] rounded-lg p-5" aria-label="Como preparar na AWS">
        <button type="button" onClick={() => setShowGuide((v) => !v)} className="flex items-center gap-2 text-sm font-semibold text-[var(--fw-heading)]">
          {showGuide ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />} Como preparar na AWS
        </button>
        {showGuide && (
          <div className="mt-3 space-y-4 text-xs text-[var(--fw-text-body)]">
            <ol className="list-decimal ml-5 space-y-1.5">
              <li>
                <strong>Escolha onde os logs ficam.</strong> VPC Flow Logs, AWS WAF e ALB podem ser entregues no S3 ou no CloudWatch Logs. Se já estão no CloudWatch, leia de lá (origem
                "CloudWatch Logs"): para o ALB, use o prefixo de stream <code>ALB_Access_Logs/</code> e só o log de acesso entra (conexão e health check ficam de fora). Entregar em S3 custa
                cerca de metade da ingestão no CloudWatch.
              </li>
              <li>
                <strong>Flow Logs:</strong> use o formato de texto (não Parquet). O padrão serve; o formato personalizado com <code>pkt-srcaddr</code>, <code>pkt-dstaddr</code> e{' '}
                <code>flow-direction</code> melhora o resultado atrás de NAT.
              </li>
              <li>
                <strong>Crie um usuário IAM só para a plataforma</strong> com a política abaixo (somente leitura) e gere uma Access Key. Para ler de outra conta, crie um papel (Role) com
                essa política e informe o ARN e o External ID acima.
              </li>
              <li>
                <strong>Teste a fonte</strong> antes de salvar: a plataforma lista os objetos recentes e tenta reconhecer o formato.
              </li>
            </ol>
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium text-[var(--fw-heading)]">Política IAM mínima</span>
                <button type="button" onClick={() => void copyPolicy()} className={btnCls}>
                  <Copy className="w-3.5 h-3.5" /> {copied ? 'Copiado' : 'Copiar'}
                </button>
              </div>
              <pre className="p-3 rounded-md bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] text-[11px] overflow-auto">{policy}</pre>
            </div>
            <div>
              <span className="font-medium text-[var(--fw-heading)]">Prefixos habituais</span>
              <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-[var(--fw-text-muted)]">
                {(Object.keys(PREFIX_HINT) as AwsSourceType[]).map((t) => (
                  <li key={t}>
                    {AWS_SOURCE_LABELS[t]}: {PREFIX_HINT[t]}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
