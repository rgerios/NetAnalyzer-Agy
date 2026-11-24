import { useEffect, useState } from 'react';
import { AlertTriangle, Cloud, Loader2, ShieldAlert, Upload } from 'lucide-react';
import type { AccessReportData } from '../../shared/accessReport.ts';
import type { AwsSiteConfigPublic } from '../../shared/aws.ts';
import { formatBytes } from '../../shared/destinations.ts';
import type { ActiveSection, AuditOverview, FirewallVendor } from '../types.ts';
import { countryName, flagEmoji } from '../utils/countryNames.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { AWS_PERIODS as RANGES, Stat, TimelineChart, nf } from './awsParts.tsx';
import type { CategorySummary } from '../../server/facets.ts';

interface AwsOverviewViewProps {
  vendor: FirewallVendor;
  overview: AuditOverview | null;
  loading: boolean;
  refreshToken: number;
  onNavigate: (section: ActiveSection) => void;
  onLoadSample: () => void;
}

function ago(iso: string | null | undefined): string {
  if (!iso) return 'nunca';
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 60) return `há ${s}s`;
  if (s < 3600) return `há ${Math.round(s / 60)} min`;
  if (s < 86400) return `há ${Math.round(s / 3600)} h`;
  return `há ${Math.round(s / 86400)} d`;
}

export function AwsOverviewView({ vendor, overview, loading, refreshToken, onNavigate, onLoadSample }: AwsOverviewViewProps) {
  const [minutes, setMinutes] = useState(30);
  const [report, setReport] = useState<AccessReportData | null>(null);
  const [config, setConfig] = useState<AwsSiteConfigPublic | null>(null);
  const [cats, setCats] = useState<CategorySummary[]>([]);
  const [tl, setTl] = useState<Array<{ t: string; allowed: number; blocked: number }>>([]);
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    let alive = true;
    setBusy(true);
    Promise.all([
      fetch(vendorApiUrl(vendor, `/access-report?minutes=${minutes}`)).then((r) => (r.ok ? (r.json() as Promise<AccessReportData>) : null)),
      fetch(vendorApiUrl(vendor, '/cloud/config')).then((r) => (r.ok ? (r.json() as Promise<AwsSiteConfigPublic>) : null)),
      fetch(vendorApiUrl(vendor, `/cloud/summary?minutes=${minutes}`)).then((r) => (r.ok ? (r.json() as Promise<{ rows: CategorySummary[]; timeline: Array<{ t: string; allowed: number; blocked: number }> }>) : null)),
    ])
      .then(([rep, cfg, ins]) => {
        if (!alive) return;
        setReport(rep);
        setConfig(cfg);
        setCats(ins?.rows ?? []);
        setTl(ins?.timeline ?? []);
      })
      .catch(() => undefined)
      .finally(() => alive && setBusy(false));
    return () => {
      alive = false;
    };
  }, [vendor, minutes, refreshToken]);

  const sources = config?.sources ?? [];
  const active = sources.filter((s) => s.enabled).length;
  const failing = sources.filter((s) => s.status?.lastError).length;
  const hasData = (report?.analyzedEvents ?? 0) > 0 || (overview?.totalSyslogs ?? 0) > 0;
  const t = report?.totals;
  const blockedPct = t && t.connections > 0 ? (t.blocked / t.connections) * 100 : 0;
  const topCountry = report?.countries?.[0];
  const maxCountry = Math.max(1, ...(report?.countries ?? []).map((c) => c.connections));
  const maxService = Math.max(1, ...(report?.services ?? []).map((s) => s.connections));
  const alerts = (overview?.alerts ?? []).slice(0, 5);

  if (!loading && !busy && !hasData && sources.length === 0) {
    return (
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-10 text-center space-y-4">
        <Cloud className="w-9 h-9 mx-auto text-[var(--fw-accent)]" aria-hidden="true" />
        <h2 className="text-base font-semibold text-[var(--fw-heading)]">Ambiente AWS ainda sem logs</h2>
        <p className="text-xs text-[var(--fw-text-muted)] max-w-xl mx-auto">
          Conecte o bucket do S3 onde a AWS grava seus VPC Flow Logs, AWS WAF e ALB. A plataforma baixa só os arquivos novos e mostra mapa, consumo, portas e alertas,
          como faz com os firewalls.
        </p>
        <div className="flex flex-wrap justify-center gap-2">
          <button
            type="button"
            onClick={() => onNavigate('connect')}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
          >
            <Upload className="w-3.5 h-3.5" /> Configurar fontes S3
          </button>
          <button
            type="button"
            onClick={onLoadSample}
            className="px-4 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)]"
          >
            Carregar amostra de demonstração
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[var(--fw-heading)] flex items-center gap-2">
            <Cloud className="w-4 h-4" aria-hidden="true" /> {overview?.activeSite.name ?? 'Conta AWS'}
            {busy && <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--fw-text-muted)]" aria-hidden="true" />}
          </h2>
          <p className="text-[11px] text-[var(--fw-text-muted)]">
            Região {config?.region ?? '—'} · logs lidos do S3 ou do CloudWatch (VPC Flow Logs, WAF e ALB)
          </p>
        </div>
        <div className="inline-flex p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Período">
          {RANGES.map((r) => (
            <button
              key={r.minutes}
              type="button"
              onClick={() => setMinutes(r.minutes)}
              aria-pressed={minutes === r.minutes}
              className={`px-3 py-1.5 text-xs font-medium rounded ${
                minutes === r.minutes ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-3" aria-label="Recursos">
        {([
          ['alb', 'ALB', 'Application Load Balancer'],
          ['vpcflow', 'VPC Flow Logs', 'VPC Flow Logs'],
          ['waf', 'WAF Logs Insight', 'AWS WAF'],
        ] as const).map(([id, label, cat]) => {
          const c = cats.find((x) => x.category === cat);
          const bad = id === 'alb' ? c?.errors5xx ?? 0 : c?.blocked ?? 0;
          return (
            <button
              key={id}
              type="button"
              onClick={() => onNavigate(id)}
              className="text-left bg-white border border-[var(--fw-border)] rounded-lg p-4 hover:border-[var(--fw-accent)] border-t-[3px] border-t-[#FF9900]"
            >
              <div className="text-xs font-semibold text-[var(--fw-heading)]">{label}</div>
              <div className="text-2xl font-semibold tabular-nums mt-1">{nf(c?.events ?? 0)}</div>
              <div className="text-[11px] text-[var(--fw-text-muted)]">
                {c ? `${nf(bad)} ${id === 'alb' ? 'erros 5xx' : id === 'waf' ? 'bloqueios' : 'rejeitados'}` : 'Sem eventos no período'}
              </div>
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <Stat label="Eventos no período" value={(report?.analyzedEvents ?? 0).toLocaleString('pt-BR')} sub={t ? `${t.sources.toLocaleString('pt-BR')} origens distintas` : undefined} />
        <Stat
          label="Bloqueados"
          value={`${blockedPct.toFixed(1)}%`}
          sub={t ? `${t.blocked.toLocaleString('pt-BR')} de ${t.connections.toLocaleString('pt-BR')}` : undefined}
          tone={blockedPct >= 30 ? 'bad' : blockedPct >= 10 ? 'warn' : undefined}
        />
        <Stat label="Países de origem" value={String(t?.countries ?? 0)} sub={topCountry ? `mais: ${flagEmoji(topCountry.code)} ${countryName(topCountry.code)}` : undefined} />
        <Stat label="Dados" value={formatBytes(t?.totalBytes ?? 0)} sub={t ? `${t.avgMbps.toLocaleString('pt-BR')} Mbps médios` : undefined} />
        <Stat
          label="Fontes de log"
          value={`${active}/${sources.length}`}
          sub={failing ? `${failing} com erro` : sources.length ? (active === 0 ? 'todas pausadas' : 'todas respondendo') : 'nenhuma cadastrada'}
          tone={failing ? 'bad' : undefined}
        />
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <section className="lg:col-span-2 bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Tráfego ao longo do tempo">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-2">Eventos ao longo do tempo</h3>
          <TimelineChart data={tl} height={230} />
        </section>

        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Fontes S3">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-[var(--fw-heading)]">Fontes de log</h3>
            <button type="button" onClick={() => onNavigate('connect')} className="text-xs font-medium text-[var(--fw-accent-mid)] hover:underline">
              Gerenciar
            </button>
          </div>
          {sources.length === 0 ? (
            <p className="text-xs text-[var(--fw-text-muted)]">Nenhuma fonte cadastrada.</p>
          ) : (
            <ul className="space-y-2.5">
              {sources.map((s) => (
                <li key={s.id} className="text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-[var(--fw-heading)] truncate">{s.name}</span>
                    <span style={{ color: s.status?.lastError ? '#dc2626' : s.enabled ? '#15803d' : '#64748b' }} className="text-[11px] font-semibold whitespace-nowrap">
                      {s.status?.lastError ? 'Erro' : s.enabled ? 'Ativa' : 'Pausada'}
                    </span>
                  </div>
                  <div className="text-[11px] text-[var(--fw-text-muted)] tabular-nums">
                    {(s.status?.eventsRead ?? 0).toLocaleString('pt-BR')} eventos · último arquivo {ago(s.status?.lastObjectAt)}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Países de origem">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Países de origem</h3>
          <ul className="space-y-2">
            {(report?.countries ?? []).slice(0, 7).map((c) => (
              <li key={c.code} className="text-xs">
                <div className="flex justify-between gap-2">
                  <span>
                    {flagEmoji(c.code)} {countryName(c.code)}
                  </span>
                  <span className="text-[var(--fw-text-muted)] tabular-nums">
                    {c.connections.toLocaleString('pt-BR')}
                    {c.blocked > 0 && <span className="text-red-600"> · {c.blocked.toLocaleString('pt-BR')} bloq.</span>}
                  </span>
                </div>
                <div className="h-1.5 mt-1 rounded bg-[var(--fw-border)] overflow-hidden">
                  <div className="h-full bg-[var(--fw-accent)]" style={{ width: `${(c.connections / maxCountry) * 100}%` }} />
                </div>
              </li>
            ))}
            {(report?.countries.length ?? 0) === 0 && <li className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</li>}
          </ul>
        </section>

        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Serviços mais acessados">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Serviços mais acessados</h3>
          <ul className="space-y-2">
            {(report?.services ?? []).slice(0, 7).map((s) => (
              <li key={s.name} className="text-xs">
                <div className="flex justify-between gap-2">
                  <span className="font-mono">{s.name}</span>
                  <span className="text-[var(--fw-text-muted)] tabular-nums">{s.connections.toLocaleString('pt-BR')}</span>
                </div>
                <div className="h-1.5 mt-1 rounded bg-[var(--fw-border)] overflow-hidden">
                  <div className="h-full bg-[var(--fw-accent)]" style={{ width: `${(s.connections / maxService) * 100}%` }} />
                </div>
              </li>
            ))}
            {(report?.services.length ?? 0) === 0 && <li className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</li>}
          </ul>
          <button type="button" onClick={() => onNavigate('vpcflow')} className="mt-3 text-xs font-medium text-[var(--fw-accent-mid)] hover:underline">
            Ver VPC Flow Logs e filtrar por porta
          </button>
        </section>

        <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label="Alertas">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" aria-hidden="true" /> Alertas ativos
          </h3>
          {alerts.length === 0 ? (
            <p className="text-xs text-[var(--fw-text-muted)]">Nenhum alerta ativo.</p>
          ) : (
            <ul className="space-y-2.5">
              {alerts.map((a) => (
                <li key={a.id} className="text-xs">
                  <div className="flex items-start gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: a.severity === 'critical' ? '#dc2626' : '#b45309' }} aria-hidden="true" />
                    <div>
                      <div className="font-medium text-[var(--fw-heading)]">{a.title}</div>
                      <div className="text-[11px] text-[var(--fw-text-muted)] line-clamp-2">{a.description}</div>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

    </div>
  );
}
