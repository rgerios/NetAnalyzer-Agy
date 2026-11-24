import { useEffect, useState } from 'react';
import { Loader2, Network, ShieldCheck, Waves } from 'lucide-react';
import type { FacetReport } from '../../shared/awsFacets.ts';
import type { HttpInsights } from '../../shared/httpInsights.ts';
import { formatBytes } from '../../shared/destinations.ts';
import type { FirewallVendor } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { FacetsGrid, HttpInsightsSection, PageHeader, PeriodSelector, Stat, TimelineChart, HttpPanel, nf } from './awsParts.tsx';
import { SyslogView } from './SyslogView.tsx';
import { RISK_STYLE, SECRET_INFO } from '../../shared/awsSecrets.ts';

export type AwsResource = 'alb' | 'vpcflow' | 'waf';

const META: Record<AwsResource, { title: string; subtitle: string; category: string; icon: React.ReactNode }> = {
  alb: {
    title: 'ALB: Application Load Balancer',
    subtitle: 'Access logs do balanceador: status, latência, endpoints, clientes, TLS, ações do WAF e targets.',
    category: 'Application Load Balancer',
    icon: <Network className="w-5 h-5" />,
  },
  vpcflow: {
    title: 'VPC Flow Logs',
    subtitle: 'Tráfego de rede das interfaces (ENI): o que o Security Group e o NACL aceitaram ou rejeitaram.',
    category: 'VPC Flow Logs',
    icon: <Waves className="w-5 h-5" />,
  },
  waf: {
    title: 'WAF Logs Insight',
    subtitle: 'Requisições inspecionadas pelo AWS WAF: regras que bloquearam, IPs, países, URIs e clientes.',
    category: 'AWS WAF',
    icon: <ShieldCheck className="w-5 h-5" />,
  },
};

interface Props {
  vendor: FirewallVendor;
  resource: AwsResource;
  refreshToken: number;
  onDataChanged: () => void;
  onAnalyzeEvent: (raw: string) => void;
}

/** Credenciais que apareceram em texto claro nas requisições, com quem deve corrigir. O valor nunca é guardado. */
function SecretsPanel({ facets }: { facets: FacetReport['facets'] }) {
  const top = facets.find((f) => f.id === 'secTop')?.items ?? [];
  const endpoints = facets.find((f) => f.id === 'secEndpoint')?.items ?? [];
  if (top.length === 0) return null;
  const total = top.reduce((n, i) => n + i.count, 0);
  const appItems = top.filter((i) => (SECRET_INFO[i.key]?.owner ?? 'Aplicação') === 'Aplicação');
  return (
    <section className="bg-white border rounded-lg p-4 space-y-3" style={{ borderColor: appItems.length > 0 ? '#D13212' : 'var(--fw-border)' }} aria-label="Credenciais expostas">
      <div>
        <h3 className="text-sm font-semibold text-[var(--fw-heading)]">Credenciais expostas nas requisições</h3>
        <p className="text-[11px] text-[var(--fw-text-muted)]">
          {nf(total)} requisição(ões) carregam credenciais em texto claro. O NetAnalyzer guarda só o tipo e o endpoint, nunca o valor. Itens de{' '}
          <b>Aplicação</b> devem ser corrigidos pelo time de desenvolvimento; os de <b>Log do WAF</b> se resolvem ocultando o campo no logging.
        </p>
      </div>
      <div className="overflow-auto">
        <table className="w-full text-xs">
          <thead className="text-left text-[var(--fw-text-muted)]">
            <tr>
              <th className="py-1.5 pr-3 font-medium">Tipo</th>
              <th className="py-1.5 px-2 font-medium">Gravidade</th>
              <th className="py-1.5 px-2 font-medium">Quem corrige</th>
              <th className="py-1.5 px-2 font-medium text-right">Requisições</th>
              <th className="py-1.5 pl-3 font-medium">O que fazer</th>
            </tr>
          </thead>
          <tbody>
            {top.map((it) => {
              const info = SECRET_INFO[it.key];
              const st = RISK_STYLE[info?.risk ?? 'info'];
              return (
                <tr key={it.key} className="border-t border-[var(--fw-border-soft)] align-top">
                  <td className="py-1.5 pr-3 font-semibold">{it.key}</td>
                  <td className="py-1.5 px-2 whitespace-nowrap">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full" style={{ background: st.color }} /> {st.label}
                    </span>
                  </td>
                  <td className="py-1.5 px-2 whitespace-nowrap">{info?.owner ?? 'Aplicação'}</td>
                  <td className="py-1.5 px-2 text-right tabular-nums">{nf(it.count)}</td>
                  <td className="py-1.5 pl-3 text-[var(--fw-text-body)]">{info?.fix ?? ''}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {endpoints.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-[var(--fw-heading)] mb-1.5">Endpoints envolvidos</h4>
          <ul className="grid sm:grid-cols-2 gap-x-6 gap-y-1 text-xs">
            {endpoints.slice(0, 10).map((e) => (
              <li key={e.key} className="flex justify-between gap-2">
                <span className="font-mono break-all">{e.key}</span>
                <span className="tabular-nums text-[var(--fw-text-muted)]">{nf(e.count)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function ConnectionSection({ report }: { report: FacetReport }) {
  const kex = report.facets.find((f) => f.id === 'kex')?.items ?? [];
  const pq = kex.filter((i) => /mlkem|kyber/i.test(i.key)).reduce((n, i) => n + i.count, 0);
  const kexTotal = kex.reduce((n, i) => n + i.count, 0);
  const noTls = report.totals.blocked;
  return (
    <section className="space-y-3" aria-label="Conexões TLS do ALB">
      <div>
        <h3 className="text-sm font-semibold text-[var(--fw-heading)]">Conexões TLS (connection logs)</h3>
        <p className="text-[11px] text-[var(--fw-text-muted)]">Uma linha por conexão, antes de qualquer requisição HTTP: handshake, versão, troca de chaves e conexões que não concluíram o TLS.</p>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="Conexões" value={nf(report.totals.events)} />
        <Stat
          label="Sem handshake TLS"
          value={nf(noTls)}
          sub={`${((noTls / Math.max(1, report.totals.events)) * 100).toFixed(1)}% das conexões`}
          tone={noTls > 0 && noTls / Math.max(1, report.totals.events) >= 0.1 ? 'warn' : undefined}
        />
        <Stat label="Troca pós-quântica" value={kexTotal > 0 ? `${((pq / kexTotal) * 100).toFixed(0)}%` : '—'} sub="X25519MLKEM768 (híbrida)" />
        <Stat label="Concluíram o TLS" value={nf(report.totals.allowed)} />
      </div>
      <FacetsGrid facets={report.facets} />
    </section>
  );
}

export function AwsLogView({ vendor, resource, refreshToken, onDataChanged, onAnalyzeEvent }: Props) {
  const meta = META[resource];
  const [tab, setTab] = useState<'panel' | 'events'>('panel');
  const [minutes, setMinutes] = useState(30);
  const [loading, setLoading] = useState(true);
  const [facets, setFacets] = useState<FacetReport | null>(null);
  const [http, setHttp] = useState<HttpInsights | null>(null);
  const [conn, setConn] = useState<FacetReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (tab !== 'panel') return;
    let alive = true;
    setLoading(true);
    const url = resource === 'alb' ? `/cloud/http-insights?minutes=${minutes}` : `/cloud/facets?kind=${resource}&minutes=${minutes}`;
    if (resource === 'alb') {
      fetch(vendorApiUrl(vendor, `/cloud/facets?kind=albconn&minutes=${minutes}`))
        .then((r) => (r.ok ? (r.json() as Promise<FacetReport>) : null))
        .then((d) => alive && setConn(d))
        .catch(() => undefined);
    }
    fetch(vendorApiUrl(vendor, url))
      .then(async (r) => {
        if (!r.ok) throw new Error(((await r.json().catch(() => ({}))) as { error?: string }).error || `Erro ${r.status}`);
        return r.json();
      })
      .then((data) => {
        if (!alive) return;
        setError(null);
        if (resource === 'alb') setHttp(data as HttpInsights);
        else setFacets(data as FacetReport);
      })
      .catch((e: unknown) => alive && setError(e instanceof Error ? e.message : 'Falha ao carregar'))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [vendor, resource, minutes, refreshToken, tab]);

  const connEvents = conn?.totals.events ?? 0;
  const empty = resource === 'alb' ? (!http || http.requests === 0) && connEvents === 0 : !facets || facets.totals.events === 0;

  return (
    <div className="space-y-5">
      <PageHeader
        icon={meta.icon}
        title={meta.title}
        subtitle={meta.subtitle}
        right={tab === 'panel' ? <PeriodSelector minutes={minutes} onChange={setMinutes} /> : undefined}
      />
      <div role="tablist" className="inline-flex p-1 bg-[var(--fw-surface-alt)] rounded-md">
        {(['panel', 'events'] as const).map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 text-xs font-medium rounded ${tab === t ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)]'}`}
          >
            {t === 'panel' ? 'Painel' : 'Eventos'}
          </button>
        ))}
      </div>

      {tab === 'events' && (
        <SyslogView
          key={resource}
          vendor={vendor}
          refreshToken={refreshToken}
          onDataChanged={onDataChanged}
          onAnalyzeEvent={onAnalyzeEvent}
          category={meta.category}
        />
      )}

      {tab === 'panel' && (
        <>
          {loading && !facets && !http && (
            <div className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)]">
              <Loader2 className="w-4 h-4 animate-spin" /> Carregando…
            </div>
          )}
          {error && <p className="text-xs text-red-600">{error}</p>}
          {!loading && !error && empty && (
            <p className="text-xs text-[var(--fw-text-muted)]">
              Nenhum evento de {meta.title} no período. Configure a origem em Contas &amp; Fontes ou carregue a amostra.
            </p>
          )}

          {resource === 'alb' && http && http.requests > 0 && <HttpInsightsSection ins={http} />}
          {resource === 'alb' && conn && connEvents > 0 && <ConnectionSection report={conn} />}
          {resource === 'alb' && !loading && !error && connEvents === 0 && http && http.requests > 0 && (
            <p className="text-[11px] text-[var(--fw-text-muted)]">
              Sem connection logs no período. Para ver handshakes TLS, conexões abandonadas e troca de chaves, adicione em Contas &amp; Fontes uma fonte do tipo ALB apontando ao log group das conexões.
            </p>
          )}

          {resource !== 'alb' && facets && facets.totals.events > 0 && (
            <>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <Stat label="Eventos" value={nf(facets.totals.events)} />
                <Stat
                  label={resource === 'waf' ? 'Bloqueados' : 'Rejeitados'}
                  value={nf(facets.totals.blocked)}
                  sub={`${((facets.totals.blocked / Math.max(1, facets.totals.events)) * 100).toFixed(1)}% do total`}
                  tone={facets.totals.blocked > 0 ? 'bad' : undefined}
                />
                <Stat label={resource === 'waf' ? 'Permitidos' : 'Aceitos'} value={nf(facets.totals.allowed)} />
                {resource === 'vpcflow' ? (
                  <Stat label="Volume" value={formatBytes(facets.totals.bytes)} sub={`${nf(facets.totals.packets)} pacotes`} />
                ) : (
                  <Stat label="Fonte dos dados" value={facets.dataSource === 'database' ? 'Banco' : 'Memória'} />
                )}
              </div>
              <HttpPanel title="Linha do tempo">
                <TimelineChart
                  data={facets.timeline}
                  okLabel={resource === 'waf' ? 'Permitidos' : 'Aceitos'}
                  badLabel={resource === 'waf' ? 'Bloqueados' : 'Rejeitados'}
                />
              </HttpPanel>
              {resource === 'waf' && <SecretsPanel facets={facets.facets} />}
              <FacetsGrid facets={facets.facets.filter((f) => !f.id.startsWith('sec'))} />
            </>
          )}
        </>
      )}
    </div>
  );
}
