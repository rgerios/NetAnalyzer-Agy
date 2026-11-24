import { useEffect, useState } from 'react';
import { Download, Loader2, Printer } from 'lucide-react';
import type { FacetReport } from '../../shared/awsFacets.ts';
import type { HttpInsights } from '../../shared/httpInsights.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { downloadCsv } from '../utils/csv.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import type { FirewallVendor } from '../types.ts';
import { AccessReportView } from './AccessReportView.tsx';
import { AWS_PERIODS, FacetsGrid, HttpInsightsSection, Stat, nf } from './awsParts.tsx';

type Tab = 'alb' | 'vpcflow' | 'waf' | 'access';

const TABS: Array<{ id: Tab; label: string; hint: string }> = [
  { id: 'alb', label: 'Aplicação (ALB)', hint: 'status, latência, endpoints e clientes' },
  { id: 'vpcflow', label: 'VPC Flow Logs', hint: 'rede aceita e rejeitada' },
  { id: 'waf', label: 'WAF', hint: 'bloqueios, regras e origens' },
  { id: 'access', label: 'Acessos e Consumo', hint: 'IPs, países e banda' },
];

const today = () => new Date().toISOString().slice(0, 10);

function ResourceReport({ vendor, kind, refreshToken }: { vendor: FirewallVendor; kind: 'alb' | 'vpcflow' | 'waf'; refreshToken: number }) {
  const [minutes, setMinutes] = useState(30);
  const [loading, setLoading] = useState(true);
  const [http, setHttp] = useState<HttpInsights | null>(null);
  const [facets, setFacets] = useState<FacetReport | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    const url = kind === 'alb' ? `/cloud/http-insights?minutes=${minutes}` : `/cloud/facets?kind=${kind}&minutes=${minutes}`;
    fetch(vendorApiUrl(vendor, url))
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => alive && (kind === 'alb' ? setHttp(d as HttpInsights | null) : setFacets(d as FacetReport | null)))
      .catch(() => undefined)
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [vendor, kind, minutes, refreshToken]);

  const label = AWS_PERIODS.find((p) => p.minutes === minutes)?.label ?? `${minutes} min`;

  const exportCsv = () => {
    if (kind === 'alb' && http) {
      downloadCsv(
        `fwaudit-alb-endpoints-${today()}.csv`,
        ['Host', 'Metodo', 'Caminho', 'Requisicoes', '4xx', '5xx', 'Latencia media (ms)', 'Latencia max (ms)', 'Lentas', 'Bytes recebidos', 'Bytes enviados'],
        http.endpoints.map((e) => [e.host, e.method, e.path, e.requests, e.errors4xx, e.errors5xx, e.avgMs, e.maxMs, e.slow, e.bytesIn, e.bytesOut])
      );
    } else if (facets) {
      downloadCsv(
        `fwaudit-${kind}-${today()}.csv`,
        ['Painel', 'Valor', 'Eventos', 'Bloqueados', 'Bytes'],
        facets.facets.flatMap((f) => f.items.map((i) => [f.title, i.key, i.count, i.blocked, i.bytes]))
      );
    }
  };

  return (
    <div className="space-y-4">
      <div className="no-print bg-white border border-[var(--fw-border)] rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="inline-flex p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Período">
          {AWS_PERIODS.map((p) => (
            <button
              key={p.minutes}
              type="button"
              aria-pressed={minutes === p.minutes}
              onClick={() => setMinutes(p.minutes)}
              className={`px-3 py-1.5 text-xs font-medium rounded ${minutes === p.minutes ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)]'}`}
            >
              {p.label}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={exportCsv} className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-white border border-[var(--fw-border-strong)] rounded-md">
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button type="button" onClick={() => window.print()} className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-white border border-[var(--fw-border-strong)] rounded-md">
            <Printer className="w-3.5 h-3.5" /> Imprimir / PDF
          </button>
        </div>
      </div>

      <div className="print-only-title text-xs text-[var(--fw-text-muted)]">
        Relatório {TABS.find((t) => t.id === kind)?.label} · últimas {label} · gerado em {new Date().toLocaleString('pt-BR')}
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-xs text-[var(--fw-text-muted)]">
          <Loader2 className="w-4 h-4 animate-spin" /> Gerando relatório…
        </div>
      )}
      {!loading && kind === 'alb' && (!http || http.requests === 0) && <p className="text-xs text-[var(--fw-text-muted)]">Sem acessos ao ALB no período.</p>}
      {kind === 'alb' && http && http.requests > 0 && <HttpInsightsSection ins={http} />}
      {kind !== 'alb' && facets && facets.totals.events > 0 && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Stat label="Eventos" value={nf(facets.totals.events)} />
            <Stat label={kind === 'waf' ? 'Bloqueados' : 'Rejeitados'} value={nf(facets.totals.blocked)} tone={facets.totals.blocked > 0 ? 'bad' : undefined} />
            <Stat label={kind === 'waf' ? 'Permitidos' : 'Aceitos'} value={nf(facets.totals.allowed)} />
            {kind === 'vpcflow' && <Stat label="Volume" value={formatBytes(facets.totals.bytes)} />}
          </div>
          <FacetsGrid facets={facets.facets} />
        </>
      )}
      {!loading && kind !== 'alb' && (!facets || facets.totals.events === 0) && <p className="text-xs text-[var(--fw-text-muted)]">Sem eventos no período.</p>}
    </div>
  );
}

/** Relatórios do ambiente AWS: um por recurso (ALB, VPC Flow Logs, WAF) mais o de acessos e consumo. */
export function AwsReportsView({ vendor, refreshToken }: { vendor: FirewallVendor; refreshToken: number }) {
  const [tab, setTab] = useState<Tab>('alb');
  return (
    <div className="space-y-4">
      <div className="no-print inline-flex flex-wrap p-1 bg-[var(--fw-surface-alt)] rounded-lg" role="tablist" aria-label="Tipo de relatório">
        {TABS.map((x) => (
          <button
            key={x.id}
            type="button"
            role="tab"
            aria-selected={tab === x.id}
            onClick={() => setTab(x.id)}
            className={`px-4 py-2 text-sm font-semibold rounded-md ${tab === x.id ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]'}`}
          >
            {x.label}
            <span className="ml-2 text-[11px] font-normal text-[var(--fw-text-subtle)] hidden xl:inline">{x.hint}</span>
          </button>
        ))}
      </div>
      {tab === 'access' ? <AccessReportView vendor={vendor} refreshToken={refreshToken} /> : <ResourceReport key={tab} vendor={vendor} kind={tab} refreshToken={refreshToken} />}
    </div>
  );
}
