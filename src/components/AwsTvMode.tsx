/** Modo TV da AWS (ALB, VPC Flow Logs e WAF): tela cheia e escura, para deixar em um monitor. */
import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Maximize2, X } from 'lucide-react';
import type { HttpInsights } from '../../shared/httpInsights.ts';
import { formatBytes } from '../../shared/destinations.ts';
import type { FacetReport, FacetResult } from '../../shared/awsFacets.ts';
import { AlbKpis, FlowChart, FlowDonut, FlowKpis, StatusDonut, TrafficChart, type FlowKind } from './awsCharts.tsx';
import { BarList, PeriodSelector, facetLabel, fmtMs, nf } from './awsParts.tsx';

/** Sem atualização por esse tempo, a tela avisa que os números podem estar velhos. */
const STALE_MS = 3 * 60_000;

const THEME = {
  '--fw-heading': '#f1f5f9',
  '--fw-text': '#e2e8f0',
  '--fw-text-body': '#cbd5e1',
  '--fw-text-muted': '#94a3b8',
  '--fw-text-subtle': '#7c8aa0',
  '--fw-border': '#26374d',
  '--fw-border-soft': '#1c2b3f',
  '--fw-surface-alt': '#16263a',
  '--fw-accent': '#ff9900',
  background: '#08111d',
  color: '#e2e8f0',
} as React.CSSProperties;

function Card({ title, badge, children, className = '' }: { title: string; badge?: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`flex flex-col min-h-0 rounded-xl border border-[var(--fw-border)] p-4 ${className}`} style={{ background: '#0d1928' }} aria-label={title}>
      <div className="flex items-center justify-between gap-2 mb-3">
        <h3 className="text-xs font-bold uppercase tracking-wide text-sky-200">{title}</h3>
        {badge && <span className="px-2 py-0.5 rounded-md border border-sky-500/40 bg-sky-500/10 text-[11px] font-mono text-sky-200">{badge}</span>}
      </div>
      <div className="flex-1 min-h-0 overflow-hidden">{children}</div>
    </section>
  );
}

interface ShellProps {
  title: string;
  /** Horário do cálculo mostrado na tela; nulo enquanto carrega. */
  generatedAt: string | null;
  note?: string;
  error: string | null;
  minutes: number;
  onMinutes: (m: number) => void;
  onClose: () => void;
  children: React.ReactNode;
}

function TvShell({ title, generatedAt, note, error, minutes, onMinutes, onClose, children }: ShellProps) {
  const root = useRef<HTMLDivElement>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    // mantém o monitor ligado quando o navegador permite (HTTPS e aba visível)
    let lock: { release: () => Promise<void> } | null = null;
    let closed = false;
    const keepAwake = () => {
      const api = (navigator as Navigator & { wakeLock?: { request: (t: 'screen') => Promise<{ release: () => Promise<void> }> } }).wakeLock;
      if (!api || document.hidden) return;
      api.request('screen').then((l) => { if (closed) void l.release(); else lock = l; }).catch(() => undefined);
    };
    keepAwake();
    document.addEventListener('visibilitychange', keepAwake);
    return () => {
      closed = true;
      window.removeEventListener('keydown', onKey);
      document.removeEventListener('visibilitychange', keepAwake);
      document.body.style.overflow = overflow;
      void lock?.release().catch(() => undefined);
      if (document.fullscreenElement) void document.exitFullscreen().catch(() => undefined);
    };
  }, [onClose]);

  const age = generatedAt ? Math.max(0, now - Date.parse(generatedAt)) : 0;
  const stale = !!error || age > STALE_MS;
  return createPortal(
    <div ref={root} className="fixed inset-0 z-[1000] flex flex-col gap-3 p-4 overflow-auto" style={THEME} role="dialog" aria-modal="true" aria-label={`Modo TV: ${title}`}>
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div>
          <h1 className="text-xl font-bold text-[var(--fw-heading)]">NetAnalyzer · {title}</h1>
          <p className={`text-xs ${stale ? 'text-amber-400 font-semibold' : 'text-[var(--fw-text-muted)]'}`} role="status">
            {!generatedAt ? 'Carregando…' : `${stale ? '⚠ Dados podem estar desatualizados · ' : '● '}atualizado às ${new Date(generatedAt).toLocaleTimeString('pt-BR')}`}
            {error ? ` · ${error}` : ''}
            {note ? ` · ${note}` : ''}
          </p>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <PeriodSelectorDark minutes={minutes} onChange={onMinutes} />
          <time className="text-3xl font-mono font-semibold tabular-nums text-[var(--fw-heading)]">{new Date(now).toLocaleTimeString('pt-BR')}</time>
          <button type="button" onClick={() => void (document.fullscreenElement ? document.exitFullscreen() : root.current?.requestFullscreen())?.catch(() => undefined)}
            className="p-2 rounded-md border border-[var(--fw-border)] hover:bg-white/10" aria-label="Alternar tela cheia" title="Tela cheia">
            <Maximize2 className="w-4 h-4" />
          </button>
          <button type="button" onClick={onClose} className="p-2 rounded-md border border-[var(--fw-border)] hover:bg-white/10" aria-label="Sair do modo TV" title="Sair (Esc)">
            <X className="w-4 h-4" />
          </button>
        </div>
      </header>

      {children}
    </div>,
    document.body
  );
}

/** Mensagem no lugar dos gráficos enquanto não há o que mostrar. */
function TvEmpty({ text }: { text: string }) {
  return <div className="flex-1 grid place-content-center text-[var(--fw-text-muted)]">{text}</div>;
}

/** Cartões no topo, gráfico e rosca no meio e três quadros embaixo. */
function TvLayout({ kpis, chartTitle, chart, donutTitle, donut, bottom }: {
  kpis: React.ReactNode; chartTitle: string; chart: React.ReactNode; donutTitle: string; donut: React.ReactNode; bottom: React.ReactNode;
}) {
  return (
    <>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 [&>div]:!bg-[#0d1928]">{kpis}</div>
      <div className="grid lg:grid-cols-3 gap-3 flex-[3] min-h-[260px]">
        <Card title={chartTitle} className="lg:col-span-2">{chart}</Card>
        <Card title={donutTitle}>
          <div className="h-full grid content-center">{donut}</div>
        </Card>
      </div>
      <div className="grid lg:grid-cols-3 gap-3 flex-[2] min-h-[270px] [&_ul]:!space-y-0 [&_ul]:flex [&_ul]:flex-col [&_ul]:h-full [&_ul]:justify-between">{bottom}</div>
    </>
  );
}

interface TvProps {
  error: string | null;
  minutes: number;
  onMinutes: (m: number) => void;
  onClose: () => void;
}

export function AlbTvMode({ ins, ...props }: TvProps & { ins: HttpInsights | null }) {
  const targets = (ins?.targets ?? [])
    .map((t) => ({ ...t, pct: t.requests > 0 ? (t.errors5xx / t.requests) * 100 : 0 }))
    .sort((a, b) => b.pct - a.pct || b.requests - a.requests)
    .slice(0, 6);

  return (
    <TvShell title="Application Load Balancer" generatedAt={ins?.generatedAt ?? null} note={ins?.truncated ? 'amostra parcial' : undefined} {...props}>
      {!ins || ins.requests === 0 ? (
        <TvEmpty text={ins ? 'Sem requisições no período.' : 'Carregando…'} />
      ) : (
        <TvLayout
          kpis={
            <>
              <AlbKpis ins={ins} big />
            <div className="rounded-lg border border-[var(--fw-border)] p-3" style={{ borderTop: '2px solid #14b8a6' }}>
              <div className="text-[11px] uppercase tracking-wide font-semibold text-[var(--fw-text-muted)]">Tráfego HTTP</div>
              <div className="text-4xl font-semibold tabular-nums text-[var(--fw-heading)]">{formatBytes(ins.bytes.in + ins.bytes.out)}</div>
              <div className="text-[11px] text-[var(--fw-text-muted)] mt-1">↑ {formatBytes(ins.bytes.in)} · ↓ {formatBytes(ins.bytes.out)}</div>
              <div className="text-[11px] text-[var(--fw-text-muted)] mt-1">WAF: {nf(ins.waf.blocked)} bloqueada(s)</div>
            </div>
            </>
          }
          chartTitle="Volume, erros 5xx e latência"
          chart={<TrafficChart data={ins.timeline} height="100%" />}
          donutTitle="Status HTTP"
          donut={<StatusDonut ins={ins} size={190} />}
          bottom={
            <>
            <Card title="Endpoints mais acessados">
              <BarList rows={ins.endpoints.slice(0, 6).map((e) => ({ label: `${e.method} ${e.path}`, value: e.requests, sub: `p95 ${fmtMs(e.p95Ms)}` }))} />
            </Card>
            <Card title="Targets: percentual de 5xx">
              <ul className="space-y-2.5">
                {targets.map((t) => (
                  <li key={`${t.ip}|${t.group}`} className="text-xs">
                    <div className="flex justify-between gap-2">
                      <span className="font-mono truncate">{t.ip} <span className="text-[var(--fw-text-subtle)]">{t.group}</span></span>
                      <span className="tabular-nums whitespace-nowrap">{t.pct.toFixed(2)}% · {nf(t.errors5xx)}/{nf(t.requests)}</span>
                    </div>
                    {/* escala fixa de 0 a 100%: um percentual baixo não vira barra cheia */}
                    <div className="h-1.5 mt-1 rounded bg-[var(--fw-border)] overflow-hidden">
                      <div className="h-full bg-red-500" style={{ width: `${t.pct}%` }} />
                    </div>
                  </li>
                ))}
                {targets.length === 0 && <li className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</li>}
              </ul>
            </Card>
            <Card title="Distribuição do tempo total">
              <BarList rows={ins.distribution.map((d, i) => ({ label: d.label, value: d.requests, bad: i >= 6 }))} />
            </Card>
            </>
          }
        />
      )}
    </TvShell>
  );
}

const FLOW_TV: Record<FlowKind, { title: string; chart: string; donut: string; cards: Array<{ id: string; title: string }> }> = {
  waf: {
    title: 'AWS WAF',
    chart: 'Requisições permitidas e bloqueadas',
    donut: 'Decisão do WAF',
    cards: [{ id: 'rules', title: 'Regras que mais bloquearam' }, { id: 'ips', title: 'IPs bloqueados' }, { id: 'countries', title: 'Países dos bloqueios' }],
  },
  vpcflow: {
    title: 'VPC Flow Logs',
    chart: 'Fluxos aceitos e rejeitados',
    donut: 'Security Group / NACL',
    cards: [{ id: 'rejSrc', title: 'Origens rejeitadas' }, { id: 'rejPorts', title: 'Portas mais rejeitadas' }, { id: 'topSrcBytes', title: 'Origens por volume (aceitos)' }],
  },
};

function facetRows(facet: FacetResult | undefined) {
  if (!facet) return [];
  const byBytes = facet.metric === 'bytes';
  return facet.items.slice(0, 7).map((it) => ({
    label: facetLabel(facet, it),
    // por volume, a barra mede os bytes e o texto mostra o tamanho legível
    value: byBytes ? it.bytes : it.count,
    text: byBytes ? formatBytes(it.bytes) : undefined,
  }));
}

export function FlowTvMode({ kind, report, ...props }: TvProps & { kind: FlowKind; report: FacetReport | null }) {
  const cfg = FLOW_TV[kind];
  // ao trocar de página, ignora o relatório do outro tipo de log
  const data = report?.kind === kind ? report : null;
  return (
    <TvShell title={cfg.title} generatedAt={data?.generatedAt ?? null} {...props}>
      {!data || data.totals.events === 0 ? (
        <TvEmpty text={data ? 'Sem eventos no período.' : 'Carregando…'} />
      ) : (
        <TvLayout
          kpis={<FlowKpis report={data} kind={kind} big />}
          chartTitle={cfg.chart}
          chart={<FlowChart data={data.timeline} kind={kind} height="100%" />}
          donutTitle={cfg.donut}
          donut={<FlowDonut report={data} kind={kind} size={190} />}
          bottom={cfg.cards.map((c) => {
            const rows = facetRows(data.facets.find((f) => f.id === c.id));
            return (
              <Card key={c.id} title={c.title}>
                {rows.length === 0 ? <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p> : <BarList rows={rows} />}
              </Card>
            );
          })}
        />
      )}
    </TvShell>
  );
}

/** O seletor padrão usa fundo branco no item ativo; na TV o destaque é laranja. */
function PeriodSelectorDark(props: { minutes: number; onChange: (m: number) => void }) {
  return (
    <div className="[&_[aria-pressed=true]]:!bg-[#ff9900] [&_[aria-pressed=true]]:!text-[#08111d]">
      <PeriodSelector {...props} />
    </div>
  );
}
