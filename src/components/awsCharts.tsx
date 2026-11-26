/** Gráficos do painel do ALB (usados na tela normal e no modo TV). */
import { useId } from 'react';
import { Area, AreaChart, Bar, CartesianGrid, ComposedChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { HttpInsights } from '../../shared/httpInsights.ts';
import type { FacetReport, FacetTimelinePoint } from '../../shared/awsFacets.ts';
import { formatBytes } from '../../shared/destinations.ts';

const nf = (n: number): string => n.toLocaleString('pt-BR');
const fmtMs = (ms: number): string => (ms >= 1000 ? `${(ms / 1000).toFixed(ms >= 10_000 ? 0 : 1)} s` : `${ms} ms`);

export const CHART = { requests: '#2f9bff', p95: '#ff9900', errors: '#ff5a4f' };

const STATUS_COLORS = [
  { key: 's2xx', label: '2xx', color: '#14b8a6' },
  { key: 's3xx', label: '3xx', color: '#60a5fa' },
  { key: 's4xx', label: '4xx', color: '#f59e0b' },
  { key: 's5xx', label: '5xx', color: '#ef4444' },
] as const;

const clock = (iso: string, withDay: boolean): string =>
  new Date(iso).toLocaleString('pt-BR', withDay ? { day: '2-digit', hour: '2-digit', minute: '2-digit' } : { hour: '2-digit', minute: '2-digit' });

/**
 * O intervalo mais recente ainda está enchendo (e os logs chegam com atraso): o "valor atual" é o do
 * último intervalo já fechado que tem requisições.
 */
export function latestPoint<T extends { t: string }>(timeline: T[], hasData: (p: T) => boolean): T | null {
  const closed = timeline.slice(0, -1);
  return [...closed].reverse().find(hasData) ?? [...timeline].reverse().find(hasData) ?? null;
}

export const pointTime = (iso: string): string => clock(iso, false);

/** Requisições (área, eixo esquerdo), p95 do tempo total (linha, eixo direito) e erros 5xx (barras). */
export function TrafficChart({ data, height = 230 }: { data: HttpInsights['timeline']; height?: number | `${number}%` }) {
  const gradient = useId().replace(/:/g, '');
  if (data.length === 0) return <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>;
  const withDay = Date.parse(data[data.length - 1].t) - Date.parse(data[0].t) >= 36 * 3_600_000;
  // sem requisições não existe latência: a linha é interrompida em vez de cair para zero
  const rows = data.map((p) => ({ t: clock(p.t, withDay), req: p.requests, err: p.errors5xx, p95: p.requests > 0 ? p.p95Ms : null }));
  const names: Record<string, string> = { req: 'Requisições', err: 'Erros 5xx', p95: 'Latência p95' };
  return (
    <div className="flex flex-col min-h-0" style={{ height }}>
      <div className="flex flex-wrap justify-center gap-x-4 text-[11px] text-[var(--fw-text-muted)]">
        <span><i className="inline-block w-2.5 h-2.5 mr-1.5 rounded-sm" style={{ background: CHART.requests }} />Requisições (esquerda)</span>
        <span><i className="inline-block w-2.5 h-2.5 mr-1.5 rounded-sm" style={{ background: CHART.errors }} />Erros 5xx (esquerda)</span>
        <span><i className="inline-block w-2.5 h-2.5 mr-1.5 rounded-sm" style={{ background: CHART.p95 }} />p95 do tempo total (direita)</span>
      </div>
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={rows} margin={{ left: 0, right: 0, top: 8, bottom: 0 }}>
            <defs>
              <linearGradient id={`req-${gradient}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={CHART.requests} stopOpacity={0.45} />
                <stop offset="100%" stopColor={CHART.requests} stopOpacity={0.03} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border)" vertical={false} />
            <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={24} />
            <YAxis yAxisId="l" tick={{ fontSize: 10, fill: CHART.requests }} width={44} allowDecimals={false} />
            <YAxis yAxisId="r" orientation="right" tick={{ fontSize: 10, fill: CHART.p95 }} width={48} tickFormatter={(v) => fmtMs(Number(v))} />
            <Tooltip
              contentStyle={{ background: '#0f1b2a', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0', fontSize: 12 }}
              formatter={(v, n) => [n === 'p95' ? fmtMs(Number(v)) : nf(Number(v)), names[String(n)]]}
            />
            <Area yAxisId="l" type="monotone" dataKey="req" stroke={CHART.requests} strokeWidth={2} fill={`url(#req-${gradient})`} isAnimationActive={false} />
            <Bar yAxisId="l" dataKey="err" fill={CHART.errors} maxBarSize={10} isAnimationActive={false} />
            <Area yAxisId="r" type="monotone" dataKey="p95" stroke={CHART.p95} strokeWidth={2} fill="none" dot={{ r: 2, fill: CHART.p95, strokeWidth: 0 }} isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/** Rosca com um destaque no centro e a legenda com quantidades e percentuais. */
export function Donut({ parts, total, center, caption, label, size = 170 }: {
  parts: Array<{ label: string; color: string; value: number }>; total: number; center: string; caption: string; label: string; size?: number;
}) {
  const base = Math.max(1, total);
  return (
    <div className="flex flex-wrap items-center justify-center gap-5" role="img" aria-label={`${label}: ${parts.map((p) => `${p.label} ${p.value}`).join(', ')}`}>
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <PieChart width={size} height={size}>
          <Pie data={parts.filter((p) => p.value > 0).map((p) => ({ ...p, fill: p.color }))} dataKey="value" nameKey="label" innerRadius="68%" outerRadius="98%" stroke="none" startAngle={90} endAngle={-270} isAnimationActive={false} />
          <Tooltip formatter={(v) => nf(Number(v))} />
        </PieChart>
        <div className="absolute inset-0 grid place-content-center text-center pointer-events-none">
          <div className="text-xl font-bold tabular-nums text-[var(--fw-heading)]">{center}</div>
          <div className="text-[10px] text-[var(--fw-text-muted)]">{caption}</div>
        </div>
      </div>
      <ul className="space-y-1.5 text-xs min-w-[150px]">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ background: p.color }} />
            <span className="min-w-7">{p.label}</span>
            <span className="ml-auto tabular-nums text-[var(--fw-heading)] font-semibold">{nf(p.value)}</span>
            <span className="w-12 text-right tabular-nums text-[var(--fw-text-muted)]">{((p.value / base) * 100).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Rosca das classes de status HTTP. */
export function StatusDonut({ ins, size }: { ins: HttpInsights; size?: number }) {
  const ok = ((ins.status.s2xx + ins.status.s3xx) / Math.max(1, ins.requests)) * 100;
  return (
    <Donut label="Status HTTP" size={size} total={ins.requests} center={`${ok.toFixed(1)}%`} caption="2xx + 3xx"
      parts={STATUS_COLORS.map((c) => ({ label: c.label, color: c.color, value: ins.status[c.key] }))} />
  );
}

/** Cartão com o total do período, o valor do último intervalo fechado e a tendência em área. */
export function KpiCard({ label, value, badge, sub, series, color, big }: {
  label: string; value: string; badge?: string; sub?: string; series: Array<number | null>; color: string; big?: boolean;
}) {
  const gradient = useId().replace(/:/g, '');
  return (
    <div className="bg-white border border-[var(--fw-border)] rounded-lg overflow-hidden flex flex-col" style={{ borderTop: `2px solid ${color}` }}>
      <div className="px-3 pt-3">
        <div className="text-[11px] uppercase tracking-wide font-semibold text-[var(--fw-text-muted)]">{label}</div>
        <div className={`${big ? 'text-4xl' : 'text-2xl'} font-semibold tabular-nums text-[var(--fw-heading)]`}>{value}</div>
        {badge && (
          <span className="inline-block mt-1 px-2 py-0.5 rounded-md text-[11px] font-mono border" style={{ color, borderColor: `${color}66`, background: `${color}1a` }}>
            {badge}
          </span>
        )}
        {sub && <div className="text-[11px] text-[var(--fw-text-muted)] mt-1">{sub}</div>}
      </div>
      <div className="mt-auto" style={{ height: big ? 44 : 36 }} aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={series.map((v, i) => ({ i, v }))} margin={{ left: 0, right: 0, top: 4, bottom: 0 }}>
            <defs>
              <linearGradient id={`kpi-${gradient}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.4} />
                <stop offset="100%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} fill={`url(#kpi-${gradient})`} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/** Os cartões principais do ALB. */
export function AlbKpis({ ins, big }: { ins: HttpInsights; big?: boolean }) {
  const last = latestPoint(ins.timeline, (p) => p.requests > 0);
  const at = last ? pointTime(last.t) : '';
  const errPct = ins.requests > 0 ? (ins.status.s5xx / ins.requests) * 100 : 0;
  const lastErr = last && last.requests > 0 ? (last.errors5xx / last.requests) * 100 : 0;
  return (
    <>
      <KpiCard big={big} label="Requisições" value={nf(ins.requests)} color={CHART.requests} series={ins.timeline.map((p) => p.requests)}
        badge={last ? `${at} · ${nf(last.requests)}` : undefined} sub={`${nf(ins.hosts.length)} host(s)`} />
      <KpiCard big={big} label="Erros 5xx" value={`${errPct.toFixed(2)}%`} color={CHART.errors} series={ins.timeline.map((p) => p.errors5xx)}
        badge={last ? `${at} · ${lastErr.toFixed(2)}%` : undefined} sub={`${nf(ins.status.s5xx)} no período · 4xx: ${nf(ins.status.s4xx)}`} />
      <KpiCard big={big} label="Latência p95" value={fmtMs(ins.latency.p95Ms)} color={CHART.p95} series={ins.timeline.map((p) => (p.requests > 0 ? p.p95Ms : null))}
        badge={last ? `${at} · ${fmtMs(last.p95Ms)}` : undefined} sub={`p50 ${fmtMs(ins.latency.p50Ms)} · p99 ${fmtMs(ins.latency.p99Ms)}`} />
    </>
  );
}

// ---------------------------------------------------------------------------
// VPC Flow Logs e WAF
// ---------------------------------------------------------------------------

export type FlowKind = 'vpcflow' | 'waf';

export const FLOW_LABELS: Record<FlowKind, { events: string; ok: string; bad: string; rate: string }> = {
  waf: { events: 'Requisições', ok: 'Permitidos', bad: 'Bloqueados', rate: 'Taxa de bloqueio' },
  vpcflow: { events: 'Fluxos', ok: 'Aceitos', bad: 'Rejeitados', rate: 'Taxa de rejeição' },
};

const blockedPct = (p: { allowed: number; blocked: number }): number | null =>
  p.allowed + p.blocked > 0 ? (p.blocked / (p.allowed + p.blocked)) * 100 : null;

/** Permitidos (área) e bloqueados (barras) à esquerda; percentual bloqueado (linha) à direita. */
export function FlowChart({ data, kind, height = 230 }: { data: FacetTimelinePoint[]; kind: FlowKind; height?: number | `${number}%` }) {
  const gradient = useId().replace(/:/g, '');
  if (data.length === 0) return <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>;
  const withDay = Date.parse(data[data.length - 1].t) - Date.parse(data[0].t) >= 36 * 3_600_000;
  // o último intervalo ainda está enchendo: com poucos eventos o percentual saltaria sem significado
  const rows = data.map((p, i) => ({ t: clock(p.t, withDay), ok: p.allowed, bad: p.blocked, pct: i === data.length - 1 && data.length > 1 ? null : blockedPct(p) }));
  const labels = FLOW_LABELS[kind];
  const names: Record<string, string> = { ok: labels.ok, bad: labels.bad, pct: labels.rate };
  return (
    <div className="flex flex-col min-h-0" style={{ height }}>
      <div className="flex flex-wrap justify-center gap-x-4 text-[11px] text-[var(--fw-text-muted)]">
        {([[CHART.requests, `${labels.ok} (esquerda)`], [CHART.errors, `${labels.bad} (esquerda)`], [CHART.p95, `${labels.rate} (direita)`]] as const).map(([color, text]) => (
          <span key={text}><i className="inline-block w-2.5 h-2.5 mr-1.5 rounded-sm" style={{ background: color }} />{text}</span>
        ))}
      </div>
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={rows} margin={{ left: 0, right: 0, top: 8, bottom: 0 }}>
            <defs>
              <linearGradient id={`ok-${gradient}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={CHART.requests} stopOpacity={0.45} />
                <stop offset="100%" stopColor={CHART.requests} stopOpacity={0.03} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border)" vertical={false} />
            <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={24} />
            <YAxis yAxisId="l" tick={{ fontSize: 10, fill: CHART.requests }} width={48} allowDecimals={false} />
            {/* escala fixa: poucos por cento não parecem um pico */}
            <YAxis yAxisId="r" orientation="right" domain={[0, 100]} tick={{ fontSize: 10, fill: CHART.p95 }} width={44} tickFormatter={(v) => `${v}%`} />
            <Tooltip
              contentStyle={{ background: '#0f1b2a', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0', fontSize: 12 }}
              formatter={(v, n) => [n === 'pct' ? `${Number(v).toFixed(1)}%` : nf(Number(v)), names[String(n)]]}
            />
            <Area yAxisId="l" type="monotone" dataKey="ok" stroke={CHART.requests} strokeWidth={2} fill={`url(#ok-${gradient})`} isAnimationActive={false} />
            <Bar yAxisId="l" dataKey="bad" fill={CHART.errors} maxBarSize={10} isAnimationActive={false} />
            <Area yAxisId="r" type="monotone" dataKey="pct" stroke={CHART.p95} strokeWidth={2} fill="none" dot={{ r: 2, fill: CHART.p95, strokeWidth: 0 }} isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export function FlowDonut({ report, kind, size }: { report: FacetReport; kind: FlowKind; size?: number }) {
  const { totals } = report;
  const labels = FLOW_LABELS[kind];
  return (
    <Donut label={`${labels.ok} e ${labels.bad}`} size={size} total={totals.events}
      center={`${((totals.allowed / Math.max(1, totals.events)) * 100).toFixed(1)}%`} caption={labels.ok.toLowerCase()}
      parts={[{ label: labels.ok, color: '#14b8a6', value: totals.allowed }, { label: labels.bad, color: '#ef4444', value: totals.blocked }]} />
  );
}

/** Quatro cartões: três com tendência e o quarto com o volume (VPC) ou a taxa de bloqueio (WAF). */
export function FlowKpis({ report, kind, big }: { report: FacetReport; kind: FlowKind; big?: boolean }) {
  const labels = FLOW_LABELS[kind];
  const { totals, timeline } = report;
  const last = latestPoint(timeline, (p) => p.allowed + p.blocked > 0);
  const badge = (value: string): string | undefined => (last ? `${pointTime(last.t)} · ${value}` : undefined);
  const rate = blockedPct(totals) ?? 0;
  const rateCard = (
    <KpiCard big={big} label={labels.rate} value={`${rate.toFixed(1)}%`} color={CHART.p95} series={timeline.slice(0, -1).map(blockedPct)}
      badge={last ? badge(`${(blockedPct(last) ?? 0).toFixed(1)}%`) : undefined} sub={`fonte: ${report.dataSource === 'database' ? 'banco' : 'memória'}`} />
  );
  return (
    <>
      <KpiCard big={big} label={labels.events} value={nf(totals.events)} color="#a78bfa" series={timeline.map((p) => p.allowed + p.blocked)}
        badge={last ? badge(nf(last.allowed + last.blocked)) : undefined} />
      <KpiCard big={big} label={labels.ok} value={nf(totals.allowed)} color={CHART.requests} series={timeline.map((p) => p.allowed)}
        badge={last ? badge(nf(last.allowed)) : undefined} />
      <KpiCard big={big} label={labels.bad} value={nf(totals.blocked)} color={CHART.errors} series={timeline.map((p) => p.blocked)}
        badge={last ? badge(nf(last.blocked)) : undefined} sub={kind === 'vpcflow' ? `${rate.toFixed(1)}% dos fluxos` : undefined} />
      {kind === 'waf' ? rateCard : (
        <div className="bg-white border border-[var(--fw-border)] rounded-lg p-3" style={{ borderTop: '2px solid #14b8a6' }}>
          <div className="text-[11px] uppercase tracking-wide font-semibold text-[var(--fw-text-muted)]">Volume</div>
          <div className={`${big ? 'text-4xl' : 'text-2xl'} font-semibold tabular-nums text-[var(--fw-heading)]`}>{formatBytes(totals.bytes)}</div>
          <div className="text-[11px] text-[var(--fw-text-muted)] mt-1">{nf(totals.packets)} pacotes</div>
          <div className="text-[11px] text-[var(--fw-text-muted)] mt-1">fonte: {report.dataSource === 'database' ? 'banco' : 'memória'}</div>
        </div>
      )}
    </>
  );
}
