import { Bar, BarChart, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { HttpEndpointRow, HttpInsights } from '../../shared/httpInsights.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { wellKnownService } from '../../shared/ports.ts';
import { countryName, flagEmoji } from '../utils/worldGeo.ts';

export function Stat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: 'warn' | 'bad' }) {
  return (
    <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
      <div className="text-[11px] text-[var(--fw-text-muted)]">{label}</div>
      <div className="text-2xl font-semibold tabular-nums" style={{ color: tone === 'bad' ? '#dc2626' : tone === 'warn' ? '#b45309' : 'var(--fw-heading)' }}>
        {value}
      </div>
      {sub && <div className="text-[11px] text-[var(--fw-text-muted)] mt-0.5">{sub}</div>}
    </div>
  );
}


export const fmtMs = (ms: number): string => (ms >= 1000 ? `${(ms / 1000).toFixed(ms >= 10_000 ? 0 : 1)} s` : `${ms} ms`);
export const nf = (n: number): string => n.toLocaleString('pt-BR');

export function EndpointTable({ rows, cols }: { rows: HttpEndpointRow[]; cols: Array<'req' | 'err' | 'avg' | 'p95' | 'max' | 'slow' | 'bytes'> }) {
  if (rows.length === 0) return <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>;
  const head: Record<string, string> = { req: 'Req.', err: '4xx / 5xx', avg: 'Média', p95: 'p95', max: 'Máx.', slow: 'Lentas', bytes: 'Enviado / Recebido' };
  return (
    <div className="overflow-auto">
      <table className="w-full text-xs">
        <thead className="text-left text-[var(--fw-text-muted)]">
          <tr>
            <th className="py-1.5 pr-3 font-medium">Endpoint</th>
            {cols.map((c) => (
              <th key={c} className="py-1.5 px-2 font-medium text-right whitespace-nowrap">
                {head[c]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={`${r.host}|${r.method}|${r.path}`} className="border-t border-[var(--fw-border-soft)]">
              <td className="py-1.5 pr-3 max-w-[340px]">
                <span className="font-semibold text-[var(--fw-heading)]">{r.method}</span>{' '}
                <span className="font-mono break-all" title={`${r.host}${r.path}`}>
                  {r.path}
                </span>
                <div className="text-[10px] text-[var(--fw-text-subtle)] truncate">{r.host}</div>
              </td>
              {cols.map((c) => (
                <td key={c} className="py-1.5 px-2 text-right tabular-nums whitespace-nowrap">
                  {c === 'req' && nf(r.requests)}
                  {c === 'err' && (
                    <>
                      <span>{nf(r.errors4xx)}</span> / <span style={{ color: r.errors5xx > 0 ? '#dc2626' : undefined }}>{nf(r.errors5xx)}</span>
                    </>
                  )}
                  {c === 'avg' && fmtMs(r.avgMs)}
                  {c === 'p95' && fmtMs(r.p95Ms)}
                  {c === 'max' && fmtMs(r.maxMs)}
                  {c === 'slow' && nf(r.slow)}
                  {c === 'bytes' && `${formatBytes(r.bytesIn)} / ${formatBytes(r.bytesOut)}`}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function BarList({ rows }: { rows: Array<{ label: string; value: number; sub?: string; bad?: boolean }> }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  if (rows.length === 0) return <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>;
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <li key={r.label} className="text-xs">
          <div className="flex justify-between gap-2">
            <span className="truncate" title={r.label}>
              {r.label}
            </span>
            <span className="text-[var(--fw-text-muted)] tabular-nums whitespace-nowrap">
              {nf(r.value)}
              {r.sub ? ` · ${r.sub}` : ''}
            </span>
          </div>
          <div className="h-1.5 mt-1 rounded bg-[var(--fw-border)] overflow-hidden">
            <div className="h-full" style={{ width: `${(r.value / max) * 100}%`, background: r.bad ? '#ef4444' : 'var(--fw-accent)' }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export function HttpPanel({ title, children, wide }: { title: string; children: React.ReactNode; wide?: boolean }) {
  return (
    <section className={`bg-white border border-[var(--fw-border)] rounded-lg p-4 ${wide ? 'lg:col-span-2' : ''}`} aria-label={title}>
      <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">{title}</h3>
      {children}
    </section>
  );
}

function TimeBreakdown({ ins }: { ins: HttpInsights }) {
  const b = ins.timeBreakdown;
  const total = Math.max(1, b.requestMs + b.targetMs + b.responseMs);
  const parts = [
    { label: 'Cliente → ALB (envio da requisição)', value: b.requestMs, color: '#F59E0B' },
    { label: 'Aplicação (target)', value: b.targetMs, color: '#0972D3' },
    { label: 'Resposta ao cliente', value: b.responseMs, color: '#7D8998' },
  ];
  const clientPct = ins.requests > 0 ? (ins.clientSlow / ins.requests) * 100 : 0;
  return (
    <div>
      <div className="flex h-3 rounded overflow-hidden bg-[var(--fw-border)]" role="img" aria-label="Divisão do tempo médio">
        {parts.map((p) => (
          <div key={p.label} title={`${p.label}: ${fmtMs(p.value)}`} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} />
        ))}
      </div>
      <ul className="mt-3 space-y-1.5 text-xs">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 min-w-0">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: p.color }} />
              <span className="truncate">{p.label}</span>
            </span>
            <span className="tabular-nums text-[var(--fw-text-muted)]">{fmtMs(p.value)}</span>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[11px] text-[var(--fw-text-muted)]">
        Média por requisição. Aplicação p95: {fmtMs(ins.latency.targetP95Ms)}.
        {ins.clientSlow > 0
          ? ` ${nf(ins.clientSlow)} requisição(ões) (${clientPct.toFixed(1)}%) levaram 1 s ou mais só para o cliente enviar o corpo: rede lenta ou upload grande, não lentidão do servidor.`
          : ''}
      </p>
    </div>
  );
}

function LatencyTimeline({ data }: { data: HttpInsights['timeline'] }) {
  if (data.length === 0) return <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>;
  const spanMs = data.length > 1 ? Date.parse(data[data.length - 1].t) - Date.parse(data[0].t) : 0;
  const timeOnly = spanMs < 36 * 3_600_000;
  const rows = data.map((p) => ({
    t: new Date(p.t).toLocaleString('pt-BR', timeOnly ? { hour: '2-digit', minute: '2-digit' } : { day: '2-digit', hour: '2-digit', minute: '2-digit' }),
    req: p.requests - p.errors5xx,
    err: p.errors5xx,
    app: p.avgTargetMs,
  }));
  return (
    <div style={{ height: 190 }}>
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={rows} margin={{ left: 0, right: 0, top: 4, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border)" vertical={false} />
          <XAxis dataKey="t" tick={{ fontSize: 10 }} />
          <YAxis yAxisId="l" tick={{ fontSize: 10 }} width={38} />
          <YAxis yAxisId="r" orientation="right" tick={{ fontSize: 10 }} width={42} tickFormatter={(v) => `${v} ms`} />
          <Tooltip formatter={(v, n) => [n === 'app' ? `${v} ms` : Number(v).toLocaleString('pt-BR'), n === 'app' ? 'Tempo médio da aplicação' : n === 'err' ? 'Erros 5xx' : 'Requisições']} />
          <Bar yAxisId="l" dataKey="req" stackId="a" fill="#0972D3" fillOpacity={0.55} />
          <Bar yAxisId="l" dataKey="err" stackId="a" fill="#D13212" />
          <Line yAxisId="r" type="monotone" dataKey="app" stroke="#FF9900" strokeWidth={2} dot={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

function SlowRequestsTable({ rows }: { rows: HttpInsights['slowRequests'] }) {
  return (
    <div className="overflow-auto">
      <table className="w-full text-xs">
        <thead className="text-left text-[var(--fw-text-muted)]">
          <tr>
            <th className="py-1.5 pr-3 font-medium">Requisição</th>
            <th className="py-1.5 px-2 font-medium">Cliente</th>
            <th className="py-1.5 px-2 font-medium text-right">Status</th>
            <th className="py-1.5 px-2 font-medium text-right">Total</th>
            <th className="py-1.5 px-2 font-medium text-right whitespace-nowrap">Envio</th>
            <th className="py-1.5 px-2 font-medium text-right">Aplicação</th>
            <th className="py-1.5 pl-2 font-medium">Trace ID</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={`${r.traceId}|${r.at}`} className="border-t border-[var(--fw-border-soft)]">
              <td className="py-1.5 pr-3 max-w-[320px]">
                <span className="font-semibold">{r.method}</span> <span className="font-mono break-all">{r.path}</span>
                <div className="text-[10px] text-[var(--fw-text-subtle)] truncate">
                  {r.host} · {new Date(r.at).toLocaleTimeString('pt-BR')}
                </div>
              </td>
              <td className="py-1.5 px-2 font-mono whitespace-nowrap">{r.client}</td>
              <td className="py-1.5 px-2 text-right tabular-nums" style={{ color: r.status.startsWith('5') ? '#dc2626' : undefined }}>
                {r.status}
              </td>
              <td className="py-1.5 px-2 text-right tabular-nums font-semibold">{fmtMs(r.totalMs)}</td>
              <td className="py-1.5 px-2 text-right tabular-nums" style={{ color: r.requestMs >= 1000 ? '#b45309' : undefined }}>
                {fmtMs(r.requestMs)}
              </td>
              <td className="py-1.5 px-2 text-right tabular-nums">{fmtMs(r.targetMs)}</td>
              <td className="py-1.5 pl-2 font-mono text-[10px] text-[var(--fw-text-subtle)] max-w-[180px] truncate" title={r.traceId}>
                {r.traceId}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-[11px] text-[var(--fw-text-muted)]">
        "Envio" é o tempo que o cliente levou para mandar a requisição ao ALB; valores em âmbar indicam rede lenta ou upload grande do lado do cliente.
      </p>
    </div>
  );
}

/** Análise de aplicação dos access logs do ALB: status, latência, endpoints, clientes, TLS, WAF e targets. */
export function HttpInsightsSection({ ins }: { ins: HttpInsights }) {
  const errPct = ins.requests > 0 ? (ins.status.s5xx / ins.requests) * 100 : 0;
  const classes = [
    { label: '2xx', value: ins.status.s2xx, color: '#0f766e' },
    { label: '3xx', value: ins.status.s3xx, color: '#38bdf8' },
    { label: '4xx', value: ins.status.s4xx, color: '#f59e0b' },
    { label: '5xx', value: ins.status.s5xx, color: '#ef4444' },
  ].filter((c) => c.value > 0);
  return (
    <div className="space-y-4" aria-label="Análise de aplicação (ALB)">
      <div>
        <h2 className="text-sm font-semibold text-[var(--fw-heading)]">Aplicação (ALB)</h2>
        <p className="text-[11px] text-[var(--fw-text-muted)]">
          Extraído dos access logs: status, tempos, endpoints, clientes, TLS, WAF e targets
          {ins.truncated ? ' · amostra parcial (agrupamentos menores omitidos)' : ''}.
        </p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <Stat label="Requisições" value={nf(ins.requests)} sub={`${nf(ins.hosts.length)} host(s)`} />
        <Stat
          label="Erros 5xx"
          value={`${errPct.toFixed(2)}%`}
          sub={`${nf(ins.status.s5xx)} · 4xx: ${nf(ins.status.s4xx)}`}
          tone={errPct >= 5 ? 'bad' : errPct >= 1 ? 'warn' : undefined}
        />
        <Stat
          label="Latência p95"
          value={fmtMs(ins.latency.p95Ms)}
          sub={`média ${fmtMs(ins.latency.avgMs)} · p50 ${fmtMs(ins.latency.p50Ms)} · p99 ${fmtMs(ins.latency.p99Ms)} · máx. ${fmtMs(ins.latency.maxMs)}`}
          tone={ins.latency.p95Ms >= 5000 ? 'bad' : ins.latency.p95Ms >= 2000 ? 'warn' : undefined}
        />
        <Stat
          label="WAF"
          value={nf(ins.waf.blocked)}
          sub={ins.waf.evaluated > 0 ? `bloqueadas de ${nf(ins.waf.evaluated)} avaliadas` : 'sem WAF nos logs'}
          tone={ins.waf.blocked > 0 ? 'warn' : undefined}
        />
        <Stat label="Tráfego HTTP" value={formatBytes(ins.bytes.in + ins.bytes.out)} sub={`↑ ${formatBytes(ins.bytes.in)} · ↓ ${formatBytes(ins.bytes.out)}`} />
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <HttpPanel title="Onde o tempo é gasto">
          <TimeBreakdown ins={ins} />
        </HttpPanel>
        <HttpPanel title="Distribuição do tempo total">
          <BarList rows={ins.distribution.map((d, i) => ({ label: d.label, value: d.requests, bad: i >= 6 }))} />
          <p className="mt-3 text-[11px] text-[var(--fw-text-muted)]">Tempo total = envio pelo cliente + aplicação + resposta. Faixas a partir de 2 s em vermelho.</p>
        </HttpPanel>
        <HttpPanel title="Volume e latência da aplicação no tempo">
          <LatencyTimeline data={ins.timeline} />
        </HttpPanel>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <HttpPanel title="Status HTTP">
          <div className="flex h-3 rounded overflow-hidden bg-[var(--fw-border)]" role="img" aria-label="Distribuição de status">
            {classes.map((c) => (
              <div key={c.label} title={`${c.label}: ${nf(c.value)}`} style={{ width: `${(c.value / Math.max(1, ins.requests)) * 100}%`, background: c.color }} />
            ))}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[var(--fw-text-muted)]">
            {classes.map((c) => (
              <span key={c.label} className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: c.color }} /> {c.label} {nf(c.value)}
              </span>
            ))}
          </div>
          <div className="mt-3">
            <BarList rows={ins.status.top.map((s) => ({ label: s.code, value: s.count, bad: s.code.startsWith('5') }))} />
          </div>
        </HttpPanel>
        <HttpPanel title="Endpoints mais acessados" wide>
          <EndpointTable rows={ins.endpoints.slice(0, 8)} cols={['req', 'err', 'avg', 'p95', 'max']} />
        </HttpPanel>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <HttpPanel title="Endpoints mais lentos (média)">
          <EndpointTable rows={ins.slowest.slice(0, 6)} cols={['avg', 'p95', 'max', 'slow', 'req']} />
        </HttpPanel>
        <HttpPanel title="Endpoints que mais movimentam dados">
          <EndpointTable rows={ins.heaviest.slice(0, 6)} cols={['bytes', 'req']} />
        </HttpPanel>
        {ins.slowRequests.length > 0 && (
          <HttpPanel title="Requisições mais lentas" wide>
            <SlowRequestsTable rows={ins.slowRequests} />
          </HttpPanel>
        )}
        {ins.errors.length > 0 && (
          <HttpPanel title="Endpoints com erro" wide>
            <EndpointTable rows={ins.errors.slice(0, 6)} cols={['err', 'req', 'avg']} />
          </HttpPanel>
        )}
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <HttpPanel title="Clientes (user-agent)">
          <BarList rows={ins.userAgents.slice(0, 7).map((u) => ({ label: u.name, value: u.requests, sub: u.errors > 0 ? `${nf(u.errors)} com 5xx` : undefined }))} />
        </HttpPanel>
        <HttpPanel title="TLS">
          <BarList rows={ins.tls.map((t) => ({ label: t.version, value: t.requests, bad: /TLSv1\.[01]$|SSL/i.test(t.version) }))} />
          <p className="mt-3 text-[11px] text-[var(--fw-text-muted)]">Versões antigas (TLS 1.0/1.1) aparecem em vermelho.</p>
          {ins.tlsReuse.total > 0 && (
            <p className="mt-1 text-[11px] text-[var(--fw-text-muted)]">
              {((ins.tlsReuse.reused / ins.tlsReuse.total) * 100).toFixed(0)}% das requisições reaproveitam a sessão TLS (menos custo de handshake).
            </p>
          )}
          <div className="mt-2">
            <BarList rows={ins.ciphers.slice(0, 4).map((c) => ({ label: c.name, value: c.requests }))} />
          </div>
        </HttpPanel>
        <HttpPanel title="Targets">
          {ins.targets.length === 0 ? (
            <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>
          ) : (
            <div className="overflow-auto">
              <table className="w-full text-xs">
                <thead className="text-left text-[var(--fw-text-muted)]">
                  <tr>
                    <th className="py-1.5 pr-3 font-medium">Target</th>
                    <th className="py-1.5 px-2 font-medium text-right">Req.</th>
                    <th className="py-1.5 px-2 font-medium text-right">5xx</th>
                    <th className="py-1.5 px-2 font-medium text-right">Média</th>
                  </tr>
                </thead>
                <tbody>
                  {ins.targets.slice(0, 6).map((t) => (
                    <tr key={`${t.ip}|${t.group}`} className="border-t border-[var(--fw-border-soft)]">
                      <td className="py-1.5 pr-3">
                        <span className="font-mono">{t.ip}</span>
                        <div className="text-[10px] text-[var(--fw-text-subtle)]">{t.group}</div>
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums">{nf(t.requests)}</td>
                      <td className="py-1.5 px-2 text-right tabular-nums" style={{ color: t.errors5xx > 0 ? '#dc2626' : undefined }}>
                        {nf(t.errors5xx)}
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums">{fmtMs(t.avgMs)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </HttpPanel>
      </div>
    </div>
  );
}


// ---------------------------------------------------------------------------
// Cabeçalho, período, linha do tempo e facetas (VPC Flow Logs e WAF)
// ---------------------------------------------------------------------------

export const AWS_PERIODS: Array<{ label: string; minutes: number }> = [
  { label: '30 min', minutes: 30 },
  { label: '1 h', minutes: 60 },
  { label: '3 h', minutes: 180 },
  { label: '6 h', minutes: 360 },
];

/** Cabeçalho de página no estilo do console: ícone em azul-marinho, título, descrição e controles à direita. */
export function PageHeader({
  icon,
  title,
  subtitle,
  right,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-3 min-w-0">
        <span className="grid place-items-center w-10 h-10 rounded-lg bg-[#232F3E] text-[#FF9900] shrink-0" aria-hidden="true">
          {icon}
        </span>
        <div className="min-w-0">
          <h2 className="text-base font-bold text-[var(--fw-heading)] leading-tight">{title}</h2>
          {subtitle && <p className="text-[11px] text-[var(--fw-text-muted)] max-w-3xl">{subtitle}</p>}
        </div>
      </div>
      {right}
    </div>
  );
}

export function PeriodSelector({ minutes, onChange }: { minutes: number; onChange: (m: number) => void }) {
  return (
    <div className="inline-flex p-1 bg-[var(--fw-surface-alt)] rounded-md" role="group" aria-label="Período">
      {AWS_PERIODS.map((r) => (
        <button
          key={r.minutes}
          type="button"
          onClick={() => onChange(r.minutes)}
          aria-pressed={minutes === r.minutes}
          className={`px-3 py-1.5 text-xs font-medium rounded ${
            minutes === r.minutes ? 'bg-white text-[var(--fw-heading)] shadow-xs' : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
          }`}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}

export function TimelineChart({
  data,
  okLabel = 'Permitidos',
  badLabel = 'Bloqueados',
  height = 200,
}: {
  data: Array<{ t: string; allowed: number; blocked: number }>;
  okLabel?: string;
  badLabel?: string;
  height?: number;
}) {
  const spanMs = data.length > 1 ? Date.parse(data[data.length - 1].t) - Date.parse(data[0].t) : 0;
  const timeOnly = spanMs < 36 * 3_600_000;
  const rows = data.map((p) => ({
    t: new Date(p.t).toLocaleString('pt-BR', timeOnly ? { hour: '2-digit', minute: '2-digit' } : { day: '2-digit', hour: '2-digit', minute: '2-digit' }),
    ok: p.allowed,
    bad: p.blocked,
  }));
  if (rows.length === 0) return <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>;
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border)" vertical={false} />
          <XAxis dataKey="t" tick={{ fontSize: 10 }} />
          <YAxis tick={{ fontSize: 10 }} width={44} />
          <Tooltip formatter={(v, n) => [Number(v).toLocaleString('pt-BR'), n === 'ok' ? okLabel : badLabel]} />
          <Bar dataKey="ok" stackId="a" fill="#0972D3" />
          <Bar dataKey="bad" stackId="a" fill="#D13212" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

import type { FacetItem, FacetResult } from '../../shared/awsFacets.ts';

function facetLabel(f: FacetResult, it: FacetItem): string {
  if (f.country) return `${flagEmoji(it.key)} ${countryName(it.key)}`.trim();
  if (f.ip) return `${it.country ? `${flagEmoji(it.country)} ` : ''}${it.key}`;
  if (f.port) {
    const svc = wellKnownService(Number(it.key));
    return svc ? `${it.key} · ${svc}` : it.key;
  }
  return it.key;
}

/** Um "top N": barras proporcionais, com bloqueios em vermelho e o volume quando a faceta é por bytes. */
export function FacetPanel({ facet }: { facet: FacetResult }) {
  const byBytes = facet.metric === 'bytes';
  const value = (it: FacetItem) => (byBytes ? it.bytes : it.count);
  const max = Math.max(1, ...facet.items.map(value));
  return (
    <HttpPanel title={facet.title}>
      {facet.hint && <p className="-mt-2 mb-3 text-[11px] text-[var(--fw-text-muted)]">{facet.hint}</p>}
      {facet.items.length === 0 ? (
        <p className="text-xs text-[var(--fw-text-muted)]">Sem dados no período.</p>
      ) : (
        <ul className="space-y-2">
          {facet.items.slice(0, 8).map((it) => (
            <li key={it.key} className="text-xs">
              <div className="flex justify-between gap-2">
                <span className="truncate" title={it.key}>
                  {facetLabel(facet, it)}
                </span>
                <span className="text-[var(--fw-text-muted)] tabular-nums whitespace-nowrap">
                  {byBytes ? formatBytes(it.bytes) : nf(it.count)}
                  {byBytes ? ` · ${nf(it.count)}` : it.blocked > 0 && it.blocked < it.count ? ` · ${nf(it.blocked)} bloq.` : ''}
                </span>
              </div>
              <div className="h-1.5 mt-1 rounded bg-[var(--fw-border)] overflow-hidden">
                <div
                  className="h-full"
                  style={{ width: `${Math.max(2, (value(it) / max) * 100)}%`, background: it.blocked > 0 && it.blocked === it.count ? '#D13212' : 'var(--fw-accent)' }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </HttpPanel>
  );
}

export function FacetsGrid({ facets }: { facets: FacetResult[] }) {
  const visible = facets.filter((f) => f.items.length > 0);
  if (visible.length === 0) return null;
  return (
    <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
      {visible.map((f) => (
        <FacetPanel key={f.id} facet={f} />
      ))}
    </div>
  );
}
