/**
 * Relatório de entrega da AWS em HTML estático: ALB (aplicação), conexões TLS, VPC Flow Logs e WAF.
 * Uma única página, sem scripts nem recursos externos, com a identidade do cliente (logo e nome) no topo.
 */
import type { ReportBranding } from '../shared/branding.ts';
import type { FacetResult, FacetReport } from '../shared/awsFacets.ts';
import type { HttpEndpointRow, HttpInsights } from '../shared/httpInsights.ts';
import { RISK_STYLE, SECRET_INFO } from '../shared/awsSecrets.ts';
import { formatBytes } from '../shared/destinations.ts';
import { BRAND_CSS, brandedTitle, renderBrandHeader } from './reportBranding.ts';

export type AwsReportSection = 'alb' | 'albconn' | 'vpcflow' | 'waf';

export const AWS_SECTION_TITLE: Record<AwsReportSection, string> = {
  alb: 'Aplicação (ALB)',
  albconn: 'Conexões TLS (ALB)',
  vpcflow: 'VPC Flow Logs',
  waf: 'AWS WAF',
};

export interface AwsReportData {
  minutes: number;
  generatedAt: string;
  accountId?: string;
  region?: string;
  alb?: HttpInsights;
  albconn?: FacetReport;
  vpcflow?: FacetReport;
  waf?: FacetReport;
}

const esc = (s: unknown) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const nf = (n: number) => n.toLocaleString('pt-BR');
const fmtMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(ms >= 10_000 ? 0 : 1).replace('.', ',')} s` : `${ms} ms`);
const pct = (a: number, b: number) => (b > 0 ? (a / b) * 100 : 0);
const bar = (p: number, color = 'var(--accent)') => `<div class="bar"><i style="width:${Math.max(1, Math.min(100, p)).toFixed(1)}%;background:${color}"></i></div>`;

export function periodLabel(minutes: number): string {
  if (minutes < 60) return `${minutes} minutos`;
  if (minutes < 1440) return `${Math.round(minutes / 60)} hora(s)`;
  return `${Math.round(minutes / 1440)} dia(s)`;
}

const kpi = (label: string, value: string, sub = '', tone = '') =>
  `<div class="kpi ${tone}"><p class="l">${esc(label)}</p><p class="v">${esc(value)}</p>${sub ? `<p class="s">${esc(sub)}</p>` : ''}</div>`;

function endpointTable(rows: HttpEndpointRow[], cols: Array<'req' | 'err' | 'avg' | 'p95' | 'max' | 'slow' | 'bytes'>): string {
  if (rows.length === 0) return '<p class="muted">Sem dados no período.</p>';
  const head: Record<string, string> = { req: 'Req.', err: '4xx / 5xx', avg: 'Média', p95: 'p95', max: 'Máx.', slow: 'Lentas', bytes: 'Enviado / Recebido' };
  return `<table><thead><tr><th>Endpoint</th>${cols.map((c) => `<th class="r">${head[c]}</th>`).join('')}</tr></thead><tbody>${rows
    .map(
      (r) => `<tr><td><b>${esc(r.method)}</b> <span class="mono">${esc(r.path)}</span><br><span class="sub">${esc(r.host)}</span></td>${cols
        .map((c) => {
          const v =
            c === 'req' ? nf(r.requests)
            : c === 'err' ? `${nf(r.errors4xx)} / <span class="${r.errors5xx > 0 ? 'bad' : ''}">${nf(r.errors5xx)}</span>`
            : c === 'avg' ? fmtMs(r.avgMs)
            : c === 'p95' ? fmtMs(r.p95Ms)
            : c === 'max' ? fmtMs(r.maxMs)
            : c === 'slow' ? nf(r.slow)
            : `${formatBytes(r.bytesIn)} / ${formatBytes(r.bytesOut)}`;
          return `<td class="r">${v}</td>`;
        })
        .join('')}</tr>`
    )
    .join('')}</tbody></table>`;
}

function barList(rows: Array<{ label: string; value: number; right?: string; bad?: boolean }>): string {
  if (rows.length === 0) return '<p class="muted">Sem dados no período.</p>';
  const max = Math.max(1, ...rows.map((r) => r.value));
  return `<ul class="bl">${rows
    .map((r) => `<li><div class="row"><span>${esc(r.label)}</span><span class="muted">${esc(r.right ?? nf(r.value))}</span></div>${bar((r.value / max) * 100, r.bad ? '#d13212' : 'var(--accent)')}</li>`)
    .join('')}</ul>`;
}

/** Pirâmide em SVG estático (barras centralizadas) com linha laranja sobre o topo de cada faixa. */
function pyramidSvg(rows: Array<{ label: string; value: number; bad?: boolean }>): string {
  if (rows.length === 0 || rows.every((r) => r.value === 0)) return '';
  const W = 320, LABEL_W = 64, VALUE_W = 44, ROW_H = 24, BAR_H = 16;
  const innerW = W - LABEL_W - VALUE_W;
  const cx = LABEL_W + innerW / 2;
  const max = Math.max(1, ...rows.map((r) => r.value));
  const wOf = (v: number) => (v > 0 ? Math.max(3, (v / max) * innerW) : 0);
  const pts = rows.map((r, i) => ({ x: cx + wOf(r.value) / 2, y: i * ROW_H + 2 + ROW_H / 2 }));
  const items = rows
    .map((r, i) => {
      const w = wOf(r.value);
      return `<text x="0" y="${(pts[i].y + 3.5).toFixed(1)}" font-size="10" fill="#5f6b7a">${esc(r.label)}</text><rect x="${(cx - w / 2).toFixed(1)}" y="${(i * ROW_H + 2 + (ROW_H - BAR_H) / 2).toFixed(1)}" width="${w.toFixed(1)}" height="${BAR_H}" rx="2" fill="${r.bad ? '#ef4444' : '#0972d3'}" fill-opacity=".6"/><text x="${W}" y="${(pts[i].y + 3.5).toFixed(1)}" font-size="10" text-anchor="end" fill="#5f6b7a">${esc(nf(r.value))}</text>`;
    })
    .join('');
  const line = `<polyline points="${pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')}" fill="none" stroke="#ff9900" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>${pts.map((p) => `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.5" fill="#ff9900"/>`).join('')}`;
  return `<svg viewBox="0 0 ${W} ${rows.length * ROW_H + 4}" width="100%" role="img" aria-label="Pirâmide da distribuição do tempo total" style="max-width:420px;margin:4px 0 10px">${items}${line}</svg>`;
}

function albSection(ins: HttpInsights): string {
  const errPct = pct(ins.status.s5xx, ins.requests);
  const b = ins.timeBreakdown;
  const parts = [
    { label: 'Cliente → ALB (envio da requisição)', value: b.requestMs, color: '#f59e0b' },
    { label: 'Aplicação (target)', value: b.targetMs, color: '#0972d3' },
    { label: 'Resposta ao cliente', value: b.responseMs, color: '#7d8998' },
  ];
  const tot = Math.max(1, b.requestMs + b.targetMs + b.responseMs);
  return `<section><h2>Aplicação (ALB)</h2>
<div class="kpis">
${kpi('Requisições', nf(ins.requests), `${nf(ins.hosts.length)} host(s)`)}
${kpi('Erros 5xx', `${errPct.toFixed(2).replace('.', ',')}%`, `${nf(ins.status.s5xx)} · 4xx: ${nf(ins.status.s4xx)}`, errPct >= 5 ? 'bad' : errPct >= 1 ? 'warn' : '')}
${kpi('Latência p95', fmtMs(ins.latency.p95Ms), `média ${fmtMs(ins.latency.avgMs)} · p50 ${fmtMs(ins.latency.p50Ms)} · p99 ${fmtMs(ins.latency.p99Ms)}`, ins.latency.p95Ms >= 5000 ? 'bad' : ins.latency.p95Ms >= 2000 ? 'warn' : '')}
${kpi('WAF', nf(ins.waf.blocked), ins.waf.evaluated > 0 ? `bloqueadas de ${nf(ins.waf.evaluated)}` : 'sem WAF nos logs')}
${kpi('Tráfego HTTP', formatBytes(ins.bytes.in + ins.bytes.out), `↑ ${formatBytes(ins.bytes.in)} · ↓ ${formatBytes(ins.bytes.out)}`)}
</div>
<div class="two">
<div><h3>Onde o tempo é gasto</h3>
<div class="stack">${parts.map((p) => `<i style="width:${(p.value / tot) * 100}%;background:${p.color}"></i>`).join('')}</div>
<ul class="bl">${parts.map((p) => `<li><div class="row"><span><span class="dot" style="background:${p.color}"></span>${esc(p.label)}</span><span class="muted">${fmtMs(p.value)}</span></div></li>`).join('')}</ul>
<p class="note">Média por requisição. Aplicação p95: ${fmtMs(ins.latency.targetP95Ms)}.${ins.clientSlow > 0 ? ` ${nf(ins.clientSlow)} requisição(ões) levaram 1 s ou mais só para o cliente enviar o corpo (rede lenta ou upload grande), e não por lentidão do servidor.` : ''}</p></div>
<div><h3>Distribuição do tempo total</h3>${pyramidSvg(ins.distribution.map((d, i) => ({ label: d.label, value: d.requests, bad: i >= 6 })))}${barList(ins.distribution.map((d, i) => ({ label: d.label, value: d.requests, bad: i >= 6 })))}</div>
</div>
<div class="two">
<div><h3>Status HTTP</h3>${barList(ins.status.top.map((s) => ({ label: s.code, value: s.count, bad: s.code.startsWith('5') })))}</div>
<div><h3>Clientes (user-agent)</h3>${barList(ins.userAgents.slice(0, 8).map((u) => ({ label: u.name, value: u.requests, right: `${nf(u.requests)}${u.errors > 0 ? ` · ${nf(u.errors)} com 5xx` : ''}` })))}</div>
</div>
<h3>Endpoints mais acessados</h3>${endpointTable(ins.endpoints.slice(0, 12), ['req', 'err', 'avg', 'p95', 'max'])}
<h3>Endpoints mais lentos (média)</h3>${endpointTable(ins.slowest.slice(0, 8), ['avg', 'p95', 'max', 'slow', 'req'])}
<h3>Endpoints que mais movimentam dados</h3>${endpointTable(ins.heaviest.slice(0, 8), ['bytes', 'req'])}
${ins.errors.length > 0 ? `<h3>Endpoints com erro</h3>${endpointTable(ins.errors.slice(0, 8), ['err', 'req', 'avg'])}` : ''}
${
  ins.slowRequests.length > 0
    ? `<h3>Requisições mais lentas</h3><table><thead><tr><th>Requisição</th><th>Cliente</th><th class="r">Status</th><th class="r">Total</th><th class="r">Envio</th><th class="r">Aplicação</th><th>Trace ID</th></tr></thead><tbody>${ins.slowRequests
        .map((r) => `<tr><td><b>${esc(r.method)}</b> <span class="mono">${esc(r.path)}</span><br><span class="sub">${esc(r.host)} · ${esc(new Date(r.at).toLocaleString('pt-BR'))}</span></td><td class="mono">${esc(r.client)}</td><td class="r ${r.status.startsWith('5') ? 'bad' : ''}">${esc(r.status)}</td><td class="r"><b>${fmtMs(r.totalMs)}</b></td><td class="r">${fmtMs(r.requestMs)}</td><td class="r">${fmtMs(r.targetMs)}</td><td class="mono sub">${esc(r.traceId)}</td></tr>`)
        .join('')}</tbody></table>`
    : ''
}
<h3>Targets</h3>${
    ins.targets.length === 0
      ? '<p class="muted">Sem dados no período.</p>'
      : `<table><thead><tr><th>Target</th><th class="r">Req.</th><th class="r">5xx</th><th class="r">Média</th></tr></thead><tbody>${ins.targets
          .slice(0, 8)
          .map((t) => `<tr><td><span class="mono">${esc(t.ip)}</span><br><span class="sub">${esc(t.group)}</span></td><td class="r">${nf(t.requests)}</td><td class="r ${t.errors5xx > 0 ? 'bad' : ''}">${nf(t.errors5xx)}</td><td class="r">${fmtMs(t.avgMs)}</td></tr>`)
          .join('')}</tbody></table>`
  }
</section>`;
}

function facetBlock(f: FacetResult): string {
  if (f.items.length === 0) return '';
  const byBytes = f.metric === 'bytes';
  const max = Math.max(1, ...f.items.map((i) => (byBytes ? i.bytes : i.count)));
  return `<div class="facet"><h3>${esc(f.title)}</h3>${f.hint ? `<p class="note">${esc(f.hint)}</p>` : ''}<ul class="bl">${f.items
    .slice(0, 8)
    .map((i) => {
      const v = byBytes ? i.bytes : i.count;
      const right = byBytes ? `${formatBytes(i.bytes)} · ${nf(i.count)}` : `${nf(i.count)}${i.blocked > 0 && i.blocked < i.count ? ` · ${nf(i.blocked)} bloq.` : ''}`;
      return `<li><div class="row"><span class="mono-ish">${esc(i.key)}</span><span class="muted">${esc(right)}</span></div>${bar((v / max) * 100, i.blocked > 0 && i.blocked === i.count ? '#d13212' : 'var(--accent)')}</li>`;
    })
    .join('')}</ul></div>`;
}

function secretsBlock(r: FacetReport): string {
  const top = r.facets.find((f) => f.id === 'secTop')?.items ?? [];
  if (top.length === 0) return '';
  const eps = r.facets.find((f) => f.id === 'secEndpoint')?.items ?? [];
  return `<div class="alertbox"><h3>Credenciais expostas nas requisições</h3>
<p class="note">Detectadas nos cabeçalhos e na URL. O NetAnalyzer guarda só o tipo e o endpoint, nunca o valor. Itens de "Aplicação" devem ser corrigidos pelo time de desenvolvimento; os de "Log do WAF" se resolvem ocultando o campo no logging.</p>
<table><thead><tr><th>Tipo</th><th>Gravidade</th><th>Quem corrige</th><th class="r">Requisições</th><th>O que fazer</th></tr></thead><tbody>${top
    .map((it) => {
      const info = SECRET_INFO[it.key];
      const st = RISK_STYLE[info?.risk ?? 'info'];
      return `<tr><td><b>${esc(it.key)}</b></td><td><span class="dot" style="background:${st.color}"></span>${esc(st.label)}</td><td>${esc(info?.owner ?? 'Aplicação')}</td><td class="r">${nf(it.count)}</td><td>${esc(info?.fix ?? '')}</td></tr>`;
    })
    .join('')}</tbody></table>
${eps.length > 0 ? `<p class="note"><b>Endpoints envolvidos:</b> ${eps.slice(0, 10).map((e) => `<span class="mono">${esc(e.key)}</span> (${nf(e.count)})`).join(' · ')}</p>` : ''}</div>`;
}

function facetSection(kind: 'albconn' | 'vpcflow' | 'waf', r: FacetReport): string {
  const t = r.totals;
  const bad = kind === 'waf' ? 'Bloqueados' : kind === 'vpcflow' ? 'Rejeitados' : 'Sem handshake TLS';
  const good = kind === 'waf' ? 'Permitidos' : kind === 'vpcflow' ? 'Aceitos' : 'Concluíram o TLS';
  const kex = r.facets.find((f) => f.id === 'kex')?.items ?? [];
  const kexTotal = kex.reduce((n, i) => n + i.count, 0);
  const pq = kex.filter((i) => /mlkem|kyber/i.test(i.key)).reduce((n, i) => n + i.count, 0);
  const extra =
    kind === 'vpcflow' ? kpi('Volume', formatBytes(t.bytes), `${nf(t.packets)} pacotes`)
    : kind === 'albconn' ? kpi('Troca pós-quântica', kexTotal > 0 ? `${((pq / kexTotal) * 100).toFixed(0)}%` : '—', 'X25519MLKEM768 (híbrida)')
    : '';
  if (t.events === 0) return `<section><h2>${AWS_SECTION_TITLE[kind]}</h2><p class="muted">Nenhum evento no período.</p></section>`;
  return `<section><h2>${AWS_SECTION_TITLE[kind]}</h2>
<div class="kpis">${kpi('Eventos', nf(t.events))}${kpi(bad, nf(t.blocked), `${pct(t.blocked, t.events).toFixed(1).replace('.', ',')}% do total`, t.blocked > 0 && kind !== 'albconn' ? 'warn' : '')}${kpi(good, nf(t.allowed))}${extra}</div>
${kind === 'waf' ? secretsBlock(r) : ''}
<div class="facets">${r.facets.filter((f) => !f.id.startsWith('sec')).map(facetBlock).join('')}</div></section>`;
}

export function renderAwsReportHtml(
  data: AwsReportData,
  sections: AwsReportSection[],
  siteName: string,
  branding?: ReportBranding
): string {
  const when = new Date(data.generatedAt).toLocaleString('pt-BR');
  const body = sections
    .map((s) => {
      if (s === 'alb') return data.alb ? albSection(data.alb) : '';
      const r = data[s];
      return r ? facetSection(s, r) : '';
    })
    .join('\n');
  const defaultTitle = sections.length === 1 ? `Relatório AWS · ${AWS_SECTION_TITLE[sections[0]]}` : 'Relatório AWS · ALB, VPC Flow Logs e WAF';
  return `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(brandedTitle(branding, defaultTitle))}</title>
<style>
:root{--ink:#16191f;--muted:#5f6b7a;--line:#e0e4e8;--soft:#f5f7f8;--accent:#0972d3;--navy:#232f3e}
*{box-sizing:border-box}body{margin:0;background:#eef1f3;color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.page{max-width:1060px;margin:24px auto;background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(20,32,46,.08);overflow:hidden}
.page>.brand-head{margin:0;padding:24px 36px;border-bottom:3px solid #ff9900;--brand-accent:#ff9900}
.top{padding:26px 36px;background:var(--navy);color:#fff}
.top .k{font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.8}
.top h1{margin:6px 0 4px;font-size:24px;font-weight:650}.top p{margin:0;opacity:.85;font-size:13px}
main{padding:10px 36px 36px}section{margin-top:28px}
h2{font-size:17px;margin:0 0 12px;padding-bottom:6px;border-bottom:2px solid #ff9900}
h3{font-size:13px;margin:18px 0 6px;color:var(--navy)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{border:1px solid var(--line);border-radius:10px;padding:12px 14px;background:var(--soft)}
.kpi .l{margin:0;font-size:11px;color:var(--muted)}.kpi .v{margin:2px 0 0;font-size:22px;font-weight:700}.kpi .s{margin:2px 0 0;font-size:11px;color:var(--muted)}
.kpi.bad .v{color:#d13212}.kpi.warn .v{color:#b45309}
.two{display:grid;grid-template-columns:1fr 1fr;gap:22px}.facets{display:grid;grid-template-columns:1fr 1fr;gap:6px 26px}
table{width:100%;border-collapse:collapse;font-size:12px;margin:6px 0 10px}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--soft);color:var(--navy);font-weight:600}.r{text-align:right;white-space:nowrap}
.mono,.mono-ish{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;word-break:break-all}.sub{color:var(--muted);font-size:11px}
.muted{color:var(--muted)}.bad{color:#d13212;font-weight:600}.note{margin:4px 0 8px;font-size:11.5px;color:var(--muted)}
.bl{list-style:none;margin:6px 0 0;padding:0}.bl li{margin:0 0 7px}.row{display:flex;justify-content:space-between;gap:10px;font-size:12.5px}
.bar{height:6px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:3px}.bar i{display:block;height:100%}
.stack{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--line);margin:6px 0 8px}.stack i{display:block}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.alertbox{border:1px solid #d13212;border-radius:10px;padding:4px 16px 8px;margin:14px 0;background:#fff8f6}
footer{padding:14px 36px 22px;color:var(--muted);font-size:11px;border-top:1px solid var(--line)}
${BRAND_CSS}
@media(max-width:760px){.two,.facets{grid-template-columns:1fr}main,.top,.page>.brand-head{padding-left:18px;padding-right:18px}table{display:block;overflow-x:auto}.page{margin:0;border-radius:0}}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;border-radius:0}.top{-webkit-print-color-adjust:exact;print-color-adjust:exact}section,.facet,.alertbox,tr{break-inside:avoid}}
</style></head><body><div class="page">
${renderBrandHeader(branding, defaultTitle, new Date(data.generatedAt))}
<div class="top"><div class="k">NetAnalyzer · AWS</div><h1>${esc(siteName)}</h1>
<p>Últimos ${esc(periodLabel(data.minutes))} · gerado em ${esc(when)}${data.accountId ? ` · conta ${esc(data.accountId)}` : ''}${data.region ? ` · ${esc(data.region)}` : ''}</p></div>
<main>
${body || '<p class="muted">Sem dados no período.</p>'}
</main>
<footer>Gerado pelo NetAnalyzer em ${esc(when)}. Credenciais encontradas nos logs nunca são armazenadas nem exibidas; só o tipo e o endpoint.</footer>
</div></body></html>`;
}
