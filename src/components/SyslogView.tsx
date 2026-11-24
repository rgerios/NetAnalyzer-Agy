import { Fragment, useEffect, useRef, useState } from 'react';
import {
  Download,
  Ban,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FileUp,
  Filter,
  Info,
  Loader2,
  RefreshCw,
  RotateCcw,
  Search,
  X,
} from 'lucide-react';
import type { FirewallVendor, SyslogEvent } from '../types.ts';
import { downloadCsv } from '../utils/csv.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';
import { VENDOR_THEMES } from '../utils/vendorTheme.ts';
import { IpConsumptionPanel } from './IpConsumptionPanel.tsx';
import { isPortFilterValid, PortFilterInput, PortsFetchPanel } from './PortsPanel.tsx';
import { UnrecognizedPanel } from './UnrecognizedPanel.tsx';

/** Rótulos dos detalhes extras que alguns logs (ALB) trazem. */
const META_LABELS: Record<string, string> = {
  accountId: 'Conta AWS', method: 'Método', host: 'Host', path: 'Caminho', pathGroup: 'Endpoint', hasQuery: 'Tem query string', status: 'Status (ALB)',
  targetStatus: 'Status (target)', userAgent: 'User-agent', uaFamily: 'Cliente', tlsVersion: 'TLS', tlsCipher: 'Cifra TLS',
  wafActions: 'Ações (WAF)', targetIp: 'IP do target', targetPort: 'Porta do target', targetGroup: 'Target group',
  elb: 'Load balancer', nodeIp: 'IP do nó do ALB', reqTime: 'Tempo da requisição (s)', targetTime: 'Tempo do target (s)',
  respTime: 'Tempo da resposta (s)', totalTime: 'Tempo total (s)', traceId: 'Trace ID', connTraceId: 'ID da conexão',
  rulePriority: 'Prioridade da regra', errorReason: 'Motivo do erro', redirectUrl: 'Redirecionamento',
  classification: 'Classificação', classificationReason: 'Motivo da classificação', listenerType: 'Protocolo do listener',
};

interface SyslogViewProps {
  vendor: FirewallVendor;
  refreshToken: number;
  onDataChanged: () => void;
  onAnalyzeEvent: (rawEventText: string) => void;
  pendingQuery?: string | null;
  onConsumePendingQuery?: () => void;
  /** AWS: restringe a lista a um recurso (ALB, VPC Flow Logs, WAF). */
  category?: string;
  /** Filtros próprios do recurso: ALB (método, endpoint, host, target group, IP do target, status) ou WAF (host, método, regra, Web ACL, ação). */
  eventFilters?: 'alb' | 'waf';
}

interface HttpFields {
  method: string;
  endpoint: string;
  host: string;
  targetGroup: string;
  targetIp: string;
  status: string;
  ruleId: string;
  webAcl: string;
  wafAction: string;
}
const EMPTY_HTTP: HttpFields = { method: '', endpoint: '', host: '', targetGroup: '', targetIp: '', status: '', ruleId: '', webAcl: '', wafAction: '' };
const HTTP_LABELS: Array<[keyof HttpFields, string]> = [
  ['method', 'Método'],
  ['endpoint', 'Endpoint'],
  ['host', 'Host'],
  ['targetGroup', 'Target group'],
  ['targetIp', 'IP do target'],
  ['status', 'Status HTTP'],
  ['ruleId', 'Rule ID'],
  ['webAcl', 'Web ACL'],
  ['wafAction', 'Ação do WAF'],
];
const trimHttp = (h: HttpFields): HttpFields => ({
  method: h.method.trim(),
  endpoint: h.endpoint.trim(),
  host: h.host.trim(),
  targetGroup: h.targetGroup.trim(),
  targetIp: h.targetIp.trim(),
  status: h.status.trim(),
  ruleId: h.ruleId.trim(),
  webAcl: h.webAcl.trim(),
  wafAction: h.wafAction.trim(),
});
const FIELD_CLS =
  'px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]';

export function SyslogView({
  vendor,
  refreshToken,
  onDataChanged,
  onAnalyzeEvent,
  pendingQuery,
  onConsumePendingQuery,
  category,
  eventFilters,
}: SyslogViewProps) {
  const httpFilters = !!eventFilters;
  const theme = VENDOR_THEMES[vendor];
  // No AWS os dados vêm das fontes S3/CloudWatch, não de syslog: o texto fala em "eventos"
  const isAws = vendor === 'aws';
  const [events, setEvents] = useState<SyslogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [matched, setMatched] = useState(0);
  const [matchedCapped, setMatchedCapped] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [query, setQuery] = useState('');
  const [srcIpFilter, setSrcIpFilter] = useState('');
  const [dstIpFilter, setDstIpFilter] = useState('');
  const [dstPortFilter, setDstPortFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [deviceFilter, setDeviceFilter] = useState('all');
  const [minutesFilter, setMinutesFilter] = useState('15');

  const [appliedFilters, setAppliedFilters] = useState({
    q: '',
    srcIp: '',
    dstIp: '',
    dstPort: '',
    action: 'all',
    severity: 'all',
    device: 'all',
    minutes: '15',
  });
  const scrollBoxRef = useRef<HTMLDivElement | null>(null);
  const [viewW, setViewW] = useState(0);
  const [httpForm, setHttpForm] = useState<HttpFields>(EMPTY_HTTP);
  const [httpApplied, setHttpApplied] = useState<HttpFields>(EMPTY_HTTP);
  const [devices, setDevices] = useState<Array<{ id: string; label: string }>>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const [showPasteBox, setShowPasteBox] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [ingesting, setIngesting] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  useEffect(() => {
    setExpandedId(null);
    setConfirmReset(false);
    setQuery('');
    setSrcIpFilter('');
    setDstIpFilter('');
    setDstPortFilter('');
    setActionFilter('all');
    setSeverityFilter('all');
    setDeviceFilter('all');
    setMinutesFilter('15');
    setAppliedFilters({
      q: '',
      srcIp: '',
      dstIp: '',
    dstPort: '',
      action: 'all',
      severity: 'all',
      device: 'all',
      minutes: '15',
    });
    setDevices([]);
    setHttpForm(EMPTY_HTTP);
    setHttpApplied(EMPTY_HTTP);
    setFeedback(null);
  }, [vendor]);

  useEffect(() => {
    if (pendingQuery) {
      setQuery(pendingQuery);
      setSrcIpFilter('');
      setDstIpFilter('');
    setDstPortFilter('');
      setActionFilter('all');
      setSeverityFilter('all');
      setDeviceFilter('all');
      setAppliedFilters((prev) => ({
        q: pendingQuery,
        srcIp: '',
        dstIp: '',
    dstPort: '',
        action: 'all',
        severity: 'all',
        device: 'all',
        minutes: prev.minutes,
      }));
      onConsumePendingQuery?.();
    }
  }, [pendingQuery, onConsumePendingQuery]);

  const PAGE_SIZE = 250;
  const [loadingMore, setLoadingMore] = useState(false);

  const fetchLogs = async (offset = 0, filters = appliedFilters, http = httpApplied) => {
    if (offset === 0) setLoading(true);
    else setLoadingMore(true);
    try {
      const params = new URLSearchParams({
        q: filters.q,
        srcIp: filters.srcIp,
        dstIp: filters.dstIp,
        dstPort: filters.dstPort,
        action: filters.action,
        severity: filters.severity,
        device: filters.device,
        minutes: filters.minutes,
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      if (category) params.set('category', category);
      if (httpFilters) for (const [k, v] of Object.entries(http)) if (v) params.set(k, v);
      const res = await fetch(vendorApiUrl(vendor, `/syslogs?${params.toString()}`));
      if (res.ok) {
        const data = await res.json();
        const page: SyslogEvent[] = data.events || [];
        setEvents((prev) => {
          if (offset === 0) return page;
          const known = new Set(prev.map((e) => e.id));
          return [...prev, ...page.filter((e) => !known.has(e.id))];
        });
        setTotal(data.total || 0);
        setMatched(data.matched || 0);
        setMatchedCapped(Boolean(data.matchedCapped));
        setSearchError(null);
        if (Array.isArray(data.devices)) {
          setDevices(data.devices);
        }
      } else {
        const data = (await res.json().catch(() => ({}))) as { error?: string };
        setSearchError(data.error || `A busca falhou (HTTP ${res.status}).`);
        if (offset === 0) {
          setEvents([]);
          setMatched(0);
          setMatchedCapped(false);
        }
      }
    } catch {
      setSearchError(isAws ? 'Não foi possível consultar os eventos. Verifique a conexão com o servidor.' : 'Não foi possível consultar os syslogs. Verifique a conexão com o servidor.');
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  useEffect(() => {
    void fetchLogs(0, appliedFilters, httpApplied);
  }, [vendor, appliedFilters, httpApplied, refreshToken]);

  useEffect(() => {
    const el = scrollBoxRef.current;
    if (!el) return;
    const measure = () => setViewW(el.clientWidth);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [events.length, loading]);

  /** Pedido de análise com o contexto certo da plataforma (a IA recebe também o contexto do ambiente). */
  const analysisPrompt = (ev: SyslogEvent): string => {
    if (isAws) {
      return `Explique este evento de log da AWS (${ev.categoryName}) em linguagem humana, avalie se há problema de desempenho, erro ou risco de segurança e indique o que verificar ou alterar na AWS:\n\n${ev.raw}`;
    }
    return `Explique este evento de syslog do ${theme.label} em linguagem humana, avalie se há risco e indique o que fazer:\n\n${ev.raw}`;
  };

  const handleApplyFilters = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!isPortFilterValid(dstPortFilter)) {
      setSearchError('Porta de destino inválida. Use números de 0 a 65535, listas (80,443) ou intervalos (8000-8100).');
      return;
    }
    if (httpFilters) setHttpApplied(trimHttp(httpForm));
    setAppliedFilters({
      q: query.trim(),
      srcIp: srcIpFilter.trim(),
      dstIp: dstIpFilter.trim(),
      dstPort: dstPortFilter.trim(),
      action: actionFilter,
      severity: severityFilter,
      device: deviceFilter,
      minutes: minutesFilter,
    });
  };

  const handleClearFilters = () => {
    setHttpForm(EMPTY_HTTP);
    setHttpApplied(EMPTY_HTTP);
    setQuery('');
    setSrcIpFilter('');
    setDstIpFilter('');
    setDstPortFilter('');
    setActionFilter('all');
    setSeverityFilter('all');
    setDeviceFilter('all');
    setMinutesFilter('15');
    setAppliedFilters({
      q: '',
      srcIp: '',
      dstIp: '',
    dstPort: '',
      action: 'all',
      severity: 'all',
      device: 'all',
      minutes: '15',
    });
  };

  const hasPendingFilterChanges =
    (!!httpFilters && JSON.stringify(trimHttp(httpForm)) !== JSON.stringify(httpApplied)) ||
    query.trim() !== appliedFilters.q ||
    srcIpFilter.trim() !== appliedFilters.srcIp ||
    dstIpFilter.trim() !== appliedFilters.dstIp ||
    dstPortFilter.trim() !== appliedFilters.dstPort ||
    actionFilter !== appliedFilters.action ||
    severityFilter !== appliedFilters.severity ||
    deviceFilter !== appliedFilters.device ||
    minutesFilter !== appliedFilters.minutes;

  const periodLabel = (m: string) => {
    if (m === '15') return 'Últimos 15 min';
    if (m === '30') return 'Últimos 30 min';
    if (m === '60') return 'Última 1 hora';
    if (m === '360') return 'Últimas 6 horas';
    if (m === '1440') return 'Últimas 24 horas';
    return 'Todo o histórico';
  };

  const activeFilterChips: string[] = [`Período: ${periodLabel(appliedFilters.minutes)}`];
  if (appliedFilters.q) activeFilterChips.push(`Busca: "${appliedFilters.q}"`);
  if (appliedFilters.srcIp) activeFilterChips.push(`Origem: ${appliedFilters.srcIp}`);
  if (appliedFilters.dstIp) activeFilterChips.push(`Destino: ${appliedFilters.dstIp}`);
  if (appliedFilters.dstPort) activeFilterChips.push(`Porta destino: ${appliedFilters.dstPort}`);
  if (httpFilters) {
    for (const [k, label] of HTTP_LABELS) if (httpApplied[k]) activeFilterChips.push(`${label}: ${httpApplied[k]}`);
  }
  if (appliedFilters.action !== 'all') {
    const actionLabel =
      appliedFilters.action === 'allow'
        ? 'Permitidos'
        : appliedFilters.action === 'blocked'
          ? 'Bloqueados'
          : 'Sistema';
    activeFilterChips.push(`Ação: ${actionLabel}`);
  }
  if (appliedFilters.severity !== 'all') activeFilterChips.push(`Severidade: ${appliedFilters.severity}`);
  if (appliedFilters.device !== 'all') activeFilterChips.push(`Device: ${appliedFilters.device}`);

  const handleFileUpload = async (file: File | undefined) => {
    if (!file) return;
    setIngesting(true);
    setFeedback(null);
    try {
      const content = await file.text();
      const res = await fetch(vendorApiUrl(vendor, '/syslogs/ingest'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, source: 'upload' }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFeedback({ type: 'err', text: data.error || 'Falha ao importar arquivo de syslog.' });
      } else {
        setFeedback({
          type: 'ok',
          text: `${data.added.toLocaleString('pt-BR')} eventos importados de ${file.name}.`,
        });
        onDataChanged();
        await fetchLogs();
      }
    } catch {
      setFeedback({ type: 'err', text: 'Erro de rede ao enviar syslogs.' });
    } finally {
      setIngesting(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!pasteText.trim()) return;
    setIngesting(true);
    setFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/syslogs/ingest'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: pasteText, source: 'paste' }),
      });
      const data = await res.json();
      if (!res.ok) {
        setFeedback({ type: 'err', text: data.error || 'Falha ao processar linhas coladas.' });
      } else {
        setFeedback({
          type: 'ok',
          text: `${data.added.toLocaleString('pt-BR')} linhas de syslog analisadas.`,
        });
        setPasteText('');
        setShowPasteBox(false);
        onDataChanged();
        await fetchLogs();
      }
    } finally {
      setIngesting(false);
    }
  };

  const handleClearLogs = async () => {
    setClearing(true);
    setFeedback(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/syslogs'), { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setFeedback({
          type: 'err',
          text: (data as { error?: string }).error || 'Falha ao resetar syslogs.',
        });
        return;
      }
      setConfirmReset(false);
      setExpandedId(null);
      setEvents([]);
      setTotal(0);
      setMatched(0);
      setFeedback({
        type: 'ok',
        text: 'Syslogs, alertas, métricas e contadores de uso foram zerados. A análise recomeça a partir de agora.',
      });
      onDataChanged();
      await fetchLogs(0);
    } catch {
      setFeedback({ type: 'err', text: 'Erro de rede ao resetar syslogs.' });
    } finally {
      setClearing(false);
    }
  };

  const renderActionLabel = (action: SyslogEvent['action']) => {
    if (action === 'allow') {
      return (
        <span className="inline-flex items-center gap-1.5 text-emerald-800 font-medium">
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> Permitido
        </span>
      );
    }
    if (action === 'drop' || action === 'deny' || action === 'reset') {
      return (
        <span className="inline-flex items-center gap-1.5 text-red-700 font-medium">
          <Ban className="w-3.5 h-3.5 shrink-0" /> {action === 'deny' ? 'Negado' : 'Drop'}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-[var(--fw-text-muted)] font-medium">
        <Info className="w-3.5 h-3.5 shrink-0" /> Sistema
      </span>
    );
  };

  const pastePlaceholder =
    vendor === 'aws'
      ? '2 123456789012 eni-0a1b2c3d4e5f60718 10.0.1.25 142.250.219.14 51234 443 6 12 4800 1763909940 1763910000 ACCEPT OK'
      : vendor === 'fortigate'
      ? '<189>date=2026-11-13 time=10:05:11 devname="FGT100F-MATRIZ" devid="FG100FTK21004512" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.20.1.50 srcport=55120 srcintf="port1" dstip=8.8.8.8 dstport=53 dstintf="wan1" proto=17 policyid=12 policyname="LAN-to-WAN-DNS" action="accept" sentbyte=142 rcvdbyte=290 msg="Allowed"'
      : '<134>id=firewall sn=2CB8ED549A10 time="2026-11-13 10:05:11" fw=192.168.10.1 pri=6 c=1024 m=537 msg="Connection Closed" src=10.20.1.50:55120:X0 dst=8.8.8.8:53:X1 proto=udp/dns fw_action="allow"';

  return (
    <div className="space-y-4">
      {!eventFilters && (
      <>
      <IpConsumptionPanel
        vendor={vendor}
        refreshToken={refreshToken}
        onFilterSyslogsByIp={(ip) => {
          setQuery(ip);
          setSrcIpFilter('');
          setDstIpFilter('');
    setDstPortFilter('');
          setActionFilter('all');
          setSeverityFilter('all');
          setDeviceFilter('all');
          setAppliedFilters((prev) => ({
            q: ip,
            srcIp: '',
            dstIp: '',
    dstPort: '',
            action: 'all',
            severity: 'all',
            device: 'all',
            minutes: prev.minutes,
          }));
        }}
      />

      <PortsFetchPanel
        vendor={vendor}
        minutes={Number(appliedFilters.minutes) || 0}
        refreshToken={refreshToken}
        selected={appliedFilters.dstPort}
        onSelect={(port) => {
          setDstPortFilter(port);
          setAppliedFilters((prev) => ({ ...prev, dstPort: port }));
        }}
      />

      </>
      )}

      <UnrecognizedPanel vendor={vendor} refreshToken={refreshToken} />

      <form
        onSubmit={handleApplyFilters}
        className="bg-white border border-[var(--fw-border)] rounded-lg p-4 space-y-3"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="w-4 h-4 text-[var(--fw-text-subtle)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Busca geral (porta, regra, mensagem...)"
              className="w-full pl-9 pr-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
            />
          </div>

          <input
            type="text"
            value={srcIpFilter}
            onChange={(e) => setSrcIpFilter(e.target.value)}
            placeholder="IP Origem (ex: 10.20.4.45)"
            aria-label="Filtrar por IP de origem"
            className="w-44 px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />

          {eventFilters === 'alb' ? (
            <>
              <input
                type="text"
                value={httpForm.targetIp}
                onChange={(e) => setHttpForm({ ...httpForm, targetIp: e.target.value })}
                placeholder="IP do target (destino)"
                aria-label="Filtrar por IP do target"
                className={`w-44 font-mono ${FIELD_CLS}`}
              />
              <input
                type="text"
                value={httpForm.host}
                onChange={(e) => setHttpForm({ ...httpForm, host: e.target.value })}
                placeholder="Host (ex: api.empresa.com)"
                aria-label="Filtrar por host"
                className={`w-52 font-mono ${FIELD_CLS}`}
              />
              <input
                type="text"
                value={httpForm.targetGroup}
                onChange={(e) => setHttpForm({ ...httpForm, targetGroup: e.target.value })}
                placeholder="Target group"
                aria-label="Filtrar por target group"
                className={`w-44 font-mono ${FIELD_CLS}`}
              />
              <input
                type="text"
                value={httpForm.endpoint}
                onChange={(e) => setHttpForm({ ...httpForm, endpoint: e.target.value })}
                placeholder="Endpoint (ex: /api/pedidos)"
                aria-label="Filtrar por endpoint"
                className={`w-56 font-mono ${FIELD_CLS}`}
              />
              <select
                value={httpForm.method}
                onChange={(e) => setHttpForm({ ...httpForm, method: e.target.value })}
                aria-label="Filtrar por método HTTP"
                className={FIELD_CLS}
              >
                <option value="">Todos os métodos</option>
                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
              <input
                type="text"
                list="alb-status-codes"
                value={httpForm.status}
                onChange={(e) => setHttpForm({ ...httpForm, status: e.target.value })}
                placeholder="Status (ex: 502 ou 5xx)"
                aria-label="Filtrar por status HTTP"
                className={`w-44 font-mono ${FIELD_CLS}`}
              />
              <datalist id="alb-status-codes">
                {['2xx', '3xx', '4xx', '5xx', '200', '201', '204', '301', '302', '304', '400', '401', '403', '404', '429', '500', '502', '503', '504'].map((c) => (
                  <option key={c} value={c} />
                ))}
              </datalist>
            </>
          ) : eventFilters === 'waf' ? (
            <>
              <input
                type="text"
                value={httpForm.host}
                onChange={(e) => setHttpForm({ ...httpForm, host: e.target.value })}
                placeholder="Host (ex: api.empresa.com)"
                aria-label="Filtrar por host"
                className={`w-52 font-mono ${FIELD_CLS}`}
              />
              <input
                type="text"
                value={httpForm.endpoint}
                onChange={(e) => setHttpForm({ ...httpForm, endpoint: e.target.value })}
                placeholder="URI (ex: /api/login)"
                aria-label="Filtrar por URI"
                className={`w-52 font-mono ${FIELD_CLS}`}
              />
              <select
                value={httpForm.method}
                onChange={(e) => setHttpForm({ ...httpForm, method: e.target.value })}
                aria-label="Filtrar por método HTTP"
                className={FIELD_CLS}
              >
                <option value="">Todos os métodos</option>
                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={httpForm.ruleId}
                onChange={(e) => setHttpForm({ ...httpForm, ruleId: e.target.value })}
                placeholder="Rule ID (ex: AWSManagedRules…)"
                aria-label="Filtrar por Rule ID"
                className={`w-60 font-mono ${FIELD_CLS}`}
              />
              <input
                type="text"
                value={httpForm.webAcl}
                onChange={(e) => setHttpForm({ ...httpForm, webAcl: e.target.value })}
                placeholder="Web ACL"
                aria-label="Filtrar por Web ACL"
                className={`w-44 font-mono ${FIELD_CLS}`}
              />
              <select
                value={httpForm.wafAction}
                onChange={(e) => setHttpForm({ ...httpForm, wafAction: e.target.value })}
                aria-label="Filtrar por ação do WAF"
                className={FIELD_CLS}
              >
                <option value="">ALLOW e BLOCK</option>
                <option value="ALLOW">ALLOW (permitido)</option>
                <option value="BLOCK">BLOCK (bloqueado)</option>
                <option value="COUNT">COUNT</option>
                <option value="CAPTCHA">CAPTCHA</option>
                <option value="CHALLENGE">CHALLENGE</option>
              </select>
            </>
          ) : (
            <>
          <input
            type="text"
            value={dstIpFilter}
            onChange={(e) => setDstIpFilter(e.target.value)}
            placeholder="IP Destino (ex: 8.8.8.8)"
            aria-label="Filtrar por IP de destino"
            className="w-44 px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />

              <PortFilterInput value={dstPortFilter} onChange={setDstPortFilter} className="w-60" />
            </>
          )}

          {eventFilters !== 'waf' && (
          <div className="flex items-center gap-1 p-1 bg-[var(--fw-surface-alt)] rounded-md">
            {[
              { id: 'all', label: 'Todos' },
              { id: 'allow', label: 'Permitidos' },
              { id: 'blocked', label: 'Bloqueados' },
              { id: 'system', label: 'Sistema' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActionFilter(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
                  actionFilter === tab.id
                    ? 'bg-white text-[var(--fw-heading)] shadow-xs'
                    : 'text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
          )}

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Filtrar por severidade"
            className="px-3 py-2 text-xs border border-[var(--fw-border-strong)] rounded-md bg-white text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          >
            <option value="all">Todas severidades</option>
            <option value="critical">Crítico</option>
            <option value="error">Erro</option>
            <option value="warning">Alerta</option>
            <option value="notice">Notice</option>
            <option value="info">Info</option>
          </select>

          <select
            value={deviceFilter}
            onChange={(e) => setDeviceFilter(e.target.value)}
            aria-label="Filtrar por device"
            className="px-3 py-2 text-xs font-mono border border-[var(--fw-border-strong)] rounded-md bg-white text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)] max-w-[210px]"
          >
            <option value="all">Todos os devices</option>
            {devices.map((dev) => (
              <option key={dev.id} value={dev.id}>
                {dev.label}
              </option>
            ))}
          </select>

          <select
            value={minutesFilter}
            onChange={(e) => setMinutesFilter(e.target.value)}
            aria-label="Filtrar por período"
            className="px-3 py-2 text-xs font-medium border border-[var(--fw-border-strong)] rounded-md bg-white text-[var(--fw-text-body)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          >
            <option value="15">Últimos 15 min</option>
            <option value="30">Últimos 30 min</option>
            <option value="60">Última 1 hora</option>
            <option value="360">Últimas 6 horas</option>
            <option value="1440">Últimas 24 horas</option>
            <option value="0">Todo o histórico</option>
          </select>

          <button
            type="submit"
            disabled={loading}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-white rounded-md transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap ${
              hasPendingFilterChanges
                ? 'bg-[var(--fw-accent)] hover:bg-[var(--fw-accent-hover)] ring-2 ring-[var(--fw-accent-mid)]/40'
                : 'bg-[var(--fw-accent)] hover:bg-[var(--fw-accent-hover)]'
            }`}
          >
            <Filter className="w-3.5 h-3.5" />
            Aplicar Filtro
          </button>

          {(activeFilterChips.length > 0 || hasPendingFilterChanges) && (
            <button
              type="button"
              onClick={handleClearFilters}
              className="inline-flex items-center gap-1 px-2.5 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] cursor-pointer whitespace-nowrap"
            >
              <X className="w-3.5 h-3.5" />
              Limpar
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--fw-border-soft)]">
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <span className="text-[var(--fw-text-muted)] font-medium">Filtrando por:</span>
            {activeFilterChips.length === 0 ? (
              <span className="px-2 py-0.5 rounded bg-[var(--fw-surface)] text-[var(--fw-text-body)]">
                Sem filtro (exibindo logs mais recentes)
              </span>
            ) : (
              activeFilterChips.map((chip) => (
                <span
                  key={chip}
                  className="px-2 py-0.5 rounded bg-[var(--fw-surface-chip)] text-[var(--fw-heading)] font-mono font-medium"
                >
                  {chip}
                </span>
              ))
            )}
            {hasPendingFilterChanges && (
              <span className="text-amber-800 font-medium ml-1">
                (alterações pendentes — clique em Aplicar Filtro)
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
          {!isAws && (
            <>
          <label className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] cursor-pointer whitespace-nowrap">
            <FileUp className="w-3.5 h-3.5" />
            Importar .log/.txt
            <input
              type="file"
              accept=".log,.txt,.syslog"
              className="hidden"
              onChange={(e) => void handleFileUpload(e.target.files?.[0])}
            />
          </label>
          <button
            type="button"
            onClick={() => setShowPasteBox((v) => !v)}
            className="px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] whitespace-nowrap"
          >
            Colar Logs
          </button>
            </>
          )}
          <button
            type="button"
            onClick={() =>
              downloadCsv(
                isAws ? `${vendor}-eventos.csv` : `${vendor}-syslogs.csv`,
                ['Data', 'Dispositivo', 'Severidade', 'Acao', 'Origem', 'Porta_Origem', 'Zona_Origem', 'Destino', 'Porta_Destino', 'Zona_Destino', 'Protocolo', 'Regra', 'Usuario', 'Bytes_Enviados', 'Bytes_Recebidos', 'Mensagem'],
                events.map((ev) => [ev.timestamp, ev.firewallHost, ev.severity, ev.action, ev.srcIp, ev.srcPort, ev.srcZone, ev.dstIp, ev.dstPort, ev.dstZone, ev.protocol, ev.ruleRef, ev.user, ev.bytesSent, ev.bytesRcvd, ev.message])
              )
            }
            disabled={events.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)] disabled:opacity-40 whitespace-nowrap"
            title="Exporta os logs atualmente carregados na tela (respeita os filtros)"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </button>
          <button
            type="button"
            onClick={() => void fetchLogs()}
            className="p-2 text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-surface)]"
            title="Atualizar"
            aria-label={isAws ? 'Atualizar lista de eventos' : 'Atualizar lista de syslogs'}
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          {!confirmReset && !category && (
            <button
              type="button"
              onClick={() => setConfirmReset(true)}
              disabled={clearing || total === 0}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-red-700 bg-white border border-red-200 rounded-md hover:bg-red-50 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
              title={
                total === 0
                  ? 'Nenhum syslog armazenado para limpar'
                  : 'Limpar todos os syslogs recebidos e começar do zero'
              }
              aria-label="Resetar todos os syslogs"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Resetar Syslogs
            </button>
          )}
          {confirmReset && (
            <div className="inline-flex items-center gap-1.5 bg-red-50 border border-red-200 rounded-md px-2.5 py-1">
              <span className="text-[11px] font-medium text-red-800">
                Apagar {total.toLocaleString('pt-BR')} log(s), alertas e métricas?
              </span>
              <button
                type="button"
                onClick={() => void handleClearLogs()}
                disabled={clearing}
                className="px-2.5 py-1 text-[11px] font-semibold text-white bg-red-600 rounded hover:bg-red-700 cursor-pointer disabled:opacity-50"
              >
                {clearing ? 'Resetando...' : 'Confirmar'}
              </button>
              <button
                type="button"
                onClick={() => setConfirmReset(false)}
                disabled={clearing}
                className="px-2 py-1 text-[11px] font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded hover:bg-[var(--fw-bg)] cursor-pointer disabled:opacity-50"
              >
                Cancelar
              </button>
            </div>
          )}
        </div>
        </div>
      </form>

      {feedback && (
        <div
          className={`px-4 py-3 rounded-md border text-xs ${
            feedback.type === 'ok'
              ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
              : 'bg-red-50 border-red-200 text-red-800'
          }`}
        >
          {feedback.text}
        </div>
      )}

      {showPasteBox && (
        <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-[var(--fw-heading)]">
              Cole linhas brutas do rsyslog ou exportação {theme.label} (
              <span className="font-mono">
                {vendor === 'fortigate' ? 'date=... devname=... srcip=...' : 'id=firewall ...'}
              </span>
              )
            </p>
            <button
              type="button"
              onClick={() => setShowPasteBox(false)}
              className="text-xs text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]"
            >
              Fechar
            </button>
          </div>
          <textarea
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            rows={5}
            placeholder={pastePlaceholder}
            className="w-full p-3 font-mono text-xs border border-[var(--fw-border-strong)] rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]"
          />
          <div className="flex justify-end">
            <button
              type="button"
              disabled={ingesting || !pasteText.trim()}
              onClick={() => void handlePasteSubmit()}
              className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)] disabled:opacity-50"
            >
              {ingesting ? 'Processando...' : 'Analisar Linhas'}
            </button>
          </div>
        </div>
      )}

      <div className="bg-white border border-[var(--fw-border)] rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[var(--fw-border)] bg-[var(--fw-surface)] flex items-center justify-between text-xs text-[var(--fw-text-body)]">
          <span className="tabular-nums">
            Exibindo {events.length.toLocaleString('pt-BR')} de{' '}
            {matched.toLocaleString('pt-BR')}
            {matchedCapped ? '+' : ''} correspondências ({total.toLocaleString('pt-BR')} total)
          </span>
          <span>Expurgo automático ativo · Porta UDP :{theme.defaultUdpPort} · Clique para expandir</span>
        </div>

        {searchError && (
          <div role="alert" className="mx-4 mt-3 p-3 rounded-md border border-red-200 bg-red-50 text-xs text-red-800">
            {searchError}
          </div>
        )}
        {matchedCapped && !loading && (
          <div className="mx-4 mt-3 p-3 rounded-md border border-amber-300 bg-amber-50 text-xs text-amber-900">
            Mais de {matched.toLocaleString('pt-BR')} correspondências: o painel mostra as mais recentes. Restrinja o
            período ou os filtros para ver o restante.
          </div>
        )}

        {loading ? (
          <div className="p-8 space-y-4">
            <div className="flex items-center justify-center gap-3 text-sm font-medium text-[var(--fw-heading)]">
              <Loader2 className="w-5 h-5 animate-spin text-[var(--fw-accent)]" />
              <span>
                {isAws ? 'Carregando eventos' : `Carregando syslogs ${theme.label}`}
                {activeFilterChips.length > 0 ? ' com os filtros aplicados...' : '...'}
              </span>
            </div>
            <p className="text-center text-xs text-[var(--fw-text-muted)]">
              Consultando registros armazenados ({total.toLocaleString('pt-BR')} eventos no total). Aguarde...
            </p>
            <div className="space-y-2 animate-pulse max-w-4xl mx-auto">
              {[1, 2, 3, 4, 5].map((n) => (
                <div key={n} className="h-9 bg-[var(--fw-surface)] rounded" />
              ))}
            </div>
          </div>
        ) : events.length === 0 && searchError ? null : events.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm font-medium text-[var(--fw-heading)]">
              {isAws ? 'Nenhum evento encontrado' : `Nenhum evento de syslog ${theme.label} encontrado`}
            </p>
            {isAws ? (
              <p className="text-xs text-[var(--fw-text-muted)] mt-1">
                Os eventos chegam das fontes configuradas em Contas &amp; Fontes. Confira a origem, o tipo de log e o período selecionado.
              </p>
            ) : (
            <p className="text-xs text-[var(--fw-text-muted)] mt-1">
              Importe um arquivo de log (<span className="font-mono">/var/log/{vendor}.log</span>),
              cole linhas acima ou inicie o receptor UDP na porta{' '}
              <span className="font-mono">{theme.defaultUdpPort}</span>.
            </p>
            )}
          </div>
        ) : (
          <>
          <div ref={scrollBoxRef} className="overflow-auto max-h-[70vh]" tabIndex={0} aria-label="Lista de eventos (role para ver a mensagem completa)">
            <table className="w-full text-xs">
              <thead className="sticky top-0 z-10">
                <tr className="border-b border-[var(--fw-border)] text-[var(--fw-text-muted)] bg-[var(--fw-bg)]">
                  <th className="py-2.5 pl-4 pr-2 text-left font-medium w-8" />
                  <th className="py-2.5 px-3 text-left font-medium">Data / Hora</th>
                  <th className="py-2.5 px-3 text-left font-medium">Device</th>
                  <th className="py-2.5 px-3 text-left font-medium">Ação</th>
                  <th className="py-2.5 px-3 text-left font-medium">Origem</th>
                  <th className="py-2.5 px-3 text-left font-medium">Destino</th>
                  <th className="py-2.5 px-3 text-left font-medium">Proto / Porta</th>
                  <th className="py-2.5 px-3 text-left font-medium">Regra / NAT</th>
                  <th className="py-2.5 px-4 text-left font-medium">Mensagem</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--fw-border-soft)]">
                {events.map((ev) => {
                  const isOpen = expandedId === ev.id;
                  return (
                    <Fragment key={ev.id}>
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : ev.id)}
                        className="hover:bg-[var(--fw-bg)] cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 pl-4 pr-2 text-[var(--fw-text-subtle)]">
                          {isOpen ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-text-muted)] whitespace-nowrap tabular-nums">
                          {ev.timestamp}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-heading)] whitespace-nowrap">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              const id =
                                (ev.firewallHost && ev.firewallHost !== '-' ? ev.firewallHost : '') ||
                                (ev.serialNumber && ev.serialNumber !== '-' ? ev.serialNumber : '');
                              if (id) {
                                const nextDevice = appliedFilters.device === id ? 'all' : id;
                                setDeviceFilter(nextDevice);
                                setAppliedFilters((prev) => ({ ...prev, device: nextDevice }));
                              }
                            }}
                            title="Clique para filtrar apenas este device"
                            className="text-left hover:underline cursor-pointer"
                          >
                            {ev.firewallHost && ev.firewallHost !== '-'
                              ? ev.firewallHost
                              : ev.serialNumber || '-'}
                          </button>
                          {ev.serialNumber &&
                            ev.serialNumber !== '-' &&
                            ev.firewallHost !== ev.serialNumber && (
                              <span className="block text-[10px] text-[var(--fw-text-subtle)]">
                                {ev.serialNumber}
                              </span>
                            )}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">{renderActionLabel(ev.action)}</td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-heading)] whitespace-nowrap">
                          {ev.srcIp}
                          {ev.srcPort ? `:${ev.srcPort}` : ''}
                          {ev.srcZone !== '-' && (
                            <span className="text-[var(--fw-text-subtle)] ml-1">({ev.srcZone})</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-heading)] whitespace-nowrap">
                          {ev.dstIp}
                          {ev.dstPort ? `:${ev.dstPort}` : ''}
                          {ev.dstZone !== '-' && (
                            <span className="text-[var(--fw-text-subtle)] ml-1">({ev.dstZone})</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-text-body)] whitespace-nowrap">
                          {ev.protocol}
                          {ev.dstPort !== null ? `/${ev.dstPort}` : ''}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[var(--fw-text-muted)] whitespace-nowrap">
                          {ev.ruleRef || '-'}
                          {ev.natRuleRef ? ` · ${ev.natRuleRef}` : ''}
                        </td>
                        <td className="py-2.5 px-4 text-[var(--fw-text-body)] whitespace-nowrap">
                          {ev.message}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-[var(--fw-bg)]">
                          <td colSpan={9} className="p-0 border-t border-[var(--fw-border)]">
                            <div className="sticky left-0 px-6 py-4" style={viewW ? { width: viewW } : undefined}>
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                              <span className="text-xs font-semibold text-[var(--fw-heading)]">Detalhes do evento</span>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onAnalyzeEvent(analysisPrompt(ev));
                                }}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
                              >
                                <Bot className="w-3.5 h-3.5" />
                                Analisar este evento com IA
                              </button>
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs mb-3">
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Device:</span>{' '}
                                <span className="font-mono text-[var(--fw-heading)] font-medium">
                                  {ev.firewallHost || '-'}
                                  {ev.serialNumber && ev.serialNumber !== '-'
                                    ? ` (${ev.serialNumber})`
                                    : ''}
                                </span>
                              </div>
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Categoria:</span>{' '}
                                <span className="text-[var(--fw-heading)] font-medium">
                                  {ev.categoryName}
                                </span>
                              </div>
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Severidade:</span>{' '}
                                <span className="font-mono text-[var(--fw-heading)]">
                                  {ev.severity} (pri {ev.priority})
                                </span>
                              </div>
                              <div>
                                <span className="text-[var(--fw-text-muted)]">Bytes Env/Rec:</span>{' '}
                                <span className="font-mono tabular-nums text-[var(--fw-heading)]">
                                  {ev.bytesSent.toLocaleString('pt-BR')} /{' '}
                                  {ev.bytesRcvd.toLocaleString('pt-BR')}
                                </span>
                              </div>
                              <div>
                                <span className="text-[var(--fw-text-muted)]">NAT Traduzido:</span>{' '}
                                <span className="font-mono text-[var(--fw-heading)]">
                                  {ev.natSrcIp || ev.natDstIp || 'Nenhum'}
                                </span>
                              </div>
                            </div>
                            {ev.meta && Object.keys(ev.meta).length > 0 && (
                              <dl className="mb-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-1 text-[11px]">
                                {Object.entries(ev.meta).map(([k, v]) => (
                                  <div key={k} className="flex gap-2 min-w-0">
                                    <dt className="text-[var(--fw-text-muted)] shrink-0">{META_LABELS[k] ?? k}:</dt>
                                    <dd className="font-mono text-[var(--fw-heading)] break-all">{String(v)}</dd>
                                  </div>
                                ))}
                              </dl>
                            )}
                            <pre className="p-3 bg-[var(--fw-terminal-bg)] text-[var(--fw-terminal-text)] rounded-md font-mono text-[11px] overflow-x-auto whitespace-pre-wrap break-all">
                              {ev.raw}
                            </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div>
            {events.length < matched && (
              <div className="px-4 py-3 border-t border-[var(--fw-border)] flex justify-center">
                <button
                  type="button"
                  disabled={loadingMore}
                  onClick={() => void fetchLogs(events.length)}
                  className="px-4 py-1.5 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)] disabled:opacity-50"
                >
                  {loadingMore
                    ? 'Carregando...'
                    : `Carregar mais ${Math.min(PAGE_SIZE, matched - events.length).toLocaleString('pt-BR')} (restam ${(matched - events.length).toLocaleString('pt-BR')})`}
                </button>
              </div>
            )}
          </div>
          </>
        )}
      </div>
    </div>
  );
}
