import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  FileSearch,
  Info,
  Loader2,
  Trash2,
  Upload,
  X,
  XCircle,
} from 'lucide-react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type {
  FirewallVendor,
  PcapConversation,
  PcapFileInfo,
  PcapFinding,
  PcapPacketDetail,
  PcapPacketRow,
  PcapPacketsPage,
  PcapSessionInfo,
  PcapStreamView,
  PcapSummary,
  PcapUploadResult,
} from '../types.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface PcapViewProps {
  vendor: FirewallVendor;
}

type Tab = 'packets' | 'diagnostic' | 'conversations' | 'endpoints';

interface FilterExample {
  label: string;
  filter: string;
  hint: string;
}

interface HelpInfo {
  examples: FilterExample[];
  fields: string[];
  maxFileMb: number;
}

const PAGE = 300;
const ROW_H = 24;

const PROTO_BG: Record<string, string> = {
  DNS: 'rgba(14,165,233,0.10)',
  MDNS: 'rgba(14,165,233,0.10)',
  HTTP: 'rgba(34,197,94,0.12)',
  TLS: 'rgba(139,92,246,0.11)',
  SSH: 'rgba(139,92,246,0.11)',
  ICMP: 'rgba(236,72,153,0.11)',
  ICMPv6: 'rgba(236,72,153,0.11)',
  ARP: 'rgba(234,179,8,0.14)',
  UDP: 'rgba(59,130,246,0.07)',
  QUIC: 'rgba(59,130,246,0.10)',
};

function rowBackground(r: PcapPacketRow): string | undefined {
  if (r.sev === 'error') return 'rgba(239,68,68,0.18)';
  if (r.sev === 'warn') return 'rgba(245,158,11,0.18)';
  return PROTO_BG[r.proto];
}

function fmtTime(t: number): string {
  return t.toFixed(6);
}

function fmtDuration(sec: number): string {
  if (sec < 1) return `${(sec * 1000).toFixed(0)} ms`;
  if (sec < 120) return `${sec.toFixed(1)} s`;
  if (sec < 7200) return `${Math.floor(sec / 60)} min ${Math.round(sec % 60)} s`;
  return `${Math.floor(sec / 3600)} h ${Math.round((sec % 3600) / 60)} min`;
}

function fmtRate(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} kbps`;
  return `${bps.toFixed(0)} bps`;
}

function sevStyle(sev: PcapFinding['severity']): { bg: string; fg: string; label: string } {
  if (sev === 'critical') return { bg: 'rgba(239,68,68,0.12)', fg: '#dc2626', label: 'Crítico' };
  if (sev === 'warning') return { bg: 'rgba(245,158,11,0.15)', fg: '#b45309', label: 'Atenção' };
  return { bg: 'rgba(59,130,246,0.12)', fg: '#2563eb', label: 'Info' };
}

interface ApiError {
  error?: string;
  code?: string;
  pos?: number;
}

class ApiFailure extends Error {
  code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.code = code;
  }
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  const body = (await res.json().catch(() => ({}))) as T & ApiError;
  if (!res.ok) throw new ApiFailure(body.error || `Erro ${res.status}`, body.code);
  return body;
}

function uploadFile(url: string, file: File, onProgress: (pct: number) => void): Promise<PcapUploadResult> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    xhr.setRequestHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onerror = () => reject(new ApiFailure('Falha de rede no envio do arquivo.'));
    xhr.onload = () => {
      let body: (PcapUploadResult & ApiError) | null = null;
      try {
        body = JSON.parse(xhr.responseText) as PcapUploadResult & ApiError;
      } catch {
        body = null;
      }
      if (xhr.status >= 200 && xhr.status < 300 && body) resolve(body);
      else if (xhr.status === 413) reject(new ApiFailure('O arquivo excede o limite de upload do servidor.'));
      else reject(new ApiFailure(body?.error || `Erro ${xhr.status} ao enviar o arquivo.`, body?.code));
    };
    xhr.send(file);
  });
}

// ---------------------------------------------------------------------------

export function PcapView({ vendor }: PcapViewProps) {
  const [help, setHelp] = useState<HelpInfo | null>(null);
  const [session, setSession] = useState<PcapSessionInfo | null>(null);
  const [uploading, setUploading] = useState<{ name: string; pct: number; index: number; total: number } | null>(null);
  const [notice, setNotice] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const [tab, setTab] = useState<Tab>('packets');
  const [filterText, setFilterText] = useState('');
  const [applied, setApplied] = useState('');
  const [filterError, setFilterError] = useState<string | null>(null);
  const [showExamples, setShowExamples] = useState(false);

  const [rows, setRows] = useState<PcapPacketRow[]>([]);
  const [matched, setMatched] = useState(0);
  const [loadingRows, setLoadingRows] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<PcapPacketDetail | null>(null);

  const [summary, setSummary] = useState<PcapSummary | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [stream, setStream] = useState<PcapStreamView | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const reqSeq = useRef(0);

  const api = useCallback((path: string) => vendorApiUrl(vendor, path), [vendor]);

  useEffect(() => {
    let alive = true;
    getJson<HelpInfo>(api('/pcap/help'))
      .then((h) => alive && setHelp(h))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [api]);

  const handleSelectPacket = useCallback((no: number) => setSelected(no), []);

  const resetView = () => {
    setRows([]);
    setMatched(0);
    setSelected(null);
    setDetail(null);
    setSummary(null);
    setStream(null);
  };

  const handleExpired = (err: unknown) => {
    if (err instanceof ApiFailure && err.code === 'expired') {
      setSession(null);
      resetView();
    }
  };

  // ----- carga dos pacotes -----
  const loadRows = useCallback(
    async (sess: PcapSessionInfo, filter: string, offset: number) => {
      const seq = ++reqSeq.current;
      setLoadingRows(true);
      try {
        const qs = new URLSearchParams({ filter, offset: String(offset), limit: String(PAGE) });
        const page = await getJson<PcapPacketsPage>(api(`/pcap/sessions/${sess.id}/packets?${qs}`));
        if (seq !== reqSeq.current) return;
        setFilterError(null);
        setMatched(page.matched);
        setRows((prev) => (offset === 0 ? page.rows : [...prev, ...page.rows]));
        if (offset === 0) {
          setApplied(filter);
          scrollRef.current?.scrollTo({ top: 0 });
        }
      } catch (err) {
        if (seq !== reqSeq.current) return;
        if (err instanceof ApiFailure && err.code === 'filter') setFilterError(err.message);
        else {
          handleExpired(err);
          setNotice({ type: 'err', text: err instanceof Error ? err.message : 'Falha ao carregar pacotes.' });
        }
      } finally {
        if (seq === reqSeq.current) setLoadingRows(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [api]
  );

  const loadSummary = useCallback(
    async (sess: PcapSessionInfo, filter: string) => {
      setLoadingSummary(true);
      try {
        const qs = new URLSearchParams({ filter });
        setSummary(await getJson<PcapSummary>(api(`/pcap/sessions/${sess.id}/summary?${qs}`)));
      } catch (err) {
        handleExpired(err);
      } finally {
        setLoadingSummary(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [api]
  );

  // sessão nova ou alterada: recarrega tudo (mantendo o filtro aplicado se ainda valer)
  const sessionKey = session ? `${session.id}:${session.totalPackets}:${session.files.length}` : '';
  useEffect(() => {
    if (!session) return;
    setSelected(null);
    setDetail(null);
    void loadRows(session, applied, 0);
    void loadSummary(session, applied);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionKey]);

  const applyFilter = useCallback(
    (text: string, goToPackets = false) => {
      if (!session) return;
      setFilterText(text);
      if (goToPackets) setTab('packets');
      setSelected(null);
      setDetail(null);
      void loadRows(session, text.trim(), 0);
      void loadSummary(session, text.trim());
    },
    [session, loadRows, loadSummary]
  );

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el || !session || loadingRows || rows.length >= matched) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_H * 12) {
      void loadRows(session, applied, rows.length);
    }
  };

  // ----- detalhe -----
  useEffect(() => {
    if (!session || selected === null) {
      setDetail(null);
      return;
    }
    let alive = true;
    getJson<PcapPacketDetail>(api(`/pcap/sessions/${session.id}/packets/${selected}`))
      .then((d) => alive && setDetail(d))
      .catch((err) => handleExpired(err));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, session?.id, api]);

  // ----- envio -----
  const sendFiles = async (list: FileList | File[]) => {
    const files = Array.from(list).filter((f) => f.size > 0);
    if (!files.length) return;
    setNotice(null);
    let current = session;
    let okCount = 0;
    for (let i = 0; i < files.length; i += 1) {
      const f = files[i];
      setUploading({ name: f.name, pct: 0, index: i + 1, total: files.length });
      try {
        const qs = new URLSearchParams({ name: f.name });
        if (current) qs.set('session', current.id);
        const result = await uploadFile(api(`/pcap/upload?${qs}`), f, (pct) =>
          setUploading((u) => (u ? { ...u, pct } : u))
        );
        current = result.session;
        setSession(result.session);
        okCount += 1;
        if (result.added.skipped > 0) {
          setNotice({
            type: 'err',
            text: `${f.name}: ${result.added.skipped.toLocaleString('pt-BR')} pacote(s) além do limite de ${result.session.maxPackets.toLocaleString('pt-BR')} foram ignorados.`,
          });
        }
      } catch (err) {
        handleExpired(err);
        setNotice({ type: 'err', text: `${f.name}: ${err instanceof Error ? err.message : 'falha no envio.'}` });
        if (err instanceof ApiFailure && err.code === 'expired') current = null;
      }
    }
    setUploading(null);
    if (okCount > 0 && !notice) {
      setNotice((n) => n ?? { type: 'ok', text: `${okCount} arquivo(s) analisado(s).` });
    }
  };

  const removeFile = async (idx: number) => {
    if (!session) return;
    try {
      const res = await fetch(api(`/pcap/sessions/${session.id}/files/${idx}`), { method: 'DELETE' });
      const body = (await res.json()) as PcapSessionInfo & { empty?: boolean };
      if (!res.ok) return;
      if (body.empty) {
        setSession(null);
        resetView();
      } else setSession(body);
    } catch {
      setNotice({ type: 'err', text: 'Falha ao remover o arquivo.' });
    }
  };

  const clearAll = async () => {
    if (session) await fetch(api(`/pcap/sessions/${session.id}`), { method: 'DELETE' }).catch(() => undefined);
    setSession(null);
    resetView();
    setFilterText('');
    setApplied('');
    setFilterError(null);
    setNotice(null);
  };

  const openStream = async (id: number) => {
    if (!session) return;
    try {
      setStream(await getJson<PcapStreamView>(api(`/pcap/sessions/${session.id}/stream/${id}`)));
    } catch (err) {
      setNotice({ type: 'err', text: err instanceof Error ? err.message : 'Falha ao abrir o stream.' });
    }
  };

  const exportUrl = useMemo(() => {
    if (!session) return '#';
    const qs = new URLSearchParams({ filter: applied });
    return api(`/pcap/sessions/${session.id}/export?${qs}`);
  }, [session, applied, api]);

  const selectedRow = rows.find((r) => r.no === selected);

  // -------------------------------------------------------------------------

  return (
    <div className="space-y-4">
      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-[var(--fw-heading)] flex items-center gap-2">
              <FileSearch className="w-4 h-4" /> Análise de PCAP
            </h2>
            <p className="text-xs text-[var(--fw-text-muted)] mt-1 max-w-3xl">
              Envie capturas do Wireshark ou tcpdump (.pcap / .pcapng) e depure com filtros no estilo Wireshark.
              Os arquivos ficam só na memória do servidor, por até 1 hora de inatividade, e não são gravados em disco.
            </p>
          </div>
          {session && (
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => inputRef.current?.click()}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)]"
              >
                <Upload className="w-3.5 h-3.5" /> Adicionar arquivo
              </button>
              <button
                type="button"
                onClick={() => void clearAll()}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-red-700 bg-white border border-red-200 rounded-md hover:bg-red-50"
              >
                <Trash2 className="w-3.5 h-3.5" /> Limpar tudo
              </button>
            </div>
          )}
        </div>

        <input
          ref={inputRef}
          type="file"
          multiple
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => {
            if (e.target.files) void sendFiles(e.target.files);
            e.target.value = '';
          }}
        />

        {!session && (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              void sendFiles(e.dataTransfer.files);
            }}
            onClick={() => inputRef.current?.click()}
            className={`mt-4 cursor-pointer rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
              dragOver ? 'border-[var(--fw-accent)] bg-[var(--fw-surface)]' : 'border-[var(--fw-border-strong)] hover:bg-[var(--fw-bg)]'
            }`}
          >
            <Upload className="w-7 h-7 mx-auto text-[var(--fw-text-muted)]" />
            <p className="mt-2 text-sm font-medium text-[var(--fw-heading)]">Arraste os arquivos aqui ou clique para escolher</p>
            <p className="mt-1 text-xs text-[var(--fw-text-muted)]">
              Aceita vários arquivos (mesclados por horário), .pcap e .pcapng
              {help ? ` · até ${help.maxFileMb} MB cada` : ''}
            </p>
          </div>
        )}

        {uploading && (
          <div className="mt-4">
            <div className="flex items-center justify-between text-xs text-[var(--fw-text-body)]">
              <span className="inline-flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                {uploading.pct < 100 ? 'Enviando' : 'Analisando'} {uploading.name}
                {uploading.total > 1 ? ` (${uploading.index}/${uploading.total})` : ''}
              </span>
              <span className="tabular-nums">{uploading.pct}%</span>
            </div>
            <div className="mt-1 h-1.5 rounded bg-[var(--fw-border)] overflow-hidden">
              <div className="h-full bg-[var(--fw-accent)] transition-all" style={{ width: `${uploading.pct}%` }} />
            </div>
          </div>
        )}

        {notice && (
          <div
            className={`mt-4 px-3 py-2 rounded-md border text-xs flex items-start gap-2 ${
              notice.type === 'ok'
                ? 'bg-[var(--fw-surface)] border-[var(--fw-border-strong)] text-[var(--fw-heading)]'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}
          >
            {notice.type === 'ok' ? <CheckCircle2 className="w-3.5 h-3.5 mt-0.5" /> : <XCircle className="w-3.5 h-3.5 mt-0.5" />}
            <span className="flex-1">{notice.text}</span>
            <button type="button" onClick={() => setNotice(null)} aria-label="Fechar aviso">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {session && (
          <div className="mt-4 flex flex-wrap gap-2">
            {session.files.map((f, i) => (
              <FileChip key={`${f.name}-${i}`} file={f} onRemove={() => void removeFile(i)} />
            ))}
          </div>
        )}
      </div>

      {session && (
        <>
          <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4 space-y-3">
            <FilterBar
              value={filterText}
              onChange={setFilterText}
              onApply={() => applyFilter(filterText, true)}
              onClear={() => {
                setFilterText('');
                applyFilter('');
              }}
              error={filterError}
              valid={!!applied && applied === filterText.trim() && !filterError}
              examples={help?.examples ?? []}
              showExamples={showExamples}
              setShowExamples={setShowExamples}
              onPick={(f) => {
                setShowExamples(false);
                applyFilter(f, true);
              }}
            />
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[var(--fw-text-muted)]">
              <span className="tabular-nums">
                {matched.toLocaleString('pt-BR')} de {session.totalPackets.toLocaleString('pt-BR')} pacotes
                {applied ? ' (filtrados)' : ''}
              </span>
              <a
                href={exportUrl}
                className="inline-flex items-center gap-1.5 text-[var(--fw-text-body)] hover:text-[var(--fw-heading)]"
                title="Baixa um .pcap só com os pacotes do filtro atual, para abrir no Wireshark"
              >
                <Download className="w-3.5 h-3.5" /> Baixar .pcap {applied ? 'filtrado' : 'completo'}
              </a>
            </div>
          </div>

          <div className="inline-flex rounded-md bg-[var(--fw-bg)] p-1 gap-1 border border-[var(--fw-border)]">
            {(
              [
                ['packets', 'Pacotes'],
                ['diagnostic', `Diagnóstico${summary?.findings.length ? ` (${summary.findings.length})` : ''}`],
                ['conversations', 'Conversas'],
                ['endpoints', 'Endpoints'],
              ] as Array<[Tab, string]>
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={`px-3 py-1.5 text-xs font-medium rounded ${
                  tab === id ? 'bg-white text-[var(--fw-heading)] shadow-sm' : 'text-[var(--fw-text-muted)] hover:text-[var(--fw-heading)]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {tab === 'packets' && (
            <PacketsTab
              rows={rows}
              matched={matched}
              loading={loadingRows}
              selected={selected}
              onSelect={handleSelectPacket}
              scrollRef={scrollRef}
              onScroll={onScroll}
              detail={detail}
              selectedRow={selectedRow}
              onFilter={(f) => applyFilter(f, true)}
              onFollow={(id) => void openStream(id)}
            />
          )}
          {tab === 'diagnostic' && (
            <DiagnosticTab summary={summary} loading={loadingSummary} onFilter={(f) => applyFilter(f, true)} />
          )}
          {tab === 'conversations' && (
            <ConversationsTab
              summary={summary}
              loading={loadingSummary}
              onFilter={(f) => applyFilter(f, true)}
              onFollow={(id) => void openStream(id)}
            />
          )}
          {tab === 'endpoints' && (
            <EndpointsTab summary={summary} loading={loadingSummary} onFilter={(f) => applyFilter(f, true)} />
          )}
        </>
      )}

      {stream && <StreamModal view={stream} onClose={() => setStream(null)} />}
    </div>
  );
}

// ---------------------------------------------------------------------------

function FileChip({ file, onRemove }: { file: PcapFileInfo; onRemove: () => void }) {
  return (
    <div className="inline-flex items-center gap-2 pl-3 pr-1.5 py-1.5 rounded-md border border-[var(--fw-border-strong)] bg-[var(--fw-bg)] text-xs">
      <span className="font-medium text-[var(--fw-heading)] max-w-[260px] truncate" title={file.name}>
        {file.name}
      </span>
      <span className="text-[var(--fw-text-muted)] tabular-nums">
        {file.packets.toLocaleString('pt-BR')} pacotes · {formatBytes(file.bytes)} · {file.format}
      </span>
      {file.truncated && (
        <span title="O arquivo termina no meio de um pacote (captura interrompida)" className="text-amber-600">
          <AlertTriangle className="w-3.5 h-3.5" />
        </span>
      )}
      <button
        type="button"
        onClick={onRemove}
        className="p-1 rounded hover:bg-white text-[var(--fw-text-muted)]"
        aria-label={`Remover ${file.name}`}
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

function FilterBar(props: {
  value: string;
  onChange: (v: string) => void;
  onApply: () => void;
  onClear: () => void;
  error: string | null;
  valid: boolean;
  examples: FilterExample[];
  showExamples: boolean;
  setShowExamples: (v: boolean) => void;
  onPick: (f: string) => void;
}) {
  const border = props.error ? '#dc2626' : props.valid ? '#16a34a' : 'var(--fw-border-strong)';
  return (
    <div className="relative">
      <div className="flex flex-wrap items-stretch gap-2">
        <input
          value={props.value}
          onChange={(e) => props.onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') props.onApply();
          }}
          spellCheck={false}
          placeholder='Filtro de exibição, ex.: ip.addr == 10.0.0.5 && tcp.port in {80 443}'
          className="flex-1 min-w-[260px] px-3 py-2 text-xs font-mono rounded-md bg-[var(--fw-bg-input)] outline-none"
          style={{ border: `1.5px solid ${border}` }}
          aria-label="Filtro de exibição no estilo Wireshark"
        />
        <button
          type="button"
          onClick={props.onApply}
          className="px-4 py-2 text-xs font-medium text-white bg-[var(--fw-accent)] rounded-md hover:bg-[var(--fw-accent-hover)]"
        >
          Aplicar
        </button>
        <button
          type="button"
          onClick={props.onClear}
          className="px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)]"
        >
          Limpar
        </button>
        <button
          type="button"
          onClick={() => props.setShowExamples(!props.showExamples)}
          className="inline-flex items-center gap-1 px-3 py-2 text-xs font-medium text-[var(--fw-text-body)] bg-white border border-[var(--fw-border-strong)] rounded-md hover:bg-[var(--fw-bg)]"
        >
          Filtros úteis <ChevronDown className="w-3.5 h-3.5" />
        </button>
      </div>
      {props.error && (
        <p className="mt-1.5 text-xs text-red-600 flex items-start gap-1.5">
          <XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" /> {props.error}
        </p>
      )}
      {props.showExamples && (
        <div className="absolute right-0 z-20 mt-1 w-[min(520px,92vw)] max-h-80 overflow-auto rounded-md border border-[var(--fw-border-strong)] bg-white shadow-lg">
          {props.examples.map((ex) => (
            <button
              key={ex.filter}
              type="button"
              onClick={() => props.onPick(ex.filter)}
              className="block w-full text-left px-3 py-2 hover:bg-[var(--fw-bg)] border-b border-[var(--fw-border-soft)] last:border-0"
            >
              <span className="block text-xs font-medium text-[var(--fw-heading)]">
                {ex.label} <span className="font-normal text-[var(--fw-text-muted)]">· {ex.hint}</span>
              </span>
              <code className="block text-[11px] font-mono text-[var(--fw-text-body)] mt-0.5 break-all">{ex.filter}</code>
            </button>
          ))}
          <div className="px-3 py-2 text-[11px] text-[var(--fw-text-muted)] bg-[var(--fw-bg)]">
            Operadores: == != &gt; &lt; &gt;= &lt;= contains matches in {'{…}'} · lógica: && || ! (ou and / or / not) · IP aceita CIDR
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------

const PacketRowItem = memo(function PacketRowItem({
  row,
  isSelected,
  onSelect,
}: {
  row: PcapPacketRow;
  isSelected: boolean;
  onSelect: (no: number) => void;
}) {
  return (
    <tr
      onClick={() => onSelect(row.no)}
      className="cursor-pointer"
      style={{
        height: ROW_H,
        background: isSelected ? 'var(--fw-accent)' : rowBackground(row),
        color: isSelected ? '#fff' : undefined,
      }}
    >
      <td className="px-2 tabular-nums whitespace-nowrap">{row.no}</td>
      <td className="px-2 tabular-nums whitespace-nowrap">{fmtTime(row.t)}</td>
      <td className="px-2 whitespace-nowrap">{row.src}</td>
      <td className="px-2 whitespace-nowrap">{row.dst}</td>
      <td className="px-2 whitespace-nowrap">{row.proto}</td>
      <td className="px-2 tabular-nums whitespace-nowrap">{row.len}</td>
      <td className="px-2 whitespace-nowrap">{row.info}</td>
    </tr>
  );
});

const PCAP_VIEWPORT_H = 380;
const PCAP_OVERSCAN = 24;

function PacketsTab(props: {
  rows: PcapPacketRow[];
  matched: number;
  loading: boolean;
  selected: number | null;
  onSelect: (no: number) => void;
  scrollRef: React.RefObject<HTMLDivElement | null>;
  onScroll: () => void;
  detail: PcapPacketDetail | null;
  selectedRow: PcapPacketRow | undefined;
  onFilter: (f: string) => void;
  onFollow: (id: number) => void;
}) {
  const { rows, selected, detail, selectedRow, onSelect } = props;
  const [scrollTop, setScrollTop] = useState(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    if (rows.length <= PAGE) {
      setScrollTop(props.scrollRef.current?.scrollTop ?? 0);
    }
  }, [rows.length, props.scrollRef]);

  useEffect(() => {
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  const handleContainerScroll = () => {
    props.onScroll();
    if (rafRef.current !== null) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      const el = props.scrollRef.current;
      if (el) setScrollTop(el.scrollTop);
    });
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const idx = rows.findIndex((r) => r.no === selected);
    const nextIdx = Math.min(rows.length - 1, Math.max(0, idx + (e.key === 'ArrowDown' ? 1 : -1)));
    const next = rows[nextIdx];
    if (next) {
      onSelect(next.no);
      const el = props.scrollRef.current;
      if (el) {
        const top = nextIdx * ROW_H;
        if (top < el.scrollTop + ROW_H) el.scrollTop = Math.max(0, top - ROW_H);
        else if (top > el.scrollTop + el.clientHeight - ROW_H * 2) {
          el.scrollTop = top - el.clientHeight + ROW_H * 2;
        }
        setScrollTop(el.scrollTop);
      }
    }
  };

  const virtualize = rows.length > 80;
  const startIdx = virtualize
    ? Math.max(0, Math.floor(scrollTop / ROW_H) - PCAP_OVERSCAN)
    : 0;
  const endIdx = virtualize
    ? Math.min(rows.length, Math.ceil((scrollTop + PCAP_VIEWPORT_H) / ROW_H) + PCAP_OVERSCAN)
    : rows.length;
  const topSpacerH = startIdx * ROW_H;
  const bottomSpacerH = Math.max(0, (rows.length - endIdx) * ROW_H);
  const visibleRows = virtualize ? rows.slice(startIdx, endIdx) : rows;

  return (
    <div className="space-y-3">
      <div className="bg-white border border-[var(--fw-border)] rounded-lg overflow-hidden">
        <div
          ref={props.scrollRef}
          onScroll={handleContainerScroll}
          onKeyDown={onKey}
          tabIndex={0}
          className="overflow-auto outline-none"
          style={{ height: PCAP_VIEWPORT_H }}
        >
          <table className="w-full text-xs font-mono border-collapse">
            <thead className="sticky top-0 z-10 bg-[var(--fw-bg)] text-[var(--fw-text-muted)]">
              <tr className="text-left">
                {['No.', 'Tempo', 'Origem', 'Destino', 'Protocolo', 'Tam.', 'Info'].map((h) => (
                  <th key={h} className="px-2 py-1.5 font-medium border-b border-[var(--fw-border)] whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {topSpacerH > 0 && (
                <tr aria-hidden="true" style={{ height: topSpacerH }}>
                  <td colSpan={7} className="p-0 border-0" />
                </tr>
              )}
              {visibleRows.map((r) => (
                <PacketRowItem
                  key={r.no}
                  row={r}
                  isSelected={r.no === selected}
                  onSelect={onSelect}
                />
              ))}
              {bottomSpacerH > 0 && (
                <tr aria-hidden="true" style={{ height: bottomSpacerH }}>
                  <td colSpan={7} className="p-0 border-0" />
                </tr>
              )}
              {!rows.length && !props.loading && (
                <tr>
                  <td colSpan={7} className="px-3 py-10 text-center text-[var(--fw-text-muted)] font-sans">
                    Nenhum pacote corresponde ao filtro.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {props.loading && (
            <div className="p-2 text-center text-xs text-[var(--fw-text-muted)] font-sans">
              <Loader2 className="w-3.5 h-3.5 animate-spin inline mr-1" /> Carregando…
            </div>
          )}
        </div>
      </div>

      {selected !== null && detail && selectedRow && (
        <div className="grid lg:grid-cols-2 gap-3">
          <div className="bg-white border border-[var(--fw-border)] rounded-lg p-3">
            <div className="flex flex-wrap items-center gap-1.5 mb-2">
              {selectedRow.stream !== undefined && (
                <>
                  <ActionBtn onClick={() => props.onFilter(`tcp.stream == ${selectedRow.stream}`)}>Filtrar este stream</ActionBtn>
                  <ActionBtn onClick={() => props.onFollow(selectedRow.stream as number)}>Seguir stream TCP</ActionBtn>
                </>
              )}
              {selectedRow.src && <ActionBtn onClick={() => props.onFilter(`ip.addr == ${selectedRow.src}`)}>IP origem</ActionBtn>}
              {selectedRow.dst && <ActionBtn onClick={() => props.onFilter(`ip.addr == ${selectedRow.dst}`)}>IP destino</ActionBtn>}
            </div>
            {detail.expert.length > 0 && (
              <div className="mb-2 px-2 py-1.5 rounded bg-amber-50 border border-amber-200 text-[11px] text-amber-800">
                Análise: {detail.expert.join(', ')}
              </div>
            )}
            <div className="space-y-1">
              {detail.layers.map((l, i) => (
                <LayerNode key={`${l.title}-${i}`} title={l.title} fields={l.fields} defaultOpen={i >= detail.layers.length - 2} />
              ))}
            </div>
          </div>
          <div className="bg-white border border-[var(--fw-border)] rounded-lg p-3 overflow-auto max-h-[420px]">
            <HexDump hex={detail.hex} />
          </div>
        </div>
      )}
      {selected === null && rows.length > 0 && (
        <p className="text-xs text-[var(--fw-text-muted)] flex items-center gap-1.5">
          <Info className="w-3.5 h-3.5" /> Clique em um pacote para ver as camadas e o hexdump. Use as setas ↑ ↓ para navegar.
        </p>
      )}
    </div>
  );
}

function ActionBtn({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="px-2 py-1 text-[11px] font-medium text-[var(--fw-text-body)] bg-[var(--fw-bg)] border border-[var(--fw-border-strong)] rounded hover:bg-white"
    >
      {children}
    </button>
  );
}

function LayerNode({ title, fields, defaultOpen }: { title: string; fields: Array<{ k: string; v: string }>; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="text-xs">
      <button type="button" onClick={() => setOpen((o) => !o)} className="flex items-start gap-1 text-left w-full font-medium text-[var(--fw-heading)]">
        {open ? <ChevronDown className="w-3.5 h-3.5 mt-0.5 shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 mt-0.5 shrink-0" />}
        <span className="break-all">{title}</span>
      </button>
      {open && (
        <dl className="ml-5 mt-1 mb-1.5 grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-3 gap-y-0.5 font-mono text-[11px]">
          {fields.map((f, i) => (
            <div key={`${f.k}-${i}`} className="contents">
              <dt className="text-[var(--fw-text-muted)]">{f.k}</dt>
              <dd className="text-[var(--fw-text-body)] break-all">{f.v}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function HexDump({ hex }: { hex: string }) {
  const lines = useMemo(() => {
    const out: Array<{ off: string; bytes: string; ascii: string }> = [];
    for (let i = 0; i < hex.length; i += 32) {
      const chunk = hex.slice(i, i + 32);
      const pairs = chunk.match(/.{1,2}/g) ?? [];
      const ascii = pairs
        .map((h) => {
          const c = parseInt(h, 16);
          return c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
        })
        .join('');
      const left = pairs.slice(0, 8).join(' ');
      const right = pairs.slice(8).join(' ');
      out.push({ off: (i / 2).toString(16).padStart(4, '0'), bytes: `${left.padEnd(23)}  ${right.padEnd(23)}`, ascii });
    }
    return out;
  }, [hex]);
  return (
    <pre className="text-[11px] leading-5 font-mono text-[var(--fw-text-body)]">
      {lines.map((l) => (
        <div key={l.off}>
          <span className="text-[var(--fw-text-muted)]">{l.off}</span>  {l.bytes}  {l.ascii}
        </div>
      ))}
    </pre>
  );
}

// ---------------------------------------------------------------------------

function Loading() {
  return (
    <div className="p-8 text-center text-xs text-[var(--fw-text-muted)]">
      <Loader2 className="w-4 h-4 animate-spin inline mr-1" /> Calculando…
    </div>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-white border border-[var(--fw-border)] rounded-lg p-3">
      <div className="text-[11px] text-[var(--fw-text-muted)]">{label}</div>
      <div className="text-lg font-semibold text-[var(--fw-heading)] tabular-nums">{value}</div>
      {sub && <div className="text-[11px] text-[var(--fw-text-muted)]">{sub}</div>}
    </div>
  );
}

function DiagnosticTab({ summary, loading, onFilter }: { summary: PcapSummary | null; loading: boolean; onFilter: (f: string) => void }) {
  if (loading && !summary) return <Loading />;
  if (!summary) return null;
  const timeline = summary.timeline.map((b) => ({
    t: b.t,
    ok: Math.max(0, b.packets - b.problems),
    problems: b.problems,
  }));
  const maxProto = Math.max(1, ...summary.protocols.map((p) => p.packets));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="Pacotes (no filtro)" value={summary.matched.toLocaleString('pt-BR')} sub={formatBytes(summary.bytes)} />
        <StatCard label="Duração" value={fmtDuration(summary.duration)} />
        <StatCard label="Taxa média" value={fmtRate(summary.avgBps)} sub={`${summary.avgPps.toFixed(1)} pacotes/s`} />
        <StatCard
          label="Achados"
          value={String(summary.findings.length)}
          sub={`${summary.findings.filter((f) => f.severity === 'critical').length} crítico(s)`}
        />
      </div>

      <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
        <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Achados e causas prováveis</h3>
        {summary.findings.length === 0 ? (
          <p className="text-xs text-[var(--fw-text-muted)] flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Nenhum problema evidente de TCP, DNS, ICMP ou TLS neste recorte.
          </p>
        ) : (
          <ul className="space-y-2">
            {summary.findings.map((f) => {
              const s = sevStyle(f.severity);
              return (
                <li key={f.id} className="rounded-md border border-[var(--fw-border)] p-3">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <span className="text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded mr-2" style={{ background: s.bg, color: s.fg }}>
                        {s.label}
                      </span>
                      <span className="text-xs font-semibold text-[var(--fw-heading)]">{f.title}</span>
                    </div>
                    {f.filter && (
                      <ActionBtn onClick={() => onFilter(f.filter as string)}>Ver pacotes</ActionBtn>
                    )}
                  </div>
                  <p className="text-xs text-[var(--fw-text-body)] mt-1.5">{f.detail}</p>
                  {f.hint && <p className="text-xs text-[var(--fw-text-muted)] mt-1">💡 {f.hint}</p>}
                  {f.filter && <code className="block mt-1.5 text-[11px] font-mono text-[var(--fw-text-muted)] break-all">{f.filter}</code>}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Pacotes ao longo do tempo</h3>
          <div style={{ height: 200 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timeline} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--fw-border)" vertical={false} />
                <XAxis dataKey="t" tickFormatter={(v: number) => `${v.toFixed(v < 10 ? 1 : 0)}s`} tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} width={42} />
                <Tooltip
                  formatter={(v, n) => [Number(v).toLocaleString('pt-BR'), n === 'ok' ? 'Normais' : 'Com problema']}
                  labelFormatter={(v) => `a partir de ${Number(v).toFixed(2)} s`}
                />
                <Bar dataKey="ok" stackId="a" fill="#3b82f6" />
                <Bar dataKey="problems" stackId="a" fill="#ef4444" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-[11px] text-[var(--fw-text-muted)] mt-1">Em vermelho: pacotes com RST, retransmissão, DNS com erro, ICMP de erro ou alerta TLS.</p>
        </div>

        <div className="bg-white border border-[var(--fw-border)] rounded-lg p-4">
          <h3 className="text-sm font-semibold text-[var(--fw-heading)] mb-3">Hierarquia de protocolos</h3>
          <div className="space-y-1.5">
            {summary.protocols.slice(0, 12).map((p) => (
              <button
                key={p.proto}
                type="button"
                onClick={() => onFilter(protoFilter(p.proto))}
                className="w-full text-left"
                title="Filtrar por este protocolo"
              >
                <div className="flex justify-between text-xs">
                  <span className="font-medium text-[var(--fw-heading)]">{p.proto}</span>
                  <span className="text-[var(--fw-text-muted)] tabular-nums">
                    {p.packets.toLocaleString('pt-BR')} · {formatBytes(p.bytes)}
                  </span>
                </div>
                <div className="h-1.5 rounded bg-[var(--fw-border)] overflow-hidden">
                  <div className="h-full bg-[var(--fw-accent)]" style={{ width: `${(p.packets / maxProto) * 100}%` }} />
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function protoFilter(proto: string): string {
  const map: Record<string, string> = {
    TCP: 'tcp', UDP: 'udp', DNS: 'dns', HTTP: 'http', TLS: 'tls', SSH: 'ssh', ICMP: 'icmp', ICMPv6: 'icmpv6', ARP: 'arp',
    MDNS: 'udp.port == 5353', QUIC: 'udp.port == 443', DHCP: 'udp.port in {67 68}', NTP: 'udp.port == 123',
  };
  return map[proto] ?? 'frame';
}

function ConversationsTab({
  summary,
  loading,
  onFilter,
  onFollow,
}: {
  summary: PcapSummary | null;
  loading: boolean;
  onFilter: (f: string) => void;
  onFollow: (id: number) => void;
}) {
  if (loading && !summary) return <Loading />;
  if (!summary) return null;
  const stateColor = (c: PcapConversation): string | undefined => {
    if (!c.state) return undefined;
    if (/sem resposta|Recusada/i.test(c.state)) return '#dc2626';
    if (/Resetada/i.test(c.state)) return '#b45309';
    return undefined;
  };
  return (
    <div className="bg-white border border-[var(--fw-border)] rounded-lg overflow-auto">
      <table className="w-full text-xs">
        <thead className="bg-[var(--fw-bg)] text-[var(--fw-text-muted)]">
          <tr className="text-left">
            {['Tipo', 'Endereço A', 'Endereço B', 'Pacotes', 'Bytes', 'Início', 'Duração', 'Estado', ''].map((h) => (
              <th key={h} className="px-3 py-2 font-medium whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {summary.conversations.map((c, i) => (
            <tr key={`${c.filter}-${i}`} className="border-t border-[var(--fw-border-soft)] hover:bg-[var(--fw-bg)]">
              <td className="px-3 py-1.5 uppercase font-mono">{c.kind}</td>
              <td className="px-3 py-1.5 font-mono whitespace-nowrap">{c.a}{c.aPort !== undefined ? `:${c.aPort}` : ''}</td>
              <td className="px-3 py-1.5 font-mono whitespace-nowrap">{c.b}{c.bPort !== undefined ? `:${c.bPort}` : ''}</td>
              <td className="px-3 py-1.5 tabular-nums">{c.packets.toLocaleString('pt-BR')}</td>
              <td className="px-3 py-1.5 tabular-nums">{formatBytes(c.bytes)}</td>
              <td className="px-3 py-1.5 tabular-nums">{c.start.toFixed(3)} s</td>
              <td className="px-3 py-1.5 tabular-nums">{fmtDuration(c.duration)}</td>
              <td className="px-3 py-1.5" style={{ color: stateColor(c) }}>{c.state ?? '—'}</td>
              <td className="px-3 py-1.5 whitespace-nowrap space-x-1">
                <ActionBtn onClick={() => onFilter(c.filter)}>Pacotes</ActionBtn>
                {c.kind === 'tcp' && c.stream !== undefined && <ActionBtn onClick={() => onFollow(c.stream as number)}>Seguir</ActionBtn>}
              </td>
            </tr>
          ))}
          {!summary.conversations.length && (
            <tr>
              <td colSpan={9} className="px-3 py-8 text-center text-[var(--fw-text-muted)]">
                Sem conversas IP neste recorte.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function EndpointsTab({ summary, loading, onFilter }: { summary: PcapSummary | null; loading: boolean; onFilter: (f: string) => void }) {
  if (loading && !summary) return <Loading />;
  if (!summary) return null;
  return (
    <div className="bg-white border border-[var(--fw-border)] rounded-lg overflow-auto">
      <table className="w-full text-xs">
        <thead className="bg-[var(--fw-bg)] text-[var(--fw-text-muted)]">
          <tr className="text-left">
            {['Endereço IP', 'Pacotes', 'Bytes', 'Enviados', 'Recebidos', ''].map((h) => (
              <th key={h} className="px-3 py-2 font-medium whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {summary.endpoints.map((e) => (
            <tr key={e.ip} className="border-t border-[var(--fw-border-soft)] hover:bg-[var(--fw-bg)]">
              <td className="px-3 py-1.5 font-mono">{e.ip}</td>
              <td className="px-3 py-1.5 tabular-nums">{e.packets.toLocaleString('pt-BR')}</td>
              <td className="px-3 py-1.5 tabular-nums">{formatBytes(e.bytes)}</td>
              <td className="px-3 py-1.5 tabular-nums">{e.txPackets.toLocaleString('pt-BR')} · {formatBytes(e.txBytes)}</td>
              <td className="px-3 py-1.5 tabular-nums">{e.rxPackets.toLocaleString('pt-BR')} · {formatBytes(e.rxBytes)}</td>
              <td className="px-3 py-1.5">
                <ActionBtn onClick={() => onFilter(`ip.addr == ${e.ip}`)}>Pacotes</ActionBtn>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StreamModal({ view, onClose }: { view: PcapStreamView; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
      <div
        className="w-full max-w-4xl max-h-[85vh] flex flex-col rounded-lg bg-white border border-[var(--fw-border-strong)] shadow-xl"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label={`Stream TCP ${view.stream}`}
      >
        <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-[var(--fw-border)]">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-[var(--fw-heading)]">Stream TCP {view.stream}</h3>
            <p className="text-[11px] text-[var(--fw-text-muted)] font-mono truncate">
              <span style={{ color: '#2563eb' }}>{view.a}</span> → <span style={{ color: '#dc2626' }}>{view.b}</span> ·{' '}
              {formatBytes(view.clientBytes)} do cliente, {formatBytes(view.serverBytes)} do servidor
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Fechar" className="p-1.5 rounded hover:bg-[var(--fw-bg)]">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-auto p-4 bg-[var(--fw-bg)]">
          {view.segments.length === 0 ? (
            <p className="text-xs text-[var(--fw-text-muted)]">Este stream não tem dados de aplicação (só handshake/controle).</p>
          ) : (
            <pre className="text-[11px] leading-5 font-mono whitespace-pre-wrap break-all">
              {view.segments.map((s, i) => (
                <span
                  key={i}
                  style={{
                    color: s.dir === 0 ? '#2563eb' : '#dc2626',
                    background: s.dir === 0 ? 'rgba(37,99,235,0.07)' : 'rgba(220,38,38,0.07)',
                    display: 'block',
                    padding: '2px 6px',
                    marginBottom: 2,
                  }}
                >
                  {s.text}
                </span>
              ))}
            </pre>
          )}
          {view.truncated && <p className="mt-2 text-[11px] text-amber-700">Exibição limitada a 256 KB.</p>}
        </div>
        <div className="px-4 py-2 text-[11px] text-[var(--fw-text-muted)] border-t border-[var(--fw-border)]">
          Azul = cliente, vermelho = servidor. Ordem de captura; retransmissões omitidas, sem remontagem completa do fluxo.
        </div>
      </div>
    </div>
  );
}
