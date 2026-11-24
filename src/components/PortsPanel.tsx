import { useEffect, useMemo, useState } from 'react';
import { Loader2, Network, X } from 'lucide-react';
import type { FirewallVendor, PortStat, PortsReport } from '../types.ts';
import { parsePortFilter } from '../../shared/ports.ts';
import { formatBytes } from '../../shared/destinations.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

/** Campo de filtro por porta de destino: "443", "80,443" ou "8000-8100". */
export function PortFilterInput({
  value,
  onChange,
  className = '',
  label = 'Porta destino',
}: {
  value: string;
  onChange: (v: string) => void;
  className?: string;
  label?: string;
}) {
  const invalid = value.trim() !== '' && parsePortFilter(value) === null;
  return (
    <input
      type="text"
      inputMode="numeric"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder="Porta destino (ex: 443 ou 80,443 ou 8000-8100)"
      aria-label={label}
      aria-invalid={invalid}
      title={invalid ? 'Use números de 0 a 65535, listas (80,443) ou intervalos (8000-8100)' : 'Filtra pela porta de destino'}
      className={`px-3 py-2 text-xs font-mono border rounded-md bg-[var(--fw-bg-input)] focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)] ${
        invalid ? 'border-red-500' : 'border-[var(--fw-border-strong)]'
      } ${className}`}
    />
  );
}

export function isPortFilterValid(value: string): boolean {
  return parsePortFilter(value) !== null;
}

/** Chip "Porta: 443" com botão para remover. */
export function PortChip({ port, onClear }: { port: string; onClear: () => void }) {
  if (!port) return null;
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full bg-[var(--fw-surface-alt)] text-[var(--fw-heading)]">
      Porta destino: <span className="font-mono">{port}</span>
      <button type="button" onClick={onClear} aria-label="Remover filtro de porta" className="text-[var(--fw-text-subtle)] hover:text-[var(--fw-heading)]">
        <X className="w-3.5 h-3.5" aria-hidden="true" />
      </button>
    </span>
  );
}

function protoLabel(p: PortStat): string {
  return `${p.port}/${p.proto}`;
}

/**
 * Ranking das portas de destino mais acessadas. Clicar em uma porta aplica o filtro; clicar de
 * novo na porta selecionada remove. `selected` é o texto do filtro atual (ex.: "443").
 */
export function PortsRanking({
  ports,
  selected,
  onSelect,
  loading = false,
  note,
  title = 'Portas de destino mais acessadas',
  initialVisible = 8,
}: {
  ports: PortStat[];
  selected: string;
  onSelect: (portText: string) => void;
  loading?: boolean;
  note?: string;
  title?: string;
  initialVisible?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const total = useMemo(() => ports.reduce((n, p) => n + p.connections, 0), [ports]);
  const max = ports.length ? ports[0].connections : 1;
  const visible = expanded ? ports : ports.slice(0, initialVisible);
  const top = ports[0];
  const selectedSet = useMemo(() => new Set(selected.split(',').map((s) => s.trim()).filter(Boolean)), [selected]);

  return (
    <section className="bg-white border border-[var(--fw-border)] rounded-lg p-4" aria-label={title}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold text-[var(--fw-heading)] flex items-center gap-2">
          <Network className="w-4 h-4" aria-hidden="true" /> {title}
          {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--fw-text-muted)]" aria-hidden="true" />}
        </h3>
        {note && <p className="text-[11px] text-[var(--fw-text-muted)]">{note}</p>}
      </div>

      {top && (
        <p className="mt-2 text-xs text-[var(--fw-text-body)]">
          Porta mais acessada: <strong className="font-mono">{protoLabel(top)}</strong>
          {top.service ? ` (${top.service})` : ''} com {top.connections.toLocaleString('pt-BR')} conexões
          {total > 0 ? ` (${Math.round((top.connections / total) * 100)}% do ranking)` : ''}
          {top.blocked > 0 ? `, ${top.blocked.toLocaleString('pt-BR')} bloqueadas` : ''}.
        </p>
      )}

      {ports.length === 0 ? (
        <p className="mt-3 text-xs text-[var(--fw-text-muted)]">
          {loading ? 'Calculando…' : 'Nenhum evento com porta de destino no período.'}
        </p>
      ) : (
        <ul className="mt-3 space-y-1.5">
          {visible.map((p) => {
            const active = selectedSet.has(String(p.port));
            return (
              <li key={`${p.port}-${p.proto}`}>
                <button
                  type="button"
                  onClick={() => onSelect(active && selectedSet.size === 1 ? '' : String(p.port))}
                  aria-pressed={active}
                  title="Filtrar por esta porta de destino"
                  className={`w-full text-left rounded-md px-2 py-1.5 border transition-colors ${
                    active
                      ? 'border-[var(--fw-accent)] bg-[var(--fw-surface)]'
                      : 'border-transparent hover:bg-[var(--fw-bg)]'
                  }`}
                >
                  <div className="flex items-baseline justify-between gap-3 text-xs">
                    <span className="font-medium text-[var(--fw-heading)]">
                      <span className="font-mono">{protoLabel(p)}</span>
                      {p.service && <span className="ml-1.5 font-normal text-[var(--fw-text-muted)]">{p.service}</span>}
                    </span>
                    <span className="text-[var(--fw-text-muted)] tabular-nums whitespace-nowrap">
                      {p.connections.toLocaleString('pt-BR')} conexões
                      {p.blocked > 0 && <span className="text-red-600"> · {p.blocked.toLocaleString('pt-BR')} bloq.</span>}
                      {p.bytes > 0 && <> · {formatBytes(p.bytes)}</>}
                      {p.sources > 0 && <> · {p.sources.toLocaleString('pt-BR')} orig.</>}
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 rounded bg-[var(--fw-border)] overflow-hidden">
                    <div
                      className="h-full"
                      style={{
                        width: `${Math.max(2, (p.connections / max) * 100)}%`,
                        background: p.blocked > p.connections / 2 ? '#ef4444' : 'var(--fw-accent)',
                      }}
                    />
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      )}

      {ports.length > initialVisible && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="mt-2 text-xs font-medium text-[var(--fw-accent-mid)] hover:underline"
        >
          {expanded ? 'Mostrar menos' : `Mostrar mais ${ports.length - initialVisible}`}
        </button>
      )}
    </section>
  );
}

/** Ranking que busca os dados sozinho (usado na aba Syslogs). */
export function PortsFetchPanel({
  vendor,
  minutes,
  refreshToken,
  selected,
  onSelect,
}: {
  vendor: FirewallVendor;
  minutes: number;
  refreshToken: number;
  selected: string;
  onSelect: (portText: string) => void;
}) {
  const [report, setReport] = useState<PortsReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    fetch(vendorApiUrl(vendor, `/ports?minutes=${minutes}`), { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error || `HTTP ${res.status}`);
        setReport((await res.json()) as PortsReport);
        setError(null);
      })
      .catch((err) => {
        if (err instanceof DOMException && err.name === 'AbortError') return;
        setError('Não foi possível carregar o ranking de portas.');
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [vendor, minutes, refreshToken]);

  if (error) {
    return <p className="text-xs text-red-600 bg-white border border-[var(--fw-border)] rounded-lg p-3">{error}</p>;
  }
  return (
    <PortsRanking
      ports={report?.ports ?? []}
      selected={selected}
      onSelect={onSelect}
      loading={loading}
      note={
        report
          ? `${report.events.toLocaleString('pt-BR')} eventos${report.dataSource === 'database' ? ' no período (banco)' : ' na janela em memória'}${report.truncated ? ' · consulta interrompida por tempo' : ''}`
          : undefined
      }
    />
  );
}
