import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronRight, Copy, Trash2 } from 'lucide-react';
import type { FirewallVendor } from '../types.ts';
import type { UnrecognizedSnapshot } from '../../shared/unrecognized.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

interface UnrecognizedPanelProps {
  vendor: FirewallVendor;
  refreshToken: number;
}

const SOURCE_LABEL: Record<string, string> = {
  udp: 'UDP',
  paste: 'colado',
  upload: 'arquivo',
  s3: 'S3',
  sample: 'amostra',
};

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isFinite(d.getTime()) ? d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : iso;
}

/**
 * Aviso das linhas de log que o analisador não entendeu. Só aparece quando existe alguma; mostra
 * exemplos reais agrupados por forma, para ampliar a cobertura do parser.
 */
export function UnrecognizedPanel({ vendor, refreshToken }: UnrecognizedPanelProps) {
  const [snap, setSnap] = useState<UnrecognizedSnapshot | null>(null);
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch(vendorApiUrl(vendor, '/syslogs/unrecognized'));
      if (res.ok) setSnap((await res.json()) as UnrecognizedSnapshot);
    } catch {
      // painel opcional: ignora falhas de rede
    }
  }, [vendor]);

  useEffect(() => {
    void load();
    const id = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(id);
  }, [load, refreshToken]);

  const clear = async () => {
    try {
      const res = await fetch(vendorApiUrl(vendor, '/syslogs/unrecognized'), { method: 'DELETE' });
      if (res.ok) setSnap((await res.json()) as UnrecognizedSnapshot);
    } catch {
      // mantém o painel como está
    }
  };

  const copy = async (text: string, i: number) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(i);
      window.setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(null);
    }
  };

  if (!snap || snap.total === 0) return null;

  return (
    <section className="bg-amber-50 border border-amber-300 rounded-lg" aria-label="Linhas de log não reconhecidas">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center gap-2 px-4 py-3 text-left text-xs text-amber-900"
      >
        {open ? <ChevronDown className="w-4 h-4 shrink-0" aria-hidden="true" /> : <ChevronRight className="w-4 h-4 shrink-0" aria-hidden="true" />}
        <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
        <span className="font-semibold">
          {snap.total.toLocaleString('pt-BR')} linha(s) de log não reconhecida(s)
        </span>
        <span className="text-amber-800">
          desde {when(snap.since)} · {snap.shapes.length} tipo(s) de mensagem
          {snap.droppedShapes > 0 ? ` (+${snap.droppedShapes} omitidos)` : ''}
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3">
          <p className="text-xs text-amber-900">
            Estas linhas chegaram, mas o analisador não conseguiu extrair os campos e elas <strong>não entram</strong> nos syslogs. Se forem mensagens
            que importam, envie os exemplos para ampliarmos a cobertura. A contagem zera quando o servidor reinicia.
          </p>
          <ul className="space-y-2">
            {snap.shapes.slice(0, 15).map((s, i) => (
              <li key={`${i}-${s.firstAt}`} className="rounded-md border border-amber-200 bg-white p-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-[var(--fw-text-muted)]">
                  <span className="tabular-nums">
                    <strong className="text-[var(--fw-heading)]">{s.count.toLocaleString('pt-BR')}×</strong> · origem {SOURCE_LABEL[s.source] ?? s.source} · última{' '}
                    {when(s.lastAt)}
                  </span>
                  <button
                    type="button"
                    onClick={() => void copy(s.sample, i)}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border border-[var(--fw-border-strong)] hover:bg-[var(--fw-bg)] text-[var(--fw-text-body)]"
                  >
                    <Copy className="w-3 h-3" aria-hidden="true" /> {copied === i ? 'Copiado' : 'Copiar exemplo'}
                  </button>
                </div>
                <pre className="mt-1.5 text-[11px] font-mono whitespace-pre-wrap break-all text-[var(--fw-text-body)]">{s.sample}</pre>
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={() => void clear()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-amber-900 bg-white border border-amber-300 rounded-md hover:bg-amber-100"
          >
            <Trash2 className="w-3.5 h-3.5" aria-hidden="true" /> Limpar a lista
          </button>
        </div>
      )}
    </section>
  );
}
