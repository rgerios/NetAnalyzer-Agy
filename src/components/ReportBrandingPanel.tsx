import { useEffect, useRef, useState } from 'react';
import { ChevronDown, ImagePlus, Loader2, Trash2 } from 'lucide-react';
import { BRANDING_LIMITS, EMPTY_BRANDING, type ReportBranding } from '../../shared/branding.ts';
import type { FirewallVendor } from '../types.ts';
import { vendorApiUrl } from '../utils/vendorApi.ts';

const MAX_W = 480;
const MAX_H = 192;
const inputCls =
  'w-full px-3 py-2 text-xs bg-white border border-[var(--fw-border-strong)] rounded-md focus:outline-none focus:ring-2 focus:ring-[var(--fw-accent-mid)]';

/** Reduz o logo no navegador (máx. 480x192) e devolve um data URI pequeno em PNG ou JPEG. */
async function prepareLogo(file: File): Promise<string> {
  if (!/^image\/(png|jpeg|webp)$/.test(file.type)) throw new Error('Use uma imagem PNG, JPEG ou WebP. SVG não é aceito.');
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error('Não foi possível ler a imagem.'));
      el.src = url;
    });
    const scale = Math.min(1, MAX_W / img.width, MAX_H / img.height);
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(img.width * scale));
    canvas.height = Math.max(1, Math.round(img.height * scale));
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('O navegador não conseguiu processar a imagem.');
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    // JPEG só quando a origem já era JPEG (sem transparência); senão PNG preserva o fundo transparente
    const out = file.type === 'image/jpeg' ? canvas.toDataURL('image/jpeg', 0.9) : canvas.toDataURL('image/png');
    if (Math.floor(((out.length - out.indexOf(',') - 1) * 3) / 4) > BRANDING_LIMITS.logoBytes) throw new Error('A imagem ficou grande demais. Use uma versão mais simples do logo.');
    return out;
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** Identidade do cliente (nome, logo e quem entrega) que sai no cabeçalho dos relatórios em HTML. */
export function ReportBrandingPanel({ vendor }: { vendor: FirewallVendor }) {
  const [open, setOpen] = useState(false);
  const [saved, setSaved] = useState<ReportBranding>(EMPTY_BRANDING);
  const [form, setForm] = useState<ReportBranding>(EMPTY_BRANDING);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    fetch(vendorApiUrl(vendor, '/branding'))
      .then((r) => (r.ok ? (r.json() as Promise<ReportBranding>) : EMPTY_BRANDING))
      .then((b) => {
        if (!alive) return;
        setSaved(b);
        setForm(b);
      })
      .catch(() => undefined)
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [vendor]);

  const dirty = JSON.stringify(form) !== JSON.stringify(saved);
  const configured = !!(saved.clientName || saved.logoDataUri);

  const pickLogo = async (file?: File) => {
    if (!file) return;
    setMsg(null);
    try {
      setForm((f) => ({ ...f, logoDataUri: '' }));
      const data = await prepareLogo(file);
      setForm((f) => ({ ...f, logoDataUri: data }));
    } catch (err) {
      setForm((f) => ({ ...f, logoDataUri: saved.logoDataUri }));
      setMsg({ ok: false, text: err instanceof Error ? err.message : 'Falha ao carregar o logo.' });
    } finally {
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const save = async () => {
    setSaving(true);
    setMsg(null);
    try {
      const res = await fetch(vendorApiUrl(vendor, '/branding'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientName: form.clientName,
          reportTitle: form.reportTitle,
          preparedBy: form.preparedBy,
          logoDataUri: form.logoDataUri || null,
        }),
      });
      const body = (await res.json().catch(() => ({}))) as ReportBranding & { error?: string };
      if (!res.ok) throw new Error(body.error || `Erro ${res.status}`);
      setSaved(body);
      setForm(body);
      setMsg({ ok: true, text: 'Identidade salva. Os próximos relatórios em HTML já saem com ela.' });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : 'Falha ao salvar.' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="no-print bg-white border border-[var(--fw-border)] rounded-lg" aria-label="Identidade do relatório">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <span className="flex items-center gap-3 min-w-0">
          {saved.logoDataUri ? (
            <img src={saved.logoDataUri} alt="" className="h-7 w-auto max-w-[110px] object-contain rounded" />
          ) : (
            <ImagePlus className="w-4 h-4 text-[var(--fw-text-muted)]" aria-hidden="true" />
          )}
          <span className="min-w-0">
            <span className="block text-sm font-semibold text-[var(--fw-heading)]">Identidade do relatório (cliente e logo)</span>
            <span className="block text-[11px] text-[var(--fw-text-muted)] truncate">
              {configured ? `${saved.clientName || 'Sem nome'}${saved.preparedBy ? ` · preparado por ${saved.preparedBy}` : ''}` : 'Opcional: coloque o nome e o logo do cliente no cabeçalho dos relatórios em HTML.'}
            </span>
          </span>
        </span>
        <ChevronDown className={`w-4 h-4 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden="true" />
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-[var(--fw-border-soft)] pt-4 space-y-4">
          {loading ? (
            <p className="text-xs text-[var(--fw-text-muted)] inline-flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> Carregando…
            </p>
          ) : (
            <>
              <div className="grid sm:grid-cols-2 gap-3">
                <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                  Nome do cliente
                  <input value={form.clientName} maxLength={BRANDING_LIMITS.name} onChange={(e) => setForm({ ...form, clientName: e.target.value })} placeholder="Ex.: Empresa Exemplo Ltda" className={inputCls} />
                </label>
                <label className="text-xs text-[var(--fw-text-muted)] space-y-1">
                  Preparado por <span className="text-[var(--fw-text-subtle)]">(sua consultoria ou equipe)</span>
                  <input value={form.preparedBy} maxLength={BRANDING_LIMITS.name} onChange={(e) => setForm({ ...form, preparedBy: e.target.value })} placeholder="Ex.: Equipe de Redes" className={inputCls} />
                </label>
                <label className="text-xs text-[var(--fw-text-muted)] space-y-1 sm:col-span-2">
                  Título do relatório <span className="text-[var(--fw-text-subtle)]">(vazio usa o título padrão de cada relatório)</span>
                  <input value={form.reportTitle} maxLength={BRANDING_LIMITS.title} onChange={(e) => setForm({ ...form, reportTitle: e.target.value })} placeholder="Ex.: Relatório mensal de segurança e desempenho" className={inputCls} />
                </label>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div className="h-16 min-w-[160px] px-3 grid place-items-center rounded-md border border-dashed border-[var(--fw-border-strong)] bg-[var(--fw-surface-soft)]">
                  {form.logoDataUri ? (
                    <img src={form.logoDataUri} alt="Logo do cliente" className="max-h-12 max-w-[200px] object-contain" />
                  ) : (
                    <span className="text-[11px] text-[var(--fw-text-muted)]">Sem logo</span>
                  )}
                </div>
                <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" className="hidden" onChange={(e) => void pickLogo(e.target.files?.[0])} />
                <button type="button" onClick={() => fileRef.current?.click()} className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-white border border-[var(--fw-border-strong)] rounded-md">
                  <ImagePlus className="w-3.5 h-3.5" /> {form.logoDataUri ? 'Trocar logo' : 'Escolher logo'}
                </button>
                {form.logoDataUri && (
                  <button type="button" onClick={() => setForm({ ...form, logoDataUri: '' })} className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-red-700 bg-white border border-red-200 rounded-md">
                    <Trash2 className="w-3.5 h-3.5" /> Remover
                  </button>
                )}
                <span className="text-[11px] text-[var(--fw-text-muted)]">PNG, JPEG ou WebP; é reduzido automaticamente.</span>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <button type="button" onClick={() => void save()} disabled={!dirty || saving} className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-[var(--fw-accent)] rounded-md disabled:opacity-40">
                  {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />} Salvar identidade
                </button>
                {msg && (
                  <span className={`text-xs ${msg.ok ? 'text-emerald-700' : 'text-red-700'}`} role={msg.ok ? 'status' : 'alert'}>
                    {msg.text}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-[var(--fw-text-muted)]">
                Vale para a localidade/conta ativa. Aparece no topo dos relatórios em HTML (auditoria, acessos e consumo, e AWS). Os PDFs continuam com o cabeçalho padrão.
              </p>
            </>
          )}
        </div>
      )}
    </section>
  );
}
