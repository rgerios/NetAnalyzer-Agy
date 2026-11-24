/** Validação e renderização da identidade do cliente nos relatórios em HTML. */
import { BRANDING_LIMITS, EMPTY_BRANDING, type ReportBranding } from '../shared/branding.ts';

const LOGO_RE = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/;

export class BrandingError extends Error {}

const clean = (v: unknown, max: number): string =>
  typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f\s]+/g, ' ').trim().slice(0, max) : '';

/** Confere o tipo real pelos primeiros bytes (não confia no que o navegador declarou). */
function magicOk(kind: string, buf: Buffer): boolean {
  if (kind === 'png') return buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  if (kind === 'jpeg') return buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  if (kind === 'webp') return buf.length > 12 && buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP';
  return false;
}

/** Valida o logo: só png/jpeg/webp reais, até 300 KB. SVG fica de fora de propósito (pode carregar script). */
export function validateLogo(dataUri: string): string {
  if (!dataUri) return '';
  const m = LOGO_RE.exec(dataUri);
  if (!m) throw new BrandingError('Logo inválido: use uma imagem PNG, JPEG ou WebP.');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > BRANDING_LIMITS.logoBytes) throw new BrandingError('Logo muito grande: o limite é 300 KB.');
  if (!magicOk(m[1], buf)) throw new BrandingError('O arquivo não é uma imagem válida.');
  return dataUri;
}

/** Aplica uma atualização parcial: texto sempre normalizado; logo só muda se vier no corpo (null/"" remove). */
export function applyBranding(current: ReportBranding | undefined, body: Record<string, unknown>): ReportBranding {
  const base = { ...EMPTY_BRANDING, ...(current ?? {}) };
  const next: ReportBranding = {
    clientName: body.clientName !== undefined ? clean(body.clientName, BRANDING_LIMITS.name) : base.clientName,
    reportTitle: body.reportTitle !== undefined ? clean(body.reportTitle, BRANDING_LIMITS.title) : base.reportTitle,
    preparedBy: body.preparedBy !== undefined ? clean(body.preparedBy, BRANDING_LIMITS.name) : base.preparedBy,
    logoDataUri: base.logoDataUri,
  };
  if (body.logoDataUri !== undefined) next.logoDataUri = body.logoDataUri === null ? '' : validateLogo(String(body.logoDataUri));
  return next;
}

/** Lê o que veio do armazenamento sem confiar nele. */
export function sanitizeStoredBranding(raw: unknown): ReportBranding {
  if (!raw || typeof raw !== 'object') return { ...EMPTY_BRANDING };
  try {
    return applyBranding(undefined, raw as Record<string, unknown>);
  } catch {
    return { ...EMPTY_BRANDING, ...applyBranding(undefined, { ...(raw as Record<string, unknown>), logoDataUri: null }) };
  }
}

export const hasBranding = (b?: ReportBranding | null): boolean => !!b && !!(b.clientName || b.logoDataUri || b.preparedBy || b.reportTitle);

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export const BRAND_CSS = `
.brand-head{display:flex;align-items:center;gap:20px;padding:0 0 20px;margin:0 0 22px;border-bottom:3px solid var(--brand-accent,#1d4e89)}
.brand-head img{max-height:72px;max-width:240px;object-fit:contain}
.brand-head .bh-text{flex:1;min-width:0}
.brand-head .bh-client{font-size:22px;font-weight:700;line-height:1.2}
.brand-head .bh-title{font-size:14px;opacity:.75;margin-top:2px}
.brand-head .bh-by{font-size:11px;opacity:.65;text-align:right;white-space:nowrap}
@media print{.brand-head{break-inside:avoid}}`;

/** Cabeçalho de entrega: logo e nome do cliente, título e quem preparou. Vazio quando não há identidade configurada. */
export function renderBrandHeader(b: ReportBranding | undefined | null, defaultTitle: string, generatedAt: Date = new Date()): string {
  if (!hasBranding(b)) return '';
  const br = b as ReportBranding;
  const when = generatedAt.toLocaleDateString('pt-BR');
  return `<header class="brand-head">
${br.logoDataUri ? `<img src="${esc(br.logoDataUri)}" alt="${esc(br.clientName || 'Logo do cliente')}">` : ''}
<div class="bh-text">${br.clientName ? `<div class="bh-client">${esc(br.clientName)}</div>` : ''}<div class="bh-title">${esc(br.reportTitle || defaultTitle)}</div></div>
<div class="bh-by">${br.preparedBy ? `Preparado por ${esc(br.preparedBy)}<br>` : ''}${esc(when)}</div>
</header>`;
}

/** Título da aba do navegador: cliente primeiro, quando houver. */
export const brandedTitle = (b: ReportBranding | undefined | null, base: string): string =>
  b?.clientName ? `${b.clientName} — ${b.reportTitle || base}` : base;
