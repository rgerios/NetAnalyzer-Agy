import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { applyBranding, BrandingError, renderBrandHeader, validateLogo, sanitizeStoredBranding } from '../server/reportBranding.ts';
import { renderAwsReportHtml } from '../server/awsReportHtml.ts';
import { renderAccessReportHtml } from '../server/accessReportHtml.ts';
import { buildHttpInsights, rowsFromAlbEvents } from '../server/httpInsights.ts';
import { facetsFromEvents } from '../server/facets.ts';
import { createAwsSampleDataset } from '../server/awsSampleData.ts';
import { aggregateEventsInMemory, buildAccessReport } from '../server/accessReport.ts';
import type { Intel } from '../server/intel.ts';

const intel: Intel = {
  lookup: (ip: string) =>
    ip.startsWith('8.8.')
      ? { country: 'US', asn: 15169, asnOrg: 'Google LLC', threats: [] }
      : ip.startsWith('185.')
        ? { country: 'RU', asn: 1, asnOrg: 'Bad Net', threats: [{ list: 'FireHOL Level 1', category: 'blacklist' as const }] }
        : { country: null, asn: null, asnOrg: null, threats: [] },
  status: () => ({ updating: false, lastCheckAt: null, autoUpdate: false, ready: true, sources: [] }),
  update: async () => intel.status(),
  start: async () => undefined,
  stop: () => undefined,
};

// PNG 1x1 válido
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

describe('identidade do relatório', () => {
  it('aceita PNG real e recusa SVG, texto disfarçado e imagem grande', () => {
    assert.equal(validateLogo(PNG), PNG);
    assert.throws(() => validateLogo('data:image/svg+xml;base64,PHN2Zy8+'), BrandingError);
    assert.throws(() => validateLogo(`data:image/png;base64,${Buffer.from('<script>alert(1)</script>').toString('base64')}`), /não é uma imagem válida/);
    const big = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(310 * 1024)]);
    assert.throws(() => validateLogo(`data:image/png;base64,${big.toString('base64')}`), /muito grande/);
  });
  it('normaliza textos e só mexe no logo quando ele vem no corpo', () => {
    const a = applyBranding(undefined, { clientName: '  Acme\u0000 Corp  ', logoDataUri: PNG });
    assert.equal(a.clientName, 'Acme Corp');
    const b = applyBranding(a, { preparedBy: 'Equipe de Redes' });
    assert.equal(b.logoDataUri, PNG);
    assert.equal(applyBranding(b, { logoDataUri: null }).logoDataUri, '');
    assert.equal(sanitizeStoredBranding({ clientName: 'X', logoDataUri: 'data:image/svg+xml;base64,AAAA' }).logoDataUri, '');
  });
  it('escapa HTML no cabeçalho e some quando não há identidade', () => {
    assert.equal(renderBrandHeader(undefined, 'T'), '');
    const h = renderBrandHeader(applyBranding(undefined, { clientName: '<img onerror=x>', logoDataUri: PNG }), 'Relatório');
    assert.equal(h.includes('<img onerror'), false);
    assert.match(h, /&lt;img onerror=x&gt;/);
    assert.match(h, /<img src="data:image\/png;base64,/);
  });
});

describe('relatórios em HTML com identidade', () => {
  const branding = applyBranding(undefined, { clientName: 'Acme Corp', preparedBy: 'Equipe de Redes', reportTitle: 'Relatório mensal', logoDataUri: PNG });
  const sample = createAwsSampleDataset(Date.now());
  const alb = buildHttpInsights({ ...rowsFromAlbEvents(sample.events, 600), minutes: 360, dataSource: 'memory', truncated: false });
  const waf = { kind: 'waf' as const, minutes: 360, generatedAt: new Date().toISOString(), dataSource: 'memory' as const, ...facetsFromEvents(sample.events, 'waf', 600) };

  it('relatório AWS leva logo, cliente e título, sem scripts e sem segredos', () => {
    const html = renderAwsReportHtml({ minutes: 360, generatedAt: new Date().toISOString(), alb, waf, accountId: '111122223333' }, ['alb', 'waf'], 'Conta AWS', branding);
    assert.match(html, /Acme Corp/);
    assert.match(html, /Relatório mensal/);
    assert.match(html, /Preparado por Equipe de Redes/);
    assert.match(html, /<img src="data:image\/png/);
    assert.equal(/<script/i.test(html), false);
    assert.match(html, /Credenciais expostas nas requisições/);
    assert.equal(html.includes('dXN1YXJpbzpzZW5oYQ'), false);
    assert.equal(/<link[^>]+href=|src="https?:/i.test(html), false, 'sem recursos externos');
  });
  it('sem identidade o relatório sai como antes (sem cabeçalho de cliente)', () => {
    const html = renderAwsReportHtml({ minutes: 60, generatedAt: new Date().toISOString(), alb }, ['alb'], 'Conta AWS');
    assert.equal(html.includes('class="brand-head"'), false);
  });
  it('relatório de acessos também recebe o cabeçalho', () => {
    const events = sample.events.filter((e) => e.categoryName === 'VPC Flow Logs');
    const minimal = buildAccessReport({ agg: aggregateEventsInMemory(events), vendor: 'aws', minutes: 60, sinceIso: null, dataSource: 'memory', intel, inbound: true });
    const html = renderAccessReportHtml(minimal, 'Matriz', { label: 'SonicWall', accent: '#e8590c' }, branding);
    assert.match(html, /Acme Corp/);
    assert.match(html, /<title>Acme Corp — Relatório mensal/);
  });
});
