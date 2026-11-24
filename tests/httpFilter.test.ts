import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { httpFilterMatches, parseHttpFilter } from '../server/httpFilter.ts';
import { createAwsSampleDataset } from '../server/awsSampleData.ts';

const events = createAwsSampleDataset(Date.parse('2026-11-24T15:00:00Z')).events;
const alb = events.filter((e) => e.categoryName === 'Application Load Balancer' && e.meta?.method !== undefined);
const waf = events.filter((e) => e.categoryName === 'AWS WAF');
const count = (list: typeof events, q: Record<string, string>) => {
  const f = parseHttpFilter(q);
  return f ? list.filter((e) => httpFilterMatches(e, f)).length : list.length;
};

describe('filtros de eventos (ALB e WAF)', () => {
  it('sem filtro informado não filtra e ignora lixo', () => {
    assert.equal(parseHttpFilter({}), null);
    assert.equal(parseHttpFilter({ method: "1;2", status: 'abc', wafAction: 'XYZ' }), null);
  });

  it('ALB: método, status exato e por classe, host, endpoint e IP do target', () => {
    const post = count(alb, { method: 'POST' });
    assert.ok(post > 0 && post < alb.length);
    assert.equal(count(alb, { method: 'post' }), post, 'método não diferencia maiúsculas');
    const s5 = count(alb, { status: '5xx' });
    assert.equal(s5, alb.filter((e) => String(e.meta?.status).startsWith('5')).length);
    assert.equal(count(alb, { status: '500,502' }), alb.filter((e) => ['500', '502'].includes(String(e.meta?.status))).length);
    assert.ok(count(alb, { host: 'rgerios.corp' }) === alb.length);
    assert.equal(count(alb, { host: 'nao-existe' }), 0);
    assert.ok(count(alb, { endpoint: '/health' }) > 0);
    assert.ok(count(alb, { endpoint: '{id}' }) > 0, 'aceita o endpoint agrupado');
    const ip = String(alb[0].meta?.targetIp || '');
    assert.ok(ip && count(alb, { targetIp: ip }) >= 1);
    assert.ok(count(alb, { targetGroup: 'tg-vendas' }) >= 1);
  });

  it('WAF: ação, regra, Web ACL, host e método', () => {
    const blocked = count(waf, { wafAction: 'BLOCK' });
    assert.equal(blocked, waf.filter((e) => e.meta?.wafAction === 'BLOCK').length);
    assert.ok(blocked > 0 && blocked < waf.length);
    assert.equal(count(waf, { wafAction: 'ALLOW,BLOCK' }), waf.length);
    const rule = String(waf.find((e) => e.meta?.wafAction === 'BLOCK')?.meta?.ruleId || '');
    assert.ok(rule && count(waf, { ruleId: rule.slice(0, 6) }) >= 1);
    assert.ok(count(waf, { webAcl: 'prod-web-acl' }) === waf.length);
    assert.ok(count(waf, { host: 'rgerios.corp', method: 'GET' }) > 0);
  });

  it('filtro de HTTP descarta eventos que não são requisições (ex.: conexões TLS e Flow Logs)', () => {
    const f = parseHttpFilter({ host: 'rgerios' })!;
    const others = events.filter((e) => e.categoryName === 'VPC Flow Logs' || e.meta?.connection === true);
    assert.equal(others.filter((e) => httpFilterMatches(e, f)).length, 0);
  });
});
