import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildAwsContextSnapshot, buildSystemInstruction } from '../server/aiClient.ts';
import { createAwsSampleDataset } from '../server/awsSampleData.ts';
import type { AuditOverview } from '../server/types.ts';

const overview = { vendor: 'aws', appliance: { serialNumber: '111122223333', host: 'sa-east-1' }, alerts: [{ title: 'Alerta de teste' }] } as unknown as AuditOverview;

describe('contexto da IA por plataforma', () => {
  it('cada plataforma recebe o seu especialista, sem misturar conceitos', () => {
    const aws = buildSystemInstruction('aws', 'CTX');
    assert.match(aws, /AWS WAF/);
    assert.match(aws, /Application Load Balancer/);
    assert.match(aws, /NÃO é um firewall SonicWall nem FortiGate/);
    assert.equal(/especialista em Fortinet|especialista em SonicWall/.test(aws), false);

    const sw = buildSystemInstruction('sonicwall', 'CTX');
    assert.match(sw, /SonicOS/);
    assert.match(sw, /não use conceitos de FortiGate/);
    assert.equal(/AWS WAF|Application Load Balancer/.test(sw), false);

    const fg = buildSystemInstruction('fortigate', 'CTX');
    assert.match(fg, /FortiOS/);
    assert.match(fg, /não use conceitos de SonicWall/);
    assert.ok(aws.endsWith('CTX') && sw.endsWith('CTX') && fg.endsWith('CTX'));
  });

  it('o contexto da AWS resume ALB, WAF e Flow Logs e não fala de regras de firewall', () => {
    const events = createAwsSampleDataset(Date.now()).events;
    const ctx = buildAwsContextSnapshot(overview, events);
    assert.match(ctx, /CONTEXTO ATUAL DA CONTA AWS/);
    assert.match(ctx, /Conta: 111122223333 \| Região: sa-east-1/);
    assert.match(ctx, /Application Load Balancer \(access logs\)/);
    assert.match(ctx, /Regras que mais bloquearam: /);
    assert.match(ctx, /Fluxos rejeitados \(Security Group\/NACL\)/);
    assert.match(ctx, /Alertas ativos: Alerta de teste/);
    assert.equal(/Regras Firewall|NAT\/VIP|SonicOS/.test(ctx), false);
  });
});
