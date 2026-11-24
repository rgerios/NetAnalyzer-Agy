import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { AuthManager } from '../server/authManager.ts';
import { PostgresStore } from '../server/database.ts';
import { formatNotificationText } from '../server/notifier.ts';
import {
  assertSafeOutboundUrl,
  isAllowedMutationRequest,
  REPORT_HTML_CSP,
  UnsafeOutboundUrlError,
} from '../server/securityGuards.ts';
import { createVendorEngine } from '../server/vendorEngine.ts';

describe('notifier vendorLabel por ambiente', () => {
  it('identifica corretamente SonicWall, FortiGate e AWS nas mensagens', () => {
    const sw = formatNotificationText({
      kind: 'test',
      vendor: 'sonicwall',
      siteName: 'Matriz',
      alerts: [],
    });
    const fg = formatNotificationText({
      kind: 'test',
      vendor: 'fortigate',
      siteName: 'Filial',
      alerts: [],
    });
    const aws = formatNotificationText({
      kind: 'test',
      vendor: 'aws',
      siteName: 'Prod AWS',
      alerts: [],
    });

    assert.match(sw, /\(SonicWall · Matriz\)/);
    assert.match(fg, /\(FortiGate · Filial\)/);
    assert.match(aws, /\(AWS · Prod AWS\)/);
    assert.doesNotMatch(aws, /SonicWall/);
  });
});

describe('proteção CSRF (isAllowedMutationRequest)', () => {
  it('permite métodos somente leitura e chamadas CLI sem Origin', () => {
    assert.equal(
      isAllowedMutationRequest({
        method: 'GET',
        headers: { origin: 'https://evil.example', host: 'painel.local' },
      }),
      true
    );
    assert.equal(
      isAllowedMutationRequest({
        method: 'POST',
        headers: { host: 'painel.local' },
      }),
      true
    );
  });

  it('permite POST do mesmo host e bloqueia cross-site ou Origin divergente', () => {
    assert.equal(
      isAllowedMutationRequest({
        method: 'POST',
        headers: { origin: 'https://painel.local:8443', host: 'painel.local:8443' },
      }),
      true
    );
    assert.equal(
      isAllowedMutationRequest({
        method: 'POST',
        headers: {
          origin: 'https://painel.local',
          host: 'backend-sonicwall:3000',
          'x-forwarded-host': 'painel.local',
        },
      }),
      true
    );
    assert.equal(
      isAllowedMutationRequest({
        method: 'POST',
        headers: { origin: 'https://evil.example', host: 'painel.local' },
      }),
      false
    );
    assert.equal(
      isAllowedMutationRequest({
        method: 'DELETE',
        headers: { origin: 'null', host: 'painel.local' },
      }),
      false
    );
    assert.equal(
      isAllowedMutationRequest({
        method: 'PUT',
        headers: { 'sec-fetch-site': 'cross-site', host: 'painel.local' },
      }),
      false
    );
  });
});

describe('proteção SSRF (assertSafeOutboundUrl) e CSP de relatórios', () => {
  it('bloqueia metadata de nuvem, containers internos e loopback não autorizado', async () => {
    const blocked = [
      'http://169.254.169.254/latest/meta-data/',
      'http://[::ffff:169.254.169.254]/latest/meta-data/',
      'http://[::ffff:a9fe:a9fe]/latest/meta-data/',
      'http://[fd00:ec2::254]/latest/meta-data/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://db:5432/',
      'http://backend-aws:3002/api/health',
      'http://127.0.0.1:8080/hook',
      'http://localhost:8080/hook',
      'ftp://hooks.slack.com/services/T00/B00/XX',
    ];

    for (const url of blocked) {
      await assert.rejects(
        () => assertSafeOutboundUrl(url, { resolveDns: false }),
        UnsafeOutboundUrlError,
        `Deveria bloquear: ${url}`
      );
    }
  });

  it('permite HTTPS externo e Ollama local, mas protege portas internas em loopback', async () => {
    const okWebhook = await assertSafeOutboundUrl('https://hooks.slack.com/services/T00/B00/XX', {
      resolveDns: false,
    });
    assert.equal(okWebhook.hostname, 'hooks.slack.com');

    const okOllama = await assertSafeOutboundUrl('http://127.0.0.1:11434/v1/chat/completions', {
      allowLoopback: true,
      resolveDns: false,
    });
    assert.equal(okOllama.port, '11434');

    await assert.rejects(
      () =>
        assertSafeOutboundUrl('http://127.0.0.1:5432/v1', {
          allowLoopback: true,
          resolveDns: false,
        }),
      UnsafeOutboundUrlError
    );
    await assert.rejects(
      () =>
        assertSafeOutboundUrl('http://localhost:3000/api/health', {
          allowLoopback: true,
          resolveDns: false,
        }),
      UnsafeOutboundUrlError
    );
    assert.match(REPORT_HTML_CSP, /default-src 'none'/);
  });
});

describe('AuthManager variáveis NETANALYZER_ADMIN_*', () => {
  it('cria administrador inicial via NETANALYZER_ADMIN_USER e NETANALYZER_ADMIN_PASS', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'netanalyzer-auth-'));
    const prevUser = process.env.NETANALYZER_ADMIN_USER;
    const prevPass = process.env.NETANALYZER_ADMIN_PASS;
    process.env.NETANALYZER_ADMIN_USER = 'netadmin';
    process.env.NETANALYZER_ADMIN_PASS = 'Sup3rS3cur3Pass!';
    try {
      const auth = new AuthManager(tmpDir);
      await auth.init();
      assert.equal(auth.needsSetup(), false);
      assert.equal(await auth.authenticateUser('netadmin', 'Sup3rS3cur3Pass!'), 'netadmin');
    } finally {
      if (prevUser === undefined) delete process.env.NETANALYZER_ADMIN_USER;
      else process.env.NETANALYZER_ADMIN_USER = prevUser;
      if (prevPass === undefined) delete process.env.NETANALYZER_ADMIN_PASS;
      else process.env.NETANALYZER_ADMIN_PASS = prevPass;
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('createVendorEngine rotas modularizadas, CSP e shutdown limpo', () => {
  it('monta sub-rotas, aplica CSP nos relatórios HTML e encerra sem timers pendentes', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'netanalyzer-engine-'));
    const prevIntel = process.env.INTEL_AUTO_UPDATE;
    const prevUdp = process.env.SYSLOG_UDP_AUTOSTART;
    process.env.INTEL_AUTO_UPDATE = 'false';
    process.env.SYSLOG_UDP_AUTOSTART = 'false';
    try {
      const pgStore = new PostgresStore('');
      const auth = new AuthManager(tmpDir, pgStore);
      await auth.init();
      const eng = createVendorEngine({
        vendor: 'aws',
        dataDir: tmpDir,
        pgStore,
        authManager: auth,
      });
      await eng.init();

      const invokeGet = (urlPath: string) =>
        new Promise<{ status: number; headers: Record<string, string>; body: string }>(
          (resolve, reject) => {
            const headers: Record<string, string> = {};
            let status = 200;
            const parsed = new URL(urlPath, 'http://localhost');
            const query: Record<string, string> = {};
            parsed.searchParams.forEach((v, k) => {
              query[k] = v;
            });
            const req = {
              method: 'GET',
              url: urlPath,
              originalUrl: urlPath,
              path: parsed.pathname,
              query,
              headers: {},
              params: {},
            };
            const res = {
              headersSent: false,
              status(code: number) {
                status = code;
                return this;
              },
              setHeader(k: string, v: string) {
                headers[k.toLowerCase()] = String(v);
                return this;
              },
              getHeader(k: string) {
                return headers[k.toLowerCase()];
              },
              json(payload: unknown) {
                this.headersSent = true;
                resolve({ status, headers, body: JSON.stringify(payload) });
                return this;
              },
              send(payload: unknown) {
                this.headersSent = true;
                resolve({ status, headers, body: String(payload) });
                return this;
              },
            };
            (eng.router as unknown as (q: unknown, s: unknown, n: (e?: unknown) => void) => void)(
              req,
              res,
              (err) => {
                if (err) reject(err);
                else resolve({ status: 404, headers, body: '' });
              }
            );
          }
        );

      const auditHtml = await invokeGet('/report/download?format=html');
      assert.equal(auditHtml.status, 200);
      assert.equal(auditHtml.headers['content-security-policy'], REPORT_HTML_CSP);
      assert.match(auditHtml.headers['content-disposition'] ?? '', /netanalyzer-aws-/);

      const accessHtml = await invokeGet('/access-report/html?minutes=60');
      assert.equal(accessHtml.status, 200);
      assert.equal(accessHtml.headers['content-security-policy'], REPORT_HTML_CSP);

      const awsHtml = await invokeGet('/cloud/report/html?minutes=60&sections=waf');
      assert.equal(awsHtml.status, 200);
      assert.equal(awsHtml.headers['content-security-policy'], REPORT_HTML_CSP);

      const appLogs = await invokeGet('/app-logs');
      assert.equal(appLogs.status, 200);

      await eng.shutdown();
    } finally {
      if (prevIntel === undefined) delete process.env.INTEL_AUTO_UPDATE;
      else process.env.INTEL_AUTO_UPDATE = prevIntel;
      if (prevUdp === undefined) delete process.env.SYSLOG_UDP_AUTOSTART;
      else process.env.SYSLOG_UDP_AUTOSTART = prevUdp;
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});
