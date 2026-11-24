import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import zlib from 'node:zlib';
import type { Request, Response } from 'express';
import { AuthManager } from '../server/authManager.ts';
import { PostgresStore } from '../server/database.ts';
import {
  httpCompressionMiddleware,
  pickAcceptedEncoding,
} from '../server/httpCompression.ts';
import { createVendorEngine } from '../server/vendorEngine.ts';
import { allCountries, countryName, flagEmoji } from '../src/utils/countryNames.ts';

describe('httpCompressionMiddleware (Brotli e Gzip nativos)', () => {
  it('seleciona br ou gzip respeitando q=0', () => {
    assert.equal(pickAcceptedEncoding('gzip, deflate, br'), 'br');
    assert.equal(pickAcceptedEncoding('gzip, deflate'), 'gzip');
    assert.equal(pickAcceptedEncoding('br;q=0, gzip;q=1.0'), 'gzip');
    assert.equal(pickAcceptedEncoding('br;q=0, gzip;q=0'), null);
    assert.equal(pickAcceptedEncoding(undefined), null);
  });

  it('comprime JSON grande com Brotli e Gzip e preserva payloads pequenos ou binários', async () => {
    const runSend = (opts: {
      acceptEncoding?: string;
      contentType: string;
      body: string | Buffer;
    }) =>
      new Promise<{ headers: Record<string, string>; payload: Buffer }>((resolve) => {
        const headers: Record<string, string> = { 'content-type': opts.contentType };
        const req = {
          method: 'GET',
          headers: opts.acceptEncoding ? { 'accept-encoding': opts.acceptEncoding } : {},
        } as unknown as Request;

        const mockRes = {
          statusCode: 200,
          headersSent: false,
          writableEnded: false,
          getHeader(k: string) {
            return headers[k.toLowerCase()];
          },
          setHeader(k: string, v: string) {
            headers[k.toLowerCase()] = String(v);
            return mockRes;
          },
          send(chunk: unknown) {
            mockRes.headersSent = true;
            mockRes.writableEnded = true;
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
            resolve({ headers, payload: buf });
            return mockRes;
          },
        };
        const res = mockRes as unknown as Response;

        httpCompressionMiddleware(req, res, () => {
          res.send(opts.body);
        });
      });

    const bigJson = JSON.stringify({
      items: Array.from({ length: 200 }, (_, i) => ({
        id: `ev-${i}`,
        srcIp: '10.20.30.40',
        dstIp: '198.51.100.10',
        message: 'Connection Closed with repeated payload text for compression ratio check',
      })),
    });

    const brRes = await runSend({
      acceptEncoding: 'gzip, br',
      contentType: 'application/json; charset=utf-8',
      body: bigJson,
    });
    assert.equal(brRes.headers['content-encoding'], 'br');
    assert.match(brRes.headers['vary'] ?? '', /Accept-Encoding/i);
    assert.ok(brRes.payload.byteLength < Buffer.byteLength(bigJson) * 0.25);
    assert.equal(zlib.brotliDecompressSync(brRes.payload).toString('utf8'), bigJson);

    const gzRes = await runSend({
      acceptEncoding: 'gzip',
      contentType: 'application/json; charset=utf-8',
      body: bigJson,
    });
    assert.equal(gzRes.headers['content-encoding'], 'gzip');
    assert.equal(zlib.gunzipSync(gzRes.payload).toString('utf8'), bigJson);

    // Payload pequeno (< 1 KB) não gasta CPU comprimindo
    const smallRes = await runSend({
      acceptEncoding: 'br',
      contentType: 'application/json',
      body: '{"ok":true}',
    });
    assert.equal(smallRes.headers['content-encoding'], undefined);
    assert.equal(smallRes.payload.toString('utf8'), '{"ok":true}');

    // Binário PCAP nunca é recomprimido
    const pcapBuf = Buffer.alloc(4096, 0xa1);
    const binRes = await runSend({
      acceptEncoding: 'br, gzip',
      contentType: 'application/vnd.tcpdump.pcap',
      body: pcapBuf,
    });
    assert.equal(binRes.headers['content-encoding'], undefined);
    assert.equal(binRes.payload.byteLength, 4096);
  });
});

describe('countryNames desacoplado de worldGeo', () => {
  it('resolve nomes em português, bandeiras emoji e lista ordenada', () => {
    assert.equal(countryName('BR'), 'Brasil');
    assert.equal(flagEmoji('BR'), '🇧🇷');
    assert.equal(flagEmoji('invalid'), '');
    const list = allCountries();
    assert.ok(list.length > 200);
    assert.ok(list.some((c) => c.code === 'BR' && c.name === 'Brasil'));
  });
});

describe('cache de buildOverview e truncamento da janela em memória', () => {
  it('mantém contadores de regras/NATs consistentes após carregar amostra e limpar dados', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'netanalyzer-perf-'));
    const prevIntel = process.env.INTEL_AUTO_UPDATE;
    const prevUdp = process.env.SYSLOG_UDP_AUTOSTART;
    process.env.INTEL_AUTO_UPDATE = 'false';
    process.env.SYSLOG_UDP_AUTOSTART = 'false';
    try {
      const pgStore = new PostgresStore('');
      const auth = new AuthManager(tmpDir, pgStore);
      await auth.init();
      const eng = createVendorEngine({
        vendor: 'sonicwall',
        dataDir: tmpDir,
        pgStore,
        authManager: auth,
      });
      await eng.init();

      const callRoute = (method: 'GET' | 'POST', urlPath: string) =>
        new Promise<{ status: number; body: Record<string, unknown> }>((resolve, reject) => {
          let status = 200;
          const req = {
            method,
            url: urlPath,
            originalUrl: urlPath,
            path: urlPath,
            query: {},
            headers: {},
            params: {},
            body: {},
          };
          const res = {
            headersSent: false,
            status(c: number) {
              status = c;
              return this;
            },
            setHeader() {
              return this;
            },
            json(payload: unknown) {
              this.headersSent = true;
              resolve({ status, body: payload as Record<string, unknown> });
              return this;
            },
          };
          (eng.router as unknown as (q: unknown, s: unknown, n: (e?: unknown) => void) => void)(
            req,
            res,
            (err) => (err ? reject(err) : resolve({ status: 404, body: {} }))
          );
        });

      const loaded = await callRoute('POST', '/sample/load');
      assert.equal(loaded.status, 200);

      const ov1 = await callRoute('GET', '/overview');
      const ov2 = await callRoute('GET', '/overview');
      const rulesSummary1 = ov1.body.rulesSummary as { total: number };
      const rulesSummary2 = ov2.body.rulesSummary as { total: number };
      assert.ok(rulesSummary1.total > 0);
      assert.deepEqual(rulesSummary1, rulesSummary2);

      const cleared = await callRoute('POST', '/data/clear');
      assert.equal(cleared.status, 200);
      const ovAfterClear = await callRoute('GET', '/overview');
      assert.equal((ovAfterClear.body.rulesSummary as { total: number }).total, 0);
      assert.equal(ovAfterClear.body.totalSyslogs, 0);

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
