/**
 * Rotas da aba "Análise PCAP". Independem do fabricante: são registradas nos dois motores
 * (SonicWall e FortiGate), já atrás da autenticação do roteador.
 */
import type express from 'express';
import type { PcapUploadResult } from '../../shared/pcap.ts';
import { buildDetail } from './detail.ts';
import { followTcpStream } from './analysis.ts';
import { FIELD_NAMES, FILTER_EXAMPLES, FilterError } from './filter.ts';
import { PcapFormatError } from './reader.ts';
import { PcapSessionStore } from './session.ts';

export const PCAP_CONTENT_TYPE = 'application/vnd.tcpdump.pcap';

function readBody(req: express.Request, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > maxBytes) {
      req.resume();
      reject(new PcapFormatError(`Arquivo maior que o limite de ${Math.round(maxBytes / 1048576)} MB.`));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let failed = false;
    req.on('data', (c: Buffer) => {
      if (failed) return;
      size += c.length;
      if (size > maxBytes) {
        failed = true;
        reject(new PcapFormatError(`Arquivo maior que o limite de ${Math.round(maxBytes / 1048576)} MB.`));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!failed) resolve(Buffer.concat(chunks, size));
    });
    req.on('error', (err) => {
      if (!failed) reject(err);
    });
  });
}

export function registerPcapRoutes(
  router: express.Router,
  opts: { vendor: string; logError: (message: string, detail?: string) => void }
): { stop: () => void } {
  const maxFileBytes = (Number(process.env.PCAP_MAX_FILE_MB) || 300) * 1048576;
  const store = new PcapSessionStore({
    maxPackets: Number(process.env.PCAP_MAX_PACKETS) || 1_000_000,
    maxSessions: 3,
    idleMs: 60 * 60 * 1000,
  });

  const handle =
    (fn: (req: express.Request, res: express.Response) => Promise<void> | void) =>
    (req: express.Request, res: express.Response) => {
      Promise.resolve()
        .then(() => fn(req, res))
        .catch((err: unknown) => {
          if (res.headersSent) return;
          if (err instanceof FilterError) {
            res.status(400).json({ error: err.message, code: 'filter', pos: err.pos });
            return;
          }
          if (err instanceof PcapFormatError) {
            res.status(400).json({ error: err.message, code: 'format' });
            return;
          }
          const msg = err instanceof Error ? err.message : String(err);
          opts.logError(`Erro na análise de PCAP`, msg);
          res.status(500).json({ error: 'Erro interno ao analisar a captura.' });
        });
    };

  const sessionOf = (req: express.Request, res: express.Response) => {
    const s = store.get(String(req.params.id));
    if (!s) {
      res.status(404).json({ error: 'A sessão de análise expirou. Envie os arquivos novamente.', code: 'expired' });
      return null;
    }
    return s;
  };

  router.get('/pcap/help', (_req, res) => {
    res.json({ examples: FILTER_EXAMPLES, fields: FIELD_NAMES, maxFileMb: Math.round(maxFileBytes / 1048576) });
  });

  router.post(
    '/pcap/upload',
    handle(async (req, res) => {
      const rawName = String(req.query.name || 'captura.pcap');
      const name = rawName.replace(/[^\w.\- ()]/g, '_').slice(0, 120) || 'captura.pcap';
      const body = await readBody(req, maxFileBytes);
      let session = req.query.session ? store.get(String(req.query.session)) : undefined;
      if (req.query.session && !session) {
        res.status(404).json({ error: 'A sessão de análise expirou. Envie os arquivos novamente.', code: 'expired' });
        return;
      }
      const created = !session;
      if (!session) session = store.create();
      try {
        const added = await session.addFile(name, body);
        const payload: PcapUploadResult = { session: session.info(), added };
        res.json(payload);
      } catch (err) {
        if (created) store.delete(session.id);
        throw err;
      }
    })
  );

  router.get('/pcap/sessions/:id', handle((req, res) => {
    const s = sessionOf(req, res);
    if (s) res.json(s.info());
  }));

  router.delete('/pcap/sessions/:id', handle((req, res) => {
    store.delete(String(req.params.id));
    res.json({ ok: true });
  }));

  router.delete('/pcap/sessions/:id/files/:idx', handle(async (req, res) => {
    const s = sessionOf(req, res);
    if (!s) return;
    const ok = await s.removeFile(Number(req.params.idx));
    if (!ok) {
      res.status(404).json({ error: 'Arquivo não encontrado na sessão.' });
      return;
    }
    if (s.parts.length === 0) store.delete(s.id);
    res.json(s.parts.length ? s.info() : { ok: true, empty: true });
  }));

  router.get('/pcap/sessions/:id/packets', handle((req, res) => {
    const s = sessionOf(req, res);
    if (!s) return;
    const offset = Math.max(0, Number(req.query.offset) || 0);
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit) || 300));
    res.json(s.page(String(req.query.filter || ''), offset, limit));
  }));

  router.get('/pcap/sessions/:id/packets/:no', handle((req, res) => {
    const s = sessionOf(req, res);
    if (!s) return;
    const p = s.packetByNo(Number(req.params.no));
    if (!p) {
      res.status(404).json({ error: 'Pacote não encontrado.' });
      return;
    }
    res.json(buildDetail(p));
  }));

  router.get('/pcap/sessions/:id/summary', handle((req, res) => {
    const s = sessionOf(req, res);
    if (!s) return;
    res.json(s.summary(String(req.query.filter || '')));
  }));

  router.get('/pcap/sessions/:id/stream/:sid', handle((req, res) => {
    const s = sessionOf(req, res);
    if (!s) return;
    const view = followTcpStream(s.packets, s.index, Number(req.params.sid));
    if (!view) {
      res.status(404).json({ error: 'Stream TCP não encontrado.' });
      return;
    }
    res.json(view);
  }));

  router.get('/pcap/sessions/:id/export', handle((req, res) => {
    const s = sessionOf(req, res);
    if (!s) return;
    const buf = s.exportPcap(String(req.query.filter || ''));
    res.setHeader('Content-Type', PCAP_CONTENT_TYPE);
    res.setHeader('Content-Disposition', 'attachment; filename="filtrado.pcap"');
    res.setHeader('Content-Length', String(buf.length));
    res.end(buf);
  }));

  return { stop: () => store.stop() };
}
