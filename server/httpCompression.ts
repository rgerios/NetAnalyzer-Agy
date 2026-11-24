import { promisify } from 'node:util';
import zlib from 'node:zlib';
import type { NextFunction, Request, Response } from 'express';

const brotliAsync = promisify(zlib.brotliCompress);
const gzipAsync = promisify(zlib.gzip);

const MIN_COMPRESS_BYTES = 1024;
const COMPRESSIBLE_TYPE_RE =
  /^(?:application\/(?:json|javascript|xml)|text\/(?:html|plain|css|csv|markdown|xml)|image\/svg\+xml)\b/i;

function appendVaryHeader(res: Response, field: string): void {
  const existing = res.getHeader('Vary');
  if (!existing) {
    res.setHeader('Vary', field);
    return;
  }
  const current = Array.isArray(existing) ? existing.join(', ') : String(existing);
  const parts = current.split(',').map((s) => s.trim().toLowerCase());
  if (!parts.includes(field.toLowerCase())) {
    res.setHeader('Vary', `${current}, ${field}`);
  }
}

export function pickAcceptedEncoding(acceptHeader: string | undefined): 'br' | 'gzip' | null {
  if (!acceptHeader) return null;
  const lower = acceptHeader.toLowerCase();
  // Rejeita quando q=0 explícito
  if (/\bbr\b(?![^,]*;\s*q=0(?:\.0+)?\b)/.test(lower)) return 'br';
  if (/\bgzip\b(?![^,]*;\s*q=0(?:\.0+)?\b)/.test(lower)) return 'gzip';
  return null;
}

/**
 * Middleware leve de compressão HTTP usando node:zlib nativo em threadpool C++ (sem dependências).
 * Intercepta respostas JSON/HTML/texto >= 1 KB enviadas via res.send / res.json, reduzindo em
 * 80%–92% o tráfego de payloads grandes (/syslogs, /overview, /report, /behavior, /destinations).
 */
export function httpCompressionMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (req.method === 'HEAD') {
    next();
    return;
  }

  const encoding = pickAcceptedEncoding(req.headers['accept-encoding']);
  if (!encoding) {
    next();
    return;
  }

  const origSend = res.send.bind(res);
  let compressing = false;

  res.send = function compressedSend(body?: unknown): Response {
    if (
      compressing ||
      res.headersSent ||
      res.statusCode === 204 ||
      res.statusCode === 304 ||
      Boolean(res.getHeader('Content-Encoding'))
    ) {
      return origSend(body);
    }

    let rawBuf: Buffer | null = null;
    if (Buffer.isBuffer(body)) {
      rawBuf = body;
    } else if (typeof body === 'string') {
      if (!res.getHeader('Content-Type')) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
      }
      rawBuf = Buffer.from(body, 'utf8');
    } else if (body !== undefined && body !== null && typeof body === 'object') {
      if (!res.getHeader('Content-Type')) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
      }
      rawBuf = Buffer.from(JSON.stringify(body), 'utf8');
    }

    if (!rawBuf) {
      return origSend(body);
    }

    const contentType = String(res.getHeader('Content-Type') || '');
    if (!COMPRESSIBLE_TYPE_RE.test(contentType)) {
      return origSend(body);
    }

    appendVaryHeader(res, 'Accept-Encoding');

    if (rawBuf.byteLength < MIN_COMPRESS_BYTES) {
      return origSend(rawBuf);
    }

    compressing = true;
    const compressPromise =
      encoding === 'br'
        ? brotliAsync(rawBuf, {
            params: {
              [zlib.constants.BROTLI_PARAM_QUALITY]: 4,
              [zlib.constants.BROTLI_PARAM_SIZE_HINT]: rawBuf.byteLength,
            },
          })
        : gzipAsync(rawBuf, { level: zlib.constants.Z_DEFAULT_COMPRESSION });

    compressPromise
      .then((compressed) => {
        if (res.headersSent || res.writableEnded) return;
        if (compressed.byteLength < rawBuf.byteLength) {
          res.setHeader('Content-Encoding', encoding);
          res.setHeader('Content-Length', String(compressed.byteLength));
          origSend(compressed);
        } else {
          origSend(rawBuf);
        }
      })
      .catch(() => {
        if (!res.headersSent && !res.writableEnded) {
          origSend(rawBuf);
        }
      });

    return res;
  };

  next();
}
