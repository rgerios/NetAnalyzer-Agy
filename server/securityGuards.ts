import dns from 'node:dns/promises';
import net from 'node:net';
import type { NextFunction, Request, Response } from 'express';

/**
 * Política CSP estrita para relatórios HTML estáticos baixados ou visualizados:
 * bloqueia execução de scripts, conexões externas, formulários e incorporação em iframes.
 */
export const REPORT_HTML_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'";

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Valida se uma requisição mutável (POST/PUT/PATCH/DELETE) tem origem legítima (mesmo host),
 * bloqueando ataques CSRF disparados a partir de páginas externas no navegador.
 * Clientes CLI (como curl sem cabeçalhos Origin/Sec-Fetch-Site) continuam funcionando normalmente.
 */
export function isAllowedMutationRequest(req: Pick<Request, 'method' | 'headers'>): boolean {
  const method = String(req.method || 'GET').toUpperCase();
  if (SAFE_METHODS.has(method)) return true;

  const fetchSite = String(req.headers['sec-fetch-site'] || '').trim().toLowerCase();
  if (fetchSite === 'cross-site') {
    return false;
  }

  const originHeader = String(req.headers.origin || '').trim();
  if (!originHeader) {
    return true;
  }
  if (originHeader.toLowerCase() === 'null') {
    return false;
  }

  let originHost: string;
  try {
    originHost = new URL(originHeader).host.toLowerCase();
  } catch {
    return false;
  }

  const rawHost = String(req.headers['x-forwarded-host'] || req.headers.host || '');
  const effectiveHost = rawHost.split(',')[0]?.trim().toLowerCase() || '';
  if (!effectiveHost) {
    return false;
  }

  return originHost === effectiveHost;
}

export function csrfProtectionMiddleware(req: Request, res: Response, next: NextFunction): void {
  if (!isAllowedMutationRequest(req)) {
    res.status(403).json({
      error: 'Requisição cross-site bloqueada por política de segurança (CSRF).',
    });
    return;
  }
  next();
}

const BLOCKED_INTERNAL_HOSTS = new Set([
  'db',
  'postgres',
  'postgresql',
  'backend-sonicwall',
  'backend-fortigate',
  'backend-aws',
  'frontend',
  'metadata',
  'metadata.google.internal',
  'instance-data',
]);

const PROTECTED_LOOPBACK_PORTS = new Set([3000, 3001, 3002, 5432]);

export class UnsafeOutboundUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeOutboundUrlError';
  }
}

function parseIpv4Octets(ip: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] as [
    number,
    number,
    number,
    number,
  ];
  if (octets.some((o) => o < 0 || o > 255)) return null;
  return octets;
}

function extractMappedIpv4(ipv6: string): string | null {
  const lower = ipv6.toLowerCase();
  if (!lower.startsWith('::ffff:')) return null;
  const tail = lower.slice('::ffff:'.length);
  if (parseIpv4Octets(tail)) return tail;
  const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail);
  if (!hexMatch) return null;
  const hi = parseInt(hexMatch[1], 16);
  const lo = parseInt(hexMatch[2], 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

function checkIpSafety(ip: string, port: number, allowLoopback: boolean, label: string): void {
  const clean = ip.replace(/^\[|\]$/g, '').split('%')[0].trim().toLowerCase();
  const mappedV4 = extractMappedIpv4(clean);
  const target = mappedV4 ?? clean;

  const v4 = parseIpv4Octets(target);
  if (v4) {
    const [a, b, c, d] = v4;
    if (a === 0) {
      throw new UnsafeOutboundUrlError(`Endereço inválido (0.0.0.0/8) não permitido para ${label}.`);
    }
    // Link-local e IMDS de nuvem (169.254.169.254, ECS 169.254.170.2) + Alibaba IMDS (100.100.100.200)
    if ((a === 169 && b === 254) || (a === 100 && b === 100 && c === 100 && d === 200)) {
      throw new UnsafeOutboundUrlError(
        `Endereço de metadata/link-local (${target}) bloqueado para ${label}.`
      );
    }
    if (a === 127) {
      if (!allowLoopback) {
        throw new UnsafeOutboundUrlError(
          `Endereço de loopback (${target}) não permitido para ${label}.`
        );
      }
      if (PROTECTED_LOOPBACK_PORTS.has(port)) {
        throw new UnsafeOutboundUrlError(
          `Porta interna do serviço (${port}) não permitida em loopback para ${label}.`
        );
      }
    }
    return;
  }

  if (net.isIPv6(target)) {
    if (target === '::' || target === '0:0:0:0:0:0:0:0') {
      throw new UnsafeOutboundUrlError(`Endereço IPv6 não especificado bloqueado para ${label}.`);
    }
    if (
      target.startsWith('fe8') ||
      target.startsWith('fe9') ||
      target.startsWith('fea') ||
      target.startsWith('feb') ||
      target === 'fd00:ec2::254'
    ) {
      throw new UnsafeOutboundUrlError(
        `Endereço IPv6 de metadata/link-local bloqueado para ${label}.`
      );
    }
    if (target === '::1' || target === '0:0:0:0:0:0:0:1') {
      if (!allowLoopback) {
        throw new UnsafeOutboundUrlError(`Endereço de loopback (::1) não permitido para ${label}.`);
      }
      if (PROTECTED_LOOPBACK_PORTS.has(port)) {
        throw new UnsafeOutboundUrlError(
          `Porta interna do serviço (${port}) não permitida em loopback para ${label}.`
        );
      }
    }
  }
}

export interface OutboundUrlCheckOptions {
  allowLoopback?: boolean;
  resolveDns?: boolean;
  label?: string;
}

/**
 * Valida URLs de saída configuráveis pelo usuário (webhooks, endpoints customizados de IA)
 * contra SSRF para serviços internos da stack Docker, loopback e endpoints de metadata de nuvem.
 */
export async function assertSafeOutboundUrl(
  rawUrl: string,
  options: OutboundUrlCheckOptions = {}
): Promise<URL> {
  const label = options.label ?? 'URL externa';
  const allowLoopback = Boolean(options.allowLoopback);
  const resolveDns = options.resolveDns !== false;

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new UnsafeOutboundUrlError(`Formato inválido de ${label}.`);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new UnsafeOutboundUrlError(`Protocolo não suportado em ${label} (use http ou https).`);
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!host) {
    throw new UnsafeOutboundUrlError(`Host ausente em ${label}.`);
  }

  const port = parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;

  if (BLOCKED_INTERNAL_HOSTS.has(host) || host.endsWith('.internal')) {
    throw new UnsafeOutboundUrlError(`Host interno (${host}) bloqueado para ${label}.`);
  }

  if (host === 'localhost' || host.endsWith('.localhost')) {
    if (!allowLoopback) {
      throw new UnsafeOutboundUrlError(`Host local (${host}) não permitido para ${label}.`);
    }
    if (PROTECTED_LOOPBACK_PORTS.has(port)) {
      throw new UnsafeOutboundUrlError(
        `Porta interna do serviço (${port}) não permitida em localhost para ${label}.`
      );
    }
    return parsed;
  }

  if (net.isIP(host)) {
    checkIpSafety(host, port, allowLoopback, label);
    return parsed;
  }

  if (resolveDns) {
    let records: Array<{ address: string }>;
    try {
      records = await dns.lookup(host, { all: true, verbatim: true });
    } catch {
      throw new UnsafeOutboundUrlError(`Não foi possível resolver o host "${host}" para ${label}.`);
    }
    if (records.length === 0) {
      throw new UnsafeOutboundUrlError(`Nenhum endereço encontrado para "${host}" em ${label}.`);
    }
    for (const rec of records) {
      checkIpSafety(rec.address, port, allowLoopback, label);
    }
  }

  return parsed;
}
