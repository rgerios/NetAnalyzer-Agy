import type { Pool } from 'pg';
import { facetSql, ITEM_LIMIT_FOR_DB, type FacetField } from './facets.ts';

/**
 * Pistas de FQDN e categoria que o firewall registra no texto original do log (mesmas chaves de
 * extractDestinationHints). A checagem com position() evita rodar a expressão regular nas linhas
 * que nem têm a chave, que são a maioria.
 */
function rawKv(key: string): string {
  const raw = `(payload_json->>'raw')`;
  return `CASE WHEN position('${key}=' in ${raw}) > 0 THEN COALESCE(substring(${raw} from '\\m${key}="([^"]*)"'), substring(${raw} from '\\m${key}=([^" ]+)')) END`;
}

const HOST_HINT_SQL = `COALESCE(${['dstname', 'dst_name', 'dsthost', 'hostname', 'dstdomain', 'fqdn', 'domain', 'url'].map(rawKv).join(', ')}, '')`;
const APPCAT_HINT_SQL = `COALESCE(${['appcat', 'catdesc'].map(rawKv).join(', ')}, '')`;

/**
 * Agregação para o relatório de acessos: agrupa no banco (sem trazer milhões de linhas ao Node).
 * Respeita o teto de tempo das buscas; se estourar, devolve o que foi possível e timedOut = true.
 */
export async function aggregateAccessDb(
  pool: Pool,
  siteId: string,
  sinceIso: string,
  groupLimit = 60_000,
  timeoutOverrideMs?: number
): Promise<{
  groups: Array<{
    src: string;
    dst: string;
    proto: string;
    port: string;
    app: string;
    blocked: boolean;
    host: string;
    c: number;
    up: number;
    down: number;
  }>;
  hours: Array<{ t: string; c: number; blocked: number; up: number; down: number }>;
  totalEvents: number;
  timedOut: boolean;
}> {
  const timeoutMs =
    timeoutOverrideMs === 0
      ? 0
      : Math.max(5000, timeoutOverrideMs ?? (Number(process.env.REPORT_QUERY_TIMEOUT_MS) || 60_000));
  const bytes = (key: string) => `COALESCE(NULLIF(payload_json->>'${key}', '')::numeric, 0)`;
  const base = `site_id = $1 AND event_at >= $2 AND action <> 'system'`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(timeoutMs)}`);
    const groups = await client.query(
      `SELECT payload_json->>'srcIp' AS src, payload_json->>'dstIp' AS dst,
              COALESCE(payload_json->>'protocol', '') AS proto, COALESCE(payload_json->>'dstPort', '') AS port,
              COALESCE(payload_json->>'appName', '') AS app,
              (action IN ('drop','deny','reset')) AS blocked,
              ${HOST_HINT_SQL} AS host,
              count(*)::bigint AS c, sum(${bytes('bytesSent')})::bigint AS up, sum(${bytes('bytesRcvd')})::bigint AS down
         FROM syslogs WHERE ${base}
          AND COALESCE(payload_json->>'srcIp', '') NOT IN ('', '-') AND COALESCE(payload_json->>'dstIp', '') NOT IN ('', '-')
        GROUP BY 1,2,3,4,5,6,7 ORDER BY c DESC LIMIT $3`,
      [siteId, sinceIso, groupLimit]
    );
    const hours = await client.query(
      `SELECT date_trunc('hour', event_at) AS t, count(*)::bigint AS c,
              count(*) FILTER (WHERE action IN ('drop','deny','reset'))::bigint AS blocked,
              sum(${bytes('bytesSent')})::bigint AS up, sum(${bytes('bytesRcvd')})::bigint AS down
         FROM syslogs WHERE ${base} GROUP BY 1 ORDER BY 1`,
      [siteId, sinceIso]
    );
    const total = await client.query(
      `SELECT count(*)::bigint AS n FROM syslogs WHERE ${base}
          AND COALESCE(payload_json->>'srcIp', '') NOT IN ('', '-') AND COALESCE(payload_json->>'dstIp', '') NOT IN ('', '-')`,
      [siteId, sinceIso]
    );
    await client.query('COMMIT');
    return {
      groups: groups.rows.map((r) => ({
        src: String(r.src),
        dst: String(r.dst),
        proto: String(r.proto),
        port: String(r.port),
        app: String(r.app),
        blocked: Boolean(r.blocked),
        host: String(r.host ?? ''),
        c: Number(r.c),
        up: Number(r.up ?? 0),
        down: Number(r.down ?? 0),
      })),
      hours: hours.rows.map((r) => ({
        t: new Date(r.t).toISOString(),
        c: Number(r.c),
        blocked: Number(r.blocked),
        up: Number(r.up ?? 0),
        down: Number(r.down ?? 0),
      })),
      totalEvents: Number(total.rows[0]?.n ?? 0),
      timedOut: false,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((err as { code?: string }).code === '57014') {
      return { groups: [], hours: [], totalEvents: 0, timedOut: true };
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Conexões agregadas por origem, destino, protocolo, porta e bloqueio sobre TODO o período, para o
 * Behavior.
 */
export async function aggregateBehaviorDb(
  pool: Pool,
  siteId: string,
  sinceIso: string,
  groupLimit = 100_000
): Promise<{
  groups: Array<{
    src: string;
    dst: string;
    proto: string;
    port: string;
    blocked: boolean;
    c: number;
    bytes: number;
    last: string | null;
  }>;
  capped: boolean;
  timedOut: boolean;
}> {
  const timeoutMs = Math.max(
    5000,
    Number(process.env.BEHAVIOR_QUERY_TIMEOUT_MS) ||
      Number(process.env.REPORT_QUERY_TIMEOUT_MS) ||
      60_000
  );
  const bytes = (key: string) => `COALESCE(NULLIF(payload_json->>'${key}', '')::numeric, 0)`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(timeoutMs)}`);
    const res = await client.query(
      `SELECT COALESCE(payload_json->>'srcIp', '') AS src, payload_json->>'dstIp' AS dst,
              split_part(COALESCE(payload_json->>'protocol', ''), '/', 1) AS proto,
              COALESCE(payload_json->>'dstPort', '') AS port,
              (action IN ('drop','deny','reset')) AS blocked,
              count(*)::bigint AS c, sum(${bytes('bytesSent')} + ${bytes('bytesRcvd')})::bigint AS bytes,
              max(event_at) AS last
         FROM syslogs
        WHERE site_id = $1 AND event_at >= $2 AND action <> 'system'
          AND COALESCE(payload_json->>'dstIp', '') NOT IN ('', '-')
        GROUP BY 1,2,3,4,5 ORDER BY c DESC LIMIT $3`,
      [siteId, sinceIso, groupLimit + 1]
    );
    await client.query('COMMIT');
    const capped = res.rows.length > groupLimit;
    return {
      groups: res.rows.slice(0, groupLimit).map((r) => ({
        src: String(r.src),
        dst: String(r.dst),
        proto: String(r.proto || ''),
        port: String(r.port || ''),
        blocked: Boolean(r.blocked),
        c: Number(r.c),
        bytes: Number(r.bytes ?? 0),
        last: r.last ? new Date(r.last).toISOString() : null,
      })),
      capped,
      timedOut: false,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((err as { code?: string }).code === '57014') {
      return { groups: [], capped: false, timedOut: true };
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Conexões agregadas para os radares de Destinos e Origens sobre TODO o período.
 */
export async function aggregateRadarDb(
  pool: Pool,
  siteId: string,
  sinceIso: string,
  options: { srcLike?: string; groupLimit?: number } = {}
): Promise<{
  rows: Array<{
    src: string;
    srcZone: string;
    user: string;
    dst: string;
    host: string;
    appCategory: string;
    proto: string;
    port: string;
    app: string;
    blocked: boolean;
    c: number;
    bytes: number;
    last: string | null;
  }>;
  capped: boolean;
  timedOut: boolean;
}> {
  const limit = options.groupLimit ?? 150_000;
  const timeoutMs = Math.max(
    5000,
    Number(process.env.RADAR_QUERY_TIMEOUT_MS) ||
      Number(process.env.REPORT_QUERY_TIMEOUT_MS) ||
      60_000
  );
  const bytes = (key: string) => `COALESCE(NULLIF(payload_json->>'${key}', '')::numeric, 0)`;
  const params: unknown[] = [siteId, sinceIso];
  let srcFilter = '';
  if (options.srcLike) {
    params.push(`%${options.srcLike.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
    srcFilter = `AND search_text LIKE $${params.length} AND LOWER(COALESCE(payload_json->>'srcIp', '')) LIKE $${params.length}`;
  }
  params.push(limit + 1);
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(timeoutMs)}`);
    const res = await client.query(
      `SELECT COALESCE(payload_json->>'srcIp', '') AS src, COALESCE(payload_json->>'srcZone', '') AS zone,
              COALESCE(payload_json->>'user', '') AS usr, payload_json->>'dstIp' AS dst,
              ${HOST_HINT_SQL} AS host, ${APPCAT_HINT_SQL} AS appcat,
              COALESCE(payload_json->>'protocol', '') AS proto, COALESCE(payload_json->>'dstPort', '') AS port,
              COALESCE(payload_json->>'appName', '') AS app,
              (action IN ('drop','deny','reset')) AS blocked,
              count(*)::bigint AS c, sum(${bytes('bytesSent')} + ${bytes('bytesRcvd')})::bigint AS bytes,
              max(event_at) AS last
         FROM syslogs
        WHERE site_id = $1 AND event_at >= $2 AND action <> 'system'
          AND COALESCE(payload_json->>'dstIp', '') NOT IN ('', '-') ${srcFilter}
        GROUP BY 1,2,3,4,5,6,7,8,9,10 ORDER BY c DESC LIMIT $${params.length}`,
      params
    );
    await client.query('COMMIT');
    const capped = res.rows.length > limit;
    return {
      rows: res.rows.slice(0, limit).map((r) => ({
        src: String(r.src),
        srcZone: String(r.zone),
        user: String(r.usr),
        dst: String(r.dst),
        host: String(r.host ?? ''),
        appCategory: String(r.appcat ?? ''),
        proto: String(r.proto),
        port: String(r.port),
        app: String(r.app),
        blocked: Boolean(r.blocked),
        c: Number(r.c),
        bytes: Number(r.bytes ?? 0),
        last: r.last ? new Date(r.last).toISOString() : null,
      })),
      capped,
      timedOut: false,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((err as { code?: string }).code === '57014') {
      return { rows: [], capped: false, timedOut: true };
    }
    throw err;
  } finally {
    client.release();
  }
}

/** Análise de aplicação dos logs do ALB (metadados HTTP), agregada no banco sobre o período. */
export async function aggregateHttpInsightsDb(
  pool: Pool,
  siteId: string,
  sinceIso: string,
  groupLimit = 100_000,
  bucketSec = 3600
): Promise<{
  groups: Array<{
    host: string;
    method: string;
    path: string;
    status: string;
    targetIp: string;
    targetGroup: string;
    waf: string;
    c: number;
    sumTime: number;
    maxTime: number;
    slow: number;
    up: number;
    down: number;
    sumReq: number;
    sumTgt: number;
    sumResp: number;
    clientSlow: number;
    hist: number[];
    tHist: number[];
  }>;
  clients: Array<{ ua: string; tls: string; cipher: string; c: number; errors: number }>;
  extras: {
    slowRequests: Array<{
      at: string;
      method: string;
      host: string;
      path: string;
      client: string;
      status: string;
      totalMs: number;
      requestMs: number;
      targetMs: number;
      targetIp: string;
      traceId: string;
    }>;
    timeline: Array<{ t: string; requests: number; errors5xx: number; sumTgt: number; maxTime: number }>;
    tlsReused: number;
  };
  capped: boolean;
  timedOut: boolean;
}> {
  const timeoutMs = Math.max(5000, Number(process.env.REPORT_QUERY_TIMEOUT_MS) || 60_000);
  const m = (key: string) => `COALESCE(payload_json#>>'{meta,${key}}', '')`;
  const sec = (key: string) => `COALESCE(NULLIF(payload_json#>>'{meta,${key}}', '')::numeric, 0)`;
  const total = sec('totalTime');
  const bytes = (key: string) => `COALESCE(NULLIF(payload_json->>'${key}', '')::numeric, 0)`;
  const histCols = (expr: string, prefix: string) =>
    [
      `count(*) FILTER (WHERE ${expr} < 0.05)::bigint AS ${prefix}0`,
      `count(*) FILTER (WHERE ${expr} >= 0.05 AND ${expr} < 0.1)::bigint AS ${prefix}1`,
      `count(*) FILTER (WHERE ${expr} >= 0.1 AND ${expr} < 0.25)::bigint AS ${prefix}2`,
      `count(*) FILTER (WHERE ${expr} >= 0.25 AND ${expr} < 0.5)::bigint AS ${prefix}3`,
      `count(*) FILTER (WHERE ${expr} >= 0.5 AND ${expr} < 1)::bigint AS ${prefix}4`,
      `count(*) FILTER (WHERE ${expr} >= 1 AND ${expr} < 2)::bigint AS ${prefix}5`,
      `count(*) FILTER (WHERE ${expr} >= 2 AND ${expr} < 5)::bigint AS ${prefix}6`,
      `count(*) FILTER (WHERE ${expr} >= 5)::bigint AS ${prefix}7`,
    ].join(', ');
  const readHist = (r: Record<string, unknown>, prefix: string) =>
    Array.from({ length: 8 }, (_, i) => Number(r[`${prefix}${i}`] ?? 0));
  const where = `site_id = $1 AND event_at >= $2 AND action <> 'system' AND payload_json#>>'{meta,method}' IS NOT NULL AND payload_json->>'categoryName' = 'Application Load Balancer'`;
  const bs = Math.max(1, Math.floor(bucketSec));
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(timeoutMs)}`);
    const g = await client.query(
      `SELECT ${m('host')} AS host, ${m('method')} AS method,
              COALESCE(NULLIF(payload_json#>>'{meta,pathGroup}', ''), ${m('path')}) AS path,
              ${m('status')} AS status, ${m('targetIp')} AS target, ${m('targetGroup')} AS tgroup, ${m('wafActions')} AS waf,
              count(*)::bigint AS c, sum(${total}) AS st, max(${total}) AS mx,
              count(*) FILTER (WHERE ${total} >= 2)::bigint AS slow,
              sum(${bytes('bytesSent')})::bigint AS up, sum(${bytes('bytesRcvd')})::bigint AS down,
              sum(${sec('reqTime')}) AS sreq, sum(${sec('targetTime')}) AS stgt, sum(${sec('respTime')}) AS sresp,
              count(*) FILTER (WHERE ${sec('reqTime')} >= 1)::bigint AS cslow,
              ${histCols(total, 'h')}, ${histCols(sec('targetTime'), 't')}
         FROM syslogs WHERE ${where}
        GROUP BY 1,2,3,4,5,6,7 ORDER BY c DESC LIMIT $3`,
      [siteId, sinceIso, groupLimit + 1]
    );
    const c = await client.query(
      `SELECT ${m('uaFamily')} AS ua, ${m('tlsVersion')} AS tls, ${m('tlsCipher')} AS cipher,
              count(*)::bigint AS c, count(*) FILTER (WHERE ${m('status')} ~ '^5')::bigint AS errors
         FROM syslogs WHERE ${where}
        GROUP BY 1,2,3 ORDER BY c DESC LIMIT 5000`,
      [siteId, sinceIso]
    );
    const tl = await client.query(
      `SELECT to_timestamp(floor(extract(epoch FROM event_at) / ${bs}) * ${bs}) AS t, count(*)::bigint AS c,
              count(*) FILTER (WHERE ${m('status')} ~ '^5')::bigint AS e5, sum(${sec('targetTime')}) AS stgt, max(${total}) AS mx,
              count(*) FILTER (WHERE ${m('tlsReused')} = 'true')::bigint AS reused
         FROM syslogs WHERE ${where} GROUP BY 1 ORDER BY 1`,
      [siteId, sinceIso]
    );
    const sl = await client.query(
      `SELECT event_at, ${m('method')} AS method, ${m('host')} AS host, ${m('path')} AS path, payload_json->>'srcIp' AS client,
              ${m('status')} AS status, ${total} AS total, ${sec('reqTime')} AS req, ${sec('targetTime')} AS tgt,
              ${m('targetIp')} AS target, ${m('traceId')} AS trace
         FROM syslogs WHERE ${where} ORDER BY ${total} DESC LIMIT 10`,
      [siteId, sinceIso]
    );
    await client.query('COMMIT');
    return {
      groups: g.rows.slice(0, groupLimit).map((r) => ({
        host: String(r.host),
        method: String(r.method),
        path: String(r.path),
        status: String(r.status),
        targetIp: String(r.target),
        targetGroup: String(r.tgroup),
        waf: String(r.waf),
        c: Number(r.c),
        sumTime: Number(r.st ?? 0),
        maxTime: Number(r.mx ?? 0),
        slow: Number(r.slow),
        up: Number(r.up ?? 0),
        down: Number(r.down ?? 0),
        sumReq: Number(r.sreq ?? 0),
        sumTgt: Number(r.stgt ?? 0),
        sumResp: Number(r.sresp ?? 0),
        clientSlow: Number(r.cslow ?? 0),
        hist: readHist(r, 'h'),
        tHist: readHist(r, 't'),
      })),
      clients: c.rows.map((r) => ({
        ua: String(r.ua),
        tls: String(r.tls),
        cipher: String(r.cipher),
        c: Number(r.c),
        errors: Number(r.errors),
      })),
      extras: {
        slowRequests: sl.rows.map((r) => ({
          at: new Date(r.event_at).toISOString(),
          method: String(r.method),
          host: String(r.host),
          path: String(r.path),
          client: String(r.client ?? ''),
          status: String(r.status),
          totalMs: Math.round(Number(r.total) * 1000),
          requestMs: Math.round(Number(r.req) * 1000),
          targetMs: Math.round(Number(r.tgt) * 1000),
          targetIp: String(r.target),
          traceId: String(r.trace),
        })),
        timeline: tl.rows.map((r) => ({
          t: new Date(r.t).toISOString(),
          requests: Number(r.c),
          errors5xx: Number(r.e5),
          sumTgt: Number(r.stgt ?? 0),
          maxTime: Number(r.mx ?? 0),
        })),
        tlsReused: tl.rows.reduce((n, r) => n + Number(r.reused ?? 0), 0),
      },
      capped: g.rows.length > groupLimit,
      timedOut: false,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((err as { code?: string }).code === '57014') {
      return {
        groups: [],
        clients: [],
        extras: { slowRequests: [], timeline: [], tlsReused: 0 },
        capped: false,
        timedOut: true,
      };
    }
    throw err;
  } finally {
    client.release();
  }
}

/** "Top N" por campo para os painéis de VPC Flow Logs e WAF, agregado no banco sobre o período. */
export async function aggregateFacetsDb(
  pool: Pool,
  siteId: string,
  sinceIso: string,
  category: string,
  specs: Array<{
    id: string;
    field: FacetField;
    where?: 'blocked' | 'allowed';
    metric?: 'count' | 'bytes';
  }>,
  bucketSec = 3600,
  extraWhere = ''
): Promise<{
  totals: { events: number; blocked: number; allowed: number; bytes: number; packets: number };
  timeline: Array<{ t: string; allowed: number; blocked: number }>;
  items: Record<string, Array<{ key: string; count: number; blocked: number; bytes: number }>>;
  timedOut: boolean;
}> {
  const timeoutMs = Math.max(5000, Number(process.env.REPORT_QUERY_TIMEOUT_MS) || 60_000);
  const bytes = `(COALESCE(NULLIF(payload_json->>'bytesSent', '')::numeric, 0) + COALESCE(NULLIF(payload_json->>'bytesRcvd', '')::numeric, 0))`;
  const blocked = `action IN ('drop','deny','reset')`;
  const base = `site_id = $1 AND event_at >= $2 AND action <> 'system' AND payload_json->>'categoryName' = $3${extraWhere ? ` AND ${extraWhere}` : ''}`;
  const params = [siteId, sinceIso, category];
  const bs = Math.max(1, Math.floor(bucketSec));
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(timeoutMs)}`);
    // Uma única leitura do período: os campos são extraídos uma vez e todos os totais, a linha do
    // tempo e os "top N" saem desse conjunto, em vez de reler a tabela a cada faceta.
    const columns = specs.map((spec, i) => `${facetSql(spec.field)} AS f${i}`);
    const tops = specs.map((spec, i) => {
      const cond = spec.where === 'blocked' ? 'AND is_blocked' : spec.where === 'allowed' ? 'AND NOT is_blocked' : '';
      const order = spec.metric === 'bytes' ? 'sum(b_total) DESC, count(*) DESC' : 'count(*) DESC';
      return `(SELECT COALESCE(json_agg(x), '[]'::json) FROM (
          SELECT f${i} AS v, count(*) AS c, count(*) FILTER (WHERE is_blocked) AS b, COALESCE(sum(b_total), 0)::bigint AS bytes
            FROM base WHERE COALESCE(f${i}, '') NOT IN ('', '-') ${cond}
           GROUP BY 1 ORDER BY ${order} LIMIT ${ITEM_LIMIT_FOR_DB}) x) AS i${i}`;
    });
    const r = await client.query(
      `WITH base AS MATERIALIZED (
         SELECT event_at, ${blocked} AS is_blocked, ${bytes} AS b_total,
                NULLIF(payload_json#>>'{meta,packets}', '')::numeric AS packets${columns.map((c) => `, ${c}`).join('')}
           FROM syslogs WHERE ${base}
       )
       SELECT
         (SELECT row_to_json(x) FROM (
            SELECT count(*) AS c, count(*) FILTER (WHERE is_blocked) AS b, COALESCE(sum(b_total), 0)::bigint AS bytes,
                   COALESCE(sum(packets), 0)::bigint AS packets FROM base) x) AS totals,
         (SELECT COALESCE(json_agg(x ORDER BY x.epoch), '[]'::json) FROM (
            SELECT floor(extract(epoch FROM event_at) / ${bs}) * ${bs} AS epoch,
                   count(*) FILTER (WHERE NOT is_blocked) AS allowed, count(*) FILTER (WHERE is_blocked) AS blocked
              FROM base GROUP BY 1) x) AS timeline${tops.map((t) => `,\n         ${t}`).join('')}`,
      params
    );
    const result = r.rows[0];
    const items: Record<string, Array<{ key: string; count: number; blocked: number; bytes: number }>> = {};
    specs.forEach((spec, i) => {
      items[spec.id] = (result[`i${i}`] as Array<{ v: unknown; c: number; b: number; bytes: number }>).map((x) => ({
        key: String(x.v),
        count: Number(x.c),
        blocked: Number(x.b),
        bytes: Number(x.bytes),
      }));
    });
    await client.query('COMMIT');
    const row = result.totals as { c: number; b: number; bytes: number; packets: number };
    const events = Number(row.c ?? 0);
    const blockedN = Number(row.b ?? 0);
    return {
      totals: {
        events,
        blocked: blockedN,
        allowed: events - blockedN,
        bytes: Number(row.bytes ?? 0),
        packets: Number(row.packets ?? 0),
      },
      timeline: (result.timeline as Array<{ epoch: number; allowed: number; blocked: number }>).map((x) => ({
        t: new Date(Number(x.epoch) * 1000).toISOString(),
        allowed: Number(x.allowed),
        blocked: Number(x.blocked),
      })),
      items,
      timedOut: false,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((err as { code?: string }).code === '57014') {
      return {
        totals: { events: 0, blocked: 0, allowed: 0, bytes: 0, packets: 0 },
        timeline: [],
        items: {},
        timedOut: true,
      };
    }
    throw err;
  } finally {
    client.release();
  }
}

/** Resumo por recurso (ALB, VPC Flow Logs, WAF) para os cartões da Visão Geral. */
export async function aggregateCategorySummaryDb(
  pool: Pool,
  siteId: string,
  sinceIso: string,
  bucketSec = 3600
): Promise<{
  rows: Array<{
    category: string;
    events: number;
    blocked: number;
    errors5xx: number;
    bytes: number;
    lastAt: string | null;
  }>;
  timeline: Array<{ t: string; allowed: number; blocked: number }>;
  timedOut: boolean;
}> {
  const timeoutMs = Math.max(5000, Number(process.env.REPORT_QUERY_TIMEOUT_MS) || 60_000);
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(timeoutMs)}`);
    const bs = Math.max(1, Math.floor(bucketSec));
    // Cartões e linha do tempo saem da mesma leitura do período
    const q = await client.query(
      `WITH base AS MATERIALIZED (
         SELECT payload_json->>'categoryName' AS cat, event_at, action IN ('drop','deny','reset') AS is_blocked,
                COALESCE(payload_json#>>'{meta,status}', '') ~ '^5' AS is_5xx,
                COALESCE(NULLIF(payload_json->>'bytesSent', '')::numeric, 0) + COALESCE(NULLIF(payload_json->>'bytesRcvd', '')::numeric, 0) AS b_total
           FROM syslogs
          WHERE site_id = $1 AND event_at >= $2 AND action <> 'system'
            AND payload_json->>'categoryName' IN ('Application Load Balancer', 'VPC Flow Logs', 'AWS WAF')
       )
       SELECT
         (SELECT COALESCE(json_agg(x), '[]'::json) FROM (
            SELECT cat, count(*) AS c, count(*) FILTER (WHERE is_blocked) AS b, count(*) FILTER (WHERE is_5xx) AS e5,
                   COALESCE(sum(b_total), 0)::bigint AS bytes, max(event_at) AS last
              FROM base GROUP BY 1) x) AS categories,
         (SELECT COALESCE(json_agg(x ORDER BY x.epoch), '[]'::json) FROM (
            SELECT floor(extract(epoch FROM event_at) / ${bs}) * ${bs} AS epoch,
                   count(*) FILTER (WHERE NOT is_blocked) AS allowed, count(*) FILTER (WHERE is_blocked) AS blocked
              FROM base GROUP BY 1) x) AS timeline`,
      [siteId, sinceIso]
    );
    const categories = q.rows[0].categories as Array<{ cat: string; c: number; b: number; e5: number; bytes: number; last: string | null }>;
    const buckets = q.rows[0].timeline as Array<{ epoch: number; allowed: number; blocked: number }>;
    await client.query('COMMIT');
    return {
      timeline: buckets.map((x) => ({
        t: new Date(Number(x.epoch) * 1000).toISOString(),
        allowed: Number(x.allowed),
        blocked: Number(x.blocked),
      })),
      rows: categories.map((x) => ({
        category: String(x.cat),
        events: Number(x.c),
        blocked: Number(x.b),
        errors5xx: Number(x.e5),
        bytes: Number(x.bytes),
        lastAt: x.last ? new Date(x.last).toISOString() : null,
      })),
      timedOut: false,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((err as { code?: string }).code === '57014') {
      return { rows: [], timeline: [], timedOut: true };
    }
    throw err;
  } finally {
    client.release();
  }
}

/** Ranking das portas de destino mais acessadas, agregado no banco (todo o histórico do período). */
export async function aggregatePortsDb(
  pool: Pool,
  siteId: string,
  sinceIso: string,
  limit = 25
): Promise<{
  ports: Array<{
    port: number;
    proto: string;
    connections: number;
    blocked: number;
    bytes: number;
    sources: number;
    destinations: number;
  }>;
  events: number;
  timedOut: boolean;
}> {
  const timeoutMs = Math.max(5000, Number(process.env.REPORT_QUERY_TIMEOUT_MS) || 60_000);
  const bytes = (key: string) => `COALESCE(NULLIF(payload_json->>'${key}', '')::numeric, 0)`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(timeoutMs)}`);
    const res = await client.query(
      `SELECT (payload_json->>'dstPort')::int AS port,
              mode() WITHIN GROUP (ORDER BY split_part(COALESCE(payload_json->>'protocol', ''), '/', 1)) AS proto,
              count(*)::bigint AS c,
              count(*) FILTER (WHERE action IN ('drop','deny','reset'))::bigint AS blocked,
              sum(${bytes('bytesSent')} + ${bytes('bytesRcvd')})::bigint AS bytes,
              count(DISTINCT payload_json->>'srcIp')::bigint AS srcs,
              count(DISTINCT payload_json->>'dstIp')::bigint AS dsts
         FROM syslogs
        WHERE site_id = $1 AND event_at >= $2 AND action <> 'system'
          AND (payload_json->>'dstPort') ~ '^[0-9]{1,5}$'
        GROUP BY 1 ORDER BY c DESC, port ASC LIMIT $3`,
      [siteId, sinceIso, limit]
    );
    const total = await client.query(
      `SELECT count(*)::bigint AS n FROM syslogs
        WHERE site_id = $1 AND event_at >= $2 AND action <> 'system' AND (payload_json->>'dstPort') ~ '^[0-9]{1,5}$'`,
      [siteId, sinceIso]
    );
    await client.query('COMMIT');
    return {
      ports: res.rows.map((r) => ({
        port: Number(r.port),
        proto: String(r.proto || 'tcp'),
        connections: Number(r.c),
        blocked: Number(r.blocked),
        bytes: Number(r.bytes ?? 0),
        sources: Number(r.srcs),
        destinations: Number(r.dsts),
      })),
      events: Number(total.rows[0]?.n ?? 0),
      timedOut: false,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((err as { code?: string }).code === '57014') {
      return { ports: [], events: 0, timedOut: true };
    }
    throw err;
  } finally {
    client.release();
  }
}
