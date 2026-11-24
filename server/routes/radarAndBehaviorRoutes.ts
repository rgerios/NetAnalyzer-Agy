import type express from 'express';
import { AWS_REGION_COUNTRY } from '../../shared/aws.ts';
import {
  parsePortFilter,
  wellKnownService,
  type PortFilterSpec,
  type PortStat,
} from '../../shared/ports.ts';
import {
  buildBehaviorReport,
  detectOrigin,
  groupsFromEvents,
  remoteOfPair,
  type BehaviorGroup,
} from '../behaviorEngine.ts';
import type { PostgresStore } from '../database.ts';
import {
  buildDestinationsReport,
  buildSourcesReport,
  filterRowsByDestination,
  filterRowsByPort,
  filterRowsBySource,
  normalizeDestinationFilter,
  normalizeSourceFilter,
  rowFromDb,
  rowsFromEvents,
  type DestinationFilter,
  type RadarRow,
} from '../destinationsEngine.ts';
import type { createIntel } from '../intel.ts';
import {
  buildPortStats,
  buildPortStatsFromGroups,
  filterEventsByPort,
  filterGroupsByPort,
} from '../portsEngine.ts';
import { getSharedResolver } from '../rdns.ts';
import type { FirewallSiteRecord } from '../types.ts';
import { aggTtl, radarMinutes, type AsyncRouteWrapper, type createAggregateCache } from './routeHelpers.ts';

const RADAR_DB_QUERY_LIMIT = 20_000;

export interface RadarAndBehaviorRoutesOptions {
  router: express.Router;
  isAws: boolean;
  usePg: boolean;
  memoryWindow: number;
  pgStore: PostgresStore;
  intel: ReturnType<typeof createIntel>;
  siteFor: (req: express.Request) => FirewallSiteRecord;
  flushPendingInserts: () => Promise<void>;
  asyncRoute: AsyncRouteWrapper;
  cachedAggregate: ReturnType<typeof createAggregateCache>;
}

export function registerRadarAndBehaviorRoutes(opts: RadarAndBehaviorRoutesOptions): void {
  const {
    router,
    isAws,
    usePg,
    memoryWindow,
    pgStore,
    intel,
    siteFor,
    flushPendingInserts,
    asyncRoute,
    cachedAggregate,
  } = opts;

  type RadarFilters = { srcIp: string; dst: DestinationFilter; ports: PortFilterSpec };

  function parseRadarFilters(req: express.Request, res: express.Response): RadarFilters | null {
    const srcIp = normalizeSourceFilter(req.query.srcIp);
    if (srcIp === null) {
      res.status(400).json({
        error: 'IP de origem inválido. Use só números, pontos e dois-pontos (ex.: 10.20.4.45).',
      });
      return null;
    }
    const dst = normalizeDestinationFilter(req.query.dst, req.query.dstIps);
    if (dst === null) {
      res.status(400).json({
        error: 'Filtro de destino inválido. Use um nome, domínio ou IP (até 10 IPs).',
      });
      return null;
    }
    const ports = parsePortFilter(req.query.dstPort);
    if (ports === null) {
      res.status(400).json({
        error:
          'Filtro de porta inválido. Use números de 0 a 65535, listas (80,443) ou intervalos (8000-8100).',
      });
      return null;
    }
    return { srcIp, dst, ports };
  }

  function getBehaviorAggregate(siteId: string, minutes: number, sinceIso: string | undefined) {
    return cachedAggregate(`behavior|${siteId}|${minutes}`, aggTtl(minutes), () =>
      pgStore.aggregateBehavior(siteId, sinceIso ?? new Date(0).toISOString())
    );
  }

  function getRadarAggregate(
    siteId: string,
    minutes: number,
    sinceIso: string | undefined,
    srcLike: string
  ) {
    return cachedAggregate(`radar|${siteId}|${minutes}|${srcLike}`, aggTtl(minutes), () =>
      pgStore.aggregateRadar(siteId, sinceIso ?? new Date(0).toISOString(), {
        srcLike: srcLike || undefined,
      })
    );
  }

  async function loadRadarRows(
    site: FirewallSiteRecord,
    minutes: number,
    filters: RadarFilters,
    lookupHost: (ip: string) => string | null | undefined
  ): Promise<{
    rows: RadarRow[];
    dataSource: 'memory' | 'database';
    truncated: boolean;
    portStats: PortStat[];
  }> {
    const sinceIso =
      minutes > 0 ? new Date(Date.now() - minutes * 60 * 1000).toISOString() : undefined;
    const memoryEvents = sinceIso
      ? site.syslogs.filter((ev) => !ev.ingestedAt || ev.ingestedAt >= sinceIso)
      : site.syslogs;
    let rows: RadarRow[];
    let dataSource: 'memory' | 'database' = 'memory';
    let truncated = false;

    const oldestInMemory =
      site.syslogs.length > 0 ? site.syslogs[site.syslogs.length - 1]?.ingestedAt : null;
    const needDb =
      usePg &&
      (minutes === 0 ||
        site.syslogs.length >= memoryWindow ||
        (!!oldestInMemory && !!sinceIso && oldestInMemory > sinceIso));
    if (needDb) {
      const agg = await getRadarAggregate(site.id, minutes, sinceIso, filters.srcIp);
      if (agg.timedOut) {
        rows = rowsFromEvents(memoryEvents);
        truncated = true;
      } else {
        rows = agg.rows.map(rowFromDb);
        truncated = agg.capped;
        dataSource = 'database';
      }
    } else {
      rows = rowsFromEvents(memoryEvents);
    }

    rows = filterRowsBySource(rows, filters.srcIp);
    rows = filterRowsByDestination(rows, filters.dst, lookupHost);
    const portStats = buildPortStatsFromGroups(
      rows.map((r) => ({
        src: r.src,
        dst: r.dst,
        proto: (r.proto || '').toLowerCase().split('/')[0],
        port: r.port === null ? '' : String(r.port),
        blocked: r.blocked,
        c: r.c,
        bytes: r.bytes,
        last: r.last,
      })),
      25
    ).ports;
    rows = filterRowsByPort(rows, filters.ports);
    return { rows, dataSource, truncated, portStats };
  }

  router.get(
    '/destinations',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const minutes = radarMinutes(req);
      const filters = parseRadarFilters(req, res);
      if (!filters) return;
      const resolver = getSharedResolver();
      const lookupHost = (ip: string) => resolver.lookupCached(ip);
      const { rows, dataSource, truncated, portStats } = await loadRadarRows(
        site,
        minutes,
        filters,
        lookupHost
      );
      const report = buildDestinationsReport({
        rows,
        minutes,
        windowSize: site.syslogs.length,
        lookupHost,
        resolver: { enabled: resolver.enabled, ...resolver.stats() },
      });
      report.srcIp = filters.srcIp;
      report.dst = filters.dst.text;
      report.dstIps = filters.dst.ips;
      report.dstPort = filters.ports.text;
      report.ports = portStats;
      report.dataSource = dataSource;
      report.truncated = truncated;
      resolver.schedule(
        report.nodes
          .filter((n) => n.host === null && n.scope === 'public')
          .slice(0, 40)
          .map((n) => n.ip)
      );
      res.json(report);
    })
  );

  router.get(
    '/behavior',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const minutes = radarMinutes(req);
      const portSpec = parsePortFilter(req.query.dstPort);
      if (portSpec === null) {
        res.status(400).json({
          error:
            'Filtro de porta inválido. Use números de 0 a 65535, listas (80,443) ou intervalos (8000-8100).',
        });
        return;
      }
      const sinceIso =
        minutes > 0 ? new Date(Date.now() - minutes * 60 * 1000).toISOString() : undefined;
      const memoryEvents = sinceIso
        ? site.syslogs.filter((ev) => !ev.ingestedAt || ev.ingestedAt >= sinceIso)
        : site.syslogs;
      let groups: BehaviorGroup[];
      let dataSource: 'memory' | 'database' = 'memory';
      let truncated = false;

      const oldestInMemory =
        site.syslogs.length > 0 ? site.syslogs[site.syslogs.length - 1]?.ingestedAt : null;
      const needDb =
        usePg &&
        (minutes === 0 ||
          site.syslogs.length >= memoryWindow ||
          (!!oldestInMemory && !!sinceIso && oldestInMemory > sinceIso));
      if (needDb) {
        const agg = await getBehaviorAggregate(site.id, minutes, sinceIso);
        if (agg.timedOut) {
          const rows = await pgStore.querySyslogsSince(
            site.id,
            sinceIso ?? new Date(0).toISOString(),
            [],
            RADAR_DB_QUERY_LIMIT,
            {}
          );
          groups = groupsFromEvents(rows);
          truncated = rows.length >= RADAR_DB_QUERY_LIMIT;
        } else {
          groups = agg.groups;
          truncated = agg.capped;
        }
        dataSource = 'database';
      } else {
        groups = groupsFromEvents(memoryEvents);
      }

      const wanIps = (site.telemetry?.interfaces ?? [])
        .filter((i) => i.role !== 'internal' || i.zone.toUpperCase() === 'WAN')
        .map((i) => i.ip);
      const origin = isAws
        ? {
            country: AWS_REGION_COUNTRY[site.connection.aws?.region ?? ''] ?? 'US',
            ip: null,
            source: 'region' as const,
          }
        : detectOrigin(site.syslogs, wanIps, intel);
      const sinceRaw = typeof req.query.since === 'string' ? req.query.since : '';
      const since =
        sinceRaw && Number.isFinite(Date.parse(sinceRaw))
          ? new Date(sinceRaw).toISOString()
          : undefined;
      const isRemote = (g: BehaviorGroup) => remoteOfPair(g.src, g.dst, isAws) !== null;
      const portStats = buildPortStatsFromGroups(groups, 25, isRemote).ports;
      const report = buildBehaviorReport({
        groups: filterGroupsByPort(groups, portSpec),
        recentEvents: filterEventsByPort(site.syslogs.slice(0, 5000), portSpec),
        minutes,
        intel,
        origin,
        since,
        dataSource,
        truncated,
        inbound: isAws,
      });
      report.dstPort = portSpec.text;
      report.ports = portStats;
      res.json(report);
    })
  );

  router.post(
    '/behavior/intel/update',
    asyncRoute(async (_req, res) => {
      if (intel.status().updating) {
        res
          .status(409)
          .json({ error: 'Já existe uma atualização em andamento.', intel: intel.status() });
        return;
      }
      void intel.update().catch(() => undefined);
      res.status(202).json({ ok: true, intel: intel.status() });
    })
  );

  router.get('/behavior/intel', (_req, res) => {
    res.json(intel.status());
  });

  router.get(
    '/ports',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const minutes = radarMinutes(req);
      const sinceIso =
        minutes > 0 ? new Date(Date.now() - minutes * 60 * 1000).toISOString() : undefined;
      if (usePg) {
        await flushPendingInserts();
        const agg = await pgStore.aggregatePorts(
          site.id,
          sinceIso ?? new Date(0).toISOString(),
          25
        );
        res.json({
          minutes,
          events: agg.events,
          ports: agg.ports.map((p) => ({ ...p, service: wellKnownService(p.port) })),
          dataSource: 'database',
          truncated: agg.timedOut,
        });
        return;
      }
      const events = sinceIso
        ? site.syslogs.filter((ev) => !ev.ingestedAt || ev.ingestedAt >= sinceIso)
        : site.syslogs;
      const { ports, counted } = buildPortStats(events, 25);
      res.json({ minutes, events: counted, ports, dataSource: 'memory', truncated: false });
    })
  );

  router.get(
    '/sources',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const minutes = radarMinutes(req);
      const filters = parseRadarFilters(req, res);
      if (!filters) return;
      const resolver = getSharedResolver();
      const lookupHost = (ip: string) => resolver.lookupCached(ip);
      const { rows, dataSource, truncated } = await loadRadarRows(
        site,
        minutes,
        filters,
        lookupHost
      );
      const report = buildSourcesReport({
        rows,
        minutes,
        windowSize: site.syslogs.length,
        lookupHost,
      });
      report.srcIp = filters.srcIp;
      report.dst = filters.dst.text;
      report.dstIps = filters.dst.ips;
      report.dataSource = dataSource;
      report.truncated = truncated;
      res.json(report);
    })
  );
}
