import type express from 'express';
import type { AwsConfigSaveBody } from '../../shared/aws.ts';
import type { HttpInsights } from '../../shared/httpInsights.ts';
import { appLog } from '../appLogger.ts';
import { resolveEventTimeMs } from '../engineHelpers.ts';
import type { AuthManager } from '../authManager.ts';
import {
  buildLogsClient,
  listLogGroups,
  listStreamPrefixes,
  testCloudWatchSource,
} from '../awsCloudWatch.ts';
import {
  applyAwsSave,
  AwsConfigError,
  defaultAwsConfig,
  normalizeSource as normalizeAwsSource,
  toPublicAwsConfig,
} from '../awsConfig.ts';
import { clientConfigFor, type createAwsIngestor } from '../awsIngest.ts';
import { renderAwsReportHtml, type AwsReportData, type AwsReportSection } from '../awsReportHtml.ts';
import { buildS3Client, describeAwsError, testSource } from '../awsS3.ts';
import type { PostgresStore } from '../database.ts';
import {
  bucketSecondsFor,
  padTimeline,
  FACETS,
  facetsFromEvents,
  KIND_CATEGORY,
  KIND_SQL_FILTER,
  summarizeCategories,
  timelineFromEvents,
  type AwsLogKind,
  type FacetReport,
} from '../facets.ts';
import { buildHttpInsights, rowsFromAlbEvents } from '../httpInsights.ts';
import type { createIntel } from '../intel.ts';
import { REPORT_HTML_CSP } from '../securityGuards.ts';
import type { FirewallSiteRecord, FirewallVendor } from '../types.ts';
import { aggTtl, radarMinutes, type AsyncRouteWrapper, type createAggregateCache } from './routeHelpers.ts';

export interface AwsCloudRoutesOptions {
  router: express.Router;
  vendor: FirewallVendor;
  usePg: boolean;
  memoryWindow: number;
  pgStore: PostgresStore;
  authManager: AuthManager;
  intel: ReturnType<typeof createIntel>;
  awsIngestor: ReturnType<typeof createAwsIngestor>;
  siteFor: (req: express.Request) => FirewallSiteRecord;
  schedulePersist: () => void;
  asyncRoute: AsyncRouteWrapper;
  cachedAggregate: ReturnType<typeof createAggregateCache>;
}

export function registerAwsCloudRoutes(opts: AwsCloudRoutesOptions): void {
  const {
    router,
    usePg,
    memoryWindow,
    pgStore,
    authManager,
    intel,
    awsIngestor,
    siteFor,
    schedulePersist,
    asyncRoute,
    cachedAggregate,
  } = opts;

  router.get('/cloud/config', (req, res) => {
    res.json(toPublicAwsConfig(siteFor(req).connection.aws));
  });

  router.put(
    '/cloud/config',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      try {
        site.connection.aws = applyAwsSave(
          site.connection.aws ?? defaultAwsConfig(),
          (req.body ?? {}) as AwsConfigSaveBody,
          (plain) => authManager.encryptSecret(plain)
        );
      } catch (err) {
        if (err instanceof AwsConfigError) {
          res.status(400).json({ error: err.message });
          return;
        }
        throw err;
      }
      site.updatedAt = new Date().toISOString();
      schedulePersist();
      res.json(toPublicAwsConfig(site.connection.aws));
    })
  );

  // Testa credenciais, bucket e prefixo (com os valores digitados, mesmo sem salvar)
  router.post(
    '/cloud/test',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const body = (req.body ?? {}) as {
        config?: AwsConfigSaveBody;
        source?: Record<string, unknown>;
      };
      const stored = site.connection.aws ?? defaultAwsConfig();
      let draft = stored;
      try {
        draft = body.config
          ? applyAwsSave(stored, { ...body.config, sources: undefined }, (p) =>
              authManager.encryptSecret(p)
            )
          : stored;
      } catch (err) {
        if (err instanceof AwsConfigError) {
          res.status(400).json({ error: err.message });
          return;
        }
        throw err;
      }
      if (!body.source) {
        res.status(400).json({ error: 'Informe a fonte a testar.' });
        return;
      }
      const src = normalizeAwsSource(body.source as never, draft.region);
      if (src.kind === 'cloudwatch' ? !src.logGroup : !src.bucket) {
        res.status(400).json({
          error:
            src.kind === 'cloudwatch'
              ? 'Informe o log group do CloudWatch.'
              : 'Informe o bucket do S3.',
        });
        return;
      }
      const cfg = clientConfigFor(
        { ...site, connection: { ...site.connection, aws: draft } },
        (enc) => authManager.decryptSecret(enc)
      );
      if (!cfg) {
        res.status(400).json({ error: 'Informe a Access Key e a Secret Access Key.' });
        return;
      }
      res.json(
        src.kind === 'cloudwatch'
          ? await testCloudWatchSource(buildLogsClient(cfg, src.region), src)
          : await testSource(buildS3Client(cfg, src.region), src)
      );
    })
  );

  // Descoberta: lista log groups e prefixos de stream com as credenciais já salvas (ou as digitadas)
  router.post(
    '/cloud/discover',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const body = (req.body ?? {}) as {
        config?: AwsConfigSaveBody;
        what?: string;
        logGroup?: string;
        region?: string;
        search?: string;
      };
      const stored = site.connection.aws ?? defaultAwsConfig();
      let draft = stored;
      try {
        draft = body.config
          ? applyAwsSave(stored, { ...body.config, sources: undefined }, (p) =>
              authManager.encryptSecret(p)
            )
          : stored;
      } catch (err) {
        if (err instanceof AwsConfigError) {
          res.status(400).json({ error: err.message });
          return;
        }
        throw err;
      }
      const cfg = clientConfigFor(
        { ...site, connection: { ...site.connection, aws: draft } },
        (enc) => authManager.decryptSecret(enc)
      );
      if (!cfg) {
        res.status(400).json({
          error: 'Salve a Access Key e a Secret Access Key primeiro (seção Credenciais).',
        });
        return;
      }
      const region = /^[a-z]{2}-[a-z]+-\d$/.test(String(body.region || ''))
        ? String(body.region)
        : draft.region;
      try {
        const client = buildLogsClient(cfg, region);
        if (body.what === 'streams') {
          const group = String(body.logGroup || '').trim();
          if (!group) {
            res.status(400).json({ error: 'Escolha o log group primeiro.' });
            return;
          }
          res.json({ prefixes: await listStreamPrefixes(client, group) });
        } else {
          res.json({ groups: await listLogGroups(client, String(body.search || '')) });
        }
      } catch (err) {
        appLog.warn(opts.vendor, 'aws', 'Falha na descoberta CloudWatch', describeAwsError(err));
        res.status(400).json({ error: describeAwsError(err) });
      }
    })
  );

  // Curto de propósito: a janela é relativa a "agora", então o resultado envelhece mesmo sem ingestão nova
  const AWS_RESULT_CACHE_TTL_MS = 15_000;
  const AWS_RESULT_CACHE_MAX = 128;
  const awsResultCache = new Map<
    string,
    { syslogsRef: unknown; expiresAt: number; value: FacetReport | HttpInsights }
  >();
  const awsInFlight = new Map<string, Promise<FacetReport | HttpInsights>>();

  function getCachedAwsResult<T extends FacetReport | HttpInsights>(
    key: string,
    site: FirewallSiteRecord,
    compute: () => Promise<T>
  ): Promise<T> {
    const now = Date.now();
    const hit = awsResultCache.get(key);
    if (hit && hit.syslogsRef === site.syslogs && hit.expiresAt > now) {
      return Promise.resolve(hit.value as T);
    }
    const pending = awsInFlight.get(key);
    if (pending) return pending as Promise<T>;
    const promise = compute()
      .then((value) => {
        if (awsResultCache.size >= AWS_RESULT_CACHE_MAX) {
          const firstKey = awsResultCache.keys().next().value;
          if (firstKey !== undefined) awsResultCache.delete(firstKey);
        }
        awsResultCache.set(key, {
          syslogsRef: site.syslogs,
          expiresAt: Date.now() + AWS_RESULT_CACHE_TTL_MS,
          value,
        });
        return value;
      })
      .finally(() => {
        awsInFlight.delete(key);
      });
    awsInFlight.set(key, promise);
    return promise;
  }

  async function computeFacets(
    site: FirewallSiteRecord,
    kind: AwsLogKind,
    minutes: number
  ): Promise<FacetReport> {
    return getCachedAwsResult(`facets|${kind}|${site.id}|${minutes}`, site, async () => {
    const sinceIso =
      minutes > 0 ? new Date(Date.now() - minutes * 60 * 1000).toISOString() : undefined;
    const memoryEvents = sinceIso
      ? site.syslogs.filter((ev) => resolveEventTimeMs(ev) >= Date.parse(sinceIso))
      : site.syslogs;
    const oldestInMemory =
      site.syslogs.length > 0 ? site.syslogs[site.syslogs.length - 1]?.ingestedAt : null;
    const needDb =
      usePg &&
      (minutes === 0 ||
        site.syslogs.length >= memoryWindow ||
        (!!oldestInMemory && !!sinceIso && oldestInMemory > sinceIso));
    const bucketSec = bucketSecondsFor(minutes);
    let result = facetsFromEvents(memoryEvents, kind, bucketSec);
    let dataSource: 'memory' | 'database' = 'memory';
    if (needDb) {
      const specs = FACETS[kind];
      const agg = await cachedAggregate(
        `facets|${kind}|${site.id}|${minutes}`,
        aggTtl(minutes),
        () =>
          pgStore.aggregateFacets(
            site.id,
            sinceIso ?? new Date(0).toISOString(),
            KIND_CATEGORY[kind],
            specs,
            bucketSec,
            KIND_SQL_FILTER[kind] ?? ''
          )
      );
      if (!agg.timedOut) {
        dataSource = 'database';
        result = {
          totals: agg.totals,
          timeline: agg.timeline,
          facets: specs.map((s) => ({
            id: s.id,
            title: s.title,
            hint: s.hint,
            metric: s.metric ?? 'count',
            ip: s.ip,
            country: s.country,
            port: s.port,
            items: agg.items[s.id] ?? [],
          })),
        };
      }
    }
    for (const f of result.facets) {
      if (!f.ip) continue;
      for (const it of f.items) it.country = intel.lookup(it.key).country;
    }
    const timeline = padTimeline(result.timeline, minutes, bucketSec, (t) => ({ t, allowed: 0, blocked: 0 }));
    return { kind, minutes, generatedAt: new Date().toISOString(), dataSource, ...result, timeline };
    });
  }

  async function computeHttpInsights(
    site: FirewallSiteRecord,
    minutes: number
  ): Promise<HttpInsights> {
    return getCachedAwsResult(`http|${site.id}|${minutes}`, site, async () => {
    const sinceIso =
      minutes > 0 ? new Date(Date.now() - minutes * 60 * 1000).toISOString() : undefined;
    const memoryEvents = sinceIso
      ? site.syslogs.filter((ev) => resolveEventTimeMs(ev) >= Date.parse(sinceIso))
      : site.syslogs;
    const oldestInMemory =
      site.syslogs.length > 0 ? site.syslogs[site.syslogs.length - 1]?.ingestedAt : null;
    const needDb =
      usePg &&
      (minutes === 0 ||
        site.syslogs.length >= memoryWindow ||
        (!!oldestInMemory && !!sinceIso && oldestInMemory > sinceIso));
    const bucketSec = bucketSecondsFor(minutes);
    let rows = rowsFromAlbEvents(memoryEvents, bucketSec);
    let dataSource: 'memory' | 'database' = 'memory';
    let truncated = false;
    if (needDb) {
      const agg = await cachedAggregate(`http|${site.id}|${minutes}`, aggTtl(minutes), () =>
        pgStore.aggregateHttpInsights(
          site.id,
          sinceIso ?? new Date(0).toISOString(),
          100_000,
          bucketSec
        )
      );
      if (agg.timedOut) {
        truncated = true;
      } else {
        rows = { groups: agg.groups, clients: agg.clients, extras: agg.extras };
        truncated = agg.capped;
        dataSource = 'database';
      }
    }
    const insights = buildHttpInsights({ ...rows, minutes, dataSource, truncated });
    insights.timeline = padTimeline(insights.timeline, minutes, bucketSec, (t) => ({
      t, requests: 0, errors5xx: 0, avgTargetMs: 0, p95Ms: 0, maxMs: 0,
    }));
    return insights;
    });
  }

  // Relatório de entrega em HTML (ALB, conexões TLS, VPC Flow Logs e WAF) com a identidade do cliente
  router.get(
    '/cloud/report/html',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const minutes = radarMinutes(req) || 60;
      const wanted = String(req.query.sections || 'alb,albconn,vpcflow,waf')
        .split(',')
        .map((x) => x.trim())
        .filter(
          (x): x is AwsReportSection =>
            x === 'alb' || x === 'albconn' || x === 'vpcflow' || x === 'waf'
        );
      const sections =
        wanted.length > 0 ? wanted : (['alb', 'albconn', 'vpcflow', 'waf'] as AwsReportSection[]);
      const data: AwsReportData = {
        minutes,
        generatedAt: new Date().toISOString(),
        accountId: /^\d{12}$/.test(site.appliance.serialNumber)
          ? site.appliance.serialNumber
          : undefined,
        region: site.connection.aws?.region,
      };
      for (const s of sections) {
        if (s === 'alb') data.alb = await computeHttpInsights(site, minutes);
        else data[s] = await computeFacets(site, s, minutes);
      }
      const stamp = new Date().toISOString().slice(0, 10);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="netanalyzer-aws-${sections.length === 1 ? sections[0] : 'completo'}-${stamp}.html"`
      );
      res.setHeader('Content-Security-Policy', REPORT_HTML_CSP);
      res.send(renderAwsReportHtml(data, sections, site.name, site.branding));
    })
  );

  // Facetas por tipo de log (VPC Flow Logs, WAF e conexões TLS do ALB)
  router.get(
    '/cloud/facets',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const kind = String(req.query.kind || '') as AwsLogKind;
      if (kind !== 'vpcflow' && kind !== 'waf' && kind !== 'albconn') {
        res.status(400).json({ error: 'Informe kind=vpcflow, waf ou albconn.' });
        return;
      }
      res.json(await computeFacets(site, kind, radarMinutes(req)));
    })
  );

  // Resumo por recurso para os cartões da Visão Geral (ALB, VPC Flow Logs e WAF)
  router.get(
    '/cloud/summary',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const minutes = radarMinutes(req);
      const sinceIso =
        minutes > 0 ? new Date(Date.now() - minutes * 60 * 1000).toISOString() : undefined;
      const memoryEvents = sinceIso
        ? site.syslogs.filter((ev) => resolveEventTimeMs(ev) >= Date.parse(sinceIso))
        : site.syslogs;
      const oldestInMemory =
        site.syslogs.length > 0 ? site.syslogs[site.syslogs.length - 1]?.ingestedAt : null;
      const needDb =
        usePg &&
        (minutes === 0 ||
          site.syslogs.length >= memoryWindow ||
          (!!oldestInMemory && !!sinceIso && oldestInMemory > sinceIso));
      const bucketSec = bucketSecondsFor(minutes);
      let rows = summarizeCategories(memoryEvents);
      let timeline = timelineFromEvents(memoryEvents, bucketSec);
      if (needDb) {
        const agg = await cachedAggregate(`summary|${site.id}|${minutes}`, aggTtl(minutes), () =>
          pgStore.aggregateCategorySummary(
            site.id,
            sinceIso ?? new Date(0).toISOString(),
            bucketSec
          )
        );
        if (!agg.timedOut) {
          rows = agg.rows;
          timeline = agg.timeline;
        }
      }
      timeline = padTimeline(timeline, minutes, bucketSec, (t) => ({ t, allowed: 0, blocked: 0 }));
      res.json({ minutes, generatedAt: new Date().toISOString(), rows, timeline });
    })
  );

  // Análise de aplicação dos access logs do ALB
  router.get(
    '/cloud/http-insights',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      res.json(await computeHttpInsights(site, radarMinutes(req)));
    })
  );

  // Lê agora (em segundo plano); a tela acompanha o andamento pelo status das fontes
  router.post(
    '/cloud/sync',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const sourceId = typeof req.body?.sourceId === 'string' ? req.body.sourceId : undefined;
      const aws = site.connection.aws;
      if (!aws || aws.sources.length === 0) {
        res.status(400).json({ error: 'Cadastre ao menos uma fonte de log.' });
        return;
      }
      if (sourceId && awsIngestor.isRunning(site.id, sourceId)) {
        res.status(409).json({ error: 'Esta fonte já está sendo lida.' });
        return;
      }
      void awsIngestor.syncSite(site, sourceId);
      res.status(202).json({ ok: true, ...toPublicAwsConfig(aws) });
    })
  );
}
