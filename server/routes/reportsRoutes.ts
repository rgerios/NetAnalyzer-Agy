import type express from 'express';
import { EMPTY_BRANDING } from '../../shared/branding.ts';
import { aggregateEventsInMemory, buildAccessReport } from '../accessReport.ts';
import { renderAccessReportHtml } from '../accessReportHtml.ts';
import { appLog } from '../appLogger.ts';
import type { PostgresStore } from '../database.ts';
import type { createIntel } from '../intel.ts';
import { getSharedResolver } from '../rdns.ts';
import { applyBranding, BrandingError } from '../reportBranding.ts';
import {
  buildAuditReport,
  renderReportHtml,
  renderReportMarkdown,
} from '../reportBuilder.ts';
import { createScheduledReports } from '../scheduledReports.ts';
import { REPORT_HTML_CSP } from '../securityGuards.ts';
import type { AuditOverview, DataStore, FirewallSiteRecord, FirewallVendor } from '../types.ts';
import type { AsyncRouteWrapper } from './routeHelpers.ts';

export interface ReportsRoutesOptions {
  router: express.Router;
  vendor: FirewallVendor;
  isAws: boolean;
  usePg: boolean;
  dataDir: string;
  pgStore: PostgresStore;
  intel: ReturnType<typeof createIntel>;
  getStore: () => DataStore;
  siteFor: (req: express.Request) => FirewallSiteRecord;
  buildOverview: (site: FirewallSiteRecord) => AuditOverview;
  flushPendingInserts: () => Promise<void>;
  schedulePersist: () => void;
  asyncRoute: AsyncRouteWrapper;
}

export function registerReportsRoutes(opts: ReportsRoutesOptions): { stop: () => void } {
  const {
    router,
    vendor,
    isAws,
    usePg,
    dataDir,
    pgStore,
    intel,
    getStore,
    siteFor,
    buildOverview,
    flushPendingInserts,
    schedulePersist,
    asyncRoute,
  } = opts;

  const brand = isAws
    ? { label: 'AWS', accent: '#0f766e' }
    : vendor === 'fortigate'
      ? { label: 'FortiGate', accent: '#da291c' }
      : { label: 'SonicWall', accent: '#e8590c' };

  router.get('/report', (req, res) => {
    const site = siteFor(req);
    const overview = buildOverview(site);
    res.json(buildAuditReport(overview, site.syslogs, site.rules, site.nats));
  });

  async function computeAccessReport(
    site: FirewallSiteRecord,
    minutes: number,
    timeoutMs?: number
  ) {
    const sinceIso = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    let agg;
    let dataSource: 'memory' | 'database' = 'memory';
    if (usePg) {
      await flushPendingInserts();
      agg = await pgStore.aggregateAccess(site.id, sinceIso, undefined, timeoutMs);
      dataSource = 'database';
    } else {
      agg = aggregateEventsInMemory(
        site.syslogs.filter((ev) => !ev.ingestedAt || ev.ingestedAt >= sinceIso)
      );
    }
    const resolver = getSharedResolver();
    const report = buildAccessReport({
      agg,
      vendor,
      inbound: isAws,
      minutes,
      sinceIso,
      dataSource,
      intel,
      lookupHost: (ip) => resolver.lookupCached(ip),
    });
    resolver.schedule(
      report.destinations
        .filter((d) => d.host === null && d.country !== null)
        .slice(0, 40)
        .map((d) => d.ip)
    );
    return report;
  }

  router.get(
    '/access-report',
    asyncRoute(async (req, res) => {
      const raw = Number(req.query.minutes ?? 1440);
      const minutes = Number.isFinite(raw) && raw > 0 ? Math.min(43200, Math.floor(raw)) : 1440;
      res.json(await computeAccessReport(siteFor(req), minutes));
    })
  );

  router.get('/branding', (req, res) => {
    res.json(siteFor(req).branding ?? { ...EMPTY_BRANDING });
  });

  router.put(
    '/branding',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      try {
        site.branding = applyBranding(site.branding, (req.body ?? {}) as Record<string, unknown>);
      } catch (err) {
        if (err instanceof BrandingError) {
          res.status(400).json({ error: err.message });
          return;
        }
        throw err;
      }
      site.updatedAt = new Date().toISOString();
      schedulePersist();
      res.json(site.branding);
    })
  );

  router.get(
    '/access-report/html',
    asyncRoute(async (req, res) => {
      const raw = Number(req.query.minutes ?? 1440);
      const minutes = Number.isFinite(raw) && raw > 0 ? Math.min(43200, Math.floor(raw)) : 1440;
      const site = siteFor(req);
      const report = await computeAccessReport(site, minutes);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="netanalyzer-acessos-${new Date().toISOString().slice(0, 10)}.html"`
      );
      res.setHeader('Content-Security-Policy', REPORT_HTML_CSP);
      res.send(renderAccessReportHtml(report, site.name, brand, site.branding));
    })
  );

  const scheduled = createScheduledReports({
    dataDir,
    brand,
    getBranding: (siteId) => getStore().sites[siteId]?.branding,
    listSites: () => Object.values(getStore().sites).map((s) => ({ id: s.id, name: s.name })),
    generate: (siteId, minutes) => {
      const site = getStore().sites[siteId];
      if (!site) throw new Error('Localidade não encontrada.');
      return computeAccessReport(
        site,
        minutes,
        Number(process.env.REPORT_SCHEDULED_TIMEOUT_MS) || 0
      );
    },
    log: (level, message, detail) => appLog[level](vendor, 'scheduled-report', message, detail),
  });
  scheduled.start();

  router.get(
    '/reports/schedule',
    asyncRoute(async (req, res) => {
      res.json(await scheduled.state(siteFor(req).id));
    })
  );

  router.put(
    '/reports/schedule',
    asyncRoute(async (req, res) => {
      const b = (req.body ?? {}) as Record<string, unknown>;
      if (b.everyHours !== undefined && ![24, 72, 168].includes(Number(b.everyHours))) {
        res.status(400).json({ error: 'Frequência inválida: use 24 horas, 3 dias ou 7 dias.' });
        return;
      }
      if (b.timeOfDay !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(b.timeOfDay))) {
        res.status(400).json({ error: 'Horário inválido: use HH:MM.' });
        return;
      }
      res.json(
        await scheduled.save(siteFor(req).id, {
          enabled: b.enabled === undefined ? undefined : Boolean(b.enabled),
          everyHours: b.everyHours === undefined ? undefined : Number(b.everyHours),
          timeOfDay: b.timeOfDay === undefined ? undefined : String(b.timeOfDay),
          keep: b.keep === undefined ? undefined : Number(b.keep),
        })
      );
    })
  );

  router.post(
    '/reports/schedule/run',
    asyncRoute(async (req, res) => {
      const siteId = siteFor(req).id;
      if (scheduled.isRunning()) {
        res.status(409).json({ error: 'Já existe um relatório sendo gerado.' });
        return;
      }
      const rawMin = Number((req.body as { minutes?: unknown } | undefined)?.minutes);
      const minutes = [60, 360, 1440, 4320, 10080, 43200].includes(rawMin) ? rawMin : undefined;
      void scheduled
        .runNow(siteId, 'manual', minutes)
        .catch((err) =>
          appLog.warn(
            vendor,
            'scheduled-report',
            'Falha ao gerar o relatório',
            err instanceof Error ? err.message : String(err)
          )
        );
      res.status(202).json({ ok: true });
    })
  );

  router.get(
    '/reports/files/:id',
    asyncRoute(async (req, res) => {
      const found = await scheduled.filePath(siteFor(req).id, String(req.params.id));
      if (!found) {
        res.status(404).json({ error: 'Relatório não encontrado.' });
        return;
      }
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `${req.query.view === '1' ? 'inline' : 'attachment'}; filename="${found.filename}"`
      );
      res.setHeader('Content-Security-Policy', REPORT_HTML_CSP);
      res.sendFile(found.file);
    })
  );

  router.delete(
    '/reports/files/:id',
    asyncRoute(async (req, res) => {
      const ok = await scheduled.remove(siteFor(req).id, String(req.params.id));
      res.status(ok ? 200 : 404).json(ok ? { ok: true } : { error: 'Relatório não encontrado.' });
    })
  );

  router.get('/report/download', (req, res) => {
    const site = siteFor(req);
    const format = String(req.query.format || 'html').toLowerCase();
    const overview = buildOverview(site);
    const report = buildAuditReport(overview, site.syslogs, site.rules, site.nats);
    const stamp = new Date().toISOString().slice(0, 10);
    const slug = isAws ? 'aws' : vendor === 'fortigate' ? 'fortigate' : 'sonicwall';

    if (format === 'md' || format === 'markdown') {
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="netanalyzer-${slug}-${stamp}.md"`);
      res.send(renderReportMarkdown(report));
      return;
    }

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="netanalyzer-${slug}-${stamp}.json"`
      );
      res.send(JSON.stringify(report, null, 2));
      return;
    }

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="netanalyzer-${slug}-${stamp}.html"`);
    res.setHeader('Content-Security-Policy', REPORT_HTML_CSP);
    res.send(renderReportHtml(report, site.branding));
  });

  return { stop: () => scheduled.stop() };
}
