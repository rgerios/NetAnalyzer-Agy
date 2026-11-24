import type express from 'express';
import { DEFAULT_AI_SETTINGS, runAiLogAnalysis, toPublicAiConfig } from '../aiClient.ts';
import { appLog } from '../appLogger.ts';
import type { AuthManager } from '../authManager.ts';
import type { PostgresStore } from '../database.ts';
import { assertSafeOutboundUrl, UnsafeOutboundUrlError } from '../securityGuards.ts';
import type {
  AiChatMessage,
  AiProviderSettings,
  AiProviderType,
  AuditOverview,
  DataStore,
  FirewallSiteRecord,
  FirewallVendor,
} from '../types.ts';
import type { AsyncRouteWrapper } from './routeHelpers.ts';

const ENC_PREFIX = 'enc:';

export interface AiAndLogsRoutesOptions {
  router: express.Router;
  vendor: FirewallVendor;
  usePg: boolean;
  pgStore: PostgresStore;
  authManager: AuthManager;
  getStore: () => DataStore;
  siteFor: (req: express.Request) => FirewallSiteRecord;
  buildOverview: (site: FirewallSiteRecord) => AuditOverview;
  schedulePersist: () => void;
  asyncRoute: AsyncRouteWrapper;
}

export function registerAiAndLogsRoutes(opts: AiAndLogsRoutesOptions): void {
  const {
    router,
    vendor,
    usePg,
    pgStore,
    authManager,
    getStore,
    siteFor,
    buildOverview,
    schedulePersist,
    asyncRoute,
  } = opts;

  function decryptAiKey(stored: string): string {
    if (!stored) return '';
    return stored.startsWith(ENC_PREFIX)
      ? authManager.decryptSecret(stored.slice(ENC_PREFIX.length))
      : stored;
  }

  function getAiSettingsPlain(): AiProviderSettings {
    const current = getStore().aiSettings || DEFAULT_AI_SETTINGS;
    return { ...current, apiKey: decryptAiKey(current.apiKey) };
  }

  async function reloadSharedAiSettings(): Promise<void> {
    if (!usePg) return;
    const shared = await pgStore.loadSharedAiSettings();
    if (shared) getStore().aiSettings = { ...DEFAULT_AI_SETTINGS, ...shared };
  }

  router.get(
    '/ai/config',
    asyncRoute(async (_req, res) => {
      await reloadSharedAiSettings();
      res.json(toPublicAiConfig(getAiSettingsPlain()));
    })
  );

  router.post(
    '/ai/config',
    asyncRoute(async (req, res) => {
      const allowedProviders = new Set<AiProviderType>(['gemini', 'openrouter', 'openai', 'local']);
      const providerRaw = String(req.body?.provider || 'gemini') as AiProviderType;
      const provider: AiProviderType = allowedProviders.has(providerRaw) ? providerRaw : 'gemini';
      const model = String(req.body?.model || '').trim();
      const baseUrl = String(req.body?.baseUrl || '').trim();
      if (baseUrl && provider !== 'gemini') {
        try {
          await assertSafeOutboundUrl(baseUrl, {
            allowLoopback: provider === 'local',
            resolveDns: false,
            label: 'URL base do provedor de IA',
          });
        } catch (err) {
          const msg = err instanceof UnsafeOutboundUrlError ? err.message : 'URL base inválida.';
          res.status(400).json({ error: msg });
          return;
        }
      }
      const incomingKey = typeof req.body?.apiKey === 'string' ? req.body.apiKey.trim() : undefined;
      const clearKey = Boolean(req.body?.clearKey);
      const anonymizeIncoming =
        typeof req.body?.anonymize === 'boolean' ? req.body.anonymize : undefined;

      await reloadSharedAiSettings();

      let plainKey = getAiSettingsPlain().apiKey;
      if (clearKey) {
        plainKey = '';
      } else if (incomingKey !== undefined && incomingKey.length > 0) {
        plainKey = incomingKey;
      }

      const updated: AiProviderSettings = {
        provider,
        model: model || (provider === 'gemini' ? DEFAULT_AI_SETTINGS.model : ''),
        baseUrl,
        apiKey: plainKey ? `${ENC_PREFIX}${authManager.encryptSecret(plainKey)}` : '',
        anonymize: anonymizeIncoming ?? getAiSettingsPlain().anonymize !== false,
      };

      getStore().aiSettings = updated;
      if (usePg) {
        await pgStore.saveSharedAiSettings(updated);
      } else {
        schedulePersist();
      }
      res.json(toPublicAiConfig(getAiSettingsPlain()));
    })
  );

  router.post(
    '/ai/chat',
    asyncRoute(async (req, res) => {
      const site = siteFor(req);
      const message = String(req.body?.message || '').trim();
      const history = Array.isArray(req.body?.history)
        ? (req.body.history as AiChatMessage[])
        : [];
      const overrideModel = typeof req.body?.model === 'string' ? req.body.model.trim() : '';

      if (!message) {
        res.status(400).json({ error: 'Digite uma pergunta ou cole um trecho de log para análise.' });
        return;
      }

      await reloadSharedAiSettings();
      const baseSettings = getAiSettingsPlain();
      const settings: AiProviderSettings = overrideModel
        ? { ...baseSettings, model: overrideModel }
        : baseSettings;

      try {
        const result = await runAiLogAnalysis({
          settings,
          overview: buildOverview(site),
          syslogs: site.syslogs,
          rules: site.rules,
          nats: site.nats,
          history,
          message,
        });

        res.json({
          reply: result.reply,
          modelUsed: result.modelUsed,
          provider: result.provider,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : 'Falha ao consultar o provedor de IA.';
        appLog.error(
          vendor,
          'ai',
          `Falha na consulta IA (${settings.provider}/${settings.model})`,
          errMsg
        );
        res.status(502).json({ error: errMsg });
      }
    })
  );

  router.get('/app-logs', (req, res) => {
    const levelRaw = typeof req.query.level === 'string' ? req.query.level : 'all';
    const level =
      levelRaw === 'info' || levelRaw === 'warn' || levelRaw === 'error' ? levelRaw : 'all';
    const search = typeof req.query.search === 'string' ? req.query.search : '';
    const limit = Number(req.query.limit || 150);
    res.json({
      logs: appLog.list({ vendor, level, search, limit }),
    });
  });

  router.delete('/app-logs', (_req, res) => {
    appLog.clear(vendor);
    res.json({ ok: true });
  });
}
