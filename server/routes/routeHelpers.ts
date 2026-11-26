import type express from 'express';

export type AsyncRouteWrapper = (
  handler: (req: express.Request, res: express.Response) => Promise<void>
) => (req: express.Request, res: express.Response) => void;

export function radarMinutes(req: express.Request): number {
  const raw = Number(req.query.minutes ?? 0);
  return Number.isFinite(raw) && raw > 0 ? Math.min(43200, Math.floor(raw)) : 0;
}

export function aggTtl(minutes: number): number {
  return minutes > 0 && minutes <= 360 ? 15_000 : 45_000;
}

/** Idade máxima de um resultado servido do cache; acima disso a requisição espera o cálculo novo. */
export function maxStaleMs(ttlMs: number): number {
  return ttlMs <= 15_000 ? 60_000 : 10 * 60_000;
}

/**
 * Cache em memória com renovação em segundo plano (stale-while-revalidate) para agregações
 * pesadas no banco (Behavior, Radares e painéis AWS).
 */
export function createAggregateCache(flushPendingInserts: () => Promise<void>) {
  const aggCache = new Map<string, { at: number; data: unknown }>();
  const aggPending = new Map<string, Promise<{ at: number; data: unknown }>>();

  return async function cachedAggregate<T extends { timedOut: boolean }>(
    key: string,
    ttlMs: number,
    load: () => Promise<T>
  ): Promise<T> {
    const refresh = (): Promise<{ at: number; data: unknown }> => {
      const running = aggPending.get(key);
      if (running) return running;
      const p = (async () => {
        await flushPendingInserts();
        const data = await load();
        const entry = { at: Date.now(), data: data as unknown };
        if (!data.timedOut) {
          aggCache.set(key, entry);
          while (aggCache.size > 12) {
            const oldest = [...aggCache.entries()].sort((x, y) => x[1].at - y[1].at)[0];
            if (!oldest) break;
            aggCache.delete(oldest[0]);
          }
        }
        return entry;
      })().finally(() => aggPending.delete(key));
      aggPending.set(key, p);
      return p;
    };
    const cached = aggCache.get(key);
    if (cached && Date.now() - cached.at <= maxStaleMs(ttlMs)) {
      if (Date.now() - cached.at > ttlMs) void refresh().catch(() => undefined);
      return cached.data as T;
    }
    return (await refresh()).data as T;
  };
}
