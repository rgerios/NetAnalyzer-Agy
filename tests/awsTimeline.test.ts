import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import { padTimeline } from '../server/facets.ts';
import { createAggregateCache } from '../server/routes/routeHelpers.ts';

describe('período dos painéis AWS', () => {
  it('a linha do tempo cobre a janela inteira até agora', () => {
    const now = Date.parse('2026-11-26T15:50:30.000Z');
    const point = { t: '2026-11-26T15:30:00.000Z', n: 5 };
    const out = padTimeline([point], 30, 60, (t) => ({ t, n: 0 }), now);
    assert.equal(out[0].t, '2026-11-26T15:20:00.000Z');
    assert.equal(out.at(-1)?.t, '2026-11-26T15:50:00.000Z');
    assert.equal(out.length, 31);
    assert.equal(out[10], point);
  });

  it('o cache não devolve resultado muito antigo', async () => {
    mock.timers.enable({ apis: ['Date'], now: 0 });
    try {
      const cached = createAggregateCache(async () => undefined);
      let n = 0;
      const load = async () => ({ timedOut: false, n: ++n });
      assert.equal((await cached('k', 15_000, load)).n, 1);
      mock.timers.setTime(3 * 3_600_000);
      assert.equal((await cached('k', 15_000, load)).n, 2);
    } finally {
      mock.timers.reset();
    }
  });
});
