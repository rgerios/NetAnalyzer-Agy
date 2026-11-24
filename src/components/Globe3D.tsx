import { useEffect, useMemo, useRef, useState } from 'react';
import { geoContains, geoDistance, geoGraticule10, geoInterpolate, geoOrthographic, geoPath } from 'd3-geo';
import { LocateFixed, Pause, Play } from 'lucide-react';
import type { BehaviorCountry } from '../types.ts';
import { heatHue } from '../utils/heat.ts';
import { countryName, flagEmoji, getWorldGeo } from '../utils/worldGeo.ts';
import type { FlowBatch, MapMode } from './WorldMap.tsx';

interface Globe3DProps {
  countries: BehaviorCountry[];
  originCode: string;
  mode: MapMode;
  selected: string | null;
  onSelect: (code: string | null) => void;
  batch: FlowBatch | null;
  /** Janela (ms) em que um lote é reproduzido: igual ao intervalo de atualização. */
  replayMs: number;
}

type LonLat = [number, number];

const MAX_ARCS = 14;
const MAX_LIVE_PARTICLES = 260;
const SPIN_DEG_PER_S = 7;
const DRAG_DEG_PER_PX = 0.4;
const fmt = (n: number) => n.toLocaleString('pt-BR');
const heatT = (conn: number, max: number) => (max > 0 ? Math.log1p(conn) / Math.log1p(max) : 0);
const reducedMotion = () => typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

interface ArcDef {
  code: string;
  interp: (t: number) => LonLat;
  dist: number;
  color: string;
  width: number;
}

interface Pending {
  at: number;
  code: string;
  blocked: boolean;
  threat: boolean;
}

interface Live {
  arc: ArcDef;
  start: number;
  dur: number;
  blocked: boolean;
  threat: boolean;
}

interface Palette {
  surfaceAlt: string;
  border: string;
  borderStrong: string;
}

/** Altura do arco sobre a superfície (fração do raio): maior para rotas mais longas. */
const liftMax = (dist: number) => 0.05 + 0.2 * (dist / Math.PI);

export function Globe3D({ countries, originCode, mode, selected, onSelect, batch, replayMs }: Globe3DProps) {
  const geo = useMemo(() => getWorldGeo(), []);
  const still = useMemo(() => reducedMotion(), []);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [hover, setHover] = useState<{ code: string; x: number; y: number } | null>(null);
  const [spinning, setSpinning] = useState(!still);

  const byCode = useMemo(() => new Map(countries.map((c) => [c.code, c])), [countries]);
  const max = useMemo(() => countries.reduce((m, c) => Math.max(m, c.connections), 0), [countries]);
  const origin = geo.byCode.get(originCode);
  const originLL: LonLat | null = origin ? origin.centroid : null;

  // Países com rota desenhada: os mais acessados + qualquer um que apareça no lote em reprodução
  const arcCodes = useMemo(() => {
    const set = new Set(countries.filter((c) => c.code !== originCode).slice(0, MAX_ARCS).map((c) => c.code));
    for (const f of batch?.flows ?? []) if (f.country !== originCode) set.add(f.country);
    return [...set];
  }, [countries, originCode, batch]);

  const arcs = useMemo<ArcDef[]>(() => {
    if (!originLL) return [];
    const topMax = countries.filter((c) => c.code !== originCode).reduce((m, c) => Math.max(m, c.connections), 0);
    const out: ArcDef[] = [];
    for (const code of arcCodes) {
      const g = geo.byCode.get(code);
      if (!g) continue;
      const c = byCode.get(code);
      const share = c && topMax > 0 ? c.connections / topMax : 0.05;
      out.push({
        code,
        interp: geoInterpolate(originLL, g.centroid),
        dist: geoDistance(originLL, g.centroid),
        color: c && c.threatIps > 0 ? '#ef4444' : c && c.connections > 0 && c.blocked / c.connections > 0.3 ? '#f59e0b' : '#38bdf8',
        width: 0.8 + share * 2.2,
      });
    }
    return out;
  }, [arcCodes, byCode, countries, geo, originCode, originLL]);

  // Estado lido pelo laço de animação (evita recriar o laço a cada render)
  const live = useRef({ arcs, byCode, max, countries, originCode, originLL, selected, mode, still });
  live.current = { arcs, byCode, max, countries, originCode, originLL, selected, mode, still };
  const spinRef = useRef(spinning);
  spinRef.current = spinning;

  const rot = useRef<LonLat>([-45, -10]);
  const drag = useRef<{ active: boolean; x: number; y: number; r0: LonLat; moved: boolean }>({ active: false, x: 0, y: 0, r0: [0, 0], moved: false });
  const hoverCode = useRef<string | null>(null);
  const pending = useRef<Pending[]>([]);
  const particles = useRef<Live[]>([]);
  const lastBatch = useRef(-1);
  const size = useRef({ w: 800, h: 520, dpr: 1 });
  const projRef = useRef(geoOrthographic().clipAngle(90).precision(0.6));
  const palette = useRef<Palette>({ surfaceAlt: '#E1E0E0', border: '#DDDCDC', borderStrong: '#BDBBBB' });

  // Centraliza na origem quando ela muda
  useEffect(() => {
    if (originLL) rot.current = [originLL[0], Math.max(-45, Math.min(45, originLL[1] * 0.6))];
  }, [originLL?.[0], originLL?.[1]]); // eslint-disable-line react-hooks/exhaustive-deps

  // Novo lote de conexões reais: agenda cada uma no instante proporcional ao horário em que ocorreu
  useEffect(() => {
    if (mode !== 'realtime' || still || !batch || batch.id === lastBatch.current) return;
    lastBatch.current = batch.id;
    const flows = batch.flows.filter((f) => f.country !== originCode);
    if (flows.length === 0) return;
    const times = flows.map((f) => Date.parse(f.at));
    const first = Math.min(...times);
    const span = Math.max(1, Math.max(...times) - first);
    const now = performance.now();
    const window = Math.max(1500, replayMs - 800);
    flows.forEach((f, i) => {
      const offset = span <= 1 ? (i / flows.length) * window : ((times[i] - first) / span) * window;
      pending.current.push({ at: now + offset, code: f.country, blocked: f.blocked, threat: f.threat });
    });
    if (pending.current.length > 2000) pending.current.splice(0, pending.current.length - 2000);
  }, [batch, mode, still, originCode, replayMs]);

  useEffect(() => {
    if (mode !== 'realtime' || still) {
      pending.current = [];
      particles.current = [];
    }
  }, [mode, still]);

  // Tamanho do canvas acompanha o contêiner
  useEffect(() => {
    const el = containerRef.current;
    const canvas = canvasRef.current;
    if (!el || !canvas) return;
    const apply = () => {
      const w = Math.max(320, Math.round(el.clientWidth));
      const h = Math.round(Math.min(680, Math.max(380, w * 0.5)));
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      size.current = { w, h, dpr };
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
    };
    apply();
    const ro = new ResizeObserver(apply);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Laço de animação: gira o globo, desenha tudo e move as conexões reais
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !container || !ctx) return;
    let raf = 0;
    let last = performance.now();
    let paletteAt = 0;

    const readPalette = (t: number) => {
      if (t - paletteAt < 600) return;
      paletteAt = t;
      const cs = getComputedStyle(container);
      const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback;
      palette.current = {
        surfaceAlt: v('--fw-surface-alt', '#E1E0E0'),
        border: v('--fw-border', '#DDDCDC'),
        borderStrong: v('--fw-border-strong', '#BDBBBB'),
      };
    };

    const tick = (t: number) => {
      raf = requestAnimationFrame(tick);
      if (document.hidden) {
        last = t;
        return;
      }
      const dt = Math.min(64, t - last);
      last = t;
      const L = live.current;
      if (spinRef.current && !drag.current.active && hoverCode.current === null) {
        rot.current[0] += (dt / 1000) * SPIN_DEG_PER_S;
      }
      readPalette(t);

      const { w, h, dpr } = size.current;
      const r = (Math.min(w, h) / 2) * 0.93;
      const cx = w / 2;
      const cy = h / 2;
      const projection = projRef.current;
      projection.scale(r).translate([cx, cy]).rotate([-rot.current[0], -rot.current[1], 0]);
      const path = geoPath(projection, ctx);
      const pal = palette.current;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      // atmosfera
      const glow = ctx.createRadialGradient(cx, cy, r * 0.97, cx, cy, r * 1.16);
      glow.addColorStop(0, 'rgba(56,189,248,0.30)');
      glow.addColorStop(1, 'rgba(56,189,248,0)');
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(cx, cy, r * 1.16, 0, Math.PI * 2);
      ctx.fill();

      // oceano
      const ocean = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.4, r * 0.1, cx, cy, r);
      ocean.addColorStop(0, 'rgba(125,211,252,0.30)');
      ocean.addColorStop(1, 'rgba(14,116,144,0.16)');
      ctx.beginPath();
      path({ type: 'Sphere' });
      ctx.fillStyle = ocean;
      ctx.fill();
      ctx.strokeStyle = pal.borderStrong;
      ctx.lineWidth = 0.8;
      ctx.stroke();

      // meridianos e paralelos
      ctx.beginPath();
      path(geoGraticule10());
      ctx.strokeStyle = 'rgba(148,163,184,0.20)';
      ctx.lineWidth = 0.5;
      ctx.stroke();

      // países
      for (const c of geo.countries) {
        const data = L.byCode.get(c.code);
        const tt = data ? heatT(data.connections, L.max) : 0;
        let fill = pal.surfaceAlt;
        let alpha = 1;
        if (data) {
          if (L.mode === 'static') {
            fill = `hsl(${heatHue(tt)} 85% 52%)`;
            alpha = 0.35 + tt * 0.6;
          } else {
            fill = '#38bdf8';
            alpha = 0.12 + tt * 0.42;
          }
        }
        if (c.code === L.originCode) {
          fill = '#2563eb';
          alpha = 0.6;
        }
        const isSel = L.selected === c.code;
        ctx.beginPath();
        path(c.feature);
        // base opaca (cor da terra) e, por cima, o calor com a transparência própria
        ctx.globalAlpha = 1;
        ctx.fillStyle = pal.surfaceAlt;
        ctx.fill();
        if (alpha < 1 || fill !== pal.surfaceAlt) {
          ctx.globalAlpha = alpha;
          ctx.fillStyle = fill;
          ctx.fill();
          ctx.globalAlpha = 1;
        }
        ctx.strokeStyle = isSel ? '#f8fafc' : pal.borderStrong;
        ctx.lineWidth = isSel ? 1.6 : 0.4;
        ctx.stroke();
      }

      // volume: escurece as bordas e clareia o lado da luz
      const shade = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.4, r * 0.15, cx, cy, r);
      shade.addColorStop(0, 'rgba(255,255,255,0.10)');
      shade.addColorStop(0.65, 'rgba(0,0,0,0)');
      shade.addColorStop(1, 'rgba(2,6,23,0.34)');
      ctx.beginPath();
      path({ type: 'Sphere' });
      ctx.fillStyle = shade;
      ctx.fill();

      const lifted = (ll: LonLat, lift: number): [number, number] | null => {
        const p = projection(ll);
        if (!p) return null;
        return [cx + (p[0] - cx) * (1 + lift), cy + (p[1] - cy) * (1 + lift)];
      };

      const realtime = L.mode === 'realtime';

      // rotas em arco, levantadas sobre a superfície
      if (realtime) {
        for (const a of L.arcs) {
          const faded = L.selected && L.selected !== a.code;
          ctx.beginPath();
          let pen = false;
          const steps = 44;
          for (let i = 0; i <= steps; i += 1) {
            const u = i / steps;
            const p = lifted(a.interp(u), Math.sin(Math.PI * u) * liftMax(a.dist));
            if (!p) {
              pen = false;
              continue;
            }
            if (pen) ctx.lineTo(p[0], p[1]);
            else ctx.moveTo(p[0], p[1]);
            pen = true;
          }
          ctx.strokeStyle = a.color;
          ctx.globalAlpha = faded ? 0.1 : 0.4;
          ctx.lineWidth = a.width;
          ctx.lineCap = 'round';
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }

      // nascimento das conexões reais
      if (realtime && !L.still) {
        const rest: Pending[] = [];
        for (const p of pending.current) {
          if (p.at > t) {
            rest.push(p);
            continue;
          }
          const arc = L.arcs.find((x) => x.code === p.code);
          if (!arc || particles.current.length >= MAX_LIVE_PARTICLES) continue;
          particles.current.push({
            arc,
            start: t,
            dur: Math.min(3600, 1500 + arc.dist * 900),
            blocked: p.blocked,
            threat: p.threat,
          });
        }
        pending.current = rest;
      }

      // partículas
      if (realtime && !L.still) {
        const keep: Live[] = [];
        for (const pt of particles.current) {
          const prog = (t - pt.start) / pt.dur;
          // bloqueada: morre a ~35% do caminho; permitida: chega ao destino
          const stopAt = pt.blocked ? 0.35 : 1;
          const u = Math.min(prog, stopAt);
          const color = pt.threat ? '#f43f5e' : pt.blocked ? '#f59e0b' : '#38bdf8';
          const lm = liftMax(pt.arc.dist);
          if (prog < stopAt) {
            // rastro
            for (let k = 3; k >= 0; k -= 1) {
              const uu = Math.max(0, u - k * 0.014);
              const p = lifted(pt.arc.interp(uu), Math.sin(Math.PI * uu) * lm);
              if (!p) continue;
              ctx.beginPath();
              ctx.arc(p[0], p[1], (pt.threat ? 3.4 : 2.4) * (1 - k * 0.18), 0, Math.PI * 2);
              ctx.fillStyle = color;
              ctx.globalAlpha = k === 0 ? 1 : 0.32 - k * 0.07;
              ctx.shadowColor = color;
              ctx.shadowBlur = k === 0 ? 10 : 0;
              ctx.fill();
            }
            ctx.shadowBlur = 0;
            ctx.globalAlpha = 1;
          } else {
            // impacto: anel que se expande onde a conexão chegou (ou morreu)
            const q = Math.min(1, (prog - stopAt) / 0.3);
            const p = lifted(pt.arc.interp(stopAt), Math.sin(Math.PI * stopAt) * lm);
            if (p && q < 1) {
              ctx.beginPath();
              ctx.arc(p[0], p[1], 2 + q * (pt.threat ? 14 : 9), 0, Math.PI * 2);
              ctx.strokeStyle = color;
              ctx.globalAlpha = 1 - q;
              ctx.lineWidth = 1.4;
              ctx.stroke();
              ctx.globalAlpha = 1;
            }
            if (q >= 1) continue;
          }
          keep.push(pt);
        }
        particles.current = keep;
      }

      // pontos vermelhos: destinos no centro do país
      const topN = L.mode === 'static' ? 60 : 24;
      let shown = 0;
      for (const c of L.countries) {
        if (c.code === L.originCode) continue;
        if (shown >= topN) break;
        shown += 1;
        const g = geo.byCode.get(c.code);
        const p = g ? projection(g.centroid) : null;
        if (!p) continue;
        const rr = 2 + heatT(c.connections, L.max) * 4.5;
        if (c.threatIps > 0 && !L.still) {
          const q = (t % 2200) / 2200;
          ctx.beginPath();
          ctx.arc(p[0], p[1], rr + q * 9, 0, Math.PI * 2);
          ctx.strokeStyle = '#ef4444';
          ctx.globalAlpha = 0.8 * (1 - q);
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
        ctx.beginPath();
        ctx.arc(p[0], p[1], rr, 0, Math.PI * 2);
        ctx.fillStyle = '#ef4444';
        ctx.globalAlpha = c.threatIps > 0 ? 1 : 0.88;
        ctx.fill();
        ctx.globalAlpha = 1;
        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      // origem (azul), com pulso
      if (L.originLL) {
        const p = projection(L.originLL);
        if (p) {
          if (!L.still) {
            const q = (t % 2600) / 2600;
            ctx.beginPath();
            ctx.arc(p[0], p[1], 5 + q * 12, 0, Math.PI * 2);
            ctx.strokeStyle = '#60a5fa';
            ctx.globalAlpha = 0.9 * (1 - q);
            ctx.lineWidth = 1.2;
            ctx.stroke();
            ctx.globalAlpha = 1;
          }
          ctx.beginPath();
          ctx.arc(p[0], p[1], 5, 0, Math.PI * 2);
          ctx.fillStyle = '#3b82f6';
          ctx.fill();
          ctx.strokeStyle = '#fff';
          ctx.lineWidth = 1.4;
          ctx.stroke();
        }
      }
    };

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [geo]);

  // ----- interação: arrastar para girar, passar o mouse e clicar em um país -----
  const countryAt = (clientX: number, clientY: number): string | null => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const box = canvas.getBoundingClientRect();
    const ll = projRef.current.invert?.([clientX - box.left, clientY - box.top]);
    if (!ll || !Number.isFinite(ll[0]) || !Number.isFinite(ll[1])) return null;
    for (const c of geo.countries) {
      if (geoContains(c.feature, ll as LonLat)) return c.code;
    }
    return null;
  };

  const lastHoverAt = useRef(0);
  const onPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    drag.current = { active: true, x: e.clientX, y: e.clientY, r0: [...rot.current] as LonLat, moved: false };
    e.currentTarget.setPointerCapture(e.pointerId);
    hoverCode.current = null;
    setHover(null);
  };
  const onPointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const d = drag.current;
    if (d.active) {
      const dx = e.clientX - d.x;
      const dy = e.clientY - d.y;
      if (Math.abs(dx) + Math.abs(dy) > 4) d.moved = true;
      rot.current = [d.r0[0] - dx * DRAG_DEG_PER_PX, Math.max(-85, Math.min(85, d.r0[1] + dy * DRAG_DEG_PER_PX))];
      return;
    }
    const now = performance.now();
    if (now - lastHoverAt.current < 40) return;
    lastHoverAt.current = now;
    const code = countryAt(e.clientX, e.clientY);
    const box = canvasRef.current?.getBoundingClientRect();
    if (code && live.current.byCode.has(code) && box) {
      hoverCode.current = code;
      setHover({ code, x: e.clientX - box.left, y: e.clientY - box.top });
    } else if (hoverCode.current !== null) {
      hoverCode.current = null;
      setHover(null);
    }
  };
  const onPointerUp = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const d = drag.current;
    drag.current = { ...d, active: false };
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
    if (!d.moved) {
      const code = countryAt(e.clientX, e.clientY);
      if (code && live.current.byCode.has(code)) onSelect(live.current.selected === code ? null : code);
    }
  };
  const onPointerLeave = () => {
    hoverCode.current = null;
    setHover(null);
  };

  const hovered = hover ? byCode.get(hover.code) : null;

  return (
    <div ref={containerRef} className="relative rounded-md bg-[var(--fw-surface-soft)] overflow-hidden select-none">
      <canvas
        ref={canvasRef}
        role="img"
        aria-label="Globo 3D de tráfego por país. Arraste para girar."
        className="block mx-auto touch-none cursor-grab active:cursor-grabbing"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onPointerLeave={onPointerLeave}
      />

      <div className="absolute top-2 right-2 flex gap-1.5">
        <button
          type="button"
          onClick={() => setSpinning((s) => !s)}
          aria-pressed={spinning}
          title={spinning ? 'Pausar a rotação' : 'Girar automaticamente'}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border border-[var(--fw-border-strong)] bg-white/90 text-[var(--fw-heading)] hover:bg-white"
        >
          {spinning ? <Pause className="w-3.5 h-3.5" aria-hidden="true" /> : <Play className="w-3.5 h-3.5" aria-hidden="true" />}
          {spinning ? 'Pausar' : 'Girar'}
        </button>
        <button
          type="button"
          onClick={() => {
            if (originLL) rot.current = [originLL[0], Math.max(-45, Math.min(45, originLL[1] * 0.6))];
          }}
          title="Voltar a mostrar o país de origem"
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border border-[var(--fw-border-strong)] bg-white/90 text-[var(--fw-heading)] hover:bg-white"
        >
          <LocateFixed className="w-3.5 h-3.5" aria-hidden="true" /> Origem
        </button>
      </div>

      {hovered && hover && (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 w-56 rounded-lg border border-[var(--fw-border-strong)] bg-white p-3 text-xs shadow-xl"
          style={{ left: Math.min(hover.x + 14, size.current.w - 232), top: hover.y + 14 }}
        >
          <p className="font-semibold text-[var(--fw-heading)]">
            {flagEmoji(hovered.code)} {countryName(hovered.code)}
          </p>
          <p className="mt-1 text-[var(--fw-text-muted)] tabular-nums">
            {fmt(hovered.connections)} conexões · {fmt(hovered.blocked)} bloqueadas
          </p>
          <p className="text-[var(--fw-text-muted)] tabular-nums">{fmt(hovered.ips)} IPs distintos</p>
          {hovered.threatIps > 0 && <p className="mt-1 font-semibold text-red-600">{fmt(hovered.threatIps)} IP(s) em lista de ameaça</p>}
        </div>
      )}
    </div>
  );
}
