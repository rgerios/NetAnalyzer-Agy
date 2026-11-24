/**
 * Registro das linhas de log que os analisadores não conseguiram interpretar. Sem isso, um tipo de
 * mensagem novo do firewall simplesmente some. As linhas parecidas são agrupadas por "forma" (números
 * e endereços trocados por marcadores), então um volume grande de uma mesma mensagem vira uma linha só.
 */

import type { UnrecognizedShape, UnrecognizedSnapshot, UnrecognizedSource } from '../shared/unrecognized.ts';

export type { UnrecognizedShape, UnrecognizedSnapshot, UnrecognizedSource };

const SAMPLE_MAX = 600;
const KEY_MAX = 180;

/** "Forma" da linha: números, IPs, hashes e textos entre aspas viram marcadores. */
export function shapeOf(line: string): string {
  return line
    .slice(0, 1000)
    .replace(/"[^"]*"/g, '"…"')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, 'IP')
    .replace(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi, 'MAC')
    .replace(/\b[0-9a-f]{12,}\b/gi, 'HEX')
    .replace(/\d+/g, '#')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, KEY_MAX);
}

export function createUnrecognizedTracker(maxShapes = 40) {
  let since = new Date().toISOString();
  let total = 0;
  let dropped = 0;
  const shapes = new Map<string, UnrecognizedShape>();

  function record(line: string, source: UnrecognizedSource): void {
    const text = line.trim();
    if (!text) return;
    total += 1;
    const key = shapeOf(text);
    const now = new Date().toISOString();
    const existing = shapes.get(key);
    if (existing) {
      existing.count += 1;
      existing.lastAt = now;
      existing.sample = text.slice(0, SAMPLE_MAX);
      return;
    }
    if (shapes.size >= maxShapes) {
      // abre espaço descartando a forma com menos ocorrências
      let weakest: string | null = null;
      let weakestCount = Infinity;
      for (const [k, v] of shapes) {
        if (v.count < weakestCount) {
          weakest = k;
          weakestCount = v.count;
        }
      }
      if (weakest !== null) shapes.delete(weakest);
      dropped += 1;
    }
    shapes.set(key, { sample: text.slice(0, SAMPLE_MAX), count: 1, firstAt: now, lastAt: now, source });
  }

  function snapshot(): UnrecognizedSnapshot {
    return {
      total,
      since,
      droppedShapes: dropped,
      shapes: [...shapes.values()].sort((a, b) => b.count - a.count || b.lastAt.localeCompare(a.lastAt)),
    };
  }

  function clear(): void {
    shapes.clear();
    total = 0;
    dropped = 0;
    since = new Date().toISOString();
  }

  return { record, snapshot, clear };
}

export type UnrecognizedTracker = ReturnType<typeof createUnrecognizedTracker>;
