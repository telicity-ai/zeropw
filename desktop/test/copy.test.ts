import { describe, expect, it } from 'vitest';
import { COPY, hasCopy, t } from '../src/copy';

const sources = import.meta.glob('../src/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const mockup = Object.values(import.meta.glob('../mockup/onboarding.html', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)[0] ?? '';

const prefixes = [...new Set(Object.keys(COPY).map((k) => k.split('.')[0]))];
const keyLiteral = new RegExp(`['"\`]((?:${prefixes.join('|')})\\.[A-Za-z0-9_.]*)['"\`]`, 'g');
const appFiles = Object.entries(sources).filter(([path]) => !path.endsWith('/copy.ts'));

describe('copy table', () => {
  it('scans the app sources', () => {
    expect(appFiles.length).toBeGreaterThan(20);
  });

  it('has every key referenced in src', () => {
    const missing: string[] = [];
    let seen = 0;
    for (const [path, text] of appFiles) {
      for (const m of text.matchAll(keyLiteral)) {
        const key = m[1] ?? '';
        seen++;
        if (!hasCopy(key)) missing.push(`${path}: ${key}`);
      }
    }
    expect(missing).toEqual([]);
    expect(seen).toBeGreaterThan(100);
  });

  it('keeps display text out of components (no Hangul outside copy.ts)', () => {
    const offenders = appFiles.filter(([, text]) => /[\u1100-\u11FF\u3130-\u318F\uAC00-\uD7A3]/.test(text)).map(([p]) => p);
    expect(offenders).toEqual([]);
  });

  it('follows the writing rules: no sentence-final period, no dashes or emoji', () => {
    const bad = Object.entries(COPY).filter(([, v]) => /\.$/.test(v) || /[\u2013\u2014]/.test(v) || /\p{Extended_Pictographic}/u.test(v));
    expect(bad).toEqual([]);
  });

  it('keeps the approved mockup table (v0.5) except mockup-only notes', () => {
    const block = mockup.slice(mockup.indexOf('/*COPY_START*/'), mockup.indexOf('/*COPY_END*/'));
    const entries = [...block.matchAll(/^\s*'([^']+)':\s*'((?:[^'\\]|\\.)*)',?$/gm)].map((m) => [m[1] ?? '', m[2] ?? ''] as const);
    expect(entries.length).toBeGreaterThan(200);
    const dropped = new Set(['toast.dash', 'toast.file.mock', 'term.pw.mock']);
    const changed = new Set(['join.local', 'toast.paste.mock']);
    for (const [k, v] of entries) {
      if (dropped.has(k)) { expect(hasCopy(k)).toBe(false); continue; }
      expect(hasCopy(k), k).toBe(true);
      if (!changed.has(k) && hasCopy(k)) expect(COPY[k], k).toBe(v);
    }
  });

  it('fills placeholders and leaves unknown ones visible', () => {
    expect(t('rec.verify.slot', { n: 3 })).toBe('3번째');
    expect(t('term.title')).toContain('{name}');
  });
});
