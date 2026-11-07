import { describe, expect, it } from 'vitest';
import { COPY, COPY_AREAS, COPY_AREAS_EN, COPY_EN, hasCopy, resolveLocale, setLocale, t, tLines, type CopyKey } from '../src/copy';

// Every visible string lives in one area table; a key defined twice would silently take the
// later area's text, so keys are unique across areas.

describe('copy tables', () => {
  it('defines every key in exactly one area', () => {
    const seen = new Map<string, string>();
    const dupes: string[] = [];
    for (const [area, table] of Object.entries(COPY_AREAS)) {
      for (const key of Object.keys(table)) {
        const before = seen.get(key);
        if (before) dupes.push(`${key} (${before}, ${area})`);
        seen.set(key, area);
      }
    }
    expect(dupes).toEqual([]);
    expect(seen.size).toBe(Object.keys(COPY).length);
  });

  it('has no empty strings, no jargon the owner ruled out and no claim that the server operates', () => {
    for (const [k, v] of Object.entries(COPY)) {
      expect(v.trim(), k).not.toBe('');
      expect(v, k).not.toContain('패스프레이즈');
      expect(v, k).not.toContain('보관함');
      expect(v, k).not.toMatch(/운영\s*중/);
      // DESIGN.md §7: no dashes, curly quotes or emoji in screen copy
      expect(v, k).not.toMatch(/[\u2013\u2014\u2018\u2019\u201c\u201d]|\p{Extended_Pictographic}/u);
    }
  });

  it('fills placeholders and joins lines', () => {
    expect(t('onetime.copied', { s: 60 })).toContain('60');
    expect(t('onetime.copied')).toContain('{s}');
    expect(tLines([{ key: 'act.retry' }, { key: 'act.cancel' }])).toBe(`${COPY['act.retry']}. ${COPY['act.cancel']}`);
    expect(hasCopy('act.retry')).toBe(true);
    expect(hasCopy('constructor')).toBe(false);
  });
});

describe('the English table', () => {
  const keys = Object.keys(COPY) as CopyKey[];
  const holes = (v: string) => [...v.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');

  it('has every key, area by area, and nothing else', () => {
    for (const [area, table] of Object.entries(COPY_AREAS)) {
      expect(Object.keys((COPY_AREAS_EN as Record<string, object>)[area]!).sort(), area).toEqual(Object.keys(table).sort());
    }
    expect(Object.keys(COPY_EN).sort()).toEqual(keys.slice().sort());
  });

  it('is translated: no Korean left except the native names of languages', () => {
    const left = keys.filter((k) => !k.endsWith('.native') && /[\u3131-\uD79D]/.test(COPY_EN[k]));
    expect(left).toEqual([]);
  });

  it('keeps the placeholders of the Korean text', () => {
    const wrong = keys.filter((k) => holes(COPY[k]) !== holes(COPY_EN[k]));
    expect(wrong).toEqual([]);
  });

  it('follows the same style rules', () => {
    for (const k of keys) {
      const v = COPY_EN[k];
      expect(v.trim(), k).not.toBe('');
      expect(v, k).not.toMatch(/[\u2013\u2014\u2018\u2019\u201c\u201d]|\p{Extended_Pictographic}/u);
      expect(v, k).not.toMatch(/\bpassphrase\b/i);
      expect(v, k).not.toMatch(/\b(is|are) (now )?(operational|operating|live)\b/i);
    }
  });

  it('switches with the locale and follows the system when unset', () => {
    expect(resolveLocale(null, ['ko-KR', 'en-US'])).toBe('ko');
    expect(resolveLocale(null, ['en-GB'])).toBe('en');
    expect(resolveLocale(null, ['fr-FR'])).toBe('en');
    expect(resolveLocale('ko', ['en-US'])).toBe('ko');
    try {
      setLocale('en');
      expect(t('nav.all')).toBe(COPY_EN['nav.all']);
      setLocale('ko');
      expect(t('nav.all')).toBe(COPY['nav.all']);
    } finally { setLocale('ko'); }
  });
});
