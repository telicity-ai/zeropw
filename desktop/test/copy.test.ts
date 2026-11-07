import { describe, expect, it } from 'vitest';
import { COPY, COPY_AREAS, hasCopy, t, tLines } from '../src/copy';

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
