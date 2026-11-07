import { afterEach, expect, it } from 'vitest';
import { setLocale } from '../src/copy';
import { shortTime } from '../src/lib/format';

afterEach(() => setLocale('ko'));

it('shows local dates in the selected language and preserves invalid timestamps', () => {
  const stamp = new Date(2026, 10, 7, 14, 3).toISOString();
  setLocale('ko');
  expect(shortTime(stamp)).toContain('11월');
  expect(shortTime(stamp)).toContain('14:03');
  setLocale('en');
  expect(shortTime(stamp)).toContain('Nov 7');
  expect(shortTime(stamp)).toContain('14:03');
  expect(shortTime('unknown')).toBe('unknown');
});
