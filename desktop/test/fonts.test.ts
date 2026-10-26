import { afterEach, describe, expect, it, vi } from 'vitest';
import { fontReady, type FontLoader } from '../src/ui/fonts';

// desktop E2E F17: the first terminal after the window opened again measured its cells with a
// fallback font, and the letters stood apart. The terminal now opens once its font can be drawn.

afterEach(() => { vi.useRealTimers(); });

/** A font loader whose font loads when the test says so. */
function loader(loaded = false) {
  let finish: (ok: boolean) => void = () => undefined;
  const calls: string[] = [];
  const fonts: FontLoader = {
    check: (font) => { calls.push(`check ${font}`); return loaded; },
    load: (font) => { calls.push(`load ${font}`); return new Promise((res, rej) => { finish = (ok) => { loaded = ok; if (ok) res([]); else rej(new Error('network')); }; }); },
  };
  return { fonts, calls, finish: (ok = true) => finish(ok) };
}
const settled = async (p: Promise<void>): Promise<boolean> => {
  let done = false;
  void p.then(() => { done = true; });
  for (let i = 0; i < 5; i++) await Promise.resolve();
  return done;
};

describe('waiting for the terminal font', () => {
  it('waits until the font has loaded, not just until it is asked for', async () => {
    vi.useFakeTimers();
    const l = loader();
    const ready = fontReady(l.fonts, '12px "JetBrains Mono"', 1500);
    expect(await settled(ready)).toBe(false);
    expect(l.calls).toEqual(['check 12px "JetBrains Mono"', 'load 12px "JetBrains Mono"']);
    vi.advanceTimersByTime(1000);
    expect(await settled(ready)).toBe(false);
    l.finish();
    expect(await settled(ready)).toBe(true);
  });

  it('goes on at once when the font is already there or there is no font loader', async () => {
    const l = loader(true);
    expect(await settled(fontReady(l.fonts, '12px "JetBrains Mono"', 1500))).toBe(true);
    expect(l.calls).toEqual(['check 12px "JetBrains Mono"']);
    expect(await settled(fontReady(undefined, '12px "JetBrains Mono"', 1500))).toBe(true);
  });

  it('never blocks the terminal: a font that fails or never loads lets it open after the wait', async () => {
    vi.useFakeTimers();
    const failing = loader();
    const a = fontReady(failing.fonts, '12px "JetBrains Mono"', 1500);
    failing.finish(false);
    expect(await settled(a)).toBe(true);
    const stuck = fontReady(loader().fonts, '12px "JetBrains Mono"', 1500);
    vi.advanceTimersByTime(1499);
    expect(await settled(stuck)).toBe(false);
    vi.advanceTimersByTime(1);
    expect(await settled(stuck)).toBe(true);
    const throwing: FontLoader = { check: () => { throw new SyntaxError('bad font'); }, load: async () => [] };
    expect(await settled(fontReady(throwing, 'nonsense', 1500))).toBe(true);
  });
});
