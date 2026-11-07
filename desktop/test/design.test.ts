import { describe, expect, it } from 'vitest';

// The design system (DESIGN.md): colours come from semantic tokens defined once for light and
// once for dark in styles/tokens.css. Components and screens use var(--token) only, every token
// they use exists, and the dark block redefines every palette value the light block sets.

const sources = import.meta.glob('../src/**/*.{css,ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const files = Object.keys(sources);
const read = (f: string): string => sources[f] ?? '';
const relative = (_root: string, f: string): string => f.replace('../src/', '');
const root = '';
const css = files.filter((f) => f.endsWith('.css'));
const tokens = read('../src/styles/tokens.css');
const defined = new Set([...tokens.matchAll(/(--[a-z0-9-]+)\s*:/g)].map((m) => m[1]!));

describe('design tokens', () => {
  it('keeps raw colours in tokens.css only', () => {
    const offenders: string[] = [];
    for (const f of css) {
      if (f.endsWith('tokens.css')) continue;
      const text = read(f).replace(/\/\*[\s\S]*?\*\//g, '');
      for (const m of text.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) offenders.push(`${relative(root, f)}: ${m[0]}`);
    }
    for (const f of files.filter((x) => /\.tsx?$/.test(x))) {
      const text = read(f);
      // inline styles with literal colours (the terminal's own palette is the one exception)
      if (f.endsWith('Terminal.tsx')) continue;
      for (const m of text.matchAll(/(color|background|border)\s*:\s*['"]#[0-9a-fA-F]{3,8}/g)) offenders.push(`${relative(root, f)}: ${m[0]}`);
    }
    expect(offenders).toEqual([]);
  });

  it('uses only tokens that exist', () => {
    const missing: string[] = [];
    for (const f of [...css, ...files.filter((x) => x.endsWith('.tsx'))]) {
      const text = read(f);
      const local = new Set([...text.matchAll(/(--[a-z0-9-]+)\s*:/g)].map((m) => m[1]!));
      for (const m of text.matchAll(/var\((--[a-z0-9-]+)/g)) {
        if (!defined.has(m[1]!) && !local.has(m[1]!)) missing.push(`${relative(root, f)}: ${m[1]}`);
      }
    }
    expect([...new Set(missing)]).toEqual([]);
  });

  it('gives the dark scheme its own value for every palette colour', () => {
    const light = tokens.slice(0, tokens.indexOf('@media (prefers-color-scheme: dark)'));
    const dark = tokens.slice(tokens.indexOf('@media (prefers-color-scheme: dark)'));
    const palette = [...light.matchAll(/(--(?:paper|ink|line|pine|amber|red|blue|green|kind)-[a-z0-9-]+)\s*:/g)].map((m) => m[1]!);
    expect(palette.length).toBeGreaterThan(20);
    for (const p of palette) expect(dark, p).toContain(`${p}:`);
  });
});
