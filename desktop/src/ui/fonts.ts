// Waiting for a bundled font before something measures it once. The webview loads the app's
// fonts lazily (font-display: swap): a window opened again starts a new document, and the first
// thing drawn in JetBrains Mono can be laid out with a fallback font until the file has loaded.

/** The part of `document.fonts` used here. */
export interface FontLoader {
  check(font: string): boolean;
  load(font: string): Promise<unknown>;
}

/** Resolves once `font` (a CSS font shorthand such as `12px "JetBrains Mono"`) can be drawn, or
 *  after `capMs` when it does not load: the caller then measures whatever font there is. Never
 *  rejects, and resolves at once without a font loader (outside a browser). */
export function fontReady(fonts: FontLoader | undefined, font: string, capMs: number): Promise<void> {
  if (!fonts) return Promise.resolve();
  try {
    if (fonts.check(font)) return Promise.resolve();
  } catch {
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    const cap = setTimeout(resolve, capMs);
    const done = () => { clearTimeout(cap); resolve(); };
    try { fonts.load(font).then(done, done); } catch { done(); }
  });
}
