import { describe, expect, it } from 'vitest';
import { TerminalSize } from '../src/ui/terminalSize';

// pr69-frontend-records-a11y-4: the terminal opens only once its font has loaded (up to 1.5 s),
// and a core that answered first was told xterm's unfitted 80x24; the PTY was resized again once
// xterm was fitted, so the first output was laid out at 80 columns and reflowed.

/** xterm's size as the terminal sees it: 80x24 until it is fitted to its box. */
function setup() {
  const term = { cols: 80, rows: 24 };
  const sent: Array<[string, number, number]> = [];
  const size = new TerminalSize((id, cols, rows) => { sent.push([id, cols, rows]); }, () => ({ ...term }));
  /** xterm opens and fits: a changed size is reported as a resize first, then the fit is done. */
  const fit = (cols: number, rows: number) => {
    const changed = cols !== term.cols || rows !== term.rows;
    term.cols = cols; term.rows = rows;
    if (changed) size.resized();
    size.fitted();
  };
  return { term, sent, size, fit };
}

describe('terminal size', () => {
  it('sizes the PTY only once the terminal is fitted when the core answers first', () => {
    const { sent, size, fit } = setup();
    size.opened('term-1');
    expect(sent).toEqual([]);                 // not the unfitted 80x24
    fit(132, 40);
    expect(sent).toEqual([['term-1', 132, 40]]);
  });

  it('sizes the PTY when the core answers after the terminal was fitted', () => {
    const { sent, size, fit } = setup();
    fit(132, 40);
    expect(sent).toEqual([]);                 // no terminal in the core yet
    size.opened('term-1');
    expect(sent).toEqual([['term-1', 132, 40]]);
  });

  it('sends every later change and nothing once the view is gone', () => {
    const { term, sent, size, fit } = setup();
    size.opened('term-1');
    fit(80, 24);                              // a box that fits exactly 80x24 reports no resize
    expect(sent).toEqual([['term-1', 80, 24]]);
    term.cols = 100; size.resized();
    expect(sent).toEqual([['term-1', 80, 24], ['term-1', 100, 24]]);
    size.dispose();
    term.cols = 120; size.resized();
    expect(sent).toHaveLength(2);
  });
});
