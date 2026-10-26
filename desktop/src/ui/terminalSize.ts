// The size of one in-app terminal's PTY (docs/desktop-app.md §4.4). xterm starts at 80x24 and
// is fitted to its box only once it opens, after its font has loaded (./fonts.ts), while the core
// may answer `terminal_open` or `terminal_attach` before that. The PTY is sized only once both have
// happened, so the shell never starts at the unfitted 80x24 and the first output is not laid out
// at 80 columns and reflowed; after that every change of xterm's size goes to the core.

export class TerminalSize {
  private id: string | null = null;
  private fittedOnce = false;

  constructor(
    private readonly send: (terminalId: string, cols: number, rows: number) => void,
    private readonly size: () => { cols: number; rows: number },
  ) {}

  /** The core opened (or reattached) the terminal. */
  opened(terminalId: string): void {
    this.id = terminalId;
    this.push();
  }

  /** xterm is open and has been fitted to its box (a fit that changes the size also reports
   *  `resized` first, which waits for this). */
  fitted(): void {
    this.fittedOnce = true;
    this.push();
  }

  /** xterm's size changed. */
  resized(): void {
    if (this.fittedOnce) this.push();
  }

  /** The view went away: nothing more is sent. */
  dispose(): void {
    this.id = null;
  }

  private push(): void {
    if (this.id === null || !this.fittedOnce) return;
    const { cols, rows } = this.size();
    this.send(this.id, cols, rows);
  }
}
