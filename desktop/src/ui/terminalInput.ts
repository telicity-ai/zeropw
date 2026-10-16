// Keyboard input for one in-app terminal (docs/desktop-app.md §4.4). Each input event (a key, a
// typed suggestion or one paste) goes to the core whole, as one `terminal_write`, in the order it
// was typed; the core queues a write all or nothing. An event over the core's per-call limit is
// refused here whole (`tooLarge`) and never cut into several writes: a later piece could be
// refused after earlier ones were taken, delivering only the head of a paste (and a bracketed
// paste's start marker without its end). The core refuses input with `terminal_busy` while the
// program leaves 256 KiB unread. The refused write is dropped, and so is everything typed behind
// it before the refusal was known: sent later, it would land after newer input and splice lines
// together. The terminal then says that input was dropped (`busy`), and the next input typed
// after that is tried again.

import { toIpcError } from '../ipc/client';

/** The core refuses one `terminal_write` over this many UTF-8 bytes (`terminal_write_too_large`). */
export const MAX_WRITE_BYTES = 64 * 1024;

/** UTF-8 length of `text`, as the core counts it against MAX_WRITE_BYTES. */
export function utf8Bytes(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length && (text.charCodeAt(i + 1) & 0xfc00) === 0xdc00) { n += 4; i++; }
    else n += 3;
  }
  return n;
}

export interface TerminalInputEvents {
  /** One input (a paste) was over MAX_WRITE_BYTES: none of it was sent. */
  tooLarge(): void;
  /** Input was refused because the program is not reading it; it was dropped. */
  busy(): void;
  /** Input went through again after a refusal. */
  accepted(): void;
  /** The terminal no longer exists. */
  gone(): void;
}

export class TerminalInput {
  private queue: string[] = [];
  private sending = false;
  private refused = false;
  private stopped = false;
  private running: Promise<void> = Promise.resolve();

  constructor(private readonly send: (data: string) => Promise<unknown>, private readonly on: TerminalInputEvents) {}

  write(data: string): void {
    if (this.stopped || !data) return;
    if (utf8Bytes(data) > MAX_WRITE_BYTES) { this.on.tooLarge(); return; }
    this.queue.push(data);
    if (!this.sending) this.running = this.pump();
  }

  /** The view went away: nothing more is sent. */
  dispose(): void {
    this.stopped = true;
    this.queue = [];
  }

  /** Settles once everything written so far was sent or dropped. */
  idle(): Promise<void> {
    return this.running;
  }

  private async pump(): Promise<void> {
    this.sending = true;
    while (this.queue.length > 0 && !this.stopped) {
      const chunk = this.queue.shift() as string;
      try {
        await this.send(chunk);
        if (this.refused) { this.refused = false; this.on.accepted(); }
      } catch (e) {
        const reason = toIpcError(e).reason;
        if (reason === 'terminal_busy') {
          this.queue = [];
          this.refused = true;
          this.on.busy();
        } else if (reason === 'terminal_not_found') {
          this.dispose();
          this.on.gone();
        }
      }
    }
    // no await between the last check of the queue and this: a write that arrives later starts a new pump
    this.sending = false;
  }
}
