import { afterEach, describe, expect, it, vi } from 'vitest';
import { call, IpcError, outputChannel, toIpcError, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { MAX_WRITE_BYTES, splitUtf8, TerminalInput } from '../src/ui/terminalInput';

// Terminal input against a program that is not reading: the core refuses input with
// `terminal_busy` once 256 KiB wait unread. Nothing may be dropped without the terminal saying
// so, and nothing typed behind a refused chunk may arrive later, spliced after newer input.

const bytes = (s: string) => new TextEncoder().encode(s).length;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

let backend: MockBackend | null = null;
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); vi.useRealTimers(); });

function recorder() {
  const events: string[] = [];
  return { events, on: { busy: () => events.push('busy'), accepted: () => events.push('accepted'), gone: () => events.push('gone') } };
}

describe('cutting input to the core limit', () => {
  it('keeps every piece within 64 KiB of UTF-8 and never cuts a character', () => {
    const text = 'a'.repeat(70_000) + '가'.repeat(30_000) + '\u{1F512}'.repeat(20_000) + '\r';
    const parts = splitUtf8(text);
    expect(parts.join('')).toBe(text);
    expect(parts.length).toBeGreaterThan(3);
    for (const p of parts) {
      expect(bytes(p)).toBeLessThanOrEqual(MAX_WRITE_BYTES);
      expect(p).not.toMatch(LONE_SURROGATE);                     // no character cut in half
    }
    expect(splitUtf8('ls\r')).toEqual(['ls\r']);
    expect(splitUtf8('')).toEqual([]);
  });
});

describe('input the program does not read', () => {
  it('sends in order, one call at a time, and drops what was typed behind a refused chunk', async () => {
    const sent: string[] = [];
    const answers: Array<{ resolve(): void; reject(e: unknown): void }> = [];
    const { events, on } = recorder();
    const input = new TerminalInput((d) => new Promise<void>((resolve, reject) => { sent.push(d); answers.push({ resolve, reject }); }), on);
    input.write('A'); input.write('B'); input.write('C');
    await Promise.resolve();
    expect(sent).toEqual(['A']);                                 // B and C wait for A's answer
    answers[0]?.resolve();
    await vi.waitFor(() => expect(sent).toEqual(['A', 'B']));
    answers[1]?.reject(new IpcError({ error: 'Unavailable', reason: 'terminal_busy' }));
    await input.idle();
    expect(events).toEqual(['busy']);
    expect(sent).toEqual(['A', 'B']);                            // C was typed before the refusal was known: dropped
    input.write('D');
    await vi.waitFor(() => expect(sent).toEqual(['A', 'B', 'D']));
    answers[2]?.resolve();
    await input.idle();
    expect(events).toEqual(['busy', 'accepted']);
  });

  it('stops for good when the terminal is gone', async () => {
    const sent: string[] = [];
    const { events, on } = recorder();
    const input = new TerminalInput(async (d) => { sent.push(d); throw new IpcError({ error: 'NotFound', reason: 'terminal_not_found' }); }, on);
    input.write('x'); input.write('y');
    await input.idle();
    input.write('z');
    await input.idle();
    expect(sent).toEqual(['x']);
    expect(events).toEqual(['gone']);
  });

  it('tells the user when the mock core refuses input from a shell that is not reading, and never delivers it', async () => {
    vi.useFakeTimers({ now: Date.UTC(2026, 9, 15, 9, 0, 0), toFake: ['Date'] });
    backend = createMockBackend({ latency: 0, initialized: true });
    useMockBackend(backend);
    const agent = await call('principal_create', { id: 'agent-busy', runtime: 'default' });
    let out = '';
    const term = await call('terminal_open', { token_ref: agent.token_ref, on_data: outputChannel((d) => { out += d; }) });
    const { events, on } = recorder();
    const input = new TerminalInput((data) => call('terminal_write', { terminal_id: term.terminal_id, data }), on);

    input.write('sleep 30\r');                                   // the program stops reading
    input.write('x'.repeat(4 * MAX_WRITE_BYTES));                // fills what the core holds unread
    await input.idle();
    expect(events).toEqual([]);
    input.write('LOST-ONE\r');
    await input.idle();
    expect(events).toEqual(['busy']);
    input.write('LOST-TWO\r');                                   // still not reading: refused and said again
    await input.idle();
    expect(events).toEqual(['busy', 'busy']);
    // one chunk over the limit is refused by the core as a whole
    const big = await call('terminal_write', { terminal_id: term.terminal_id, data: 'y'.repeat(MAX_WRITE_BYTES + 1) }).then(() => '', (e) => toIpcError(e).reason);
    expect(big).toBe('terminal_write_too_large');

    vi.setSystemTime(Date.now() + 31_000);                       // the program reads again
    input.write('\x03');
    input.write('kept\r');
    await input.idle();
    expect(events).toEqual(['busy', 'busy', 'accepted']);
    expect(out).toContain('command not found: kept');
    expect(out).not.toContain('LOST');
  });
});
