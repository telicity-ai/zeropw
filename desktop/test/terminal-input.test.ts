import { afterEach, describe, expect, it, vi } from 'vitest';
import { call, IpcError, outputChannel, toIpcError, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
import { MAX_WRITE_BYTES, TerminalInput, utf8Bytes } from '../src/ui/terminalInput';
import { COPY } from '../src/copy';

// Terminal input against a program that is not reading: the core refuses input with
// `terminal_busy` once 256 KiB wait unread. Nothing may be dropped without the terminal saying
// so, nothing typed behind a refused write may arrive later, spliced after newer input, and one
// paste arrives whole or not at all.

const bytes = (s: string) => new TextEncoder().encode(s).length;

let backend: MockBackend | null = null;
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); vi.useRealTimers(); });

function recorder() {
  const events: string[] = [];
  return { events, on: { tooLarge: () => events.push('tooLarge'), busy: () => events.push('busy'), accepted: () => events.push('accepted'), gone: () => events.push('gone') } };
}

describe('one paste is one write', () => {
  it('counts UTF-8 bytes as the core does', () => {
    for (const s of ['', 'ls\r', '가나다', '\u{1F512}x', 'a'.repeat(70_000) + '가'.repeat(300) + '\u{1F512}'.repeat(200)]) expect(utf8Bytes(s), s.slice(0, 8)).toBe(bytes(s));
  });

  it('sends input of up to 64 KiB as one call and refuses a larger paste whole, without cutting it', async () => {
    const sent: string[] = [];
    const { events, on } = recorder();
    const input = new TerminalInput(async (d) => { sent.push(d); }, on);
    const exact = 'a'.repeat(MAX_WRITE_BYTES - 3) + '가';                    // exactly 64 KiB
    input.write(exact);
    await input.idle();
    expect(sent).toEqual([exact]);
    // a 300 KiB multi-line script in a bracketed paste: none of it goes, not even its start marker
    const script = '\x1b[200~' + 'echo line\r'.repeat(30_000) + '\x1b[201~';
    input.write(script);
    input.write('가'.repeat(MAX_WRITE_BYTES / 3 + 1));                         // just over the limit in multi-byte text
    await input.idle();
    expect(sent).toHaveLength(1);
    expect(events).toEqual(['tooLarge', 'tooLarge']);
    // what is typed next goes as usual
    input.write('ls\r');
    await input.idle();
    expect(sent).toEqual([exact, 'ls\r']);
    expect(COPY['term.tooLarge']).toContain('64KB');
    expect(COPY['term.tooLarge']).toContain('보내지 않았어요');
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
    for (let i = 0; i < 4; i++) input.write('x'.repeat(MAX_WRITE_BYTES));   // fills what the core holds unread
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

  it('delivers a paste that does not fit what the core still holds not at all, never only its head', async () => {
    vi.useFakeTimers({ now: Date.UTC(2026, 9, 15, 9, 0, 0), toFake: ['Date'] });
    backend = createMockBackend({ latency: 0, initialized: true });
    useMockBackend(backend);
    const agent = await call('principal_create', { id: 'agent-paste', runtime: 'default' });
    let out = '';
    const term = await call('terminal_open', { token_ref: agent.token_ref, on_data: outputChannel((d) => { out += d; }) });
    const { events, on } = recorder();
    const sent: string[] = [];
    const input = new TerminalInput((data) => { sent.push(data); return call('terminal_write', { terminal_id: term.terminal_id, data }); }, on);

    input.write('sleep 30\r');
    for (let i = 0; i < 3; i++) input.write('x'.repeat(MAX_WRITE_BYTES));
    input.write('x'.repeat(MAX_WRITE_BYTES - 100));              // 100 bytes of room left
    await input.idle();
    const paste = 'PASTE-HEAD ' + 'p'.repeat(1000) + ' PASTE-TAIL\r';   // plain text: this toy shell ignores escapes
    input.write(paste);
    await input.idle();
    expect(events).toEqual(['busy']);
    expect(sent.filter((d) => d.includes('PASTE'))).toEqual([paste]);   // tried once, whole

    vi.setSystemTime(Date.now() + 31_000);
    input.write('\x03');
    input.write('kept\r');
    await input.idle();
    expect(out).toContain('command not found: kept');
    expect(out).not.toContain('PASTE');
  });
});
