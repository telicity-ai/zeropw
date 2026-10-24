// Typed IPC client. Inside Tauri every call goes to the core with `invoke`; in a normal browser
// (`npm run dev`) the same calls go to the in-memory mock backend so the UI can be reviewed
// without the core. Arguments are passed as the top-level invoke payload with the snake_case keys
// of contract.ts (the Rust commands use `rename_all = "snake_case"`). Errors always arrive as
// AppError {error, reason, detail?} and never echo the inputs.

import { Channel, invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { AppError, CommandName, Commands, Events } from './contract';
import { createMockBackend, type MockBackend, type MockChannel, type MockSeed } from './mock';

export type CommandInput<K extends CommandName> = Commands[K][0];
export type CommandOutput<K extends CommandName> = Commands[K][1];
export type CallArgs<K extends CommandName> = CommandInput<K> extends void ? [] : [CommandInput<K>];

export class IpcError extends Error implements AppError {
  readonly error: string;
  readonly reason: string;
  readonly detail?: string;

  constructor(e: AppError) {
    super(`${e.error}: ${e.reason}`);
    this.name = 'IpcError';
    this.error = e.error;
    this.reason = e.reason;
    if (e.detail !== undefined) this.detail = e.detail;
  }
}

function isAppErrorShape(v: unknown): v is AppError {
  if (!v || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  return typeof o.error === 'string' && typeof o.reason === 'string' && (o.detail === undefined || typeof o.detail === 'string');
}

/** Normalise anything thrown by a call into an IpcError. Unknown shapes never leak their text. */
export function toIpcError(e: unknown): IpcError {
  if (e instanceof IpcError) return e;
  if (isAppErrorShape(e)) return new IpcError(e);
  return new IpcError({ error: 'IpcError', reason: 'ipc_failed' });
}

let backend: MockBackend | null = null;

/** True when the page runs inside the Tauri webview. */
export function inDesktop(): boolean {
  try {
    return isTauri();
  } catch {
    return false;
  }
}

function seedFromLocation(): MockSeed {
  if (typeof location === 'undefined') return {};
  const q = new URLSearchParams(location.search);
  const ready = q.get('state') === 'ready';
  return { initialized: ready, latency: 1, activity: ready || q.has('activity'), sshWithoutCli: q.has('ssh-without-cli') };
}

/** The mock backend in use outside Tauri (created on first use). */
export function mockBackend(): MockBackend {
  if (!backend) backend = createMockBackend(seedFromLocation());
  return backend;
}

/** Replace the mock backend (tests). */
export function useMockBackend(b: MockBackend | null): void {
  backend = b;
}

/** Commands whose `on_data` argument must reach the core as a Tauri `Channel<string>`. */
const CHANNEL_COMMANDS: ReadonlySet<CommandName> = new Set<CommandName>(['terminal_open', 'terminal_attach']);

/** In the app, `on_data` must be a real Channel (the core rejects anything else). A plain
 *  `{onmessage}` sink, as the mock uses, is wrapped in one that forwards to it. */
function withChannel(name: CommandName, input: Record<string, unknown>): Record<string, unknown> {
  if (!CHANNEL_COMMANDS.has(name)) return input;
  const sink = input.on_data;
  if (sink instanceof Channel) return input;
  const ch = new Channel<string>();
  const forward = sink && typeof (sink as MockChannel).onmessage === 'function' ? (sink as MockChannel) : null;
  ch.onmessage = (data) => forward?.onmessage(data);
  return { ...input, on_data: ch };
}

export async function call<K extends CommandName>(name: K, ...args: CallArgs<K>): Promise<CommandOutput<K>> {
  const input = (args[0] ?? undefined) as CommandInput<K>;
  try {
    if (inDesktop()) {
      const payload = withChannel(name, (input ?? {}) as Record<string, unknown>);
      return await invoke<CommandOutput<K>>(name, payload);
    }
    return await mockBackend().call(name, input);
  } catch (e) {
    throw toIpcError(e);
  }
}

/** A stream channel for terminal output: a Tauri Channel in the app, a plain sink in the mock. */
export function outputChannel(onMessage: (data: string) => void): unknown {
  if (inDesktop()) {
    const ch = new Channel<string>();
    ch.onmessage = onMessage;
    return ch;
  }
  const sink: MockChannel = { onmessage: onMessage };
  return sink;
}

/** `terminal_open` with its output streamed to `onData` (xterm.js `write`). */
export function terminalOpen(
  input: { token_ref: string; as_user?: string },
  onData: (data: string) => void,
): Promise<CommandOutput<'terminal_open'>> {
  return call('terminal_open', { ...input, on_data: outputChannel(onData) });
}

/** Reattach to a terminal that kept running: the buffered output is replayed into `onData`
 *  first, then live output follows. */
export function terminalAttach(terminal_id: string, onData: (data: string) => void): Promise<CommandOutput<'terminal_attach'>> {
  return call('terminal_attach', { terminal_id, on_data: outputChannel(onData) });
}

/** Subscribe to a core event. Returns an unsubscribe function. */
export async function on<E extends keyof Events>(name: E, handler: (payload: Events[E]) => void): Promise<() => void> {
  if (inDesktop()) {
    const un = await listen<Events[E]>(name, (ev) => handler(ev.payload));
    return un;
  }
  return mockBackend().on(name, handler);
}
