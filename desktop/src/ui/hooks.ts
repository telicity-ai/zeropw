// Small hooks every screen shares: loading with stale-answer protection, actions that cannot
// run twice at once, a ticking clock, visible-only polling and keyboard shortcuts.

import { useCallback, useEffect, useRef, useState, type DependencyList } from 'react';
import { toIpcError, type IpcError } from '../ipc/client';

export interface Load<T> {
  data: T | null;
  /** The last failure, cleared by the next success. */
  error: IpcError | null;
  /** A read is running (the first one, or a reload while the last good data stays shown). */
  loading: boolean;
  reload(): void;
}

/** Read with `fn` whenever `deps` change or `reload()` is called. An answer older than the
 *  latest request is dropped; the last good data stays while a reload runs or after it fails. */
export function useLoad<T>(fn: () => Promise<T>, deps: DependencyList): Load<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<IpcError | null>(null);
  const [loading, setLoading] = useState(true);
  const [n, setN] = useState(0);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    const mine = ++seq.current;
    setLoading(true);
    fnRef.current().then(
      (v) => { if (seq.current === mine) { setData(v); setError(null); setLoading(false); } },
      (e) => { if (seq.current === mine) { setError(toIpcError(e)); setLoading(false); } },
    );
  }, [...deps, n]);
  useEffect(() => () => { seq.current += 1; }, []);
  const reload = useCallback(() => setN((k) => k + 1), []);
  return { data, error, loading, reload };
}

export interface Action {
  busy: boolean;
  /** Run `task` unless one is already running (a double click is ignored). Resolves with the
   *  task's value, or `undefined` when it was ignored. Errors are rethrown to the caller. */
  run<T>(task: () => Promise<T>): Promise<T | undefined>;
}

export function useAction(): Action {
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const run = useCallback(async <T,>(task: () => Promise<T>): Promise<T | undefined> => {
    if (running.current) return undefined;
    running.current = true;
    setBusy(true);
    try {
      return await task();
    } finally {
      running.current = false;
      if (alive.current) setBusy(false);
    }
  }, []);
  return { busy, run };
}

/** The current time, re-read every `everyMs` while `active`. */
export function useNow(active: boolean, everyMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), everyMs);
    return () => clearInterval(id);
  }, [active, everyMs]);
  return now;
}

/** Call `fn` every `everyMs` while `active` and the window is visible, and once more whenever
 *  the window becomes visible again. Calls never overlap: a tick while one runs is skipped. */
export function usePoll(fn: () => Promise<unknown> | void, everyMs: number, active = true): void {
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    if (!active) return;
    let running = false;
    const tick = () => {
      if (running || (typeof document !== 'undefined' && document.hidden)) return;
      running = true;
      Promise.resolve(fnRef.current()).catch(() => undefined).finally(() => { running = false; });
    };
    const id = setInterval(tick, everyMs);
    const vis = () => { if (!document.hidden) tick(); };
    document.addEventListener('visibilitychange', vis);
    return () => { clearInterval(id); document.removeEventListener('visibilitychange', vis); };
  }, [everyMs, active]);
}

/** A keyboard shortcut on the whole window: `mod` is ⌘ on macOS (Ctrl elsewhere). Ignored while
 *  a dialog is open (it handles its own keys) unless `inDialog`, and while an IME composes. */
export function useHotkey(key: string, fn: (e: KeyboardEvent) => void, opts: { mod?: boolean; shift?: boolean; enabled?: boolean; inDialog?: boolean } = {}): void {
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const { mod = true, shift = false, enabled = true, inDialog = false } = opts;
  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.isComposing || e.keyCode === 229) return;
      const m = e.metaKey || e.ctrlKey;
      if (mod !== m || shift !== e.shiftKey || e.altKey) return;
      if (e.key.toLowerCase() !== key.toLowerCase()) return;
      if (!inDialog && document.querySelector('[data-dialog-open]')) return;
      e.preventDefault();
      fnRef.current(e);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [key, mod, shift, enabled, inDialog]);
}

/** Whether the window is at most `px` wide (follows resizes). */
export function useNarrow(px: number): boolean {
  const query = `(max-width: ${px}px)`;
  const [narrow, setNarrow] = useState(() => typeof matchMedia === 'function' && matchMedia(query).matches);
  useEffect(() => {
    if (typeof matchMedia !== 'function') return;
    const mq = matchMedia(query);
    const fn = () => setNarrow(mq.matches);
    fn();
    mq.addEventListener('change', fn);
    return () => mq.removeEventListener('change', fn);
  }, [query]);
  return narrow;
}
