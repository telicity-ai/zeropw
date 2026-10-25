import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { CopyKey } from '../copy';
import { toIpcError } from '../ipc/client';
import type { Control, ServeStatus } from '../ipc/contract';
import type { PageId } from './pages';

/** What a page should open when another page sends the user there (home quick actions, the
 *  home's recent alerts). */
export type Intent = 'add-key' | 'add-connection' | 'add-agent' | 'add-grant' | 'invite' | 'join' | 'ack-restore' | 'import' | 'alerts';

/** Why the relay did not start: a copy key and the core's reason code it may show. */
export interface RelayProblem { key: CopyKey; reason: string }

export interface RelayApi {
  /** A start or restart from this window is running. */
  busy: boolean;
  /** The last failure to start, until the relay runs again or another start begins. */
  problem: RelayProblem | null;
  /** `serve_start`; on failure the reason is shown (toast and next to the relay status). */
  start(): Promise<boolean>;
  /** Run a restart from elsewhere (settings, team): the relay counts as busy and the last
   *  failure is cleared while it runs. */
  run<T>(task: () => Promise<T>): Promise<T>;
  /** Show why a restart elsewhere (settings, team) left the relay off. */
  report(e: unknown): void;
  /** The saved other-device address, or null. The relay runs team sync in the same process, so
   *  an address it cannot open (a VPN that is down, a port in use) keeps the whole relay off. */
  teamListen: string | null;
  /** Offer to turn other-device access off: only after the team address kept the relay off
   *  (lib/reasons.ts `offersListenOff`). */
  offerListenOff: boolean;
  /** Ask before turning other-device access off (team changes stop arriving), then turn it off
   *  and start the relay without it. */
  confirmListenOff(): void;
}

export interface DashApi {
  go(page: PageId, intent?: Intent): void;
  /** Bumps when the shell re-reads its status (window focus, `bump`): pages reload their lists. */
  tick: number;
  /** Bumps when new usage records arrive: only pages that show records or usage reload. */
  activity: number;
  /** Something changed: re-read the shell status and let other pages reload. */
  bump(): void;
  control: Control;
  serve: ServeStatus;
  setControl(c: Control): void;
  setServe(s: ServeStatus): void;
  relay: RelayApi;
}

export const DashContext = createContext<DashApi | null>(null);

export function useDash(): DashApi {
  const api = useContext(DashContext);
  if (!api) throw new Error('DashContext missing');
  return api;
}

/** Sheets render outside the page (so the page can be made inert under them) into this host. */
export interface SheetHost { el: HTMLElement | null; hold(delta: 1 | -1): void }
export const SheetHostContext = createContext<SheetHost | null>(null);

/** Error text for an action that asked for the admin passphrase again. */
export function passErrorKey(e: unknown): CopyKey {
  const err = toIpcError(e);
  if (err.error === 'AuthFailed') return err.reason === 'passphrase_missing' ? 'pass.err.empty' : 'error.auth';
  return 'error.generic';
}

/** Map a stable reason code to copy; anything unknown is the generic error. */
export function reasonKey(e: unknown, map: Record<string, CopyKey>): CopyKey {
  const err = toIpcError(e);
  return map[err.reason] ?? (err.error === 'AuthFailed' ? 'error.auth' : 'error.generic');
}

/** Load data for a page; keeps the last good value while reloading. `deps` re-run the loader. */
export function useLoad<T>(load: () => Promise<T>, deps: readonly unknown[]): { data: T | null; failed: boolean; reload(): void } {
  const [data, setData] = useState<T | null>(null);
  const [failed, setFailed] = useState(false);
  const [n, setN] = useState(0);
  const seq = useRef(0);
  const fn = useRef(load);
  fn.current = load;
  useEffect(() => {
    const k = ++seq.current;
    fn.current().then(
      (v) => { if (k === seq.current) { setData(v); setFailed(false); } },
      () => { if (k === seq.current) setFailed(true); },
    );
  }, [n, ...deps]); // eslint-style exhaustive deps are the caller's list plus the manual reload counter
  const reload = useCallback(() => setN((x) => x + 1), []);
  return { data, failed, reload };
}

/** One open sheet at a time per page. Each kind keeps its last data so it can animate out, and
 *  gets a fresh key every time it opens so its form starts empty. */
export function useSheets<S extends { kind: string }>() {
  type K = S['kind'];
  const [cur, setCur] = useState<S | null>(null);
  const [last, setLast] = useState<Partial<Record<K, S>>>({});
  const [gen, setGen] = useState<Partial<Record<K, number>>>({});
  const open = useCallback((s: S) => {
    const k = s.kind as K;
    setGen((g) => ({ ...g, [k]: (g[k] ?? 0) + 1 }));
    setLast((l) => ({ ...l, [k]: s }));
    setCur(s);
  }, []);
  const close = useCallback(() => setCur(null), []);
  const key = (kind: K) => `${kind}-${gen[kind] ?? 0}`;
  const isOpen = (kind: K) => cur?.kind === kind;
  const data = <T extends K>(kind: T) => last[kind] as Extract<S, { kind: T }> | undefined;
  return { cur, open, close, key, isOpen, data };
}

/** Run `clear` whenever `open` turns false, so a sheet that stays mounted after it closes does not
 *  keep a typed passphrase, secret value or link in its state (the sheet's DOM goes away after
 *  the closing animation, its component state does not). */
export function useClearOnClose(open: boolean, clear: () => void): void {
  const fn = useRef(clear);
  fn.current = clear;
  useEffect(() => { if (!open) fn.current(); }, [open]);
}

/** Run an intent from another page once, when the page mounts or the intent changes. */
export function useIntent(intent: Intent | undefined, onIntent: () => void, handle: (i: Intent) => boolean): void {
  const fn = useRef(handle);
  fn.current = handle;
  useEffect(() => {
    if (!intent) return;
    if (fn.current(intent)) onIntent();
  }, [intent, onIntent]);
}

/** A clock for countdowns; ticks only while `active`. */
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
