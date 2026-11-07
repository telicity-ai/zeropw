// The open vault's shared state: where the window is, the local service and stop state, the
// vault listing every screen reads, and the hand-offs from the core's events (a dropped .env
// file, an opened invite link). Screens read it with useShell().

import { createContext, useContext } from 'react';
import type { CopyKey } from '../copy';
import type { Control, EnvFileRef, InvitePreview, Project, SecretView, ServeStatus, TeamEnvironment } from '../ipc/contract';
import type { Load } from '../ui/hooks';

export type Page = 'vault' | 'devices' | 'services' | 'developer' | 'activity' | 'settings';

/** One-time requests a page acts on when it opens, then clears. */
export type Intent =
  | 'add' | 'import'                           // vault
  | 'enroll' | 'pair-add' | 'pair-join'        // devices
  | 'add-connection'                           // services
  | 'add-agent' | 'add-grant' | 'invite' | 'join' | 'share' // developer
  | 'alerts' | 'incidents'                     // activity
  | 'ack-restore' | 'server' | 'backup';       // settings

export interface Route {
  page: Page;
  /** Page-specific view: the vault's filter (`all`, `kind:<kind>`, `place:<project>/<env>`), a
   *  developer or settings tab. */
  view?: string;
  /** An item to select (a secret id, a device fingerprint, a connection id). */
  item?: string;
  intent?: Intent;
}

export interface Listing { projects: Project[]; team_environments?: TeamEnvironment[]; team_environments_error?: string }
export interface VaultData { secrets: SecretView[]; listing: Listing }

export interface RelayProblem { key: CopyKey; reason: string }

/** The local service (`zeropw-admin serve`): its gateway, SSH signer and team sync. */
export interface RelayApi {
  /** A start, restart or settings change is running. */
  busy: boolean;
  /** Why the last start from this window failed, until it runs again. */
  problem: RelayProblem | null;
  start(): Promise<boolean>;
  /** Run a task that restarts the service (counts as busy, clears the problem first). */
  run<T>(task: () => Promise<T>): Promise<T>;
  /** Show why a restart elsewhere left the service off. */
  report(e: unknown): void;
  /** The saved other-device access address, or null. */
  teamListen: string | null;
  /** Offer turning other-device access off (only after a failure on that address). */
  offerListenOff: boolean;
  confirmListenOff(): void;
}

export interface ShellApi {
  route: Route;
  go(page: Page, opts?: Omit<Route, 'page'>): void;
  /** The page handled its intent. */
  clearIntent(): void;
  /** Bumps when the window re-reads the global state (focus, bump()). */
  tick: number;
  /** Bumps when new usage records appear. */
  activity: number;
  /** Re-read the global state and every screen's data. */
  bump(): void;
  control: Control;
  serve: ServeStatus;
  setControl(c: Control): void;
  setServe(s: ServeStatus): void;
  relay: RelayApi;
  /** Every secret (values never) and the projects, re-read on tick and after vault changes. */
  vault: Load<VaultData>;
  /** A .env file dropped on the window, held for the vault's import. */
  envFile: EnvFileRef | null;
  takeEnvFile(): void;
  /** An invite link (zeropw://join#…) opened while the vault is open. */
  invite: { ref: string; preview: InvitePreview } | null;
  takeInvite(ref: string): void;
  lock(): void;
  /** Width class: `rail` hides sidebar labels, `single` shows list or detail, not both. */
  narrow: { rail: boolean; single: boolean };
}

export const ShellContext = createContext<ShellApi | null>(null);

export function useShell(): ShellApi {
  const api = useContext(ShellContext);
  if (!api) throw new Error('ShellContext missing');
  return api;
}

/** The open vault locks after this many minutes without input (fixed). */
export const IDLE_LOCK_MIN = 15;

export const NO_CONTROL: Control = { stopped: false, restore_pending: false, incident_open: false };
