// Creating the vault (`vault_init`). The core runs `init` and then starts the local service;
// when the service does not start, `vault_init` fails although the vault now exists
// (desktop/core/src/commands.rs `vault_init`). So after any failure the UI asks the core whether
// the vault exists (`app_status.initialized`) instead of trusting the error: an existing vault is
// never created again, and the recovery code and passphrase the person saw are the ones it uses.
// Only when the vault does not exist is the error read, to send the person back to the step that
// has to change.

import { call, toIpcError } from '../../ipc/client';
import { PERSONAL_ENV, PERSONAL_PROJECT } from '../../lib/places';

export type RecoveryChoice = { ref: string } | { typed: string };

/** recovery_expired: the generated code is gone from the core (it keeps it 10 minutes);
 *  recovery_weak: a chosen code is too close to the passphrase; unknown: the core could not say
 *  whether the vault exists, so nothing may change before a retry; failed: anything else. */
export type InitFailure = 'recovery_expired' | 'recovery_weak' | 'unknown' | 'failed';

export class InitError extends Error {
  readonly kind: InitFailure;
  constructor(kind: InitFailure) {
    super(kind);
    this.name = 'InitError';
    this.kind = kind;
  }
}

/** true or false from `app_status`, or null when the core cannot answer. */
export async function vaultExists(): Promise<boolean | null> {
  try {
    return (await call('app_status')).initialized === true;
  } catch {
    return null;
  }
}

/** What a `vault_init` failure means when the vault does not exist. */
export function initFailureOf(reason: string, detail?: string): InitFailure {
  if (reason === 'onetime_ref_unknown' || reason === 'onetime_ref_invalid') return 'recovery_expired';
  if (reason === 'passphrases_identical') return 'recovery_weak';
  if ((reason === 'passphrase_weak' || reason === 'passphrase_too_short') && detail === 'recovery') return 'recovery_weak';
  return 'failed';
}

/** Between attempts: whether an earlier attempt may have created the vault without saying so. */
export interface InitAttempts { unsure: boolean }

/** One attempt. Resolves when the vault exists (made now, or by an earlier attempt whose service
 *  failed); throws InitError otherwise. */
export async function createVault(secrets: { admin: string; recovery: RecoveryChoice | null }, attempts: InitAttempts): Promise<void> {
  if (attempts.unsure) {
    const exists = await vaultExists();
    if (exists === true) { attempts.unsure = false; return; }
    if (exists === null) throw new InitError('unknown');
    attempts.unsure = false;
  }
  if (!secrets.recovery) throw new InitError('recovery_expired');
  if (!secrets.admin) throw new InitError('failed');
  try {
    await call('vault_init', { admin_passphrase: secrets.admin, recovery: secrets.recovery });
  } catch (e) {
    const err = toIpcError(e);
    const exists = await vaultExists();
    if (exists === true) return;   // `init` ran; only the service did not start (its line retries it)
    if (exists === null) { attempts.unsure = true; throw new InitError('unknown'); }
    throw new InitError(initFailureOf(err.reason, err.detail));
  }
}

/** The personal place every vault starts with (project `personal`, environment `main`). A
 *  place that already exists (a retry after an unclear answer) counts as made. */
export async function ensurePersonalPlace(): Promise<void> {
  try {
    await call('project_create', { name: PERSONAL_PROJECT, environments: [PERSONAL_ENV] });
  } catch (e) {
    if (toIpcError(e).reason !== 'project_exists') throw e;
  }
}

/** The local service runs (vault_init starts it; this starts it when that start failed). */
export async function ensureService(): Promise<string | null> {
  let s = await call('serve_status');
  if (!s.running) s = await call('serve_start');
  if (!s.running) throw { error: 'Unavailable', reason: 'serve_not_running' };
  return s.url;
}
