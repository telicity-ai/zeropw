// Creating the vault during onboarding (`vault_init`). The core runs `init` and then starts the
// relay; when the relay does not start, `vault_init` fails although the vault now exists
// (desktop/core/src/commands.rs `vault_init`). So after any failure the UI asks the core whether
// the vault exists (`app_status.initialized`) instead of trusting the error: an existing vault is
// never created again, and the recovery code and admin passphrase the user saw are the ones it
// uses. Only when the vault does not exist is the error read, to send the user back to the step
// that has to change.

import { call, toIpcError } from '../ipc/client';

export type RecoveryChoice = { ref: string } | { typed: string };

/** recovery_expired: the generated code is gone from the core (it keeps it 10 minutes), a new one
 *  must be written down; recovery_weak: a chosen code is too close to the admin passphrase;
 *  unknown: the core could not say whether the vault exists, so nothing may change before a retry;
 *  failed: the vault was not created, anything else. */
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

/** One attempt. Resolves when the vault exists (made now, or by an earlier attempt whose relay
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
    if (exists === true) return;   // `init` ran; only the relay did not start (the relay line retries it)
    if (exists === null) { attempts.unsure = true; throw new InitError('unknown'); }
    throw new InitError(initFailureOf(err.reason, err.detail));
  }
}
