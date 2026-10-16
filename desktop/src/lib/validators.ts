// Input rules shared by the screens and the mock backend. The core re-checks everything; these
// only decide what the UI marks as ready and which hint it shows.

/** Project, environment, principal and runtime names (rust/src/projects.rs NAME_RE). */
export const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const isValidName = (v: string): boolean => NAME_RE.test(v);

export const DEFAULT_ENVIRONMENTS = ['dev', 'staging', 'prod'] as const;

// ---------------------------------------------------------------- passphrases

/** zxcvbn-style score 0..4 from `password_strength`. */
export const ADMIN_MIN_SCORE = 3;
export const RECOVERY_MIN_SCORE = 4;
export const MIN_PASSPHRASE_CHARS = 8;
export const METER_CELLS = 24;

export type MeterLevel = 1 | 2 | 3 | 4;
export function meterLevel(score: number): MeterLevel {
  if (score >= 4) return 4;
  if (score >= 3) return 3;
  if (score >= 2) return 2;
  return 1;
}
export const meterFraction = (score: number): number => Math.min(1, Math.max(0, score / 4));
export const meterCellsOn = (score: number): number => Math.round(meterFraction(score) * METER_CELLS);
export const charCount = (v: string): number => [...v].length;

export interface AdminRules { len: boolean; match: boolean; strong: boolean }
export function adminRules(pass: string, confirm: string, score: number): AdminRules {
  return { len: charCount(pass) >= MIN_PASSPHRASE_CHARS, match: !!pass && pass === confirm, strong: !!pass && score >= ADMIN_MIN_SCORE };
}
export const adminReady = (r: AdminRules): boolean => r.len && r.match && r.strong;

/** A chosen recovery code must not be the admin passphrase (case and outer spaces ignored). */
export const sameAsAdmin = (code: string, admin: string): boolean =>
  !!code && code.trim().toLowerCase() === admin.trim().toLowerCase();

/** The core scores a chosen recovery code with the admin passphrase as a related input (zxcvbn
 *  user inputs), which `password_strength` does not: a code that contains the admin passphrase,
 *  forwards or backwards and ignoring case, scores far lower there. The UI refuses such a code. */
export function containsAdmin(code: string, admin: string): boolean {
  const a = admin.trim().toLowerCase();
  if (charCount(a) < 4) return false;
  const c = code.toLowerCase();
  return c.includes(a) || c.includes([...a].reverse().join(''));
}

export interface RecoveryOwnRules { strong: boolean; match: boolean; same: boolean; similar: boolean }
export function recoveryOwnRules(code: string, confirm: string, admin: string, score: number): RecoveryOwnRules {
  const same = sameAsAdmin(code, admin);
  const similar = !same && !!code && containsAdmin(code, admin);
  return {
    strong: charCount(code) >= MIN_PASSPHRASE_CHARS && !same && !similar && score >= RECOVERY_MIN_SCORE,
    match: !!code && code === confirm, same, similar,
  };
}

// ---------------------------------------------------------------- recovery code

export const RECOVERY_GROUP_COUNT = 6;
export const RECOVERY_GROUP_RE = /^[A-Z2-7]{4}$/;

/** One slot from the first three groups and one from the last three, as the mockup asks. */
export function pickVerifySlots(bytes: ArrayLike<number>): [number, number] {
  return [(bytes[0] ?? 0) % 3, 3 + ((bytes[1] ?? 0) % 3)];
}

export const normalizeGroup = (v: string): string => v.trim().toUpperCase();

export function verifyRecoveryGroups(groups: readonly string[], slots: readonly [number, number], typed: readonly [string, string]): boolean {
  if (groups.length !== RECOVERY_GROUP_COUNT) return false;
  const a = groups[slots[0]], b = groups[slots[1]];
  if (a === undefined || b === undefined || slots[0] === slots[1]) return false;
  return normalizeGroup(typed[0]) === a && normalizeGroup(typed[1]) === b;
}

/** Per verify field: null when it matches, 'empty' when nothing is typed, 'wrong' otherwise. */
export type VerifyState = null | 'empty' | 'wrong';
export function verifyStates(groups: readonly string[], slots: readonly [number, number], typed: readonly [string, string]): [VerifyState, VerifyState] {
  const one = (i: 0 | 1): VerifyState => {
    const v = normalizeGroup(typed[i]);
    if (!v) return 'empty';
    return groups[slots[i]] !== undefined && v === groups[slots[i]] ? null : 'wrong';
  };
  return [one(0), one(1)];
}

/** The core keeps a generated recovery code for 10 minutes (desktop/core/src/onetime.rs
 *  DEFAULT_TTL); a code older than this, less a margin for vault creation, is made again before
 *  the user goes on, so the code on paper is always the one the vault uses. */
export const RECOVERY_REF_TTL_MS = 10 * 60_000;
export const RECOVERY_REF_MARGIN_MS = 45_000;
export const recoveryRefStale = (generatedAt: number, now: number): boolean => now - generatedAt > RECOVERY_REF_TTL_MS - RECOVERY_REF_MARGIN_MS;

export const canonicalRecovery = (groups: readonly string[]): string => groups.join('-');

// ---------------------------------------------------------------- HTTP connection target (for the dashboard)

export type TargetCheck =
  | { ok: true; host: string; port: number; tls: boolean; private: boolean }
  | { ok: false; error: 'format' | 'meta' };

const META_HOST = /^(169\.254\.|100\.100\.100\.200$|168\.63\.129\.16$)|^\[(fe[89ab][0-9a-f]:|fd00:ec2:|fd20:ce:|fd00:c1:)/i;
const PRIVATE_HOST = /^(localhost$|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)|^\[(::1|f[cd][0-9a-f]{2}:)/i;

/** Origin only (scheme, host, optional port), no path, query, fragment or user info. */
export function parseTarget(v: string): TargetCheck {
  if (!/^https?:\/\/[^/?#@\s]+\/?$/i.test(v)) return { ok: false, error: 'format' };
  let u: URL;
  try { u = new URL(v); } catch { return { ok: false, error: 'format' }; }
  const host = u.hostname, tls = u.protocol === 'https:';
  const port = u.port ? Number(u.port) : tls ? 443 : 80;
  if (META_HOST.test(host)) return { ok: false, error: 'meta' };
  const priv = PRIVATE_HOST.test(host) || /\.(local|internal|lan|localhost)$/.test(host);
  return { ok: true, host, port, tls, private: priv };
}

// ---------------------------------------------------------------- team invite links

export const INVITE_LINK_MAX = 4096;
const INVITE_LINK_RE = /^zeropw:\/\/join\/?#[a-z2-7]{80,4096}$/i;
export const isInviteLink = (v: string): boolean => v.length <= INVITE_LINK_MAX && INVITE_LINK_RE.test(v);

/** `team join` defaults to project `team-<first 8 of the inviter>` and environment `shared`. */
export const defaultLocalName = (inviter: string): string => `team-${inviter.slice(0, 8).toLowerCase()}/shared`;

export function parseLocalName(v: string): { project: string; environment: string } | null {
  const parts = v.trim().split('/');
  if (parts.length !== 2) return null;
  const [project, environment] = parts as [string, string];
  return isValidName(project) && isValidName(environment) ? { project, environment } : null;
}

/** First 16 characters of a device fingerprint in groups of four. */
export const formatFingerprint = (fp: string): string => (fp.slice(0, 16).match(/.{1,4}/g) ?? []).join(' ');

export function formatCountdown(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return [s / 3600, (s % 3600) / 60, s % 60].map((v) => String(Math.floor(v)).padStart(2, '0')).join(':');
}

// ---------------------------------------------------------------- agents

/** macOS short user names. */
export const isAccountName = (v: string): boolean => /^[a-z_][a-z0-9._-]{0,31}$/i.test(v);

/** Agents that share an OS account share a blast radius, so the account is the runtime. */
export function runtimeFor(where: 'other' | 'same', account: string): string {
  if (where === 'same') return 'default';
  const r = `user-${account.toLowerCase().replace(/[^a-z0-9._-]/g, '-')}`.slice(0, 64);
  return isValidName(r) ? r : 'default';
}
