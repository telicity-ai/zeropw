// Pure helpers behind the dashboard pages: input rules for the forms, grouping for the lists and
// value-free text for records. The core re-checks every input; these only decide what the UI
// marks as ready and which inline error it shows. Nothing here ever handles a secret value.

import type { AuditRecord, ConnectionView, Grant, Project, SecretView } from '../ipc/contract';
import { isValidName } from './validators';

// ---------------------------------------------------------------- projects and environments

export interface EnvPair { project: string; environment: string; key: string }

export const envKey = (project: string, environment: string): string => `${project}/${environment}`;

/** Every project/environment pair, in the order the projects list them. */
export function envPairs(projects: readonly Project[]): EnvPair[] {
  const out: EnvPair[] = [];
  for (const p of projects) {
    for (const e of p.environments) {
      if (typeof e === 'string') out.push({ project: p.name, environment: e, key: envKey(p.name, e) });
    }
  }
  return out;
}

export function splitEnv(key: string): { project: string; environment: string } | null {
  const parts = key.split('/');
  if (parts.length !== 2) return null;
  const [project, environment] = parts as [string, string];
  return isValidName(project) && isValidName(environment) ? { project, environment } : null;
}

export interface SecretGroup { key: string; project: string; environment: string; secrets: SecretView[] }

/** Secrets grouped by project/environment: known pairs first (in project order), then any pair the
 *  project list does not know, each group sorted by id. Empty groups are left out. */
export function groupSecrets(secrets: readonly SecretView[], projects: readonly Project[]): SecretGroup[] {
  const groups = new Map<string, SecretGroup>();
  for (const pair of envPairs(projects)) groups.set(pair.key, { ...pair, secrets: [] });
  for (const s of secrets) {
    const key = envKey(String(s.project), String(s.environment));
    let g = groups.get(key);
    if (!g) { g = { key, project: String(s.project), environment: String(s.environment), secrets: [] }; groups.set(key, g); }
    g.secrets.push(s);
  }
  return [...groups.values()]
    .filter((g) => g.secrets.length > 0)
    .map((g) => ({ ...g, secrets: g.secrets.slice().sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)) }));
}

/** A secret version as the CLI printed it: a JSON number (or a numeric string). The UI shows it
 *  as text and sends it back to the core unchanged. */
export type VersionId = string | number;

/** Versions newest first; the CLI prints them as numbers or numeric strings. */
export function sortedVersions(s: SecretView): SecretView['versions'] {
  return s.versions.slice().sort((a, b) => Number(b.version) - Number(a.version));
}

/** Kinds of stored key the core accepts for each connection type (`secret_kind_mismatch`). */
export const CONNECTION_KEY_KINDS: Record<'http' | 'ssh', readonly SecretView['kind'][]> = {
  http: ['api_key', 'password', 'env_var'],
  ssh: ['ssh_private_key'],
};

/** Stored keys a new connection in `env` can use: same project and environment, a kind the
 *  connection type accepts and an active version. Sorted by id. */
export function keyChoices(secrets: readonly SecretView[], env: string, type: 'http' | 'ssh'): SecretView[] {
  const kinds = CONNECTION_KEY_KINDS[type];
  return secrets
    .filter((s) => envKey(String(s.project), String(s.environment)) === env && kinds.includes(s.kind)
      && s.active_version !== null && s.active_version !== undefined && String(s.active_version) !== '')
    .slice()
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/** The public half of a generated SSH key in `secret_put` output, if there is one. */
export function publicKeyOf(out: Record<string, unknown> | null | undefined): string | null {
  const v = out?.public_key;
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

// ---------------------------------------------------------------- HTTP connection form

export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
export type Method = typeof METHODS[number];
export const WRITE_METHODS: ReadonlySet<Method> = new Set<Method>(['POST', 'PUT', 'PATCH', 'DELETE']);
/** off → not allowed; confirm → allowed after a one-time approval each time; allow → allowed. */
export type MethodState = 'off' | 'confirm' | 'allow';
export type MethodStates = Record<Method, MethodState>;

export function defaultMethodStates(): MethodStates {
  return { GET: 'allow', HEAD: 'allow', POST: 'off', PUT: 'off', PATCH: 'off', DELETE: 'off', OPTIONS: 'off' };
}

/** A write chip turned on asks for approval first; one more press allows it outright (DESIGN.md §5.4). */
export function nextMethodState(m: Method, s: MethodState): MethodState {
  if (WRITE_METHODS.has(m)) return s === 'off' ? 'confirm' : s === 'confirm' ? 'allow' : 'off';
  return s === 'off' ? 'allow' : 'off';
}

export function methodsPayload(states: MethodStates): { methods: string[]; confirm_methods: string[] } {
  const on = METHODS.filter((m) => states[m] !== 'off');
  return { methods: on, confirm_methods: on.filter((m) => states[m] === 'confirm') };
}

/** Write methods that are on, in the order the chips show them. */
export function writeConsequences(states: MethodStates): Array<{ method: Method; confirm: boolean }> {
  return METHODS.filter((m) => WRITE_METHODS.has(m) && states[m] !== 'off').map((m) => ({ method: m, confirm: states[m] === 'confirm' }));
}

/** `/v1, /repos` → ['/v1', '/repos']; empty means every path; null when a part is not a path. */
export function parsePathPrefixes(v: string): string[] | null {
  const parts = v.split(',').map((x) => x.trim()).filter(Boolean);
  if (parts.some((p) => !/^\/[^\s?#\x00-\x1f\x7f]*$/.test(p) || p.length > 256)) return null;
  return [...new Set(parts)];
}

export const isHeaderName = (v: string): boolean => /^[A-Za-z0-9-]{1,64}$/.test(v);
export const isBasicUser = (v: string): boolean => v.length > 0 && v.length <= 256 && !/[:\x00-\x1f\x7f]/.test(v);
export const isCliPath = (v: string): boolean => /^\/[^\x00-\x1f\x7f]{1,1023}$/.test(v);
const CONTROL = /[\x00-\x1f\x7f]/;
export const isPlainText = (v: string, max = 200): boolean => v.length <= max && !CONTROL.test(v);

// ---------------------------------------------------------------- SSH connection form

const HOST_LABEL = '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?';
const HOST_RE = new RegExp(`^(${HOST_LABEL}\\.)*${HOST_LABEL}$`);
/** Lower-case DNS name or IPv4 literal, as the core's connection rules accept. */
export const isSshHost = (v: string): boolean => v.length <= 253 && (HOST_RE.test(v) || /^\d{1,3}(\.\d{1,3}){3}$/.test(v));
export const isSshUser = (v: string): boolean => /^[a-z_][a-z0-9_.-]{0,31}$/.test(v);
/** The core accepts Ed25519 host keys only (`unsupported_host_key` otherwise). */
export const isHostKey = (v: string): boolean => /^ssh-ed25519 [A-Za-z0-9+/]{16,}={0,3}( [^\x00-\x1f\x7f]*)?$/.test(v.trim());

export function parsePort(v: string, min = 1): number | null {
  if (!/^\d{1,5}$/.test(v.trim())) return null;
  const n = Number(v.trim());
  return n >= min && n <= 65535 ? n : null;
}

// ---------------------------------------------------------------- grants

export const GRANT_TTLS = ['1h', '8h', '24h'] as const;
export type GrantTtl = typeof GRANT_TTLS[number];

/** '' → no limit; otherwise a positive decimal integer the core will accept. */
export function parseMaxUses(v: string): { ok: true; value: string | undefined } | { ok: false } {
  const s = v.trim();
  if (!s) return { ok: true, value: undefined };
  if (!/^[1-9]\d{0,8}$/.test(s)) return { ok: false };
  return { ok: true, value: s };
}

export const isActive = (status: string | null | undefined): boolean => status === 'active';

/** A whole number from CLI output, which prints counts as JSON numbers (the contract types them as
 *  strings); null for anything else. */
export function countOf(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && /^\s*\d{1,15}\s*$/.test(v)) return Number(v);
  return null;
}

export type GrantState = 'live' | 'expired' | 'used' | 'revoked' | 'other';

/** What a grant means right now. The CLI keeps a grant's stored status `active` after it expires
 *  or uses up its `max_uses`, so both are derived here from `expires_at` and `uses`/`max_uses`.
 *  A grant without an expiry, or with one the UI cannot read, is not called expired: when in
 *  doubt the page shows authority as live rather than hiding it. */
export function grantState(g: Grant, now: number): GrantState {
  if (g.status !== 'active') return g.status === 'revoked' ? 'revoked' : g.status === 'expired' ? 'expired' : 'other';
  const exp = typeof g.expires_at === 'string' && g.expires_at ? Date.parse(g.expires_at) : NaN;
  if (!Number.isNaN(exp) && exp <= now) return 'expired';
  const max = countOf(g.max_uses), uses = countOf(g.uses);
  if (max !== null && uses !== null && uses >= max) return 'used';
  return 'live';
}

/** Grants that still give a principal access right now, latest expiry first. */
export function liveGrants(grants: readonly Grant[], principal: string, now: number = Date.now()): Grant[] {
  return grants
    .filter((g) => g.principal === principal && grantState(g, now) === 'live')
    .sort((a, b) => Date.parse(String(b.expires_at)) - Date.parse(String(a.expires_at)));
}

// ---------------------------------------------------------------- incidents

/** An incident for this runtime also stops every relay and signature when no active principal
 *  runs anywhere else (rust/src/incident.rs `runtime_covers_all_active`; vacuously true when no
 *  principal is active). */
export function runtimeStopsAll(principals: readonly { runtime: string; status: string }[], runtime: string): boolean {
  return principals.filter((p) => p.status === 'active').every((p) => p.runtime === runtime);
}

// ---------------------------------------------------------------- connections (CLI output, untyped)

export interface ConnectionSummary { kind: 'http' | 'ssh' | 'other'; host: string; env: string; auth: string | null; active: boolean }

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});
const str = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');

/** The few fields the list shows, read defensively from `Connection::to_value`. */
export function summarizeConnection(c: ConnectionView): ConnectionSummary {
  const kind = c.kind === 'http' || c.kind === 'ssh' ? c.kind : 'other';
  let host = '';
  if (kind === 'http') {
    const t = obj(c.http_target);
    const port = str(t.port), scheme = str(t.scheme);
    const def = (scheme === 'https' && port === '443') || (scheme === 'http' && port === '80');
    host = str(t.host) + (port && !def ? `:${port}` : '');
  } else if (kind === 'ssh') {
    const t = obj(c.ssh_target);
    const user = str(t.username), port = str(t.port);
    host = (user ? `${user}@` : '') + str(t.host) + (port && port !== '22' ? `:${port}` : '');
  }
  const auth = kind === 'http' ? str(obj(c.http_auth).mode) || null : null;
  return { kind, host, env: envKey(str(c.project), str(c.environment)), auth, active: c.status === 'active' };
}

// ---------------------------------------------------------------- audit records

const CLIP = 160;
/** Any JSON value as one line of text, clipped. Rendered as a text node, never as markup. */
export function valueText(v: unknown): string {
  let s: string;
  if (typeof v === 'string') s = v;
  else if (v === null || v === undefined) s = '';
  else if (typeof v === 'number' || typeof v === 'boolean') s = String(v);
  else { try { s = JSON.stringify(v) ?? ''; } catch { s = ''; } }
  s = s.replace(/[\x00-\x1f\x7f]+/g, ' ');
  return s.length > CLIP ? s.slice(0, CLIP - 1) + '…' : s;
}

/** Title and fields of an audit record or alert: the event name, then every other field as
 *  `key=value` text in the order the record has them. */
export function recordFields(rec: AuditRecord, titleKey = 'event'): { ts: string; title: string; fields: string[] } {
  const ts = valueText(rec.ts);
  const title = valueText(rec[titleKey]) || valueText(rec.alert) || valueText(rec.event);
  const fields: string[] = [];
  for (const [k, v] of Object.entries(rec)) {
    if (k === 'ts' || k === titleKey) continue;
    const text = valueText(v);
    if (text !== '') fields.push(`${valueText(k)}=${text}`);
  }
  return { ts, title, fields };
}

/** A stable signature for "the newest record I have seen". */
export function recordSig(rec: AuditRecord | undefined): string | null {
  if (!rec) return null;
  try { return JSON.stringify(rec); } catch { return null; }
}

/** How many records in `records` (oldest first) came after the one with signature `prev`.
 *  `prev` null means the log was empty last time, so everything is new; a signature that fell
 *  out of the window also counts the whole window. The caller skips the very first poll. */
export function newRecordCount(prev: string | null, records: readonly AuditRecord[]): number {
  if (records.length === 0) return 0;
  if (prev === null) return records.length;
  for (let i = records.length - 1; i >= 0; i--) {
    if (recordSig(records[i]) === prev) return records.length - 1 - i;
  }
  return records.length;
}

// ---------------------------------------------------------------- approvals

// Text that decides an approval is shown in full (wrapped, not clipped), with control and
// bidirectional formatting characters removed so one request cannot pass for another on screen.
const BIDI = /[‎‏‪-‮⁦-⁩]/g;
const APPROVAL_TEXT_MAX = 8192;

/** One line of untrusted text, in full up to a generous limit. */
export function lineText(v: unknown, max = APPROVAL_TEXT_MAX): string {
  const s = typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '';
  const clean = s.replace(BIDI, '').replace(/[\x00-\x1f\x7f]+/g, ' ');
  return clean.length > max ? clean.slice(0, max - 1) + '…' : clean;
}

/** Several lines of untrusted text (a request body preview): line breaks and tabs stay, every
 *  other control or bidirectional formatting character goes. */
export function blockText(v: unknown, max = APPROVAL_TEXT_MAX): string {
  if (typeof v !== 'string') return '';
  const clean = v.replace(BIDI, '').replace(/\r\n?/g, '\n').replace(/[\x00-\x08\x0b-\x1f\x7f]+/g, ' ');
  return clean.length > max ? clean.slice(0, max - 1) + '…' : clean;
}

/** First 16 hex digits of a SHA-256 in groups of four, to tell two similar requests apart. */
export function shortHash(v: unknown): string | null {
  if (typeof v !== 'string' || !/^[0-9a-f]{16,}$/i.test(v)) return null;
  return (v.slice(0, 16).toLowerCase().match(/.{4}/g) ?? []).join(' ');
}

export interface ApprovalView {
  digest: string; caller: string; connection: string; method: string;
  /** The path without the query, in full. */
  path: string;
  /** The query string (without `?`), or null when the request had none. */
  query: string | null;
  /** `path?query` as the request was bound, in full. */
  target: string;
  created_at: string; status: string;
  contentType: string | null; bodyBytes: number | null; bodyHash: string | null;
  /** The start of a text body (the core keeps 256 characters), or null for none or binary. */
  bodyPreview: string | null; bodyTruncated: boolean; origin: string | null;
}

/** Pending approvals with everything the core bound the approval to: the full path and query, the
 *  body's size, type, hash and preview. Fields are read defensively and shown as text only. */
export function pendingApprovals(list: readonly Record<string, unknown>[]): ApprovalView[] {
  return list
    .map((a): ApprovalView => {
      const path = lineText(a.path);
      const query = typeof a.query === 'string' ? lineText(a.query) : null;
      const preview = typeof a.body_preview === 'string' ? blockText(a.body_preview) : null;
      return {
        digest: str(a.digest), caller: valueText(a.caller), connection: valueText(a.connection), method: valueText(a.method),
        path, query, target: query !== null ? `${path}?${query}` : path, created_at: valueText(a.created_at), status: str(a.status),
        contentType: typeof a.content_type === 'string' && a.content_type ? lineText(a.content_type, 200) : null,
        bodyBytes: countOf(a.body_bytes), bodyHash: shortHash(a.body_sha256),
        bodyPreview: preview, bodyTruncated: a.body_preview_truncated === true,
        origin: typeof a.origin === 'string' && a.origin ? lineText(a.origin, 300) : null,
      };
    })
    .filter((a) => a.digest && a.status === 'pending');
}

// ---------------------------------------------------------------- team

/** `100.64.1.7:47420` → parts; null for anything else. */
export function parseListen(v: string | null | undefined): { ip: string; port: number } | null {
  if (!v) return null;
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(v);
  if (!m) return null;
  const port = parsePort(m[2] ?? '');
  const ip = m[1] ?? '';
  if (port === null || ip.split('.').some((o) => Number(o) > 255)) return null;
  return { ip, port };
}

export const DEFAULT_TEAM_PORT = 47420;

/** The address other devices most likely reach: a VPN address first, then the LAN. */
export function defaultListenIp(interfaces: readonly { ip: string; kind: string }[]): string {
  return (interfaces.find((i) => i.kind === 'vpn') ?? interfaces.find((i) => i.kind === 'lan') ?? interfaces[0])?.ip ?? '';
}

/** `100.64.1.7 · VPN` for the address picker; the interface name when the kind is unknown. */
export const interfaceLabel = (i: { ip: string; name: string; kind: string }): string =>
  `${i.ip} · ${i.kind === 'vpn' ? 'VPN' : i.kind === 'lan' ? 'LAN' : i.name}`;
export const MIN_GATEWAY_PORT = 1024;

export const msLeft = (expiresAt: string, now: number): number => {
  const t = Date.parse(expiresAt);
  return Number.isNaN(t) ? 0 : Math.max(0, t - now);
};

/** Fraction of a 24-hour invite still left, for the ring. */
export const inviteFraction = (expiresAt: string, now: number): number => Math.min(1, msLeft(expiresAt, now) / (24 * 3600 * 1000));

/** Seconds left of a revealed value's 30-second window. */
export const REVEAL_SECONDS = 30;
