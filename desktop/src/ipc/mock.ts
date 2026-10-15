// In-memory stand-in for the Tauri core, used only outside the desktop app (`npm run dev` in a
// browser, and tests). Every value here is synthetic. It follows the contract and the core's
// rules closely enough to review the onboarding and dashboard flows: one-time references,
// value-free errors and a small simulated shell for the agent terminal.
// Seeded review state (`?state=ready`): the synthetic admin passphrase is `mock-admin-pass` and
// the synthetic recovery code is `ABCD-EFGH-IJKL-MNOP-QRST-UVWX`.

import type {
  Alert, AppError, AuditRecord, CommandName, Commands, ConnectionView, Control, Events, Grant, Incident, InviteListItem, InvitePreview,
  Member, Principal, Project, SecretKind, SecretView, ServeStatus, Settings,
} from './contract';
import { fnv1a, mulberry32 } from '../lib/rng';
import { isInviteLink, isValidName, MIN_PASSPHRASE_CHARS, parseTarget, sameAsAdmin } from '../lib/validators';
import { isHostKey, isSshHost, isSshUser, parseListen, splitEnv } from '../lib/dash';

export interface MockChannel { onmessage: (data: string) => void }
export interface MockSeed {
  /** Start with a vault, a project, an agent and some records (dashboard review). */
  initialized?: boolean;
  /** Multiplier for simulated latency; 0 resolves immediately. */
  latency?: number;
  /** Emit a synthetic audit record now and then while the relay runs. */
  activity?: boolean;
}
export interface MockInspect {
  initialized: boolean; onetime: number; terminals: number; projects: string[]; principals: string[]; stopped: boolean;
  secureView: boolean; secrets: string[]; connections: string[];
}
export interface MockBackend {
  call<K extends CommandName>(name: K, input: Commands[K][0]): Promise<Commands[K][1]>;
  on<E extends keyof Events>(name: E, handler: (payload: Events[E]) => void): () => void;
  emit<E extends keyof Events>(name: E, payload: Events[E]): void;
  /** Value-free view for tests. */
  inspect(): MockInspect;
  dispose(): void;
}

const SEED_ADMIN = 'mock-admin-pass';
const SEED_RECOVERY = 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX';
const BUNDLE = '/Applications/ZeroPW.app/Contents/MacOS';
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
const HEX = '0123456789abcdef';
const KINDS: readonly SecretKind[] = ['api_key', 'password', 'env_var', 'ssh_private_key'];
const RING = 64 * 1024;

const fail = (error: string, reason: string, detail?: string): AppError => (detail ? { error, reason, detail } : { error, reason });

function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}
const randFrom = (n: number, alphabet: string): string => [...randBytes(n)].map((x) => alphabet[x & (alphabet.length - 1)]).join('');
const newRef = (): string => 'ref_' + [...randBytes(16)].map((x) => x.toString(16).padStart(2, '0')).join('');
const iso = (ms = Date.now()): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const HOUR = 3_600_000;

/** Recovery codes compare in their canonical form (six groups, upper case, dashes). */
function canonicalRecovery(v: string): string {
  const compact = v.replace(/[\s-]+/g, '').toUpperCase();
  return /^[A-Z2-7]{24}$/.test(compact) ? (compact.match(/.{4}/g) ?? []).join('-') : v;
}

// ---- passphrase score: the mockup's placeholder heuristic, reported as a zxcvbn-style 0..4
const COMMON = /(password|passw0rd|qwerty|asdf|iloveyou|letmein|admin|welcome|zeropw|1234|abcd|\uBE44\uBC00\uBC88\uD638|\uC0AC\uB791\uD574)/i;
export function mockStrength(p: string): { score: number; reason: string | null } {
  if (!p) return { score: 0, reason: null };
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(p)) pool += 24;
  const n = [...p].length, uniq = new Set(p).size / n;
  let s = Math.min(1, Math.max(0, (n * Math.log2(Math.max(pool, 2)) * (0.55 + 0.45 * uniq)) / 90));
  let reason: string | null = null;
  if (COMMON.test(p)) { s = Math.min(s, 0.3); reason = 'common_password'; }
  else if (/(.)\1{2,}/.test(p) || /(.{3,})\1/.test(p)) { s = Math.min(s, 0.4); reason = 'repeated'; }
  else if (/(19|20)\d\d$/.test(p)) { s = Math.min(s, 0.45); reason = 'date'; }
  else if (n < 12) reason = 'too_guessable';
  const score = s >= 0.85 ? 4 : s >= 0.5 ? 3 : s >= 0.3 ? 2 : s >= 0.1 ? 1 : 0;
  return { score, reason };
}

// ---- a tiny shell behind the agent terminal
interface MockTerminal {
  id: string; out: MockChannel | null; user: string; line: string; password: string | null; cols: number; rows: number; closed: boolean;
  timers: Set<ReturnType<typeof setTimeout>>; principal: string; asUser: string | null; ring: string; suggestions: string[];
}

interface OneTime { kind: 'recovery' | 'token' | 'invite' | 'link' | 'secret'; text: string; preview?: InvitePreview; principal?: string }
interface MockVersion { version: number; status: 'staged' | 'active' | 'retired' | 'revoked'; created_at: string; value: string; public: { public_key: string; fingerprint: string; algorithm: string } | null }
interface MockSecret { id: string; project: string; environment: string; kind: SecretKind; versions: MockVersion[] }
interface MockInvite extends InviteListItem { secret: string }
interface MockTeamEnv { env_id: string; project: string; environment: string; members: Member[]; invites: MockInvite[] }
interface MockFile { purpose: 'secret' | 'ssh_key' | 'ca'; name: string; content: string }

function previewFor(text: string): InvitePreview {
  const body = text.slice(text.indexOf('#') + 1).toLowerCase();
  const rnd = mulberry32(fnv1a(body));
  const pick = (n: number) => Array.from({ length: n }, () => B32[Math.floor(rnd() * 32)]).join('');
  const inviter = pick(26).toUpperCase();
  const expired = body.startsWith('zzzz');
  return {
    env_id: pick(26), inviter, addresses: ['100.64.1.7:47420'], role: rnd() < 0.8 ? 'user' : 'admin', name: 'teammate',
    expires_at: iso(Date.now() + (expired ? -60_000 : (23 * 3600 + 12 * 60 + 4) * 1000)), expired, invite_id: pick(32),
  };
}

function secretView(s: MockSecret): SecretView {
  const active = s.versions.find((v) => v.status === 'active');
  return {
    id: s.id, project: s.project, environment: s.environment, kind: s.kind, active_version: active ? String(active.version) : null,
    versions: s.versions.map((v) => ({ version: String(v.version), status: v.status, created_at: v.created_at, public: v.public })),
  };
}

export function createMockBackend(seed: MockSeed = {}): MockBackend {
  const latency = seed.latency ?? 0;
  const listeners = new Map<string, Set<(p: unknown) => void>>();
  const onetime = new Map<string, OneTime>();
  const terminals = new Map<string, MockTerminal>();
  let adminPass: string | null = null;
  let recoveryCode: string | null = null;
  let initialized = false;
  let serve: ServeStatus = { running: false, url: null, pid: null, team_listen: null };
  let control: Control = { stopped: false, restore_pending: false, incident_open: false };
  const projects: Project[] = [];
  const principals: Principal[] = [];
  const secrets = new Map<string, MockSecret>();
  const connections = new Map<string, ConnectionView>();
  const grants: Grant[] = [];
  const approvals = new Map<string, Record<string, unknown>>();
  const approvalHistory: Record<string, unknown>[] = [];
  const incidents: Incident[] = [];
  const teams = new Map<string, MockTeamEnv>();
  const files = new Map<string, MockFile>();
  let deviceFp: string | null = null;
  let secureView = false;
  const audit: AuditRecord[] = [];
  const alerts: Alert[] = [];
  let settings: Settings = { gateway_port: 47380, team_listen: null };
  let activity: ReturnType<typeof setInterval> | null = null;

  const wait = (ms: number) => new Promise<void>((r) => { if (latency > 0) setTimeout(r, ms * latency); else r(); });
  const emit = <E extends keyof Events>(name: E, payload: Events[E]) => { listeners.get(name)?.forEach((h) => h(payload)); };
  const needInit = () => { if (!initialized) throw fail('UsageError', 'not_initialized'); };
  const checkAdmin = (p: unknown) => {
    if (typeof p !== 'string' || !p) throw fail('AuthFailed', 'passphrase_missing');
    if (p !== adminPass) throw fail('AuthFailed', 'bad_passphrase');
  };
  const startServe = () => {
    serve = { running: true, url: `http://127.0.0.1:${settings.gateway_port}`, pid: 40000 + (randBytes(1)[0] ?? 0), team_listen: settings.team_listen };
    emit('serve://status', serve);
  };
  const record = (rec: AuditRecord) => { audit.push(rec); if (audit.length > 500) audit.shift(); emit('audit://records', { records: [rec] }); };
  const setControl = (c: Control) => { control = c; emit('control://changed', control); };
  const requireEnv = (project: unknown, environment: unknown) => {
    const p = projects.find((x) => x.name === project);
    if (!p) throw fail('InvalidInput', 'project_unknown');
    if (typeof environment !== 'string' || !p.environments.includes(environment)) throw fail('InvalidInput', 'environment_unknown');
  };
  const fingerprint = () => (deviceFp ??= randFrom(26, B32).toUpperCase());
  const grantView = (g: Grant): Grant => (g.status === 'active' && Date.parse(g.expires_at) < Date.now() ? { ...g, status: 'expired' } : { ...g });
  const inviteView = (i: MockInvite): InviteListItem => {
    const v: InviteListItem = {
      invite_id: i.invite_id, role: i.role, name: i.name, link: i.link, created_at: i.created_at, expires_at: i.expires_at, status: i.status,
      used_at: i.used_at, used_by: i.used_by, revoked_at: i.revoked_at,
    };
    if (v.status === 'pending' && Date.parse(v.expires_at) < Date.now()) v.status = 'expired';
    return v;
  };
  const teamOf = (env: unknown): MockTeamEnv => {
    const pair = typeof env === 'string' ? splitEnv(env) : null;
    if (!pair) throw fail('UsageError', 'invalid_env');
    const t = teams.get(`${pair.project}/${pair.environment}`);
    if (!t) throw fail('NotFound', 'team_env_not_found');
    return t;
  };

  function addSecret(id: string, kind: SecretKind, project: string, environment: string, value: string, pub: MockVersion['public'] = null): MockVersion {
    let s = secrets.get(id);
    if (!s) { s = { id, project, environment, kind, versions: [] }; secrets.set(id, s); }
    else if (s.project !== project || s.environment !== environment || s.kind !== kind) throw fail('InvalidInput', 'secret_identity_mismatch');
    for (const v of s.versions) if (v.status === 'active') v.status = 'retired';
    const v: MockVersion = { version: s.versions.reduce((m, x) => Math.max(m, x.version), 0) + 1, status: 'active', created_at: iso(), value, public: pub };
    s.versions.push(v);
    return v;
  }

  function seedReady() {
    initialized = true;
    adminPass = SEED_ADMIN;
    recoveryCode = SEED_RECOVERY;
    startServe();
    const ago = (ms: number) => iso(Date.now() - ms);
    projects.push({ name: 'demo', environments: ['dev', 'staging', 'prod'], created_at: ago(24 * HOUR) });
    principals.push({ id: 'agent-1', status: 'active', created_at: ago(22 * HOUR), runtime: 'user-agent' });
    addSecret('example-api', 'api_key', 'demo', 'dev', 'sk_test_mock_' + randFrom(24, B32));
    addSecret('example-api', 'api_key', 'demo', 'dev', 'sk_test_mock_' + randFrom(24, B32));
    addSecret('db-password', 'password', 'demo', 'prod', 'mock-db-' + randFrom(16, B32));
    addSecret('sentry-dsn', 'env_var', 'demo', 'staging', 'https://mock' + randFrom(12, HEX) + '@example.invalid/1');
    connections.set('example-api', {
      id: 'example-api', project: 'demo', environment: 'dev', service: 'example-api', kind: 'http', secret_id: 'example-api', secret_version: null,
      description: null, http_target: { scheme: 'https', host: 'api.example.com', port: 443, ca_file: null, allow_private_network: false },
      http_auth: { mode: 'bearer', header_name: null, value_prefix: null, basic_username: null },
      http_scope: { methods: ['GET', 'HEAD', 'POST'], path_prefixes: [], confirm_methods: ['POST'] }, ssh_target: null, cli: null,
      policy_version: 1, status: 'active', created_at: ago(20 * HOUR), updated_at: ago(20 * HOUR),
    });
    grants.push({ id: 'grant_' + randFrom(12, HEX), principal: 'agent-1', connection: 'example-api', expires_at: iso(Date.now() + 6 * HOUR), max_uses: null, uses: '14', status: 'active' });
    approvals.set(randFrom(64, HEX), {
      caller: 'agent-1', connection: 'example-api', method: 'POST', path: '/v1/items', status: 'pending', created_at: ago(90_000), expires_at: Math.floor((Date.now() + 600_000) / 1000),
    });
    incidents.push({
      id: 'inc_' + randFrom(12, HEX), status: 'closed', scope: 'principal', opened_at: ago(30 * HOUR), runtime: null, principals: ['agent-0'],
      trigger: 'manual', rule: null, detail: 'rotated after a test', actions: {}, assessment: {}, notification: {}, closed_at: ago(29 * HOUR), widened_from: [],
    });
    alerts.push(
      { ts: ago(HOUR), alert: 'grant_expired', caller: 'agent-1', connection: 'example-api' },
      { ts: ago(600_000), alert: 'policy_denied', caller: 'agent-1', connection: 'example-api', reason: 'method_not_allowed' },
    );
    for (const [ms, rec] of [
      [24 * HOUR, { event: 'init' }], [24 * HOUR, { event: 'project_create', project: 'demo' }],
      [22 * HOUR, { event: 'principal_create', principal: 'agent-1' }], [20 * HOUR, { event: 'connection_create', connection: 'example-api' }],
      [19 * HOUR, { event: 'grant_create', principal: 'agent-1', connection: 'example-api' }],
      [3 * HOUR, { event: 'proxy_request', caller: 'agent-1', connection: 'example-api', method: 'GET', path: '/v1/items', status: 200 }],
      [90_000, { event: 'approval_request', caller: 'agent-1', connection: 'example-api', method: 'POST', path: '/v1/items' }],
    ] as const) audit.push({ ts: ago(ms), ...rec });
    // a terminal left running by the onboarding, so the agents page has something to reattach
    const term = newTerminal('agent-1', 'agent');
    term.user = 'agent';
    term.ring = prompt('me') + term.suggestions[0] + '\r\nPassword:\r\n' + prompt('agent') + term.suggestions[1] + '\r\n{"connections":[]}\r\n' + prompt('agent');
  }

  // ---- terminal
  const prompt = (u: string) => `\x1b[38;2;143;176;255m${u}@mac ~ %\x1b[0m `;
  function newTerminal(principal: string, asUser: string | null): MockTerminal {
    const id = 'term_' + randFrom(10, HEX);
    const list = `${BUNDLE}/zeropw-agent list-connections`;
    const suggestions = asUser ? [`sudo --preserve-env=ZEROPW_GATEWAY_URL,ZEROPW_CALLER_TOKEN,no_proxy -u ${asUser} -i`, list] : [list];
    const term: MockTerminal = { id, out: null, user: 'me', line: '', password: null, cols: 80, rows: 24, closed: false, timers: new Set(), principal, asUser, ring: '', suggestions };
    terminals.set(id, term);
    return term;
  }
  function deliver(term: MockTerminal, data: string) {
    term.ring = (term.ring + data).slice(-RING);
    term.out?.onmessage(data);
  }
  function termSend(term: MockTerminal, data: string, delay = 0) {
    if (term.closed) return;
    if (latency <= 0 || delay <= 0) { deliver(term, data); return; }
    const id = setTimeout(() => { term.timers.delete(id); if (!term.closed) deliver(term, data); }, delay * latency);
    term.timers.add(id);
  }
  function runLine(term: MockTerminal, cmd: string) {
    const c = cmd.trim();
    if (term.password !== null) {
      const target = term.password; term.password = null;
      termSend(term, '\r\n');
      term.user = target;
      termSend(term, prompt(term.user), 400);
      return;
    }
    termSend(term, '\r\n');
    if (!c) { termSend(term, prompt(term.user)); return; }
    const sudo = /^sudo\b.*\s-u\s+([A-Za-z0-9._-]+)\s+-i$/.exec(c);
    if (sudo) { term.password = sudo[1] ?? 'agent'; termSend(term, 'Password:', 200); return; }
    if (/(^|\/)zeropw-agent\s+list-connections$/.test(c)) {
      const visible = grants.filter((g) => g.principal === term.principal && grantView(g).status === 'active').map((g) => g.connection);
      termSend(term, JSON.stringify({ connections: visible.map((id) => ({ id })) }) + '\r\n', 260);
      termSend(term, prompt(term.user), 300);
      return;
    }
    if (c === 'exit') {
      if (term.user !== 'me') { term.user = 'me'; termSend(term, 'logout\r\n' + prompt(term.user)); return; }
      termSend(term, '\r\n[process completed]\r\n'); term.closed = true; return;
    }
    const word = c.split(/\s+/)[0] ?? c;
    termSend(term, `zsh: command not found: ${word}\r\n` + prompt(term.user));
  }
  function termWrite(term: MockTerminal, data: string) {
    if (term.closed) return;
    if (data.startsWith('\x1b')) return;                    // arrows and other escapes: ignored by this toy shell
    for (const ch of data) {
      if (ch === '\r' || ch === '\n') { const l = term.line; term.line = ''; runLine(term, l); }
      else if (ch === '\x7f' || ch === '\b') { if (term.line) { term.line = term.line.slice(0, -1); if (term.password === null) termSend(term, '\b \b'); } }
      else if (ch === '\x03') { term.line = ''; term.password = null; termSend(term, '^C\r\n' + prompt(term.user)); }
      else if (ch >= ' ') { term.line += ch; if (term.password === null) termSend(term, ch); }
    }
  }
  const channelOf = (on_data: unknown): MockChannel => {
    const out = on_data as MockChannel | undefined;
    if (!out || typeof out.onmessage !== 'function') throw fail('InvalidInput', 'channel_missing');
    return out;
  };

  if (seed.initialized) seedReady();
  if (seed.activity && typeof window !== 'undefined') {
    activity = setInterval(() => {
      if (!initialized || !serve.running || control.stopped) return;
      record({ ts: iso(), event: 'proxy_request', caller: 'agent-1', connection: 'example-api', method: 'GET', status: 200 });
    }, 9000);
  }

  // ---- commands
  type Handler<K extends CommandName> = (input: Commands[K][0]) => Promise<Commands[K][1]> | Commands[K][1];
  const handlers: { [K in CommandName]?: Handler<K> } = {
    app_status: () => ({ initialized, state_dir: '~/Library/Application Support/ZeroPW/state', serve, control: initialized ? control : null }),
    password_strength: ({ value }) => mockStrength(typeof value === 'string' ? value : ''),
    recovery_generate: () => {
      const groups = Array.from({ length: 6 }, () => randFrom(4, B32).toUpperCase());
      const ref = newRef();
      onetime.set(ref, { kind: 'recovery', text: groups.join('-') });
      return { ref, groups };
    },
    vault_init: async ({ admin_passphrase, recovery }) => {
      if (initialized) throw fail('StateError', 'vault_exists');
      if (typeof admin_passphrase !== 'string' || [...admin_passphrase].length < MIN_PASSPHRASE_CHARS) throw fail('InvalidInput', 'passphrase_too_short');
      let code: string;
      if ('ref' in recovery) {
        const item = onetime.get(recovery.ref);
        if (!item || item.kind !== 'recovery') throw fail('NotFound', 'onetime_ref_unknown');
        onetime.delete(recovery.ref);
        code = item.text;
      } else if (typeof recovery.typed !== 'string' || [...recovery.typed].length < MIN_PASSPHRASE_CHARS) {
        throw fail('InvalidInput', 'recovery_too_short');
      } else if (sameAsAdmin(recovery.typed, admin_passphrase)) {
        throw fail('InvalidInput', 'recovery_same_as_admin');
      } else {
        code = canonicalRecovery(recovery.typed);
      }
      await wait(1100);
      initialized = true;
      adminPass = admin_passphrase;
      recoveryCode = code;
      startServe();
      record({ ts: iso(), event: 'init' });
      return { state_dir: '~/Library/Application Support/ZeroPW/state', kms_key_id: 'kms-dev-' + randFrom(8, HEX) };
    },
    serve_start: async () => { needInit(); await wait(300); startServe(); return serve; },
    serve_stop: async () => { await wait(150); serve = { running: false, url: null, pid: null, team_listen: null }; emit('serve://status', serve); return serve; },
    serve_status: () => serve,
    control_get: () => { needInit(); return control; },
    stop_all: async () => {
      needInit(); await wait(250);
      setControl({ ...control, stopped: true }); record({ ts: iso(), event: 'stop_all' }); return control;
    },
    resume: async ({ admin_passphrase }) => {
      needInit(); await wait(350);
      if (!adminPass || admin_passphrase !== adminPass) throw fail('AuthFailed', 'bad_passphrase');
      setControl({ ...control, stopped: false }); record({ ts: iso(), event: 'resume' }); return control;
    },

    // ---- projects
    project_list: () => { needInit(); return { projects: projects.map((p) => ({ ...p, environments: p.environments.slice() })) }; },
    project_create: async ({ name, environments }) => {
      needInit();
      if (!isValidName(name)) throw fail('InvalidInput', 'invalid_name', 'project');
      if (!Array.isArray(environments) || !environments.length || !environments.every(isValidName)) throw fail('InvalidInput', 'invalid_name', 'environment');
      if (projects.some((p) => p.name === name)) throw fail('InvalidInput', 'project_exists');
      await wait(250);
      const p: Project = { name, environments: [...new Set(environments)], created_at: iso() };
      projects.push(p); record({ ts: iso(), event: 'project_create', project: name });
      return p;
    },

    // ---- secrets (values stay here; only onetime_show hands one out)
    secret_list: ({ project, environment } = {}) => {
      needInit();
      const list = [...secrets.values()].filter((s) => (!project || s.project === project) && (!environment || s.environment === environment));
      return { secrets: list.map(secretView) };
    },
    secret_versions: ({ id }) => {
      needInit();
      const s = secrets.get(id);
      if (!s) throw fail('NotFound', 'secret_not_found');
      return secretView(s);
    },
    secret_put: async ({ id, kind, project, environment, source }) => {
      needInit();
      if (!isValidName(id)) throw fail('InvalidInput', 'invalid_secret_id');
      if (!KINDS.includes(kind)) throw fail('InvalidInput', 'invalid_secret_kind');
      requireEnv(project, environment);
      let value: string, pub: MockVersion['public'] = null;
      if (source && 'typed' in source) {
        if (typeof source.typed !== 'string' || !source.typed) throw fail('InvalidInput', 'invalid_secret_value');
        value = source.typed;
      } else if (source && 'file_token' in source) {
        const f = files.get(source.file_token);
        if (!f || (f.purpose !== 'secret' && f.purpose !== 'ssh_key')) throw fail('InvalidInput', 'file_token_unknown');
        files.delete(source.file_token);
        value = f.content;
      } else if (source && 'generate_ed25519' in source && source.generate_ed25519 === true) {
        if (kind !== 'ssh_private_key') throw fail('InvalidInput', 'source_kind_mismatch');
        value = 'mock-openssh-private-key-' + randFrom(32, B32);
        const fp = 'SHA256:' + randFrom(43, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
        pub = { public_key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${randFrom(43, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')} ${id}`, fingerprint: fp, algorithm: 'ssh-ed25519' };
      } else {
        throw fail('InvalidInput', 'secret_source_required');
      }
      await wait(300);
      const v = addSecret(id, kind, project, environment, value, pub);
      record({ ts: iso(), event: 'secret_put', secret: id, version: v.version, kind });
      const out: Record<string, unknown> = { id, version: v.version, status: 'active', kind, project, environment };
      if (pub) { out.public_key = pub.public_key; out.fingerprint = pub.fingerprint; }
      return out;
    },
    secret_reveal: async ({ id, version, admin_passphrase }) => {
      needInit(); await wait(350);
      checkAdmin(admin_passphrase);
      const s = secrets.get(id);
      if (!s) throw fail('NotFound', 'secret_not_found');
      const v = version ? s.versions.find((x) => String(x.version) === version) : s.versions.find((x) => x.status === 'active');
      if (!v) throw fail('NotFound', 'version_not_found');
      if (v.status === 'revoked') throw fail('InvalidInput', 'version_revoked');
      const ref = newRef();
      onetime.set(ref, { kind: 'secret', text: v.value });
      record({ ts: iso(), event: 'secret_reveal', secret: id, version: v.version });
      return { ref, id, version: String(v.version) };
    },
    secret_retire: ({ id, version }) => {
      needInit();
      const v = secrets.get(id)?.versions.find((x) => String(x.version) === version);
      if (!v) throw fail('NotFound', 'version_not_found');
      if (v.status === 'revoked') throw fail('InvalidInput', 'version_revoked');
      if (v.status === 'active') throw fail('InvalidInput', 'version_is_active');
      v.status = 'retired'; record({ ts: iso(), event: 'secret_retire', secret: id, version: v.version });
      return { id, version: v.version, status: v.status };
    },
    secret_revoke: ({ id, version }) => {
      needInit();
      const v = secrets.get(id)?.versions.find((x) => String(x.version) === version);
      if (!v) throw fail('NotFound', 'version_not_found');
      v.status = 'revoked'; v.value = ''; record({ ts: iso(), event: 'secret_revoke', secret: id, version: v.version });
      return { id, version: v.version, status: v.status };
    },

    // ---- connections
    connection_list: () => { needInit(); return { connections: [...connections.values()].map((c) => ({ ...c })) }; },
    connection_create_http: async (input) => {
      needInit(); await wait(400);
      checkAdmin(input.admin_passphrase);
      if (!isValidName(input.id)) throw fail('InvalidInput', 'invalid_connection_id');
      if (connections.has(input.id)) throw fail('InvalidInput', 'connection_exists');
      requireEnv(input.project, input.environment);
      const s = secrets.get(input.secret_id);
      if (!s || s.project !== input.project || s.environment !== input.environment) throw fail('InvalidInput', 'secret_not_found');
      const target = parseTarget(input.target);
      if (!target.ok) throw fail('InvalidInput', target.error === 'meta' ? 'metadata_address_not_allowed' : 'invalid_scheme');
      if (target.private && !input.allow_private_network) throw fail('InvalidInput', 'target_address_not_allowed');
      if (!['bearer', 'basic', 'header'].includes(input.auth)) throw fail('InvalidInput', 'invalid_auth');
      if (!input.methods.length) throw fail('InvalidInput', 'invalid_methods');
      const now = iso();
      const c: ConnectionView = {
        id: input.id, project: input.project, environment: input.environment, service: input.service, kind: 'http', secret_id: input.secret_id,
        secret_version: null, description: input.description ?? null,
        http_target: { scheme: target.tls ? 'https' : 'http', host: target.host, port: target.port, ca_file: input.ca_file_token ? 'ca.pem' : null, allow_private_network: input.allow_private_network },
        http_auth: { mode: input.auth, header_name: input.header_name ?? null, value_prefix: input.value_prefix ?? null, basic_username: input.basic_username ?? null },
        http_scope: { methods: input.methods.slice(), path_prefixes: input.path_prefixes.slice(), confirm_methods: input.confirm_methods.slice() },
        ssh_target: null, cli: input.cli_program ? { program: input.cli_program, kind: 'http', base_url_env: 'ZEROPW_API_BASE_URL', extra_env: {} } : null,
        policy_version: 1, status: 'active', created_at: now, updated_at: now,
      };
      connections.set(c.id, c); record({ ts: now, event: 'connection_create', connection: c.id, kind: 'http' });
      return { ...c };
    },
    connection_create_ssh: async (input) => {
      needInit(); await wait(400);
      checkAdmin(input.admin_passphrase);
      if (!isValidName(input.id)) throw fail('InvalidInput', 'invalid_connection_id');
      if (connections.has(input.id)) throw fail('InvalidInput', 'connection_exists');
      requireEnv(input.project, input.environment);
      const s = secrets.get(input.secret_id);
      if (!s || s.kind !== 'ssh_private_key') throw fail('InvalidInput', 'secret_not_found');
      if (!isSshHost(input.host)) throw fail('InvalidInput', 'invalid_host');
      if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535) throw fail('InvalidInput', 'invalid_port');
      if (!isSshUser(input.username)) throw fail('InvalidInput', 'invalid_ssh_username');
      if (!input.host_keys.length) throw fail('InvalidInput', 'ssh_host_keys_required');
      if (!input.host_keys.every(isHostKey)) throw fail('InvalidInput', 'unsupported_host_key');
      const now = iso();
      const c: ConnectionView = {
        id: input.id, project: input.project, environment: input.environment, service: input.service, kind: 'ssh', secret_id: input.secret_id,
        secret_version: null, description: input.description ?? null, http_target: null, http_auth: null, http_scope: null,
        ssh_target: { host: input.host, port: input.port, username: input.username, host_keys: input.host_keys.slice() }, cli: null,
        policy_version: 1, status: 'active', created_at: now, updated_at: now,
      };
      connections.set(c.id, c); record({ ts: now, event: 'connection_create', connection: c.id, kind: 'ssh' });
      return { ...c };
    },
    connection_disable: ({ id }) => {
      needInit();
      const c = connections.get(id);
      if (!c) throw fail('NotFound', 'connection_not_found');
      c.status = 'disabled'; record({ ts: iso(), event: 'connection_disable', connection: id });
      return { id, status: 'disabled' };
    },

    // ---- agents and grants
    principal_list: () => { needInit(); return { principals: principals.map((p) => ({ ...p })) }; },
    principal_create: async ({ id, runtime }) => {
      needInit();
      if (!isValidName(id)) throw fail('InvalidInput', 'invalid_name', 'principal_id');
      if (!isValidName(runtime)) throw fail('InvalidInput', 'invalid_name', 'runtime');
      if (principals.some((p) => p.id === id)) throw fail('InvalidInput', 'principal_exists');
      await wait(250);
      principals.push({ id, status: 'active', created_at: iso(), runtime });
      const token_ref = newRef();
      onetime.set(token_ref, { kind: 'token', text: 'zpwc_' + randFrom(43, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'), principal: id });
      record({ ts: iso(), event: 'principal_create', principal: id });
      return { id, runtime, token_ref };
    },
    principal_disable: ({ id }) => {
      const p = principals.find((x) => x.id === id);
      if (!p) throw fail('InvalidInput', 'principal_unknown');
      p.status = 'disabled';
      record({ ts: iso(), event: 'principal_disable', principal: id });
      return { id, status: 'disabled' };
    },
    grant_list: ({ principal } = {}) => {
      needInit();
      return { grants: grants.filter((g) => !principal || g.principal === principal).map(grantView) };
    },
    grant_create: async ({ principal, connection, ttl, max_uses, admin_passphrase }) => {
      needInit(); await wait(300);
      checkAdmin(admin_passphrase);
      const p = principals.find((x) => x.id === principal);
      if (!p || p.status !== 'active') throw fail('InvalidInput', 'principal_unknown');
      const c = connections.get(connection);
      if (!c || c.status !== 'active') throw fail('InvalidInput', 'connection_unknown');
      const m = /^(\d{1,6})([smhd]?)$/.exec(ttl ?? '');
      if (!m) throw fail('InvalidInput', 'invalid_ttl');
      const secs = Number(m[1]) * ({ s: 1, m: 60, h: 3600, d: 86400 } as Record<string, number>)[m[2] || 's']!;
      if (secs <= 0 || secs > 30 * 86400) throw fail('InvalidInput', 'invalid_ttl');
      if (max_uses !== undefined && !/^[1-9]\d{0,8}$/.test(max_uses)) throw fail('InvalidInput', 'invalid_argument', 'max_uses');
      const g: Grant = { id: 'grant_' + randFrom(12, HEX), principal, connection, expires_at: iso(Date.now() + secs * 1000), max_uses: max_uses ?? null, uses: '0', status: 'active' };
      grants.push(g); record({ ts: iso(), event: 'grant_create', principal, connection, grant: g.id });
      return { ...g };
    },
    grant_revoke: ({ id }) => {
      needInit();
      const g = grants.find((x) => x.id === id);
      if (!g) throw fail('NotFound', 'grant_not_found');
      g.status = 'revoked'; record({ ts: iso(), event: 'grant_revoke', grant: id, principal: g.principal });
      return { ...g };
    },

    // ---- terminal
    terminal_open: async ({ token_ref, as_user, on_data }) => {
      needInit();
      const item = onetime.get(token_ref);
      if (!item || item.kind !== 'token') throw fail('InvalidInput', 'token_ref_unknown');
      const out = channelOf(on_data);
      if (as_user !== undefined && !/^[a-z_][a-z0-9._-]{0,31}$/i.test(as_user)) throw fail('InvalidInput', 'invalid_user');
      if (!serve.running) throw fail('Unavailable', 'serve_not_running');
      await wait(200);
      const term = newTerminal(item.principal ?? 'agent', as_user ?? null);
      term.out = out;
      termSend(term, prompt(term.user), 150);
      return { terminal_id: term.id, suggestions: term.suggestions.slice() };
    },
    terminal_attach: async ({ terminal_id, on_data }) => {
      const term = terminals.get(terminal_id);
      if (!term) throw fail('NotFound', 'terminal_not_found');
      const out = channelOf(on_data);
      await wait(120);
      term.out = out;
      if (term.ring) out.onmessage(term.ring);
      return { terminal_id: term.id, suggestions: term.suggestions.slice() };
    },
    terminal_list: () => ({
      terminals: [...terminals.values()].map((x) => ({ terminal_id: x.id, principal: x.principal, as_user: x.asUser, alive: !x.closed })),
    }),
    terminal_write: ({ terminal_id, data }) => {
      const term = terminals.get(terminal_id);
      if (!term) throw fail('NotFound', 'terminal_not_found');
      if (typeof data !== 'string' || data.length > 65536) throw fail('InvalidInput', 'data_invalid');
      termWrite(term, data);
    },
    terminal_resize: ({ terminal_id, cols, rows }) => {
      const term = terminals.get(terminal_id);
      if (!term) throw fail('NotFound', 'terminal_not_found');
      term.cols = cols; term.rows = rows;
    },
    terminal_close: ({ terminal_id }) => {
      const term = terminals.get(terminal_id);
      if (!term) return;
      term.closed = true; term.out = null; term.timers.forEach((id) => clearTimeout(id)); terminals.delete(terminal_id);
    },
    secure_view: ({ on }) => { secureView = on === true; },

    // ---- records
    audit_tail: ({ limit }) => ({ records: audit.slice(-Math.max(0, limit)), unparseable_lines: 0 }),
    alerts: ({ limit }) => ({ alerts: alerts.slice(-Math.max(0, limit)), unparseable_lines: 0 }),
    approvals_list: () => {
      needInit();
      const list = [...approvals.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([digest, e]) => ({ digest, ...e }));
      return { approvals: list, history: approvalHistory.slice() };
    },
    approvals_approve: async ({ digest, admin_passphrase }) => {
      needInit(); await wait(300);
      checkAdmin(admin_passphrase);
      const e = approvals.get(digest);
      if (!e) throw fail('NotFound', 'approval_not_found');
      if (e.status !== 'pending') throw fail('InvalidInput', 'approval_not_pending');
      e.status = 'approved'; e.approved_at = iso();
      approvalHistory.push({ digest, ...e });
      record({ ts: iso(), event: 'approval_grant', connection: e.connection, digest, principal: e.caller, method: e.method, path: e.path });
      return { digest, ...e };
    },

    // ---- incidents
    incident_list: () => { needInit(); return { incidents: incidents.map((x) => ({ ...x })) }; },
    incident_show: ({ id }) => {
      const x = incidents.find((i) => i.id === id);
      if (!x) throw fail('NotFound', 'incident_not_found');
      return { ...x };
    },
    incident_declare: async ({ scope, principal, runtime, reason, admin_passphrase }) => {
      needInit(); await wait(400);
      if (scope === 'all') checkAdmin(admin_passphrase);
      else if (admin_passphrase) checkAdmin(admin_passphrase);
      let affected: string[];
      if (scope === 'principal') {
        if (!principal || !principals.some((p) => p.id === principal)) throw fail('InvalidInput', 'principal_unknown');
        affected = [principal];
      } else if (scope === 'runtime') {
        if (!runtime || !isValidName(runtime)) throw fail('InvalidInput', 'invalid_runtime');
        affected = principals.filter((p) => p.runtime === runtime).map((p) => p.id);
      } else if (scope === 'all') {
        affected = principals.map((p) => p.id);
      } else {
        throw fail('UsageError', 'invalid_scope');
      }
      for (const g of grants) if (affected.includes(g.principal) && g.status === 'active') g.status = 'revoked';
      for (const p of principals) if (affected.includes(p.id)) p.status = 'disabled';
      const inc: Incident = {
        id: 'inc_' + randFrom(12, HEX), status: 'open', scope, opened_at: iso(), runtime: scope === 'runtime' ? runtime ?? null : null,
        principals: affected, trigger: 'manual', rule: null, detail: reason ?? null, actions: { grants_revoked: true }, assessment: {}, notification: {},
        closed_at: null, widened_from: [],
      };
      incidents.push(inc);
      record({ ts: iso(), event: 'incident_open', incident: inc.id, scope });
      setControl({ ...control, incident_open: true, stopped: scope === 'all' ? true : control.stopped });
      return { ...inc };
    },
    incident_close: async ({ id, admin_passphrase }) => {
      needInit(); await wait(300);
      checkAdmin(admin_passphrase);
      const x = incidents.find((i) => i.id === id);
      if (!x) throw fail('NotFound', 'incident_not_found');
      if (x.status === 'closed') throw fail('InvalidInput', 'incident_already_closed');
      x.status = 'closed'; x.closed_at = iso();
      record({ ts: iso(), event: 'incident_close', incident: id });
      setControl({ ...control, incident_open: incidents.some((i) => i.status === 'open') });
      return { ...x };
    },

    // ---- backup and recovery (the native file dialogs are the core's; the mock skips them)
    backup_create: async () => {
      needInit(); await wait(500);
      record({ ts: iso(), event: 'backup' });
      return { path: '~/Desktop/zeropw-backup.zpwb', created_at: iso() };
    },
    backup_restore: async ({ admin_passphrase }) => {
      needInit(); await wait(700);
      checkAdmin(admin_passphrase);
      setControl({ ...control, restore_pending: true });
      record({ ts: iso(), event: 'restore' });
      return { restored: true, restore_pending: true };
    },
    restore_ack: async ({ admin_passphrase }) => {
      needInit(); await wait(300);
      checkAdmin(admin_passphrase);
      if (!control.restore_pending) throw fail('InvalidInput', 'restore_not_pending');
      setControl({ ...control, restore_pending: false });
      record({ ts: iso(), event: 'restore_ack' });
      return { restore_pending: false };
    },
    recover: async ({ recovery_passphrase }) => {
      needInit(); await wait(700);
      if (typeof recovery_passphrase !== 'string' || !recovery_passphrase) throw fail('AuthFailed', 'passphrase_missing');
      if (!recoveryCode || canonicalRecovery(recovery_passphrase) !== recoveryCode) throw fail('AuthFailed', 'bad_recovery_passphrase');
      record({ ts: iso(), event: 'recover' });
      return { recovered: true };
    },

    // ---- team
    team_init: () => { needInit(); return { fingerprint: fingerprint() }; },
    team_share: async ({ project, environment, name, admin_passphrase }) => {
      needInit(); await wait(500);
      checkAdmin(admin_passphrase);
      requireEnv(project, environment);
      const key = `${project}/${environment}`;
      if (teams.has(key)) throw fail('InvalidInput', 'team_env_already_shared');
      const env_id = randFrom(26, B32);
      teams.set(key, { env_id, project, environment, members: [{ fingerprint: fingerprint(), name: name ?? 'this-mac', role: 'admin', status: 'active', owner: true }], invites: [] });
      record({ ts: iso(), event: 'team_share', project, environment });
      return { env_id, project, environment, not_shared: [] };
    },
    team_members: ({ env }) => {
      needInit();
      const t = teamOf(env);
      return { env_id: t.env_id, members: t.members.map((m) => ({ ...m })) };
    },
    team_remove: async ({ env, device, admin_passphrase }) => {
      needInit(); await wait(400);
      checkAdmin(admin_passphrase);
      const t = teamOf(env);
      const m = t.members.find((x) => x.fingerprint === device);
      if (!m) throw fail('InvalidInput', 'member_unknown');
      if (m.owner) throw fail('InvalidInput', 'cannot_remove_owner');
      m.status = 'removed'; record({ ts: iso(), event: 'team_remove', device });
      return { env_id: t.env_id, fingerprint: device, status: 'removed' };
    },
    team_invite_create: async ({ env, role, name, address, admin_passphrase }) => {
      needInit(); await wait(450);
      checkAdmin(admin_passphrase);
      const t = teamOf(env);
      if (role !== 'user' && role !== 'admin') throw fail('UsageError', 'invalid_role');
      if (typeof name !== 'string' || !name.trim() || name.length > 64) throw fail('InvalidInput', 'invalid_name', 'name');
      if (!parseListen(address)) throw fail('InvalidInput', 'invalid_address');
      const secret = randFrom(488, B32);
      const now = Date.now();
      const inv: MockInvite = {
        invite_id: randFrom(32, HEX), role, name, link: true, created_at: iso(now), expires_at: iso(now + 24 * HOUR), status: 'pending',
        used_at: null, used_by: null, revoked_at: null, secret,
      };
      t.invites.push(inv);
      const link_ref = newRef();
      onetime.set(link_ref, { kind: 'link', text: `zeropw://join#${secret}` });
      record({ ts: iso(), event: 'team_invite', invite_id: inv.invite_id, role });
      return { invite_id: inv.invite_id, link_ref, expires_at: inv.expires_at, inviter: fingerprint() };
    },
    team_invites: ({ env }) => {
      needInit();
      const t = teamOf(env);
      return { env_id: t.env_id, invites: t.invites.map(inviteView) };
    },
    team_revoke_invite: ({ env, invite_id }) => {
      needInit();
      const t = teamOf(env);
      const inv = t.invites.find((i) => i.invite_id === invite_id);
      if (!inv) throw fail('NotFound', 'invite_not_found');
      if (inv.status === 'used') throw fail('InvalidInput', 'invite_already_used');
      if (inv.status !== 'revoked') { inv.status = 'revoked'; inv.revoked_at = iso(); inv.secret = ''; record({ ts: iso(), event: 'team_invite_revoke', invite_id }); }
      return { env_id: t.env_id, invite_id, status: 'revoked' };
    },
    team_invite_preview: async ({ text }) => {
      const v = typeof text === 'string' ? text.trim() : '';
      if (!isInviteLink(v)) throw fail('InvalidInput', 'invite_invalid');
      await wait(250);
      const preview = previewFor(v);
      const ref = newRef();
      onetime.set(ref, { kind: 'invite', text: v, preview });
      return { ref, preview };
    },
    team_join: async ({ ref, project, environment }) => {
      needInit();
      const item = onetime.get(ref);
      if (!item || item.kind !== 'invite' || !item.preview) throw fail('InvalidInput', 'invite_ref_unknown');
      onetime.delete(ref);
      if (item.preview.expired) throw fail('InvalidInput', 'invite_expired');
      if (project !== undefined && !isValidName(project)) throw fail('InvalidInput', 'invalid_name', 'project');
      if (environment !== undefined && !isValidName(environment)) throw fail('InvalidInput', 'invalid_name', 'environment');
      await wait(1600);
      const p = project ?? `team-${item.preview.inviter.slice(0, 8).toLowerCase()}`, e = environment ?? 'shared';
      const existing = projects.find((x) => x.name === p);
      if (existing) { if (!existing.environments.includes(e)) existing.environments.push(e); }
      else projects.push({ name: p, environments: [e], created_at: iso() });
      teams.set(`${p}/${e}`, {
        env_id: item.preview.env_id, project: p, environment: e, invites: [],
        members: [
          { fingerprint: item.preview.inviter, name: 'inviter', role: 'admin', status: 'active', owner: true },
          { fingerprint: fingerprint(), name: item.preview.name, role: item.preview.role, status: 'active', owner: false },
        ],
      });
      record({ ts: iso(), event: 'team_join', project: p });
      return { env_id: item.preview.env_id, self_fingerprint: fingerprint(), inviter_fingerprint: item.preview.inviter, project: p, environment: e };
    },

    // ---- one-time values
    onetime_show: ({ ref }) => {
      const item = onetime.get(ref);
      if (!item || item.kind === 'invite') throw fail('InvalidInput', 'onetime_unknown');
      onetime.delete(ref);
      return { text: item.text };
    },
    onetime_copy: ({ ref }) => {
      const item = onetime.get(ref);
      if (!item || item.kind === 'invite') throw fail('InvalidInput', 'onetime_unknown');
      onetime.delete(ref);                                   // the core forgets a value once it is on the clipboard
      return { copied: true, clears_in_s: 60 };
    },
    onetime_discard: ({ ref }) => { onetime.delete(ref); },
    file_pick: ({ purpose }) => {
      if (purpose !== 'secret' && purpose !== 'ssh_key' && purpose !== 'ca') throw fail('InvalidInput', 'invalid_purpose');
      const file_token = 'file_' + randFrom(16, HEX);
      const name = purpose === 'ssh_key' ? 'id_ed25519' : purpose === 'ca' ? 'ca.pem' : 'example.key';
      files.set(file_token, { purpose, name, content: `mock-${purpose}-` + randFrom(32, B32) });
      return { file_token, name };
    },
    settings_get: () => ({ ...settings }),
    settings_set: (next) => {
      if (!Number.isInteger(next.gateway_port) || next.gateway_port < 1024 || next.gateway_port > 65535) throw fail('InvalidInput', 'invalid_port', 'gateway_port');
      if (next.team_listen !== null) {
        const l = parseListen(next.team_listen);
        if (!l || l.ip === '0.0.0.0' || l.ip === '255.255.255.255' || l.port === 0) throw fail('InvalidInput', 'invalid_listen', 'team_listen');
      }
      settings = { gateway_port: next.gateway_port, team_listen: next.team_listen };
      return { ...settings };
    },
    net_interfaces: () => [{ name: 'utun4', ip: '100.64.1.7', kind: 'vpn' }, { name: 'en0', ip: '192.168.0.12', kind: 'lan' }],
  };

  return {
    async call<K extends CommandName>(name: K, input: Commands[K][0]): Promise<Commands[K][1]> {
      const h = handlers[name] as Handler<K> | undefined;
      if (!h) throw fail('UsageError', 'mock_unsupported');
      await Promise.resolve();
      return h(input);
    },
    on(name, handler) {
      let set = listeners.get(name);
      if (!set) { set = new Set(); listeners.set(name, set); }
      const h = handler as (p: unknown) => void;
      set.add(h);
      return () => { set?.delete(h); };
    },
    emit,
    inspect: () => ({
      initialized, onetime: onetime.size, terminals: terminals.size, projects: projects.map((p) => p.name), principals: principals.map((p) => p.id),
      stopped: control.stopped, secureView, secrets: [...secrets.keys()], connections: [...connections.keys()],
    }),
    dispose() {
      if (activity) clearInterval(activity);
      for (const term of terminals.values()) term.timers.forEach((id) => clearTimeout(id));
      terminals.clear(); listeners.clear();
    },
  };
}
