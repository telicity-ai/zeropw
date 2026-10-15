// In-memory stand-in for the Tauri core, used only outside the desktop app (`npm run dev` in a
// browser, and tests). Every value here is synthetic. It follows the contract and the core's
// rules closely enough to review the onboarding and dashboard flows: one-time references,
// value-free errors and a small simulated shell for the agent terminal.
// Seeded review state (`?state=ready`): the synthetic admin passphrase is `mock-admin-pass`.

import type {
  Alert, AppError, AuditRecord, CommandName, Commands, Control, Events, InvitePreview, Principal, Project, ServeStatus, Settings,
} from './contract';
import { fnv1a, mulberry32 } from '../lib/rng';
import { isInviteLink, isValidName, MIN_PASSPHRASE_CHARS, sameAsAdmin } from '../lib/validators';

export interface MockChannel { onmessage: (data: string) => void }
export interface MockSeed {
  /** Start with a vault, a project and an agent (dashboard review). */
  initialized?: boolean;
  /** Multiplier for simulated latency; 0 resolves immediately. */
  latency?: number;
  /** Emit a synthetic audit record now and then while the relay runs. */
  activity?: boolean;
}
export interface MockBackend {
  call<K extends CommandName>(name: K, input: Commands[K][0]): Promise<Commands[K][1]>;
  on<E extends keyof Events>(name: E, handler: (payload: Events[E]) => void): () => void;
  emit<E extends keyof Events>(name: E, payload: Events[E]): void;
  /** Value-free view for tests. */
  inspect(): { initialized: boolean; onetime: number; terminals: number; projects: string[]; principals: string[]; stopped: boolean };
  dispose(): void;
}

const SEED_ADMIN = 'mock-admin-pass';
const BUNDLE = '/Applications/ZeroPW.app/Contents/MacOS';
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

const fail = (error: string, reason: string, detail?: string): AppError => (detail ? { error, reason, detail } : { error, reason });

function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}
const randFrom = (n: number, alphabet: string): string => [...randBytes(n)].map((x) => alphabet[x & (alphabet.length - 1)]).join('');
const newRef = (): string => 'ref_' + [...randBytes(16)].map((x) => x.toString(16).padStart(2, '0')).join('');
const iso = (ms = Date.now()): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

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
  if (COMMON.test(p)) { s = Math.min(s, 0.3); reason = 'common'; }
  else if (/(.)\1{2,}/.test(p) || /(.{3,})\1/.test(p)) { s = Math.min(s, 0.4); reason = 'repeat'; }
  else if (/(19|20)\d\d$/.test(p)) { s = Math.min(s, 0.45); reason = 'year'; }
  else if (n < 12) reason = 'short';
  const score = s >= 0.85 ? 4 : s >= 0.5 ? 3 : s >= 0.3 ? 2 : s >= 0.1 ? 1 : 0;
  return { score, reason };
}

// ---- a tiny shell behind the agent terminal
interface MockTerminal {
  id: string; out: MockChannel; user: string; line: string; password: string | null; cols: number; rows: number; closed: boolean;
  timers: Set<ReturnType<typeof setTimeout>>;
}

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

export function createMockBackend(seed: MockSeed = {}): MockBackend {
  const latency = seed.latency ?? 0;
  const listeners = new Map<string, Set<(p: unknown) => void>>();
  const onetime = new Map<string, { kind: 'recovery' | 'token' | 'invite'; text: string; preview?: InvitePreview }>();
  const terminals = new Map<string, MockTerminal>();
  let adminPass: string | null = null;
  let initialized = false;
  let serve: ServeStatus = { running: false, url: null, pid: null, team_listen: null };
  let control: Control = { stopped: false, restore_pending: false, incident_open: false };
  const projects: Project[] = [];
  const principals: Principal[] = [];
  const audit: AuditRecord[] = [];
  const alerts: Alert[] = [];
  let settings: Settings = { gateway_port: 47380, team_listen: null };
  let activity: ReturnType<typeof setInterval> | null = null;

  const wait = (ms: number) => new Promise<void>((r) => { if (latency > 0) setTimeout(r, ms * latency); else r(); });
  const emit = <E extends keyof Events>(name: E, payload: Events[E]) => { listeners.get(name)?.forEach((h) => h(payload)); };
  const needInit = () => { if (!initialized) throw fail('UsageError', 'not_initialized'); };
  const startServe = () => {
    serve = { running: true, url: `http://127.0.0.1:${settings.gateway_port}`, pid: 40000 + (randBytes(1)[0] ?? 0), team_listen: settings.team_listen };
    emit('serve://status', serve);
  };
  const record = (rec: AuditRecord) => { audit.push(rec); if (audit.length > 500) audit.shift(); emit('audit://records', { records: [rec] }); };

  function seedReady() {
    initialized = true;
    adminPass = SEED_ADMIN;
    startServe();
    projects.push({ name: 'demo', environments: ['dev', 'staging', 'prod'], created_at: iso(Date.now() - 86_400_000) });
    principals.push({ id: 'agent-1', status: 'active', created_at: iso(Date.now() - 80_000_000), runtime: 'user-agent' });
    alerts.push(
      { ts: iso(Date.now() - 3_600_000), alert: 'grant_expired', caller: 'agent-1', connection: 'example-api' },
      { ts: iso(Date.now() - 600_000), alert: 'policy_denied', caller: 'agent-1', connection: 'example-api', reason: 'method_not_allowed' },
    );
  }
  if (seed.initialized) seedReady();
  if (seed.activity && typeof window !== 'undefined') {
    activity = setInterval(() => {
      if (!initialized || !serve.running || control.stopped) return;
      record({ ts: iso(), event: 'proxy_request', caller: 'agent-1', connection: 'example-api', method: 'GET', status: 200 });
    }, 9000);
  }

  // ---- terminal
  const prompt = (u: string) => `\x1b[38;2;143;176;255m${u}@mac ~ %\x1b[0m `;
  function termSend(term: MockTerminal, data: string, delay = 0) {
    if (term.closed) return;
    if (latency <= 0 || delay <= 0) { term.out.onmessage(data); return; }
    const id = setTimeout(() => { term.timers.delete(id); if (!term.closed) term.out.onmessage(data); }, delay * latency);
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
      termSend(term, '{"connections":[]}\r\n', 260);
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
      if (initialized) throw fail('UsageError', 'already_initialized');
      if (typeof admin_passphrase !== 'string' || [...admin_passphrase].length < MIN_PASSPHRASE_CHARS) throw fail('InvalidInput', 'passphrase_too_short');
      if ('ref' in recovery) {
        const item = onetime.get(recovery.ref);
        if (!item || item.kind !== 'recovery') throw fail('InvalidInput', 'recovery_ref_unknown');
        onetime.delete(recovery.ref);
      } else if (typeof recovery.typed !== 'string' || [...recovery.typed].length < MIN_PASSPHRASE_CHARS) {
        throw fail('InvalidInput', 'recovery_too_short');
      } else if (sameAsAdmin(recovery.typed, admin_passphrase)) {
        throw fail('InvalidInput', 'recovery_same_as_admin');
      }
      await wait(1100);
      initialized = true;
      adminPass = admin_passphrase;
      startServe();
      record({ ts: iso(), event: 'init' });
      return { state_dir: '~/Library/Application Support/ZeroPW/state', kms_key_id: 'kms-dev-' + randFrom(8, '0123456789abcdef') };
    },
    serve_start: async () => { needInit(); await wait(300); startServe(); return serve; },
    serve_stop: () => { serve = { running: false, url: null, pid: null, team_listen: null }; emit('serve://status', serve); return serve; },
    serve_status: () => serve,
    control_get: () => { needInit(); return control; },
    stop_all: async () => {
      needInit(); await wait(250);
      control = { ...control, stopped: true }; record({ ts: iso(), event: 'stop_all' }); emit('control://changed', control); return control;
    },
    resume: async ({ admin_passphrase }) => {
      needInit(); await wait(350);
      if (!adminPass || admin_passphrase !== adminPass) throw fail('AuthFailed', 'bad_passphrase');
      control = { ...control, stopped: false }; record({ ts: iso(), event: 'resume' }); emit('control://changed', control); return control;
    },
    project_list: () => { needInit(); return { projects: projects.slice() }; },
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
    principal_list: () => { needInit(); return { principals: principals.slice() }; },
    principal_create: async ({ id, runtime }) => {
      needInit();
      if (!isValidName(id)) throw fail('InvalidInput', 'invalid_name', 'principal_id');
      if (!isValidName(runtime)) throw fail('InvalidInput', 'invalid_name', 'runtime');
      if (principals.some((p) => p.id === id)) throw fail('InvalidInput', 'principal_exists');
      await wait(250);
      principals.push({ id, status: 'active', created_at: iso(), runtime });
      const token_ref = newRef();
      onetime.set(token_ref, { kind: 'token', text: 'zpwc_' + randFrom(43, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_') });
      record({ ts: iso(), event: 'principal_create', principal: id });
      return { id, runtime, token_ref };
    },
    principal_disable: ({ id }) => {
      const p = principals.find((x) => x.id === id);
      if (!p) throw fail('InvalidInput', 'principal_unknown');
      p.status = 'disabled';
      return { id, status: 'disabled' };
    },
    terminal_open: async ({ token_ref, as_user, on_data }) => {
      needInit();
      const item = onetime.get(token_ref);
      if (!item || item.kind !== 'token') throw fail('InvalidInput', 'token_ref_unknown');
      const out = on_data as MockChannel | undefined;
      if (!out || typeof out.onmessage !== 'function') throw fail('InvalidInput', 'channel_missing');
      if (as_user !== undefined && !/^[a-z_][a-z0-9._-]{0,31}$/i.test(as_user)) throw fail('InvalidInput', 'invalid_user');
      await wait(200);
      const id = 'term_' + randFrom(10, '0123456789abcdef');
      const term: MockTerminal = { id, out, user: 'me', line: '', password: null, cols: 80, rows: 24, closed: false, timers: new Set() };
      terminals.set(id, term);
      termSend(term, prompt(term.user), 150);
      const list = `${BUNDLE}/zeropw-agent list-connections`;
      const suggestions = as_user
        ? [`sudo --preserve-env=ZEROPW_GATEWAY_URL,ZEROPW_CALLER_TOKEN,no_proxy -u ${as_user} -i`, list]
        : [list];
      return { terminal_id: id, suggestions };
    },
    terminal_write: ({ terminal_id, data }) => {
      const term = terminals.get(terminal_id);
      if (!term) throw fail('InvalidInput', 'terminal_unknown');
      if (typeof data !== 'string' || data.length > 65536) throw fail('InvalidInput', 'data_invalid');
      termWrite(term, data);
    },
    terminal_resize: ({ terminal_id, cols, rows }) => {
      const term = terminals.get(terminal_id);
      if (!term) throw fail('InvalidInput', 'terminal_unknown');
      term.cols = cols; term.rows = rows;
    },
    terminal_close: ({ terminal_id }) => {
      const term = terminals.get(terminal_id);
      if (!term) return;
      term.closed = true; term.timers.forEach((id) => clearTimeout(id)); terminals.delete(terminal_id);
    },
    audit_tail: ({ limit }) => ({ records: audit.slice(-Math.max(0, limit)), unparseable_lines: 0 }),
    alerts: ({ limit }) => ({ alerts: alerts.slice(-Math.max(0, limit)), unparseable_lines: 0 }),
    approvals_list: () => ({ approvals: [], history: [] }),
    incident_list: () => ({ incidents: [] }),
    secret_list: () => ({ secrets: [] }),
    connection_list: () => ({ connections: [] }),
    grant_list: () => ({ grants: [] }),
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
      projects.push({ name: p, environments: [e], created_at: iso() });
      record({ ts: iso(), event: 'team_join', project: p });
      return { env_id: item.preview.env_id, self_fingerprint: randFrom(26, B32).toUpperCase(), inviter_fingerprint: item.preview.inviter, project: p, environment: e };
    },
    onetime_show: ({ ref }) => {
      const item = onetime.get(ref);
      if (!item) throw fail('InvalidInput', 'onetime_unknown');
      onetime.delete(ref);
      return { text: item.text };
    },
    onetime_copy: ({ ref }) => {
      if (!onetime.has(ref)) throw fail('InvalidInput', 'onetime_unknown');
      return { copied: true, clears_in_s: 60 };
    },
    onetime_discard: ({ ref }) => { onetime.delete(ref); },
    file_pick: () => null,
    settings_get: () => settings,
    settings_set: (next) => {
      if (!Number.isInteger(next.gateway_port) || next.gateway_port < 1024 || next.gateway_port > 65535) throw fail('InvalidInput', 'port_invalid');
      settings = { ...next }; return settings;
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
    inspect: () => ({ initialized, onetime: onetime.size, terminals: terminals.size, projects: projects.map((p) => p.name), principals: principals.map((p) => p.id), stopped: control.stopped }),
    dispose() {
      if (activity) clearInterval(activity);
      for (const term of terminals.values()) term.timers.forEach((id) => clearTimeout(id));
      terminals.clear(); listeners.clear();
    },
  };
}
