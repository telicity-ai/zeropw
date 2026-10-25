import { describe, expect, it } from 'vitest';
import { t } from '../src/copy';
import { recordView } from '../src/lib/records';

// The CLI's own list of events and the alerts it writes (rust/src/audit.rs), read from the source
// so a new event or alert there shows up here.
const audit = Object.values(import.meta.glob('../../rust/src/audit.rs', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)[0] ?? '';
const block = (name: string): string => audit.slice(audit.indexOf(`pub const ${name}`), audit.indexOf('];', audit.indexOf(`pub const ${name}`)));
const quoted = (text: string): string[] => [...text.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1] ?? '');
const EVENTS = quoted(block('EVENTS'));
const maybeAlert = audit.slice(audit.indexOf('fn maybe_alert'), audit.indexOf('pub fn tail'));
const ALERTS = [...new Set([...maybeAlert.matchAll(/self\.alert\(\s*"([a-z_]+)"/g)].map((m) => m[1] ?? ''))];
// fixed English details: the ones written with an alert, and the exposure and failure tables
const DETAILS = [
  ...[...maybeAlert.matchAll(/self\.alert\(\s*"[a-z_]+",\s*record,\s*"([^"]+)"/g)].map((m) => m[1] ?? ''),
  ...[...block('CREDENTIAL_EXPOSURE_REASONS').matchAll(/\(\s*"[a-z_]+",\s*"([^"]+)",?\s*\)/g)].map((m) => m[1] ?? ''),
  ...[...block('FAILURE_ALERT_REASONS').matchAll(/\(\s*"[a-z_]+",\s*"([^"]+)",?\s*\)/g)].map((m) => m[1] ?? ''),
];
const HANGUL = /[가-힣]/;

// The results and reasons the relay, the SSH signer and an agent's commands record, read the same
// way (each file's `mod tests` left out).
const sources = import.meta.glob(['../../rust/src/gateway.rs', '../../rust/src/signer.rs', '../../rust/src/tools.rs', '../../rust/src/runs.rs'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const rs = (name: string): string => {
  const text = Object.entries(sources).find(([k]) => k.endsWith(`/${name}`))?.[1] ?? '';
  const tests = text.search(/^#\[cfg\(test\)\]\r?\nmod tests\b/m);
  return tests < 0 ? text : text.slice(0, tests);
};
const all = (text: string, re: RegExp): string[] => [...text.matchAll(re)].map((m) => m[1] ?? '');
const gateway = rs('gateway.rs'), signer = rs('signer.rs'), tools = rs('tools.rs'), runs = rs('runs.rs');
const RESULTS = [...new Set([
  ...all(gateway + signer + tools + runs, /result: Some\("([a-z_]+)"\)/g),
  ...all(gateway, /result: "([a-z_]+)"/g), ...all(gateway, /self\.audit\("([a-z_]+)"/g),
  ...all(tools, /refuse_exec\(\s*ctx,\s*caller,\s*id,\s*req,\s*"([a-z_]+)"/g), ...all(tools, /Some\(\("([a-z_]+)", Error::/g),
  ...all(runs, /(?:COMPLETED|CANCELLED|BLOCKED|_) => "([a-z]+)",/g),
])];
const REASONS = [...new Set([
  ...all(signer, /safe_audit\(\s*"[a-z_]+",\s*"[a-z_]+",\s*Some\("([a-z_]+)"\)/g),
  ...all(gateway, /UpstreamFailure::(?:denied|error|blocked)\("([a-z_]+)"/g),
  ...all(gateway, /self\.refuse\(\s*\d+,\s*"([a-z_]+)"/g),
  ...all(tools, /refuse_exec\(\s*ctx,\s*caller,\s*id,\s*req,\s*"[a-z_]+",\s*"([a-z_]+)"/g),
  ...all(tools, /Error::(?:unsupported|state)\("([a-z_]+)"\)/g),
])];

// The events the administrator's CLI records with the caller `admin`: its record helpers and
// refusals (rust/src/admin_cli.rs) and the team commands (rust/src/team/membership.rs `audit`).
const adminSources = import.meta.glob(['../../rust/src/admin_cli.rs', '../../rust/src/team/membership.rs'], { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const adminCli = Object.entries(adminSources).find(([k]) => k.endsWith('/admin_cli.rs'))?.[1] ?? '';
const membership = Object.entries(adminSources).find(([k]) => k.endsWith('/membership.rs'))?.[1] ?? '';
const ADMIN_WRITTEN = [...new Set([
  ...all(adminCli, /admin_record(?:_for)?\(\s*&?ctx,\s*"([a-z_]+)"/g),
  ...all(adminCli, /refuse_cli_env\([^;]*?,\s*"([a-z_]+)"\)/g),
  ...all(adminCli + membership, /\.record\(\s*"([a-z_]+)",\s*RecordArgs \{\s*caller: Some\("admin"\)/g),
  ...all(membership, /\baudit\(\s*ctx,\s*"([a-z_]+)"/g),
])];

describe('records and alerts in plain words', () => {
  it('reads the CLI source it follows', () => {
    expect(EVENTS.length).toBeGreaterThan(60);
    expect(EVENTS).toContain('http_relay');
    expect(ALERTS).toEqual(expect.arrayContaining(['secret_reveal', 'intrusion', 'revoked_use_attempt', 'repeated_denials', 'failure', 'credential_exposure']));
    expect(DETAILS.length).toBeGreaterThanOrEqual(13);
    expect(RESULTS).toEqual(expect.arrayContaining(['ok', 'denied', 'failed', 'attempt', 'error', 'blocked', 'cancelled', 'unsupported']));
    expect(REASONS).toEqual(expect.arrayContaining(['unknown_key', 'no_session_bind', 'upstream_unreachable', 'request_in_flight', 'cli_not_supported', 'cli_program_missing']));
  });

  it('says every result in words, and every reason the relay, the SSH signer and a command record', () => {
    for (const result of RESULTS) {
      const v = recordView({ ts: 't', event: 'http_relay', result }, 'audit');
      expect(v.raw, result).toEqual([]);
      if (result !== 'ok') expect(v.meta, result).toEqual([expect.stringMatching(HANGUL)]);
    }
    for (const reason of REASONS) {
      const v = recordView({ ts: 't', event: 'ssh_sign', caller: 'agent-1', result: 'denied', reason }, 'audit');
      expect(v.raw, reason).toEqual([]);
      expect(v.meta, reason).toEqual(['agent-1', t('log.res.denied'), expect.stringMatching(HANGUL)]);
    }
  });

  it('names every event the CLI writes in Korean, with nothing left on the raw line', () => {
    for (const event of EVENTS) {
      const v = recordView({ ts: '2026-10-22T10:00:00Z', event, caller: 'admin', result: 'ok' }, 'audit');
      expect(v.title, event).not.toBe(t('log.event.other'));
      expect(v.title, event).toMatch(HANGUL);
      expect(v.title, event).not.toContain('_');
      expect(v.raw, event).toEqual([]);
    }
  });

  it('names every alert the CLI writes and drops its fixed English detail', () => {
    for (const alert of ALERTS) {
      const v = recordView({ ts: 't', alert, event: alert }, 'alert');
      expect(v.title, alert).not.toBe(t('log.alert.other'));
      expect(v.title, alert).toMatch(HANGUL);
    }
    for (const detail of DETAILS) expect(recordView({ ts: 't', alert: 'failure', detail }, 'alert').raw, detail).toEqual([]);
  });

  // desktop E2E F4: these two lines were shown as the CLI wrote them
  it('says who, the result and the reason instead of the raw fields', () => {
    const denied = recordView({ ts: 't', event: 'auth_failed', caller: 'admin', connection: null, reason: 'admin_reauth_failed', result: 'denied', policy_version: null }, 'audit');
    expect(denied).toEqual({ ts: 't', title: '인증 실패', meta: ['관리자', '거절', '관리 비밀번호 틀림'], raw: [] });
    const reveal = recordView({ ts: 't', alert: 'secret_reveal', caller: 'admin', connection: null, event: 'secret_reveal', reason: null, detail: 'administrator revealed a single secret version' }, 'alert');
    expect(reveal).toEqual({ ts: 't', title: '관리자가 키를 봤어요', meta: ['관리자'], raw: [] });
  });

  // pr69-frontend-records-a11y-1: an agent may be named `admin`, and its relay requests, signings
  // and denials carry that name as the caller; they were said to be the administrator's
  it('calls the caller admin the administrator only on records the administrator writes', () => {
    expect(ADMIN_WRITTEN).toEqual(expect.arrayContaining(['principal_create', 'grant_revoke', 'connection_create', 'auth_failed', 'team_join']));
    for (const event of ADMIN_WRITTEN) {
      const reason = event === 'auth_failed' ? 'admin_reauth_failed' : null;
      expect(recordView({ ts: 't', event, caller: 'admin', result: 'ok', reason }, 'audit').meta[0], event).toBe('관리자');
    }
    // every other event is an agent's (the relay, the signer, its commands) or has no caller;
    // the reveal is the administrator's alone
    for (const event of EVENTS.filter((e) => !ADMIN_WRITTEN.includes(e) && e !== 'secret_reveal')) {
      expect(recordView({ ts: 't', event, caller: 'admin', result: 'ok' }, 'audit').meta[0], event).toBe('admin');
    }
    expect(recordView({ ts: 't', event: 'http_relay', caller: 'admin', connection: 'example-api', result: 'denied', reason: 'grant_revoked' }, 'audit').meta)
      .toEqual(['admin', 'example-api', '거절', '회수한 권한']);
    expect(recordView({
      ts: 't', alert: 'revoked_use_attempt', caller: 'admin', connection: 'example-api', event: 'http_relay', reason: 'grant_revoked',
      detail: 'use attempted under a revoked, stale, or stopped grant',
    }, 'alert').meta).toEqual(['admin', 'example-api', 'API 중계', '회수한 권한']);
    // a disabled agent's token is refused under the agent's id (rust/src/server.rs), the
    // administrator's password under `admin`
    expect(recordView({ ts: 't', event: 'auth_failed', caller: 'admin', kind: 'caller_token', result: 'denied', reason: 'principal_disabled' }, 'audit').meta[0]).toBe('admin');
    const denials = (reason: string) => recordView({ ts: 't', alert: 'repeated_denials', caller: 'admin', event: 'auth_failed', reason, detail: '5 denials within 60s' }, 'alert');
    expect(denials('principal_disabled').meta[0]).toBe('admin');
    expect(denials('admin_reauth_failed').meta[0]).toBe('관리자');
  });

  it('keeps the agent and connection names as they are and adds the event behind an alert', () => {
    const v = recordView({
      ts: 't', alert: 'revoked_use_attempt', caller: 'agent-1', connection: 'example-api', event: 'http_relay', reason: 'grant_revoked',
      detail: 'use attempted under a revoked, stale, or stopped grant',
    }, 'alert');
    expect(v.title).toBe('막힌 권한으로 쓰려고 했어요');
    expect(v.meta).toEqual(['agent-1', 'example-api', 'API 중계', '회수한 권한']);
    expect(v.raw).toEqual([]);
  });

  it('reads the scope of an incident alert and the count of repeated denials from their fixed formats', () => {
    expect(recordView({ ts: 't', alert: 'intrusion', event: 'incident_open', reason: 'auto', detail: 'incident opened: scope=runtime reason=auto' }, 'alert'))
      .toMatchObject({ title: '사고가 열렸어요', meta: ['실행 계정 범위', '자동 감지'], raw: [] });
    expect(recordView({ ts: 't', alert: 'intrusion', event: 'incident_widen', reason: 'widen', detail: 'incident widened to scope=all' }, 'alert'))
      .toMatchObject({ title: '사고 범위가 넓어졌어요', meta: ['전체 범위'], raw: [] });
    expect(recordView({ ts: 't', alert: 'repeated_denials', caller: 'agent-1', event: 'http_relay', reason: 'path_not_allowed', detail: '5 denials within 60s' }, 'alert').meta)
      .toEqual(['agent-1', 'API 중계', '60초 안에 5번', '허용하지 않은 경로']);
    // a scope this table does not know is not read out of the text
    expect(recordView({ ts: 't', alert: 'intrusion', event: 'incident_open', detail: 'incident opened: scope=fleet reason=manual' }, 'alert').raw)
      .toEqual(['detail=incident opened: scope=fleet reason=manual']);
  });

  it('keeps unknown codes and free text on the raw line, as written', () => {
    const v = recordView({ ts: 't', event: 'brand_new_event', caller: 'agent-1', result: 'exploded', reason: 'some_new_reason', detail: 'free text', status: 200, path: '/v1/<b>' }, 'audit');
    expect(v.title).toBe(t('log.event.other'));
    expect(v.meta).toEqual(['agent-1']);
    expect(v.raw).toEqual(['event=brand_new_event', 'result=exploded', 'reason=some_new_reason', 'detail=free text', 'status=200', 'path=/v1/<b>']);
    const a = recordView({ ts: 't', alert: 'brand_new_alert', event: 'later_event', detail: 'something the CLI said' }, 'alert');
    expect(a.title).toBe(t('log.alert.other'));
    expect(a.raw).toEqual(['alert=brand_new_alert', 'event=later_event', 'detail=something the CLI said']);
  });

  it('shows the other fields of a record as before, the scope of an incident in words', () => {
    const relay = recordView({ ts: 't', action: 'GET', caller: 'agent-1', connection: 'api', event: 'http_relay', path: '/v1/items', policy_version: 3, result: 'ok', status: 200 }, 'audit');
    expect(relay).toEqual({ ts: 't', title: 'API 중계', meta: ['agent-1', 'api'], raw: ['action=GET', 'path=/v1/items', 'policy_version=3', 'status=200'] });
    const inc = recordView({ ts: 't', event: 'incident_open', incident_id: 'inc_1', reason: 'manual', result: 'ok', rule: null, runtime: null, scope: 'principal' }, 'audit');
    expect(inc).toEqual({ ts: 't', title: '사고 열림', meta: ['에이전트 범위', '직접 선언'], raw: ['incident_id=inc_1'] });
  });

  it('never takes a code for an inherited property, and renders text only', () => {
    const v = recordView({ ts: 't', event: 'constructor', reason: 'toString', caller: '<img src=x onerror=alert(1)>' }, 'audit');
    expect(v.title).toBe(t('log.event.other'));
    expect(v.meta).toEqual(['<img src=x onerror=alert(1)>']);
    expect(v.raw).toEqual(['event=constructor', 'reason=toString']);
  });
});
