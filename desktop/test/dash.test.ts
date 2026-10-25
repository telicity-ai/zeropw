import { describe, expect, it } from 'vitest';
import type { ConnectionView, Control, Grant, Project, SecretView, ServeStatus, TeamEnvironment } from '../src/ipc/contract';
import { t } from '../src/copy';
import {
  addressChoices, blockText, countOf, declarableScopes, declareOutcome, defaultListenIp, defaultMethodStates, envPairs, grantState, groupSecrets, interfaceLabel, inviteFraction, isBasicUser,
  isCliPath, isHeaderName, isHostKey, isPlainText, isSshHost, isSshUser, keyChoices, lineText, liveGrants, methodsPayload, msLeft,
  newRecordCount, nextMethodState, olderVersionCount, openIncident, parseListen, parseMaxUses, parsePathPrefixes, parsePort, pendingApprovals, publicKeyOf,
  recordSig, relayBlocked, relayPill, relayState, runtimeStopsAll, sameControl, settingsFields, shortHash, sortedVersions, splitEnv, SSH_PROGRAM, summarizeConnection,
  teamEnvPairs, valueText, writeConsequences,
} from '../src/lib/dash';

const projects: Project[] = [
  { name: 'demo', environments: ['dev', 'staging', 'prod'], created_at: '2026-10-14T00:00:00Z' },
  { name: 'shop', environments: ['prod'], created_at: '2026-10-14T00:00:00Z' },
];
const secret = (id: string, project: string, environment: string, versions: Array<[string, string]> = [['1', 'active']]): SecretView => ({
  id, project, environment, kind: 'api_key', active_version: versions.find(([, s]) => s === 'active')?.[0] ?? null,
  versions: versions.map(([version, status]) => ({ version, status, created_at: '2026-10-14T00:00:00Z' })),
});

describe('projects and environments', () => {
  it('lists every pair in project order and parses keys back', () => {
    expect(envPairs(projects).map((p) => p.key)).toEqual(['demo/dev', 'demo/staging', 'demo/prod', 'shop/prod']);
    expect(splitEnv('demo/dev')).toEqual({ project: 'demo', environment: 'dev' });
    for (const bad of ['demo', 'demo/dev/x', 'Demo/dev', '/dev', 'demo/']) expect(splitEnv(bad)).toBeNull();
  });

  it('adds the team environments the projects do not list, such as one joined from another device', () => {
    const team: TeamEnvironment[] = [
      { project: 'demo', environment: 'dev', env_id: 'own' },          // shared from here: already a local pair
      { project: 'team-abcdefgh', environment: 'shared', env_id: 'joined' },
    ];
    expect(teamEnvPairs({ projects, team_environments: team }).map((p) => p.key))
      .toEqual(['demo/dev', 'demo/staging', 'demo/prod', 'shop/prod', 'team-abcdefgh/shared']);
    expect(teamEnvPairs({ projects: [], team_environments: team.slice(1) })).toEqual([{ project: 'team-abcdefgh', environment: 'shared', key: 'team-abcdefgh/shared' }]);
    // an older CLI prints no team list; a malformed entry is skipped
    expect(teamEnvPairs({ projects })).toEqual(envPairs(projects));
    expect(teamEnvPairs({ projects, team_environments: [{ project: 7, environment: 'x', env_id: 'e' } as unknown as TeamEnvironment] })).toEqual(envPairs(projects));
  });

  it('groups secrets by pair, drops empty groups and keeps pairs the project list does not know', () => {
    const groups = groupSecrets([secret('zeta', 'shop', 'prod'), secret('alpha', 'demo', 'prod'), secret('beta', 'demo', 'prod'), secret('orphan', 'gone', 'x')], projects);
    expect(groups.map((g) => g.key)).toEqual(['demo/prod', 'shop/prod', 'gone/x']);
    expect(groups[0]?.secrets.map((s) => s.id)).toEqual(['alpha', 'beta']);
    expect(groupSecrets([], projects)).toEqual([]);
  });

  // desktop E2E F9: with both versions revoked the list said "이전 버전 1개"
  it('counts every version as earlier when none is in use, and all but the one in use otherwise', () => {
    expect(olderVersionCount(secret('a', 'demo', 'dev', [['1', 'retired'], ['2', 'active']]))).toBe(1);
    expect(olderVersionCount(secret('a', 'demo', 'dev', [['1', 'revoked'], ['2', 'revoked']]))).toBe(2);
    expect(olderVersionCount(secret('a', 'demo', 'dev', [['1', 'revoked']]))).toBe(1);
    expect(olderVersionCount(secret('a', 'demo', 'dev', [['1', 'active']]))).toBe(0);
    // versions as the CLI prints them: numbers
    expect(olderVersionCount({ active_version: 3, versions: [{ version: 1 }, { version: 3 }, { version: 2 }] } as unknown as SecretView)).toBe(2);
  });

  it('sorts versions newest first by number, not text', () => {
    expect(sortedVersions(secret('a', 'demo', 'dev', [['2', 'retired'], ['10', 'active'], ['9', 'retired']])).map((v) => v.version)).toEqual(['10', '9', '2']);
  });
});

describe('HTTP connection form', () => {
  it('starts with reads allowed and writes off', () => {
    expect(methodsPayload(defaultMethodStates())).toEqual({ methods: ['GET', 'HEAD'], confirm_methods: [] });
  });

  it('cycles a write chip through approval before allowing it outright', () => {
    expect(nextMethodState('POST', 'off')).toBe('confirm');
    expect(nextMethodState('POST', 'confirm')).toBe('allow');
    expect(nextMethodState('POST', 'allow')).toBe('off');
    expect(nextMethodState('GET', 'allow')).toBe('off');
    expect(nextMethodState('GET', 'off')).toBe('allow');
  });

  it('sends approved writes as confirm methods and lists their consequences', () => {
    const st = { ...defaultMethodStates(), POST: 'confirm' as const, DELETE: 'allow' as const };
    expect(methodsPayload(st)).toEqual({ methods: ['GET', 'HEAD', 'POST', 'DELETE'], confirm_methods: ['POST'] });
    expect(writeConsequences(st)).toEqual([{ method: 'POST', confirm: true }, { method: 'DELETE', confirm: false }]);
  });

  it('parses path prefixes and refuses anything that is not a path', () => {
    expect(parsePathPrefixes('')).toEqual([]);
    expect(parsePathPrefixes(' /v1, /repos ,/v1')).toEqual(['/v1', '/repos']);
    for (const bad of ['v1', '/v1?x=1', '/a b', '/v1#x', 'https://x/']) expect(parsePathPrefixes(bad)).toBeNull();
  });

  it('checks header names, basic user names, CLI paths and one-line text', () => {
    expect(isHeaderName('X-Api-Key')).toBe(true);
    for (const bad of ['', 'X Api', 'X_Api', 'a'.repeat(65), 'X:Y']) expect(isHeaderName(bad)).toBe(false);
    expect(isBasicUser('deploy')).toBe(true);
    for (const bad of ['', 'a:b', 'a\nb']) expect(isBasicUser(bad)).toBe(false);
    expect(isCliPath('/usr/local/bin/gh')).toBe(true);
    for (const bad of ['gh', './gh', '/x\n']) expect(isCliPath(bad)).toBe(false);
    expect(isPlainText('rotated after a leak')).toBe(true);
    expect(isPlainText('two\nlines')).toBe(false);
    expect(isPlainText('x'.repeat(201))).toBe(false);
  });
});

describe('SSH connection form', () => {
  it('accepts lower-case host names and IPv4 literals', () => {
    for (const ok of ['git.example.com', 'host-1', '10.0.0.5']) expect(isSshHost(ok)).toBe(true);
    for (const bad of ['Git.example.com', '-host', 'host_1', 'a b', '']) expect(isSshHost(bad)).toBe(false);
  });
  it('accepts POSIX-style user names', () => {
    expect(isSshUser('git')).toBe(true);
    expect(isSshUser('_svc.deploy-1')).toBe(true);
    for (const bad of ['Git', '1git', 'a b', '']) expect(isSshUser(bad)).toBe(false);
  });
  it('accepts Ed25519 host keys only', () => {
    expect(isHostKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl')).toBe(true);
    expect(isHostKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl host comment')).toBe(true);
    for (const bad of ['ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ', 'ssh-ed25519 short', 'AAAAC3NzaC1lZDI1NTE5', '']) expect(isHostKey(bad)).toBe(false);
  });
  it('starts with the system ssh, a path the form itself accepts', () => {
    // left as it is, the field must not stop the form (desktop E2E finding F8)
    expect(SSH_PROGRAM).toBe('/usr/bin/ssh');
    expect(isCliPath(SSH_PROGRAM)).toBe(true);
  });
  it('parses ports within range', () => {
    expect(parsePort('22')).toBe(22);
    expect(parsePort('65535')).toBe(65535);
    expect(parsePort('1023', 1024)).toBeNull();
    for (const bad of ['0', '65536', '2a', '', '-1', '1.5']) expect(parsePort(bad)).toBeNull();
  });
});

describe('grants', () => {
  it('treats an empty limit as none and refuses anything but a positive integer', () => {
    expect(parseMaxUses('')).toEqual({ ok: true, value: undefined });
    expect(parseMaxUses(' 25 ')).toEqual({ ok: true, value: '25' });
    for (const bad of ['0', '-1', '1.5', 'ten', '1e3', '9999999999']) expect(parseMaxUses(bad).ok).toBe(false);
  });

  it('shows only a principal’s live grants, latest expiry first', () => {
    const now = Date.parse('2026-10-15T00:00:00Z');
    const g = (id: string, principal: string, status: string, expires: string): Grant => ({ id, principal, connection: 'c', expires_at: expires, max_uses: null, uses: '0', status });
    const list = [g('a', 'p', 'active', '2026-10-15T01:00:00Z'), g('b', 'p', 'revoked', '2026-10-15T09:00:00Z'), g('c', 'p', 'active', '2026-10-15T05:00:00Z'), g('d', 'q', 'active', '2026-10-15T09:00:00Z')];
    expect(liveGrants(list, 'p', now).map((x) => x.id)).toEqual(['c', 'a']);
  });

  it('derives expired and used-up from time and uses, since the CLI keeps the stored status `active`', () => {
    const now = Date.parse('2026-10-15T12:00:00Z');
    // counts arrive as JSON numbers from the CLI; the contract still types them as text
    const g = (expires: string | null, uses: unknown, max: unknown, status = 'active') =>
      ({ id: 'g', principal: 'p', connection: 'c', expires_at: expires, uses, max_uses: max, status }) as unknown as Grant;
    expect(grantState(g('2026-10-15T13:00:00Z', 3, null), now)).toBe('live');
    expect(grantState(g('2026-10-15T11:59:59Z', 3, null), now)).toBe('expired');
    expect(grantState(g('2026-10-15T12:00:00Z', 0, null), now)).toBe('expired');
    expect(grantState(g('2026-10-15T13:00:00Z', 5, 5), now)).toBe('used');
    expect(grantState(g('2026-10-15T13:00:00Z', '5', '5'), now)).toBe('used');
    expect(grantState(g('2026-10-15T13:00:00Z', 4, 5), now)).toBe('live');
    expect(grantState(g('2026-10-15T13:00:00Z', 1, null, 'revoked'), now)).toBe('revoked');
    // without a readable expiry the grant is shown as live rather than hidden
    expect(grantState(g(null, 0, null), now)).toBe('live');
    expect(grantState(g('soon', 0, null), now)).toBe('live');
    expect(liveGrants([g('2026-10-15T11:00:00Z', 0, null)], 'p', now)).toEqual([]);
  });

  it('reads counts as numbers or digit strings only', () => {
    expect(countOf(3)).toBe(3);
    expect(countOf(' 12 ')).toBe(12);
    for (const bad of [null, undefined, '', 'x', '1.5', Number.NaN, Infinity, {}]) expect(countOf(bad)).toBeNull();
  });
});

describe('stored keys for a connection', () => {
  const s = (id: string, kind: SecretView['kind'], environment = 'dev', active: string | null = '1'): SecretView =>
    ({ id, project: 'demo', environment, kind, active_version: active, versions: [] });
  const secrets = [s('b-key', 'api_key'), s('a-env', 'env_var'), s('pw', 'password'), s('ssh', 'ssh_private_key'), s('other', 'api_key', 'prod'), s('none', 'api_key', 'dev', null)];

  it('offers keys from the same environment that the connection type takes, with an active version', () => {
    expect(keyChoices(secrets, 'demo/dev', 'http').map((x) => x.id)).toEqual(['a-env', 'b-key', 'pw']);
    expect(keyChoices(secrets, 'demo/dev', 'ssh').map((x) => x.id)).toEqual(['ssh']);
    expect(keyChoices(secrets, 'demo/prod', 'http').map((x) => x.id)).toEqual(['other']);
    expect(keyChoices(secrets, 'demo/staging', 'http')).toEqual([]);
  });

  it('keeps the public half of a generated key from secret_put output', () => {
    expect(publicKeyOf({ public_key: 'ssh-ed25519 AAAA deploy' })).toBe('ssh-ed25519 AAAA deploy');
    expect(publicKeyOf({ id: 'x' })).toBeNull();
    expect(publicKeyOf(null)).toBeNull();
  });
});

describe('incident scope', () => {
  it('a runtime incident stops everything when no active agent runs elsewhere', () => {
    const p = (runtime: string, status = 'active') => ({ runtime, status });
    expect(runtimeStopsAll([p('user-a'), p('user-a')], 'user-a')).toBe(true);
    expect(runtimeStopsAll([p('user-a'), p('default', 'disabled')], 'user-a')).toBe(true);
    expect(runtimeStopsAll([p('user-a'), p('default')], 'user-a')).toBe(false);
    expect(runtimeStopsAll([], 'user-a')).toBe(true);
  });

  // rust/src/incident.rs `open_incident` widens an open incident only to a wider scope and returns
  // it unchanged for any other, even one naming another agent or runtime
  it('offers only scopes wider than the open incident', () => {
    expect(declarableScopes(null)).toEqual(['principal', 'runtime', 'all']);
    expect(declarableScopes('principal')).toEqual(['runtime', 'all']);
    expect(declarableScopes('runtime')).toEqual(['all']);
    expect(declarableScopes('all')).toEqual([]);
    // an unknown stored scope ranks below every scope in the core, so each one widens it
    expect(declarableScopes('weird')).toEqual(['principal', 'runtime', 'all']);
  });

  it('finds the open incident, the widest when several are open', () => {
    const i = (id: string, status: string, scope: string) => ({ id, status, scope });
    expect(openIncident([i('a', 'closed', 'all'), i('b', 'closed', 'principal')])).toBeNull();
    expect(openIncident([i('a', 'closed', 'all'), i('b', 'open', 'principal')])?.id).toBe('b');
    expect(openIncident([i('a', 'open', 'principal'), i('b', 'open', 'runtime'), i('c', 'open', 'principal')])?.id).toBe('b');
  });

  it('reads a declaration that met an open incident as no lockdown unless it widened it', () => {
    expect(declareOutcome({})).toBe('opened');
    expect(declareOutcome({ existing: false })).toBe('opened');
    expect(declareOutcome({ existing: true, widened: true })).toBe('widened');
    expect(declareOutcome({ existing: true, widened: false })).toBe('unchanged');
    expect(declareOutcome({ existing: true })).toBe('unchanged');
    expect(declareOutcome({ existing: 'yes', widened: 'yes' })).toBe('unchanged');
  });
});

describe('connection summaries (CLI output read defensively)', () => {
  const base = { id: 'x', project: 'demo', environment: 'dev', status: 'active' };
  it('shows the HTTP host, hiding the default port', () => {
    const c = { ...base, kind: 'http', http_target: { scheme: 'https', host: 'api.example.com', port: 443 }, http_auth: { mode: 'bearer' } } as ConnectionView;
    expect(summarizeConnection(c)).toEqual({ kind: 'http', host: 'api.example.com', env: 'demo/dev', auth: 'bearer', active: true, noCli: false });
    const odd = { ...c, http_target: { scheme: 'https', host: 'api.example.com', port: 8443 } } as ConnectionView;
    expect(summarizeConnection(odd).host).toBe('api.example.com:8443');
  });
  it('shows user@host for SSH', () => {
    const c = { ...base, kind: 'ssh', status: 'disabled', ssh_target: { host: 'git.example.com', port: 2222, username: 'git' } } as ConnectionView;
    expect(summarizeConnection(c)).toMatchObject({ kind: 'ssh', host: 'git@git.example.com:2222', active: false });
  });
  // an SSH connection the app made before it sent an ssh: exec refuses it (cli_not_supported)
  it('marks an SSH connection without its ssh, and only that', () => {
    const ssh = { ...base, kind: 'ssh', ssh_target: { host: 'git.example.com', port: 22, username: 'git' } };
    expect(summarizeConnection({ ...ssh, cli: null } as ConnectionView).noCli).toBe(true);
    expect(summarizeConnection(ssh as ConnectionView).noCli).toBe(true);
    expect(summarizeConnection({ ...ssh, cli: { program: SSH_PROGRAM, kind: 'ssh' } } as ConnectionView).noCli).toBe(false);
    const http = { ...base, kind: 'http', http_target: { scheme: 'https', host: 'api.example.com', port: 443 }, cli: null } as ConnectionView;
    expect(summarizeConnection(http).noCli).toBe(false);
  });
  it('does not throw on unexpected shapes', () => {
    const c = { ...base, kind: 'weird', http_target: 'nope', ssh_target: [1, 2] } as unknown as ConnectionView;
    expect(summarizeConnection(c)).toMatchObject({ kind: 'other', host: '' });
  });
});

describe('records rendered as text', () => {
  it('turns any value into one clipped line without control characters', () => {
    expect(valueText('a\nb\tc')).toBe('a b c');
    expect(valueText(200)).toBe('200');
    expect(valueText(null)).toBe('');
    expect(valueText({ a: [1, 2] })).toBe('{"a":[1,2]}');
    expect(valueText('x'.repeat(500))).toHaveLength(160);
    expect(valueText('<img src=x onerror=alert(1)>')).toBe('<img src=x onerror=alert(1)>');   // kept verbatim, shown as text
  });

  it('counts records that arrived since the last one seen', () => {
    const a = { ts: '1', event: 'a' }, b = { ts: '2', event: 'b' }, c = { ts: '3', event: 'c' };
    expect(newRecordCount(recordSig(a), [a, b, c])).toBe(2);
    expect(newRecordCount(recordSig(c), [a, b, c])).toBe(0);
    expect(newRecordCount(null, [a])).toBe(1);                       // the log was empty before
    expect(newRecordCount(recordSig({ ts: '0', event: 'old' }), [a, b])).toBe(2);   // fell out of the window
    expect(newRecordCount(recordSig(a), [])).toBe(0);
  });

  it('keeps only pending approvals with a digest', () => {
    const list = pendingApprovals([
      { digest: 'd1', caller: 'agent-1', connection: 'api', method: 'POST', path: '/v1/items', status: 'pending', created_at: 't' },
      { digest: 'd2', status: 'approved' }, { status: 'pending' }, { digest: 'd3', status: 'pending', path: { evil: true } },
    ]);
    expect(list.map((a) => a.digest)).toEqual(['d1', 'd3']);
    expect(list[1]?.path).toBe('');                               // a path that is not text is not shown as one
    expect(list[0]).toMatchObject({ target: '/v1/items', query: null, bodyBytes: null, bodyPreview: null, bodyTruncated: false });
  });

  it('shows everything an approval is bound to: full path, query, body size, type, hash and preview', () => {
    const path = '/v1/transfers/' + 'segment/'.repeat(30) + 'confirm';
    const [a] = pendingApprovals([{
      digest: 'd', status: 'pending', caller: 'agent-1', connection: 'bank', method: 'POST', path, query: 'force=true', created_at: 't',
      content_type: 'application/json', body_bytes: 31, body_sha256: 'ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
      body_preview: '{"amount":999999,\r\n"to":"x"}\u0007', body_preview_truncated: true, origin: 'https://bank.example.com:443',
    }]);
    expect(a?.path).toBe(path);                                   // not clipped at 160 characters
    expect(a?.target).toBe(`${path}?force=true`);
    expect(a?.bodyBytes).toBe(31);
    expect(a?.bodyHash).toBe('abcd ef01 2345 6789');
    expect(a?.bodyPreview).toBe('{"amount":999999,\n"to":"x"} ');  // line breaks kept, control characters gone
    expect(a?.bodyTruncated).toBe(true);
    expect(a?.contentType).toBe('application/json');
    expect(a?.origin).toBe('https://bank.example.com:443');
  });

  it('removes bidirectional overrides so one request cannot look like another', () => {
    expect(lineText('/v1/‮exe.txt')).toBe('/v1/exe.txt');
    expect(blockText('a⁦b\tc\nd')).toBe('ab\tc\nd');
    expect(lineText('x'.repeat(10_000)).length).toBe(8192);
    expect(shortHash('nothex')).toBeNull();
  });
});

describe('team helpers', () => {
  it('parses this device’s listen address', () => {
    expect(parseListen('100.64.1.7:47420')).toEqual({ ip: '100.64.1.7', port: 47420 });
    for (const bad of [null, '', '100.64.1.7', '300.1.1.1:80', 'host:80', '1.2.3.4:0', '[::1]:80']) expect(parseListen(bad)).toBeNull();
  });
  it('counts invite time down to zero', () => {
    const now = Date.parse('2026-10-15T00:00:00Z');
    expect(msLeft('2026-10-15T01:00:00Z', now)).toBe(3_600_000);
    expect(msLeft('2026-10-14T23:00:00Z', now)).toBe(0);
    expect(msLeft('not a date', now)).toBe(0);
    expect(inviteFraction('2026-10-16T00:00:00Z', now)).toBe(1);
    expect(inviteFraction('2026-10-15T12:00:00Z', now)).toBe(0.5);
  });
  it('labels interfaces', () => {
    expect(interfaceLabel({ ip: '100.64.1.7', name: 'utun4', kind: 'vpn' })).toBe('100.64.1.7 · VPN');
    expect(interfaceLabel({ ip: '10.0.0.2', name: 'bridge0', kind: 'other' })).toBe('10.0.0.2 · bridge0');
  });
  const VPN = { name: 'utun4', ip: '100.64.1.7', kind: 'vpn' as const };
  const LAN = { name: 'en0', ip: '192.168.0.145', kind: 'lan' as const };

  // desktop E2E F16: a saved 127.0.0.1 (not in the list) showed as the LAN address but stayed saved
  it('offers a saved address that is not in the list, marked, so the picker shows what is saved', () => {
    const choices = addressChoices([LAN], '127.0.0.1');
    expect(choices).toEqual([{ value: '127.0.0.1', label: `127.0.0.1 · ${t('set.listen.unlisted')}` }, { value: LAN.ip, label: '192.168.0.145 · LAN' }]);
    // a listed address, or none picked yet: only the list
    expect(addressChoices([VPN, LAN], LAN.ip).map((c) => c.value)).toEqual([VPN.ip, LAN.ip]);
    expect(addressChoices([VPN, LAN], '')).toHaveLength(2);
    expect(addressChoices([], '10.0.0.9').map((c) => c.value)).toEqual(['10.0.0.9']);
    // whatever is picked is one of the options, so choosing another changes it
    for (const [list, cur] of [[[LAN], '127.0.0.1'], [[VPN, LAN], VPN.ip], [[], '10.0.0.9']] as const) {
      expect(addressChoices(list, cur).some((c) => c.value === cur)).toBe(true);
    }
  });

  // desktop E2E F13: emptying the port field refilled it with the saved port
  it('fills the settings fields from the saved settings once and keeps them as the user left them', () => {
    const saved = { gateway_port: 47380, team_listen: '127.0.0.1:47421' };
    const first = settingsFields(null, saved, [VPN, LAN]);
    expect(first).toEqual({ port: '47380', ip: '127.0.0.1', tport: '47421' });
    expect(settingsFields({ ...first, port: '' }, saved, [VPN, LAN])).toEqual({ ...first, port: '' });
    expect(settingsFields({ ...first, port: '473', tport: '' }, { gateway_port: 48000, team_listen: null }, [LAN])).toEqual({ ...first, port: '473', tport: '' });
    // without a saved address the picker starts on the likeliest one, and an empty pick takes one later
    expect(settingsFields(null, { gateway_port: 47380, team_listen: null }, [LAN, VPN])).toEqual({ port: '47380', ip: VPN.ip, tport: '47420' });
    expect(settingsFields({ port: '', ip: '', tport: '9' }, { gateway_port: 47380, team_listen: null }, [LAN])).toEqual({ port: '', ip: LAN.ip, tport: '9' });
  });

  it('picks a VPN address first for other-device access, then the LAN', () => {
    expect(defaultListenIp([{ ip: '192.168.0.12', kind: 'lan' }, { ip: '100.64.1.7', kind: 'vpn' }])).toBe('100.64.1.7');
    expect(defaultListenIp([{ ip: '10.9.0.1', kind: 'other' }, { ip: '192.168.0.12', kind: 'lan' }])).toBe('192.168.0.12');
    expect(defaultListenIp([{ ip: '10.9.0.1', kind: 'other' }])).toBe('10.9.0.1');
    expect(defaultListenIp([])).toBe('');
  });
});

describe('relay status', () => {
  const live: ServeStatus = { running: true, url: 'http://127.0.0.1:47380', pid: 7, team_listen: null };
  const off: ServeStatus = { running: false, url: null, pid: null, team_listen: null };
  const open: Control = { stopped: false, restore_pending: false, incident_open: false };

  it('says the relay is held while a restore waits, whether or not it runs or is stopped too', () => {
    const held = { ...open, restore_pending: true };
    expect(relayState(live, held)).toBe('held');
    expect(relayState(off, held)).toBe('held');
    expect(relayState(live, { ...held, stopped: true })).toBe('held');
    expect(relayPill(live, held)).toEqual({ kind: 'held' });
    expect(relayBlocked(held)).toBe(true);
  });

  it('says stopped under a global stop, otherwise whether the relay runs', () => {
    const stopped = { ...open, stopped: true, incident_open: true };
    expect(relayState(live, stopped)).toBe('stopped');
    expect(relayPill(live, stopped)).toEqual({ kind: 'stopped' });
    expect(relayBlocked(stopped)).toBe(true);
    expect(relayState(live, open)).toBe('live');
    expect(relayPill(live, open)).toEqual({ kind: 'live', addr: '127.0.0.1:47380' });
    expect(relayState(off, open)).toBe('off');
    expect(relayPill(off, null)).toEqual({ kind: 'off' });
    // an open incident alone does not refuse requests (it revokes grants and disables agents)
    expect(relayBlocked({ ...open, incident_open: true })).toBe(false);
    expect(relayBlocked(null)).toBe(false);
  });

  it('compares stop, incident and restore states field by field', () => {
    expect(sameControl(open, { ...open })).toBe(true);
    for (const k of ['stopped', 'restore_pending', 'incident_open'] as const) expect(sameControl(open, { ...open, [k]: true })).toBe(false);
  });
});
