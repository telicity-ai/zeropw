import { describe, expect, it } from 'vitest';
import type { ConnectionView, Grant, Project, SecretView } from '../src/ipc/contract';
import {
  defaultMethodStates, envPairs, groupSecrets, interfaceLabel, inviteFraction, isBasicUser, isCliPath, isHeaderName, isHostKey, isPlainText,
  isSshHost, isSshUser, liveGrants, methodsPayload, msLeft, newRecordCount, nextMethodState, parseListen, parseMaxUses, parsePathPrefixes,
  parsePort, pendingApprovals, recordFields, recordSig, sortedVersions, splitEnv, summarizeConnection, valueText, writeConsequences,
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

  it('groups secrets by pair, drops empty groups and keeps pairs the project list does not know', () => {
    const groups = groupSecrets([secret('zeta', 'shop', 'prod'), secret('alpha', 'demo', 'prod'), secret('beta', 'demo', 'prod'), secret('orphan', 'gone', 'x')], projects);
    expect(groups.map((g) => g.key)).toEqual(['demo/prod', 'shop/prod', 'gone/x']);
    expect(groups[0]?.secrets.map((s) => s.id)).toEqual(['alpha', 'beta']);
    expect(groupSecrets([], projects)).toEqual([]);
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

  it('shows only a principal’s active grants, latest expiry first', () => {
    const g = (id: string, principal: string, status: string, expires: string): Grant => ({ id, principal, connection: 'c', expires_at: expires, max_uses: null, uses: '0', status });
    const list = [g('a', 'p', 'active', '2026-10-15T01:00:00Z'), g('b', 'p', 'revoked', '2026-10-15T09:00:00Z'), g('c', 'p', 'active', '2026-10-15T05:00:00Z'), g('d', 'q', 'active', '2026-10-15T09:00:00Z')];
    expect(liveGrants(list, 'p').map((x) => x.id)).toEqual(['c', 'a']);
  });
});

describe('connection summaries (CLI output read defensively)', () => {
  const base = { id: 'x', project: 'demo', environment: 'dev', status: 'active' };
  it('shows the HTTP host, hiding the default port', () => {
    const c = { ...base, kind: 'http', http_target: { scheme: 'https', host: 'api.example.com', port: 443 }, http_auth: { mode: 'bearer' } } as ConnectionView;
    expect(summarizeConnection(c)).toEqual({ kind: 'http', host: 'api.example.com', env: 'demo/dev', auth: 'bearer', active: true });
    const odd = { ...c, http_target: { scheme: 'https', host: 'api.example.com', port: 8443 } } as ConnectionView;
    expect(summarizeConnection(odd).host).toBe('api.example.com:8443');
  });
  it('shows user@host for SSH', () => {
    const c = { ...base, kind: 'ssh', status: 'disabled', ssh_target: { host: 'git.example.com', port: 2222, username: 'git' } } as ConnectionView;
    expect(summarizeConnection(c)).toMatchObject({ kind: 'ssh', host: 'git@git.example.com:2222', active: false });
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

  it('keeps every field of a record except the title and time', () => {
    const f = recordFields({ ts: '2026-10-15T10:00:00Z', event: 'proxy_request', caller: 'agent-1', status: 200, path: '/v1/<b>' });
    expect(f).toEqual({ ts: '2026-10-15T10:00:00Z', title: 'proxy_request', fields: ['caller=agent-1', 'status=200', 'path=/v1/<b>'] });
    expect(recordFields({ ts: 't', alert: 'grant_expired', caller: 'a' }, 'alert').title).toBe('grant_expired');
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
    expect(list[1]?.path).toBe('{"evil":true}');
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
});
