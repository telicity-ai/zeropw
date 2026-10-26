import { describe, expect, it } from 'vitest';
import {
  adminReady, adminRules, canonicalRecovery, containsAdmin, defaultLocalName, formatCountdown, formatFingerprint, isAccountName, isInviteLink,
  isValidName, meterCellsOn, meterLevel, parseLocalName, parseTarget, pickVerifySlots, RECOVERY_REF_TTL_MS, recoveryOwnRules, recoveryRefStale,
  runtimeFor, verifyRecoveryGroups, verifyStates,
} from '../src/lib/validators';
import { counted, FULL, JOIN_FLOW, neighbour, progressOf } from '../src/onboarding/flow';

describe('names (^[a-z0-9][a-z0-9._-]{0,63}$)', () => {
  it.each(['demo', 'a', '0', 'my-app.v2_x', 'a'.repeat(64)])('accepts %s', (v) => expect(isValidName(v)).toBe(true));
  it.each(['', 'Demo', '-x', '.x', '_x', 'a b', 'a/b', 'a'.repeat(65), 'demo\n', '데모'])('rejects %j', (v) => expect(isValidName(v)).toBe(false));
});

describe('connection target (mockup parseTarget)', () => {
  it('accepts an https origin and reports host and port', () => {
    expect(parseTarget('https://api.example.com')).toEqual({ ok: true, host: 'api.example.com', port: 443, tls: true, private: false });
    expect(parseTarget('https://api.example.com/')).toMatchObject({ ok: true, port: 443 });
    expect(parseTarget('https://api.example.com:8443')).toMatchObject({ ok: true, port: 8443 });
  });
  it('flags plain http without rejecting it', () => {
    expect(parseTarget('http://api.example.com')).toMatchObject({ ok: true, tls: false, port: 80 });
  });
  it.each([
    'api.example.com', 'ftp://example.com', 'https://api.example.com/v1', 'https://api.example.com?x=1', 'https://api.example.com#f',
    'https://user@api.example.com', 'https://user:pw@api.example.com', 'https://', ' https://api.example.com', 'https://a b.com',
  ])('rejects %j as a format error', (v) => expect(parseTarget(v)).toEqual({ ok: false, error: 'format' }));
  it.each(['http://169.254.169.254', 'http://100.100.100.200', 'http://168.63.129.16', 'http://[fd00:ec2::254]'])(
    'blocks metadata endpoint %s', (v) => expect(parseTarget(v)).toEqual({ ok: false, error: 'meta' }));
  it.each(['http://localhost:8080', 'http://127.0.0.1', 'http://10.1.2.3', 'http://192.168.0.12', 'http://172.16.0.1', 'http://172.31.255.1',
    'http://100.64.1.7', 'http://100.127.0.1', 'http://[::1]', 'http://[fd12:3456::1]', 'https://printer.local', 'https://svc.internal', 'https://nas.lan'])(
    'marks %s as private', (v) => expect(parseTarget(v)).toMatchObject({ ok: true, private: true }));
  it.each(['https://172.32.0.1', 'https://100.128.0.1', 'https://8.8.8.8', 'https://localhost.example.com'])(
    'does not mark %s as private', (v) => expect(parseTarget(v)).toMatchObject({ ok: true, private: false }));
});

describe('recovery code confirmation', () => {
  const groups = ['ABCD', 'EFGH', 'IJKL', 'MNOP', 'QRST', 'UVWX'];
  it('picks one slot from each half', () => {
    for (let a = 0; a < 256; a += 17) for (let b = 0; b < 256; b += 13) {
      const [x, y] = pickVerifySlots([a, b]);
      expect(x).toBeGreaterThanOrEqual(0); expect(x).toBeLessThan(3);
      expect(y).toBeGreaterThanOrEqual(3); expect(y).toBeLessThan(6);
    }
  });
  it('accepts the right groups in any case with outer spaces', () => {
    expect(verifyRecoveryGroups(groups, [1, 4], ['efgh', ' QRST '])).toBe(true);
  });
  it('rejects wrong, swapped or partial groups', () => {
    expect(verifyRecoveryGroups(groups, [1, 4], ['EFGH', 'QRSX'])).toBe(false);
    expect(verifyRecoveryGroups(groups, [1, 4], ['QRST', 'EFGH'])).toBe(false);
    expect(verifyRecoveryGroups(groups, [1, 4], ['EFG', 'QRST'])).toBe(false);
    expect(verifyRecoveryGroups(groups.slice(0, 5), [1, 4], ['EFGH', 'QRST'])).toBe(false);
    expect(verifyRecoveryGroups(groups, [2, 2], ['IJKL', 'IJKL'])).toBe(false);
  });
  it('joins groups into the canonical code', () => expect(canonicalRecovery(groups)).toBe('ABCD-EFGH-IJKL-MNOP-QRST-UVWX'));
  it('says per field what is wrong, so the error can sit under that field', () => {
    expect(verifyStates(groups, [1, 4], ['efgh', 'QRST'])).toEqual([null, null]);
    expect(verifyStates(groups, [1, 4], ['', 'QRSX'])).toEqual(['empty', 'wrong']);
    expect(verifyStates(groups, [1, 4], ['0BCD', ' '])).toEqual(['wrong', 'empty']);
  });
  it('makes a generated code again before the core forgets it (10 minutes)', () => {
    const t0 = 1_000_000;
    expect(recoveryRefStale(t0, t0 + 60_000)).toBe(false);
    expect(recoveryRefStale(t0, t0 + RECOVERY_REF_TTL_MS - 60_000)).toBe(false);
    expect(recoveryRefStale(t0, t0 + RECOVERY_REF_TTL_MS - 30_000)).toBe(true);
    expect(recoveryRefStale(t0, t0 + RECOVERY_REF_TTL_MS + 1)).toBe(true);
  });
});

describe('passphrase rules', () => {
  it('needs 8 characters, a match and score 3 for the admin passphrase', () => {
    expect(adminReady(adminRules('abcdefgh', 'abcdefgh', 3))).toBe(true);
    expect(adminRules('abcdefg', 'abcdefg', 4).len).toBe(false);
    expect(adminRules('abcdefgh', 'abcdefgH', 4).match).toBe(false);
    expect(adminRules('abcdefgh', 'abcdefgh', 2).strong).toBe(false);
    expect(adminRules('', '', 4)).toEqual({ len: false, match: false, strong: false });
    expect(adminRules('가나다라마바사아', '가나다라마바사아', 3).len).toBe(true);
  });
  it('needs score 4 and a different value for a chosen recovery code', () => {
    expect(recoveryOwnRules('long recovery words', 'long recovery words', 'admin pass', 4)).toEqual({ strong: true, match: true, same: false, similar: false });
    expect(recoveryOwnRules('long recovery words', 'long recovery words', 'admin pass', 3).strong).toBe(false);
    expect(recoveryOwnRules(' Admin Pass ', ' Admin Pass ', 'admin pass', 4)).toMatchObject({ strong: false, same: true });
  });
  it('refuses a chosen code that contains the admin passphrase, as the core scores it with that passphrase', () => {
    const admin = 'Quiet-River-Lantern-82!';
    // the finding's case: the UI's own score (without the admin passphrase) says 4, the core says weak
    expect(recoveryOwnRules(`${admin}-spare-copy`, `${admin}-spare-copy`, admin, 4)).toMatchObject({ strong: false, similar: true });
    expect(containsAdmin(`copy-${[...admin].reverse().join('')}`, admin)).toBe(true);
    expect(containsAdmin('QUIET-RIVER-LANTERN-82!-x', admin)).toBe(true);
    expect(containsAdmin('river lantern quiet', admin)).toBe(false);
    expect(containsAdmin('abc', 'ab')).toBe(false);              // too short to mean anything
  });
  it('maps scores to meter levels and cells', () => {
    expect([0, 1, 2, 3, 4].map(meterLevel)).toEqual([1, 1, 2, 3, 4]);
    expect([0, 2, 4].map(meterCellsOn)).toEqual([0, 12, 24]);
  });
});

describe('invite links and join names', () => {
  const body = 'a'.repeat(120);
  it.each([`zeropw://join#${body}`, `zeropw://join/#${body}`, `ZEROPW://JOIN#${body.toUpperCase()}`])('accepts %#', (v) => expect(isInviteLink(v)).toBe(true));
  it.each([`zeropw://join?x=1#${body}`, `zeropw://join#${body}#x`, `zeropw://join#${body} `, `zeropw://join#${body.slice(0, 50)}`,
    `https://join#${body}`, `zeropw://join#${body}1`, `zeropw://join#${'a'.repeat(4090)}`, `zeropw://evil@join#${body}`])(
    'rejects %#', (v) => expect(isInviteLink(v)).toBe(false));
  it('derives and parses the local project/environment', () => {
    expect(defaultLocalName('ABCDEFGHIJKL')).toBe('team-abcdefgh/shared');
    expect(parseLocalName('team-abcdefgh/shared')).toEqual({ project: 'team-abcdefgh', environment: 'shared' });
    expect(parseLocalName('team/a/b')).toBeNull();
    expect(parseLocalName('Team/shared')).toBeNull();
    expect(parseLocalName('team')).toBeNull();
  });
  it('formats fingerprints and countdowns', () => {
    expect(formatFingerprint('ABCDEFGHIJKLMNOPQRSTUVWXYZ')).toBe('ABCD EFGH IJKL MNOP');
    expect(formatCountdown((23 * 3600 + 12 * 60 + 4) * 1000 + 999)).toBe('23:12:04');
    expect(formatCountdown(-5)).toBe('00:00:00');
  });
});

describe('agents', () => {
  it('validates macOS account names and derives a valid runtime', () => {
    expect(isAccountName('agent')).toBe(true);
    expect(isAccountName('_svc.agent-1')).toBe(true);
    expect(isAccountName('1agent')).toBe(false);
    expect(isAccountName('a b')).toBe(false);
    expect(runtimeFor('other', 'Agent')).toBe('user-agent');
    expect(runtimeFor('same', 'agent')).toBe('default');
    expect(isValidName(runtimeFor('other', 'x'.repeat(40)))).toBe(true);
  });
});

describe('onboarding flow (v0.5)', () => {
  it('has no service connection step', () => {
    expect(FULL).toEqual(['admin', 'recovery', 'create', 'project']);
    expect(JOIN_FLOW).toEqual(['admin', 'recovery', 'create']);
    expect(counted(false)).not.toContain('connect');
  });
  it('steps back and forward inside the flow', () => {
    expect(neighbour('admin', false, -1)).toBe('welcome');
    expect(neighbour('project', false, -1)).toBe('create');
    expect(neighbour('project', false, 1)).toBe('done');
    expect(neighbour('create', true, 1)).toBe('done');
    expect(progressOf('recovery', false)).toEqual({ index: 1, total: 4 });
    expect(progressOf('create', true)).toEqual({ index: 2, total: 3 });
    expect(progressOf('done', false)).toBeNull();
  });
});
