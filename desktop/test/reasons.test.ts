import { afterEach, describe, expect, it, vi } from 'vitest';
import { COPY, hasCopy } from '../src/copy';
import { call, toIpcError, useMockBackend } from '../src/ipc/client';
import { createMockBackend, INVITE_TTL_MS, type MockBackend } from '../src/ipc/mock';
import { finaleJoinErrorKey, invitePreviewErrorKey, isStaleRef, joinErrorKey, relayError } from '../src/lib/reasons';
import { holdSecureView, protectionOf } from '../src/ui/secure';

let backend: MockBackend | null = null;
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); });

describe('invite reason codes', () => {
  it('calls a malformed invite "not an invite link", as the CLI and core report it', () => {
    for (const r of ['invite_malformed', 'invite_missing', 'invite_too_long', 'deep_link_invalid']) expect(invitePreviewErrorKey(r)).toBe('join.err');
    expect(invitePreviewErrorKey('invite_expired')).toBe('join.err.expired');
    expect(invitePreviewErrorKey('admin_binary_missing')).toBe('join.err.check');
  });

  it('maps what the mock (like the core) answers for a corrupted link', async () => {
    backend = createMockBackend({ latency: 0 });
    useMockBackend(backend);
    const reason = await call('team_invite_preview', { text: 'zeropw://join#not-base32!' }).then(() => '', (e) => toIpcError(e).reason);
    expect(invitePreviewErrorKey(reason)).toBe('join.err');
  });

  it('tells the user to paste the link again when the preview expired in the core', () => {
    expect(isStaleRef('onetime_ref_unknown')).toBe(true);
    expect(joinErrorKey('onetime_ref_unknown')).toBe('join.err.reopen');
    expect(finaleJoinErrorKey('onetime_ref_unknown')).toBe('done.join.reopen');
    expect(finaleJoinErrorKey('invite_expired')).toBe('done.join.expired');
    expect(joinErrorKey('team_join_timeout')).toBe('join.err.failed');
  });

  it('keeps a previewed invite for an hour, long enough to make the vault first, and says so', async () => {
    vi.useFakeTimers({ now: Date.UTC(2026, 9, 15, 9, 0, 0) });
    try {
      backend = createMockBackend({ latency: 0 });
      useMockBackend(backend);
      const link = 'zeropw://join#' + 'abcdefghijklmnopqrstuvwxyz234567'.repeat(8);
      const kept = await call('team_invite_preview', { text: link });
      const dropped = await call('team_invite_preview', { text: link });
      const rec = await call('recovery_generate');
      vi.setSystemTime(Date.now() + 9 * 60_000);                 // the recovery step can take most of 10 minutes
      await call('vault_init', { admin_passphrase: 'Quiet-River-Lantern-82!', recovery: { ref: rec.ref } });
      vi.setSystemTime(Date.now() + 40 * 60_000);                // 49 minutes after the preview
      expect((await call('team_join', { ref: kept.ref, project: 'team-x', environment: 'shared' })).project).toBe('team-x');
      vi.setSystemTime(Date.now() + 12 * 60_000);                // 61 minutes: gone from the core
      const reason = await call('team_join', { ref: dropped.ref }).then(() => '', (e) => toIpcError(e).reason);
      expect(finaleJoinErrorKey(reason)).toBe('done.join.reopen');
    } finally {
      vi.useRealTimers();
    }
    expect(INVITE_TTL_MS).toBe(60 * 60_000);
    for (const k of ['toast.join.later', 'join.err.reopen', 'done.join.reopen'] as const) expect(COPY[k], k).toContain('1시간');
    expect(Object.values(COPY).join('\n')).not.toContain('10분');
  });
});

describe('relay start failures', () => {
  it('maps the core reasons and shows unknown ones as their code', () => {
    expect(relayError('serve_exited').key).toBe('relay.err.exited');
    expect(relayError('serve_start_timeout').key).toBe('relay.err.timeout');
    expect(relayError('admin_binary_missing').key).toBe('relay.err.missing');
    expect(relayError('serve_spawn_failed')).toEqual({ key: 'relay.err.other', reason: 'serve_spawn_failed' });
    expect(relayError('<b>not a code</b>').reason).toBe('unknown');
    for (const r of ['serve_exited', 'serve_start_timeout', 'admin_binary_missing', 'invalid_port', 'invalid_listen', 'listen_failed', 'x']) expect(hasCopy(relayError(r).key)).toBe(true);
  });

  it('tells a busy gateway port from a team address by the setting the core names (desktop/core/src/serve.rs listen_setting)', () => {
    expect(relayError('listen_failed', 'gateway_port')).toEqual({ key: 'relay.err.portBusy', reason: 'listen_failed' });
    expect(relayError('invalid_listen', 'team_listen').key).toBe('relay.err.team');
    expect(relayError('invalid_listen', 'gateway_port').key).toBe('relay.err.listen');
    expect(relayError('invalid_listen').key).toBe('relay.err.listen');
    for (const r of ['team_invalid_listen_address', 'team_listen_failed', 'team_address_in_use']) {
      expect(relayError(r, 'team_listen').key, r).toBe('relay.err.team');
      expect(relayError(r).key, r).toBe('relay.err.team');       // an older core without the detail
    }
    expect(relayError('serve_exited', undefined).key).toBe('relay.err.exited');
    expect(COPY['relay.err.portBusy']).toContain('중계기 포트');
    expect(COPY['relay.err.portBusy']).not.toContain('다른 기기 접속');
  });
});

describe('screen-capture protection answers', () => {
  it('reads both answer shapes of secure_view', () => {
    expect(protectionOf(undefined)).toBeNull();
    expect(protectionOf(null)).toBeNull();
    expect(protectionOf({ protected: true })).toBe(true);
    expect(protectionOf({ protected: false })).toBe(false);
    expect(protectionOf({ protected: 'yes' })).toBeNull();
  });

  it('reports a protection the platform cannot give, without blocking the hold', async () => {
    for (const [guard, want] of [['void', null], ['protected', true], ['unprotected', false]] as const) {
      backend?.dispose();
      backend = createMockBackend({ latency: 0, screenGuard: guard });
      useMockBackend(backend);
      const h = holdSecureView();
      expect(await h.ready).toBe(want);
      h.release();
      await new Promise((r) => setTimeout(r, 0));
    }
  });
});
