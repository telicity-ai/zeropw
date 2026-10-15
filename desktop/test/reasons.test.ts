import { afterEach, describe, expect, it } from 'vitest';
import { hasCopy } from '../src/copy';
import { call, toIpcError, useMockBackend } from '../src/ipc/client';
import { createMockBackend, type MockBackend } from '../src/ipc/mock';
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
});

describe('relay start failures', () => {
  it('maps the core reasons and shows unknown ones as their code', () => {
    expect(relayError('serve_exited').key).toBe('relay.err.exited');
    expect(relayError('serve_start_timeout').key).toBe('relay.err.timeout');
    expect(relayError('admin_binary_missing').key).toBe('relay.err.missing');
    expect(relayError('serve_spawn_failed')).toEqual({ key: 'relay.err.other', reason: 'serve_spawn_failed' });
    expect(relayError('<b>not a code</b>').reason).toBe('unknown');
    for (const r of ['serve_exited', 'serve_start_timeout', 'admin_binary_missing', 'invalid_port', 'invalid_listen', 'x']) expect(hasCopy(relayError(r).key)).toBe(true);
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
