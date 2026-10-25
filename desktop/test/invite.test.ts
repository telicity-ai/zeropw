import { beforeEach, describe, expect, it, vi } from 'vitest';
import { call } from '../src/ipc/client';
import { shareAndInvite } from '../src/dashboard/invite';

vi.mock('../src/ipc/client', () => ({ call: vi.fn() }));
const ipc = vi.mocked(call);
const input = { env: 'demo/dev', role: 'user' as const, name: 'teammate', address: '192.168.1.2:47420', admin_passphrase: 'synthetic-only' };

beforeEach(() => ipc.mockReset());
describe('explicit share and invite confirmation', () => {
  it('reauthenticates both changes and reports committed sharing before inviting', async () => {
    const order: string[] = [];
    ipc.mockImplementation(async (command) => { order.push(command); return {} as never; });
    await shareAndInvite(input, false, () => order.push('shared'));
    expect(order).toEqual(['team_share', 'shared', 'team_invite_create']);
    expect(ipc).toHaveBeenNthCalledWith(1, 'team_share', { project: 'demo', environment: 'dev', admin_passphrase: input.admin_passphrase });
    expect(ipc).toHaveBeenNthCalledWith(2, 'team_invite_create', input);
  });
  it('does not invite when sharing fails, including failed reauthentication', async () => {
    const failure = { error: 'AuthFailed', reason: 'admin_reauth_failed' };
    ipc.mockRejectedValueOnce(failure);
    const shared = vi.fn();
    await expect(shareAndInvite(input, false, shared)).rejects.toEqual(failure);
    expect(shared).not.toHaveBeenCalled();
    expect(ipc).toHaveBeenCalledTimes(1);
  });
  it('preserves committed sharing when inviting fails and does not retry uncertain writes', async () => {
    ipc.mockResolvedValueOnce({} as never).mockRejectedValueOnce({ error: 'IpcError', reason: 'ipc_failed' });
    const shared = vi.fn();
    await expect(shareAndInvite(input, false, shared)).rejects.toMatchObject({ reason: 'ipc_failed' });
    expect(shared).toHaveBeenCalledTimes(1);
    expect(ipc).toHaveBeenCalledTimes(2);
    // A subsequent human confirmation uses the known shared state, never another share.
    ipc.mockResolvedValueOnce({} as never);
    await shareAndInvite(input, true, shared);
    expect(ipc).toHaveBeenNthCalledWith(3, 'team_invite_create', input);
  });
  it('refuses a malformed environment before any mutation', async () => {
    await expect(shareAndInvite({ ...input, env: 'invalid' }, false, vi.fn())).rejects.toMatchObject({ reason: 'invalid_name' });
    expect(ipc).not.toHaveBeenCalled();
  });
});
