import { beforeEach, describe, expect, it, vi } from 'vitest';
import { call } from '../src/ipc/client';
import type { InvitePreview } from '../src/ipc/contract';
import { InvitePreviewRequests } from '../src/lib/invitePreview';
vi.mock('../src/ipc/client', () => ({ call: vi.fn() }));
const ipc = vi.mocked(call);
const preview = {} as InvitePreview;
function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((r, j) => { resolve = r; reject = j; });
  return { promise, resolve, reject };
}
beforeEach(() => ipc.mockReset());
describe('join preview ownership', () => {
  it('removes the previous actionable invite before waiting for a replacement', async () => {
    const delayed = deferred<{ ref: string; preview: InvitePreview }>();
    ipc.mockImplementationOnce(() => delayed.promise as never);
    let held: string | null = 'invite-A';
    const requests = new InvitePreviewRequests();
    const pending = requests.preview('link-B', () => { held = null; }, (r) => { held = r.ref; }, vi.fn());
    expect(held).toBeNull(); // submitting while the new preview is delayed cannot join A
    delayed.resolve({ ref: 'invite-B', preview });
    await pending;
    expect(held).toBe('invite-B');
  });
  it('discards a slow paste result after a newer deep link takes ownership', async () => {
    const delayed = deferred<{ ref: string; preview: InvitePreview }>();
    ipc.mockImplementationOnce(() => delayed.promise as never).mockResolvedValueOnce({} as never);
    const requests = new InvitePreviewRequests();
    const ready = vi.fn(), failed = vi.fn();
    const pending = requests.preview('old-paste', vi.fn(), ready, failed);
    requests.invalidate(); // deep link, close, back or submit
    delayed.resolve({ ref: 'stale-reference', preview });
    await pending;
    expect(ready).not.toHaveBeenCalled();
    expect(failed).not.toHaveBeenCalled();
    expect(ipc).toHaveBeenLastCalledWith('onetime_discard', { ref: 'stale-reference' });
  });
  it('keeps the newer preview when older responses arrive out of order', async () => {
    const delayed = deferred<{ ref: string; preview: InvitePreview }>();
    ipc.mockImplementationOnce(() => delayed.promise as never).mockResolvedValueOnce({ ref: 'new', preview } as never).mockResolvedValueOnce({} as never);
    const requests = new InvitePreviewRequests();
    const ready = vi.fn();
    const old = requests.preview('old', vi.fn(), ready, vi.fn());
    await requests.preview('new', vi.fn(), ready, vi.fn());
    delayed.resolve({ ref: 'old', preview });
    await old;
    expect(ready).toHaveBeenCalledTimes(1);
    expect(ready).toHaveBeenCalledWith({ ref: 'new', preview });
  });
  it('ignores errors from cancelled requests so they cannot clear a newer preview', async () => {
    const delayed = deferred<{ ref: string; preview: InvitePreview }>();
    ipc.mockImplementationOnce(() => delayed.promise as never).mockResolvedValueOnce({ ref: 'new', preview } as never);
    const requests = new InvitePreviewRequests();
    const ready = vi.fn(), failed = vi.fn();
    const old = requests.preview('old', vi.fn(), ready, failed);
    requests.invalidate(); // component unmount or explicit cancellation
    await requests.preview('new', vi.fn(), ready, failed);
    delayed.reject({ error: 'InvalidInput', reason: 'invite_invalid' });
    await old;
    expect(failed).not.toHaveBeenCalled();
    expect(ready).toHaveBeenCalledExactlyOnceWith({ ref: 'new', preview });
  });

});
