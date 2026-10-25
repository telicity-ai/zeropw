import { describe, expect, it, vi } from 'vitest';
import { PendingInviteOwner } from '../src/dashboard/pendingInvite';

describe('dashboard pending invite ownership', () => {
  it('discards only a different replaced queued reference, including final disposal', () => {
    const discard = vi.fn();
    const owner = new PendingInviteOwner(discard);
    owner.replace('queued-A');
    owner.replace('queued-A');
    expect(discard).not.toHaveBeenCalled();
    owner.replace('queued-B');
    expect(discard.mock.calls).toEqual([['queued-A']]);
    expect(owner.take('queued-A')).toBe(false); // a stale transfer cannot clear newer ownership
    owner.dispose();
    owner.dispose();
    expect(discard.mock.calls).toEqual([['queued-A'], ['queued-B']]);
  });
  it('relinquishes taken refs to the sheet and never discards them on replacement or disposal', () => {
    const discard = vi.fn();
    const owner = new PendingInviteOwner(discard);
    owner.replace('taken-by-sheet');
    expect(owner.take('taken-by-sheet')).toBe(true);
    owner.dispose();
    owner.replace('new-pending');
    owner.dispose();
    expect(discard.mock.calls).toEqual([['new-pending']]);
  });
});
