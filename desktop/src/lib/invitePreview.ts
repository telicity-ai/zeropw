import { call } from '../ipc/client';
import type { InvitePreview } from '../ipc/contract';

/** A replacement clears the actionable preview synchronously. Results from older text or a
 * superseded paste never replace a newer deep link, and their core references are discarded. */
export class InvitePreviewRequests {
  private sequence = 0;
  invalidate(): void { this.sequence++; }
  async preview(text: string, clear: () => void, ready: (r: { ref: string; preview: InvitePreview }) => void, failed: (e: unknown) => void): Promise<void> {
    const request = ++this.sequence;
    clear();
    try {
      const result = await call('team_invite_preview', { text });
      if (request !== this.sequence) {
        await call('onetime_discard', { ref: result.ref }).catch(() => undefined);
        return;
      }
      ready(result);
    } catch (e) {
      if (request === this.sequence) failed(e);
    }
  }
}
