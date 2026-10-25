/** Own only previews still queued in the dashboard. Once a sheet takes a reference, its
 * lifecycle owns disposal; replacing another queued link must never discard that taken ref. */
export class PendingInviteOwner {
  private pending: string | null = null;
  constructor(private readonly discard: (reference: string) => void) {}
  replace(reference: string): void {
    if (this.pending && this.pending !== reference) this.discard(this.pending);
    this.pending = reference;
  }
  take(reference: string): boolean {
    if (this.pending !== reference) return false;
    this.pending = null;
    return true;
  }
  dispose(): void {
    if (this.pending) this.discard(this.pending);
    this.pending = null;
  }
}
