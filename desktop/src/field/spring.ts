/** Critically-damped-ish spring integrated with fixed sub-steps (port of the mockup's Spring). */
export class Spring {
  v: number;
  t: number;
  vel = 0;
  k: number;
  d: number;

  constructor(v: number, k = 90, d = 18) {
    this.v = v;
    this.t = v;
    this.k = k;
    this.d = d;
  }

  set(t: number, k?: number, d?: number): void {
    this.t = t;
    if (k) this.k = k;
    if (d) this.d = d;
  }

  snap(): void {
    this.v = this.t;
    this.vel = 0;
  }

  step(dt: number): void {
    const n = Math.max(1, Math.ceil(dt / 0.016));
    const h = dt / n;
    for (let i = 0; i < n; i++) {
      const a = (this.t - this.v) * this.k - this.vel * this.d;
      this.vel += a * h;
      this.v += this.vel * h;
    }
  }
}
