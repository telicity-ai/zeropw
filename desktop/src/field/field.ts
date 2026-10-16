// Pixel field (DESIGN.md §3): a port of the approved mockup's Field engine to a class.
// Particles are splatted into a low-resolution additive buffer, tone-mapped by luminance and
// scaled up with nearest-neighbour sampling; a 4×4 downsampled copy blurred in JS is the glow.
// Every change of the sphere is driven by a product state; nothing here touches secrets.

import { Spring } from './spring';
import { clamp, mulberry32 } from '../lib/rng';

export type FieldMode =
  | 'welcome' | 'admin' | 'recovery' | 'create' | 'project' | 'connect'
  | 'agent' | 'invite' | 'join' | 'done' | 'dash';
export type SpringName = 'cx' | 'cy' | 'r' | 'coh' | 'sat' | 'bri' | 'scale' | 'spin' | 'mem' | 'peer' | 'agent' | 'svc';
export type ModeTargets = Partial<Record<Exclude<SpringName, 'bri' | 'scale'>, number>>;
export type ChipName = 'svc' | 'agent' | 'peer';
export type ConnKind = { kind: 'http' | 'ssh' };

export interface FieldChip { el: HTMLElement; label: HTMLElement }
export interface FieldDom {
  /** The window element: its size is the field size and it receives pointer events. */
  host: HTMLElement;
  field: HTMLCanvasElement;
  glow: HTMLCanvasElement;
  aura?: HTMLElement | null;
  hint?: HTMLElement | null;
  chips?: Partial<Record<ChipName, FieldChip>>;
}
export interface FieldEnv {
  raf(cb: (now: number) => void): number;
  caf(id: number): void;
  now(): number;
  dpr(): number;
  hidden(): boolean;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(id: unknown): void;
}
export interface FieldOptions {
  motion?: boolean;
  env?: Partial<FieldEnv>;
  /** Pointer-downs on these elements never start a drag of the sphere. */
  ignoreSelector?: string;
}

const GS = 4;                                  // glow cell = 4×4 field pixels
const TILT0 = 0.45;
const N = 9000, NF = 4600, D = 560, M = 520, MS = 640, RMAX = 6;
const DASH_REF_FP = 46;                        // the small sphere keeps the big one's pixel density
const WHITE = [0.93, 0.94, 1.0] as const, AZ = [0.33, 0.52, 1.0] as const, IR = [0.62, 0.40, 1.0] as const;
type Rgb = readonly [number, number, number];
const GREY: Rgb = [0.62, 0.62, 0.68];
const IGNORE_DEFAULT = 'button, input, select, textarea, label, a, summary, .card, .hero, .finale, .titlebar, .dash-main, .side-nav, .side-foot, .sheet-wrap, .scrim';

export const MODES: Record<FieldMode, Required<ModeTargets>> = {
  welcome: { cx: .50, cy: .33, r: .19, coh: .97, sat: .48, spin: .16, mem: 0, peer: 0, agent: 0, svc: 0 },
  admin:   { cx: .31, cy: .53, r: .27, coh: .3,  sat: .14, spin: .13, mem: 0, peer: 0, agent: 0, svc: 0 },
  recovery:{ cx: .31, cy: .53, r: .27, coh: 1,   sat: .55, spin: .13, mem: 0, peer: 0, agent: 0, svc: 0 },
  create:  { cx: .31, cy: .53, r: .27, coh: 1,   sat: .55, spin: .14, mem: 0, peer: 0, agent: 0, svc: 0 },
  project: { cx: .31, cy: .53, r: .26, coh: 1,   sat: .55, spin: .14, mem: 0, peer: 0, agent: 0, svc: 0 },
  connect: { cx: .33, cy: .53, r: .23, coh: 1,   sat: .6,  spin: .14, mem: 0, peer: 0, agent: 0, svc: 0 },
  agent:   { cx: .34, cy: .54, r: .22, coh: 1,   sat: .62, spin: .13, mem: 1, peer: 0, agent: 1, svc: 1 },
  invite:  { cx: .28, cy: .55, r: .19, coh: 1,   sat: .66, spin: .13, mem: .5, peer: 1, agent: 0, svc: 0 },
  join:    { cx: .28, cy: .55, r: .21, coh: .97, sat: .5,  spin: .14, mem: 0, peer: .7, agent: 0, svc: 0 },
  done:    { cx: .50, cy: .28, r: .15, coh: 1,   sat: .62, spin: .15, mem: .8, peer: 0, agent: .8, svc: .8 },
  // parked in the dashboard sidebar header; the shell owns cx/cy/r through extras
  dash:    { cx: .09, cy: .14, r: .04, coh: 1,   sat: .6,  spin: .14, mem: 1, peer: 0, agent: 0, svc: 0 },
};

interface Ripple { ox: number; oy: number; oz: number; t0: number; amp: number }
type Leg = [number, (e: number) => [number, number], Rgb, number?];

function defaultEnv(): FieldEnv {
  const g = globalThis as typeof globalThis & { devicePixelRatio?: number };
  const hasRaf = typeof g.requestAnimationFrame === 'function';
  return {
    raf: hasRaf ? (cb) => g.requestAnimationFrame(cb) : (cb) => setTimeout(() => cb(Date.now()), 16) as unknown as number,
    caf: hasRaf ? (id) => g.cancelAnimationFrame(id) : (id) => clearTimeout(id),
    now: () => (typeof performance !== 'undefined' ? performance.now() : Date.now()),
    dpr: () => g.devicePixelRatio || 1,
    hidden: () => typeof document !== 'undefined' && document.hidden,
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
  };
}

export class Field {
  private readonly env: FieldEnv;
  private readonly ignoreSelector: string;
  private dom: FieldDom | null = null;
  private gx: CanvasRenderingContext2D | null = null;
  private gg: CanvasRenderingContext2D | null = null;
  private PX = 2;                              // CSS px per field pixel, snapped to whole device pixels
  private W = 0; private H = 0; private bw = 0; private bh = 0; private gw = 0; private gh = 0;
  private img: ImageData | null = null;
  private gimg: ImageData | null = null;
  private acc = new Float32Array(0);
  private gacc = new Float32Array(0);
  private gtmp = new Float32Array(0);
  private readonly rnd = mulberry32(0x5eed1e);

  // sphere: jittered Fibonacci lattice + latitude rings at the poles + uniform random
  private readonly P = new Float32Array(N * 3);
  private readonly RAD = new Float32Array(N);
  private readonly HUE = new Float32Array(N);
  private readonly SAT = new Float32Array(N);
  private readonly SPK = new Uint8Array(N);
  private readonly PH = new Float32Array(N);
  private readonly NZ = new Float32Array(N);
  private readonly OX = new Float32Array(N);
  private readonly OY = new Float32Array(N);
  private readonly DX = new Float32Array(D);
  private readonly DY = new Float32Array(D);
  private readonly DZ = new Float32Array(D);
  private readonly DP = new Float32Array(D);
  private readonly SP = new Float32Array(M * 3);   // teammate sphere
  private readonly MEM = new Float32Array(MS * 3); // gateway shell points

  private readonly S: Record<SpringName, Spring> = {
    cx: new Spring(0.5, 26, 10), cy: new Spring(0.33, 26, 10), r: new Spring(0.19, 26, 10),
    coh: new Spring(0.95, 30, 10), sat: new Spring(0.3, 24, 10), bri: new Spring(1, 50, 12),
    scale: new Spring(0, 22, 7), spin: new Spring(0.16, 14, 8),
    mem: new Spring(0, 24, 10), peer: new Spring(0, 18, 8), agent: new Spring(0, 24, 10), svc: new Spring(0, 24, 10),
  };
  private rotY = 0.6; private rotVel = 0; private tilt = TILT0; private yaw = 0; private t = 0; private last = 0;
  private mode: FieldMode = 'welcome';
  private targets: Required<ModeTargets> = { ...MODES.welcome };
  private motion: boolean;
  private looping = false; private rafId = 0; private dragged = false; private hoverSince = 0; private dirty = false;
  private frameNo = 0;
  private stopped = false;
  private conn: ConnKind | null = null;
  private peerGhost = true;
  private readonly mouse = { x: -1e4, y: -1e4, in: false };
  private drag: { x: number; t: number } | null = null;

  // ripples: a per-frame lookup table indexed by half-chord (≈ uniform in angle)
  private readonly ripples: Ripple[] = [];
  private readonly LUT = new Float32Array(RMAX * 1024);
  private readonly RO = new Float64Array(RMAX * 3);
  private shock: { t0: number } | null = null;
  private readonly packets: number[] = [];
  private nextPacket = 0;
  private readonly timers = new Set<unknown>();

  // node chips: positions written as transforms, widths measured only when their text changes
  private readonly lastKey = new WeakMap<object, string>();
  private readonly halfW = new Map<ChipName, number>();

  constructor(opts: FieldOptions = {}) {
    this.env = { ...defaultEnv(), ...opts.env };
    this.ignoreSelector = opts.ignoreSelector ?? IGNORE_DEFAULT;
    this.motion = opts.motion ?? true;
    this.build();
  }

  private build(): void {
    const { P, RAD, HUE, SAT, SPK, PH, NZ, DX, DY, DZ, DP, SP, MEM, rnd } = this;
    const put = (i: number, x: number, y: number, z: number) => {
      const l = Math.hypot(x, y, z);
      P[i * 3] = x / l; P[i * 3 + 1] = y / l; P[i * 3 + 2] = z / l;
    };
    let i = 0;
    const ga = Math.PI * (3 - Math.sqrt(5)), sp = Math.sqrt(4 * Math.PI / NF) * 0.5;
    for (let k = 0; k < NF; k++, i++) {
      const y = 1 - 2 * (k + 0.5) / NF, r = Math.sqrt(1 - y * y), th = k * ga;
      put(i, r * Math.cos(th) + (rnd() - .5) * sp, y + (rnd() - .5) * sp, r * Math.sin(th) + (rnd() - .5) * sp);
    }
    for (let pole = -1; pole <= 1; pole += 2) for (let ring = 0; ring < 6; ring++) {
      const lat = (62 + ring * 4.4) * Math.PI / 180, cnt = 40 + 10 * ring;
      for (let k = 0; k < cnt; k++, i++) {
        const lon = (k + rnd() * .5) / cnt * 6.2832, la = lat + (rnd() - .5) * 0.0087;
        put(i, Math.cos(la) * Math.cos(lon), pole * Math.sin(la), Math.cos(la) * Math.sin(lon));
      }
    }
    for (; i < N; i++) {
      const u = rnd() * 2 - 1, th = rnd() * 6.2832, r = Math.sqrt(1 - u * u);
      put(i, r * Math.cos(th), u, r * Math.sin(th));
    }
    for (let j = 0; j < N; j++) {
      const y = P[j * 3 + 1];
      RAD[j] = rnd() < 0.07 ? 0.3 + 0.6 * Math.sqrt(rnd()) : 1 - Math.pow(rnd(), 2.4) * 0.1;
      HUE[j] = clamp(0.5 - 0.42 * y + (rnd() - 0.5) * 0.4, 0, 1);
      SAT[j] = 0.3 + 0.7 * rnd(); SPK[j] = rnd() < 0.022 ? 1 : 0;
      PH[j] = rnd() * 6.2832; NZ[j] = Math.pow(rnd(), 1.5);
    }
    for (let j = 0; j < D; j++) { DX[j] = rnd(); DY[j] = rnd(); DZ[j] = 0.15 + rnd() * 0.85; DP[j] = rnd() * 6.283; }
    for (let j = 0; j < M; j++) {
      const u = rnd() * 2 - 1, t = rnd() * 6.283, r = Math.sqrt(1 - u * u), rr = 1 - Math.pow(rnd(), 2) * 0.15;
      SP[j * 3] = r * Math.cos(t) * rr; SP[j * 3 + 1] = u * rr; SP[j * 3 + 2] = r * Math.sin(t) * rr;
    }
    for (let j = 0; j < MS; j++) {
      const u = rnd() * 2 - 1, t = rnd() * 6.283, r = Math.sqrt(1 - u * u);
      MEM[j * 3] = r * Math.cos(t); MEM[j * 3 + 1] = u; MEM[j * 3 + 2] = r * Math.sin(t);
    }
  }

  // ---------------------------------------------------------------- lifecycle

  attach(dom: FieldDom): void {
    this.detach();
    this.dom = dom;
    this.gx = dom.field.getContext('2d');
    this.gg = dom.glow.getContext('2d');
    const h = dom.host;
    h.addEventListener('pointermove', this.onMove);
    h.addEventListener('pointerleave', this.onLeave);
    h.addEventListener('pointerdown', this.onDown);
    h.addEventListener('pointerup', this.onUp);
    this.resize();
    if (!this.motion) this.snapAll();
    this.kick();
  }

  detach(): void {
    const dom = this.dom;
    if (!dom) return;
    dom.host.removeEventListener('pointermove', this.onMove);
    dom.host.removeEventListener('pointerleave', this.onLeave);
    dom.host.removeEventListener('pointerdown', this.onDown);
    dom.host.removeEventListener('pointerup', this.onUp);
    if (this.looping) this.env.caf(this.rafId);
    this.looping = false;
    for (const id of this.timers) this.env.clearTimeout(id);
    this.timers.clear();
    this.dom = null; this.gx = null; this.gg = null;
  }

  resize(): void {
    const dom = this.dom;
    if (!dom) return;
    this.W = dom.host.clientWidth; this.H = dom.host.clientHeight;
    const dpr = this.env.dpr() || 1;
    this.PX = Math.max(2, Math.round(2 * dpr)) / dpr;
    const { PX } = this;
    this.bw = Math.ceil(this.W / PX); this.bh = Math.ceil(this.H / PX);
    this.gw = Math.ceil(this.bw / GS); this.gh = Math.ceil(this.bh / GS);
    const cv = dom.field, cg = dom.glow;
    cv.width = this.bw; cv.height = this.bh; cv.style.width = this.bw * PX + 'px'; cv.style.height = this.bh * PX + 'px';
    cg.width = this.gw; cg.height = this.gh; cg.style.width = this.gw * GS * PX + 'px'; cg.style.height = this.gh * GS * PX + 'px';
    if (!this.gx || !this.gg || this.bw < 1 || this.bh < 1) { this.img = null; this.gimg = null; return; }
    this.img = this.gx.createImageData(this.bw, this.bh); this.acc = new Float32Array(this.bw * this.bh * 3);
    this.gimg = this.gg.createImageData(this.gw, this.gh);
    this.gacc = new Float32Array(this.gw * this.gh * 4); this.gtmp = new Float32Array(this.gw * this.gh * 4);
    this.measureChips();
    this.requestRender();
  }

  get motionOn(): boolean { return this.motion; }
  get currentMode(): FieldMode { return this.mode; }
  get isStopped(): boolean { return this.stopped; }

  // ---------------------------------------------------------------- state API (same as the mockup)

  setMode(m: FieldMode, extra?: ModeTargets | null): void {
    this.mode = m;
    this.targets = { ...MODES[m], ...(extra ?? {}) };
    for (const k of Object.keys(this.targets) as (keyof ModeTargets)[]) this.S[k].set(this.targets[k]);
    if (m !== 'create') { this.S.scale.set(1, 22, 7); this.S.bri.set(1); }   // never leave a partial creation contraction behind
    if (this.stopped) this.applyStopped();
    if (!this.motion) { this.snapAll(); this.requestRender(); }
    this.kick();
  }

  set(name: SpringName, v: number): void {
    this.S[name].set(v);
    if (name !== 'bri' && name !== 'scale') this.targets[name] = v;
    if (!this.motion) { this.S[name].snap(); this.requestRender(); }
  }

  setStrength(s: number): void {
    this.S.coh.set(0.25 + 0.75 * s); this.S.sat.set(0.1 + 0.6 * s);
    if (!this.motion) { this.S.coh.snap(); this.S.sat.snap(); this.requestRender(); }
  }

  ripple(amp = 0.05): void {
    if (!this.motion) return;
    const lastR = this.ripples[this.ripples.length - 1];
    if (lastR && this.t - lastR.t0 < 0.12) { lastR.amp = Math.min(0.14, lastR.amp + amp * 0.6); return; }  // coalesce fast typing
    const ox = (this.rnd() - 0.5) * 0.9, oy = (this.rnd() - 0.5) * 0.9, oz = 1, l = Math.hypot(ox, oy, oz);
    this.ripples.push({ ox: ox / l, oy: oy / l, oz: oz / l, t0: this.t, amp });
    if (this.ripples.length > RMAX) this.ripples.shift();
  }

  excite(v: number): void { if (this.motion && !this.stopped) this.S.bri.set(1 + v); }

  pulse(): void {
    if (!this.motion) return;
    this.S.coh.set(1); this.ripple(0.09); this.excite(0.4);
    this.later(() => this.excite(0), 260);
  }

  /** Vault creation: the list drives the clock; each finished item contracts the sphere. */
  createStep(k: number, n: number): void {
    if (!this.motion) return;
    const S = this.S;
    S.scale.set(1 - 0.85 * k / n, 34, 9); S.spin.set(0.3 + 1.6 * k / n, 10, 6); S.sat.set(0.9); S.bri.set(1.25, 40, 9);
    this.later(() => { if (this.motion) S.bri.set(1.05); }, 160);
    this.ripple(0.03);
  }

  /** The last item bursts the sphere with a shockwave. */
  createBurst(): void {
    const S = this.S;
    S.scale.set(1, 150, 9); S.spin.set(MODES.create.spin, 6, 5); S.bri.set(1, 20, 8); S.sat.set(MODES.create.sat);
    if (!this.motion) { this.snapAll(); this.requestRender(); return; }
    S.bri.set(1.12, 20, 8); this.later(() => S.bri.set(1), 500);
    this.shock = { t0: this.t }; this.ripple(0.12); this.ripple(0.08);
  }

  intro(): void { this.S.scale.set(1, 20, 7); if (!this.motion) { this.S.scale.snap(); this.requestRender(); } }

  setMotion(on: boolean): void {
    this.motion = on;
    if (on) { this.kick(); return; }
    this.S.bri.set(this.stopped ? 0.62 : 1);
    this.snapAll();
    this.ripples.length = 0; this.shock = null; this.packets.length = 0;
    this.requestRender();
  }

  /** Stop-all look: no spin, cooled to grey (DESIGN.md §3.2). */
  setStopped(on: boolean): void {
    if (this.stopped === on) return;
    this.stopped = on;
    if (on) { this.applyStopped(); this.packets.length = 0; }
    else {
      this.S.spin.set(this.targets.spin, 14, 8); this.S.sat.set(this.targets.sat); this.S.bri.set(1);
      if (this.motion) this.ripple(0.06);
    }
    if (!this.motion) { this.snapAll(); this.requestRender(); }
    this.kick();
  }

  setConn(c: ConnKind | null): void { this.conn = c; this.requestRender(); }
  setPeerGhost(g: boolean): void { this.peerGhost = g; this.requestRender(); }

  chipText(name: ChipName, text: string): void {
    const chip = this.dom?.chips?.[name];
    if (!chip) return;
    chip.label.textContent = text;
    this.halfW.set(name, chip.el.offsetWidth / 2);
  }

  /** Draw one frame now (used by tests and by still images). */
  renderNow(): void { this.render(); }

  // ---------------------------------------------------------------- internals

  private applyStopped(): void { this.S.spin.set(0, 10, 8); this.S.sat.set(0); this.S.bri.set(0.62); this.rotVel = 0; }

  private snapAll(): void { for (const k of Object.keys(this.S) as SpringName[]) this.S[k].snap(); }

  private later(fn: () => void, ms: number): void {
    const id = this.env.setTimeout(() => { this.timers.delete(id); fn(); }, ms);
    this.timers.add(id);
  }

  private requestRender(): void {
    if (this.motion || this.dirty || !this.dom) return;
    this.dirty = true;
    this.env.raf(() => { this.dirty = false; this.render(); });
  }

  private kick(): void {
    if (this.motion && !this.looping && this.dom) {
      this.looping = true; this.last = this.env.now(); this.rafId = this.env.raf(this.frame);
    }
  }

  private readonly frame = (now: number): void => {
    if (!this.motion || !this.dom) { this.looping = false; return; }
    this.rafId = this.env.raf(this.frame);
    if (this.env.hidden()) { this.last = now; return; }
    const dt = Math.min(0.05, (now - this.last) / 1000); this.last = now; this.t += dt;
    for (const k of Object.keys(this.S) as SpringName[]) this.S[k].step(dt);
    this.rotVel *= Math.exp(-dt * 2.0); this.rotY += (this.S.spin.v + this.rotVel) * dt;
    const { mouse } = this;
    const mxn = mouse.in ? mouse.x / this.W - 0.5 : 0, myn = mouse.in ? mouse.y / this.H - 0.5 : 0;
    this.tilt += ((TILT0 + myn * 0.35) - this.tilt) * Math.min(1, dt * 2.5);
    this.yaw += ((mxn * 0.5) - this.yaw) * Math.min(1, dt * 2.5);
    // the parked dashboard sphere is small: half the frame rate is plenty and saves the battery
    if (this.mode === 'dash' && (this.frameNo++ & 1)) return;
    this.render();
  };

  private readonly onMove = (e: PointerEvent): void => {
    const host = this.dom?.host; if (!host || !this.W) return;
    const b = host.getBoundingClientRect(), sc = b.width / this.W || 1;
    this.mouse.x = (e.clientX - b.left) / sc; this.mouse.y = (e.clientY - b.top) / sc; this.mouse.in = true;
    if (this.drag) {
      const dx = (e.clientX - this.drag.x) / sc, now = this.env.now();
      this.rotVel = clamp(dx * 0.6 / Math.max(16, now - this.drag.t), -4, 4);
      this.drag.x = e.clientX; this.drag.t = now; this.rotY += dx * 0.008; this.requestRender();
    }
  };
  private readonly onLeave = (): void => { this.mouse.in = false; this.drag = null; };
  private readonly onDown = (e: PointerEvent): void => {
    const target = e.target as Element | null;
    if (target && typeof target.closest === 'function' && target.closest(this.ignoreSelector)) return;
    this.drag = { x: e.clientX, t: this.env.now() }; this.dragged = true;
    try { this.dom?.host.setPointerCapture(e.pointerId); } catch { /* pointer already released */ }
  };
  private readonly onUp = (): void => { this.drag = null; };

  private measureChips(): void {
    const chips = this.dom?.chips; if (!chips) return;
    for (const name of Object.keys(chips) as ChipName[]) { const c = chips[name]; if (c) this.halfW.set(name, c.el.offsetWidth / 2); }
  }

  private placeChip(name: ChipName, x: number, y: number, a: number): void {
    const el = this.dom?.chips?.[name]?.el; if (!el) return;
    const op = a > 0.05 ? Math.min(1, a).toFixed(2) : '0';
    if (op === '0' && (this.lastKey.get(el) || '').endsWith(',0')) return;
    const hw = this.halfW.get(name) || 40, cardL = this.W - 44 - 468;
    const right = this.mode === 'done' || this.mode === 'welcome' ? this.W - 12 - hw : cardL - 12 - hw;
    x = Math.round(clamp(x, hw + 12, Math.max(hw + 12, right))); y = Math.round(y);
    const key = x + ',' + y + ',' + op; if (this.lastKey.get(el) === key) return; this.lastKey.set(el, key);
    el.style.transform = `translate3d(${x}px,${y}px,0) translate(-50%,-50%)`; el.style.opacity = op;
  }

  private plot(x: number, y: number, r: number, g: number, b: number): void {
    const ix = (x / this.PX) | 0, iy = (y / this.PX) | 0;
    if (ix < 0 || iy < 0 || ix >= this.bw || iy >= this.bh) return;
    const k = (iy * this.bw + ix) * 3, acc = this.acc;
    acc[k] += r; acc[k + 1] += g; acc[k + 2] += b;
  }

  private render(): void {
    const { img, gimg, gx, gg, dom } = this;
    if (!img || !gimg || !gx || !gg || !dom) return;
    const { S, P, RAD, HUE, SAT, SPK, PH, NZ, OX, OY, acc, PX, W, H, t, mouse, LUT, RO } = this;
    const motionOn = this.motion, dash = this.mode === 'dash';
    acc.fill(0);
    const R = S.r.v * H * Math.max(0.0001, S.scale.v), cX = S.cx.v * W, cY = S.cy.v * H;
    const cyR = Math.cos(this.rotY + this.yaw), syR = Math.sin(this.rotY + this.yaw), cxT = Math.cos(this.tilt), sxT = Math.sin(this.tilt);
    const tint: Rgb | null = this.stopped ? GREY : null;

    // dust
    for (let i = 0; i < D; i++) {
      const z = this.DZ[i];
      const x = ((this.DX[i] * W - this.yaw * 40 * z + t * 2.5 * z) % W + W) % W, y = ((this.DY[i] * H - (this.tilt - TILT0) * 60 * z) % H + H) % H;
      const b = (0.05 + 0.11 * (0.5 + 0.5 * Math.sin(t * 0.9 + this.DP[i]))) * z;
      this.plot(x, y, b * 0.8, b * 0.85, b);
    }

    const coh = clamp(S.coh.v, 0, 1), loose = 1 - coh, spread = 1.5 - S.coh.v;
    const satG = S.sat.v, bri = S.bri.v * (0.75 + 0.25 * coh);
    const REP = dash ? Math.min(74, R * 1.4) : 74, REP2 = REP * REP, mIn = mouse.in && !this.drag && motionOn;
    const stride = dash ? Math.max(1, Math.floor((DASH_REF_FP / Math.max(1, R / PX)) ** 2)) : 1;

    // ripple LUTs for this frame
    let nr = 0;
    const ripples = this.ripples;
    for (let q = ripples.length - 1; q >= 0; q--) if (t - ripples[q].t0 > 1.8) ripples.splice(q, 1);
    for (const rp of ripples) {
      const age = t - rp.t0, front = age * 2.3, a = rp.amp * Math.exp(-age * 1.6), base = nr * 1024;
      for (let k = 0; k < 1024; k++) { const f = 2 * Math.asin(k / 1023) - front; LUT[base + k] = a * Math.exp(-16 * f * f); }
      RO[nr * 3] = rp.ox; RO[nr * 3 + 1] = rp.oy; RO[nr * 3 + 2] = rp.oz; nr++;
    }

    const bw = this.bw, bh = this.bh;
    for (let i = 0; i < N; i += stride) {
      const j = i * 3, x = P[j], y = P[j + 1], z = P[j + 2];
      let rr = 1 + (RAD[i] - 1) * spread * 1.4;
      if (loose > 0.02) rr += loose * 0.22 * NZ[i] * (motionOn ? 0.6 + 0.4 * Math.sin(t * 1.3 + PH[i]) : 0.8);   // weak passphrase = frayed silhouette
      rr = Math.max(0.15, rr) * (1 + 0.013 * Math.sin(t * 1.15 + y * 5 + x * 2.2));
      const x1 = x * cyR + z * syR, z1 = -x * syR + z * cyR;
      const y1 = y * cxT - z1 * sxT, z2 = y * sxT + z1 * cxT;
      if (nr) {
        let disp = 0;
        for (let q = 0; q < nr; q++) { const d = x1 * RO[q * 3] + y1 * RO[q * 3 + 1] + z2 * RO[q * 3 + 2]; disp += LUT[q * 1024 + ((Math.sqrt(Math.max(0, (1 - d) * 0.5)) * 1023 + 0.5) | 0)]; }
        rr *= 1 + disp;
      }
      const persp = 1 / (1 - z2 * 0.16);
      let sx = cX + x1 * rr * R * persp, sy = cY - y1 * rr * R * persp;
      if (loose > 0.02 && motionOn) { sx += loose * 1.5 * PX * Math.sin(t * 2.1 + PH[i] * 3); sy += loose * 1.5 * PX * Math.cos(t * 1.9 + PH[i] * 2); }
      if (mIn) {
        const dx = sx - mouse.x, dy = sy - mouse.y, d2 = dx * dx + dy * dy;
        if (d2 < REP2) { const d = Math.sqrt(d2) + 0.001, f = 1 - d / REP, p = f * f * (dash ? 6 : 20); OX[i] += (dx / d * p - OX[i]) * 0.22; OY[i] += (dy / d * p - OY[i]) * 0.22; }
        else { OX[i] *= 0.9; OY[i] *= 0.9; }
      } else if (OX[i] !== 0) { OX[i] *= 0.9; OY[i] *= 0.9; }
      sx += OX[i]; sy += OY[i];
      const ix = (sx / PX) | 0, iy = (sy / PX) | 0;
      if (ix < 0 || iy < 0 || ix >= bw || iy >= bh) continue;
      const depth = (z2 + 1) * 0.5, rim = 1 - Math.abs(z2);
      let b = (0.11 + 0.89 * Math.pow(depth, 2.6) + 0.22 * rim * rim * rim * rim) * bri;
      if (SPK[i]) b *= 1.9;
      const m = Math.min(1, 1.4 * satG * SAT[i] * (0.75 + 0.6 * (1 - depth)));
      const h = HUE[i] + (1 - HUE[i]) * 0.5 * (1 - depth);                // back hemisphere leans iris
      const tr = AZ[0] + (IR[0] - AZ[0]) * h, tg = AZ[1] + (IR[1] - AZ[1]) * h, tb = AZ[2] + (IR[2] - AZ[2]) * h;
      const base = tint ?? WHITE;
      const k = (iy * bw + ix) * 3;
      acc[k] += (base[0] + (tr - base[0]) * m) * b * 0.62;
      acc[k + 1] += (base[1] + (tg - base[1]) * m) * b * 0.62;
      acc[k + 2] += (base[2] + (tb - base[2]) * m) * b * 0.62;
    }

    // creation shockwave
    if (this.shock) {
      const age = t - this.shock.t0;
      if (age > 1.4) this.shock = null;
      else {
        const rad = R * (1.02 + age * 1.5), a = Math.pow(1 - age / 1.4, 2) * 0.9;
        for (let q = 0; q < 640; q++) { const th = q / 640 * 6.283, jj = 1 + Math.sin(q * 12.9898) * 0.01; this.plot(cX + Math.cos(th) * rad * jj, cY + Math.sin(th) * rad * jj, a * IR[0], a * IR[1], a * IR[2]); }
      }
    }

    // gateway: a glass shell around the vault, rim-weighted so it reads as a boundary
    const mem = S.mem.v, MR = 1.24, MEM = this.MEM, shellCol: Rgb = tint ?? AZ;
    if (mem > 0.01) {
      const mstride = dash ? Math.max(1, Math.floor(stride / 3)) : 1;
      for (let i = 0; i < MS; i += mstride) {
        const j = i * 3, x = MEM[j], y = MEM[j + 1], z = MEM[j + 2];
        const x1 = x * cyR + z * syR, z1 = -x * syR + z * cyR, y1 = y * cxT - z1 * sxT, z2 = y * sxT + z1 * cxT;
        const rim = 1 - Math.abs(z2), a = mem * (0.08 + 0.75 * rim * rim * rim) * (z2 > 0 ? 1 : 0.6) * (this.stopped ? 0.5 : 1);
        const persp = 1 / (1 - z2 * 0.16);
        this.plot(cX + x1 * MR * R * persp, cY - y1 * MR * R * persp, a * shellCol[0], a * shellCol[1], a * shellCol[2]);
      }
    }

    // service and agent nodes on the free left side
    // colours: azure = agent traffic (no secret) · iris = authenticated leg (credential/signature) · white = response
    const sv = S.svc.v, ag = S.agent.v;
    const svA = 3.95, agA = 2.7, ND = 1.75;
    const svX = cX + Math.cos(svA) * R * ND, svY = cY + Math.sin(svA) * R * ND, agX = cX + Math.cos(agA) * R * ND, agY = cY + Math.sin(agA) * R * ND;
    const node = (x: number, y: number, v: number, col: Rgb, ring: boolean) => {
      for (let a = -3; a <= 3; a++) for (let b2 = -3; b2 <= 3; b2++) {
        const edge = ring ? Math.abs(Math.hypot(a, b2) - 3) < 0.6 : Math.max(Math.abs(a), Math.abs(b2)) === 3, core = Math.abs(a) <= 1 && Math.abs(b2) <= 1;
        if (edge || core) { const vv = (edge ? 0.45 : 1) * v; this.plot(x + a * PX, y + b2 * PX, vv * col[0], vv * col[1], vv * col[2]); }
      }
    };
    if (sv > 0.01) node(svX, svY, sv, WHITE, true);
    if (ag > 0.01) node(agX, agY, ag, AZ, false);
    if (ag > 0.01 && sv > 0.01 && this.conn && !this.stopped) {
      const mR = R * MR, aA = agA, bA = svA, ssh = this.conn.kind === 'ssh';
      const Ax = cX + Math.cos(aA) * mR, Ay = cY + Math.sin(aA) * mR, Bx = cX + Math.cos(bA) * mR, By = cY + Math.sin(bA) * mR;
      const lerp = (x0: number, y0: number, x1: number, y1: number, e: number): [number, number] => [x0 + (x1 - x0) * e, y0 + (y1 - y0) * e];
      const arc = (a0: number, a1: number, e: number): [number, number] => { const th = a0 + (a1 - a0) * e; return [cX + Math.cos(th) * mR, cY + Math.sin(th) * mR]; };
      // each leg: [duration, (e) => [x, y], colour, flash]
      const LEGS: Leg[] = ssh ? [
        [0.55, e => lerp(agX, agY, svX, svY, e), AZ],             // ssh client → server
        [0.35, e => lerp(cX, cY, agX, agY, e), IR, 1],            // signer answers through the socket: a signature, never the key
        [0.5, e => lerp(agX, agY, svX, svY, e), IR],              // authenticated
        [0.55, e => lerp(svX, svY, agX, agY, e), WHITE],          // session output
      ] : [
        [0.5, e => lerp(agX, agY, Ax, Ay, e * e), AZ],            // request with a handle, no credential
        [0.12, () => [Ax, Ay], WHITE, 1],                         // gateway checks policy
        [0.45, e => arc(aA, bA, e), AZ],                          // travels the shell, never the core
        [0.45, e => lerp(Bx, By, svX, svY, e), IR],               // credential attached only on this leg
        [0.4, e => lerp(svX, svY, Bx, By, e), WHITE],             // response
        [0.4, e => arc(bA, aA, e), WHITE],                        // reflection check on the shell
        [0.45, e => lerp(Ax, Ay, agX, agY, 1 - (1 - e) * (1 - e)), WHITE],
      ];
      const T = LEGS.reduce((p, l) => p + l[0], 0);
      const pos = (u: number): [number, number, Rgb, number] => {
        let s = u;
        for (const L of LEGS) { if (s < L[0]) { const e = s / L[0], p = L[1](e); return [p[0], p[1], L[2], L[3] ? 1 - e : 0]; } s -= L[0]; }
        const L = LEGS[LEGS.length - 1], p = L[1](1); return [p[0], p[1], L[2], 0];
      };
      if (motionOn) {
        if (t > this.nextPacket) { this.packets.push(t); this.nextPacket = t + 0.9 + this.rnd() * 0.5; }
        const v = 1.1 * Math.min(ag, sv);
        for (let q = this.packets.length - 1; q >= 0; q--) {
          const u = t - this.packets[q]; if (u > T) { this.packets.splice(q, 1); continue; }
          for (let tr = 0; tr < 6; tr++) {
            const p = pos(Math.max(0, u - tr * 0.022)), vv = v * (1 - tr / 6);
            this.plot(p[0], p[1], vv * p[2][0], vv * p[2][1], vv * p[2][2]);
            if (tr === 0 && p[3] > 0) for (let s2 = 0; s2 < 16; s2++) { const th = s2 / 16 * 6.283, rr2 = 4 + 6 * (1 - p[3]); this.plot(p[0] + Math.cos(th) * rr2, p[1] + Math.sin(th) * rr2, p[3], p[3], p[3]); }
          }
        }
      } else {
        // still image: the route as a dotted path
        const v = 0.55 * Math.min(ag, sv);
        for (let s = 0; s < 120; s++) { const p = pos(s / 120 * T * (ssh ? 0.6 : 0.55)); if (s % 3 === 0) this.plot(p[0], p[1], v * p[2][0], v * p[2][1], v * p[2][2]); }
      }
    }
    this.placeChip('svc', svX, svY - 22, sv);
    this.placeChip('agent', agX, agY + 22, ag);

    // a teammate's device on an inclined orbit sized to the free space; a rim-only ghost until it joins
    const pe = S.peer.v;
    let peX = 0, peY = 0, pr = 0, vis = 0;
    if (pe > 0.01) {
      const cardL = W - 44 - 468, pr0 = R * 0.15;
      const roomR = (this.mode === 'done' ? W - 16 : cardL - 24) - cX - pr0, roomL = cX - pr0 - 16;
      const ampX = Math.max(R * 0.6, Math.min(R * 1.6, roomR, roomL));
      const a = t * 0.33 + 0.6, oz = Math.sin(a), dz = (1 + oz) / 2;
      const ox = Math.cos(a) * ampX, oy = oz * R * 0.5 - R * 0.2;
      peX = cX + ox; peY = cY + oy; pr = pr0 * pe * (0.8 + 0.3 * dz);
      const occl = oz < 0 ? clamp((R * 1.05 - Math.hypot(ox, oy)) / (R * 0.25), 0, 1) : 0;
      vis = pe * (0.5 + 0.5 * dz) * (1 - 0.7 * occl);
      const c2 = Math.cos(t * 1.4), s2 = Math.sin(t * 1.4), SPa = this.SP;
      for (let i = 0; i < M; i++) {
        const j = i * 3, x = SPa[j], y = SPa[j + 1], z = SPa[j + 2];
        const x1 = x * c2 + z * s2, z1 = -x * s2 + z * c2;
        if (this.peerGhost && Math.abs(z1) > 0.35) continue;
        const d = (z1 + 1) * 0.5, v = (this.peerGhost ? 0.5 : 0.12 + 0.88 * d * d) * vis * 0.85;
        this.plot(peX + x1 * pr, peY - y * pr, v * (0.75 + 0.25 * IR[0]), v * (0.7 + 0.3 * IR[1]), v);
      }
      const Ld = Math.hypot(ox, oy), ux = ox / Ld, uy = oy / Ld, from = R * 1.05, to = Ld - pr * 1.3, la = this.peerGhost ? 0.12 : 0.55;
      if (to > from) for (let s = 0; s < 46; s++) { const f = s / 46, dp = from + (to - from) * f, on = ((f * 8 - t * 1.4) % 1 + 1) % 1 < 0.45, v = (on ? la : 0.08) * vis; this.plot(cX + ux * dp, cY + uy * dp, v * IR[0], v * IR[1], v * IR[2]); }
    }
    this.placeChip('peer', peX, peY - pr - 18, vis * 1.4);

    // luminance tone-map (keeps hue) and an exact 4×4 premultiplied downsample (rgb + coverage) for the glow
    const d = img.data, gw = this.gw, gh = this.gh, gacc = this.gacc, gtmp = this.gtmp;
    gacc.fill(0);
    for (let iy = 0, p = 0; iy < bh; iy++) {
      const grow = ((iy / GS) | 0) * gw;
      for (let ix = 0; ix < bw; ix++, p++) {
        const k = p * 3, o = p * 4, L = Math.max(acc[k], acc[k + 1], acc[k + 2]);
        if (L < 0.0027) { d[o + 3] = 0; continue; }
        const f = 1 - Math.exp(-L * 1.5), inv = 1 / L;
        d[o] = acc[k] * inv * 255; d[o + 1] = acc[k + 1] * inv * 255; d[o + 2] = acc[k + 2] * inv * 255; d[o + 3] = f * 255;
        const gk = (grow + ((ix / GS) | 0)) * 4, w = f * inv;
        gacc[gk] += acc[k] * w; gacc[gk + 1] += acc[k + 1] * w; gacc[gk + 2] += acc[k + 2] * w; gacc[gk + 3] += f;
      }
    }
    gx.putImageData(img, 0, 0);
    // glow: 4 separable [1,1,1]/3 passes over rgb + coverage, then unpremultiply, brighten ×1.5, saturate ×1.4
    const row = gw * 4;
    for (let pass = 0; pass < 4; pass++) {
      for (let y = 0; y < gh; y++) for (let x = 0; x < gw; x++) { const i0 = (y * gw + x) * 4, l = x > 0 ? i0 - 4 : i0, r = x < gw - 1 ? i0 + 4 : i0; for (let c = 0; c < 4; c++) gtmp[i0 + c] = (gacc[l + c] + gacc[i0 + c] + gacc[r + c]) / 3; }
      for (let y = 0; y < gh; y++) for (let x = 0; x < gw; x++) { const i0 = (y * gw + x) * 4, u = y > 0 ? i0 - row : i0, dn = y < gh - 1 ? i0 + row : i0; for (let c = 0; c < 4; c++) gacc[i0 + c] = (gtmp[u + c] + gtmp[i0 + c] + gtmp[dn + c]) / 3; }
    }
    const gd = gimg.data, cells = GS * GS;
    for (let p = 0; p < gw * gh; p++) {
      const o = p * 4, a = gacc[o + 3] / cells;
      if (a < 0.002) { gd[o + 3] = 0; continue; }
      let r = 1.5 * gacc[o] / (cells * a), g = 1.5 * gacc[o + 1] / (cells * a), b = 1.5 * gacc[o + 2] / (cells * a);
      const l = 0.213 * r + 0.715 * g + 0.072 * b; r = l + (r - l) * 1.4; g = l + (g - l) * 1.4; b = l + (b - l) * 1.4;
      gd[o] = clamp(r, 0, 1) * 255; gd[o + 1] = clamp(g, 0, 1) * 255; gd[o + 2] = clamp(b, 0, 1) * 255; gd[o + 3] = Math.min(1, a) * 255;
    }
    gg.putImageData(gimg, 0, 0);

    // aura and drag hint (transform and opacity only)
    const auraEl = dom.aura;
    if (auraEl) {
      const ad = R * 3.4 + 40, aop = ((0.55 + 0.45 * clamp(S.sat.v, 0, 1)) * Math.min(1, S.bri.v) * (dash ? 0.7 : 1)).toFixed(3);
      const akey = cX.toFixed(1) + '|' + cY.toFixed(1) + '|' + ad.toFixed(1) + '|' + aop;
      if (this.lastKey.get(auraEl) !== akey) {
        this.lastKey.set(auraEl, akey);
        auraEl.style.transform = `translate3d(${(cX - ad / 2).toFixed(1)}px,${(cY - ad / 2).toFixed(1)}px,0) scale(${(ad / 1024).toFixed(4)})`;
        auraEl.style.opacity = aop;
      }
    }
    const overSphere = mouse.in && Math.hypot(mouse.x - cX, mouse.y - cY) < R * 1.1;
    if (overSphere && !this.hoverSince) this.hoverSince = t || 0.001;
    if (!overSphere) this.hoverSince = 0;
    const hintEl = dom.hint;
    if (hintEl) {
      const showHint = !this.dragged && overSphere && this.mode === 'welcome' && t - this.hoverSince > 0.8;
      const hkey = Math.round(cX) + '|' + Math.round(cY + R * 0.78) + '|' + showHint;
      if (this.lastKey.get(hintEl) !== hkey) {
        this.lastKey.set(hintEl, hkey);
        hintEl.style.transform = `translate3d(${Math.round(cX)}px,${Math.round(cY + R * 0.78)}px,0) translateX(-50%)`;
        hintEl.style.opacity = showHint ? '1' : '0';
      }
    }
  }
}
