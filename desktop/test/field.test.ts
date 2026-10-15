import { describe, expect, it } from 'vitest';
import { Field, MODES, type FieldEnv } from '../src/field/field';

// A stub 2D context: enough for the engine to allocate buffers and hand frames over.
function stubCanvas() {
  const frames: ImageData[] = [];
  const ctx = {
    createImageData: (w: number, h: number) => ({ width: w, height: h, data: new Uint8ClampedArray(w * h * 4), colorSpace: 'srgb' }) as unknown as ImageData,
    putImageData: (img: ImageData) => { frames.push(img); },
  };
  const canvas = { width: 0, height: 0, style: { width: '', height: '' }, getContext: (kind: string) => (kind === '2d' ? ctx : null) };
  return { canvas: canvas as unknown as HTMLCanvasElement, frames };
}

function stubHost(w = 1180, h = 780) {
  const listeners = new Map<string, EventListener>();
  const host = {
    clientWidth: w, clientHeight: h,
    getBoundingClientRect: () => ({ left: 0, top: 0, width: w, height: h }),
    addEventListener: (type: string, fn: EventListener) => { listeners.set(type, fn); },
    removeEventListener: (type: string) => { listeners.delete(type); },
    setPointerCapture: () => undefined,
  };
  return { host: host as unknown as HTMLElement, listeners };
}

function stubStyled() {
  return { style: { transform: '', opacity: '' }, offsetWidth: 80, textContent: '' } as unknown as HTMLElement;
}

function manualEnv() {
  let now = 0;
  const queue: Array<(t: number) => void> = [];
  const timers: Array<() => void> = [];
  const env: FieldEnv = {
    raf: (cb) => { queue.push(cb); return queue.length; },
    caf: () => { queue.length = 0; },
    now: () => now,
    dpr: () => 1,
    hidden: () => false,
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: () => undefined,
  };
  const pump = (frames = 1, dtMs = 16) => {
    for (let i = 0; i < frames; i++) {
      now += dtMs;
      const batch = queue.splice(0);
      batch.forEach((cb) => cb(now));
    }
  };
  return { env, pump, queue, timers };
}

function setup(motion: boolean) {
  const f = stubCanvas(), g = stubCanvas(), h = stubHost();
  const m = manualEnv();
  const chipEl = stubStyled(), chipLabel = stubStyled();
  const field = new Field({ motion, env: m.env });
  field.attach({ host: h.host, field: f.canvas, glow: g.canvas, aura: stubStyled(), hint: stubStyled(), chips: { agent: { el: chipEl, label: chipLabel } } });
  return { field, f, g, h, m, chipLabel };
}

/** Lit pixels inside a circle (CSS px) of the latest field frame. */
function litNear(img: ImageData, cx: number, cy: number, r: number, px = 2) {
  let n = 0, spread = 0;
  for (let y = Math.max(0, Math.floor((cy - r) / px)); y < Math.min(img.height, Math.ceil((cy + r) / px)); y++) {
    for (let x = Math.max(0, Math.floor((cx - r) / px)); x < Math.min(img.width, Math.ceil((cx + r) / px)); x++) {
      if (Math.hypot(x * px - cx, y * px - cy) > r) continue;
      const o = (y * img.width + x) * 4;
      if (img.data[o + 3]! > 40) { n++; spread += Math.abs(img.data[o]! - img.data[o + 2]!); }
    }
  }
  return { n, spread: n ? spread / n : 0 };
}

describe('pixel field', () => {
  it('builds with stub canvases and sizes buffers to whole field pixels', () => {
    const { f, g, h } = setup(false);
    expect(h.listeners.has('pointermove')).toBe(true);
    expect(f.canvas.width).toBe(590);   // 1180 / 2 CSS px per field pixel at dpr 1
    expect(f.canvas.height).toBe(390);
    expect(g.canvas.width).toBe(Math.ceil(590 / 4));
  });

  it('renders the sphere where the mode puts it, without a loop when motion is off', () => {
    const { field, f, m } = setup(false);
    field.setMode('admin');
    expect(m.queue.length).toBe(1);              // one still frame, not a loop
    m.pump();
    const img = f.frames.at(-1)!;
    const { cx, cy, r } = MODES.admin;
    expect(litNear(img, cx * 1180, cy * 780, r * 780 * 0.6).n).toBeGreaterThan(500);
    expect(litNear(img, 0.85 * 1180, 0.2 * 780, r * 780 * 0.6).n).toBeLessThan(60);   // dust only, far from the sphere
    expect(m.queue.length).toBe(0);
  });

  it('parks a small sphere for the dashboard and cools it to grey when stopped', () => {
    const { field, f, m } = setup(false);
    const ax = 110, ay = 110, rad = 30;
    field.setMode('dash', { cx: ax / 1180, cy: ay / 780, r: rad / 780 });
    m.pump();
    const live = litNear(f.frames.at(-1)!, ax, ay, rad);
    expect(live.n).toBeGreaterThan(40);
    expect(litNear(f.frames.at(-1)!, 0.31 * 1180, 0.53 * 780, 120).n).toBeLessThan(80);   // only dust where the big sphere was
    field.setStopped(true);
    expect(field.isStopped).toBe(true);
    m.pump();
    const stopped = litNear(f.frames.at(-1)!, ax, ay, rad);
    expect(stopped.n).toBeGreaterThan(20);
    expect(stopped.spread).toBeLessThan(live.spread);   // less blue/violet: grey
  });

  it('runs the animation API with motion on', () => {
    const { field, f, m, chipLabel } = setup(true);
    expect(field.motionOn).toBe(true);
    field.setMode('create');
    for (let k = 1; k <= 6; k++) field.createStep(k, 6);
    field.createBurst();
    field.setStrength(0.4); field.ripple(0.05); field.excite(0.3); field.pulse();
    field.setConn({ kind: 'http' }); field.setMode('agent', { svc: 1 });
    field.setPeerGhost(false); field.set('peer', 1);
    field.chipText('agent', 'agent-1');
    expect(chipLabel.textContent).toBe('agent-1');
    m.pump(30);
    expect(f.frames.length).toBeGreaterThanOrEqual(25);
    m.timers.forEach((fn) => fn());
    field.setMotion(false);
    expect(field.motionOn).toBe(false);
    m.pump(3);
    const before = f.frames.length;
    m.pump(3);
    expect(f.frames.length).toBe(before);           // no loop once motion is paused
  });

  it('detaches its listeners and stops drawing', () => {
    const { field, f, h, m } = setup(true);
    m.pump(2);
    field.detach();
    expect(h.listeners.size).toBe(0);
    const n = f.frames.length;
    m.pump(5);
    expect(f.frames.length).toBe(n);
    expect(() => field.setMode('welcome')).not.toThrow();
  });
});
