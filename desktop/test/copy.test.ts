import { describe, expect, it } from 'vitest';
import { COPY, hasCopy, t } from '../src/copy';

const sources = import.meta.glob('../src/**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const mockup = Object.values(import.meta.glob('../mockup/onboarding.html', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)[0] ?? '';

const prefixes = [...new Set(Object.keys(COPY).map((k) => k.split('.')[0]))];
const keyLiteral = new RegExp(`['"\`]((?:${prefixes.join('|')})\\.[A-Za-z0-9_.]*)['"\`]`, 'g');
const appFiles = Object.entries(sources).filter(([path]) => !path.endsWith('/copy.ts'));

describe('copy table', () => {
  it('scans the app sources', () => {
    expect(appFiles.length).toBeGreaterThan(20);
  });

  it('has every key referenced in src', () => {
    const missing: string[] = [];
    let seen = 0;
    for (const [path, text] of appFiles) {
      for (const m of text.matchAll(keyLiteral)) {
        const key = m[1] ?? '';
        seen++;
        if (!hasCopy(key)) missing.push(`${path}: ${key}`);
      }
    }
    expect(missing).toEqual([]);
    expect(seen).toBeGreaterThan(100);
  });

  it('keeps display text out of components (no Hangul outside copy.ts)', () => {
    const offenders = appFiles.filter(([, text]) => /[\u1100-\u11FF\u3130-\u318F\uAC00-\uD7A3]/.test(text)).map(([p]) => p);
    expect(offenders).toEqual([]);
  });

  it('follows the writing rules: no sentence-final period, no dashes or emoji', () => {
    const bad = Object.entries(COPY).filter(([, v]) => /\.$/.test(v) || /[\u2013\u2014]/.test(v) || /\p{Extended_Pictographic}/u.test(v));
    expect(bad).toEqual([]);
  });

  it('keeps the approved mockup table (v0.5) except mockup-only notes', () => {
    const block = mockup.slice(mockup.indexOf('/*COPY_START*/'), mockup.indexOf('/*COPY_END*/'));
    const entries = [...block.matchAll(/^\s*'([^']+)':\s*'((?:[^'\\]|\\.)*)',?$/gm)].map((m) => [m[1] ?? '', m[2] ?? ''] as const);
    expect(entries.length).toBeGreaterThan(200);
    const dropped = new Set(['toast.dash', 'toast.file.mock', 'term.pw.mock']);
    // changed after review: the core keeps a previewed invite 60 minutes (toast.join.later), and
    // replacing the device key is not a response to a leaked key file (rec.sub)
    const changed = new Set(['join.local', 'toast.paste.mock', 'toast.join.later', 'rec.sub']);
    for (const [k, v] of entries) {
      if (dropped.has(k)) { expect(hasCopy(k)).toBe(false); continue; }
      expect(hasCopy(k), k).toBe(true);
      if (!changed.has(k) && hasCopy(k)) expect(COPY[k], k).toBe(v);
    }
  });

  it('keeps the glossary and the polite informal style (DESIGN.md §6)', () => {
    const banned = /(\uC2B5\uB2C8\uB2E4|\uC2ED\uC2DC\uC624|\uAC8C\uC774\uD2B8\uC6E8\uC774|\uBCFC\uD2B8|\uD504\uB9B0\uC2DC\uD384|\uC790\uACA9 ?\uC99D\uBA85|\bTTL\b|vault|gateway|principal|passphrase|\bgrant\b)/i;
    expect(Object.entries(COPY).filter(([, v]) => banned.test(v.replace(/\{\w+\}/g, '')))).toEqual([]);
  });

  it('has the placeholders the dashboard fills in', () => {
    const need: Record<string, string[]> = {
      'keys.version': ['n'], 'keys.older': ['n'], 'keys.reveal.left': ['s'], 'keys.value.loaded': ['name'], 'keys.reveal.aria': ['id'],
      'grant.until': ['time'], 'grant.uses': ['n'], 'grant.usesOf': ['n', 'max'], 'grant.revoke.aria': ['conn'], 'grant.for.aria': ['id'],
      'term.end.aria': ['id'], 'appr.approve.aria': ['req'], 'inv.revoke.aria': ['name'], 'team.remove.aria': ['name'], 'inc.close.aria': ['id'],
      'conns.disable.aria': ['id'], 'agents.disable.aria': ['id'], 'agents.grants.aria': ['id'], 'keys.versions.aria': ['id'],
      'relay.err.other': ['reason'], 'toast.recovered': ['n'], 'appr.body.size': ['n'], 'rec.verify.err': ['n'], 'rec.verify.need': ['n'],
    };
    for (const [k, vars] of Object.entries(need)) {
      expect(hasCopy(k), k).toBe(true);
      for (const v of vars) expect(COPY[k as keyof typeof COPY], k).toContain(`{${v}}`);
    }
  });

  it('claims only what the product does', () => {
    const all = Object.values(COPY).join('\n');
    // `recover` needs the existing device key file and only replaces it; a backup opens only with
    // the device key that made it (rust/src/context.rs, rust/src/vault.rs)
    expect(all).not.toMatch(/기기 키를 잃었을 때/);             // "기기 키를 잃었을 때"
    expect(COPY['rec.warn']).toMatch(/열 수 없어요/);                         // losing the key file: the vault cannot be opened
    expect(COPY['set.recover.warn']).toMatch(/회수/);                                     // the recover sheet says it revokes permissions
    // `recover` wraps the same data key under a new key file: it is never offered for a leaked
    // key file, the sheet says what a leak needs instead, and that earlier backups stop restoring
    for (const k of ['rec.sub', 'set.recover', 'set.recover.sub', 'set.recover.confirm', 'toast.recovered', 'toast.recovered.any'] as const) {
      expect(COPY[k], k).not.toMatch(/새었|유출/);
    }
    expect(COPY['set.recover.sub']).toContain('같은 데이터 키');
    expect(COPY['set.recover.leak']).toMatch(/새었을 수 있다면/);
    expect(COPY['set.recover.leak']).toMatch(/서비스에서 예전 키를 폐기/);
    expect(COPY['set.recover.warn']).toContain('백업');
    expect(COPY['set.backup.help']).toContain('바꾼 기기 키');
    // a joined device syncs only with other-device access on
    for (const k of ['done.msg.join', 'toast.join.needListen', 'sync.need', 'team.joined.sub'] as const) expect(COPY[k]).toContain('다른 기기 접속');
    // stop and revocation block new requests only; open SSH sessions are named as a limit
    for (const k of ['stop.sub', 'toast.stopped', 'grant.revoke.sub', 'keys.revoke.warn', 'inc.declare.sub', 'agents.disable.sub', 'conns.disable.sub'] as const) {
      expect(COPY[k], k).toContain('새 ');
    }
    expect(COPY['session.note']).toContain('SSH');
    // a key revoked or replaced in the vault still works at the service
    for (const k of ['inc.close.note', 'team.remove.warn', 'toast.team.removed', 'toast.key.revoked', 'toast.key.replaced', 'keys.provider.note'] as const) {
      expect(COPY[k], k).toContain('서비스');
    }
  });

  it('shows the open-session note on every sheet that blocks access (DESIGN.md §5.3)', () => {
    // stop-all, grant revoke, agent disable, connection disable, key revoke, incident declare
    const blocking = ['sheet-stop', 'sheet-grant-revoke', 'sheet-agent-disable', 'sheet-conn-disable', 'sheet-key-confirm', 'sheet-inc-declare'];
    for (const id of blocking) {
      const file = appFiles.find(([, text]) => text.includes(`id="${id}"`));
      expect(file, id).toBeDefined();
      const text = file?.[1] ?? '';
      const from = text.indexOf(`id="${id}"`);
      const next = text.indexOf('id="sheet-', from + 1);
      expect(text.slice(from, next < 0 ? undefined : next), id).toContain(`t('session.note')`);
    }
  });

  it('fills placeholders and leaves unknown ones visible', () => {
    expect(t('rec.verify.slot', { n: 3 })).toBe('3번째');
    expect(t('term.title')).toContain('{name}');
  });
});
