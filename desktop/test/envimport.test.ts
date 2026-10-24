import { afterEach, describe, expect, it } from 'vitest';
import { hasCopy } from '../src/copy';
import { call, on, toIpcError, useMockBackend } from '../src/ipc/client';
import type { ImportEntry, ImportReport } from '../src/ipc/contract';
import { createMockBackend, mockClassify, type MockBackend } from '../src/ipc/mock';
import {
  badLineKey, badLines, dropErrorKey, importBlocker, importErrorCopy, isForced, isIdPrefix, plannedAction, plannedKey, resultKey, writeCount,
} from '../src/lib/envimport';

// .env import (docs/env-import.md §8): the sheet's rules over the core's preview, and the mock's
// stand-in for the core. Values stay behind the import reference; the webview gets names and IDs.

const OPENAI = 'sk-synthetic-openai-0123456789';
const ENV = `# app\nexport OPENAI_API_KEY=${OPENAI}\nPORT=3000\nNODE_ENV=development\nDATABASE_URL='postgres://app:synthetic-pw-01@db.example/app'\nEMPTY=\n`;

const entry = (over: Partial<ImportEntry>): ImportEntry => ({
  line: 1, name: 'A', id: 'a', kind: 'env_var', selected: true, why: 'secret_name', action: 'create', state: 'new', forced: false, ...over,
});
const report = (entries: ImportEntry[], shared = false): ImportReport => ({ project: 'demo', environment: 'dev', shared, dry_run: true, entries, empty_lines: [] });

let backend: MockBackend | null = null;
function ready(): MockBackend {
  backend?.dispose();
  backend = createMockBackend({ latency: 0, initialized: true });
  useMockBackend(backend);
  return backend;
}
afterEach(() => { backend?.dispose(); backend = null; useMockBackend(null); });

async function reason(p: Promise<unknown>): Promise<string> {
  try { await p; } catch (e) { return toIpcError(e).reason; }
  throw new Error('expected a rejection');
}

describe('import sheet rules', () => {
  it('derives what each entry would do from its state, the selection and update', () => {
    expect(plannedAction(entry({ state: 'new' }), true, false)).toBe('create');
    expect(plannedAction(entry({ state: 'new' }), false, false)).toBe('skip');
    expect(plannedAction(entry({ state: 'same' }), true, false)).toBe('unchanged');
    expect(plannedAction(entry({ state: 'different' }), true, false)).toBe('conflict');
    expect(plannedAction(entry({ state: 'different' }), true, true)).toBe('new_version');
    expect(plannedAction(entry({ state: 'elsewhere' }), true, true)).toBe('id_taken');
    for (const a of ['create', 'new_version', 'unchanged', 'conflict', 'id_taken'] as const) expect(hasCopy(plannedKey(a) ?? '')).toBe(true);
    expect(plannedKey('skip')).toBeNull();
    expect(resultKey(entry({ action: 'created' }))).toBe('imp.act.created');
    expect(resultKey(entry({ action: 'new_version' }))).toBe('imp.act.replaced');
    expect(resultKey(entry({ action: 'skipped' }))).toBeNull();
  });

  it('says what keeps a selection from being imported, in order', () => {
    const r = report([
      entry({ name: 'NEW', state: 'new' }),
      entry({ name: 'SAME', state: 'same' }),
      entry({ name: 'DIFF', state: 'different' }),
      entry({ name: 'TAKEN', state: 'elsewhere' }),
      entry({ name: 'CLI', state: 'new', blocked_by: 'api' }),
    ]);
    expect(importBlocker(r, new Set(), false)).toBe('imp.err.none');
    expect(importBlocker(r, new Set(['NEW', 'TAKEN']), true)).toBe('imp.err.taken');
    expect(importBlocker(r, new Set(['NEW', 'DIFF']), false)).toBe('imp.err.conflict');
    expect(importBlocker(r, new Set(['NEW', 'DIFF']), true)).toBeNull();
    expect(importBlocker(r, new Set(['CLI']), false)).toBe('imp.err.blocked');
    // an unchanged key writes nothing, so a CLI profile carrying it does not matter
    expect(importBlocker(report([entry({ name: 'S', state: 'same', blocked_by: 'api' })]), new Set(['S']), false)).toBeNull();
    expect(writeCount(r, new Set(['NEW', 'SAME', 'DIFF']), true)).toBe(2);
    expect(writeCount(r, new Set(['SAME']), true)).toBe(0);
    expect(isForced(entry({ selected: false, why: 'plain_value' }), true)).toBe(true);
    expect(isForced(entry({ selected: true }), true)).toBe(false);
  });

  it('reads parse errors as line numbers and reasons, dropping a pair the 300-character limit cut', () => {
    expect(badLines('1:not_assignment,3:unquoted_hash,4:dollar_needs_sin')).toEqual([
      { line: 1, reason: 'not_assignment' }, { line: 3, reason: 'unquoted_hash' },
    ]);
    expect(badLines(undefined)).toEqual([]);
    expect(badLines('1:<script>')).toEqual([]);
    expect(badLineKey('lone_carriage_return')).toBe('imp.bad.lone_carriage_return');
    expect(badLineKey('anything')).toBe('imp.bad.other');
    for (const r of ['not_assignment', 'invalid_name', 'name_too_long', 'duplicate_name', 'unquoted_hash', 'dollar_needs_single_quotes',
      'unsupported_escape', 'backslash_in_single_quotes', 'backtick_quote', 'unterminated_quote', 'trailing_text', 'nul_byte']) {
      expect(badLineKey(r), r).toBe(`imp.bad.${r}`);
    }
  });

  it('maps drop and import failures to copy, never echoing anything but names', () => {
    expect(dropErrorKey('drop_one_file')).toBe('drop.err.drop_one_file');
    expect(dropErrorKey('env_file_too_large')).toBe('drop.err.env_file_too_large');
    expect(dropErrorKey('something_else')).toBe('drop.err.file_unreadable');
    expect(importErrorCopy('cli_env_contains_credential', 'api:OTHER_TOKEN')).toEqual({ key: 'imp.err.cli', vars: { conn: 'api', name: 'OTHER_TOKEN' } });
    expect(importErrorCopy('cli_env_contains_credential').key).toBe('imp.err.blocked');
    expect(importErrorCopy('not_admin').key).toBe('imp.err.admin');
    expect(importErrorCopy('onetime_ref_unknown').key).toBe('imp.err.expired');
    expect(importErrorCopy('whatever').key).toBe('error.generic');
    expect(isIdPrefix('')).toBe(true);
    expect(isIdPrefix('staging.')).toBe(true);
    expect(isIdPrefix('Staging')).toBe(false);
    expect(isIdPrefix('-x')).toBe(false);
  });
});

describe('mock .env import', () => {
  it('classifies as rust/src/envfile.rs does', () => {
    expect(mockClassify('OPENAI_API_KEY', OPENAI)).toEqual([true, 'secret_name']);
    expect(mockClassify('AUTH_ENABLED', 'true')).toEqual([false, 'plain_value']);
    expect(mockClassify('DB_PASSWORD', 'short')).toEqual([false, 'short_value']);
    expect(mockClassify('DATABASE_URL', 'postgres://app:pw-0123456@db/app')).toEqual([true, 'url_password']);
    expect(mockClassify('NODE_ENV', 'development')).toEqual([false, 'no_hint']);
  });

  it('keeps a dropped file behind a reference the webview cannot open, previews names only and imports the selection', async () => {
    const b = ready();
    const seen: Array<{ import_ref?: string; name?: string; error?: string }> = [];
    const off = await on('envfile://dropped', (d) => seen.push(d));
    b.dropFile('.env', ENV);
    off();
    const ref = seen[0]?.import_ref ?? '';
    expect(seen[0]?.name).toBe('.env');
    expect(JSON.stringify(seen)).not.toContain(OPENAI);
    expect(await reason(call('onetime_show', { ref }))).toBe('onetime_ref_unknown');
    expect(await reason(call('onetime_copy', { ref }))).toBe('onetime_ref_unknown');

    const preview = await call('secret_import_preview', { import_ref: ref, project: 'demo', environment: 'dev' });
    expect(JSON.stringify(preview)).not.toContain(OPENAI);
    expect(JSON.stringify(preview)).not.toContain('synthetic-pw');
    expect(preview.empty_lines).toEqual([6]);
    expect(preview.entries.map((e) => [e.name, e.selected, e.why])).toEqual([
      ['OPENAI_API_KEY', true, 'secret_name'], ['PORT', false, 'plain_value'], ['NODE_ENV', false, 'no_hint'], ['DATABASE_URL', true, 'url_password'],
    ]);

    const out = await call('secret_import', { import_ref: ref, project: 'demo', environment: 'dev', selected: ['OPENAI_API_KEY', 'PORT'], update: false });
    expect(out.entries.map((e) => [e.name, e.action])).toEqual([['OPENAI_API_KEY', 'created'], ['PORT', 'created'], ['NODE_ENV', 'skipped'], ['DATABASE_URL', 'skipped']]);
    expect(out.entries.find((e) => e.name === 'PORT')?.forced).toBe(true);
    expect(b.inspect().secrets).toEqual(expect.arrayContaining(['openai_api_key', 'port']));
    // an import forgets the file
    expect(await reason(call('secret_import_preview', { import_ref: ref, project: 'demo', environment: 'dev' }))).toBe('onetime_ref_unknown');
  });

  it('reports a changed value, an ID used elsewhere and bad lines', async () => {
    const b = ready();
    const drop = async (text: string) => {
      let ref = '';
      const off = await on('envfile://dropped', (d) => { ref = d.import_ref ?? ''; });
      b.dropFile('prod.env', text);
      off();
      return ref;
    };
    await call('secret_import', { import_ref: await drop(ENV), project: 'demo', environment: 'dev', selected: ['OPENAI_API_KEY'], update: false });
    const next = await drop(`OPENAI_API_KEY=${OPENAI}-rotated\n`);
    const p = await call('secret_import_preview', { import_ref: next, project: 'demo', environment: 'dev' });
    expect(p.entries[0]?.state).toBe('different');
    expect(await reason(call('secret_import', { import_ref: next, project: 'demo', environment: 'dev', selected: ['OPENAI_API_KEY'], update: false }))).toBe('import_conflict');
    const elsewhere = await call('secret_import_preview', { import_ref: next, project: 'demo', environment: 'prod' });
    expect(elsewhere.entries[0]?.state).toBe('elsewhere');
    const prefixed = await call('secret_import_preview', { import_ref: next, project: 'demo', environment: 'prod', id_prefix: 'prod.' });
    expect(prefixed.entries[0]).toMatchObject({ id: 'prod.openai_api_key', state: 'new' });
    expect((await call('secret_import', { import_ref: next, project: 'demo', environment: 'dev', selected: ['OPENAI_API_KEY'], update: true })).entries[0]?.action).toBe('new_version');

    const bad = await drop(`${OPENAI}\nA=b#c\n`);
    const err = await call('secret_import_preview', { import_ref: bad, project: 'demo', environment: 'dev' }).then(() => null, toIpcError);
    expect(err?.reason).toBe('env_file_invalid');
    expect(err?.detail).toBe('1:not_assignment,2:unquoted_hash');
    expect(JSON.stringify(err)).not.toContain(OPENAI);
  });

  it('picks a file natively and refuses a token picked for another purpose', async () => {
    ready();
    const key = await call('file_pick', { purpose: 'secret' });
    expect(await reason(call('env_file_load', { file_token: key?.file_token ?? '' }))).toBe('file_token_unknown');
    const env = await call('file_pick', { purpose: 'env_file' });
    const loaded = await call('env_file_load', { file_token: env?.file_token ?? '' });
    expect(loaded.name).toBe('.env');
    expect(await reason(call('env_file_load', { file_token: env?.file_token ?? '' }))).toBe('file_token_unknown');
  });

  it('reads nothing before a vault exists', async () => {
    backend = createMockBackend({ latency: 0 });
    useMockBackend(backend);
    const seen: Array<{ error?: string }> = [];
    const off = await on('envfile://dropped', (d) => seen.push(d));
    backend.dropFile('.env', ENV);
    off();
    expect(seen).toEqual([{ error: 'vault_missing' }]);
  });
});
