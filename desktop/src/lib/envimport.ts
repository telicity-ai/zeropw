// `.env` import on the keys page (docs/env-import.md §8): what each entry would do with the
// user's selection, what stops an import, and the copy for the core's reason codes. The core's
// preview carries names and key IDs only; values never reach the webview.

import { hasCopy, type CopyKey } from '../copy';
import type { ImportEntry, ImportReport, ImportWhy } from '../ipc/contract';

export const IMPORT_WHY: Record<ImportWhy, CopyKey> = {
  secret_name: 'imp.why.secret_name', url_password: 'imp.why.url_password', plain_value: 'imp.why.plain_value',
  short_value: 'imp.why.short_value', no_hint: 'imp.why.no_hint',
};
export const whyKey = (why: string): CopyKey => IMPORT_WHY[why as ImportWhy] ?? 'imp.why.no_hint';

export type PlannedAction = 'create' | 'new_version' | 'unchanged' | 'conflict' | 'id_taken' | 'skip';

/** What importing `e` does when it is selected (`on`) and existing keys may get a new value
 *  (`update`): the CLI's preview action for that choice. */
export function plannedAction(e: ImportEntry, on: boolean, update: boolean): PlannedAction {
  if (!on) return 'skip';
  switch (e.state) {
    case 'new': return 'create';
    case 'same': return 'unchanged';
    case 'different': return update ? 'new_version' : 'conflict';
    default: return 'id_taken';
  }
}

/** The tag a preview row shows for its planned action (none for a skipped entry). */
export function plannedKey(a: PlannedAction): CopyKey | null {
  return a === 'skip' ? null : (`imp.act.${a}` as CopyKey);
}

/** The tag a result row shows: what was written. */
export function resultKey(e: ImportEntry): CopyKey | null {
  if (e.action === 'created') return 'imp.act.created';
  if (e.action === 'new_version') return 'imp.act.replaced';
  if (e.action === 'unchanged') return 'imp.act.unchanged';
  return null;
}

/** Entries an import of `selected` writes (new keys and new versions). */
export function writeCount(report: ImportReport, selected: ReadonlySet<string>, update: boolean): number {
  return report.entries.filter((e) => {
    const a = plannedAction(e, selected.has(e.name), update);
    return a === 'create' || a === 'new_version';
  }).length;
}

/** The first thing that keeps `selected` from being imported, as copy, or null when it can go. */
export function importBlocker(report: ImportReport, selected: ReadonlySet<string>, update: boolean): CopyKey | null {
  const chosen = report.entries.filter((e) => selected.has(e.name));
  if (chosen.length === 0) return 'imp.err.none';
  if (chosen.some((e) => e.state === 'elsewhere')) return 'imp.err.taken';
  if (!update && chosen.some((e) => e.state === 'different')) return 'imp.err.conflict';
  if (chosen.some((e) => e.blocked_by && (e.state === 'new' || (e.state === 'different' && update)))) return 'imp.err.blocked';
  return null;
}

/** Selected, but the default would have skipped it (a setting): storing it has side effects. */
export const isForced = (e: ImportEntry, on: boolean): boolean => on && !e.selected;

/** `env_file_invalid`'s detail: `line:reason` pairs, at most 300 characters (a pair the limit cut
 *  is dropped). */
export function badLines(detail: string | undefined): Array<{ line: number; reason: string }> {
  if (!detail) return [];
  const out: Array<{ line: number; reason: string }> = [];
  for (const part of detail.split(',')) {
    const m = /^(\d{1,6}):([a-z_]+)$/.exec(part.trim());
    if (m && hasCopy(`imp.bad.${m[2]}`)) out.push({ line: Number(m[1]), reason: m[2] ?? '' });
  }
  return out;
}

export const badLineKey = (reason: string): CopyKey => {
  const key = `imp.bad.${reason}`;
  return hasCopy(key) ? key : 'imp.bad.other';
};

/** Copy for a drop the core could not read (`envfile://dropped` `error`). */
export function dropErrorKey(reason: string): CopyKey {
  const key = `drop.err.${reason}`;
  return hasCopy(key) ? key : 'drop.err.file_unreadable';
}

/** Copy for a failed `secret_import`, with the values it fills in. Reasons the sheet already
 *  prevents (no selection, conflicts, IDs elsewhere) map to the same lines as the blockers. */
export function importErrorCopy(reason: string, detail?: string): { key: CopyKey; vars?: Record<string, string> } {
  switch (reason) {
    case 'cli_env_contains_credential': {
      const [conn = '', name = ''] = (detail ?? '').split(':');
      return conn && name ? { key: 'imp.err.cli', vars: { conn, name } } : { key: 'imp.err.blocked' };
    }
    case 'not_admin': return { key: 'imp.err.admin' };
    case 'team_rekey_pending': return { key: 'imp.err.rekey' };
    case 'onetime_ref_unknown': return { key: 'imp.err.expired' };
    case 'import_nothing_selected': return { key: 'imp.err.none' };
    case 'import_conflict': return { key: 'imp.err.conflict' };
    case 'secret_identity_mismatch': return { key: 'imp.err.taken' };
    case 'id_collision': return { key: 'imp.err.collision', vars: { ids: detail ?? '' } };
    case 'env_file_too_many_entries': return { key: 'imp.err.many' };
    default: return { key: 'error.generic' };
  }
}

/** `--id-prefix` as the core accepts it: empty, or a key ID head followed by ID characters. */
export const isIdPrefix = (v: string): boolean => v === '' || /^[a-z0-9][a-z0-9._-]{0,62}$/.test(v);
