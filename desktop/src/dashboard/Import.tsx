import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { EnvFileRef, ImportReport } from '../ipc/contract';
import { splitEnv, type EnvPair } from '../lib/dash';
import {
  badLineKey, badLines, importBlocker, importErrorCopy, isForced, isIdPrefix, plannedAction, plannedKey, resultKey, whyKey, writeCount,
} from '../lib/envimport';
import { useApp } from '../ui/context';
import { SelectField, TextField } from '../ui/fields';
import { Callout } from '../ui/form';
import { Empty, Tag } from './parts';
import { Sheet } from './Sheet';

const PREVIEW_DELAY_MS = 250;
type Bad = { lines: Array<{ line: number; reason: string }>; key: CopyKey; vars?: Record<string, string> };

/** Which environments are shared with a team: `team_members` answers for a shared one. */
async function sharedEnvs(keys: string[]): Promise<Set<string>> {
  const found = await Promise.all(keys.map((env) => call('team_members', { env }).then(() => env, () => null)));
  return new Set(found.filter((e): e is string => e !== null));
}

/** `.env` import (docs/env-import.md §8): the core read the file (picked or dropped on the
 *  window) and keeps it; this sheet shows the preview (names, key IDs, why each is chosen), lets
 *  the user change the selection and imports in one step. A shared environment is chosen first,
 *  since an import there reaches the team in one commit. No value ever comes here. */
export function ImportSheet({ open, file, pairs, onClose, onDone }: {
  open: boolean; file: EnvFileRef | undefined; pairs: readonly EnvPair[]; onClose(): void; onDone(): void;
}) {
  const { toast, field, announce } = useApp();
  const [shared, setShared] = useState<Set<string> | null>(null);
  const [env, setEnv] = useState('');
  const [prefix, setPrefix] = useState('');
  // the last preview and the environment and prefix it was made for
  const [loaded, setLoaded] = useState<{ place: string; report: ImportReport } | null>(null);
  const [bad, setBad] = useState<Bad | null>(null);
  const [selected, setSelected] = useState<Set<string> | null>(null);
  const [update, setUpdate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ key: CopyKey; vars?: Record<string, string> } | null>(null);
  const [result, setResult] = useState<ImportReport | null>(null);
  const done = useRef(false);
  const envRef = useRef<HTMLSelectElement>(null);
  const prefixRef = useRef<HTMLInputElement>(null);
  const ref = file?.import_ref ?? '';

  // a file that was not imported is forgotten as soon as the sheet closes, or gives way to a
  // file dropped after it
  useEffect(() => {
    if (!open || !ref) return;
    return () => { if (!done.current) call('onetime_discard', { ref }).catch(() => undefined); };
  }, [open, ref]);

  // a shared environment first
  useEffect(() => {
    if (!open || shared || pairs.length === 0) return;
    let live = true;
    sharedEnvs(pairs.map((p) => p.key)).then((s) => {
      if (!live) return;
      setShared(s);
      setEnv((cur) => cur || (pairs.find((p) => s.has(p.key)) ?? pairs[0])?.key || '');
    });
    return () => { live = false; };
  }, [open, shared, pairs]);

  // the preview follows the environment and the prefix; until the one for the current choice
  // arrives the list stays as it was but nothing can be imported, so a run never goes to an
  // environment or under IDs the screen did not show
  const prefixOk = isIdPrefix(prefix);
  const place = `${env}\n${prefix}`;
  const preview = loaded?.place === place ? loaded.report : null;
  const shown = loaded?.report ?? null;
  useEffect(() => {
    const pair = splitEnv(env);
    if (!open || !ref || !pair || !prefixOk || result) return;
    let live = true;
    setBad(null);
    const tm = setTimeout(() => {
      call('secret_import_preview', { import_ref: ref, project: pair.project, environment: pair.environment, ...(prefix ? { id_prefix: prefix } : {}) }).then(
        (p) => {
          if (!live) return;
          setLoaded({ place: `${env}\n${prefix}`, report: p }); setErr(null);
          setSelected((cur) => cur ?? new Set(p.entries.filter((e) => e.selected).map((e) => e.name)));
        },
        (e) => {
          if (!live) return;
          const x = toIpcError(e);
          setLoaded(null);
          if (x.reason === 'env_file_invalid') setBad({ lines: badLines(x.detail), key: 'imp.bad' });
          else if (x.reason === 'invalid_id_prefix') setErr({ key: 'proj.err.name' });
          else setBad({ lines: [], ...importErrorCopy(x.reason, x.detail) });
        },
      );
    }, prefix ? PREVIEW_DELAY_MS : 0);
    return () => { live = false; clearTimeout(tm); };
  }, [open, ref, env, prefix, prefixOk, result]);

  const sel = selected ?? new Set<string>();
  const isShared = preview?.shared ?? (shared?.has(env) ?? false);
  // what a run writes once allowed: a changed key counts even before "update" is chosen
  const n = shown ? writeCount(shown, sel, true) : 0;
  const blocker: CopyKey | null = !preview ? 'boot.loading' : importBlocker(preview, sel, update) ?? (n === 0 ? 'imp.done.none' : null);
  const hasTaken = !!shown?.entries.some((e) => e.state === 'elsewhere');
  const hasDifferent = !!shown?.entries.some((e) => e.state === 'different');

  const toggle = (name: string) => {
    setSelected((cur) => {
      const next = new Set(cur ?? []);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
    setErr(null);
  };

  const run = async () => {
    const pair = splitEnv(env);
    if (!preview || !pair) return;
    setBusy(true); setErr(null);
    try {
      const out = await call('secret_import', {
        import_ref: ref, project: pair.project, environment: pair.environment, ...(prefix ? { id_prefix: prefix } : {}),
        selected: preview.entries.filter((e) => sel.has(e.name)).map((e) => e.name), update,
      });
      done.current = true;
      const written = out.entries.filter((e) => e.action === 'created' || e.action === 'new_version').length;
      setResult(out);
      announce(t(out.shared ? 'imp.done.shared' : 'imp.done', { n: written }));
      toast(t('toast.import.done', { n: written }));
      field.ripple(0.08);
      onDone();
    } catch (e) {
      const x = toIpcError(e);
      setErr(importErrorCopy(x.reason, x.detail));
    } finally { setBusy(false); }
  };

  const blocked = () => {
    if (blocker === 'imp.err.taken') prefixRef.current?.focus();
    setErr(blocker && blocker !== 'boot.loading' ? { key: blocker } : null);
  };

  if (result) {
    const written = result.entries.filter((e) => e.action === 'created' || e.action === 'new_version').length;
    const shown = result.entries.filter((e) => resultKey(e));
    return (
      <Sheet id="sheet-import" open={open} title={t('imp.title')}
        lead={written === 0 ? t('imp.done.none') : t(result.shared ? 'imp.done.shared' : 'imp.done', { n: written })}
        onClose={onClose} closeLabel={t('common.done')}>
        <ul className="sub-list imp-list" aria-label={t('imp.items')}>
          {shown.map((e) => (
            <li key={e.name}><span className="mono">{e.id}</span><span className="sub-meta" />{resultKey(e) && <Tag>{t(resultKey(e) as CopyKey)}</Tag>}</li>
          ))}
        </ul>
        <Callout kind="info">{t('imp.left')}</Callout>
        {result.shared && <Callout kind="info">{t('imp.left.team')}</Callout>}
      </Sheet>
    );
  }

  const forced = shown?.entries.some((e) => isForced(e, sel.has(e.name))) ?? false;
  const blockedBy = shown?.entries.find((e) => sel.has(e.name) && e.blocked_by && plannedAction(e, true, update) !== 'unchanged');
  const ready = !busy && blocker === null;
  return (
    <Sheet id="sheet-import" open={open} title={t('imp.title')} lead={t('imp.sub')}
      primaryLabel={bad ? undefined : n > 0 ? t(isShared ? 'imp.go.shared' : 'imp.go', { n }) : t(isShared ? 'imp.go.shared.none' : 'imp.go.none')}
      busy={busy} ready={ready} onPrimary={() => void run()} onBlocked={blocked} onClose={onClose}>
      {file && <dl className="kv sheet-kv"><dt>{t('imp.file')}</dt><dd>{file.name}</dd></dl>}
      {pairs.length === 0 ? <Callout kind="info">{t('keys.err.noEnv')}</Callout> : (
        <SelectField id="imp-env" label={t('keys.field.env')} mono value={env} selectRef={envRef}
          options={pairs.map((p) => ({ value: p.key, label: p.key }))} onChange={(v) => { setEnv(v); setErr(null); }} />
      )}
      {isShared && <Callout kind="info">{t('imp.shared')}</Callout>}
      {bad ? (
        <>
          <Callout kind="warn">{t(bad.key, bad.vars)}</Callout>
          {bad.lines.length > 0 && (
            <ul className="sub-list imp-list" aria-label={t('imp.items')}>
              {bad.lines.map((b) => (
                <li key={`${b.line}-${b.reason}`}><span className="imp-line">{t('imp.bad.line', { line: b.line })}</span><span className="sub-meta imp-meta wrap">{t(badLineKey(b.reason))}</span></li>
              ))}
            </ul>
          )}
        </>
      ) : !shown ? <Empty text={t('boot.loading')} /> : shown.entries.length === 0 ? <Empty text={t('imp.none')} /> : (
        <div className="field">
          <div className="label"><span id="imp-items-lbl">{t('imp.items')}</span></div>
          <ul className="sub-list imp-list" aria-labelledby="imp-items-lbl">
            {shown.entries.map((e) => {
              const on = sel.has(e.name);
              const tag = plannedKey(plannedAction(e, on, update));
              const warn = on && (e.state === 'different' && !update || e.state === 'elsewhere' || !!e.blocked_by);
              return (
                <li key={e.name}>
                  <button className="chip imp-chip" type="button" aria-pressed={on} aria-label={t('imp.toggle.aria', { name: e.name })} onClick={() => toggle(e.name)}>
                    <i aria-hidden="true" /><span>{e.name}</span>
                  </button>
                  <span className="sub-meta imp-meta">{e.id !== e.name.toLowerCase() && <span className="imp-id">{e.id}</span>}{t(whyKey(e.why))}</span>
                  {tag && <Tag warn={warn}>{t(tag)}</Tag>}
                </li>
              );
            })}
          </ul>
          {shown.empty_lines.length > 0 && <div className="help">{t('imp.empty', { n: shown.empty_lines.length })}</div>}
          {blockedBy?.blocked_by && <div className="help warn">{t('imp.blocked', { conn: blockedBy.blocked_by })}</div>}
          {forced && <div className="help warn">{t('imp.forced')}</div>}
        </div>
      )}
      {shown && hasDifferent && (
        <label className="check tight">
          <input type="checkbox" checked={update} onChange={(e) => { setUpdate(e.target.checked); setErr(null); }} /> <span>{t('imp.update')}</span>
        </label>
      )}
      {(hasTaken || prefix) && (
        <TextField id="imp-prefix" label={t('imp.prefix')} hint={t('imp.prefix.hint')} mono value={prefix} inputRef={prefixRef} maxLength={63}
          placeholder={`${splitEnv(env)?.environment ?? 'dev'}.`} error={!prefixOk ? t('proj.err.name') : null} onChange={(v) => { setPrefix(v); setErr(null); }} />
      )}
      {err && <div className="help err" role="alert">{t(err.key, err.vars)}</div>}
    </Sheet>
  );
}
