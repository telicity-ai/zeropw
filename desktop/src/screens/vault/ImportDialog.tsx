// `.env` import (docs/env-import.md §8). The core read the file (picked or dropped on the
// window) and keeps it behind `import_ref`; this dialog shows the preview (names, item IDs, why
// each is chosen), lets the person change the selection and imports in one step. A shared place
// is chosen first, since an import there reaches the other devices in one commit. No value ever
// comes here. A file that was not imported is discarded when the dialog closes.

import { useEffect, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { EnvFileRef, ImportReport } from '../../ipc/contract';
import { splitEnv, type EnvPair } from '../../lib/dash';
import {
  badLineKey, badLines, importBlocker, importErrorCopy, isForced, isIdPrefix, plannedAction, plannedKey, resultKey, whyKey, writeCount,
} from '../../lib/envimport';
import { useApp } from '../../ui/app';
import { Button, Checkbox, SelectField, TextField } from '../../ui/controls';
import { Dialog } from '../../ui/Dialog';
import { More } from '../../ui/disclosure';
import { Badge, Banner, EmptyState, SkeletonRows } from '../../ui/feedback';
import { Icon } from '../../ui/icons';
import { placeText } from './logic';

const PREVIEW_DELAY_MS = 250;
type Msg = { key: CopyKey; vars?: Record<string, string> };
type Bad = { lines: Array<{ line: number; reason: string }> } & Msg;

/** Which places are team environments: `team_members` answers for a shared one. */
async function sharedPlaces(keys: string[]): Promise<Set<string>> {
  const found = await Promise.all(keys.map((env) => call('team_members', { env }).then(() => env, () => null)));
  return new Set(found.filter((e): e is string => e !== null));
}

export function ImportDialog({ file, pairs, onClose, onDone }: { file: EnvFileRef; pairs: readonly EnvPair[]; onClose(): void; onDone(): void }) {
  const { toast, announce } = useApp();
  const [shared, setShared] = useState<Set<string> | null>(null);
  const [env, setEnv] = useState('');
  const [prefix, setPrefix] = useState('');
  const [loaded, setLoaded] = useState<{ place: string; report: ImportReport } | null>(null);
  const [bad, setBad] = useState<Bad | null>(null);
  const [selected, setSelected] = useState<Set<string> | null>(null);
  const [update, setUpdate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<Msg | null>(null);
  const [result, setResult] = useState<ImportReport | null>(null);
  const [moreOpen, setMoreOpen] = useState(false);
  const done = useRef(false);
  const running = useRef(false);
  const prefixRef = useRef<HTMLInputElement>(null);
  const ref = file.import_ref;

  // the file is forgotten unless it was imported, when the dialog closes or another file replaces it
  useEffect(() => () => { if (!done.current) void call('onetime_discard', { ref }).catch(() => undefined); }, [ref]);

  useEffect(() => {
    if (shared || pairs.length === 0) return;
    let live = true;
    sharedPlaces(pairs.map((p) => p.key)).then((s) => {
      if (!live) return;
      setShared(s);
      setEnv((cur) => cur || (pairs.find((p) => s.has(p.key)) ?? pairs[0])?.key || '');
    });
    return () => { live = false; };
  }, [shared, pairs]);

  // the preview follows the place and the prefix; until the one for the current choice arrives
  // nothing can be imported, so a run never goes somewhere the screen did not show
  const prefixOk = isIdPrefix(prefix);
  const place = `${env}\n${prefix}`;
  const preview = loaded?.place === place ? loaded.report : null;
  const shown = loaded?.report ?? null;
  useEffect(() => {
    const pair = splitEnv(env);
    if (!pair || !prefixOk || result) return;
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
          if (x.reason === 'env_file_invalid') setBad({ lines: badLines(x.detail), key: 'vault.imp.bad' });
          else if (x.reason === 'invalid_id_prefix') setErr({ key: 'vault.err.name' });
          else setBad({ lines: [], ...importErrorCopy(x.reason, x.detail) });
        },
      );
    }, prefix ? PREVIEW_DELAY_MS : 0);
    return () => { live = false; clearTimeout(tm); };
  }, [ref, env, prefix, prefixOk, result]);

  const sel = selected ?? new Set<string>();
  const isShared = preview?.shared ?? (shared?.has(env) ?? false);
  const n = shown ? writeCount(shown, sel, true) : 0;
  const blocker: CopyKey | null = !preview ? 'vault.imp.wait' : importBlocker(preview, sel, update) ?? (n === 0 ? 'vault.imp.done.none' : null);
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
    if (running.current || !preview || !pair) return;
    if (blocker) {
      if (blocker === 'imp.err.taken') { setMoreOpen(true); setTimeout(() => prefixRef.current?.focus(), 40); }
      if (blocker === 'imp.err.conflict') setMoreOpen(true);
      setErr(blocker === 'vault.imp.wait' ? null : { key: blocker });
      return;
    }
    running.current = true; setBusy(true); setErr(null);
    try {
      const out = await call('secret_import', {
        import_ref: ref, project: pair.project, environment: pair.environment, ...(prefix ? { id_prefix: prefix } : {}),
        selected: preview.entries.filter((e) => sel.has(e.name)).map((e) => e.name), update,
      });
      done.current = true;
      const written = out.entries.filter((e) => e.action === 'created' || e.action === 'new_version').length;
      setResult(out);
      announce(t(out.shared ? 'vault.imp.done.shared' : 'vault.imp.done', { n: written }));
      toast(t('vault.toast.imported', { n: written }), 'ok');
      onDone();
    } catch (e) {
      const x = toIpcError(e);
      setErr(importErrorCopy(x.reason, x.detail));
    } finally { running.current = false; setBusy(false); }
  };

  if (result) {
    const written = result.entries.filter((e) => e.action === 'created' || e.action === 'new_version').length;
    const rows = result.entries.filter((e) => resultKey(e));
    return (
      <Dialog open title={t('vault.imp.title')} onClose={onClose} size="md"
        description={written === 0 ? t('vault.imp.done.none') : t(result.shared ? 'vault.imp.done.shared' : 'vault.imp.done', { n: written })}
        footer={<Button tone="primary" onClick={onClose}>{t('act.done')}</Button>}>
        {rows.length > 0 && (
          <ul className="rows vault-imp-rows" aria-label={t('vault.imp.items')}>
            {rows.map((e) => (
              <li key={e.name} className="srow">
                <span className="srow-main"><span className="srow-title mono">{e.id}</span></span>
                <Badge tone="ok">{t(resultKey(e) as CopyKey)}</Badge>
              </li>
            ))}
          </ul>
        )}
        <p className="vault-note">{t('vault.imp.left')}{result.shared ? `. ${t('vault.imp.left.team')}` : ''}</p>
      </Dialog>
    );
  }

  const forced = shown?.entries.some((e) => isForced(e, sel.has(e.name))) ?? false;
  const blockedBy = shown?.entries.find((e) => sel.has(e.name) && e.blocked_by && plannedAction(e, true, update) !== 'unchanged');
  const label = n > 0 ? t(isShared ? 'vault.imp.go.shared' : 'vault.imp.go', { n }) : t('vault.imp.go.none');
  return (
    <Dialog open title={t('vault.imp.title')} description={<><span className="mono">{file.name}</span> · {t('vault.imp.sub')}</>} onClose={onClose} busy={busy} size="md" onSubmit={() => void run()}
      footer={<>
        <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
        {!bad && <Button tone="primary" type="submit" busy={busy} blocked={blocker !== null}
          onBlocked={() => void run()}>{label}</Button>}
      </>}>
      {pairs.length === 0 ? <Banner tone="info">{t('vault.noPlace.text')}</Banner> : pairs.length > 1 && (
        <SelectField label={t('vault.add.place')} value={env} options={pairs.map((p) => ({ value: p.key, label: placeText(p.key) }))}
          onChange={(v) => { setEnv(v); setErr(null); }} />
      )}
      {isShared && <p className="vault-note">{t('vault.imp.shared')}</p>}
      {bad ? (
        <>
          <Banner tone="warn">{t(bad.key, bad.vars)}</Banner>
          {bad.lines.length > 0 && (
            <ul className="rows" aria-label={t('vault.imp.items')}>
              {bad.lines.map((b) => (
                <li key={`${b.line}-${b.reason}`} className="srow">
                  <span className="srow-main"><span className="srow-title">{t('imp.bad.line', { line: b.line })}</span><span className="srow-meta">{t(badLineKey(b.reason))}</span></span>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : !shown ? <SkeletonRows n={3} /> : shown.entries.length === 0 ? <EmptyState compact icon="file" title={t('vault.imp.none')} /> : (
        <div className="field">
          <div className="field-label"><span id="vault-imp-label">{t('vault.imp.items')}</span></div>
          <ul className="rows vault-imp-rows" aria-labelledby="vault-imp-label">
            {shown.entries.map((e) => {
              const on = sel.has(e.name);
              const tag = plannedKey(plannedAction(e, on, update));
              const warn = on && ((e.state === 'different' && !update) || e.state === 'elsewhere' || !!e.blocked_by);
              return (
                <li key={e.name} className={'srow vault-imp-row' + (on ? ' is-on' : '')}>
                  <button type="button" className="vault-imp-toggle" aria-pressed={on} aria-label={t('vault.imp.toggle.aria', { name: e.name })} onClick={() => toggle(e.name)}>
                    <span className="check-box" aria-hidden="true"><Icon name="check" size={12} /></span>
                  </button>
                  <span className="srow-main">
                    <span className="srow-title mono">{e.name}</span>
                    <span className="srow-meta">{e.id !== e.name.toLowerCase() && <span className="mono">{e.id} · </span>}{t(whyKey(e.why))}</span>
                  </span>
                  {tag && <Badge tone={warn ? 'warn' : on ? 'accent' : 'neutral'}>{t(tag)}</Badge>}
                </li>
              );
            })}
          </ul>
          {shown.empty_lines.length > 0 && <div className="field-note">{t('vault.imp.empty', { n: shown.empty_lines.length })}</div>}
          {blockedBy?.blocked_by && <div className="field-note is-error">{t('vault.imp.blocked', { conn: blockedBy.blocked_by })}</div>}
          {forced && <div className="field-note is-warn">{t('vault.imp.forced')}</div>}
        </div>
      )}
      {shown && (hasDifferent || hasTaken || !!prefix) && (
        <More label={t('vault.imp.more.hint')} open={moreOpen || !prefixOk} onToggle={setMoreOpen}>
          {hasDifferent && <Checkbox checked={update} onChange={(v) => { setUpdate(v); setErr(null); }}>{t('vault.imp.update')}</Checkbox>}
          <TextField label={t('vault.imp.prefix')} help={t('vault.imp.prefix.help')} mono value={prefix} inputRef={prefixRef} maxLength={63}
            placeholder={`${splitEnv(env)?.environment ?? 'dev'}.`} error={!prefixOk ? t('vault.err.name') : null} onChange={(v) => { setPrefix(v); setErr(null); }} />
        </More>
      )}
      {err && <Banner tone="danger">{t(err.key, err.vars)}</Banner>}
    </Dialog>
  );
}
