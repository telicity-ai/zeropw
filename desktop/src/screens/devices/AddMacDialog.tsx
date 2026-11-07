// The Mac with the vault adds another of its owner's Macs: pick the places to share, re-
// authenticate, make the one-time pairing code (copied or shown once), then read the join
// requests every few seconds while this dialog is open and approve or refuse each requesting
// Mac after comparing its confirmation code. The code alone never joins anyone.

import { useEffect, useMemo, useRef, useState } from 'react';
import { t, type CopyKey } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { JoinRequest, LinkStatus, PairingCreated } from '../../ipc/contract';
import { envPairs, msLeft } from '../../lib/dash';
import { pairingEnvs, requestsByDevice } from '../../lib/devices';
import { poll } from '../../lib/poll';
import { formatCountdown } from '../../lib/validators';
import { placeLabel } from '../../lib/places';
import { useShell } from '../../app/shell';
import { useApp } from '../../ui/app';
import { Button, Chip, PassField, TextField } from '../../ui/controls';
import { Dialog, isAuthError, passErrorKey } from '../../ui/Dialog';
import { More } from '../../ui/disclosure';
import { Banner, Fingerprint, Section } from '../../ui/feedback';
import { useNow } from '../../ui/hooks';
import { Icon } from '../../ui/icons';
import { OneTimeValue, type Handed } from '../../ui/OneTime';
import { isDisplayName } from './states';

export const REQUESTS_POLL_MS = 3000;
export const REQUESTS_WAIT_MS = 30 * 60_000;

type Decision = { fingerprint: string; envs: string[]; approved: boolean };

export function AddMacDialog({ open, link, onClose, onChanged }: { open: boolean; link: LinkStatus | null; onClose(): void; onChanged(): void }) {
  const { toast, announce } = useApp();
  const { vault } = useShell();
  const all = useMemo(() => (vault.data ? envPairs(vault.data.listing.projects).map((p) => p.key) : []), [vault.data]);
  const [chosen, setChosen] = useState<string[] | null>(null);
  const envs = (chosen ?? all).filter((e) => all.includes(e));
  const [name, setName] = useState(t('mac.addDlg.name.default'));
  const [pass, setPass] = useState('');
  const [errs, setErrs] = useState<{ envs?: CopyKey; name?: CopyKey; pass?: CopyKey; form?: CopyKey }>({});
  const [busy, setBusy] = useState(false);
  const [made, setMade] = useState<PairingCreated | null>(null);
  const [handed, setHanded] = useState<Handed | null>(null);
  const [requests, setRequests] = useState<JoinRequest[]>([]);
  const [decided, setDecided] = useState<Decision[]>([]);
  const passRef = useRef<HTMLInputElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const running = useRef(false);
  const now = useNow(open && !!made);

  useEffect(() => {
    if (open) return;
    setPass(''); setMade(null); setHanded(null); setRequests([]); setDecided([]); setErrs({}); setChosen(null);
    setName(t('mac.addDlg.name.default'));
  }, [open]);

  // join requests, while the code is out and the dialog is open
  useEffect(() => {
    if (!open || !made) return;
    const forEnvs = pairingEnvs(made);
    const handle = poll({
      step: () => call('join_requests', { envs: forEnvs }),
      done: () => false,
      onValue: (r) => setRequests(r.requests),
      every: REQUESTS_POLL_MS,
      until: Date.now() + REQUESTS_WAIT_MS,
    });
    return () => handle.cancel();
  }, [open, made]);

  const toggle = (env: string) => {
    setChosen((xs) => { const cur = (xs ?? all); return cur.includes(env) ? cur.filter((x) => x !== env) : all.filter((x) => x === env || cur.includes(x)); });
    setErrs((x) => ({ ...x, envs: undefined }));
  };

  const create = async () => {
    if (running.current) return;
    if (made) { onClose(); return; }
    const e: typeof errs = {};
    if (!envs.length) e.envs = all.length ? 'mac.addDlg.places.err' : 'mac.addDlg.noPlaces';
    if (!isDisplayName(name)) e.name = 'mac.addDlg.name.err';
    if (!pass) e.pass = 'pass.err.empty';
    setErrs(e);
    if (e.envs) return;
    if (e.name) { setTimeout(() => nameRef.current?.focus(), 50); return; }
    if (e.pass) { passRef.current?.focus(); return; }
    running.current = true; setBusy(true);
    try {
      const out = await call('pairing_create', { envs, device_name: name.trim(), admin_passphrase: pass, ...(link?.device_name ? { name: link.device_name } : {}) });
      setMade(out);
      toast(t('mac.toast.code'), 'ok'); announce(t('mac.toast.code'));
      onChanged();
    } catch (err) {
      const ipc = toIpcError(err);
      if (isAuthError(err)) { setErrs({ pass: passErrorKey(err) }); passRef.current?.focus(); }
      else if (ipc.reason === 'invalid_name') { setErrs({ name: 'mac.addDlg.name.err' }); setTimeout(() => nameRef.current?.focus(), 50); }
      else setErrs({ form: ipc.reason === 'link_not_enrolled' ? 'mac.needEnroll' : ipc.reason === 'serve_without_link' || ipc.reason === 'serve_not_running' ? 'mac.addDlg.needRelay' : 'error.generic' });
      onChanged();
    } finally { running.current = false; setBusy(false); setPass(''); }
  };

  // decided per Mac and place: a later request for another place of the same code still shows
  const decidedKeys = new Set(decided.flatMap((d) => d.envs.map((env) => `${d.fingerprint}|${env}`)));
  const groups = requestsByDevice(requests.filter((r) => !decidedKeys.has(`${r.fingerprint}|${r.env}`)));
  const left = made ? msLeft(made.expires_at, now) : 0;
  const expired = !!made && left <= 0;

  return (
    <Dialog open={open} title={t('mac.addDlg.title')} description={made ? t('mac.code.how') : t('mac.addDlg.sub')} onClose={onClose} busy={busy}
      size="md" id="dlg-mac-add" onSubmit={() => void create()}
      footer={made
        ? <Button tone="primary" type="submit">{t('act.done')}</Button>
        : <>
          <Button tone="ghost" onClick={onClose} blocked={busy}>{t('act.cancel')}</Button>
          <Button tone="primary" type="submit" busy={busy}>{t('mac.addDlg.create')}</Button>
        </>}>
      {!made && (
        <>
          <More hint={t('mac.addDlg.more', { n: envs.length })} open={!!errs.envs || !!errs.name}>
            <div className="field">
              <div className="field-label"><span id="mac-add-places">{t('mac.addDlg.places')}</span></div>
              {all.length === 0
                ? <p className="field-note">{t(vault.data ? 'mac.addDlg.noPlaces' : 'state.loading')}</p>
                : (
                  <div className="chips" role="group" aria-labelledby="mac-add-places">
                    {all.map((env) => {
                      const [p, e] = env.split('/') as [string, string];
                      return <Chip key={env} on={envs.includes(env)} onToggle={() => toggle(env)}>{placeLabel(p, e)}</Chip>;
                    })}
                  </div>
                )}
              {errs.envs && <div className="field-note is-error" role="alert"><Icon name="alert" size={13} />{t(errs.envs)}</div>}
            </div>
            <Banner tone="info" compact>{t('mac.addDlg.share')}</Banner>
            <TextField label={t('mac.addDlg.name')} value={name} inputRef={nameRef} maxLength={64} error={errs.name ? t(errs.name) : null}
              onChange={(v) => { setName(v); setErrs((x) => ({ ...x, name: undefined })); }} />
          </More>
          <PassField value={pass} inputRef={passRef} error={errs.pass ? t(errs.pass) : null}
            onChange={(v) => { setPass(v); setErrs((x) => ({ ...x, pass: undefined })); }} />
          {errs.form && <Banner tone="danger">{t(errs.form)}</Banner>}
          <p className="field-note">{t('mac.addDlg.snapshot')}</p>
        </>
      )}
      {made && (
        <>
          <div className="mac-code">
            <div className="mac-code-head">
              <span className="field-label">{t('mac.code.label')}</span>
              <span className={'mac-code-left num' + (expired ? ' is-expired' : '')}>
                <Icon name="clock" size={12} />{expired ? t('mac.code.expired') : t('mac.code.left', { time: formatCountdown(left) })}
              </span>
            </div>
            {!expired || handed
              ? <OneTimeValue valueRef={made.ref} masked={t('mac.code.masked')} label={t('mac.code.label')} onHanded={setHanded} multiline />
              : <div className="onetime-value mono">{t('mac.code.expired')}</div>}
            <div className="mac-code-self"><span>{t('mac.self')}</span><Fingerprint value={made.fingerprint} /></div>
          </div>
          <Banner tone="warn" compact>{t('mac.code.warn')}</Banner>
          <Section title={t('mac.req.title')}>
            {groups.length === 0 && !expired && <p className="muted text-sm" role="status">{t('mac.req.wait')}</p>}
            {groups.map((g) => (
              <RequestCard key={g.fingerprint} fingerprint={g.fingerprint} envs={g.envs} attempts={g.attempts}
                onDecided={(approved) => {
                  setDecided((xs) => [...xs, { fingerprint: g.fingerprint, envs: g.envs, approved }]);
                  const msg = t(approved ? 'mac.req.approved' : 'mac.req.denied');
                  toast(msg, approved ? 'ok' : 'warn'); announce(msg);
                  onChanged();
                }} />
            ))}
            {decided.length > 0 && (
              <ul className="mac-decided" aria-label={t('mac.req.decided')}>
                {decided.map((d, i) => (
                  <li key={i}><Fingerprint value={d.fingerprint} short /><span className={d.approved ? 'is-ok' : 'is-denied'}>{t(d.approved ? 'mac.req.approved' : 'mac.req.denied')}</span></li>
                ))}
              </ul>
            )}
          </Section>
        </>
      )}
    </Dialog>
  );
}

/** One requesting Mac: its confirmation code to compare with its own screen, and approve or
 *  refuse with the administrator passphrase. */
export function RequestCard({ fingerprint, envs, attempts, onDecided }: { fingerprint: string; envs: string[]; attempts: number; onDecided(approved: boolean): void }) {
  const [pass, setPass] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const passRef = useRef<HTMLInputElement>(null);
  const decide = async (approve: boolean) => {
    if (running.current) return;
    if (!pass) { setErr('pass.err.empty'); passRef.current?.focus(); return; }
    running.current = true; setBusy(true); setErr(null);
    try {
      const out = await call(approve ? 'approve_join' : 'deny_join', { envs, fingerprint, admin_passphrase: pass });
      if (out.envs.some((e) => !e.ok)) { setErr('mac.req.failed'); return; }
      onDecided(approve);
    } catch (e) {
      setErr(passErrorKey(e));
      passRef.current?.focus();
    } finally { running.current = false; setBusy(false); setPass(''); }
  };
  return (
    <div className="mac-request card" data-fingerprint={fingerprint}
      onKeyDown={(e) => { if (e.key === 'Enter' && (e.target as HTMLElement).tagName === 'INPUT') e.preventDefault(); }}>
      <div className="mac-request-fp">
        <span className="mac-compare-label">{t('mac.req.fp')}</span>
        <Fingerprint value={fingerprint} />
        <span className="muted text-xs">{t('mac.req.meta', { n: envs.length, count: attempts })}</span>
      </div>
      <p className="field-note">{t('mac.req.check')}</p>
      <PassField value={pass} inputRef={passRef} error={err ? t(err) : null} onChange={(v) => { setPass(v); setErr(null); }} />
      <div className="row mac-request-actions">
        <Button tone="ghost" blocked={busy} onClick={() => void decide(false)}>{t('mac.req.deny')}</Button>
        <Button tone="primary" busy={busy} onClick={() => void decide(true)}>{t('mac.req.approve')}</Button>
      </div>
    </div>
  );
}
