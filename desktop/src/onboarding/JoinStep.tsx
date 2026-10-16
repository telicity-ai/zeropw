import { useEffect, useRef, useState, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { InvitePreview } from '../ipc/contract';
import { invitePreviewErrorKey } from '../lib/reasons';
import { defaultLocalName, formatCountdown, formatFingerprint, isInviteLink, parseLocalName } from '../lib/validators';
import { ri, useApp } from '../ui/context';
import { Callout } from '../ui/form';
import { Sigil } from '../ui/pixels';
import { BackButton, StepFrame, type FrameState } from './StepFrame';

export interface JoinPlan { ref: string; preview: InvitePreview; project: string; environment: string; local: string }
interface Held { ref: string; preview: InvitePreview; fromLink: boolean }

const discard = (ref: string) => { call('onetime_discard', { ref }).catch(() => undefined); };

/** Join path: paste the link (or open a zeropw://join link) → preview → create the vault → join.
 *  Nothing happens automatically; preview fields are untrusted and rendered as text only. */
export function JoinStep({ frame, sectionRef, incoming, onBack, onNext }: {
  frame: FrameState; sectionRef: Ref<HTMLElement>; incoming: { ref: string; preview: InvitePreview } | null;
  onBack(): void; onNext(plan: JoinPlan): void;
}) {
  const { field, desktop, toast } = useApp();
  const [link, setLink] = useState('');
  const [err, setErr] = useState<CopyKey | null>(null);
  const [held, setHeld] = useState<Held | null>(null);
  const [local, setLocal] = useState('');
  const [localErr, setLocalErr] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const heldRef = useRef<Held | null>(null);
  const seq = useRef(0);
  const linkRef = useRef<HTMLInputElement>(null);
  const previewRef = useRef<HTMLDivElement>(null);

  const hold = (h: Held | null) => {
    const old = heldRef.current;
    if (old && old.ref !== h?.ref) discard(old.ref);
    heldRef.current = h; setHeld(h);
    if (h) {
      setLocal(defaultLocalName(h.preview.inviter)); setLocalErr(false);
      field.chipText('peer', `${t('join.pv.picture')} · ${h.preview.inviter.slice(0, 4)}`);
      field.set('peer', 1); field.ripple(0.06);
    } else {
      field.set('peer', 0.7);
    }
  };

  // a deep link arrived: show its preview without the link text
  useEffect(() => {
    if (!incoming) return;
    setLink(''); setErr(incoming.preview.expired ? 'join.err.expired' : null);
    if (incoming.preview.expired) { discard(incoming.ref); hold(null); return; }
    hold({ ref: incoming.ref, preview: incoming.preview, fromLink: true });
  }, [incoming]); // only when a new deep link arrives

  const onLink = (v: string) => {
    setLink(v);
    const text = v.trim(), n = ++seq.current;
    if (!text) { setErr(null); hold(null); return; }
    if (!isInviteLink(text)) { setErr('join.err'); hold(null); return; }
    setErr(null);
    call('team_invite_preview', { text }).then(
      (r) => {
        if (n !== seq.current) { discard(r.ref); return; }
        if (r.preview.expired) { discard(r.ref); setErr('join.err.expired'); hold(null); return; }
        hold({ ref: r.ref, preview: r.preview, fromLink: false });
      },
      (e) => {
        if (n !== seq.current) return;
        setErr(invitePreviewErrorKey(toIpcError(e).reason));
        hold(null);
      },
    );
  };

  // remaining time ticks while the preview is on screen
  useEffect(() => {
    if (!held || !frame.active) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [held, frame.active]);

  const paste = () => {
    // the webview cannot read the clipboard; this fills a synthetic link in the browser review build
    const b = new Uint8Array(488);
    globalThis.crypto.getRandomValues(b);
    onLink('zeropw://join#' + [...b].map((x) => 'abcdefghijklmnopqrstuvwxyz234567'[x & 31]).join(''));
    toast(t('toast.paste.mock'));
  };

  const back = () => { seq.current++; setLink(''); setErr(null); hold(null); onBack(); };

  const next = () => {
    const h = heldRef.current;
    if (!h) { linkRef.current?.focus(); return; }
    const parsed = parseLocalName(local);
    if (!parsed) { setLocalErr(true); return; }
    heldRef.current = null; setHeld(null); seq.current++; setLink(''); setErr(null);   // the plan owns the reference now
    onNext({ ref: h.ref, preview: h.preview, project: parsed.project, environment: parsed.environment, local: local.trim() });
  };

  const p = held?.preview;
  const left = p ? Date.parse(p.expires_at) - now : 0;
  const addr = p ? (p.addresses[0] ?? '') + (p.addresses.length > 1 ? ' ' + t('join.pv.more', { n: p.addresses.length - 1 }) : '') : '';

  return (
    <StepFrame name="join" frame={frame} sectionRef={sectionRef} title={t('join.title')} lead={t('join.sub')}
      nav={<>
        <BackButton onClick={back} label={t('join.back')} />
        <button className="btn btn-primary" type="button" aria-disabled={!held} onClick={next}>
          <span>{t('join.next')}</span> <span className="arrow" aria-hidden="true">→</span>
        </button>
      </>}>
      <div className="field r" style={ri(2)}>
        <div className="label"><label htmlFor="ob-join-link">{t('join.field')}</label></div>
        <div className="input mono" data-invalid={err ? '' : undefined}>
          <input type="password" id="ob-join-link" ref={linkRef} value={link} placeholder="zeropw://join#…" autoComplete="off" spellCheck={false}
            aria-invalid={err ? true : undefined} aria-describedby="ob-join-err" onChange={(e) => onLink(e.target.value)} />
          {!desktop && <span className="suffix"><button className="icon-btn" type="button" onClick={paste}>{t('join.paste')}</button></span>}
        </div>
        <div className="help err" id="ob-join-err" hidden={!err}>{err ? t(err) : ''}</div>
        {held?.fromLink && <div className="help">{t('join.fromLink')}</div>}
      </div>
      <div className={'reveal-wrap' + (held ? ' on' : '')} inert={!held}>
        <div>
          {p && (
            <>
              <div className="preview" ref={previewRef} tabIndex={-1} role="region" aria-label={t('join.title')}>
                <div className="sigil"><Sigil fp={p.inviter} /><span className="cap">{t('join.pv.picture')}</span></div>
                <dl className="kv">
                  <dt>{t('join.pv.code')}</dt><dd>{formatFingerprint(p.inviter)}</dd>
                  <dt>{t('join.pv.env')}</dt><dd>{p.env_id.slice(0, 10) + '…'}</dd>
                  <dt>{t('join.pv.role')}</dt><dd>{p.role === 'admin' ? t('inv.role.admin') : t('inv.role.user')}</dd>
                  <dt>{t('join.pv.addr')}</dt><dd>{addr}</dd>
                  <dt>{t('join.pv.left')}</dt><dd>{formatCountdown(left)}</dd>
                </dl>
              </div>
              <div className="field" style={{ marginTop: 12 }}>
                <div className="label"><label htmlFor="ob-join-local">{t('join.local')}</label></div>
                <div className="input mono" data-invalid={localErr ? '' : undefined}>
                  <input id="ob-join-local" value={local} spellCheck={false} autoComplete="off" aria-invalid={localErr ? true : undefined}
                    aria-describedby="ob-join-local-err" onChange={(e) => { setLocal(e.target.value); setLocalErr(false); }} />
                </div>
                <div className="help err" id="ob-join-local-err" hidden={!localErr}>{localErr ? t('join.local.err') : ''}</div>
              </div>
              <Callout>{t('join.check')}</Callout>
            </>
          )}
        </div>
      </div>
    </StepFrame>
  );
}
