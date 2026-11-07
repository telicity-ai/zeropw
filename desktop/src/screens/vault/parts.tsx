// Small pieces of the vault screens.

import { useEffect, useRef } from 'react';
import { t, type CopyKey } from '../../copy';
import { Badge, type Tone } from '../../ui/feedback';

/** An SSH public key (not a secret): selectable text, so it can go onto a server. It takes focus
 *  when it replaces a form inside an open dialog. */
export function PublicKeyBox({ publicKey, fingerprint, autoFocus }: { publicKey: string; fingerprint?: string | null; autoFocus?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!autoFocus) return;
    const id = setTimeout(() => ref.current?.focus({ preventScroll: true }), 40);
    return () => clearTimeout(id);
  }, [autoFocus]);
  return (
    <div className="stack-sm">
      <div className="field-label"><span id="vault-pub-label">{t('vault.pub')}</span></div>
      <div ref={ref} className="vault-pub mono" role="textbox" aria-readonly="true" aria-labelledby="vault-pub-label" tabIndex={0} data-selectable="">{publicKey}</div>
      {fingerprint && <div className="vault-note"><span>{t('vault.pub.fp')} </span><span className="mono" data-selectable="">{fingerprint}</span></div>}
      <p className="vault-note">{t('vault.pub.help')}</p>
    </div>
  );
}

const STATUS: Record<string, { key: CopyKey; tone: Tone }> = {
  active: { key: 'vault.st.active', tone: 'ok' },
  staged: { key: 'vault.st.staged', tone: 'info' },
  retired: { key: 'vault.st.retired', tone: 'neutral' },
  revoked: { key: 'vault.st.revoked', tone: 'danger' },
};

/** A version's status as a badge; an unknown status stays as the CLI wrote it. */
export function VersionBadge({ status }: { status: string }) {
  const s = STATUS[status];
  return <Badge tone={s?.tone ?? 'neutral'}>{s ? t(s.key) : status}</Badge>;
}
