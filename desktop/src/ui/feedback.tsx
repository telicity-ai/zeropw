// State and status presentation: banners, empty and error states, badges, dots, key/value
// lists and fingerprints. Untrusted text (names from other Macs, record fields) is rendered as
// text only.

import type { ReactNode } from 'react';
import { t } from '../copy';
import type { IpcError } from '../ipc/client';
import { Button } from './controls';
import { Icon, type IconName } from './icons';

export type Tone = 'info' | 'ok' | 'warn' | 'danger' | 'neutral' | 'accent';

const TONE_ICON: Record<Tone, IconName> = { info: 'info', ok: 'check', warn: 'alert', danger: 'alert', neutral: 'info', accent: 'info' };

/** A message inside a pane or dialog. `action` is one button at the end. */
export function Banner({ tone = 'info', title, children, action, icon, compact }: {
  tone?: Tone; title?: ReactNode; children?: ReactNode; action?: ReactNode; icon?: IconName; compact?: boolean;
}) {
  return (
    <div className={`banner banner-${tone}` + (compact ? ' is-compact' : '')} role={tone === 'danger' || tone === 'warn' ? 'alert' : 'note'}>
      <Icon name={icon ?? TONE_ICON[tone]} size={15} />
      <div className="banner-body">
        {title && <strong className="banner-title">{title}</strong>}
        {children && <div className="banner-text">{children}</div>}
      </div>
      {action && <div className="banner-action">{action}</div>}
    </div>
  );
}

export function EmptyState({ icon = 'vault', title, children, action, compact }: { icon?: IconName; title: ReactNode; children?: ReactNode; action?: ReactNode; compact?: boolean }) {
  return (
    <div className={'empty' + (compact ? ' is-compact' : '')}>
      <span className="empty-icon" aria-hidden="true"><Icon name={icon} size={compact ? 18 : 22} /></span>
      <h2 className="empty-title">{title}</h2>
      {children && <p className="empty-text">{children}</p>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

/** A failed read with a retry. The reason code is shown small, never the CLI's text. */
export function LoadError({ error, onRetry, what }: { error: IpcError | null; onRetry(): void; what?: ReactNode }) {
  return (
    <div className="load-error" role="alert">
      <Icon name="alert" size={16} />
      <div>
        <p>{what ?? t('error.load')}</p>
        {error && <p className="load-error-code">{t('error.reason', { reason: error.reason })}</p>}
      </div>
      <Button size="sm" tone="ghost" icon="refresh" onClick={onRetry}>{t('act.retry')}</Button>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return <span className="spinner" role={label ? 'status' : undefined} aria-label={label} aria-hidden={label ? undefined : true} />;
}

/** Placeholder rows while the first read runs. */
export function SkeletonRows({ n = 4 }: { n?: number }) {
  return (
    <div className="skeleton" role="status" aria-label={t('state.loading')}>
      {Array.from({ length: n }, (_, i) => <div key={i} className="skeleton-row"><i /><span><b /><b /></span></div>)}
    </div>
  );
}

export function Badge({ tone = 'neutral', children, icon }: { tone?: Tone; children: ReactNode; icon?: IconName }) {
  return <span className={`badge badge-${tone}`}>{icon && <Icon name={icon} size={11} />}{children}</span>;
}

/** A status dot with its words next to it (colour never carries meaning alone). */
export function Status({ tone, children, pulse }: { tone: Tone; children: ReactNode; pulse?: boolean }) {
  return <span className={`status status-${tone}` + (pulse ? ' is-pulse' : '')}><i aria-hidden="true" />{children}</span>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}

export interface KV { k: ReactNode; v: ReactNode; mono?: boolean }

export function KeyValues({ items, dense }: { items: readonly (KV | null | false)[]; dense?: boolean }) {
  return (
    <dl className={'kv' + (dense ? ' is-dense' : '')}>
      {items.filter((x): x is KV => !!x).map((x, i) => (
        <div className="kv-row" key={i}>
          <dt>{x.k}</dt>
          <dd className={x.mono ? 'mono wrap-anywhere' : 'wrap-anywhere'} data-selectable="">{x.v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A device fingerprint in groups of four, all of it, selectable for comparison. */
export function Fingerprint({ value, short }: { value: string; short?: boolean }) {
  const text = short ? value.slice(0, 16) : value;
  const groups = text.match(/.{1,4}/g) ?? [];
  return (
    <span className="fingerprint mono" data-selectable="" aria-label={groups.join(' ')}>
      {groups.map((g, i) => <span key={i}>{g}</span>)}
    </span>
  );
}

/** A pane section with a quiet heading and optional trailing control. */
export function Section({ title, aside, children, id }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <section className="section" aria-labelledby={title && id ? id : undefined}>
      {(title || aside) && (
        <div className="section-head">
          {title && <h2 id={id}>{title}</h2>}
          {aside && <div className="section-aside">{aside}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
