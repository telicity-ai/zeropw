import type { ReactNode } from 'react';
import { t, type CopyKey } from '../copy';

// Small building blocks shared by the dashboard pages (DESIGN.md §5.3): a section title with its
// actions, glass list cards, rows (name, mono detail, status dot, actions on the right) and the
// one-line empty state with at most one primary button. Every string shown here is rendered as
// text; rows never interpret what the core or a teammate wrote.

export function SectionHead({ id, title, children }: { id?: string; title: string; children?: ReactNode }) {
  return (
    <div className="sec-head">
      <h2 className="section-title" id={id}>{title}</h2>
      {children !== undefined && <div className="sec-acts">{children}</div>}
    </div>
  );
}

export type Dot = 'on' | 'idle' | 'warn' | 'live';

export function Row({ dot = 'idle', name, meta, mono, tag, children, sub }: {
  dot?: Dot; name: ReactNode; meta?: ReactNode; mono?: boolean; tag?: ReactNode; children?: ReactNode; sub?: ReactNode;
}) {
  return (
    <li className="list-row">
      <span className={'stdot' + (dot === 'idle' ? '' : ' ' + dot)} aria-hidden="true" />
      <div className="main">
        <div className={'name' + (mono ? ' mono' : '')}>{name}{tag}</div>
        {meta !== undefined && meta !== '' && <div className="meta">{meta}</div>}
        {sub}
      </div>
      {children !== undefined && <div className="acts">{children}</div>}
    </li>
  );
}

export function Tag({ children, warn }: { children: ReactNode; warn?: boolean }) {
  return <span className={'tag' + (warn ? ' warn' : '')}>{children}</span>;
}

export function Empty({ text, action }: { text: string; action?: ReactNode }) {
  return (
    <div className="empty">
      <span className="line"><span className="px" aria-hidden="true" />{text}</span>
      {action}
    </div>
  );
}

/** A glass card holding a list, an empty line, or the loading/failed line. */
export function ListCard<T>({ items, failed, empty, emptyAction, children, label }: {
  items: readonly T[] | null; failed?: boolean; empty: CopyKey; emptyAction?: ReactNode; children(items: readonly T[]): ReactNode; label?: string;
}) {
  return (
    <div className="glass">
      {items === null
        ? <Empty text={failed ? t('error.load') : t('boot.loading')} />
        : items.length === 0
          ? <Empty text={t(empty)} action={emptyAction} />
          : <ul className="list" aria-label={label}>{children(items)}</ul>}
    </div>
  );
}

/** Join the parts of a row's detail line, skipping empty ones. */
export const metaLine = (...parts: Array<string | null | undefined | false>): string => parts.filter((p): p is string => !!p).join(' · ');
