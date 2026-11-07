// Requests waiting for approval. Everything the gateway bound an approval to (method, full path
// and query, agent, connection, body size, type, hash and preview) is shown as text; approving
// is re-authenticated and allows that one request.

import { useState } from 'react';
import { t } from '../../copy';
import { call, toIpcError } from '../../ipc/client';
import type { ApprovalView } from '../../lib/dash';
import { shortTime } from '../../lib/format';
import { useApp } from '../../ui/app';
import { Button } from '../../ui/controls';
import { ConfirmDialog } from '../../ui/Dialog';
import { Badge, Banner, EmptyState, KeyValues, LoadError, Section, SkeletonRows } from '../../ui/feedback';
import type { Load } from '../../ui/hooks';

function bodySummary(a: ApprovalView): string {
  if (!a.bodyBytes) return t('appr.body.none');
  return [t('appr.body.size', { n: a.bodyBytes }), a.contentType, a.bodyHash].filter(Boolean).join(' · ');
}

function ApprovalDetails({ a }: { a: ApprovalView }) {
  return (
    <>
      <KeyValues dense items={[
        { k: t('appr.req'), v: `${a.method} ${a.target}`, mono: true },
        { k: t('appr.agent'), v: a.caller, mono: true },
        { k: t('appr.conn'), v: a.connection, mono: true },
        { k: t('appr.when'), v: shortTime(a.created_at) },
        a.origin ? { k: t('appr.origin'), v: a.origin, mono: true } : null,
        { k: t('appr.body'), v: bodySummary(a) },
      ]} />
      {a.bodyPreview !== null && a.bodyPreview !== '' && (
        <div className="stack-sm">
          <div className="field-label"><span id="appr-body-lbl">{t('appr.body.preview')}</span>{a.bodyTruncated && <span className="field-aside">{t('appr.body.cut')}</span>}</div>
          <pre className="code" role="region" aria-labelledby="appr-body-lbl" tabIndex={0}>{a.bodyPreview}</pre>
        </div>
      )}
      {!!a.bodyBytes && a.bodyPreview === null && <p className="muted text-sm">{t('appr.body.binary')}</p>}
    </>
  );
}

export function ApprovalsTab({ load }: { load: Load<ApprovalView[]> }) {
  const { toast } = useApp();
  const [open, setOpen] = useState<ApprovalView | null>(null);
  const list = load.data;
  return (
    <>
      <Banner tone="neutral">{t('appr.intro')}</Banner>
      <Section title={t('appr.list')} id="dev-appr-h">
        {!list && load.error ? <LoadError error={load.error} onRetry={load.reload} />
          : !list ? <SkeletonRows n={2} />
            : list.length === 0 ? <EmptyState icon="check" title={t('appr.empty.title')} compact>{t('appr.empty.body')}</EmptyState>
              : (
                <ul className="rows" aria-labelledby="dev-appr-h">
                  {list.map((a) => (
                    <li key={a.digest} className="srow dev-appr">
                      <Badge tone="warn">{a.method}</Badge>
                      <div className="srow-main">
                        <span className="srow-title mono wrap-anywhere" data-selectable="">{a.target}</span>
                        <span className="srow-meta">{[a.caller, a.connection, shortTime(a.created_at), bodySummary(a)].join(' · ')}</span>
                      </div>
                      <div className="srow-end">
                        <Button size="sm" tone="primary" aria-label={t('appr.approve.aria', { req: `${a.method} ${a.target}` })} onClick={() => setOpen(a)}>{t('appr.approve')}</Button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
      </Section>
      <ConfirmDialog open={!!open} title={t('appr.title')} description={t('appr.sub')} confirmLabel={t('appr.confirm')} needPass size="md"
        onClose={() => setOpen(null)}
        errorFor={(e) => {
          const r = toIpcError(e).reason;
          if (r === 'approval_not_pending' || r === 'approval_not_found') { load.reload(); return 'appr.err.gone'; }
          return null;
        }}
        run={async (pass) => {
          if (!open) return;
          await call('approvals_approve', { digest: open.digest, admin_passphrase: pass });
          toast(t('appr.toast.done'), 'ok'); setOpen(null); load.reload();
        }}>
        {open && <ApprovalDetails a={open} />}
      </ConfirmDialog>
    </>
  );
}
