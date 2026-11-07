// 개발자: agents and their permissions with the in-app terminal, requests waiting for approval,
// and sharing a place with another person. The tab follows the route's view; an intent opens its
// tab first, then the tab handles it.

import { useEffect } from 'react';
import { t } from '../../copy';
import { call } from '../../ipc/client';
import { pendingApprovals } from '../../lib/dash';
import { useShell, type Intent } from '../../app/shell';
import { Segmented } from '../../ui/controls';
import { useLoad } from '../../ui/hooks';
import { PaneHeader } from '../../ui/layout';
import { AgentsTab } from './AgentsTab';
import { ApprovalsTab } from './ApprovalsTab';
import { asTab, intentTab, type DevTab } from './common';
import { SharingTab } from './SharingTab';

export function DeveloperPage({ intent }: { intent?: Intent }) {
  const { route, go, tick, activity } = useShell();
  const tab = asTab(route.view);
  const want = intentTab(intent);
  useEffect(() => {
    if (want && want !== tab) go('developer', { view: want, intent });
  }, [want, tab, intent, go]);
  // the approvals tab and its count read the same list
  const approvals = useLoad(async () => pendingApprovals((await call('approvals_list')).approvals), [tick, activity]);
  const count = approvals.data?.length ?? 0;
  const shown: DevTab = want ?? tab;
  return (
    <div className="page dev-page">
      <div className="pane">
        <PaneHeader title={t('nav.developer')} actions={(
          <Segmented<DevTab> label={t('agent.tabs')} size="sm" value={tab} onChange={(v) => go('developer', { view: v })}
            options={[
              { value: 'agents', label: t('agent.tab.agents'), icon: 'user' },
              { value: 'approvals', label: count ? t('agent.tab.approvals.n', { n: count }) : t('agent.tab.approvals'), icon: 'check' },
              { value: 'sharing', label: t('agent.tab.sharing'), icon: 'share' },
            ]} />
        )} />
        <div className="pane-body">
          <div className="pane-content dev-content" key={shown}>
            {shown === 'agents' && <AgentsTab intent={want === 'agents' ? intent : undefined} />}
            {shown === 'approvals' && <ApprovalsTab load={approvals} />}
            {shown === 'sharing' && <SharingTab intent={want === 'sharing' ? intent : undefined} />}
          </div>
        </div>
      </div>
    </div>
  );
}
