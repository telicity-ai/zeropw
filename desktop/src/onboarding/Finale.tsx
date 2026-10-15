import { useEffect, useState, type Ref } from 'react';
import { t, type CopyKey } from '../copy';
import { call } from '../ipc/client';
import type { InvitePreview, NetInterface, Settings } from '../ipc/contract';
import { ListenSetup } from '../dashboard/ListenSetup';
import { parseListen } from '../lib/dash';
import { ri, useApp } from '../ui/context';

export type JoinOutcome = 'idle' | 'pending' | 'ok' | 'failed';
interface TileData { k: string; v: string; s: string; st: 'on' | 'idle' | 'warn' }

export function Finale(props: {
  visible: boolean; titleRef: Ref<HTMLHeadingElement>;
  project: { name: string; environments: string[] } | null;
  agent: { id: string; where: 'other' | 'same' } | null;
  join: { preview: InvitePreview; local: string } | null;
  joinOutcome: JoinOutcome;
  /** Why the join failed, kept on screen (the toast goes away). */
  joinError?: CopyKey | null;
  onDashboard(): void; onInvite(): void;
}) {
  const { visible, titleRef, project, agent, join, joinOutcome, joinError, onDashboard, onInvite } = props;
  const { toast } = useApp();
  // after joining: team sync runs only with other-device access on, so offer it right here
  const [listen, setListen] = useState<{ settings: Settings; interfaces: NetInterface[] } | null>(null);
  useEffect(() => {
    if (joinOutcome !== 'ok') return;
    let live = true;
    Promise.all([call('settings_get'), call('net_interfaces').catch(() => [] as NetInterface[])]).then(
      ([s, i]) => { if (live && !parseListen(s.team_listen)) setListen({ settings: s, interfaces: i }); },
      () => undefined,
    );
    return () => { live = false; };
  }, [joinOutcome]);

  const role = join?.preview.role === 'admin' ? t('inv.role.admin') : t('inv.role.user');
  const joinSub = joinOutcome === 'ok' ? t('done.tile.joined') : joinOutcome === 'failed' ? t('done.tile.joinFailed') : t('done.tile.joining');
  // No service connection is made during onboarding, so the agent has no permission yet.
  const tiles: TileData[] = join ? [
    { k: t('done.tile.vault'), v: t('done.tile.vault.v'), s: t('done.tile.vault.s'), st: 'on' },
    { k: t('done.tile.join'), v: join.local, s: joinSub, st: joinOutcome === 'failed' ? 'warn' : 'on' },
    { k: t('done.tile.role'), v: role, s: '', st: 'on' },
    { k: t('done.tile.conn'), v: t('done.tile.afterSync'), s: '', st: 'idle' },
    { k: t('done.tile.agent'), v: t('done.tile.none'), s: t('done.tile.addLater'), st: 'idle' },
  ] : [
    { k: t('done.tile.vault'), v: t('done.tile.vault.v'), s: t('done.tile.vault.s'), st: 'on' },
    { k: t('done.tile.project'), v: project?.name ?? t('done.tile.none'), s: project ? project.environments.join(' · ') : t('done.tile.addLater'), st: project ? 'on' : 'idle' },
    { k: t('done.tile.conn'), v: t('done.tile.none'), s: t('done.tile.addLater'), st: 'idle' },
    {
      k: t('done.tile.agent'), v: agent ? agent.id : t('done.tile.none'),
      s: agent ? t('done.tile.agent.nogrant') : t('done.tile.addLater'),
      st: !agent ? 'idle' : agent.where === 'same' ? 'warn' : 'on',
    },
    { k: t('done.tile.team'), v: t('done.tile.team.off'), s: '', st: 'idle' },
  ];
  return (
    <section className={'finale' + (visible ? ' in' : ' away') + (join ? ' tall' : '')} aria-labelledby="t-done" inert={!visible}>
      <h1 className="r" style={ri(0)} id="t-done" tabIndex={-1} ref={titleRef}>{t('done.title')}</h1>
      <p className="r" style={ri(1)}>{join ? t('done.msg.join') : t('done.msg.none')}</p>
      <div className="tiles r" style={ri(2)}>
        {tiles.map((x) => (
          <div key={x.k} className={'tile' + (x.st === 'on' ? '' : ' ' + x.st)}>
            <div className="k"><i aria-hidden="true" />{x.k}</div>
            <div className="v">{x.v}{x.s && <small>{x.s}</small>}</div>
          </div>
        ))}
      </div>
      {join && joinOutcome === 'failed' && joinError && <div className="foot warn r" style={ri(2)} role="status">{t(joinError)}</div>}
      {join && listen && (
        <ListenSetup id="done-listen" className="finale-listen" note={false} settings={listen.settings} interfaces={listen.interfaces}
          onDone={() => { setListen(null); toast(t('toast.listen.on')); }} />
      )}
      <div className="actions r" style={ri(3)}>
        <button className="btn btn-primary" type="button" onClick={onDashboard}><span>{t('done.dash')}</span> <span className="arrow" aria-hidden="true">→</span></button>
        {!join && <button className="btn btn-ghost" type="button" onClick={onInvite}>{t('done.invite')}</button>}
      </div>
      <div className="foot r" style={ri(4)}>{t('done.backup')}</div>
    </section>
  );
}
