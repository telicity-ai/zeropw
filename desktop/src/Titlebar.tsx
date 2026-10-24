import { t } from './copy';
import { Logo } from './ui/pixels';
import type { Pill } from './ui/context';

export function Titlebar({ desktop, motionOn, onToggleMotion, pill }: {
  desktop: boolean; motionOn: boolean; onToggleMotion(): void; pill: Pill;
}) {
  const cls = 'status-pill' + (pill.kind === 'live' || pill.kind === 'stopped' || pill.kind === 'held' ? ' ' + pill.kind : '');
  return (
    <header className={'titlebar' + (desktop ? ' native' : '')} data-tauri-drag-region="">
      {!desktop && <div className="lights" aria-hidden="true"><i /><i /><i /></div>}
      <div className="brand" data-tauri-drag-region=""><Logo /><span lang="en">{t('app.brand')}</span></div>
      <div className="tb-spacer" data-tauri-drag-region="" />
      <button className="icon-tb" type="button" aria-pressed={!motionOn} aria-label={t('top.motion.aria')} onClick={onToggleMotion}>
        <svg viewBox="0 0 10 10" aria-hidden="true"><rect x="1.5" y="1" width="2.4" height="8" fill="currentColor" /><rect x="6.1" y="1" width="2.4" height="8" fill="currentColor" /></svg>
      </button>
      <span className={cls}>
        <span className="dot" aria-hidden="true" />
        <span>
          {pill.kind === 'none' && t('top.status.none')}
          {pill.kind === 'off' && t('top.status.off')}
          {pill.kind === 'stopped' && t('top.status.stopped')}
          {pill.kind === 'held' && t('top.status.held')}
          {pill.kind === 'live' && <>{t('top.status.ready')} {pill.addr && <span className="mono">{pill.addr}</span>}</>}
        </span>
      </span>
    </header>
  );
}
