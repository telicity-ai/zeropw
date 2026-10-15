import type { Ref } from 'react';
import { t } from '../copy';
import { ri, useApp } from '../ui/context';

export function Welcome({ visible, onStart, onJoin, startRef }: {
  visible: boolean; onStart(): void; onJoin(): void; startRef: Ref<HTMLButtonElement>;
}) {
  const { field } = useApp();
  return (
    <section className={'hero' + (visible ? ' in' : ' away')} aria-labelledby="hero-title" inert={!visible}>
      <h1 className="r" style={ri(0)} id="hero-title" tabIndex={-1}>
        <span>{t('welcome.title1')}</span><br /><span className="soft">{t('welcome.title2')}</span>
      </h1>
      <p className="r" style={ri(1)}>{t('welcome.sub')}</p>
      <div className="actions r" style={ri(2)}>
        <button className="btn btn-primary" type="button" ref={startRef} onClick={onStart}
          onPointerEnter={() => field.excite(0.35)} onPointerLeave={() => field.excite(0)}>
          <span>{t('welcome.start')}</span> <span className="arrow" aria-hidden="true">→</span>
        </button>
        <button className="btn btn-ghost" type="button" onClick={onJoin}>{t('welcome.join')}</button>
      </div>
    </section>
  );
}
