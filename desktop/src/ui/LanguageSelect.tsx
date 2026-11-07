import { useRef, useState } from 'react';
import { t, type Locale } from '../copy';
import { useApp } from './app';
import { SelectField } from './controls';

/** Language is a non-secret preference saved by the core, including before vault creation.
 * A failed write keeps the current language and every field on screen. */
export function LanguageSelect({ compact = false }: { compact?: boolean }) {
  const { language, setLanguage } = useApp();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const running = useRef(false);
  const change = async (value: string) => {
    if (running.current || !['ko', 'en', 'system'].includes(value)) return;
    running.current = true;
    setBusy(true); setFailed(false);
    try { await setLanguage(value as Locale | 'system'); }
    catch { setFailed(true); }
    finally { running.current = false; setBusy(false); }
  };
  return (
    <div className={'language-choice' + (compact ? ' is-compact' : '')}>
      <SelectField label={t('language.label')} hideLabel={compact} value={language}
        disabled={busy} aria-busy={busy || undefined} onChange={(v) => void change(v)}
        error={failed ? t('language.error') : null}
        options={[
          { value: 'system', label: t('language.system') },
          { value: 'ko', label: t('language.ko.native') },
          { value: 'en', label: t('language.en.native') },
        ]} />
    </div>
  );
}
