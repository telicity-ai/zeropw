// App-wide services every screen may use: toasts, the polite live region and whether the page
// runs inside the desktop app. Screen-specific state lives in the shell (src/app/shell.ts).

import { createContext, useContext } from 'react';
import type { Locale } from '../copy';

export type ToastTone = 'info' | 'ok' | 'warn';

export interface AppApi {
  desktop: boolean;
  /** A short message at the bottom of the window; never a secret, never an input value. */
  toast(message: string, tone?: ToastTone): void;
  /** Polite live-region message for screen readers; bursts within 60 ms are joined. */
  announce(message: string): void;
  /** The language the window shows now. */
  locale: Locale;
  /** The saved preference: a language, or `system` to follow macOS. */
  language: Locale | 'system';
  /** Save a preference and translate the window without discarding open forms or sessions. */
  setLanguage(pref: Locale | 'system'): Promise<void>;
}

export const AppContext = createContext<AppApi | null>(null);

export function useApp(): AppApi {
  const api = useContext(AppContext);
  if (!api) throw new Error('AppContext missing');
  return api;
}
