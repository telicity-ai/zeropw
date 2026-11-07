// Every visible string in the app, in Korean and English, grouped by area. Components never
// hard-code display text: they call t() with a key, and t() reads the table of the current
// locale. Each area's English table is typed against its Korean one, so a key missing from
// either language fails to compile; test/copy.test.ts checks that placeholders match.

import { ACTIVITY, ACTIVITY_EN } from './activity';
import { BACKEND, BACKEND_EN } from './backend';
import { COMMON, COMMON_EN } from './common';
import { DEVELOPER, DEVELOPER_EN } from './developer';
import { DEVICES, DEVICES_EN } from './devices';
import { ONBOARDING, ONBOARDING_EN } from './onboarding';
import { SERVICES, SERVICES_EN } from './services';
import { SETTINGS, SETTINGS_EN } from './settings';
import { VAULT, VAULT_EN } from './vault';

export type Locale = 'ko' | 'en';
export const LOCALES: readonly Locale[] = ['ko', 'en'];

/** Each area's tables, by name (tests check that no key is defined twice). */
export const COPY_AREAS = { BACKEND, COMMON, VAULT, DEVICES, SERVICES, DEVELOPER, ACTIVITY, SETTINGS, ONBOARDING } as const;
export const COPY_AREAS_EN = { BACKEND: BACKEND_EN, COMMON: COMMON_EN, VAULT: VAULT_EN, DEVICES: DEVICES_EN, SERVICES: SERVICES_EN, DEVELOPER: DEVELOPER_EN, ACTIVITY: ACTIVITY_EN, SETTINGS: SETTINGS_EN, ONBOARDING: ONBOARDING_EN } as const;

/** The Korean table (the reference every other language is checked against). */
export const COPY = { ...BACKEND, ...COMMON, ...VAULT, ...DEVICES, ...SERVICES, ...DEVELOPER, ...ACTIVITY, ...SETTINGS, ...ONBOARDING } as const;

export type CopyKey = keyof typeof COPY;
export type CopyVars = Record<string, string | number>;

export const COPY_EN: { readonly [K in CopyKey]: string } = {
  ...BACKEND_EN, ...COMMON_EN, ...VAULT_EN, ...DEVICES_EN, ...SERVICES_EN, ...DEVELOPER_EN, ...ACTIVITY_EN, ...SETTINGS_EN, ...ONBOARDING_EN,
};

const TABLES: Record<Locale, { readonly [K in CopyKey]: string }> = { ko: COPY, en: COPY_EN };

let current: Locale = 'ko';

/** The locale t() reads. The window sets it once at boot and when the person changes it. */
export function setLocale(locale: Locale): void {
  current = locale;
  if (typeof document !== 'undefined') document.documentElement.lang = locale;
}
export const getLocale = (): Locale => current;

/** The locale for a saved preference (`ko`, `en`, or null to follow the system). */
export function resolveLocale(pref: Locale | null | undefined, systemLanguages: readonly string[]): Locale {
  if (pref === 'ko' || pref === 'en') return pref;
  for (const lang of systemLanguages) {
    const l = lang.toLowerCase();
    if (l.startsWith('ko')) return 'ko';
    if (l.startsWith('en')) return 'en';
  }
  return 'en';
}

/** Look up a string in the current locale and fill `{name}` placeholders. Unknown
 *  placeholders stay visible. */
export function t(key: CopyKey, vars?: CopyVars): string {
  const text: string = TABLES[current][key] ?? COPY[key];
  return text.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const v = vars?.[name];
    return v === undefined ? whole : String(v);
  });
}

/** One line of a message built from several copy entries. */
export interface CopyLine { key: CopyKey; vars?: CopyVars }

/** Several sentences shown in one place (an error slot), as one text: a period between them and
 *  none at the end. */
export function tLines(lines: readonly CopyLine[]): string {
  return lines.map((l) => t(l.key, l.vars)).join('. ');
}

export function hasCopy(key: string): key is CopyKey {
  return Object.prototype.hasOwnProperty.call(COPY, key);
}

export type { Translation } from './types';
