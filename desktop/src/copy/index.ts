// Every visible string in the app, grouped by area. Components never hard-code display text:
// they call t() with a key from COPY. Keys are unique across areas (test/copy.test.ts).

import { ACTIVITY } from './activity';
import { BACKEND } from './backend';
import { COMMON } from './common';
import { DEVELOPER } from './developer';
import { DEVICES } from './devices';
import { ONBOARDING } from './onboarding';
import { SERVICES } from './services';
import { SETTINGS } from './settings';
import { VAULT } from './vault';

/** Each area's table, by name (tests check that no key is defined twice). */
export const COPY_AREAS = { BACKEND, COMMON, VAULT, DEVICES, SERVICES, DEVELOPER, ACTIVITY, SETTINGS, ONBOARDING } as const;

export const COPY = { ...BACKEND, ...COMMON, ...VAULT, ...DEVICES, ...SERVICES, ...DEVELOPER, ...ACTIVITY, ...SETTINGS, ...ONBOARDING } as const;

export type CopyKey = keyof typeof COPY;
export type CopyVars = Record<string, string | number>;

/** Look up a string and fill `{name}` placeholders. Unknown placeholders stay visible. */
export function t(key: CopyKey, vars?: CopyVars): string {
  const text: string = COPY[key];
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
