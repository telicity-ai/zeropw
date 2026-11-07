import { getLocale } from '../copy';

/** `http://127.0.0.1:47380` → `127.0.0.1:47380`. */
export function hostPort(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).host || null;
  } catch {
    return null;
  }
}

/** Compact local time in the selected language. Unparseable input is shown as given. */
export function shortTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return new Intl.DateTimeFormat(getLocale() === 'ko' ? 'ko-KR' : 'en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).format(d);
}
