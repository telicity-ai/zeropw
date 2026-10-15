/** `http://127.0.0.1:47380` → `127.0.0.1:47380`. */
export function hostPort(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).host || null;
  } catch {
    return null;
  }
}

const pad = (n: number) => String(n).padStart(2, '0');

/** Compact local time for lists: `10-15 14:03`. Unparseable input is shown as given. */
export function shortTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
