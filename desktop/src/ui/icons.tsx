// One icon set for the whole app: 16-unit grid, 1.5 stroke, round joins. Icons are decorative
// (aria-hidden); the control that holds one carries the accessible name.

import type { ReactElement, SVGProps } from 'react';

export type IconName =
  | 'vault' | 'lock' | 'unlock' | 'search' | 'plus' | 'close' | 'check' | 'chevron-right' | 'chevron-left' | 'chevron-down'
  | 'copy' | 'eye' | 'eye-off' | 'key' | 'password' | 'env' | 'ssh' | 'laptop' | 'plug' | 'code' | 'activity' | 'settings'
  | 'alert' | 'info' | 'refresh' | 'more' | 'trash' | 'clock' | 'sync' | 'offline' | 'shield' | 'user' | 'share' | 'link'
  | 'terminal' | 'pause' | 'play' | 'download' | 'upload' | 'file' | 'folder' | 'layers' | 'stack' | 'globe' | 'server'
  | 'history' | 'conflict' | 'sidebar' | 'arrow-right' | 'dot' | 'edit' | 'stop' | 'fingerprint';

const P: Record<IconName, ReactElement> = {
  vault: <><rect x="2.25" y="2.75" width="11.5" height="10.5" rx="2" /><circle cx="8" cy="8" r="2.25" /><path d="M8 5.75V5M8 11v-.75M5.75 8H5M11 8h-.75M4.5 13.25v1M11.5 13.25v1" /></>,
  lock: <><rect x="3" y="7" width="10" height="7" rx="1.75" /><path d="M5.25 7V5.25a2.75 2.75 0 0 1 5.5 0V7" /><path d="M8 9.75v1.5" /></>,
  unlock: <><rect x="3" y="7" width="10" height="7" rx="1.75" /><path d="M5.25 7V5.25a2.75 2.75 0 0 1 5.3-1.05" /><path d="M8 9.75v1.5" /></>,
  search: <><circle cx="7" cy="7" r="4.25" /><path d="m10.25 10.25 3.25 3.25" /></>,
  plus: <path d="M8 3v10M3 8h10" />,
  close: <path d="m4 4 8 8M12 4l-8 8" />,
  check: <path d="m3.25 8.5 3 3 6.5-7" />,
  'chevron-right': <path d="m6.25 3.5 4.5 4.5-4.5 4.5" />,
  'chevron-left': <path d="M9.75 3.5 5.25 8l4.5 4.5" />,
  'chevron-down': <path d="m3.5 6.25 4.5 4.5 4.5-4.5" />,
  copy: <><rect x="5.25" y="5.25" width="8" height="8" rx="1.75" /><path d="M10.75 5.25V4a1.25 1.25 0 0 0-1.25-1.25H4A1.25 1.25 0 0 0 2.75 4v5.5A1.25 1.25 0 0 0 4 10.75h1.25" /></>,
  eye: <><path d="M1.75 8S4 3.75 8 3.75 14.25 8 14.25 8 12 12.25 8 12.25 1.75 8 1.75 8Z" /><circle cx="8" cy="8" r="2" /></>,
  'eye-off': <><path d="M6.4 4c.5-.16 1.03-.25 1.6-.25 4 0 6.25 4.25 6.25 4.25a11 11 0 0 1-1.7 2.2M4.2 5.2A10.6 10.6 0 0 0 1.75 8S4 12.25 8 12.25c1.1 0 2.08-.32 2.94-.8" /><path d="M6.6 6.6a2 2 0 0 0 2.8 2.8M2.5 2.5l11 11" /></>,
  key: <><circle cx="5.5" cy="10.5" r="2.75" /><path d="m7.5 8.5 5.75-5.75M11 5l1.75 1.75M9.5 6.5l1.25 1.25" /></>,
  password: <><rect x="1.75" y="4.5" width="12.5" height="7" rx="2" /><path d="M5 7v2M4.13 7.5l1.74 1M4.13 8.5l1.74-1M8 7v2M7.13 7.5l1.74 1M7.13 8.5l1.74-1M10.75 9.25h1.5" /></>,
  env: <><path d="M5.25 3C4 3 3.5 3.6 3.5 4.75v1.5C3.5 7.4 3 8 2 8c1 0 1.5.6 1.5 1.75v1.5C3.5 12.4 4 13 5.25 13M10.75 3C12 3 12.5 3.6 12.5 4.75v1.5c0 1.15.5 1.75 1.5 1.75-1 0-1.5.6-1.5 1.75v1.5c0 1.15-.5 1.75-1.75 1.75" /><path d="M6.5 8h3" /></>,
  ssh: <><rect x="1.75" y="2.75" width="12.5" height="10.5" rx="2" /><path d="m4.5 6 2 2-2 2M8 10.25h3.5" /></>,
  laptop: <><rect x="3" y="3.25" width="10" height="7" rx="1.25" /><path d="M1.5 12.75h13" /></>,
  plug: <><path d="M5.5 1.75v3M10.5 1.75v3M3.75 4.75h8.5v2.5a4.25 4.25 0 0 1-8.5 0v-2.5ZM8 11.5v2.75" /></>,
  code: <path d="M5.5 4.5 2 8l3.5 3.5M10.5 4.5 14 8l-3.5 3.5M9 3 7 13" />,
  activity: <path d="M1.75 8.25h2.5l1.75-4 3 8 1.75-4h3.5" />,
  settings: <><circle cx="8" cy="8" r="2" /><path d="M8 1.75v1.5M8 12.75v1.5M14.25 8h-1.5M3.25 8h-1.5M12.42 3.58l-1.06 1.06M4.64 11.36l-1.06 1.06M12.42 12.42l-1.06-1.06M4.64 4.64 3.58 3.58" /></>,
  alert: <><path d="M7.13 2.6a1 1 0 0 1 1.74 0l5.4 9.4a1 1 0 0 1-.87 1.5H2.6a1 1 0 0 1-.87-1.5l5.4-9.4Z" /><path d="M8 6.25V9M8 11.25v.01" /></>,
  info: <><circle cx="8" cy="8" r="6.25" /><path d="M8 7.25V11M8 5v.01" /></>,
  refresh: <><path d="M13.25 8A5.25 5.25 0 1 1 11.5 4.1" /><path d="M11.75 1.75v2.75H9" /></>,
  more: <><circle cx="3.75" cy="8" r=".9" fill="currentColor" stroke="none" /><circle cx="8" cy="8" r=".9" fill="currentColor" stroke="none" /><circle cx="12.25" cy="8" r=".9" fill="currentColor" stroke="none" /></>,
  trash: <><path d="M2.75 4.25h10.5M6.25 4.25V2.75h3.5v1.5M4.25 4.25l.6 8.5a1.25 1.25 0 0 0 1.25 1.15h3.8a1.25 1.25 0 0 0 1.25-1.15l.6-8.5" /></>,
  clock: <><circle cx="8" cy="8" r="6.25" /><path d="M8 4.75V8l2.25 1.5" /></>,
  sync: <><path d="M2.75 6.5A5.25 5.25 0 0 1 12.6 5M13.25 9.5A5.25 5.25 0 0 1 3.4 11" /><path d="M12.75 2.25V5H10M3.25 13.75V11H6" /></>,
  offline: <><path d="M1.75 1.75l12.5 12.5M5.9 5.4A5.6 5.6 0 0 0 3 6.7M2 4.9A8.6 8.6 0 0 1 4.3 3.6M8.9 5.05a5.7 5.7 0 0 1 4.1 1.65M11.4 3.4c1 .4 1.9.9 2.6 1.5M5.6 9.9a3.4 3.4 0 0 1 4.3-.2M8 12.75v.01" /></>,
  shield: <><path d="M8 1.75 13 3.5v4.25c0 3-2.1 5.4-5 6.5-2.9-1.1-5-3.5-5-6.5V3.5L8 1.75Z" /><path d="m5.75 8 1.5 1.5 3-3" /></>,
  user: <><circle cx="8" cy="5.5" r="2.75" /><path d="M2.75 13.75c.6-2.4 2.7-4 5.25-4s4.65 1.6 5.25 4" /></>,
  share: <><circle cx="4" cy="8" r="1.75" /><circle cx="12" cy="3.75" r="1.75" /><circle cx="12" cy="12.25" r="1.75" /><path d="m5.55 7.2 4.9-2.6M5.55 8.8l4.9 2.6" /></>,
  link: <><path d="M6.75 9.25a2.75 2.75 0 0 0 3.9 0l2-2a2.75 2.75 0 0 0-3.9-3.9l-.75.75" /><path d="M9.25 6.75a2.75 2.75 0 0 0-3.9 0l-2 2a2.75 2.75 0 0 0 3.9 3.9l.75-.75" /></>,
  terminal: <><rect x="1.75" y="2.75" width="12.5" height="10.5" rx="2" /><path d="m4.75 6.25 1.75 1.75-1.75 1.75M8.5 10h2.75" /></>,
  pause: <path d="M5.75 3.5v9M10.25 3.5v9" />,
  play: <path d="M5 3.25v9.5L12.5 8 5 3.25Z" />,
  download: <path d="M8 2.25v8M4.75 7 8 10.25 11.25 7M2.75 13.25h10.5" />,
  upload: <path d="M8 10.25v-8M4.75 5.5 8 2.25l3.25 3.25M2.75 13.25h10.5" />,
  file: <><path d="M9.25 1.75H4.5A1.25 1.25 0 0 0 3.25 3v10a1.25 1.25 0 0 0 1.25 1.25h7A1.25 1.25 0 0 0 12.75 13V5.25L9.25 1.75Z" /><path d="M9.25 1.75v3.5h3.5" /></>,
  folder: <path d="M1.75 4.5A1.25 1.25 0 0 1 3 3.25h3l1.5 1.5H13a1.25 1.25 0 0 1 1.25 1.25v6A1.25 1.25 0 0 1 13 13.25H3A1.25 1.25 0 0 1 1.75 12V4.5Z" />,
  layers: <><path d="M8 2 14 5.25 8 8.5 2 5.25 8 2Z" /><path d="m2 8.25 6 3.25 6-3.25M2 11l6 3.25L14 11" /></>,
  stack: <><rect x="2.75" y="2.75" width="10.5" height="4" rx="1.25" /><rect x="2.75" y="9.25" width="10.5" height="4" rx="1.25" /></>,
  globe: <><circle cx="8" cy="8" r="6.25" /><path d="M1.75 8h12.5M8 1.75c1.7 1.75 2.5 3.8 2.5 6.25S9.7 12.5 8 14.25C6.3 12.5 5.5 10.45 5.5 8S6.3 3.5 8 1.75Z" /></>,
  server: <><rect x="2.25" y="2.25" width="11.5" height="4.75" rx="1.25" /><rect x="2.25" y="9" width="11.5" height="4.75" rx="1.25" /><path d="M5 4.6v.01M5 11.4v.01" /></>,
  history: <><path d="M2.5 8a5.5 5.5 0 1 0 1.6-3.9" /><path d="M2.25 2.5v2.75H5M8 5v3l2 1.25" /></>,
  conflict: <><path d="M4.5 2.25v6.5M4.5 8.75a3 3 0 0 0 3 3h1" /><circle cx="4.5" cy="12" r="1.75" /><circle cx="11.5" cy="11.75" r="1.75" /><path d="M10 2.5l3 3M13 2.5l-3 3" /></>,
  sidebar: <><rect x="1.75" y="2.75" width="12.5" height="10.5" rx="2" /><path d="M6 2.75v10.5" /></>,
  'arrow-right': <path d="M2.75 8h10.5M9 3.75 13.25 8 9 12.25" />,
  dot: <circle cx="8" cy="8" r="3" fill="currentColor" stroke="none" />,
  edit: <><path d="M10.4 2.6a1.5 1.5 0 0 1 2.1 0l.9.9a1.5 1.5 0 0 1 0 2.1L6 13H3v-3l7.4-7.4Z" /><path d="m9.25 3.75 3 3" /></>,
  stop: <><circle cx="8" cy="8" r="6.25" /><rect x="5.75" y="5.75" width="4.5" height="4.5" rx=".75" /></>,
  fingerprint: <><path d="M4.1 3.4A5.5 5.5 0 0 1 13.5 7.5v1M2.5 6.25A5.5 5.5 0 0 0 2.5 9.5M5 12.75A9 9 0 0 1 4.75 8a3.25 3.25 0 0 1 6.5 0c0 .9-.05 1.75-.2 2.6M8 8c0 2.3-.4 4.2-1.3 5.8M10.6 12.6c-.2.6-.45 1.1-.75 1.6" /></>,
};

export function Icon({ name, size = 16, ...rest }: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, 'name'>) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={1.5}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" {...rest}>
      {P[name]}
    </svg>
  );
}

/** The app mark: a rounded vault door with a single pine dot, drawn with currentColor. */
export function Mark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" aria-hidden="true" focusable="false">
      <rect x="1.5" y="1.5" width="17" height="17" rx="5" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="10" cy="10" r="3.4" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="10" cy="10" r="1.2" fill="var(--accent)" />
    </svg>
  );
}
