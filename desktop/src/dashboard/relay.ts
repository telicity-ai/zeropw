// Relay (serve sidecar) control shared by the sidebar, Home, Settings, the team page and the end
// of the onboarding. The core keeps a running relay on its old port and address until it is
// restarted, and a relay that failed to start stays off until something calls `serve_start`.

import { call } from '../ipc/client';
import type { ServeStatus, Settings } from '../ipc/contract';

/** Stop the relay if it runs, then start it, so a changed port or team address takes effect. */
export async function restartRelay(): Promise<ServeStatus> {
  const s = await call('serve_status');
  if (s.running) await call('serve_stop');
  return call('serve_start');
}

/** Turn on other-device access (`team_listen`) at `ip:port` and restart the relay so team sync
 *  listens there. Without it a joined device never syncs (rust/src/admin_cli.rs `run_serve`). */
export async function turnOnListen(settings: Settings, ip: string, port: number): Promise<ServeStatus> {
  await call('settings_set', { gateway_port: settings.gateway_port, team_listen: `${ip}:${port}` });
  return restartRelay();
}
