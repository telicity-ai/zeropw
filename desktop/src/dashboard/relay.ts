// Relay (serve sidecar) control shared by the sidebar, Home, Settings, the team page and the end
// of the onboarding. The core keeps a running relay on its old port and address until it is
// restarted, and a relay that failed to start stays off until something calls `serve_start`.
// `serve_start` reads the saved settings, so a new setting is saved first and then tried.

import type { CopyLine } from '../copy';
import { call, toIpcError } from '../ipc/client';
import type { ServeStatus } from '../ipc/contract';
import { listenFailureLines, relayError } from '../lib/reasons';

/** Stop the relay if it runs, then start it, so a changed port or team address takes effect. */
export async function restartRelay(): Promise<ServeStatus> {
  const s = await call('serve_status');
  if (s.running) await call('serve_stop');
  return call('serve_start');
}

/** Other-device access could not be turned on at `address`. The relay runs the gateway, the SSH
 *  signer and team sync in one process, and a team address it cannot open (a VPN that is down, a
 *  port in use) stops all of it (rust/src/admin_cli.rs `run_serve`). So the previous setting was
 *  put back and the relay started with it. */
export class ListenError extends Error {
  /** The address that could not be used. */
  readonly address: string;
  /** Why the relay did not start with it (the sidecar's reason, or `serve_exited` from an older core). */
  readonly reason: string;
  /** The setting the core says failed to open (`gateway_port` or `team_listen`), when it says. */
  readonly detail: string | undefined;
  /** The previous setting is saved again. */
  readonly restored: boolean;
  /** The relay is running again (with the previous setting). */
  readonly relayBack: boolean;
  /** Why the relay did not come back, when it did not. */
  readonly relayError: unknown;

  constructor(f: { address: string; reason: string; detail?: string; restored: boolean; relayBack: boolean; relayError: unknown }) {
    super(`listen_failed: ${f.reason}`);
    this.name = 'ListenError';
    this.address = f.address;
    this.reason = f.reason;
    this.detail = f.detail;
    this.restored = f.restored;
    this.relayBack = f.relayBack;
    this.relayError = f.relayError;
  }
}

/** Turn on (or move) other-device access (`team_listen`) at `ip:port` and restart the relay so
 *  team sync listens there. Without it a joined device never syncs. When the relay does not start
 *  with the new address, the previous `team_listen` is saved again and the relay restarted with
 *  it, and a ListenError says what happened; the new address is never left saved with the relay
 *  off. A setting the core refuses outright (`invalid_listen`, `invalid_port`) throws as it is,
 *  with nothing changed. */
export async function turnOnListen(ip: string, port: number): Promise<ServeStatus> {
  const address = `${ip}:${port}`;
  const before = await call('settings_get');
  await call('settings_set', { gateway_port: before.gateway_port, team_listen: address });
  try {
    const s = await restartRelay();
    if (s.running) return s;
    throw { error: 'Unavailable', reason: 'serve_not_running' };
  } catch (e) {
    const { reason, detail } = toIpcError(e);
    let restored = false, relayBack = false, relayError: unknown = e;
    try {
      await call('settings_set', { gateway_port: before.gateway_port, team_listen: before.team_listen });
      restored = true;
      relayBack = (await restartRelay()).running;
      relayError = relayBack ? null : { error: 'Unavailable', reason: 'serve_not_running' };
    } catch (again) {
      if (restored) relayError = again;
    }
    throw new ListenError({ address, reason, detail, restored, relayBack, relayError });
  }
}

/** Why turning on other-device access failed, as sentences for one error slot. A ListenError
 *  names the address (or the relay port, when the core says that is what failed) and says
 *  whether the previous setting and the relay are back. */
export function listenErrorLines(e: unknown): CopyLine[] {
  if (e instanceof ListenError) return listenFailureLines(e);
  const { reason, detail } = toIpcError(e);
  if (reason === 'invalid_listen') return [{ key: 'set.listen.port.err' }];
  if (reason.startsWith('serve_') || reason === 'admin_binary_missing' || reason === 'invalid_port') {
    const r = relayError(reason, detail);
    return [{ key: r.key, vars: { reason: r.reason } }];
  }
  return [{ key: 'error.generic' }];
}

/** Why the relay is left off after turning on other-device access failed, or null when it runs. */
export function relayLeftOff(e: unknown): unknown {
  return e instanceof ListenError && !e.relayBack ? e.relayError : null;
}

/** Turn other-device access off and restart the relay without it. */
export async function turnOffListen(): Promise<ServeStatus> {
  const s = await call('settings_get');
  await call('settings_set', { gateway_port: s.gateway_port, team_listen: null });
  return restartRelay();
}
