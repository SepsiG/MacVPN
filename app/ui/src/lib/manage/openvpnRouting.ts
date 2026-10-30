// OpenVPN's "Send all traffic over VPN" on Linux (LinVPN decisions 7 and 8, L-b resolved point 4): Server decides
// (default) / Always / Never. The choice is stored in the config text itself (`redirect-gateway def1` or
// `pull-filter ignore "redirect-gateway"`), read and rewritten by the backend (`openvpn_routing_read` / `_write`),
// so it syncs through backups, exports and team catalogs. macOS and Windows show no control.
import type { Kind } from '../api';
import type { Os } from '../l10n-core';
import type { NmRowsView } from '../setup';
import type { Tr } from './ras';

/// The backend's ids of the three choices.
export type RoutingId = 'server' | 'always' | 'never';

/// What the editor knows about this system's OpenVPN: `pushVisible` is false with OpenVPN older than 2.7, whose
/// server push NetworkManager cannot see.
export interface RoutingCaps {
  pushVisible: boolean;
}

/// Whether this system's NetworkManager sees the server's redirect-gateway, from System Status' OpenVPN row (its
/// `pushVisible`). Before the first check (no rows) it is assumed, so no older-OpenVPN text is shown on a guess.
export function pushVisible(nm: NmRowsView | undefined): boolean {
  if (nm === undefined) return true;
  return nm.kinds.find((k) => k.kind === 'openvpn')?.pushVisible === true;
}

/// The three choices in the control's order.
export function routingOptions(tr: Tr): { id: RoutingId; label: string }[] {
  return [
    { id: 'server', label: tr('Server decides') },
    { id: 'always', label: tr('Always') },
    { id: 'never', label: tr('Never (split tunnel)') },
  ];
}

/// The control is LinVPN's only: macOS' and Windows' OpenVPN honour the config's own lines.
export function visible(os: Os, kind: Kind | string): boolean {
  return os === 'linux' && kind === 'openvpn';
}

/// What the chosen value means (with OpenVPN < 2.7, what "Server decides" falls back to).
export function helpText(routing: RoutingId, caps: RoutingCaps, tr: Tr): string {
  switch (routing) {
    case 'server':
      return caps.pushVisible
        ? tr("The server's redirect-gateway decides.")
        : tr("This system's OpenVPN is older than 2.7: “Server decides” keeps a split tunnel unless the profile says otherwise.");
    case 'always':
      return tr('All traffic goes through the VPN (redirect-gateway def1).');
    case 'never':
      return tr("Only the VPN's own networks go through it; a redirect-gateway from the server is ignored.");
  }
}
