// System Status' engine rows (WinVPN): the WinVPN Service, OpenVPN Community and WireGuard, in this order, each
// with its title. Without an engine (macOS, or WinVPN while the service is missing) there are none. The Windows VPN
// client row (WinVPN 2c) is shown under them, or under the engine note: the native VPNs need no service.
import type { CheckRow, EngineRowsView } from './api';

export type EngineRowId = 'service' | 'openvpn' | 'wireguard' | 'ras';

export interface EngineRowItem {
  id: EngineRowId;
  title: string;
  row: CheckRow;
}

/// `tr`: the UI's text lookup (the titles are its literal keys).
export function engineRows(setup: { engine?: EngineRowsView }, tr: (key: string) => string): EngineRowItem[] {
  const engine = setup.engine;
  if (engine === undefined) return [];
  return [
    { id: 'service', title: tr('WinVPN Service'), row: engine.service },
    { id: 'openvpn', title: tr('OpenVPN Community'), row: engine.openvpn },
    { id: 'wireguard', title: tr('WireGuard'), row: engine.wireguard },
  ];
}

/// The Windows VPN client row (L2TP/IPsec, IKEv2, SSTP through Windows' own client); none on macOS.
export function rasRow(setup: { ras?: CheckRow }, tr: (key: string) => string): EngineRowItem | null {
  return setup.ras === undefined ? null : { id: 'ras', title: tr('Windows VPN client'), row: setup.ras };
}

/// The uninstall area's texts: MacVPN's "Uninstall MacVPN…", or WinVPN's "Remove WinVPN from This Account…" (the
/// in-app clean-up before the MSI's uninstall in Settings → Apps). `tr`: the UI's text lookup (literal keys).
export interface UninstallTexts {
  caption: string;
  button: string;
  title: string;
  message: string;
  confirm: string;
}

export function uninstallTexts(setup: { accountCleanup?: boolean }, tr: (key: string) => string): UninstallTexts {
  if (setup.accountCleanup) {
    return {
      caption: tr(
        "Before you uninstall: disconnects every connection and removes launch at login and WinVPN's Windows VPN entries; optionally your connections too.",
      ),
      button: tr('Remove WinVPN from This Account…'),
      title: tr('Remove WinVPN from This Account'),
      message: tr(
        "These are removed from this Windows account:\n• Launch at Login\n• WinVPN's Windows VPN entries and the pre-shared keys Windows keeps for them\n\nActive connections are disconnected first. Your own Windows VPNs are kept. Then Settings → Apps → Installed apps opens: uninstall WinVPN there (the WinVPN Service and the program files go with it).",
      ),
      confirm: tr('Remove'),
    };
  }
  return {
    caption: tr('Removes the root scripts, the sudoers rule and the logs; optionally your connections too.'),
    button: tr('Uninstall MacVPN…'),
    title: tr('Uninstall MacVPN'),
    message: tr(
      'After you enter an admin password, these are deleted:\n• /usr/local/libexec/macvpn (root scripts)\n• /etc/sudoers.d/macvpn (sudoers rule)\n• /var/run/macvpn, /var/run/macvpn-ui (runtime data)\n• /var/log/macvpn (connection logs)\n\nActive connections are disconnected first. Homebrew packages are kept.',
    ),
    confirm: tr('Uninstall'),
  };
}
