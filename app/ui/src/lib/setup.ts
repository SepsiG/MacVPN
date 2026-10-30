// System Status' engine rows (WinVPN): the WinVPN Service, OpenVPN Community and WireGuard, in this order, each
// with its title. Without an engine (macOS, or WinVPN while the service is missing) there are none. The Windows VPN
// client row (WinVPN 2c) is shown under them, or under the engine note: the native VPNs need no service. LinVPN
// (L-b) shows NetworkManager and one row per kind (the plugin it needs) instead.
import type { CheckRow, EngineRowsView } from './api';
import type { Os } from './l10n-core.ts';

export type EngineRowId = 'service' | 'openvpn' | 'wireguard' | 'ras' | 'networkmanager' | `nm-${string}`;

export interface EngineRowItem {
  id: EngineRowId;
  title: string;
  row: CheckRow;
  /// LinVPN: the row's Install button (a package is missing): its element id and the kind's raw value it installs.
  install?: { buttonId: string; kind: string };
}

/// System Status' NetworkManager rows (LinVPN; the backend's `NmRowsView`). Absent on macOS and Windows.
export type NmRowsView = {
  networkmanager: CheckRow;
  /// `pushVisible`: OpenVPN's row only, when NetworkManager sees the server's redirect-gateway (OpenVPN ≥ 2.7).
  kinds: { kind: string; row: CheckRow; packages: string; action?: 'install'; pushVisible?: boolean }[];
};

/// The kinds under NetworkManager, in the window's order, with their names (product names: not translated).
const NM_KINDS: readonly (readonly [string, string])[] = [
  ['wireguard', 'WireGuard'],
  ['openvpn', 'OpenVPN'],
  ['l2tp', 'L2TP/IPsec'],
  ['strongswan', 'IKEv2'],
  ['cisco', 'Cisco IPsec'],
  ['sstp', 'SSTP'],
];

/// NetworkManager's row, then one per kind the backend reports (in `NM_KINDS` order); none without `nm`.
export function nmRows(setup: { nm?: NmRowsView }, tr: (key: string) => string): EngineRowItem[] {
  const nm = setup.nm;
  if (nm === undefined) return [];
  const items: EngineRowItem[] = [{ id: 'networkmanager', title: tr('NetworkManager'), row: nm.networkmanager }];
  for (const [kind, name] of NM_KINDS) {
    const entry = nm.kinds.find((k) => k.kind === kind);
    if (entry === undefined) continue;
    const item: EngineRowItem = { id: `nm-${kind}`, title: name, row: entry.row };
    if (entry.action === 'install') item.install = { buttonId: `nm-install-${kind}`, kind };
    items.push(item);
  }
  return items;
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

/// The system uninstall note's "Open Installed Apps…" (WinVPN: Settings → Apps). LinVPN's note names the command
/// that removes the package (`apt remove linvpn`): there is no page to open, so the note stands alone.
export function opensInstalledApps(os: Os): boolean {
  return os !== 'linux';
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
