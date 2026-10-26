// The backup and restore commands (app/src-tauri/src/backup.rs). No path crosses: the panels run in the backend,
// which keeps the chosen file and returns only its name. A password is sent once and never stored here.
import { invoke } from '@tauri-apps/api/core';

/// A preference carried in a backup.
export type Preference = 'autoCheck' | 'delay24h' | 'launchAtLogin' | 'controlApi' | 'autoUnlock';

/// What a merge does with an item that already exists.
export type ConflictMode = 'overwrite' | 'keepExisting' | 'keepBoth';

/// The opened backup, before anything is written.
export interface RestoreSummary {
  /// Unix time (seconds).
  created: number;
  appVersion: string;
  connections: number;
  folders: number;
  credentials: number;
  added: number;
  conflicts: number;
  lostOnReplace: number;
  /// The team catalog subscriptions a replace removes (not in the backup).
  lostSubscriptions: string[];
  /// The admin key roles the backup replaces with its own key (a role it has no key for stays).
  lostAdminKeys: ('primary' | 'backup')[];
  /// The publications the backup replaces with its own record (one it does not have stays).
  lostPublications: string[];
  /// Everything a replace loses: the number its confirmation sends back.
  lostTotal: number;
  /// The connections whose acknowledged risky OpenVPN directives a replace keeps (a merge drops them).
  acknowledgedRisky: string[];
  nativeProfiles: number;
  fresh: boolean;
}

export interface PreferenceChoice {
  key: Preference;
  backedUp: boolean;
  current: boolean;
  /// The checkbox starts ticked (never for the control API).
  ticked: boolean;
}

export interface NativeProfileView {
  id: string;
  name: string;
  installed: boolean;
  /// Why the platform could not install it (WinVPN: Cisco IPsec); absent on macOS.
  note?: string;
}

export interface RestoreOutcome {
  preferences: PreferenceChoice[];
  nativeProfiles: NativeProfileView[];
  /// The backup's folders and connections a team catalog owns here: not restored (the catalog's stay).
  skippedCatalogItems: string[];
}

export interface PreferenceFailure {
  key: Preference;
  message: string;
}

export const backupApi = {
  showWindow: (name: 'backup' | 'restore') => invoke<void>('backup_show_window', { name }),
  closeWindow: () => invoke<void>('backup_close_window'),
  /// The save panel; the chosen file's name, or null when cancelled.
  chooseDestination: () => invoke<string | null>('backup_choose_destination'),
  /// `master` is always checked; the file is sealed with `password`, or with the master password when null.
  save: (master: string, password: string | null) => invoke<void>('backup_save', { master, password }),
  /// The open panel; the chosen file's name, or null when cancelled.
  chooseFile: () => invoke<string | null>('restore_choose_file'),
  open: (password: string) => invoke<RestoreSummary>('restore_open', { password }),
  merge: (conflict: ConflictMode) =>
    invoke<RestoreOutcome>('restore_apply', { mode: 'merge', conflict, expectedLost: null }),
  replace: (expectedLost: number) =>
    invoke<RestoreOutcome>('restore_apply', { mode: 'replace', conflict: null, expectedLost }),
  /// The create-vault window's restore, once the new vault exists (plan B Task 14).
  freshApply: () => invoke<RestoreOutcome>('restore_fresh_apply'),
  applyPreferences: (keys: Preference[]) => invoke<PreferenceFailure[]>('restore_apply_preferences', { keys }),
  reinstallProfile: (id: string) => invoke<NativeProfileView[]>('restore_reinstall_profile', { id }),
  discard: () => invoke<void>('restore_discard'),
};
