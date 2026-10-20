// The publisher's commands (app/src-tauri/src/catalog.rs, spec 7). No path crosses: the save and open panels run
// in the backend, which keeps the chosen file and returns only its name. A password goes to the backend once and is
// never kept here; a subscription string never comes back (it goes to the pasteboard in the backend). The team key
// comes back once, from a first publish or a rotation, for `TeamKeyReveal`.
import { invoke } from '@tauri-apps/api/core';

export type AdminKeyRole = 'primary' | 'backup';

/// An admin key: its role and fingerprint, never the key.
export interface AdminKeyView {
  role: AdminKeyRole;
  /// 8 groups of 4.
  fingerprint: string;
  /// Unix time (seconds).
  created: number;
  /// A backup key exported and removed from this Mac (only its public half is kept: still announced).
  offline: boolean;
}

/// A ticked team secret of a connection: `psk` or `keypass`.
export interface SecretChoice {
  item: string;
  field: string;
}

/// A ticked inline key of a config (`wireguardPrivateKey`, `tlsAuth`, …).
export interface InlineChoice {
  item: string;
  secret: string;
}

/// The wizard's selection, as `publish_preview` and `publish_catalog` take it.
export interface SelectionInput {
  folders: string[];
  connections: string[];
  secrets: SecretChoice[];
  slots: string[];
  inlineSecrets: InlineChoice[];
}

export interface PublicationView {
  id: string;
  name: string;
  version: number;
  /// Unix time (seconds).
  lastPublished: number | null;
  /// The last file's name only.
  fileName: string | null;
  /// Published connections changed since the last publish.
  changed: number;
  /// The saved selection ("Publish New Version", "Rotate Team Key").
  selection?: SelectionInput;
  /// Its last version announced a successor key that its next version would no longer announce.
  successorDropped?: boolean;
}

export interface PublishingView {
  adminKeys: AdminKeyView[];
  publications: PublicationView[];
}

/// "Published in “…” (vN)" on a source connection's row.
export interface PublishedBadge {
  catalogId: string;
  name: string;
  version: number;
  changed: boolean;
}

/// A connection and a code (a personal field, an inline key, a stored secret, a refusal).
export interface ItemField {
  item: string;
  field: string;
}

export interface SlotChoice {
  id: string;
  name: string;
  /// Selected connections linked to it.
  connections: number;
}

/// The wizard's review of a selection.
export interface PublishPreview {
  counts: { folders: number; connections: number; slots: number; secrets: number };
  /// `sstpUser`, `nativeAccount`, `wireguardPrivateKey`, `openvpnInlineKey`.
  personal: ItemField[];
  /// Each needs its own tick.
  inlineSecrets: ItemField[];
  /// `psk` / `keypass` stored for a selected connection: opt-in.
  availableSecrets: ItemField[];
  availableSlots: SlotChoice[];
  /// `inlineCredentials`, `config`, `nativeSettings`, `configTooLarge`, `connectionName`, `invalid`.
  refused: ItemField[];
  /// The publications (their names) whose next version would no longer announce the successor key their last
  /// version announced.
  successorDroppedIn?: string[];
}

/// A written catalog. `teamKey` only for a new catalog or a rotation: shown once.
export interface PublishedView {
  catalogId: string;
  version: number;
  fingerprint: string;
  fileName: string;
  teamKey: string | null;
}

export const EMPTY_PUBLISHING: PublishingView = { adminKeys: [], publications: [] };

export const publishApi = {
  generateKey: (role: AdminKeyRole) => invoke<string>('admin_key_generate', { role }),
  /// The save panel, then the sealed file. `null`: the panel was cancelled.
  exportKey: (password: string, removeAfter: boolean) => invoke<string | null>('admin_key_export', { password, removeAfter }),
  /// The open panel: the file's name (`null`: cancelled).
  chooseKeyFile: () => invoke<string | null>('admin_key_choose_file'),
  importKey: (password: string) => invoke<string>('admin_key_import', { password }),
  promoteKey: () => invoke<string>('admin_key_promote'),
  preview: (selection: SelectionInput) => invoke<PublishPreview>('publish_preview', { selection }),
  /// The save panel, then the file. `null`: the panel was cancelled.
  publish: (catalogId: string | null, name: string, selection: SelectionInput) =>
    invoke<PublishedView | null>('publish_catalog', { catalogId, name, selection }),
  rotate: (catalogId: string) => invoke<PublishedView | null>('publication_rotate_team_key', { catalogId }),
  /// The open panel for the file the team will use as the source (`null`: cancelled).
  chooseSourceFile: () => invoke<string | null>('catalog_choose_file_source'),
  /// Copied to the pasteboard in the backend; nothing comes back.
  copySubscription: (catalogId: string, masterPassword: string, url: string | null, chosenFile: boolean) =>
    invoke<void>('publication_copy_subscription', { catalogId, masterPassword, url, chosenFile }),
  forget: (catalogId: string) => invoke<void>('publication_forget', { catalogId }),
  /// The team key was copied: the backend empties the pasteboard a minute later if it still holds it.
  copyTeamKey: (teamKey: string) => invoke<void>('catalog_copy_team_key', { teamKey }),
};
