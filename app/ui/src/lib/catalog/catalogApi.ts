// The subscriber's team catalog commands (app/src-tauri/src/catalog.rs, plan Task 15). No path crosses: the open
// panel runs in the backend, which keeps the chosen file and returns only its name. A team key, an access token or
// a subscription string is sent once as a command argument and never comes back (the view model has none).
import { invoke } from '@tauri-apps/api/core';

/// A credential slot of a subscription: the shared credential the catalog's connections use.
export interface SlotView {
  name: string;
  /// The user filled in a user name or a password.
  filled: boolean;
  /// The shared credential's name in the Credentials section.
  credentialName: string | null;
}

export type SubscriptionStatus = 'ok' | 'notModified' | 'unavailable' | 'failed' | 'rollbackRefused' | 'teamKeyChanged';

/// One subscription in the "Team catalogs" section. Never a key, a token or the source's query.
export interface SubscriptionView {
  id: string;
  name: string;
  /// A URL without its query, a file by its file name.
  source: string;
  /// The 8 groups of the pinned publisher fingerprint.
  fingerprint: string;
  version: number | null;
  status: SubscriptionStatus | string;
  /// Unix time (seconds).
  lastRefresh: number | null;
  lastSuccess: number | null;
  /// The problem, translated.
  error: string | null;
  hasToken: boolean;
  slots: SlotView[];
}

/// The "Team" badge of a catalog connection's row.
export interface CatalogBadge {
  catalogId: string;
  name: string;
  /// Removed from the catalog while up: deleted once it disconnects.
  pendingRemoval: boolean;
  /// The catalog changed this native connection: its profile needs a reinstall.
  profileOutdated: boolean;
}

/// A pasted subscription string as the backend read it: the source and the fingerprint (never the team key).
export interface ParsedSubscription {
  kind: 'https' | 'file';
  source: string;
  fingerprint: string;
}

/// "Check": the verified first download, waiting for "Subscribe" under `pendingId`.
export interface CatalogPreview {
  pendingId: string;
  catalogId: string;
  name: string;
  version: number;
  fingerprint: string;
  connections: number;
  folders: number;
  /// The credential slots' names.
  slots: string[];
  /// Connections with risky settings (each subscriber acknowledges them).
  risky: number;
  /// Team secrets the catalog carries.
  teamSecrets: number;
}

export interface ApplyView {
  added: number;
  changed: number;
  removed: number;
  /// Removed connections that are up: deleted once they disconnect.
  deferred: number;
}

export interface RefreshView {
  id: string;
  outcome: 'notModified' | 'applied' | 'unchanged' | 'refused' | 'locked';
  applied: ApplyView | null;
  /// Why it was refused (translated).
  error: string | null;
}

export interface UnsubscribeView {
  removed: number;
  /// The slot credentials the user filled in, kept as ordinary shared credentials.
  keptCredentials: string[];
}

/// What "Check" sends: a pasted subscription string, or the fields (an `https://` URL or the chosen file, the team
/// key, the fingerprint); an access token with either.
export interface PreviewInput {
  subscription: string | null;
  url: string | null;
  chosenFile: boolean;
  teamKey: string | null;
  fingerprint: string | null;
  token: string | null;
}

export const catalogApi = {
  parseSubscription: (text: string) => invoke<ParsedSubscription>('catalog_parse_subscription', { text }),
  /// The open panel for a file source: the chosen file's name (`null`: cancelled).
  chooseFileSource: () => invoke<string | null>('catalog_choose_file_source'),
  preview: (input: PreviewInput) => invoke<CatalogPreview>('catalog_preview', { ...input }),
  confirm: (pendingId: string) => invoke<ApplyView>('catalog_confirm', { pendingId }),
  /// The add dialog was closed without subscribing.
  discard: (pendingId: string) => invoke<void>('catalog_discard', { pendingId }),
  refresh: (catalogId: string) => invoke<RefreshView>('catalog_refresh', { catalogId }),
  refreshAll: () => invoke<RefreshView[]>('catalog_refresh_all'),
  /// `true`: the new source is on another origin and the stored access token was dropped (ask for a new one).
  updateSource: (catalogId: string, url: string | null, chosenFile: boolean) =>
    invoke<boolean>('catalog_update_source', { catalogId, url, chosenFile }),
  updateTeamKey: (catalogId: string, teamKey: string) => invoke<void>('catalog_update_team_key', { catalogId, teamKey }),
  /// `null`: removes the stored token.
  updateBearer: (catalogId: string, token: string | null) => invoke<void>('catalog_update_bearer', { catalogId, token }),
  unsubscribe: (catalogId: string) => invoke<UnsubscribeView>('catalog_unsubscribe', { catalogId }),
  /// "Duplicate as personal connection…": the copy's id.
  duplicate: (itemId: string, name: string) => invoke<string>('catalog_duplicate', { itemId, name }),
  installProfile: (itemId: string) => invoke<void>('catalog_install_profile', { itemId }),
  /// "I installed it": clears the "reinstall its profile" mark of a staged profile macOS cannot show as installed.
  profileInstalled: (itemId: string) => invoke<void>('catalog_profile_installed', { itemId }),
};
