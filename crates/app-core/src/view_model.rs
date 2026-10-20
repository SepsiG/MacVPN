//! The serializable view model of the menu popover (and, later, the other windows): the rows in ranking order
//! with their state, the status error line, the tray icon state and the open MFA prompts.

use crate::connections::ManageView;
use crate::credential_prompt::CredentialPromptView;
use crate::manager::{ConnectionItem, FolderSnapshot, ManagerSnapshot};
use crate::pairing::PairingView;
use crate::prompt::PromptView;
use crate::quit::QuitQuestion;
use crate::setup::SetupView;
use crate::shared_credentials::CredentialsView;
use crate::updates::UpdateView;
use crate::vault::VaultState;
use crate::vault_setup::VaultSetupView;
use macvpn_core::control::protocol::escape_unsafe_text;
use macvpn_core::control::registry::PairedClient;
use macvpn_core::l10n;
use macvpn_core::models::{AuthWaitKind, ConnectionState, VPNKind, uuid_string};
use macvpn_core::vault::{ColorSource, FolderColor, FolderTree, TreeEntry};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

/// The menu bar icon (the Swift `menuBarSymbol`): template glyphs, the system tints them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrayIcon {
    /// `shield`: nothing active (grey).
    Idle,
    /// `checkmark.shield.fill`: a connection is active (green).
    Active,
    /// `exclamationmark.shield.fill`: a failure or a status error (red).
    Failure,
    /// `key.fill`: waiting for authentication (code or web sign-in).
    Auth,
}

impl TrayIcon {
    pub fn from_snapshot(s: &ManagerSnapshot) -> TrayIcon {
        if s.awaiting_auth {
            TrayIcon::Auth
        } else if s.has_failure || s.status_error.is_some() {
            TrayIcon::Failure
        } else if s.has_active {
            TrayIcon::Active
        } else {
            TrayIcon::Idle
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum RowState {
    Disconnected,
    Connecting,
    Connected {
        ip: Option<String>,
        /// Unix time (seconds).
        since: Option<f64>,
    },
    Disconnecting,
    Failed {
        reason: String,
    },
    AwaitingAuth {
        /// `code`, `web` or `credentials`.
        wait: &'static str,
        deadline: Option<f64>,
    },
}

impl From<&ConnectionState> for RowState {
    fn from(state: &ConnectionState) -> Self {
        match state {
            ConnectionState::Disconnected => RowState::Disconnected,
            ConnectionState::Connecting => RowState::Connecting,
            ConnectionState::Connected { ip, since } => {
                RowState::Connected { ip: ip.clone(), since: since.map(|d| d.time_interval_since_1970()) }
            }
            ConnectionState::Disconnecting => RowState::Disconnecting,
            ConnectionState::Failed(reason) => RowState::Failed { reason: reason.clone() },
            ConnectionState::AwaitingAuth(wait) => RowState::AwaitingAuth {
                wait: match wait.kind {
                    AuthWaitKind::Code => "code",
                    AuthWaitKind::Web => "web",
                    AuthWaitKind::Credentials => "credentials",
                },
                deadline: wait.deadline.map(|d| d.time_interval_since_1970()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowView {
    /// The connection's UUID string or the system VPN's scutil service ID.
    pub id: String,
    pub name: String,
    /// `WireGuard`, `OpenVPN`, … or the system VPN's type label.
    pub type_label: String,
    /// False: a system VPN not managed by MacVPN.
    pub managed: bool,
    /// A managed connection's kind (`openvpn`, `wireguard`, …).
    pub kind: Option<&'static str>,
    /// A system VPN whose PSK / password MacVPN can keep (L2TP / Cisco IPsec).
    pub stored_secrets: bool,
    pub pinned: bool,
    /// False: a tool for the type is missing ("Missing tool").
    pub available: bool,
    #[serde(flatten)]
    pub state: RowState,
    /// The switch shows "on" (the state is active).
    pub switch_on: bool,
    /// The switch can be used (available, and not disconnecting).
    pub switch_enabled: bool,
    /// The paired apps holding the connection through the control API ("Held by …"), sorted.
    pub held_by: Vec<String>,
    /// A team catalog connection: the "Team" badge (`None` for the user's own and system VPNs).
    pub catalog: Option<crate::catalog::CatalogBadge>,
    /// A source connection the user publishes: "Published in “…” (vN)" per publication (empty otherwise).
    pub published: Vec<crate::catalog_publish::PublishedBadge>,
}

/// One row of the folder tree (spec 3), in display order: per folder its subfolders, then its items (pinned first,
/// then by usage). The contents of collapsed folders are included; the views hide them. An item's other fields are
/// in [`ViewModel::rows`] (same `id`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TreeRowView {
    Folder {
        id: String,
        name: String,
        /// The parent folder (`None`: the root).
        parent: Option<String>,
        /// The real nesting depth (0 at the root); the views cap the indentation.
        depth: usize,
        /// The effective colour (a palette id), its source (`own`, `inherited`, `none`) and the own colour.
        color: Option<&'static str>,
        color_source: &'static str,
        own_color: Option<&'static str>,
        collapsed: bool,
        /// The active connections in the folder and all its subfolders.
        active_count: usize,
        /// One of them is connected (the green dot).
        has_connected: bool,
        /// The managed connections in the folder and all its subfolders ("Delete the connections too").
        connection_count: usize,
        /// Every item in the folder and all its subfolders, and its subfolders.
        item_count: usize,
        folder_count: usize,
    },
    Item {
        id: String,
        parent: Option<String>,
        depth: usize,
        color: Option<&'static str>,
        color_source: &'static str,
        /// The item's own colour (an override; `None`: the folder's).
        own_color: Option<&'static str>,
    },
}

fn color_source(source: ColorSource) -> &'static str {
    match source {
        ColorSource::Own => "own",
        ColorSource::Inherited(_) => "inherited",
        ColorSource::None => "none",
    }
}

impl TreeRowView {
    /// The rows of the snapshot's folder tree, with each folder's counts over its whole subtree.
    pub fn build(folders: &FolderSnapshot, states: &HashMap<String, (ConnectionState, bool)>) -> Vec<TreeRowView> {
        let tree = FolderTree::new(folders.folders.clone()).unwrap_or_default();
        let folder_of = |key: &str| folders.placements.get(key).and_then(|p| p.folder).filter(|f| tree.contains(*f));
        // The items directly in each folder.
        let mut direct: HashMap<uuid::Uuid, Vec<&str>> = HashMap::new();
        for entry in &folders.entries {
            if let TreeEntry::Item { key, .. } = entry
                && let Some(folder) = folder_of(key)
            {
                direct.entry(folder).or_default().push(key);
            }
        }
        let own = |c: Option<FolderColor>| c.map(FolderColor::as_str);
        folders
            .entries
            .iter()
            .map(|entry| match entry {
                TreeEntry::Folder { id, depth } => {
                    let node = tree.get(*id);
                    let subtree: Vec<uuid::Uuid> = std::iter::once(*id).chain(tree.descendants(*id)).collect();
                    let keys: Vec<&str> =
                        subtree.iter().flat_map(|f| direct.get(f).into_iter().flatten().copied()).collect();
                    let state = |k: &&str| states.get(*k).map(|(s, _)| s);
                    let (color, source) = tree.folder_color(*id);
                    TreeRowView::Folder {
                        id: uuid_string(id),
                        name: node.map(|n| n.name.clone()).unwrap_or_default(),
                        parent: node.and_then(|n| n.parent).map(|p| uuid_string(&p)),
                        depth: *depth,
                        color: own(color),
                        color_source: color_source(source),
                        own_color: own(node.and_then(|n| n.color)),
                        collapsed: node.is_some_and(|n| n.collapsed),
                        active_count: keys.iter().filter(|k| state(k).is_some_and(ConnectionState::is_active)).count(),
                        has_connected: keys.iter().any(|k| matches!(state(k), Some(ConnectionState::Connected { .. }))),
                        connection_count: keys.iter().filter(|k| states.get(**k).is_some_and(|(_, m)| *m)).count(),
                        item_count: keys.len(),
                        folder_count: subtree.len() - 1,
                    }
                }
                TreeEntry::Item { key, depth } => {
                    let placement = folders.placements.get(key);
                    let own_color = placement.and_then(|p| p.color);
                    let (color, source) = tree.item_color(own_color, folder_of(key));
                    TreeRowView::Item {
                        id: key.clone(),
                        parent: folder_of(key).map(|f| uuid_string(&f)),
                        depth: *depth,
                        color: own(color),
                        color_source: color_source(source),
                        own_color: own(own_color),
                    }
                }
            })
            .collect()
    }
}

/// "Launch at Login" (the platform layer's `LoginItemState`, mapped by the app).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginItemView {
    pub is_on: bool,
    pub can_toggle: bool,
    /// The note under the switch (already translated).
    pub note: Option<String>,
    /// The "Open Login Items Settings…" button.
    pub shows_open_settings: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewModel {
    /// `en` or `hu` (the core's language rule).
    pub language: &'static str,
    pub rows: Vec<RowView>,
    /// The folder tree over `rows` (spec 3): every folder and item in display order.
    pub tree: Vec<TreeRowView>,
    /// Folders can be edited (a folder store is configured); otherwise every item is at the root.
    pub folders_enabled: bool,
    /// Why folders cannot be edited now (the 1.1 data waits for its migration), shown above the tree.
    pub folders_note: Option<String>,
    /// The colour palette's ids, in display order (the `--folder-<id>` tokens).
    pub palette: Vec<&'static str>,
    pub status_error: Option<String>,
    pub tray: TrayIcon,
    pub has_active: bool,
    pub prompts: Vec<PromptView>,
    /// The system status check found nothing missing.
    pub setup_complete: bool,
    pub update: UpdateView,
    /// `None` until the system state was read.
    pub login_item: Option<LoginItemView>,
    /// The Connections window: selection, unsaved changes, tab requests, an import's question.
    pub manage: ManageView,
    /// The System Status window.
    pub setup: SetupView,
    /// A quit question being asked (the active-connections question is shown by the menu, and for an update by
    /// the Update window).
    pub quit: Option<QuitQuestion>,
    /// Under the active-connections question: the apps whose sessions quitting ends (`quit::lease_holders_note`).
    pub quit_note: Option<String>,
    /// The control API: the setting, the paired apps, the audit lines.
    pub control: ControlView,
    /// The open pairing requests (each in its `pair-<id>` window).
    pub pairings: Vec<PairingView>,
    /// The open credential prompts (each in its `cred-<id>` window). Never a typed value.
    pub credential_prompts: Vec<CredentialPromptView>,
    /// The Connections window's Credentials section (never a password).
    pub credentials: CredentialsView,
    /// The app's version (the workspace's Cargo version, which the bundle carries too), shown at the bottom of the
    /// menu as "MacVPN <version>".
    pub app_version: &'static str,
    /// The vault's state (never a password or key).
    pub vault: VaultView,
    /// The create window's step (`vault-create`), while it is open. Never a password or the recovery key.
    pub vault_setup: Option<VaultSetupView>,
    /// "Back up everything…" and "Restore from backup…" are offered (the vault is open).
    pub backup_available: bool,
    /// The "Team catalogs" section (`CatalogService::view`). Never a team key, a token or a source's query.
    pub catalogs: Vec<crate::catalog::SubscriptionView>,
    /// The folders a team catalog owns (its root folder and the publisher's tree): folder id → catalog id. They
    /// carry the "Team" badge and are read-only.
    pub team_folders: BTreeMap<String, String>,
    /// The "Publishing" section: the admin keys and the publications. Never a key or a team key.
    pub publishing: PublishingView,
}

/// An admin key in the "Publishing" section: its role and fingerprint, never the seed.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminKeyView {
    /// `primary` or `backup`.
    pub role: &'static str,
    /// The 8 groups of the fingerprint.
    pub fingerprint: String,
    /// Unix time (seconds).
    pub created: f64,
    /// A backup key exported and removed from this Mac (only its public half is kept).
    pub offline: bool,
}

impl From<&macvpn_core::vault::AdminKeyRecord> for AdminKeyView {
    fn from(k: &macvpn_core::vault::AdminKeyRecord) -> Self {
        AdminKeyView {
            role: k.role.as_str(),
            fingerprint: k.fingerprint.to_text(),
            created: k.created.time_interval_since_1970(),
            offline: k.offline,
        }
    }
}

/// The publisher's side (spec 7): empty while the vault is locked.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishingView {
    pub admin_keys: Vec<AdminKeyView>,
    pub publications: Vec<crate::catalog_publish::PublicationView>,
}

impl PublishingView {
    /// From the publisher (nothing while the vault is locked or cannot be read).
    pub fn build(publisher: &crate::catalog_publish::Publisher) -> PublishingView {
        PublishingView {
            admin_keys: publisher.admin_keys().unwrap_or_default().iter().map(AdminKeyView::from).collect(),
            publications: publisher.publications().unwrap_or_default(),
        }
    }
}

/// The vault's part of the view model (spec 2.3). Never a password, a recovery key or a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    /// `notCreated`, `locked`, `unlocked` or `legacyReadOnly`.
    pub state: &'static str,
    /// The key-store item exists (the next launch unlocks without the password).
    pub auto_unlock: bool,
    /// The menu shows "Lock now": auto-unlock is off, or the user turned "Show Lock now" on. Only while unlocked.
    pub show_lock_now: bool,
    /// The preference "Show Lock now" itself (the settings switch).
    pub show_lock_now_pref: bool,
    /// The active connections (the locked menu shows only this count).
    pub active_count: usize,
    /// Why the app runs from the old storage (the migration's error), in the legacy read-only mode.
    pub legacy_error: Option<String>,
    /// The `vault-password` window's mode while it is open: `change` (the current password and a new one twice)
    /// or `confirm` (the master password once, to turn auto-unlock on).
    pub password_mode: Option<&'static str>,
}

impl Default for VaultView {
    /// Before the vault was looked at: as unlocked, so nothing is hidden by mistake in the tests of other parts.
    fn default() -> Self {
        VaultView {
            state: "unlocked",
            auto_unlock: true,
            show_lock_now: false,
            show_lock_now_pref: false,
            active_count: 0,
            legacy_error: None,
            password_mode: None,
        }
    }
}

impl VaultView {
    pub fn build(state: &VaultState, auto_unlock: bool, show_lock_now_pref: bool, active_count: usize) -> VaultView {
        let (name, legacy_error) = match state {
            VaultState::NotCreated => ("notCreated", None),
            VaultState::Locked => ("locked", None),
            VaultState::Unlocked => ("unlocked", None),
            // An empty error: the create window runs in migration mode (nothing failed).
            VaultState::LegacyReadOnly { error } => ("legacyReadOnly", Some(error.clone()).filter(|e| !e.is_empty())),
        };
        VaultView {
            state: name,
            auto_unlock,
            show_lock_now: *state == VaultState::Unlocked && (!auto_unlock || show_lock_now_pref),
            show_lock_now_pref,
            active_count,
            legacy_error,
            password_mode: None,
        }
    }

    /// Nothing from the vault may be shown: locked, or no vault yet (and no old storage to read).
    pub fn hides_data(&self) -> bool {
        matches!(self.state, "locked" | "notCreated")
    }
}

/// A paired app in the Connections window's "Paired apps" section. Never the token or its hash.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedAppView {
    pub id: String,
    /// Self-reported at pairing.
    pub name: String,
    /// The pinned executable path.
    pub executable: String,
    /// The connection keys it may use.
    pub allowed: Vec<String>,
    /// Unix time (seconds).
    pub created: f64,
    pub last_used: Option<f64>,
    /// The token was last presented from this other executable (the user re-pairs).
    pub path_changed: Option<String>,
}

impl PairedAppView {
    pub fn new(client: &PairedClient, path_changed: Option<&String>) -> Self {
        PairedAppView {
            id: uuid_string(&client.id),
            name: client.name.clone(),
            executable: escape_unsafe_text(&client.executable),
            allowed: client.allowed.clone(),
            created: client.created.time_interval_since_1970(),
            last_used: client.last_used.map(|d| d.time_interval_since_1970()),
            path_changed: path_changed.map(|p| escape_unsafe_text(p)),
        }
    }
}

/// The control API's part of the view model.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlView {
    /// "Allow other apps to control VPNs" is on.
    pub enabled: bool,
    /// The server is running.
    pub running: bool,
    /// Why the server could not start (translated), while the setting is on.
    pub error: Option<String>,
    pub clients: Vec<PairedAppView>,
    /// The latest audit lines ("Control API"), oldest first.
    pub activity: Vec<String>,
}

impl ControlView {
    pub fn build(
        enabled: bool,
        running: bool,
        error: Option<String>,
        clients: &[PairedClient],
        path_changes: &HashMap<Uuid, String>,
        activity: Vec<String>,
    ) -> ControlView {
        let clients = clients.iter().map(|c| PairedAppView::new(c, path_changes.get(&c.id))).collect();
        ControlView { enabled, running, error, clients, activity }
    }
}

impl ViewModel {
    /// `available`: whether the tools of a managed connection's type are installed (system VPNs always are).
    pub fn build(
        snapshot: &ManagerSnapshot,
        language: &'static str,
        available: impl Fn(VPNKind) -> bool,
        prompts: Vec<PromptView>,
        setup_complete: bool,
    ) -> ViewModel {
        let rows = snapshot
            .items
            .iter()
            .map(|(item, state, pinned)| {
                let (id, type_label, managed, available) = match item {
                    ConnectionItem::Managed(c) => {
                        (uuid_string(&c.id), c.kind.display_name().to_string(), true, available(c.kind))
                    }
                    ConnectionItem::System(s) => (s.id.clone(), s.type_label.clone(), false, true),
                };
                let (kind, stored_secrets) = match item {
                    ConnectionItem::Managed(c) => (Some(c.kind.raw_value()), false),
                    ConnectionItem::System(s) => (None, s.supports_stored_secrets()),
                };
                RowView {
                    id,
                    name: item.name().to_string(),
                    type_label,
                    managed,
                    kind,
                    stored_secrets,
                    pinned: *pinned,
                    available,
                    state: RowState::from(state),
                    switch_on: state.is_active(),
                    switch_enabled: available && *state != ConnectionState::Disconnecting,
                    held_by: Vec::new(),
                    catalog: None,
                    published: Vec::new(),
                }
            })
            .collect();
        let states: HashMap<String, (ConnectionState, bool)> = snapshot
            .items
            .iter()
            .map(|(item, state, _)| (item.id(), (state.clone(), matches!(item, ConnectionItem::Managed(_)))))
            .collect();
        ViewModel {
            language,
            rows,
            tree: TreeRowView::build(&snapshot.folders, &states),
            folders_enabled: snapshot.folders.enabled,
            folders_note: None,
            palette: FolderColor::ALL.iter().map(|c| c.as_str()).collect(),
            status_error: snapshot.status_error.clone(),
            tray: TrayIcon::from_snapshot(snapshot),
            has_active: snapshot.has_active,
            prompts,
            setup_complete,
            update: UpdateView::default(),
            login_item: None,
            manage: ManageView::default(),
            setup: SetupView::default(),
            quit: None,
            quit_note: None,
            control: ControlView::default(),
            pairings: Vec::new(),
            credential_prompts: Vec::new(),
            credentials: CredentialsView::default(),
            app_version: macvpn_core::VERSION,
            vault: VaultView::default(),
            vault_setup: None,
            backup_available: false,
            catalogs: Vec::new(),
            team_folders: BTreeMap::new(),
            publishing: PublishingView::default(),
        }
    }

    /// The "Team" badges of the catalog connections (`CatalogService::badges`).
    pub fn set_catalog_badges(&mut self, badges: &HashMap<String, crate::catalog::CatalogBadge>) {
        for row in &mut self.rows {
            row.catalog = badges.get(&row.id).cloned();
        }
    }

    /// The "Published in “…” (vN)" badges of the source connections (`Publisher::published_badges`).
    pub fn set_published_badges(&mut self, badges: &HashMap<String, Vec<crate::catalog_publish::PublishedBadge>>) {
        for row in &mut self.rows {
            row.published = badges.get(&row.id).cloned().unwrap_or_default();
        }
    }

    /// Sets the vault's part. While nothing from the vault may be shown ([`VaultView::hides_data`]) the rows (with
    /// every connection name), the paired apps and the Connections window's selection are removed; only the
    /// number of active connections stays (`vault.active_count`).
    pub fn apply_vault(&mut self, mut vault: VaultView) {
        vault.active_count = self.rows.iter().filter(|r| r.switch_on).count();
        if vault.state == "legacyReadOnly" {
            // The 1.1 data has no folders, and none may be written before the migration (it would block it).
            self.folders_enabled = false;
            self.folders_note = Some(l10n::tr("Folders can be made once your data is in the vault.", &[]));
        }
        if vault.hides_data() {
            self.rows.clear();
            // The folder tree (names, colours, placements) is vault data too; no folder editing either.
            self.tree.clear();
            self.palette.clear();
            self.folders_enabled = false;
            // The shared credentials (names, user names, how many use them) too. The lock dismissed the credential
            // prompts; one still listed is not sent, and an MFA prompt shows no connection name.
            self.credentials = CredentialsView::locked();
            self.credential_prompts.clear();
            for prompt in &mut self.prompts {
                prompt.connection_name.clear();
            }
            self.control.clients.clear();
            self.control.activity.clear();
            // The team catalogs and the publishing side (names, sources, fingerprints) are vault data too.
            self.catalogs.clear();
            self.team_folders.clear();
            self.publishing = PublishingView::default();
            self.manage.selected = None;
            self.manage.dirty.clear();
        }
        self.vault = vault;
    }

    /// The "Held by …" labels: the lease holder names per connection key (`ControlServer::holders`).
    pub fn set_holders(&mut self, holders: &BTreeMap<String, Vec<String>>) {
        for row in &mut self.rows {
            row.held_by = holders.get(&row.id).cloned().unwrap_or_default();
        }
    }
}
