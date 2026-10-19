// The backend's command and event surface (app/src-tauri/src/commands.rs). Nothing else is reachable: the
// capability file allows only these commands and listening to events.
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export type RowState =
  | { state: 'disconnected' }
  | { state: 'connecting' }
  | { state: 'connected'; ip: string | null; since: number | null }
  | { state: 'disconnecting' }
  | { state: 'failed'; reason: string }
  | { state: 'awaitingAuth'; wait: 'code' | 'web' | 'credentials'; deadline: number | null };

export type Kind = 'openvpn' | 'wireguard' | 'strongswan' | 'sstp' | 'l2tp' | 'cisco';

export type Row = RowState & {
  id: string;
  name: string;
  typeLabel: string;
  managed: boolean;
  kind: Kind | null;
  storedSecrets: boolean;
  pinned: boolean;
  available: boolean;
  switchOn: boolean;
  switchEnabled: boolean;
  /// The paired apps holding the connection through the control API.
  heldBy: string[];
};

/// The folder and connection colour palette (spec 3): the `--folder-<id>` tokens.
export type FolderColor =
  | 'red'
  | 'orange'
  | 'amber'
  | 'yellow'
  | 'lime'
  | 'green'
  | 'teal'
  | 'cyan'
  | 'blue'
  | 'indigo'
  | 'purple'
  | 'pink';

/// Where an effective colour comes from: the row's own, an ancestor folder's, or none.
export type ColorSource = 'own' | 'inherited' | 'none';

/// A folder of the tree. The counts cover the folder and all its subfolders.
export interface FolderTreeRow {
  type: 'folder';
  id: string;
  name: string;
  /// null: at the top level.
  parent: string | null;
  /// The real nesting depth (0 at the top level); the views cap the indentation.
  depth: number;
  color: FolderColor | null;
  colorSource: ColorSource;
  ownColor: FolderColor | null;
  collapsed: boolean;
  activeCount: number;
  hasConnected: boolean;
  /// Managed connections (what "Delete the connections too" deletes).
  connectionCount: number;
  itemCount: number;
  folderCount: number;
}

/// An item of the tree; its other fields are the `rows` entry with the same id.
export interface ItemTreeRow {
  type: 'item';
  id: string;
  parent: string | null;
  depth: number;
  color: FolderColor | null;
  colorSource: ColorSource;
  /// The item's own colour (an override of the folder's).
  ownColor: FolderColor | null;
}

/// The folder tree in display order: per folder its subfolders, then its items (pinned first, then by use).
export type TreeRow = FolderTreeRow | ItemTreeRow;

export interface PromptView {
  id: number;
  connectionId: string;
  connectionName: string;
  kind: 'code' | 'webAuth';
  text: string | null;
  echo: boolean;
  fromServer: boolean;
  url: string | null;
  /// The web sign-in URL's host (ASCII, lower case).
  host: string | null;
  deadline: number;
}

/// A credential the prompt asks for.
export type CredentialField = 'username' | 'password' | 'psk' | 'keyPassword';

/// An open credential prompt (its window is `cred-<id>`). Never a typed value.
export interface CredentialPromptView {
  id: number;
  connectionId: string;
  connectionName: string;
  /// Only the asked fields, in display order.
  fields: CredentialField[];
  /// The stored user name, pre-filled.
  username: string | null;
  /// The re-prompt's "Sign-in failed …" line (already localized).
  message: string | null;
  deadline: number;
  /// The shared credential the asked password belongs to (its name and how many connections use it), or null for
  /// the connection's own fields.
  credentialName: string | null;
  usedBy: number | null;
}

export type TrayIcon = 'idle' | 'active' | 'failure' | 'auth';

export interface ReleaseView {
  tag: string;
  /// Plain text: rendered with inline emphasis only (never as HTML).
  notes: string;
  hasPage: boolean;
}

export interface UpdateView {
  enabled: boolean;
  available: string | null;
  checking: boolean;
  autoCheck: boolean;
  delayUpdates: boolean;
  currentVersion: string;
  release: ReleaseView | null;
  installStage: string | null;
  installError: string | null;
  notice: Notice | null;
}

export interface CheckRow {
  ok: boolean;
  detail: string;
}

export interface SetupView {
  checked: boolean;
  homebrew: CheckRow | null;
  tools: CheckRow | null;
  root: CheckRow | null;
  canInstallTools: boolean;
  brewOutput: string;
  brewRunning: boolean;
  installingRoot: boolean;
  installError: string | null;
  upgradeNotice: string | null;
  uninstalling: boolean;
}

export interface QuitQuestion {
  origin: 'menu' | 'system' | 'update' | 'uninstall';
  step: 'unsaved' | 'activeConnections';
}

export interface UninstallResult extends Notice {
  done: boolean;
}

export interface LoginItemView {
  isOn: boolean;
  canToggle: boolean;
  note: string | null;
  showsOpenSettings: boolean;
}

export interface Notice {
  title: string;
  message: string;
}

export type CheckNowResult = { result: 'available' } | ({ result: 'notice' } & Notice);

export interface QuestionView {
  id: number;
  title: string;
  message: string;
  yes: string;
  no: string;
  /// A choice question's options (a pop-up menu; `yes` takes the chosen one). Empty for yes / no.
  options: string[];
}

export interface Choice<T extends string = string> {
  value: T;
  title: string;
}

export type LogFilter = 'all' | 'commands' | 'errors';

export interface ManageView {
  selected: string | null;
  pending: 'select' | 'closeWindow' | 'quit' | null;
  dirty: string[];
  logRequest: string | null;
  settingsRequest: string | null;
  question: QuestionView | null;
  editorsEpoch: number;
  kinds: Choice<Kind>[];
  logFilters: Choice<LogFilter>[];
  /// The selected system VPN was removed from macOS: its detail stays, read-only.
  selectedRemoved: boolean;
}

export interface Otp {
  enabled: boolean;
  separator: 'none' | 'comma' | 'colon';
}

/// A secret field: `null` keeps the stored value (the backend never sends it), a string stores it (`''`: removes
/// the stored one).
export type SecretInput = string | null;

export interface TextFields {
  type: 'text';
  name: string;
  text: string;
  username: string;
  password: SecretInput;
  psk: SecretInput;
  keyPassword: SecretInput;
  acknowledged: string[];
  otp: Otp;
}

export interface NativeFields {
  type: 'native';
  name: string;
  server: string;
  account: string;
  groupName: string;
  sendAllTraffic: boolean;
  password: SecretInput;
  psk: SecretInput;
  otp: Otp;
}

export interface SstpFields {
  type: 'sstp';
  name: string;
  server: string;
  port: number;
  user: string;
  cert: 'system' | 'ca' | 'insecure';
  routeAll: boolean;
  peerDns: boolean;
  caPem: string;
  password: SecretInput;
  otp: Otp;
}

export interface SystemFields {
  type: 'system';
  psk: SecretInput;
  password: SecretInput;
  otp: Otp;
}

/// Which secret fields have a value in the vault.
export interface StoredSecrets {
  password: boolean;
  psk: boolean;
  keyPassword: boolean;
}

export type EditorFields = TextFields | NativeFields | SstpFields | SystemFields;

export interface RiskyView {
  line: number;
  directive: string;
  reason: string;
}

export interface EditorView {
  id: string;
  kind: Kind | 'system';
  fields: EditorFields;
  dirty: boolean;
  issues: string[];
  error: string | null;
  saved: boolean;
  savedAt: number | null;
  risky: RiskyView[];
  acknowledgesRisk: boolean;
  staticChallenge: boolean;
  certCount: number;
  passwordRule: string | null;
  importError: string | null;
  hasStored: boolean;
  hasStoredSecret: StoredSecrets;
  /// System VPN: removed from macOS (the editor is read-only).
  removed: boolean;
  /// The shared credential (its name) the username and password come from; `null`: its own fields.
  credential: string | null;
}

export interface Report {
  title: string;
  message: string;
}

export interface LogLineView {
  text: string;
  kind: 'header' | 'step' | 'command' | 'error' | 'output';
}

export interface LogEvent {
  generation: number;
  reset: boolean;
  lines: LogLineView[];
}

/// A paired app of the control API (never its token or the token's hash).
export interface PairedApp {
  id: string;
  /// Self-reported at pairing.
  name: string;
  /// The pinned executable path.
  executable: string;
  allowed: string[];
  created: number;
  lastUsed: number | null;
  /// The token was last presented from this other executable.
  pathChanged: string | null;
}

export interface ControlView {
  enabled: boolean;
  running: boolean;
  error: string | null;
  clients: PairedApp[];
  activity: string[];
}

export interface PairingItem {
  id: string;
  name: string;
}

/// An open pairing request (its window is `pair-<id>`).
export interface PairingView {
  id: number;
  /// Self-reported by the app.
  name: string;
  executable: string;
  items: PairingItem[];
  deadline: number;
}

/// The vault's state (spec 2.3). Never a password or the recovery key.
export interface VaultView {
  state: 'notCreated' | 'locked' | 'unlocked' | 'legacyReadOnly';
  autoUnlock: boolean;
  /// The menu shows "Lock now" (auto-unlock off, or the preference on).
  showLockNow: boolean;
  /// The preference "Show Lock now" itself.
  showLockNowPref: boolean;
  /// The active connections (the locked menu shows only this count).
  activeCount: number;
  /// Why the app runs from the old storage (a failed migration).
  legacyError: string | null;
  /// The `vault-password` window's mode while it is open.
  passwordMode: 'change' | 'confirm' | null;
}

/// The vault windows the menu opens.
export type VaultWindowName = 'unlock' | 'create' | 'changePassword' | 'confirmPassword' | 'newRecoveryKey';

/// A new recovery key (`vault-recovery`): the check's reply, and on success the key, shown once.
export interface NewKeyReply {
  reply: UnlockReply;
  key: { recoveryKey: string; group: number } | null;
}

export type VaultSetupStep =
  | 'intro'
  | 'password'
  | 'recoveryKey'
  | 'confirm'
  | 'migrating'
  | 'verified'
  | 'done'
  | 'failed';

/// The create window's step (`vault-create`). Never a password or the recovery key.
export interface VaultSetupView {
  step: VaultSetupStep;
  migrating: boolean;
  keychainItems: number;
  /// `confirm`: the group to retype, 0-based.
  group: number | null;
  message: string | null;
  connections: number;
  secrets: number;
  skipped: number;
  canRestore: boolean;
  /// A backup is restored in place of the migration (after the recovery key check).
  restoring: boolean;
  /// A migration left from an earlier run, shown at launch.
  resumed: boolean;
  /// `failed`: the new vault was removed (the old data is used read-only); otherwise the vault was kept.
  vaultRemoved: boolean;
}

/// The reply of an unlock (or a password check). Never any part of the secret.
export interface UnlockReply {
  ok: boolean;
  error: 'wrong' | 'tooSoon' | 'corrupt' | 'newer' | 'invalid' | 'error' | null;
  /// The next attempt is taken after this many milliseconds.
  retryAfterMs: number | null;
  message: string | null;
}

export type VaultSetupAction = 'continue' | 'back' | 'saved' | 'retry' | 'finish' | 'close';

/// A shared credential in the Credentials section (never its password).
export interface CredentialItem {
  id: string;
  name: string;
  username: string;
  hasPassword: boolean;
  usedBy: number;
}

export interface CredentialsView {
  /// The vault is open: the list is real.
  available: boolean;
  /// Why not (the vault is locked).
  message: string | null;
  items: CredentialItem[];
}

/// A connection with the same username and password ("Create from connection…"): never the values.
export interface CredentialMatch {
  item: string;
  name: string;
}

export interface ViewModel {
  language: 'en' | 'hu';
  rows: Row[];
  /// The folder tree over `rows` (every folder and item, collapsed folders' contents included).
  tree: TreeRow[];
  /// Folders can be edited (otherwise every item is at the top level).
  foldersEnabled: boolean;
  /// Why folders cannot be edited now (shown above the tree).
  foldersNote: string | null;
  palette: FolderColor[];
  statusError: string | null;
  tray: TrayIcon;
  hasActive: boolean;
  prompts: PromptView[];
  setupComplete: boolean;
  update: UpdateView;
  loginItem: LoginItemView | null;
  manage: ManageView;
  setup: SetupView;
  quit: QuitQuestion | null;
  /// Under the active-connections question: the apps whose sessions quitting ends.
  quitNote: string | null;
  control: ControlView;
  pairings: PairingView[];
  credentialPrompts: CredentialPromptView[];
  /// The Connections window's Credentials section.
  credentials: CredentialsView;
  /// The app's version (the backend's Cargo / bundle version), shown at the bottom of the menu.
  appVersion: string;
  vault: VaultView;
  vaultSetup: VaultSetupView | null;
  /// "Back up everything…" and "Restore from backup…" are offered (the vault is open).
  backupAvailable: boolean;
}

export type WindowName = 'manage' | 'setup' | 'update';
export type QuitChoice = 'disconnectAndQuit' | 'keepRunning' | 'cancel';
export type QuitReply = 'terminating' | 'ask' | 'unsaved' | 'cancelled' | 'update';
export type PromptAction = 'code' | 'openUrl' | 'cancel';
export type CredentialAction = 'connect' | 'cancel';
export type UnsavedChoice = 'save' | 'discard' | 'cancel';

export const api = {
  viewModel: () => invoke<ViewModel>('get_view_model'),
  connect: (id: string, debug: boolean) => invoke<void>('connect', { id, debug }),
  disconnect: (id: string) => invoke<void>('disconnect', { id }),
  pin: (id: string) => invoke<void>('pin', { id }),
  unpin: (id: string) => invoke<void>('unpin', { id }),
  movePinned: (from: number[], to: number) => invoke<void>('move_pinned', { from, to }),
  openWindow: (name: WindowName) => invoke<void>('open_window', { name }),
  setMenuHeight: (height: number) => invoke<void>('set_menu_height', { height }),
  /// A prompt window's content height (its own window only).
  fitWindow: (height: number) => invoke<void>('fit_window', { height }),
  quit: (choice: QuitChoice | null) => invoke<QuitReply>('quit', { choice }),
  checkForUpdates: () => invoke<CheckNowResult>('check_for_updates'),
  setUpdateOption: (option: 'autoCheck' | 'delayUpdates', on: boolean) => invoke<void>('set_update_option', { option, on }),
  setLaunchAtLogin: (on: boolean) => invoke<Notice | null>('set_launch_at_login', { on }),
  openLoginItemsSettings: () => invoke<void>('open_login_items_settings'),
  openUserGuide: () => invoke<void>('open_user_guide'),
  // The Connections window.
  selectConnection: (id: string | null) => invoke<boolean>('select_connection', { id }),
  resolveUnsaved: (choice: UnsavedChoice) => invoke<Report | null>('resolve_unsaved', { choice }),
  takeTabRequest: (id: string) => invoke<'settings' | 'log' | null>('take_tab_request', { id }),
  editorOpen: (id: string) => invoke<EditorView>('editor_open', { id }),
  editorUpdate: (id: string, fields: EditorFields) => invoke<EditorView>('editor_update', { id, fields }),
  editorSave: (id: string, fields: EditorFields) => invoke<EditorView>('editor_save', { id, fields }),
  editorForget: (id: string) => invoke<EditorView>('editor_forget', { id }),
  editorChooseCa: (id: string) => invoke<EditorView>('editor_choose_ca', { id }),
  createConnection: (kind: Kind) => invoke<void>('create_connection', { kind }),
  importFiles: () => invoke<Report | null>('import_files'),
  answerQuestion: (id: number, answer: boolean) => invoke<void>('answer_question', { id, answer }),
  exportCheck: (id: string) => invoke<Report | null>('export_check', { id }),
  exportConnection: (id: string, withKeys: boolean) => invoke<Notice | null>('export_connection', { id, withKeys }),
  deleteConnection: (id: string) => invoke<void>('delete_connection', { id }),
  logSubscribe: (id: string | null) => invoke<LogEvent | null>('log_subscribe', { id }),
  logCopy: (filter: LogFilter, search: string) => invoke<void>('log_copy', { filter, search }),
  logSave: () => invoke<Notice | null>('log_save'),
  // System Status.
  setupCheck: () => invoke<void>('setup_check'),
  setupInstallHomebrew: () => invoke<Notice | null>('setup_install_homebrew'),
  setupInstallTools: () => invoke<void>('setup_install_tools'),
  setupInstallRoot: () => invoke<void>('setup_install_root'),
  setupUninstall: (removeUserData: boolean) => invoke<UninstallResult>('setup_uninstall', { removeUserData }),
  quitAfterUninstall: () => invoke<QuitReply>('quit_after_uninstall'),
  closeWindow: (name: WindowName) => invoke<void>('close_window', { name }),
  // Update.
  updateInstall: () => invoke<void>('update_install'),
  updateOpenPage: () => invoke<void>('update_open_page'),
  updateDismissNotice: () => invoke<void>('update_dismiss_notice'),
  // MFA prompt windows (only their own prompt).
  answerPrompt: (id: number, action: PromptAction, response: string | null) =>
    invoke<void>('answer_prompt', { id, action, response }),
  /// The page is loaded and shows the prompt: the backend's input lock counts from now (at the earliest).
  promptReady: (id: number) => invoke<void>('prompt_ready', { id }),
  // Credential windows (only their own prompt): `connect` with exactly the asked fields, or `cancel` with none.
  answerCredentials: (id: number, action: CredentialAction, values: Partial<Record<CredentialField, string>>, save: boolean) =>
    invoke<void>('answer_credentials', { id, action, values, save }),
  /// The page is loaded and shows the prompt: the backend's input lock counts from now (at the earliest).
  credentialsReady: (id: number) => invoke<void>('credentials_ready', { id }),
  // Pairing windows (only their own pairing): `null` denies.
  pairingAnswer: (id: number, allowed: string[] | null) => invoke<void>('pairing_answer', { id, allowed }),
  pairingReady: (id: number) => invoke<void>('pairing_ready', { id }),
  // Paired apps (the Connections window).
  controlSetEnabled: (on: boolean) => invoke<void>('control_set_enabled', { on }),
  controlSetAllowed: (clientId: string, keys: string[]) => invoke<void>('control_set_allowed', { clientId, keys }),
  controlRevoke: (clientId: string) => invoke<void>('control_revoke', { clientId }),
  /// The audit log into a file chosen in the save panel (a failure comes back as the alert).
  controlAuditSave: () => invoke<Notice | null>('control_audit_save'),
  // The vault windows (each command checks the calling window; secrets are sent once and never come back, except
  // the new recovery key in the create reply).
  /// The page is loaded and shown: the window's input lock counts from now (at the earliest).
  vaultReady: () => invoke<void>('vault_ready'),
  /// The window follows its content's height.
  vaultSetupStep: (action: VaultSetupAction) => invoke<void>('vault_setup_step', { action }),
  vaultCreate: (password: string, autoUnlock: boolean) =>
    invoke<{ recoveryKey: string; group: number }>('vault_create', { password, autoUnlock }),
  vaultConfirmRecovery: (group: number, typed: string) => invoke<void>('vault_confirm_recovery', { group, typed }),
  vaultOpenRestore: () => invoke<void>('vault_open_restore'),
  vaultUnlock: (password: string) => invoke<UnlockReply>('vault_unlock', { password }),
  vaultRecover: (recoveryKey: string, newPassword: string) =>
    invoke<UnlockReply>('vault_recover', { recoveryKey, newPassword }),
  /// Closes the calling vault window (Cancel, Done).
  vaultClose: () => invoke<void>('vault_close'),
  vaultChangePassword: (current: string, newPassword: string) =>
    invoke<UnlockReply>('vault_change_password', { current, newPassword }),
  vaultEnableAutoUnlock: (password: string) => invoke<UnlockReply>('vault_enable_auto_unlock', { password }),
  vaultNewRecoveryKey: (password: string) => invoke<NewKeyReply>('vault_new_recovery_key', { password }),
  vaultConfirmNewKey: (group: number, typed: string) => invoke<void>('vault_confirm_new_key', { group, typed }),
  /// The recovery key was copied: the backend empties the pasteboard a minute later if it still holds a key.
  vaultKeyCopied: () => invoke<void>('vault_key_copied'),
  // The vault from the menu (and the Connections window).
  vaultShow: (window: VaultWindowName) => invoke<void>('vault_show', { window }),
  vaultLockNow: () => invoke<void>('vault_lock_now'),
  vaultAutoUnlockOff: () => invoke<void>('vault_auto_unlock_off'),
  vaultSetShowLockNow: (on: boolean) => invoke<void>('vault_set_show_lock_now', { on }),
  // Folders and colours (`parent` / `folder` null: the top level; `color` null: none / "Use folder colour").
  folderCreate: (parent: string | null, name: string) => invoke<string>('folder_create', { parent, name }),
  folderRename: (id: string, name: string) => invoke<void>('folder_rename', { id, name }),
  folderSetColor: (id: string, color: FolderColor | null) => invoke<void>('folder_set_color', { id, color }),
  folderSetCollapsed: (id: string, collapsed: boolean) => invoke<void>('folder_set_collapsed', { id, collapsed }),
  folderMove: (id: string, parent: string | null, position: number) => invoke<void>('folder_move', { id, parent, position }),
  folderDelete: (id: string, mode: 'moveUp' | 'deleteContents') => invoke<void>('folder_delete', { id, mode }),
  itemMove: (key: string, folder: string | null) => invoke<void>('item_move', { key, folder }),
  itemSetColor: (key: string, color: FolderColor | null) => invoke<void>('item_set_color', { key, color }),
  // Shared credentials (the Connections window). A password goes only to the backend, never back.
  credentialCreate: (name: string, username: string, password: string | null) =>
    invoke<void>('credential_create', { name, username, password }),
  credentialUpdate: (id: string, name: string | null, username: string | null, password: SecretInput) =>
    invoke<void>('credential_update', { id, name, username, password }),
  /// `null`: deleted; otherwise the names of the connections that use it (nothing changed).
  credentialDelete: (id: string, copyInto: boolean) => invoke<string[] | null>('credential_delete', { id, copyInto }),
  credentialLink: (item: string, credential: string | null) => invoke<void>('credential_link', { item, credential }),
  credentialMatches: (item: string) => invoke<CredentialMatch[]>('credential_matches', { item }),
  credentialFromConnection: (item: string, name: string, link: string[]) =>
    invoke<void>('credential_from_connection', { item, name, link }),
  /// A choice question's answer: the option's index, or `null` for the negative button.
  answerQuestionChoice: (id: number, choice: number | null) => invoke<void>('answer_question_choice', { id, choice }),
};

export function onViewModel(handler: (vm: ViewModel) => void): Promise<UnlistenFn> {
  return listen<ViewModel>('view-model', (event) => handler(event.payload));
}

/// A drop on the Connections window was imported (the report to show).
export function onImportReport(handler: (report: Report) => void): Promise<UnlistenFn> {
  return listen<Report>('import-report', (event) => handler(event.payload));
}

/// New lines of the Log tab being shown.
export function onLogLines(handler: (event: LogEvent) => void): Promise<UnlistenFn> {
  return listen<LogEvent>('log-lines', (event) => handler(event.payload));
}
