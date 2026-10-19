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

/// Which secret fields have a value in the Keychain.
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

export interface ViewModel {
  language: 'en' | 'hu';
  rows: Row[];
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
