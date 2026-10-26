# MacVPN app (Tauri 2)

- `src-tauri/`: the Rust shell (`macvpn-app`): tray icon, menu popover, windows and the IPC commands. It reaches
  the operating system only through `macvpn-platform-api`: `src-tauri/src/platform/` (the app's only
  `cfg(target_os)`) creates the platform (`MacPlatform` from `macvpn-platform-mac` on macOS, `WinPlatform` from
  `macvpn-platform-win` on Windows) and holds the Tauri glue (native window handle, activation policy, the macOS
  run events, the Windows single instance and its forwarded files) and the smoke driver. On Windows the app is
  WinVPN: no app menu, the popover above the taskbar icon, a tinted tray icon, and System Status' rows for the
  WinVPN Service, OpenVPN Community, WireGuard and the Windows VPN client.
- `ui/`: the web UI (Svelte 5 + TypeScript + Vite). Texts come from `crates/core/l10n/strings.json` (scope `app`
  only is bundled); the language is the core's rule, sent by the backend in the view model. The OS and the product
  name (for the per-OS text variants and the Cmd / Ctrl shortcuts) come from the `get_platform` command at start.
- The logic (connection manager, view model, polling, launch order, quit decision, update schedule) is in
  `crates/app-core`, tested without a UI.

The rest of the repository: `crates/core` (platform-independent logic and the EN/HU text table), `crates/platform-api`
(the platform traits and the product identity), `crates/platform-mac` (the macOS platform), `crates/platform-win` (the
Windows platform), `crates/winsys` (its Win32 bindings, shared with core), `crates/helper` (the root binary `mvpn` on
macOS, the WinVPN Service `WinVPNService.exe` on Windows), `scripts/` (build, test and signing scripts). How they fit
together: [`docs/architecture.md`](../docs/architecture.md). The 0.x Swift app is only in the git history (up to tag
`v0.4.0`).

## Build

Toolchain: `rust-toolchain.toml` pins the exact Rust version (1.99.1, with clippy, rustfmt, both macOS targets and
both Windows targets), which `rustup` uses inside the repository (`rustup toolchain install` installs it). CI and the release workflow use
Node.js 26.8.2; `package.json` requires at least 22.12.

```sh
cd app/ui
npm ci              # pinned versions (package-lock.json); the Tauri CLI is a dev dependency
npm test            # language rule, format, l10n coverage of the UI sources
npm run build       # svelte-check, then vite build -> app/ui/dist

cargo build -p macvpn-app                              # dev build (see below)
cargo build -p macvpn-app --features custom-protocol   # embeds app/ui/dist
npm run tauri -- build --debug --no-bundle             # the same through the Tauri CLI
```

### Why `cargo` needs no Node (the `custom-protocol` feature)

`tauri::generate_context!()` only embeds the UI when the `custom-protocol` feature is on (Tauri's standard
dev / production split). Without it (`cargo build`, `cargo clippy`, `cargo test --workspace`, the CI cargo jobs)
the binary is a dev build that loads the Vite dev server (`devUrl`, `npm run dev` in `app/ui`, or
`npm run tauri dev`), so neither Node nor a built `dist` is needed, and no placeholder `dist` is committed. With
the feature on, the build fails at compile time if `app/ui/dist` is missing; `npm run tauri build` runs
`npm run build` first.

### Release build (`scripts/build-dmg.sh`)

`scripts/build-dmg.sh` makes `dist/MacVPN.app` and `dist/MacVPN-<version>.dmg` (the app and an `Applications`
link): `npm ci && npm run build`, then `tauri build --target universal-apple-darwin --features custom-protocol`
(arm64 + x86_64, `lipo`; `mainBinaryName` makes the executable `MacVPN`, `src-tauri/Info.plist` is merged into the
bundle's Info.plist), the universal `mvpn` and `crates/helper/VERSION` into `Contents/Resources/root/` (where the
root installer looks), `Resources/AppIcon.icns` as the icon. Every Info.plist key the updater and macOS rely on
is checked (`local.macvpn`, `MacVPN`, the version, 14.0, `LSUIElement`, `en` / `[en, hu]`, the update source).
`mvpn` and the bundle are signed ad-hoc with the hardened runtime and no entitlements (dyld ignores `DYLD_*` and
loads no foreign library, so nothing can be injected into the app that reads the Keychain); `codesign --verify
--strict` (also `--deep`) and the symlink check must pass. The version is the one in
`tauri.conf.json`, which must equal the workspace `Cargo.toml` and `app/ui/package.json` versions. The language
list comes from `CFBundleLocalizations` (no `.lproj` needed: the app reads the preferred languages through
`CFLocaleCopyPreferredLanguages`, which honours a per-app language set in System Settings).
`MVPN_IMPL=rust MVPN_BIN=$PWD/dist/MacVPN.app/Contents/Resources/root/mvpn scripts/test-root.sh` runs the root
layer tests against the signed binary.

The WinVPN MSIs (`WinVPN-<version>-x64.msi`, `-arm64.msi`) are built on Windows by `scripts/build-msi.sh`, with
gates of their own: see [The WinVPN MSIs](../docs/architecture.md#the-winvpn-msis).

### The vault database: SQLCipher with CommonCrypto

The vault (`crates/core`, behind the `vault` cargo feature, enabled by `macvpn-app-core` and
`macvpn-platform-mac` only) is SQLCipher 4 through `rusqlite` with `bundled-sqlcipher`. On macOS, `libsqlite3-sys`
builds SQLCipher with Apple's **CommonCrypto** provider, but only when no OpenSSL location is set: with any
`OPENSSL_DIR`, `OPENSSL_LIB_DIR`, `OPENSSL_INCLUDE_DIR`, `OPENSSL_STATIC` or `OPENSSL_LIBS` (also the
`AARCH64_APPLE_DARWIN_` / `X86_64_APPLE_DARWIN_` prefixed forms) it silently links that `libcrypto` dylib (for
example Homebrew's). Its build script does not track these variables for rebuilds, so an exported variable can
also leave a stale build behind. Keep them unset when you build (`unset OPENSSL_DIR …`, then `cargo clean -p
libsqlite3-sys` if one was set); `scripts/build-dmg.sh` unsets all of them itself.

**Release gates** in `scripts/build-dmg.sh` (the build fails if one does not hold):

- the app binary contains none of the debug-only markers (`setInspectable`, `developerExtrasEnabled`,
  `MACVPN_SANDBOX_HOME`, `MACVPN_SMOKE`);
- `otool -L` of the app binary lists no `libcrypto`, `libssl` or `openssl`;
- in each architecture slice, the app binary contains no `openssl` / `libcrypto` string, and the linked SQLCipher
  carries the `commoncrypto` provider name;
- `mvpn` contains neither `sqlcipher` nor `SQLite format`: the vault code must never reach the root layer
  (`crates/helper` uses `crates/core` without the `vault` feature);
- the bundle carries `THIRD-PARTY-NOTICES.txt` (see `docs/RELEASING.md`), and the usual Info.plist, signature and
  symlink checks pass.

## Tests

- `cargo test --workspace`: unit, compatibility and l10n coverage tests (also of this app's logic in `crates/app-core`)
- `scripts/test-root.sh`: black-box tests of the `mvpn` root binary (dry run, no root needed; `MVPN_BIN=` tests a
  built binary)
- `npm test` and `npm run build` in `app/ui`: the UI tests, then `svelte-check` and the build
- `scripts/smoke-manage.sh`: the smoke test of the real windows (below), with `SMOKE_LANG=en` and `SMOKE_LANG=hu`
- `scripts/check-windows.sh`: the Windows compile check that runs on a Mac (`macvpn-core` without the vault,
  `macvpn-helper`, the control client; both Windows targets, debug and release). The app, app-core, the vault and
  the platform crates need an MSVC toolchain for their C code, so they are checked on Windows: in CI (the
  `windows` and `windows-node` jobs in `.github/workflows/ci.yml`) and on the Windows test machine
  (`scripts/win-remote.sh test`, `scripts/win-remote.sh run 'cargo test --locked --target x86_64-pc-windows-msvc -p macvpn-app'`)
- `scripts/check-ignored.sh`: no test is ignored on one OS only
- `crates/app-core/tests/cfg_rule.rs` (in `cargo test`): an OS `cfg` in this crate only under `src/platform/`,
  and no `unsafe` at all
- `scripts/bundle-baseline.sh dist/MacVPN.app` and `node scripts/l10n-baseline.mjs --check`: the built bundle and
  the macOS texts compared with the 1.4.0 baseline
- the manual checklist: `docs/manual-test-checklist.md` (its WinVPN section for what needs a Windows desktop)

## Running a development build without touching real data

Debug builds honour `MACVPN_SANDBOX_HOME=<absolute dir>`: the vault and the app's other files live under that
directory, and the Keychain is replaced by an in-memory store (the vault's auto-unlock key stays in memory; no
prompt). `mvpn status` and `scutil --nc list` still run (read-only). Release builds ignore the variable.

```sh
MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app
```

Native (L2TP / Cisco) profiles are staged under `<sandbox>/tmp` and never opened, so nothing reaches the
system's profiles. The sandbox never changes the system: the Homebrew installer script is written but not opened,
`brew install` is not run (a simulated output instead), the root installer and uninstaller answer as if the
administrator prompt was cancelled, a web sign-in URL is not opened, preferences stay in memory, no login item
is registered, no notification is posted (notifications need an app bundle). The update steps run against
`<sandbox>/tmp` (nothing is downloaded or mounted; the helper script is written, never run): with nothing to
ask before quitting, "Download and Install" only quits the app.

On Windows (at the desktop, in a Command Prompt; the sandbox keeps the vault key and the preferences in memory,
never in Credential Manager or `%LOCALAPPDATA%\WinVPN`, registers no login item, and its RAS engine writes only to a
private phonebook under the sandbox, never dialling):

```bat
cd app\ui && npm run dev
rem in a second Command Prompt, from the repository root:
cargo build -p macvpn-app
set MACVPN_SANDBOX_HOME=%TEMP%\winvpn-sandbox
target\debug\macvpn-app.exe
```

Toasts need the AppUserModelID of the installed MSI's Start-menu shortcut, so test them with the MSI
(`scripts/build-msi.sh`, see `docs/architecture.md`, "The WinVPN MSIs").

### Smoke test of the windows

`scripts/smoke-manage.sh` (after `npm run build` and `cargo build -p macvpn-app --features custom-protocol`)
seeds a throwaway sandbox and starts the app with `MACVPN_SMOKE_DIR=scripts/smoke` (debug builds and the sandbox
only). The scripts there run one after the other in the real windows, each saving its result into a seeded
connection's name, and the shell checks the vault's dump and the log (`SMOKE_LOG=<file>` keeps the log).
`SMOKE_LANG=en` / `SMOKE_LANG=hu` forces the language the way macOS selects it (`-AppleLanguages '(hu)'`, the
argument domain of the `AppleLanguages` preference) and checks that the core picked it and the windows show it; run
it in both before a release. The header of `scripts/smoke-manage.sh` describes every step; in short:

- the vault (`vault-create.js`, `vault-menu.js`, `vault-unlock.js`, `vault-password.js`), the Connections window
  (`manage.js`, `folders.js`, `shared.js`, `shared-prompt.js`), System Status (`setup.js`, a mock report), Update
  (`update.js`, a mock release), the MFA and credential prompts (`prompt.js`, `credentials.js`), backup and restore
  (`backup.js`, `restore.js`), the control API (`control.js`, `pairing.js`, with the Node client
  `control-client.mjs`), the live system VPN list (`live.js`, `live-menu.js`), team catalogs (`catalog.js`,
  `publish.js`), files opened from Finder (`open.js`), the quit flows (`quit.js`, `system.js`);
- the 2.0 features: `appearance.js`, `engines.js` (a missing engine greyed with "Not installed: … – System
  Status"), `notices.js` (connection notifications, recorded: the sandbox posts none) and `reconnect.js`
  (auto-reconnect over a scripted network and the sleep / wake hooks);
- Windows only: `ras.js` (the native VPNs through the stand-in helper and native layer, never a dial).

On Windows `scripts/win-smoke.sh en|hu` runs the same script in the test machine's desktop session; the AppKit-only
steps (the Dock icon, the screenshots) print "skipped on Windows".

## Localization check

Every text has an English key and a Hungarian text in `crates/core/l10n/strings.json`:

- `npm test` (`l10n.test.ts`): every `tr('…')` key of the UI is an `app` entry with a Hungarian text, `tr` only gets
  literal keys, and no text is hard-coded in the Svelte markup (text nodes, `title` / `placeholder` /
  `aria-label` / `label` … attributes) or in TypeScript objects.
- `cargo test` (`crates/app-core/tests/l10n_coverage.rs`): every key the Rust side translates (core, `mvpn`,
  platform layer, app logic, Tauri shell), literal or passed through a listed variable, has a Hungarian text;
  `crates/core/tests/l10n.rs` checks the table itself (both languages, the same format specifiers, also in every
  per-OS variant). `macos_terms_are_classified` (in `l10n_coverage.rs`) fails for a text that names a macOS
  facility (Keychain, Finder, System Settings, Dock, …) without `only` or a `windows` variant: see
  [Texts per OS](../docs/architecture.md#texts-per-os).

## Security

- CSP: `default-src 'self'`, scripts / styles / images / fonts only from the app, IPC only, no `eval`, no
  objects, frames or forms; `freezePrototype`; the asset protocol is off; no remote URL is ever loaded.
- Capabilities: only the app's own commands (generated as `allow-<command>` by `build.rs`) and listening to
  events. Each main window has its own file granting only the commands its UI uses: `menu.json` (the menu
  popover), `manage.json` (Connections), `setup.json` (System Status) and `update.json` (Update);
  `prompt.json` (the `prompt-*` windows) grants only `get_view_model`, `get_platform`, `prompt_ready`,
`answer_prompt`, `fit_window` and listening to events; `credentials.json` (`cred-*`), `pairing.json` (`pair-*`),
`vault.json` (the vault windows), `restore-fresh.json` (a restore from the vault's create window) and
`backup.json` (backup and restore) grant only their own windows' commands in the same way. The
  commands that change the machine or delete data also check the calling window's label in Rust (`guard.rs`):
  `ras_trust_ca`, `ras_allow_l2tp_nat`, `make_l2tp_copy`, `delete_connection`, `folder_delete`,
  `export_connection`, `control_set_enabled`, `control_set_allowed` and `control_revoke` (Connections only);
  the `setup_install_*` commands, `setup_uninstall`, `setup_open_system_uninstall` and `quit_after_uninstall`
  (System Status only); `update_install` (Update only). No core window / webview / path API, no plugin (a test keeps the files to exactly the generated commands). Every
  window's capability also grants `get_platform` (read-only, no input; it returns the OS and the product name).
- Commands (the full list is the `generate_handler!` in `src-tauri/src/main.rs`): the menu's `get_view_model`,
  `get_platform`, `connect` (with the Option-click / Alt-click debug flag), `disconnect`, `pin`, `unpin`,
  `move_pinned`, `open_window`, `set_menu_height`, `quit`, `check_for_updates`, `set_update_option`,
  `set_launch_at_login`, `set_appearance`, `set_connection_notifications`, `open_login_items_settings`,
  `open_user_guide`; the Connections window's `select_connection`, `resolve_unsaved`, `take_tab_request`,
  `editor_open` / `_update` / `_save` / `_forget` / `_choose_ca`, `create_connection`, `import_files`,
  `answer_question`, `export_check`, `export_connection`, `delete_connection`, `set_auto_reconnect`,
  `log_subscribe`, `log_copy`, `log_save`, the native VPNs' `ras_ca_summary`, `ras_trust_ca`, `ras_allow_l2tp_nat`,
  `make_l2tp_copy`, and the `folder_*`, `item_*`, `credential_*`, `control_*`, `catalog_*`, `admin_key_*`,
  `publish_*` and `publication_*` families; System Status's `setup_check`, `setup_install_homebrew`,
  `setup_install_tools`, `setup_install_root`, `setup_uninstall` (the user-data flag),
  `setup_open_system_uninstall`, `quit_after_uninstall`; the Update window's `update_install`, `update_open_page`,
  `update_dismiss_notice`, `close_window` (System Status / Update only); the prompt windows' `prompt_ready` /
  `answer_prompt`, `credentials_ready` / `answer_credentials`, `pairing_ready` / `pairing_answer`; the vault's
  `vault_*` and the backup's `backup_*` / `restore_*`. Each validates its input (UUID-shaped keys that
  must name a listed connection, bounded indexes and sizes, allow-listed window names, kinds, options, filters
  and answers; typed editor fields with the config text and CA PEM at most 1 MB, other fields 64 KB, unknown
  fields refused). Help and the release page only ever open a plain `https://github.com/…` URL.
- MFA prompts: one window per open prompt (`prompt-<id>`), floating, ordered front without becoming key and
  without activating the app, so typing meant for another app never reaches it; it becomes key only when
  clicked (or through its "authentication needed" notification). No default button; nothing but Cancel is
  accepted in the first second after the window became visible (the UI disables the controls; the backend refuses
  early answers too, counting from the later of ordering the window on screen and the page's `prompt_ready`).
  `answer_prompt` takes the prompt ID (only the calling window's own prompt), the action (`code` / `openUrl` /
  `cancel`) and the code (at most 256 bytes, no control characters). "Open in Browser" opens the broker's own
  copy of the URL, validated again (`https://`, strict ASCII, ASCII host), never a URL from the web view. The
  window closes when the prompt ends (answered, replaced, disconnected, or after 2 minutes for a code, at most
  5 for a web sign-in); its close button cancels.
- Release notes are shown as text with inline emphasis only (`notes.ts` splits them into text segments; no
  `{@html}`), so markup in a release cannot inject anything; link texts are shown, their URLs are not opened.
- Secrets: the stored passwords, PSKs and the private key password never reach the web view. An editor gets
  `null` for each secret field and a `hasStoredSecret` flag; the field shows "Saved — type to replace". A value
  is only sent to the backend when the user types a new one (or `""` after "Remove saved password"); saving with
  an untouched field keeps the stored value (in the vault). Only the non-secret user name is shown.
- Files: no command takes or returns a path. Import, the SSTP CA file, export and the log's Save… use a panel
  shown by the Rust side (macOS: an `NSOpenPanel` / `NSSavePanel` sheet, `platform-mac::dialogs`; Windows:
  `IFileOpenDialog` / `IFileSaveDialog`), and a drop on the
  Connections window arrives as the window's drag-drop event (system paths, not from the web view); the import
  reads only regular UTF-8 files of at most 1 MB. Exports and saved logs are written 0600 without following a
  symlink. No dialog / fs plugin and no extra permission.
- Preferences: on macOS the same `UserDefaults` keys as 0.x in the `local.macvpn` domain (CFPreferences), so the
  settings carry over from 0.x; on Windows `%LOCALAPPDATA%\WinVPN\preferences.json` (private). The sandbox keeps
  them in memory. On macOS the update check only runs from a bundle whose Info.plist names the update source; WinVPN
  has the source built in.

## Notifications

Only from a real app bundle on macOS (`UNUserNotificationCenter` needs a bundle identifier, through
`objc2-user-notifications`; permission for alerts with sound at launch, banners with sound in the foreground too)
and from the installed MSI on Windows (WinRT toasts need the AppUserModelID `local.winvpn` of its Start-menu
shortcut). The sandbox posts none.

- **Connection notifications** (2.0, `app-core::connection_notices`): connected, reconnected, dropped, failed, not
  reconnected, could not reconnect, each with a fixed reason sentence that names only the connection (no server,
  user name, address or log line on the lock screen). Settings → **Connection Notifications** turns them off.
- **Always** (not behind the switch): the MFA and credential prompts' "authentication needed" notifications and the
  team catalog notices.

A click on an authentication notification brings its prompt forward; any other click opens the Connections window
on the connection, on its Log tab for a managed one.

## Quitting

Every quit goes through one quit guard (`app-core::quit`): first "Unsaved Changes" (in the Connections window),
then "There are active VPN connections" (in the menu; for an update in the Update window).

- The menu's Quit and Cmd+Q (the app's own menu item) ask and then call `app.exit`.
- Tauri (tao) does not implement `applicationShouldTerminate:`, so AppKit would terminate the app at once on
  logout, restart, shutdown or a quit Apple Event, and Tauri would only report `RunEvent::Exit` afterwards
  (`RunEvent::ExitRequested` comes only from closing the last window, `code: None`, which the app ignores, or
  from `app.exit`). The app adds the method to tao's delegate class at launch (`platform-mac::app_hooks`): with
  nothing to ask it answers "now"; otherwise "later", shows the question, and replies once it is answered (yes:
  AppKit terminates the app; no: the logout is cancelled). macOS cancels a logout whose question stays unanswered
  for too long. `app.exit` stops the event loop without `terminate:`, so the app's own
  quit is not asked twice.
- "Download and Install" asks the same questions on its worker thread, just before launching the helper; once
  the helper runs, the app quits at once without asking again. Its active-connections question is shown only in
  the Update window, which opens again if it was closed meanwhile; a question no window can show is cancelled at
  once, and closing the Update window cancels the update's question (either step; the Connections window's
  "Unsaved Changes" goes with it), so the worker never waits forever. A failure before the questions (download,
  checksum, signature, mount, the app's check) never quits the app: a system quit pending meanwhile is decided by
  its own question. If a menu or system quit joined the update's questions and the answer was quit, the app quits
  even when the helper then fails to launch.
- While a quit's "Unsaved Changes" is shown, a selection (a notification click, an Option-click debug connect)
  never replaces it: it follows once the question is answered, if the app keeps running.
- The uninstaller's final "Quit MacVPN" asks only about unsaved changes (the root layer is gone).
- On Windows, platform-win's lifecycle window answers a logoff or shutdown (`WM_QUERYENDSESSION`) with the same
  questions (Windows is held with "Closing WinVPN…" meanwhile); the popover's Quit asks as on macOS.

## Threads

The main thread only runs the event loop. The platform calls are synchronous, so connect / disconnect run on the
blocking pool, the status poller (3 s with an active connection, 30 s otherwise, re-checked every second; an
open popover or a wake – `NSWorkspace` `didWake` on macOS, `PBT_APMRESUMEAUTOMATIC` on Windows – refreshes at once)
and the launch steps on their own threads. Auto-reconnect has its own thread (`macvpn-reconnect`), fed by the sleep,
wake and network-change events. One publisher thread
coalesces the manager's change notifications and emits the latest view model (`view-model`) and tray icon. The
Connections window's Log tab is polled every 0.5 s on its own thread (`log-lines` events, numbered by
subscription); a native debug connect's `log stream` has a reader thread and stops after 60 s or once the
connection settles. `brew install` (30 min limit) and an update's install run on their own threads, so they go on when
their window closes; the MFA prompt broker blocks the connecting thread until the prompt window answers.

## Tray icons

`src-tauri/icons/tray/*.png` are template images rendered from SF Symbols (the same symbols as 0.x); on Windows
the same images are tinted at runtime (white on a dark taskbar, black on a light one). To regenerate
them (needs the Xcode command line tools for `swift`; not part of the build):
`swift scripts/make-tray-icons.swift app/src-tauri/icons/tray`.
