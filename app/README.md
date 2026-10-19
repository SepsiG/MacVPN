# MacVPN app (Tauri 2)

- `src-tauri/`: the Rust shell (`macvpn-app`): tray icon, menu popover, windows, the IPC commands, and the
  adapters from `macvpn-app-core`'s traits to `macvpn-platform-mac`.
- `ui/`: the web UI (Svelte 5 + TypeScript + Vite). Texts come from `crates/core/l10n/strings.json` (scope `app`
  only is bundled); the language is the core's rule, sent by the backend in the view model.
- The logic (connection manager, view model, polling, launch order, quit decision, update schedule) is in
  `crates/app-core`, tested without a UI.

The rest of the repository: `crates/core` (platform-independent logic and the EN/HU text table), `crates/mvpn` (the
root binary), `crates/platform-mac` (macOS services), `scripts/` (build, test and signing scripts). `legacy/swift` is
the 0.x Swift app, kept only as the reference of a few compatibility tests; it is not built and will be removed.

## Build

Toolchain: `rust-toolchain.toml` pins the exact Rust version (1.99.1, with clippy, rustfmt and both macOS targets),
which `rustup` uses inside the repository (`rustup toolchain install` installs it). CI and the release workflow use
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
bundle's Info.plist), the universal `mvpn` and `crates/mvpn/VERSION` into `Contents/Resources/root/` (where the
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
  (`crates/mvpn` uses `crates/core` without the `vault` feature);
- the bundle carries `THIRD-PARTY-NOTICES.txt` (see `docs/RELEASING.md`), and the usual Info.plist, signature and
  symlink checks pass.

## Tests

- `cargo test --workspace`: unit, compatibility and l10n coverage tests (also of this app's logic in `crates/app-core`)
- `scripts/test-root.sh`: black-box tests of the `mvpn` root binary (dry run, no root needed; `MVPN_BIN=` tests a
  built binary)
- `npm test` and `npm run build` in `app/ui`: the UI tests, then `svelte-check` and the build
- `scripts/smoke-manage.sh`: the smoke test of the real windows (below), with `SMOKE_LANG=en` and `SMOKE_LANG=hu`
- the manual checklist: `docs/manual-test-checklist.md`

## Running a development build without touching real data

Debug builds honour `MACVPN_SANDBOX_HOME=<absolute dir>`: the connection store, `connection-order.json` and
`system-otp.json` live under that directory, and the Keychain is replaced by an in-memory store (no migration, no
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

### Smoke test of the windows

`scripts/smoke-manage.sh` (after `npm run build` and `cargo build -p macvpn-app --features custom-protocol`)
seeds a throwaway sandbox and starts the app with `MACVPN_SMOKE_DIR=scripts/smoke` (debug builds and the sandbox
only). The scripts there run one after the other in the real windows, each saving its result into a seeded
connection's name, and the shell checks the store and the log (`SMOKE_LOG=<file>` keeps the log).
`SMOKE_LANG=en` / `SMOKE_LANG=hu` forces the language the way macOS selects it (`-AppleLanguages '(hu)'`, the
argument domain of the `AppleLanguages` preference) and checks that the core picked it and the windows show it; run
it in both before a release:

- `manage.js` (Connections): the risky panel and its acknowledgement, the unsaved-changes question, the Log tab,
  the SSTP and native forms (the staged profile is 0600 and has no password; the editor view never holds the
  stored password, an untouched field keeps it), New and Delete;
- `setup.js` (System Status, over a mock report: a missing tool, root layer 6 installed, 7 bundled): the rows,
  the reinstall notice, the simulated brew output, the root install error, the uninstall confirmation with the
  user-data checkbox and its failure;
- `update.js` (Update, over a mock release): the notes rendered as text (markup and HTML stay text), then
  "Download and Install" with an unsaved change: the stages run up to the quit questions, "Unsaved Changes" is
  cancelled, the update stops and its files are cleaned up;
- `prompt.js` (MFA): a code prompt (the server's text labelled, a secure field, answered once it takes input) and
  a web sign-in ("Open in Browser" with the ASCII host shown; the sandbox logs instead of opening).
- `quit.js` (Connections): the quit flows' edge cases: a selection (as a notification click) while the menu
  quit's "Unsaved Changes" is shown waits for its answer and the guard is freed by Cancel; "Download and Install"
  with the Update window closed during the download still asks (in Connections), and closing the reopened Update
  window while that question is shown cancels the update and dismisses the question;
- `system.js` (Connections, last): an unsaved change; the shell then sends the app a quit Apple Event
  (`NSRunningApplication.terminate`, as logout does) and checks that `applicationShouldTerminate` asked about the
  change first (the script answers Discard) and that the app then quit.

## Localization check

Every text has an English key and a Hungarian text in `crates/core/l10n/strings.json`:

- `npm test` (`l10n.test.ts`): every `tr('…')` key of the UI is an `app` entry with a Hungarian text, `tr` only gets
  literal keys, and no text is hard-coded in the Svelte markup (text nodes, `title` / `placeholder` /
  `aria-label` / `label` … attributes) or in TypeScript objects.
- `cargo test` (`crates/app-core/tests/l10n_coverage.rs`): every key the Rust side translates (core, `mvpn`,
  platform layer, app logic, Tauri shell), literal or passed through a listed variable, has a Hungarian text;
  `crates/core/tests/l10n.rs` checks the table itself (both languages, the same format specifiers).

## Security

- CSP: `default-src 'self'`, scripts / styles / images / fonts only from the app, IPC only, no `eval`, no
  objects, frames or forms; `freezePrototype`; the asset protocol is off; no remote URL is ever loaded.
- Capabilities: only the app's own commands (generated as `allow-<command>` by `build.rs`) and listening to
  events. `main.json` (the menu, Connections, System Status and Update windows) grants every command but
  `answer_prompt` and `prompt_ready`; `prompt.json` (the `prompt-*` windows) grants only `get_view_model`,
  `prompt_ready` and `answer_prompt`. No core
  window / webview / path API, no plugin (a test keeps the files to exactly the generated commands).
- Commands: `get_view_model`, `connect` (with the Option-click debug flag), `disconnect`, `pin`, `unpin`,
  `move_pinned`, `open_window`, `set_menu_height`, `quit`, `check_for_updates`, `set_update_option`,
  `set_launch_at_login`, `open_login_items_settings`, `open_user_guide`; the Connections window's
  `select_connection`, `resolve_unsaved`, `take_tab_request`, `editor_open` / `_update` / `_save` / `_forget` /
  `_choose_ca`, `create_connection`, `import_files`, `answer_question`, `export_check`, `export_connection`,
  `delete_connection`, `log_subscribe`, `log_copy`, `log_save`; System Status's `setup_check`,
  `setup_install_homebrew`, `setup_install_tools`, `setup_install_root`, `setup_uninstall` (the user-data flag),
  `quit_after_uninstall`; the Update window's `update_install`, `update_open_page`, `update_dismiss_notice`,
  `close_window` (System Status / Update only); the prompt windows' `prompt_ready` and `answer_prompt`. Each validates its input (UUID-shaped keys that
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
- Files: no command takes or returns a path. Import, the SSTP CA file, export and the log's Save… use an
  `NSOpenPanel` / `NSSavePanel` sheet shown by the Rust side (`platform-mac::dialogs`), and a drop on the
  Connections window arrives as the window's drag-drop event (system paths, not from the web view); the import
  reads only regular UTF-8 files of at most 1 MB. Exports and saved logs are written 0600 without following a
  symlink. No dialog / fs plugin and no extra permission.
- Preferences: the same `UserDefaults` keys as 0.x in the `local.macvpn` domain (CFPreferences), so the settings
  carry over from 0.x; the sandbox keeps them in memory. The update check only runs from a bundle whose Info.plist names the update source.

## Notifications

Only from a real app bundle (`UNUserNotificationCenter` needs a bundle identifier), through
`objc2-user-notifications`: permission for alerts with sound at launch, banners with sound in the foreground too,
"…: connection failed" / "…: the connection dropped" / "…: authentication needed" with generic bodies (a
failure's reason, server or user name never appears on the lock screen; the details stay in the app). A click
on an authentication notification brings its prompt forward; any other click opens the Connections window on
the connection, on its Log tab for a managed one.

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

## Threads

The main thread only runs the event loop. The platform calls are synchronous, so connect / disconnect run on the
blocking pool, the status poller (3 s with an active connection, 30 s otherwise, re-checked every second; an
open popover or a woken Mac – `NSWorkspace` `didWake` – refreshes at once) and the launch steps on their own threads. One publisher thread
coalesces the manager's change notifications and emits the latest view model (`view-model`) and tray icon. The
Connections window's Log tab is polled every 0.5 s on its own thread (`log-lines` events, numbered by
subscription); a native debug connect's `log stream` has a reader thread and stops after 60 s or once the
connection settles. `brew install` (30 min limit) and an update's install run on their own threads, so they go on when
their window closes; the MFA prompt broker blocks the connecting thread until the prompt window answers.

## Tray icons

`src-tauri/icons/tray/*.png` are template images rendered from SF Symbols (the same symbols as 0.x). To regenerate
them (needs the Xcode command line tools for `swift`; not part of the build):
`swift scripts/make-tray-icons.swift app/src-tauri/icons/tray`.
