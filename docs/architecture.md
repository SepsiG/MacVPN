# MacVPN architecture

This is the map of the workspace for a developer who is new to it: which crate does what, which rules hold the
layers apart, and where a new operating system plugs in. It describes the code as of 1.5.0, the release that
restructured the workspace for a Windows version (WinVPN) without changing MacVPN. The design behind it is
[the cross-platform spec](superpowers/specs/2026-10-20-cross-platform-winvpn-design.md) (section 3); the step-by-step
history is [the phase 1 plan](superpowers/plans/2026-10-20-platform-neutral-refactor.md).

In one sentence: **one app, one UI and one body of logic; a thin platform layer per operating system, chosen once
at compile time.** In 1.5.0 the only real platform is macOS. Windows has a stub platform that compiles and answers
"not supported" everywhere, so the whole workspace already builds for Windows.

## The crates

```
crates/
  core/          macvpn-core: the shared logic (models, validators, import/export, the vault behind the
                 `vault` feature, team catalogs, MFA, update checks, the EN/HU text table). Its only
                 OS-specific code is `fsx`, the safe file operations.
  platform-api/  macvpn-platform-api: the traits every platform implements, the shared types,
                 `PlatformError` and the product identity (`Product`, `MACVPN`, `WINVPN`).
  platform-mac/  macvpn-platform-mac: the macOS platform (`MacPlatform`): Keychain, native VPN, notifications,
                 file panels, login item, installers, updater, the control socket. macOS-only as a whole.
  platform-win/  macvpn-platform-win: the Windows platform of phase 1 (`WinPlatform`), a stub.
  helper/        macvpn-helper: the privileged helper, binary `mvpn` (the macOS root layer). Shared protocol
                 logic plus one backend per OS (`macos`; `windows` refuses in phase 1).
  app-core/      macvpn-app-core: the app logic without a UI (connection manager, view model, control server,
                 vault flows, catalogs, quit guard, updates).
app/src-tauri/   macvpn-app: the Tauri 2 app. Its `platform` module picks the platform crate; everything else
                 uses platform-api only.
app/ui/          the Svelte + TypeScript UI, one for every OS.
examples/macvpn-control-client/   a control-API client template for other apps (Unix socket; Windows later).
```

The dependency graph (an arrow means "depends on"):

```
                      macvpn-core
                     ▲   ▲       ▲
        (vault)      │   │       │ (no vault)
   macvpn-platform-api   │     macvpn-helper  (binary mvpn)
     ▲      ▲       ▲    │
     │      │       │    │
 platform-mac  platform-win  macvpn-app-core
     ▲  (macOS)     ▲ (other OS)   ▲
     └──────────── macvpn-app ─────┘   (also core and platform-api)
```

- `platform-api` depends on core only (with `vault`, for the traits it re-exports). It never depends on Tauri.
- `app-core` depends on core and platform-api, never on a platform crate.
- `platform-mac` and `platform-win` depend on core and platform-api, never on app-core or on each other.
- The app depends on `macvpn-platform-mac` only for `cfg(target_os = "macos")` and on `macvpn-platform-win` for
  every other target (`[target.'cfg(not(target_os = "macos"))'.dependencies]` in `app/src-tauri/Cargo.toml`).
- The helper uses core **without** the `vault` feature. The release gate in `scripts/build-dmg.sh` checks that
  `mvpn` links no SQLite and no catalog code.

### core

Platform-independent logic. macOS paths and product names are not in core: the functions take them as
parameters (`ConnectionStore::default_base_dir(data_dir)`, `store::remove_user_data(dir, expected_name)`,
`UpdateChecker::parse_release(data, repo, asset)`, `UserGuide::url(repo, fallback_repo, stem, preferred)`,
`mfa::AuthUIState::read(path, expected_owner)`).

- **`TargetOs`** (`crates/core/src/target_os.rs`): `MacOs`, `Windows`, `Linux`. `TargetOs::host()` reads
  `std::env::consts::OS`, a compile-time constant, so it needs no `cfg`.
- **The OpenVPN platform tier** (`crates/core/src/validators/openvpn.rs`): `platform_reasons(os)` lists the
  directives an OS refuses or that need an acknowledgement there. The validator uses the host OS (a security rule
  never depends on a launch-time setting). Only the macOS table ships in phase 1; the Windows and Linux tables are
  drafts for the phase 2 security review. See [OpenVPN directives](openvpn-directives.md).
- **`fsx`** (`crates/core/src/fsx/`): the safe file operations, the only OS-specific module of core. `mod.rs`
  holds the portable API (`Access::{Private, Shared}`, `Follow::{No, Yes}`, `create_new`, `open_regular`,
  `atomic_write`, `owner`, `file_id`, `is_unavailable`, …); `unix.rs` and `windows.rs` hold the OS calls. On Unix
  every function does exactly what its call sites did before 1.5 (`O_NOFOLLOW`, `O_NONBLOCK`, modes 0600 / 0700,
  the same order of checks and error kinds). On Windows, opening without following reparse points, the atomic
  replace and the "unavailable" errors are real; anything that needs an owner check or an owner-only ACL
  (`Access::Private`, `owner`, `has_access`) **fails closed** with `io::ErrorKind::Unsupported` until phase 2, and
  `file_id` is `None`. core calls no libc function (only constants) and has no `unsafe`.

### platform-api

The interface between the app and an operating system (`crates/platform-api/src/lib.rs`).

- **`Platform`**, the one handle: `product()`, `install_core_hooks()`, then one accessor per facility:
  `system()` (`SystemInfo`), `shell()`, `setup()` (`SystemSetup`), `updater()`, `windows()` (`WindowChrome`),
  `file_panels()`, `notifier()`, `clipboard()` (`SecretClipboard`), `lifecycle()`, `download_mark()`,
  `system_vpn_watch()`, `control_transport()`, `helper_client()`, `native_controller()`, `native_profiles()`,
  `auth_state()`, `log_streams()`, `release_source()`, `https_catalog_fetcher()`, `key_store()`, `entropy()`,
  `legacy_keychain()`, `legacy_secrets()`, `migrate_legacy_service()`, `preferences()`, `login_items()`.
- **`PlatformError`**: `Unsupported { what }` (the user sees the localized "Not available on this system yet";
  `what` is for the code only) or `Failed(message)` with an already localized message.
- **Moved here from app-core** and re-exported at their old app-core paths, so app-core's callers did not change:
  `HelperClient`, `NativeController`, `SystemVpn`, `NativeProfiles`, `NativeProfile`, `AuthStateReader`,
  `PreferenceStore`, `ReleaseSource`, `UpdateSource`, `LogStreamSpawner` and the control transport types.
- **Re-exported from core**, where they stay because core's vault and catalog code call them: `TargetOs`,
  `KeyStore`, `Entropy`, `LegacyKeychain`, `CatalogFetcher`.
- **Shared implementations:** `MemoryPreferences`, the one in-memory `PreferenceStore` of every crate (tests, the
  development sandbox, runs without a bundle, platforms that cannot store preferences yet); app-core re-exports it
  as `macvpn_app_core::app::MemoryPreferences`.
- A few signatures differ from the first draft of the plan, and the code is what counts:
  `SystemInfo::user_owner()` returns `Result<FileOwner, PlatformError>` (the stub has no owner and fails closed;
  the caller then reads no helper state file); `SystemSetup::install_tools(report, output)` streams the installer's
  output into a sink (`&mut dyn FnMut(&str)`) for the System Status window; `SystemInfo::user_name()`,
  `Updater::cache_directory()`, `HelperClient::log_path()` (default `None`), `NativeProfiles::sweep_leftovers()` /
  `services_seen()` (default no-ops) and `ControlTransport::prepare_dir()` (required, no default: each platform
  checks the directory's owner its own way) were added when the app moved onto the traits.
- Traits the app implements over its own state stay in app-core: `ConnectionRepository`, `SecretReader`,
  `SecretWriter`, `ControlHost`, `RegistryStore`, `PreferencePort`, `UninstallSystem`, `TrackedPrompt`, the stores.
- `debug.rs` (debug builds only): `SmokeHooks` for the smoke driver.

### platform-mac

The macOS platform. `#![cfg(target_os = "macos")]` at the top of `crates/platform-mac/src/lib.rs`, so another
target sees an empty crate, and every Apple binding (`objc2*`, `core-foundation*`, `security-framework-sys`,
`block2`, `oslog`, `plist`) is a `[target.'cfg(target_os = "macos")'.dependencies]` entry. `api/` holds
`MacPlatform::new(sandbox)` and its adapters; every accessor wraps the module that did the job before 1.5, so the
behaviour is 1.4's. The sandbox (`MACVPN_SANDBOX_HOME`, debug builds) gets memory stores and never reaches the real
Keychain or preferences. The control socket's `Transport` lives in `api/control.rs`.

The storage identifiers are literals in this crate (or the helper) and never derive from `Product`: the Keychain
services `local.macvpn.vault` and `local.macvpn.secrets`, the preferences domain `local.macvpn`, the LaunchAgent
label `local.macvpn.launcher`, `macvpn.sock` / `macvpn.lock`, the root paths (`/usr/local/libexec/macvpn`,
`/var/run/macvpn`, `/var/run/macvpn-ui`, `/var/log/macvpn`, `/etc/sudoers.d/macvpn`) and the UTIs. Renaming them
would orphan users' data.

### platform-win

`WinPlatform`, the Windows platform of phase 1 (`crates/platform-win/src/lib.rs`): a stub with no `cfg`, no
`unsafe` and no `windows-sys`, so it compiles and is tested on macOS too (`crates/platform-win/tests/stub.rs`).
`product()` is `WINVPN`; `install_core_hooks()` sets only the text platform; every fallible call returns
`Unsupported`; infallible calls are inert (no mark, no notification, panels answer "cancelled"). It fails closed:
the key store loads nothing and stores nothing (no auto-unlock), entropy fails (no vault can be created by
mistake), the control transport does not bind, catalog fetches fail. Preferences are `MemoryPreferences`.

### helper

`crates/helper` (package `macvpn-helper`, binary still `mvpn`, installed as `/usr/local/libexec/macvpn/mvpn`; root
layer version in `crates/helper/VERSION`, 8 since 1.2.0).

- `src/shared/`: the logic every OS shares, with no `cfg`, no `unsafe` and no process or file I/O: the command
  line (`cli`), the framed stdin (`framing`), masking, the `respond` answer, the status JSON, the validation
  dispatch and the management-bridge state machine (`bridge`, over any `Read + Write` stream).
- `src/macos/`: everything the macOS root layer does (sudo, the tools, run directories, DNS hooks, the
  `MVPN_*` test-mode hooks for non-root runs only). `#![cfg(target_os = "macos")]`.
- `src/windows/`: phase 1 prints "Not available on this system yet" and exits 1.
- `src/main.rs` picks the backend with `cfg`; Linux uses the Windows `main` until phase 4.

### app-core

The app logic without a UI, tested without one. macOS concepts got neutral names in 1.5: `SystemVpn` (was
`SystemService`), `HelperClient` / `Dependencies::helper` (was `RootClient` / `root`), `NativeProfiles` with
`build()` (was `ProfileInstaller`; macOS builds the same `.mobileconfig` bytes). Every serialized format kept its
field names (`#[serde(rename = …)]` where a Rust name changed); the 1.4.0 compatibility fixtures in
`crates/app-core/tests/fixtures/compat-1.4.0` prove it (`cargo test -p macvpn-app-core --test compat_1_4`).

### The app's platform module

`app/src-tauri/src/platform/` is the app's one door to the OS and its only `cfg(target_os)`:

- `mod.rs` picks `macos.rs` (creates `MacPlatform`) or `windows.rs` (the `WinPlatform` stub, for every target
  that is not macOS) and offers `init(sandbox)` / `get()` (the `&'static dyn Platform`), and the Tauri glue that
  platform-api cannot hold because it does not depend on Tauri: `native_window` (`ns_window()` / `hwnd()`),
  `configure_app` (the activation policy), `set_window_presence` (the Dock icon), `on_run_event` (`Reopen`,
  `Opened`) and `supported()`. On Windows `supported()` returns `WinVPN is not available yet` and `main` exits 1
  before any window opens.
- `environment.rs`: `Environment` (home, bundle, sandbox, Info.plist), built from `SystemInfo` and `Product`.
- `smoke.rs`: the smoke driver (macOS debug builds only), reached elsewhere through the `platform::smoke_*`
  facades, which do nothing on other targets.

Window code passes `platform::native_window(&w)` (a `NativeWindow`, never dereferenced outside a platform crate)
to `WindowChrome` and `FilePanels`.

### The UI

One Svelte UI. It learns the OS and the product from the read-only command `get_platform`
(`{ os, productName }`), which `main.ts` awaits before mounting (an error or an unknown OS keeps the macOS
default). `tr()` passes the platform to `translate()` in `app/ui/src/lib/l10n-core.ts`. Keyboard shortcuts use
`isPrimaryShortcut` from `app/ui/src/lib/keys.ts`: Cmd on macOS, Ctrl on Windows and Linux. The view model does not
carry the platform, so its JSON is the same as in 1.4.

## The rules and the tests that enforce them

| Rule | Enforced by |
|---|---|
| An OS `cfg` (`cfg(target_os …)`, `cfg(unix)`, `cfg(windows)`, their `not` / `any` / `all` forms, `cfg_attr` and `cfg!` with one of them, `target_os =`) appears in production code only in `crates/core/src/fsx/`, `crates/platform-mac/`, `crates/platform-win/`, `crates/helper/src/{macos,windows}/`, `crates/helper/src/main.rs` and `app/src-tauri/src/platform/`. Tests, `examples/`, build scripts and Cargo target tables are outside the rule; `debug_assertions`, `test` and `feature` are not OS `cfg`s. | `crates/app-core/tests/cfg_rule.rs` (`os_cfgs_only_in_the_platform_places`; it scans `crates/*/src` and `app/src-tauri/src`, ignoring comments, strings and `#[cfg(test)]` items; `target_env` and `target_family` count as OS words, and a `cfg($metavariable)`, `#[path = …]` and `include!` count as violations, because the scan cannot see their code) |
| `unsafe`, and an `allow`/`expect`/`warn` of the `unsafe_code` lint, appear only in `crates/platform-mac`, `crates/platform-win` and `crates/helper`. The workspace lint `unsafe_code = "deny"` holds everywhere else; platform-api and platform-win also `#![forbid(unsafe_code)]`. | `cfg_rule.rs` (`unsafe_only_in_the_platform_crates_and_the_helper`) |
| MacVPN's data formats, view model and IPC payloads stay as in 1.4.0. | `crates/app-core/tests/compat_1_4.rs` (the fixtures normalize the version) |
| Every macOS text stays byte-identical. | `node scripts/l10n-baseline.mjs --check` (against `scripts/bundle-baseline/1.4.0/l10n-macos.json`), and the same comparison in `crates/core/tests/l10n.rs` and `app/ui/src/lib/l10n.test.ts` |
| The built bundle looks the same from outside (Info.plist, files, linked libraries, entitlements, Tauri config). | `scripts/bundle-baseline.sh dist/MacVPN.app` (compare with `scripts/bundle-baseline/1.4.0/`) |
| No OpenSSL in a macOS binary. | `cargo tree --locked --target aarch64-apple-darwin -i openssl-sys` prints nothing; the release gate in `scripts/build-dmg.sh` |

## Product identity and the per-OS Tauri config

`Product` (`crates/platform-api/src/product.rs`) is the identity: `name` (`MacVPN` / `WinVPN`, also the data
directory's name), `os`, `app_id` (`local.macvpn` / `local.winvpn`), `repo` (`SepsiG/MacVPN` for both: one
repository, one version number) and `user_guide_stem` (`user-guide` / `winvpn-user-guide`). From these:

- `data_dir(app_data_root)`: `<root>/<name>`; the platform gives the root (macOS:
  `~/Library/Application Support`, so `~/Library/Application Support/MacVPN` as before).
- `update_asset(version, arch)`: `MacVPN-<version>.dmg`; `WinVPN-<version>-x64.msi` or `-arm64.msi`.
- `text_platform()`: the OS and product the texts are worded for.

The update signature (`macvpn-update-v1\n<version>\n<sha256>\n`) names neither the product nor the asset. It
binds the file's bytes (through the hash), not its name: a signed file renamed to another asset of the same version
would still verify, and both products share one repo, one version line and the same keys. That is harmless in
1.5.0 (no WinVPN asset is signed; on macOS a non-DMG file fails at the mount), but it must be closed before the first
signed WinVPN asset (see "Adding a platform", step 11).

The Tauri config is split: `app/src-tauri/tauri.conf.json` holds everything shared and the macOS identity as the
default (product name, identifier, version, windows, CSP); `tauri.macos.conf.json` adds the macOS bundle settings
(`macOSPrivateApi`, the `app` target, the icons with `icon.icns`, the minimum macOS version);
`tauri.windows.conf.json` sets `WinVPN`, `local.winvpn`, the `msi` target and the icons with `icon.ico`. Tauri
merges the OS file over the base (JSON merge patch). `app/src-tauri/tests/tauri_config.rs` checks that base +
macOS equals the 1.4.0 config.

## Texts per OS

Every text is in `crates/core/l10n/strings.json`, keyed by the English **macOS** text, so no call site changes and
the macOS output is the 1.4 text. An entry may carry two optional fields (documented in the file's `comment`):

- `variants.<os>` (`windows` or `linux`): the text on that OS, with both `en` and `hu`.
- `only`: the OSes whose code paths show the text (for example `["macos"]` for Homebrew, the root layer, sudoers,
  LaunchAgent, Device Management, Gatekeeper and the 1.1 Keychain migration). It needs no variant.

Resolution (`l10n::tr_for` in Rust, `translate` in `l10n-core.ts`): the OS's variant if there is one, else the
base text; then, on a product other than MacVPN, `MacVPN` becomes the product name, except in a text whose `only`
excludes this OS. Hungarian suffixes stay right because both names end in "VPN". The platform installs the text
platform at launch (`install_core_hooks`); the default is macOS, so tests need no setup.

The glossary for Windows variants: Keychain → Credential Manager („Hitelesítőadat-kezelő”), Finder → File Explorer
(„Fájlkezelő”), this Mac → this PC („ez a számítógép”, with the right case), System Settings → Settings
(„Gépház”), Login Items → Startup apps („Indítási alkalmazások”), menu bar → notification area („értesítési
terület”), Dock → taskbar („tálca”), Option-click → Alt-click („Alt+kattintás”).

The coverage test `macos_terms_are_classified` in `crates/app-core/tests/l10n_coverage.rs` fails for any text that
names a macOS facility (Keychain, Finder, Mac, System Settings, Dock, menu bar, …) without `only` or a `windows`
variant. Every variant keeps its base's format specifiers (`crates/core/tests/l10n.rs`).

## The control API transport

app-core's `ControlServer` runs over platform-api's transport traits, not over `UnixStream`:
`ControlTransport::bind(dir)` gives a `BoundEndpoint` (a `ControlListener`, the text of the "listening on …" log
line, the socket file to remove at stop, a guard); `ControlListener::accept(poll)` returns
`Accepted::Client { stream, peer }` or `Idle`. The listener identifies the peer at accept time (`PeerIdentity`
with `PeerUser::Uid(n)` or `PeerUser::Sid(…)`), so a named pipe needs no stream downcast later. `PeerUser::Uid(501)`
displays as `uid 501`, so every audit log line keeps its 1.4 text.

macOS implements it over the Unix socket (`crates/platform-mac/src/api/control.rs`, `control_socket.rs`). The
app-core tests run the whole server suite over both a Unix-socket transport and a TCP loopback transport
(`crates/app-core/tests/control_support/`), so the suite also runs on Windows. The example client
(`examples/macvpn-control-client`) has a Unix transport; on Windows `Client::connect` returns `Unsupported`.

## Checking Windows

The C dependencies (SQLCipher with a vendored OpenSSL, the app's Windows resource) need an MSVC toolchain, which a
Mac does not have ([the Windows check spike](superpowers/spikes/2026-10-20-windows-check-spike.md)). So there are
two levels:

- **On a Mac:** `scripts/check-windows.sh` runs `cargo check --all-targets` for `x86_64-pc-windows-msvc` and
  `aarch64-pc-windows-msvc`, debug and release, on `macvpn-core` (without `vault`), `macvpn-helper` and
  `macvpn-control-client`. It installs nothing: the targets come from `rust-toolchain.toml`.
- **In CI only:** the vault, platform-api, platform-win, app-core and the app. The `windows` and `windows-node`
  jobs in `.github/workflows/ci.yml` (on `windows-latest`) check, lint and test the workspace and run the UI tests
  on Windows.

On Windows the vault uses `bundled-sqlcipher-vendored-openssl` (a `[target.'cfg(windows)'.dependencies]` line in
`crates/core/Cargo.toml`). That puts `openssl-src` and `openssl-sys` into `Cargo.lock`, but resolver 3 never
activates them for a macOS target. `scripts/third-party-notices.mjs` still walks `cargo metadata` for the two macOS
targets and leaves out the crates that only a Windows build links, so `THIRD-PARTY-NOTICES.txt` did not change.

## Adding a platform

Phase 2 (WinVPN) follows this list; Linux (phase 4) will too.

1. **Product.** Add a `Product` constant in `crates/platform-api/src/product.rs` (name, OS, app id, repo, user
   guide stem) and its `update_asset` rule, with tests in `crates/platform-api/tests/product.rs`.
2. **Platform crate.** A new `crates/platform-<os>` that implements `Platform` (start from `platform-win`: every
   method is there). Put the OS bindings under target-specific dependency tables and the crate under a crate-level
   `#![cfg(target_os = …)]` once it calls the OS. Keep the storage identifiers literal.
3. **App selection.** In `app/src-tauri/src/platform/mod.rs`, a module for the OS with `init`, `get`,
   `native_window`, `configure_app`, `set_window_presence`, `on_run_event` and `supported`; the dependency in
   `app/src-tauri/Cargo.toml` under the OS's target table.
4. **fsx.** Implement `Access::Private`, `owner` and `has_access` for the OS (Windows: ACLs through the platform
   layer), so the tests that create private files or a vault run on that OS too.
5. **Helper.** A backend in `crates/helper/src/<os>/` over `shared`, and its `main` in `src/main.rs`.
6. **The cfg rule.** Add the new directories to `CFG_ALLOWED` (and `UNSAFE_ALLOWED` if needed) in
   `crates/app-core/tests/cfg_rule.rs`. Nowhere else.
7. **Texts.** Write the OS's `variants` for every text the coverage test flags, and new texts for the OS's own
   flows (with `only`).
8. **Tauri config.** `app/src-tauri/tauri.<os>.conf.json` with the identity and bundle settings.
9. **OpenVPN tier.** Review `platform_reasons(os)` (the Windows and Linux tables are drafts until then).
10. **Checks.** Extend `scripts/check-windows.sh` or the CI job, and the release gates of the OS's build script.
11. **Update signature (phase 2 blocker).** Before the first signed WinVPN asset: keep `macvpn-update-v1` byte for
    byte for MacVPN; WinVPN gets its own domain that includes the asset name, e.g.
    `winvpn-update-v1\n<asset>\n<version>\n<sha256>\n` (or separate keys). Tests: MacVPN rejects a WinVPN-domain
    signature; WinVPN rejects the x64 MSI's signature for the arm64 asset.
12. **Importer paths (known phase 2 issue).** `importer::read_inline_data` builds referenced-file paths as
    `/`-joined strings and compares the canonical path with the base folder as text. On Windows canonical paths are
    `\\?\C:\…`, so a referenced file (e.g. `cert user.pem`) resolves to `MissingFile` or `OutsideBaseDirectory`.
    Fix it with `Path` joins and a component-wise `starts_with` on canonical paths; the 24 importer tests marked
    `cfg_attr(windows, ignore)` for it must then run on Windows.
