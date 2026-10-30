# MacVPN architecture

This is the map of the workspace for a developer who is new to it: which crate does what, which rules hold the
layers apart, and where a new operating system plugs in. It describes the code of the joint 2.0.0 release of MacVPN
and WinVPN: 1.5.0 restructured the workspace for a Windows version without changing MacVPN, phase 2a made Windows a
real platform, phase 2b added the WinVPN Service with OpenVPN and WireGuard, and phase 2c the native Windows VPNs
(RAS) and the system VPNs. The design behind it is
[the cross-platform spec](superpowers/specs/2026-10-20-cross-platform-winvpn-design.md) (section 3); the step-by-step
history is [the phase 1 plan](superpowers/plans/2026-10-20-platform-neutral-refactor.md),
[the phase 2a plan](superpowers/plans/2026-10-21-winvpn-2a-foundations.md),
[the phase 2b plan](superpowers/plans/2026-10-22-winvpn-2b-service-openvpn-wireguard.md) and
[the phase 2c plan](superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md) with its
[parity audit](superpowers/specs/2026-10-25-winvpn-parity-audit.md). The features added for 2.0
(appearance, connection notices, missing engines, auto-reconnect, the macOS DNS manager, log caps, engine updates)
are mapped in [The 2.0 features](#the-20-features). The third product, **LinVPN** (Linux), is being built after
[the LinVPN spec](superpowers/specs/2026-10-29-linvpn-design.md): its phase L-a (the platform layer, the tray and
panel, the `.deb` and the signed self-update, [the L0/L-a plan](superpowers/plans/2026-10-29-linvpn-l0-la.md)) is
described in [LinVPN on Linux](#linvpn-on-linux); it connects no VPN yet (the NetworkManager engines are phase L-b).

In one sentence: **one app, one UI and one body of logic; a thin platform layer per operating system, chosen once
at compile time.** Both products are complete. WinVPN connects OpenVPN and WireGuard through the **WinVPN Service**
(a LocalSystem service behind `\\.\pipe\WinVPN`, the counterpart of MacVPN's root layer), and L2TP/IPsec, IKEv2 and
SSTP through the **Windows RAS client**, dialled in the user's own process from a WinVPN-private phonebook (no
service, no administrator); the user's own Windows VPNs are its system VPNs. The one kind Windows cannot run is Cisco
IPsec (IKEv1 XAUTH): such connections are kept, greyed with their reason, with **Make an L2TP/IPsec Copy**.

## The crates

```
crates/
  core/          macvpn-core: the shared logic (models, validators, import/export, the vault behind the
                 `vault` feature, team catalogs, MFA, update checks, the EN/HU text table). Its only
                 OS-specific code is `fsx`, the safe file operations.
  platform-api/  macvpn-platform-api: the traits every platform implements, the shared types,
                 `PlatformError` and the product identity (`Product`, `MACVPN`, `WINVPN`, `LINVPN`).
  platform-mac/  macvpn-platform-mac: the macOS platform (`MacPlatform`): Keychain, native VPN, notifications,
                 file panels, login item, installers, updater, the control socket. macOS-only as a whole.
  platform-win/  macvpn-platform-win: the Windows platform (`WinPlatform`, WinVPN): Credential Manager, known
                 folders, DWM, COM file dialogs, WinRT toasts, the clipboard, the Run key, the lifecycle
                 window, the control pipe, one instance per user; the WinVPN Service's client, the native
                 VPNs (RAS) and the system VPNs, the OpenVPN Community installer, the updater. Its pure
                 logic compiles on every OS.
  winsys/        macvpn-winsys: the Win32 calls core's `fsx` and platform-win share (SIDs, security
                 descriptors, file identity, randomness, named pipes, Authenticode, the service manager, the
                 certificate store, IP Helper, the RAS API). Windows only; empty elsewhere.
  platform-linux/ macvpn-platform-linux: the Linux platform (`LinPlatform`, LinVPN): `pure/` (paths, texts, the
                 autostart file, the update rules, placement; every OS) and `lin/` (Linux only): the D-Bus
                 services through `zbus` (Secret Service, notifications, the desktop portal, logind, the
                 single-instance name, the tray over `ksni`), GTK (clipboard, window sizes, SIGTERM), the
                 control socket, autostart, the `.deb` updater; the VPN parts answer "not yet" until L-b.
  unixsys/       macvpn-unixsys: the Unix calls macOS and Linux share: the control API's Unix socket (moved from
                 platform-mac) with its transport, and the kernel's randomness. Unix only; empty on Windows.
  helper/        macvpn-helper: the privileged helper, binary `mvpn`: the macOS root layer, and on Windows the
                 WinVPN Service (installed as `WinVPNService.exe`). Shared protocol logic plus one backend per OS.
                 On Linux no `mvpn`: only LinVPN's root update step, binary `linvpn-install-update`.
  app-core/      macvpn-app-core: the app logic without a UI (connection manager, view model, control server,
                 vault flows, catalogs, quit guard, updates).
app/src-tauri/   macvpn-app: the Tauri 2 app. Its `platform` module picks the platform crate; everything else
                 uses platform-api only.
app/ui/          the Svelte + TypeScript UI, one for every OS.
examples/macvpn-control-client/   a control-API client template for other apps (a Unix socket on macOS and
                 Linux, the named pipe on Windows through macvpn-winsys).
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
     ▲  (macOS)     ▲ (Windows)    ▲
     └──────────── macvpn-app ─────┘   (also core and platform-api)

 Windows only:   macvpn-core ──▶ macvpn-winsys ◀── platform-win, macvpn-helper
                 macvpn-control-client ──▶ macvpn-winsys ◀── macvpn-app-core (tests only)

 Linux:          platform-linux ──▶ core (vault), platform-api; macvpn-app ──▶ platform-linux
 Unix only:      platform-mac, platform-linux, macvpn-helper (Linux) ──▶ macvpn-unixsys ──▶ platform-api
```

- `platform-api` depends on core only (with `vault`, for the traits it re-exports). It never depends on Tauri.
- `app-core` depends on core and platform-api, never on a platform crate. On Windows its tests use
  `macvpn-winsys` (a dev-dependency) for the control server suite over a real pipe; winsys is a binding crate,
  not a platform.
- `platform-mac` and `platform-win` depend on core and platform-api, never on app-core or on each other.
- `macvpn-winsys` depends on `windows-sys` only and knows nothing of MacVPN. Core, platform-win, the helper and the
  example client depend on it under `[target.'cfg(windows)'.dependencies]`, so no macOS binary links it:
  `cargo tree --locked -e normal --target aarch64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none | grep -E '^(windows|macvpn-winsys)'`
  prints nothing (the same for `x86_64-apple-darwin`).
- The app depends on `macvpn-platform-mac` only for `cfg(target_os = "macos")`, on `macvpn-platform-win` only
  for `cfg(windows)` and on `macvpn-platform-linux` only for `cfg(target_os = "linux")`
  (`app/src-tauri/Cargo.toml`); any other target stops at a `compile_error!` in `app/src-tauri/src/platform/mod.rs`.
- `platform-linux` depends on core and platform-api like the other platform crates; its Linux bindings (`zbus`,
  `ksni`, `gtk`, `glib`, `gdk`, `libc`, `macvpn-unixsys`) are `[target.'cfg(target_os = "linux")'.dependencies]`
  pinned exactly, so no Linux-only crate reaches a macOS or Windows binary:
  `cargo tree --locked -e normal --target aarch64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none | grep -E '^(zbus|ksni|macvpn-platform-linux) '`
  prints nothing (and the same for `x86_64-pc-windows-msvc`).
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
  directives an OS refuses or that need an acknowledgement there; on Windows `FORBIDDEN_WINDOWS` and the `setenv`
  allowlist come on top. The validator uses the host OS (a security rule never depends on a launch-time setting).
  The macOS and Windows tables ship in 2.0.0; the Linux table is a draft for phase 4. See
  [OpenVPN directives](openvpn-directives.md).
- **`fsx`** (`crates/core/src/fsx/`): the safe file operations, the only OS-specific module of core. `mod.rs`
  holds the portable API (`Access::{Private, Shared}`, `Follow::{No, Yes}`, `create_new`, `open_regular`,
  `atomic_write`, `owner`, `file_id`, `is_unavailable`, …); `unix.rs` and `windows.rs` hold the OS calls. On Unix
  every function does exactly what its call sites did before 1.5 (`O_NOFOLLOW`, `O_NONBLOCK`, modes 0600 / 0700,
  the same order of checks and error kinds). core calls no libc function (only constants) and has no `unsafe`.
  - **`fsx::Stat`.** `owner`, `has_access`, `file_id` and `hard_links` take a `&Stat`, not a `std::fs::Metadata`.
    `Stat` derefs to `Metadata`; on Windows it also carries what was read from the open handle (the owner SID, the
    DACL's shape, the volume serial and 128-bit file id, the link count, the reparse tag). On Unix `fsx::stat(&file)`
    is `fstat`, `stat_path(p, Follow::No)` is `lstat` and `Follow::Yes` is `stat`: every call site makes the syscall
    it made before. `open_regular` returns `(File, Stat)`.
  - **Windows** (through `macvpn-winsys`). `Access::Private` is a protected DACL (nothing inherited) with
    `FILE_ALL_ACCESS` for the current user and `NT AUTHORITY\SYSTEM` only, the owner set explicitly to the user;
    directories carry the same ACEs inheritable, so SQLite's `-wal` / `-shm` files are private too. `has_access`
    is true only for exactly that shape (the counterpart of `mode & 0o7777 == 0o600`). `Access::Shared` is also
    protected: the user and SYSTEM with full access, `BUILTIN\Users` read (the counterpart of 0644 / 0755).
    `Follow::No` refuses name-surrogate reparse points (symlinks, junctions) with `is_symlink_refused`; other
    reparse points (OneDrive / Cloud Files placeholders, deduplicated files) are regular files: `open_regular`
    reopens them without `FILE_FLAG_OPEN_REPARSE_POINT` and checks that the second handle is the same file
    (volume and 128-bit id); a provider that cannot hydrate counts as `is_unavailable`. A file whose name holds
    `:` (an alternate data stream) is refused by `names_a_stream` (always `false` on Unix). `hard_links` is the real
    count (`u64::MAX` when it cannot be read, so `store::shred_file` never overwrites a file it cannot count).
    `sync_dir` stays a no-op (NTFS journals the rename). Whatever cannot be read fails closed.

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
  development sandbox, runs without a bundle); app-core re-exports it as `macvpn_app_core::app::MemoryPreferences`.
  `FilePreferences`, a JSON file written with `fsx::atomic_write` (private; a corrupt file reads as empty), is
  WinVPN's store (portable, tested on macOS too; macOS keeps `CFPreferences`).
- **Added in 2a, with defaults that keep macOS as it is:** `SystemSetup::engine_note()` (default `None`; a note
  System Status shows instead of the Homebrew, tools and helper rows; the view model's `engineNote` is absent when
  `None`, so the 1.4 JSON is unchanged) and `WindowChrome::tray_tint()` (default `None`: template icons).
- **Added in 2b** (the WinVPN Service; defaults keep macOS): the curl layer moved here from platform-mac
  (`curl::{Curl, http, catalog}`: one argv builder for both OSes, `CurlHttpClient::new_with` / `download_pinned` /
  `download_from` with a runner and a user agent, `CurlCatalogFetcher::new_with`; macOS' argv is pinned by its golden
  test), `HelperClient::log_source` (a `LogSource`: the Log tab's tail over any source, here the service's
  `log <id> <offset>`), `SetupReport::{engine: Option<EngineReport { service, openvpn, wireguard }>, engine_missing,
  later_kinds}` with `later_reason`, `SystemSetup::{later_note, helper_upgrade_notice, update_package_index}` and the
  `EngineRow` type System Status renders.
- **Added in 2c** (the native VPNs): `NativeController::{managed_service_id, log_source}` (a platform log for native
  kinds), `NativeProfiles::{remove, reconcile, removes_profiles, needs_approval}`, the `NativeSupport` trait
  (`unsupported_reason` per connection, `editor_notes` → `PlatformNotes`, `system_psk_note`), the `AdminSteps` trait
  (`ca_summary`, `ca_trusted`, `trust_ca`, `allow_l2tp_behind_nat`, `offered_action`; default `NoAdminSteps`),
  `SetupReport::{ras, ras_unsupported_kinds}` with `ras_unsupported_reason`, `needs_service(kind)` and
  `start_refusal(kind)` (the one refusal of the `connect` command, the control API's `up` and `connect_key`: a native
  kind or a system VPN never needs the service), `LogStreamSpawner::is_available`, `SystemSetup::account_cleanup` (G-9)
  and `UninstallSystem::helper_disconnects`. macOS answers every one of them as before (`setup_report.rs`,
  `admin_steps.rs` pin it).
- A few signatures differ from the first draft of the plan, and the code is what counts:
  `SystemInfo::user_owner()` returns `Result<FileOwner, PlatformError>` (a platform that cannot read the owner fails
  closed; the caller then reads no helper state file); `SystemSetup::install_tools(report, output)` streams the installer's
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

### winsys

`crates/winsys` (`macvpn-winsys`) holds every Win32 call that core's `fsx`, the Windows platform and the WinVPN
Service need, behind safe functions, generic (it knows nothing of WinVPN's names or texts). It is its own crate
because core may not contain `unsafe` and cannot depend on platform-win (which depends on core). `#![cfg(windows)]` as
a whole; every `unsafe` block says why it is sound. The tests (`crates/winsys/tests/`) run on Windows. The modules:

- `sid` (the current user's SID, well-known SIDs), `file` (open with the right flags, the DACL shapes `Private`,
  `Shared` and `Protection::Admins` (SYSTEM + Administrators, for the service's data), what a handle says: owner, DACL
  shape, 128-bit id, link count, reparse tag), `random` (`BCryptGenRandom`), `mutex` (a named mutex with a private
  DACL), `pipe` (below).
- 2b: `trust` (Authenticode: `verify_signature` → `Signer { subject }`, revocation not checked online), `version`
  (a file's version resource), `acl_check::is_admin_only` (a path whose every level only administrators can change),
  `dll` (`SetDefaultDllDirectories`, `Library::system32(name)`: System32 only, never the search path), `known` (known
  folders: ProgramData, System32, Windows), `scm` (read-only `query`, `disable_and_stop`, `set_recovery`), `net` (IP
  Helper and WLAN reads for the network probe of 2.0's auto-reconnect).
- 2c: `ras` (the RAS API, below), `cert_store::local_machine_contains` (read-only lookup by SHA-1 thumbprint in the
  computer's store, for "Trusted by Windows") and `profiles::list` (the machine's `ProfileList`: SID → profile folder,
  for the service's logoff net).

**`winsys::ras`** (`entry`, `ini`, `creds`, `dial`, `watch`): `Phonebook::at(path)` (a private phonebook: write, read,
delete, list) and `Phonebook::system()` (the default phonebooks, read and list only; every write refuses it).
`Entry { name, strategy: L2tp|Sstp|Ikev2|Other, server, auth: MsChapV2 { psk } | EapMsChapV2 | MachineCertificate,
default gateways, ts_as_routes, ike_fragmentation, interface_metric, policy, guid }` is encoded into `RASENTRYW`
exactly as Microsoft's own `Add-VpnConnection` writes it (pinned against reference phonebook sections captured on
Windows 11, `crates/winsys/tests/fixtures/ras/`); `write` also writes the EAP data (`RasSetCustomAuthDataW`) and the
IKEv2 policy keys (`NumCustomPolicy` / `CustomIPSecPolicies`, six DWORDs, after every write, read back). There is no
IKEv2 PSK form: Windows dials none. Credentials: `set_psk` / `clear_psk` / `has_psk` (`RasSetCredentialsW` with
`RASCM_PreSharedKey`; the PSK is never in the file), `saved_credentials` (only "saved or not" leaves winsys).
Dialling: `dial` / `dial_saved` (`RasDialW` with a `RasDialFunc2` callback found through `dwCallbackId`; the
`RASDIALPARAMSW` / `RASCREDENTIALSW` buffers are wiped with volatile writes right after the call), `hang_up(handle,
wait)` (`RasHangUpW`, then `RasGetConnectStatusW` until the handle is gone), `connections()` (with the phonebook path
as the dialler passed it), `status`, `ipv4` (`RasGetProjectionInfoEx`), `error_text`, `dial_dlg` (Windows' own sign-in
window, `rasdlg.dll` from System32). `Watcher` waits on a RAS connection event, one change handle per phonebook folder
(or its nearest existing parent) and a stop event. A dial in an SSH (network) logon cannot be seen or hung up by its
own process (the 2c spike): those tests are `#[ignore = "desktop: …"]` and run at the desktop.

`pipe` is the one pipe implementation (the control pipe, the single-instance pipe, the example client):

- **Server:** a protected DACL that denies `NT AUTHORITY\NETWORK` and allows the user and SYSTEM, owner = the user;
  `PIPE_REJECT_REMOTE_CLIENTS`; the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name already taken (by
  another WinVPN of this user or by a squatter) is `AddrInUse`. The peer: its PID, its image path, and its SID from
  `ImpersonateNamedPipeClient` + `OpenThreadToken` (identification level; if `RevertToSelf` fails, the process
  aborts). A client that allows less than identification cannot be identified and is closed.
- **Client:** opens with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` and refuses a server whose process does
  not run as the same user (`GetNamedPipeServerProcessId`) before it sends anything. A squatter can identify the
  client while it connects (its SID, groups and privileges, at identification level), but it can never act as the
  client and receives no data (no bearer token, no request).
- **The WinVPN Service's endpoint** (`Listener::bind_endpoint(name, Endpoint::Service)`, only in a LocalSystem
  process, else `PermissionDenied`): owner SYSTEM; protected DACL: deny `NT AUTHORITY\NETWORK`, allow SYSTEM all,
  allow `NT AUTHORITY\INTERACTIVE` `SERVICE_CLIENT_ACCESS` (`FILE_GENERIC_READ | FILE_WRITE_DATA`: never
  `FILE_CREATE_PIPE_INSTANCE`, `WRITE_DAC` or `WRITE_OWNER`, so no user can add a rogue instance to the name or
  change the DACL). Its clients (`connect_with(name, timeout, ServerTrust::LocalSystem)`) open with exactly
  `SERVICE_CLIENT_ACCESS` and identification-level impersonation, read the pipe object's owner from the handle and
  refuse anything not owned by SYSTEM (`NOT_THE_SERVICE`, also when the owner cannot be read) before they send a
  byte: only SYSTEM can create an object owned by SYSTEM, so a squatter of `\\.\pipe\WinVPN` never receives a
  request. `Endpoint::ServiceForTests` is the debug console service's pipe (owner and full access: this user;
  INTERACTIVE as above; network logons allowed for SSH tests; refused in a LocalSystem process), reached with
  `ServerTrust::SameUser`. The unit tests check the production DACL with this user as a test-only owner; the
  installed pipe itself is the admin test `admin_the_installed_service_pipe_is_owned_by_system`.
- **I/O:** overlapped, one event per operation, exact timeouts; a timed-out read cancels only itself and keeps data
  that arrived in the race; `shutdown` cancels pending I/O and closes the handle once the operations in flight have
  finished; `peer_connected` is `PeekNamedPipe`.

Because the DACL denies network logons, the production pipes refuse the same user over SSH (a network logon); the
tests pass `NetworkLogons::Allow` on their own pipe names so they run over `scripts/win-remote.sh`. The one test
that needs a second account (`another_user_is_refused_both_ways`) is ignored everywhere and is a manual check.

### platform-win

`WinPlatform` (`crates/platform-win`), created by `WinPlatform::new(sandbox)` on the main thread before any window
(it records the main thread and sets the process' AppUserModelID). No crate-level `cfg`:

- `src/pure/`: the logic without system calls, compiled and tested on every OS (`tests/pure.rs`, so the macOS CI
  covers it): the texts, the Mark-of-the-Web parser, Run-key values, toast XML, date formats, the
  single-instance message format; from 2b `engine` (System Status' rows from the service's facts), `openvpn_install`
  / `openvpn_pins` (winget and the official MSI: parsing, choices, the elevated step's arguments), `wireguard_update`,
  `update` / `update_check` (the updater's portable half); from 2c `ras_state` (the dial state machine), `ras_errors`
  (Windows error codes → texts, `AdminAction`), `ras_log` (log lines, `LogMasker`, the debug dump), `ras_connect`
  (the engine's decisions, the L2TP profile format), `ras_editor` (the editor notes), `ras_sweep`, `system_vpn`,
  `ca_trust` (a bounded DER reader for the CA summary), `admin_steps` (the fixed trust-step / `reg.exe` argv, the
  TLS-only usage property and the step's codes) and
  `cisco` (option A).
- `src/win/`: everything that calls Win32 (through `windows-sys`, the `windows` crate for COM and WinRT, and
  `macvpn-winsys`), behind `#[cfg(windows)]` in `lib.rs`. `WinPlatform` exists only on Windows.

What it implements:

- **Folders and data:** home is `FOLDERID_Profile`, the data root `FOLDERID_LocalAppData`, so the data directory is
  `%LOCALAPPDATA%\WinVPN` (not the roaming profile: a roaming sync could copy the open SQLite vault, and the vault
  key is per machine anyway). Preferences are `FilePreferences` (platform-api): `%LOCALAPPDATA%\WinVPN\preferences.json`,
  private, written with `fsx::atomic_write`; a corrupt file reads as empty.
- **Vault key:** a generic credential in Credential Manager, target `local.winvpn.vault`, user name `dek`,
  `CRED_PERSIST_LOCAL_MACHINE` (DPAPI for this user; never roams). `ERROR_NOT_FOUND` is "no key",
  `ERROR_NO_SUCH_LOGON_SESSION` is `Unavailable` (an SSH key logon has no credential session). The blob copy is
  zeroized. Entropy is `BCryptGenRandom`. The legacy keychain and legacy secrets are empty.
- **Mark of the Web:** the `Zone.Identifier` stream (read through std, at most 4 KiB): `ZoneId` 3 or 4 is marked,
  0–2 or no stream is not, anything unreadable is marked.
- **Window chrome:** `DWMWA_WINDOW_CORNER_PREFERENCE` = round (Windows 11, radius 8; on Windows 10 the call fails and
  the corners stay square), for every window: the app's `corners` plugin rounds each window Tauri creates
  (`on_window_ready`, through `WindowChrome::window_corner_radius`; `None` on macOS). DWM draws no rounded corners
  without a hardware display driver (a VM on the Microsoft Basic Display Adapter shows every window square, File
  Explorer's too); the tray tint (white on a dark taskbar, black on a light one, from
  `SystemUsesLightTheme`), read again whenever the icon is set or the popover opens.
- **File panels:** `IFileOpenDialog` / `IFileSaveDialog`, shown from a message posted to platform-win's hidden
  message window, so `choose_files` returns at once and the modal loop never runs inside a caller's lock.
- **Notifications:** WinRT toasts under the AppUserModelID `local.winvpn` (also on the MSI's Start-menu shortcut);
  the tag is the notification identifier (hashed when longer than 64 characters), so `remove_delivered` works.
- **Secret clipboard:** `CF_UNICODETEXT` plus `ExcludeClipboardContentFromMonitorProcessing`,
  `CanIncludeInClipboardHistory` = 0 and `CanUploadToCloudClipboard` = 0; the mark is the clipboard sequence number,
  so `clear_if_unchanged` empties only an untouched clipboard.
- **Lifecycle:** a hidden top-level window (message-only windows get no `WM_QUERYENDSESSION`) answers a logoff or
  shutdown with the quit questions (`Later` holds Windows with `ShutdownBlockReasonCreate`, "Closing WinVPN…"), and
  turns `PBT_APMRESUMEAUTOMATIC` into a wake.
- **Launch at login:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinVPN` = the quoted path of the installed
  `WinVPN.exe`; the Settings switch (`…\Explorer\StartupApproved\Run\WinVPN`) is read, and a disabled entry shows the
  note and the button to `ms-settings:startupapps`. The sandbox and development builds get an item that cannot be
  switched on.
- **Single instance:** a named mutex `Local\WinVPN-instance-<SID>` (protected DACL: the user and SYSTEM, owner the
  user; `macvpn_winsys::mutex`) decides; a second launch forwards its absolute file arguments (or an empty list:
  "show yourself") over `\\.\pipe\WinVPN-open-<SID>-<session>` (same-user peers only, at most 64 KiB, one 2 s
  deadline per message) and exits 0. An existing mutex that another user owns (or that cannot be opened) is a
  squatter, not a running WinVPN; every claim failure is shown in a message box (EN/HU) before WinVPN exits 1.
- **Control transport:** `\\.\pipe\WinVPN-control-<SID>` (see [the control API transport](#the-control-api-transport)).
- **The WinVPN Service's client (2b):** `HelperClient` and `AuthStateReader` are `win::service_client::ServiceClient`
  over `\\.\pipe\WinVPN` (`macvpn_core::service_proto`, one request per pipe connection, `--lang` of the app). It
  opens the pipe with `ServerTrust::LocalSystem` (`FILE_GENERIC_READ | FILE_WRITE_DATA`, identification level) and
  refuses a pipe not owned by SYSTEM before a byte is sent; the `up` body is `macvpn_core::helper_args::up_stdin`
  (the root layer 8 frame, zeroized; shared with macOS' `MvpnClient`). The live log is a `LogSource` over `log <id>
  <offset>` (the generation is the identity), the MFA state comes from `auth-state <id>`. `SystemSetup::check` asks
  `engine` and maps the facts with `pure::engine::report`: three rows (service, OpenVPN with its DCO and
  TAP-Windows6 drivers, WireGuard; 2c adds a fourth, the Windows VPN client, `ras`), and `engine_missing` only when the service is absent ("The WinVPN Service is
  missing or from another WinVPN version. Repair WinVPN: …"), unreachable or not provably the service ("The WinVPN
  Service is not reachable."), of another version, or degraded (its reason). Then `SetupReport::is_available` is
  false for every kind, every row (`ViewModel::set_engine_missing`: `unavailableReason`, absent on macOS) shows that
  text, System Status shows it instead of the rows, the `connect` command refuses with it, and the control API's
  `up` answers `failed` with it (`ControlHost::engine_missing`), never `setup_required`.
  (2c: `engine_missing` greys and refuses only the kinds that need the service: `set_engine_missing_where` and
  `SetupReport::start_refusal`; L2TP, IKEv2, SSTP and system VPNs keep working without it.)
- **OpenVPN Community (2b):** `win::openvpn_install` installs, repairs and updates it from System Status: winget
  (machine scope, `--override` with the pinned `ADDLOCAL`: `openvpn.exe`, DCO, TAP-Windows6), else the newest
  official MSI from `openvpn.net`'s download page (or the hash-pinned MSI of `scripts/pins/openvpn.txt` as the
  minimum and offline fallback), its Authenticode signer `OpenVPN Inc.` checked by the app and again by the elevated
  step. The elevated step is the installed `WinVPN.exe --winvpn-openvpn-step …` started with `ShellExecuteExW(runas)`
  (`win::elevate`; only from Program Files), which re-opens the MSI deny-write, runs System32's `msiexec.exe`,
  disables and stops OpenVPN's Interactive Service on installs WinVPN made, and records `OpenVpnInstalledByWinVpn`
  under `HKLM\SOFTWARE\WinVPN`. Update offers come from `winget list --upgrade-available` (read-only) and the page;
  never a downgrade.
- **The updater (2b):** `win::updater` downloads `WinVPN-<version>-<arch>.msi` with its `.sha256` and `.sig`, checks
  `verify_trusted_for(WinVpnV1, asset, …)`, holds the MSI deny-write, creates msiexec's log new, starts a relauncher
  copy (`WinVPN-relaunch.exe`) that re-opens and re-hashes the MSI and holds it and the log until msiexec has exited,
  then starts System32's `msiexec.exe` elevated (one UAC prompt), hands the relauncher its PID and quits; the
  relauncher starts WinVPN again; logs and the one-time notice in `%LOCALAPPDATA%\WinVPN\updates`. The release source is `pure::update_check` (the GitHub
  repository ID, as in MacVPN's Info.plist).
- **Over-the-shoulder UAC: the elevated step is another account.** On a standard user's account the UAC prompt
  asks for an administrator's credentials and the elevated program runs as *that* administrator: its `HKCU`,
  `%LOCALAPPDATA%`, `%TEMP%` and profile are the administrator's, and the signed-in user's private files (this user
  and SYSTEM only) are closed to it. Every elevated step (`win::elevate`) therefore gets absolute paths on its
  command line, never derives a per-user path or `HKCU` value itself (it touches only `HKLM`, `C:\ProgramData`,
  the service manager and the machine's certificate store), and every file it crosses is opened to it on the file
  itself, while the folders above stay private (every account has "Bypass traverse checking"): what it reads
  (the OpenVPN MSI, WinVPN's update MSI, the CA certificate of **Trust This CA in Windows…**) is
  `Protection::Shared` (`BUILTIN\Users` read; public, checked again by the step or re-hashed by the relauncher),
  what it writes (msiexec's update log) `Protection::AdminsReadWrite` (Administrators read and write, never delete,
  `WRITE_DAC` or `WRITE_OWNER`). The updater's relauncher refuses to answer `held` unless both files have exactly
  these DACLs. 2.1.0 (OpenVPN MSI) and 2.1.1 (update MSI and log) left them private, so the elevated step failed
  only on standard users' accounts. The tests prove the other account's rights without signing in as it:
  `macvpn_winsys::file::access_for` runs the system's access check (`AuthzAccessCheck`) for an arbitrary SID
  with the groups of an elevated administrator. The elevated steps: the update's `msiexec.exe` (`win::updater`), the
  OpenVPN step (`WinVPN.exe --winvpn-openvpn-step`), the trust step (`WinVPN.exe --winvpn-trust-ca-step`) and
  `reg.exe` for **Allow L2TP Behind NAT…** (no file); winget elevates its own installer from its own downloads.
- **HTTPS (2b):** `win::curl_runner` runs System32's `curl.exe` (absolute path, environment `SystemRoot` + `PATH` =
  System32 only, no window, output caps, a time limit) for the update check, the updater, the OpenVPN download and
  the HTTPS catalog fetcher (`win::https`); the bearer token goes on curl's stdin (`--config -`), never in argv.
- **The native VPNs (2c):** `win::ras_engine::RasEngine` (one per process) implements `NativeController`,
  `NativeProfiles` and `NativeSupport`, and `RasHelper { service, ras }` is the app's `HelperClient`: IKEv2 and SSTP
  go to the engine, OpenVPN and WireGuard to the service. `win::system_vpns` lists and dials the user's own Windows
  VPNs, `win::ras_watch` feeds the live list, `win::admin_steps` runs the two UAC steps. See
  [Native VPNs on Windows (RAS)](#native-vpns-on-windows-ras).
- **Lifecycle additions:** `WM_ENDSESSION` with `ENDSESSION_LOGOFF` hangs up the user's RAS connections
  (`observe_logoff`), `PBT_APMSUSPEND` / `RegisterSuspendResumeNotification` announce sleep (2.0's auto-reconnect),
  `WM_SETTINGCHANGE` "ImmersiveColorSet" re-tints the tray icon (G-7). `SystemSetup::update_package_index` answers
  `Updated` with a usable service, so the daily scheduler re-checks the engines (G-1).
- **Clean-up (G-9):** `SystemSetup::account_cleanup()` is true on Windows: System Status offers **Remove WinVPN from
  This Account…**, which runs app-core's `setup::uninstall` (every connection down, the Run value, every
  `WinVPN-<UUID>` entry and its PSK through `NativeProfiles::remove` and `reconcile(∅)`, optionally the data folder and
  the Credential Manager key) and then opens Installed apps for the MSI. The service and Program Files stay the MSI's.

The storage identifiers (`local.winvpn.vault`, the Run value `WinVPN`, the pipe and mutex names) are literals in
this crate and never derive from `Product`. Tests on Windows (`tests/windows.rs`, `tests/lifecycle.rs`,
`tests/control_pipe.rs`) use their own names (`local.winvpn.test.<uuid>`, `WinVPN-test-…`) and delete them; the
Credential Manager round trip skips itself in an SSH key logon, so it is part of the manual checklist.

### platform-linux

The Linux platform (LinVPN), laid out like platform-win: `src/pure/` compiles and is tested on every OS (the XDG
paths, the sandbox's "not yet" texts, the autostart file, the update rules and the update check, the panel's
placement, the portal's values, the single-instance names, the preferred languages, the download mark's decision,
and `pure::nm`/`pure::net`: NetworkManager's states, the agent's rules, the plugin rows, the system VPN rules, the
tunnel interfaces, the physical network's choice); `src/lin/` calls the system and exists only under
`cfg(target_os = "linux")`: `LinPlatform` (every trait, `lin/platform.rs`), one lazily opened session and system bus
(`lin/bus.rs`; the sandbox and the tests open none unless they call a service), one module per facility, and
`lin/nm/` (the NetworkManager engine, L-b). The pure translation of a connection into NetworkManager settings is
`macvpn_core::nm_plan`, `linvpn-logd`'s protocol and filter are `macvpn_core::logd`, and `linvpn-xfrmd`'s protocol,
XFRM dump parser and ownership rule are `macvpn_core::xfrmd` (all tested on every OS).
Details in [LinVPN on Linux](#linvpn-on-linux).

The storage identifiers are literals in this crate and never derive from `Product`: the Secret Service attributes
`application = local.linvpn`, `kind = vault-key`, the bus names `local.linvpn.Instance` and
`local.linvpn.Sandbox.h<hash>`, `linvpn.desktop`, `linvpn.sock` / `linvpn.lock`. Tests that need a session bus run
under `dbus-run-session` against fakes they serve themselves; the few that need the real desktop are ignored
everywhere (`desktop:` in `scripts/ignored-everywhere.txt`) and run at a checkpoint.

### unixsys

`crates/unixsys` (`macvpn-unixsys`) holds the Unix calls macOS and Linux share, behind a safe API: the control API's
socket (`control_socket`: the private `control/` directory, `bind` with the lock file and `flock`, the umask, the
peer's identity, `is_already_closed`, `random_32`; moved from platform-mac byte for byte, which re-exports it as
`macvpn_platform_mac::control_socket`, so its callers and tests did not change), the socket's platform-api transport
(`transport`), and the kernel's randomness (`random`: `getentropy` on macOS, `getrandom(2)` on Linux). The peer
lookup is per OS: macOS keeps `getpeereid` + `LOCAL_PEERPID` + `proc_pidpath`; Linux uses `SO_PEERCRED` and
`/proc/<pid>/exe` (a target ending in ` (deleted)` cannot pair). `SUN_PATH_LEN` is 104 on macOS and 108 on Linux.
`#![cfg(unix)]`: empty on Windows. Every `unsafe` block is a direct libc call with a `SAFETY` comment.

### helper

`crates/helper` (package `macvpn-helper`, binary `mvpn`: installed as `/usr/local/libexec/macvpn/mvpn` on macOS and
as `C:\Program Files\WinVPN\WinVPNService.exe` on Windows; root layer version in `crates/helper/VERSION`, 8 from
1.2.0, 9 in 2.0.0: the DNS manager, the log caps, strongSwan's credentials and concurrent connections; 10 in 2.0.3:
`mvpn liveness <id>` for dead-tunnel detection, see [Dead tunnels](#dead-tunnels-and-the-live-network-switch); 11 in
2.0.4: `mvpn traffic <id>` and strongSwan's virtual IP in `mvpn status`, see [Live traffic](#live-traffic); 12 in
2.0.7: an IKEv2 client certificate in the `up` frame and the key password, see [IKEv2 client
certificates](#ikev2-client-certificates-root-layer-12)).

- `src/shared/`: the logic every OS shares, with no `cfg`, no `unsafe` and no process or file I/O: the command
  line (`cli`), the framed stdin (`framing`), masking, the `respond` answer, the status JSON, the validation
  dispatch and the management-bridge state machine (`bridge`, over any `Read + Write` stream).
- `src/macos/`: everything the macOS root layer does (sudo, the tools, run directories, DNS hooks, the
  `MVPN_*` test-mode hooks for non-root runs only). `#![cfg(target_os = "macos")]`.
- `src/windows/`: the WinVPN Service (see [The WinVPN Service](#the-winvpn-service)). Its request handling and the
  engines' pure parts (`service`, `logs`, `ovpn_args`, `ovpn_run`, `bridge_state`, `wg_nt`, `wg_plan`, `wg_update`,
  `diagnostics`, `ras_logoff`, `recovery`, the pins) compile and are tested on every OS; `sys/` (Windows only) holds
  the host, the pipe server and the engines.
- `src/linux/`: LinVPN's root update step, the second binary `linvpn-install-update`
  (`src/linux/main_install_update.rs`, installed as `/usr/libexec/linvpn/linvpn-install-update`; see [the update
  chain](#the-update-chain-and-the-deb)), and the third binary `linvpn-logd` (`src/linux/logd*.rs`, installed as
  `/usr/libexec/linvpn/linvpn-logd`, socket-activated, not root; see [`linvpn-logd`](#linvpn-logd-and-the-log-tab)),
  and the fourth binary `linvpn-xfrmd` (`src/linux/xfrmd*.rs`, installed as `/usr/libexec/linvpn/linvpn-xfrmd`,
  socket-activated, not root, `CAP_NET_ADMIN` only; see [`linvpn-xfrmd`](#linvpn-xfrmd-ikev2-traffic-and-liveness)).
  Their pure rules are `macvpn_core::deb_update` (asset names, the `.deb` fields, version order, exit codes),
  `macvpn_core::logd` and `macvpn_core::xfrmd`, shared with the app. `#![cfg(target_os = "linux")]`; elsewhere the binaries exit 2.
- `src/main.rs` picks the backend with `cfg`; on Linux `mvpn` only says it is not used there (exit 2): LinVPN drives
  NetworkManager and needs no root layer for its VPNs.

### The WinVPN Service

The Windows counterpart of the root layer (spec 4.1; [the 2b plan](superpowers/plans/2026-10-22-winvpn-2b-service-openvpn-wireguard.md)).

- **Binary and modes:** `WinVPNService.exe service` is what the SCM starts (service `WinVPN`, display name "WinVPN
  Service", LocalSystem, automatic start; installed by the MSI's `ServiceInstall`). It refuses to run unless the
  process is LocalSystem. Debug builds also have `console` (`mvpn.exe console [--fake-engine] …`): the same core on a
  user-owned test pipe, for the tests that run as a standard user over SSH. The release gate of `build-msi.sh`
  refuses the console's markers in the shipped exe. At every start the service sets its own recovery actions
  (`winsys::scm::set_recovery`: restart after 5 s and 30 s, reset after a day; Windows Installer's own table cannot,
  error 1939).
- **The protocol** (`macvpn_core::service_proto`, `SERVICE_VERSION` 1): one request per pipe connection, the
  argument list of `mvpn` (`up|down <kind> <id> [--debug] [--accept-risky …] [--lang en|hu]`, `respond`, `status`,
  `version`, `engine`, `auth-state <id>`, `log <id> <offset>`, `clear-log <id>`, `liveness <id>`, `traffic <id>`, `wireguard-check`, `wireguard-update`) plus the framed
  stdin body of root layer 8 (`core::helper_args::up_stdin`, shared with macOS' `MvpnClient`), zeroized after use;
  the answer is an exit code with stdout/stderr. A whole request has a 5 s deadline; one in-flight request per SID.
- **The pipe:** `\\.\pipe\WinVPN`, owner SYSTEM, a protected DACL (NETWORK denied, INTERACTIVE gets
  `FILE_GENERIC_READ | FILE_WRITE_DATA` only, never `FILE_CREATE_PIPE_INSTANCE`, `WRITE_DAC` or `WRITE_OWNER`),
  `FILE_FLAG_FIRST_PIPE_INSTANCE` (a squatted name is retried every 5 s, logged, while the SCM already sees
  `RUNNING`). The app's client (`ServerTrust::LocalSystem`) refuses a pipe not owned by SYSTEM before it sends a byte.
- **Identity and ownership:** the caller's SID comes from identification-level impersonation of the pipe, never from
  the request; a connection belongs to the SID that brought it up, and only it can take it down, answer its MFA
  prompt, read its log or see it in `status` (another user's ID answers "Invalid ID": no oracle). Limits: connections
  and logs per user, `MAX_LOGS_TOTAL`, a busy marker per ID, an epoch so a `down` or a logoff during a blocking `up`
  wins.
- **The data directory** `C:\ProgramData\WinVPN` (`logs`, `run\<ID>`, `engines\wireguard-nt`, `service.log`):
  created with `Protection::Admins`; an existing folder must be a real directory with an owner in
  {SYSTEM, Administrators} and exactly that DACL, else the service runs **degraded**: every engine answers "The folder
  … has unsafe permissions …" and System Status shows it. Names below it come only from UUIDs; reparse points are
  refused; leftover run directories are swept at start.
- **The job and logoff:** every engine process runs in the service's job object (killed with it).
  `SERVICE_CONTROL_SESSIONCHANGE` / `WTS_SESSION_LOGOFF` takes down the connections of a SID with no session left
  (decision 2), and (2c, `ras_logoff`) hangs up that user's WinVPN RAS connections: their phonebook must be exactly
  `<profile>\AppData\Local\WinVPN\ras\WinVPN.pbk` (the profile from `HKLM\…\ProfileList`, compared component by
  component), the entry name exactly `WinVPN-<UUID>`; one 10 s budget, one `service.log` line per hang-up. Locking and
  user switching keep everything.
- **OpenVPN:** `sys::detect` reads `HKLM\SOFTWARE\OpenVPN` (64-bit view) and the `ovpn-dco` / `tap0901` driver
  services, and before every start checks `openvpn.exe`: an admin-only path (`acl_check`), Authenticode signer
  `OpenVPN Inc.`, version ≥ `min_version` 2.6.0. `ovpn_args::argv` builds the command line from the run directory's
  fixed file names only (the validated config, a password file, `--management 127.0.0.1 <port>` with a password file,
  `--mute 20`, `--verb 5` in debug); `choose_driver` picks DCO or TAP-Windows6 (`--disable-dco`) from the validated
  config, never from `windows-driver`, and a DCO incompatibility the server pushes gets one TAP-Windows6 retry. The
  environment is cleared. The management port's peer is checked with `GetExtendedTcpTable` (the password goes only to
  the child's PID); the in-process bridge (`shared::bridge`) answers only `ManagementCommand`s, writes `auth-state`
  for the app, and logs `[mgmt] …`. Stop: `signal SIGTERM` on the management socket, 5 s, then terminate.
- **WireGuard:** `wireguard.dll` (wireguard-nt 1.1, pinned by SHA-256 in `scripts/pins/wireguard-nt.txt`) is loaded
  from the install folder held deny-write, checked for signer `WireGuard LLC` at every load; a newer one the service
  downloaded (`wg_update`: the official listing, a bounded zip reader, signer, version and machine checks, swapped only
  while no WireGuard connection is up) is preferred when valid. `wg_plan` / `wg_nt` turn the validated config into
  the driver's structs (keys zeroized); IP Helper sets addresses, routes and DNS on the adapter's own LUID only
  (`sys::iphlp`); the adapter's name and GUID are derived from the connection ID with SHA-256.
- **Logs:** `FileLogStore` (`logs.rs`): one masked log per connection (8 MiB, then `<ID>.log.1`), read by the app
  through `log <id> <offset>`; `clear-log <id>` (the Log tab's "Clear Log…"; the log's owner only, now or after
  `down`) empties it in place under the writing sink's lock, deletes `.1`, writes `core::log::cleared_note` with the
  service's local time and takes a new generation (the app's tail starts over; an older service answers the usage
  error, which the app shows as "update WinVPN"; `SERVICE_VERSION` stays 1); `service.log` 1 MiB + `.1`. **Debug mode** (G-6) adds `diagnostics::snapshot` before and
  after an `up` (resolution, IPv4 routes, DNS, interfaces; read-only IP Helper) and WireGuard's peer status
  (`WireGuardGetConfiguration`, without keys).
- **Tested where:** the pure parts on every OS (`service_core.rs`, `wg_update.rs`, `diagnostics.rs`, `ras_logoff.rs`,
  …); the console over SSH as a standard user (`service_client.rs`, `wireguard_update.rs`, `openvpn_fake.rs`); the
  admin set (`service_admin`, `wireguard_admin`, `openvpn_installed`, `openvpn_e2e`, winsys `service_pipe`; ignored
  everywhere else) in CI's `windows-admin` job and in the maintainer's elevated checklist run.

### app-core

The app logic without a UI, tested without one. macOS concepts got neutral names in 1.5: `SystemVpn` (was
`SystemService`), `HelperClient` / `Dependencies::helper` (was `RootClient` / `root`), `NativeProfiles` with
`build()` (was `ProfileInstaller`; macOS builds the same `.mobileconfig` bytes). Every serialized format kept its
field names (`#[serde(rename = …)]` where a Rust name changed); the 1.4.0 compatibility fixtures in
`crates/app-core/tests/fixtures/compat-1.4.0` prove it (`cargo test -p macvpn-app-core --test compat_1_4`).

### The app's platform module

`app/src-tauri/src/platform/` is the app's one door to the OS and its only `cfg(target_os)`:

- `mod.rs` picks `macos.rs` (creates `MacPlatform`), `windows.rs` (creates `WinPlatform`) or `linux.rs` (creates
  `LinPlatform`; any other target is a `compile_error!`) and offers `init(sandbox)` / `get()` (the `&'static dyn Platform`), and the Tauri glue that
  platform-api cannot hold because it does not depend on Tauri: `native_window` (`ns_window()` / `hwnd()`),
  `configure_app` (macOS: the activation policy; Windows: this launch's files and the single-instance listener),
  `set_window_presence` (the Dock icon; a no-op on Windows, which shows a taskbar button for every real window),
  `on_run_event` (`Reopen`, `Opened`; nothing on Windows), `supported()` (`Ok` on both) and `uses_app_menu()`.
- On Windows the app installs no app menu (it would become a menu bar in every window; WebView2 keeps the text
  shortcuts and Quit is in the popover). `claim_instance()` runs first: a second launch forwards its files to the
  running WinVPN and exits; with no files the running WinVPN brings its open windows forward, or opens the
  Connections window (the vault's unlock or create window while the vault is closed;
  `macvpn_app_core::open_files::show_yourself`). Files from File Explorer go through the same
  `open_files::opened` handler as macOS' `RunEvent::Opened`, so the Mark-of-the-Web question applies to each.
- `tray.rs` is shared: `popover_position` puts the popover **above** the icon when the icon is in the lower half of
  its monitor (the Windows taskbar) and below it otherwise (the macOS result is unchanged, tested). When the
  content's height changes (`set_menu_height`), a popover below the icon keeps its top edge (macOS, as before) and
  one above it keeps its bottom edge, growing and shrinking upward inside the work area (`resized_top`; moved and
  resized in one step by `WindowChrome::set_outer_frame`); the icons are
  template images on macOS and the same PNGs tinted with `WindowChrome::tray_tint()` on Windows; the tooltip is the
  product's name.
- On Linux (`linux.rs`) the glue is the `GtkWindow` handle, one instance per user over the session bus (a second
  launch forwards its files, `linvpn %F`, through the same `open_files` handlers), the exit hook for SIGTERM, and
  the platform's own tray icon (`create_own_tray`) and the popover as the card panel's overlay
  (`menu_is_overlay`, `present_menu_overlay`), which `tray.rs` uses instead of Tauri's tray (see [LinVPN on
  Linux](#linvpn-on-linux)).
- `environment.rs`: `Environment` (home, bundle, sandbox, Info.plist), built from `SystemInfo` and `Product`.
- `smoke/`: the smoke driver (debug builds), reached elsewhere through the `platform::smoke_*` facades, which do
  nothing on other targets; on Linux `linux_smoke.rs` answers "not a smoke run" until the Linux smoke driver
  (LinVPN plan, Task 23) arrives.

Window code passes `platform::native_window(&w)` (a `NativeWindow`, never dereferenced outside a platform crate)
to `WindowChrome` and `FilePanels`.

### The UI

One Svelte UI. It learns the OS and the product from the read-only command `get_platform`
(`{ os, productName }`), which `main.ts` awaits before mounting (an error or an unknown OS keeps the macOS
default). `tr()` passes the platform to `translate()` in `app/ui/src/lib/l10n-core.ts`. Keyboard shortcuts use
`isPrimaryShortcut` from `app/ui/src/lib/keys.ts`: Cmd on macOS, Ctrl on Windows and Linux. The view model does not
carry the platform, so its JSON is the same as in 1.4. The font stacks list the Windows fonts after the Apple ones
(`Segoe UI Variable Text`, `Segoe UI`; `Consolas` for monospace), so macOS renders exactly as before.

## Native VPNs on Windows (RAS)

L2TP/IPsec, IKEv2 and SSTP connect through the Windows RAS client, **in the app process** (the user's own logon),
without the WinVPN Service and without an administrator; the user's own Windows VPNs are listed as system VPNs
([the 2c plan](superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md), "Resolved points"; the facts behind it are in
[the RAS spike](superpowers/spikes/2026-10-25-winvpn-ras.md)).

- **A private phonebook per user:** `%LOCALAPPDATA%\WinVPN\ras\WinVPN.pbk` (the data folder's private ACL), passed
  to every RAS call. It never collides with the user's own entries (`%APPDATA%\…\Pbk\rasphone.pbk` and the
  all-users phonebook, which WinVPN never writes), needs no administrator, and its entries are not shown in Settings →
  VPN (connecting is WinVPN's). **Entry names** are `WinVPN-<UUID upper case>` from the connection ID only
  (`macvpn_core::ras::names`); the engine refuses to write, dial or delete any other name of its phonebook.
- **`macvpn_core::ras`** (pure, every OS): `plan_for(connection, config)` → `RasEntryPlan` (strategy, server, the
  user name the connection names, auth `MsChapV2 { psk } | EapMsChapV2 | MachineCertificate | Ikev2Psk`, default
  route / traffic selectors as routes, interface metric, `WindowsPolicy`, `needs`, `warnings`) or `Unsupported
  { reasons, invalid_config }`. L2TP from the native settings; SSTP from `SSTPConfig` (`cert=insecure` is a reason,
  `host:port` when the port is not 443, `peer_dns=no` → metric 9000); IKEv2 by translating the first connection and
  child of `swanctl.conf` (`local auth = psk`, EAP-TLS, IKEv1, several rounds, `remote id` ≠ address, … are precise
  reasons; `dpd_action = restart` and `start_action` are warnings; `proposals` map to one Windows IKE/ESP policy,
  default AES-256 / SHA-256 / DH 14). `CISCO_UNSUPPORTED` is option A's text. The policy's DWORD values live in
  winsys, not in core.
- **`winsys::ras`:** the FFI (see [winsys](#winsys)).
- **platform-win, pure:** `ras_state::Dial` (dial events → `RootStatus` / system VPN status, log lines; an error after
  our own hang-up is "cancelled"; a drop is "closed by the server or the network"), `ras_errors::explain(code,
  context)` (the Windows codes → WinVPN texts, the `AdminAction` they offer, `log_line` "Windows error <code>: …" that
  `failure_reason` classifies), `ras_log` (masking, the debug dump), `ras_connect` (the engine's decisions, the L2TP
  profile format), `ras_editor` (the editors' notes), `ras_sweep`, `system_vpn` (labels, ids, `how_to_start`, the
  Windows VPN client row).
- **The `RasEngine`** (`win/ras_engine.rs`, `win/ras_paths.rs`): one per process. **L2TP** keeps the macOS model:
  `NativeProfiles::build` encodes the plan (no secret), `install` writes the entry and keeps `<data>\ras\<UUID>.ras`
  (there is no approval step: `needs_approval()` is false), `NativeController::start` rewrites the entry from it and
  dials. **IKEv2 and SSTP** keep the helper model: `RasHelper::up` writes the entry from the config it is given and
  dials. Every connect replaces the log, writes the warnings (and the debug dump), checks the credentials, writes the
  PSK (`set_psk`, from the vault, just before dialling), calls `RasDialW` (633: one retry) and waits for the outcome
  (≤ 150 s; a sign-in failure's text lets the manager re-prompt for IKEv2/SSTP). The password (+ OTP) is only in the
  dial parameters. `status`/`list` adopt connections of this phonebook found through `RasEnumConnectionsW` (a relaunch
  shows them connected). `remove` hangs up, clears the PSK, deletes the entry, the profile and the logs; `reconcile`
  (after every unlock and restore, never on a locked vault: `ConnectionsModel::sync_native_profiles`) deletes
  `WinVPN-<UUID>` entries whose connection is gone. The log is `<data>\logs\ras\<UUID>.log` (1 MiB + `.1`), read
  through `NativeController::log_source` / `HelperClient::log_source` (G-2: the Log tab tails it; no `log stream`)
  and cleared by `NativeController::clear_log` / `HelperClient::clear_log` (in place, through the dial's `RasLog`
  when one holds it, `.1` emptied too). At logoff (`WM_ENDSESSION`) it hangs up its connections; the service is the second net.
- **System VPNs** (`win/system_vpns.rs`, `win/ras_watch.rs`): `RasEnumEntriesW(NULL, NULL)` minus the private
  phonebook; id = the entry's GUID as an upper-case UUID (so the vault's stored secrets work), label L2TP / IKEv2 /
  SSTP / VPN, status from `RasEnumConnectionsW` (GUID first). `start`: a PSK stored in WinVPN is written to that entry
  only when Windows has none (the one write WinVPN ever makes to a user's own entry), then the stored password with
  Windows' saved user name, else Windows' saved credentials (`dial_saved`), else Windows' own window (`dial_dlg`).
  The live list is a `Watcher` on the two `Pbk` folders and WinVPN's `ras` folder plus the manager's poll (the RAS
  connection event is only a hint, the spike showed).
- **The Windows VPN client row** (`SetupReport::ras`): green "Built into Windows", red when `RasMan`, `IKEEXT`,
  `PolicyAgent` or `SstpSvc` is disabled (the affected kinds go into `ras_unsupported_kinds`); Cisco is always there
  under option A, so the kind gate hides New → Cisco IPsec.
- **Per-connection reasons:** `NativeSupport::unsupported_reason` (the plan's first reason) greys a row at every
  reload (the manager reads the configs; the view model never does); `editor_notes` give the editors every reason,
  IKEv2's "On Windows: …" summary, the warnings, the SSTP "No verification" lock, the trust-CA and L2TP-copy buttons
  and the "no install step" flag (`EditorView.platform`, absent on macOS).
- **Administrator steps** (`win/admin_steps.rs`, never through the service): **Trust This CA in Windows…** stages the
  CA's DER as `ca-<random>.cer` in the user's temp folder, held `FILE_SHARE_READ` only, runs the installed
  `WinVPN.exe --winvpn-trust-ca-step <file>` with `runas` (only an admin-only exe), which checks the file again and
  adds the CA to `LocalMachine\Root` with the enhanced key usage property set to server and client authentication
  only (`cert_store::add_with_usage`, read back, removed again otherwise; M-1 of the 2.0.0 security review: no
  code-signing trust), and the app checks `LocalMachine\Root` by SHA-1 thumbprint and that property
  (`cert_store`); **Allow L2TP Behind NAT…** runs `<System32>\reg.exe add …\PolicyAgent /v
  AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 2 /f` with `runas` and reads the value back. Both argv are
  fixed words plus a path WinVPN created; the summary (subject, validity, SHA-256) and the warning come first.
- **Cisco IPsec (option A):** a reason, never a dial; `editor::l2tp_copy_of` makes "<name> (L2TP)" with the same
  server, account, password and PSK (or the same shared credential).
- **Tested where:** core's plans, platform-win's pure modules and app-core's hooks on every OS; `winsys::ras`,
  the engine's entry/PSK/sweep tests and the system VPN list over SSH as a standard user (scratch phonebooks named
  `WinVPN-test-…`); dialling, hanging up and finding a dial (`desktop:` tests) at the VM's desktop; real connections
  against the lab (`scripts/vpn-lab/`) in the native VPN section of the manual checklist.

## LinVPN on Linux

LinVPN's phase L-a ([the plan](superpowers/plans/2026-10-29-linvpn-l0-la.md), "Resolved points"; the spikes behind
it are in `docs/superpowers/spikes/2026-10-29-linvpn-*.md`) brought every platform facility to Linux; phase L-b
([the plan](superpowers/plans/2026-10-29-linvpn-lb.md), "Resolved points") the VPNs, through NetworkManager (from
[The NetworkManager engine](#the-networkmanager-engine) on). The code is `crates/platform-linux` (above), the app's
`platform/linux.rs`, `crates/unixsys`, the helper's `src/linux/`, `macvpn_core::{nm_plan, logd, xfrmd, openvpn_routing}`
and `packaging/linux/`.

### Paths and the control socket

- **XDG base directories** (`pure::paths`): data `$XDG_DATA_HOME/LinVPN` (default `~/.local/share/LinVPN`: the
  vault, `control/` with the control API's audit file), settings `$XDG_CONFIG_HOME/LinVPN` (default
  `~/.config/LinVPN`: `preferences.json`, platform-api's `FilePreferences`, private dir 0700 and file 0600), the
  update cache `$XDG_CACHE_HOME/LinVPN/updates` (default `~/.cache`), run files `$XDG_RUNTIME_DIR/linvpn`. A
  variable counts only when it is set, non-empty and absolute. The sandbox keeps everything under its home, with
  `<sandbox>/run` as the runtime dir, and memory preferences.
- **The control socket** is `$XDG_RUNTIME_DIR/linvpn/control/linvpn.sock` with `linvpn.lock` beside it (unixsys'
  code; spec 3.1), not under the data dir: `ControlTransport::bind(dir)` ignores `dir` for the socket, as Windows'
  pipe does, while `prepare_dir(dir)` still prepares the audit file's directory. `$XDG_RUNTIME_DIR` must be a real
  directory of this uid with no group or other access, else the control API stays off with the error shown (fail
  closed). The peer is identified with `SO_PEERCRED` and `/proc/<pid>/exe`. The example client's
  `default_socket_path()` returns the same path on Linux.

### Desktop services

- **The vault key** (`lin/keystore.rs`) is one item in the Secret Service's default collection (gnome-keyring):
  label `LinVPN vault key`, attributes `application = local.linvpn`, `kind = vault-key`, over plain `zbus` calls
  (`OpenSession("plain")`, `SearchItems`, `Unlock` with the system's own prompt, at most 120 s, `GetSecret`,
  `CreateItem` with `replace`, `Item.Delete`); every copy of the key is `Zeroizing`. No Secret Service, or a
  dismissed prompt: `Unavailable`, and the vault asks for the master password. The `plain` session crosses only the
  user's own session bus: the same-user boundary the Keychain and Credential Manager already accept.
- **Notifications** (`lin/notify.rs`): `org.freedesktop.Notifications.Notify` with app name `LinVPN`, the hint
  `desktop-entry = linvpn`, the `default` action (a click: `ActionInvoked` → the click handler with the user info),
  `replaces_id` per identifier; the identifier → id map is in memory only.
- **The desktop portal** (`lin/portal.rs`): appearance from `org.freedesktop.portal.Settings` `color-scheme`
  (1 dark, 2 light, 0 or unreadable: the toolkit's default) through `WindowChrome::system_dark()`, re-applied on
  `SettingChanged` (GTK 3 and WebKitGTK do not follow it themselves); the file panels through the portal's
  `FileChooser` (`OpenFile`, `SaveFile`, the `Response` signal), with an empty parent window id.
- **The clipboard** (`lin/clipboard.rs`): GTK's, on the main thread; a secret carries the extra target
  `x-kde-passwordManagerHint` = `secret`, and `clear_if_unchanged` compares an `owner-change` counter.
- **The download mark** (`pure/mark.rs`, `lin/xattr.rs`): the `user.xdg.origin.url` extended attribute browsers
  set. Only "absent", "no user xattrs on this file system" and "no such file" count as unmarked (fail closed).
- **Window chrome** (`lin/chrome.rs`): sizes through GTK; square corners on Linux; the tray icon drawn white
  (GNOME's top bar is dark in both themes).

### The tray icon and the panel

Spike L0-2 ([findings](superpowers/spikes/2026-10-29-linvpn-tray.md)) and the maintainer's decision at CP-L0
(2026-10-29) chose **variant S**: LinVPN's own StatusNotifierItem over `ksni` 0.3.7 (`lin/tray.rs`; Tauri's Linux
tray delivers no click at all). `ItemIsMenu = false`, so the host sends `Activate` (GNOME's AppIndicator extension:
a double click; KDE: a single click) and `SecondaryActivate` (a middle click): both toggle the panel. A single left
or right click on GNOME shows the item's menu after the host's double-click wait: **Open LinVPN** first, then
**Quit LinVPN**. The host's XDG activation token is passed to GTK before the panel is presented. ksni runs on
zbus' own executor (`async-io`, no tokio); its callbacks only hand the event to the main thread.

**The panel** (`FORCE_X11 = false`): GNOME on Wayland centres every positioned toplevel and has no layer shell, so
the popover window is a **transparent, undecorated, maximized overlay** (Mutter fills the work area of its
monitor); the page draws the card at the top-right, 8 px in from the right edge and 8 px below the work area's top
(`pure::placement`), and the GDK window's input region is the card's rectangle, re-applied on every
`size-allocate` (GTK resets it), so a click outside passes through and the focus loss hides the panel. LinVPN stays
on native Wayland; `GDK_BACKEND=x11` (Xwayland, with an explicit position) is only the fallback if the overlay fails
on real hardware, and it is not built in L-a. Every window carries the Wayland app id `linvpn`, so the dock shows
LinVPN's icon.

### Single instance, quitting, sleep and autostart

- **One LinVPN per user and session** (`lin/instance.rs`): the first launch owns the session-bus name
  `local.linvpn.Instance` (`RequestName` with `DO_NOT_QUEUE`) and serves `local.linvpn.Instance1.Open(aay files)`
  at `/local/linvpn/Instance`; a later launch calls `Open` with its absolute file arguments (none: "show
  yourself", `open_files::show_yourself`) and exits 0. A sandbox owns `local.linvpn.Sandbox.h<16 hex digits>`,
  so a smoke run never meets an installed LinVPN. Without a session bus LinVPN runs anyway (the control socket's
  lock still keeps one control server per user).
- **Quitting and logout** (`lin/lifecycle.rs`): SIGTERM (systemd stops the session's scope at logout) and SIGINT
  reach the terminate handler on the GTK main loop: `Now` exits, `Later` runs the app's quit flow, `Cancel` is
  logged and the app stays (the session then ends with SIGKILL after systemd's stop timeout).
- **Sleep and wake:** logind's `PrepareForSleep(bool)` on the system bus.
- **Launch at login** (`pure/autostart.rs`, `lin/login_item.rs`): `$XDG_CONFIG_HOME/autostart/linvpn.desktop`
  with `Exec=/usr/bin/linvpn`. On when the file exists without `Hidden=true` or `X-GNOME-Autostart-enabled=false`;
  a file another tool turned off shows "Turned off by another app." and switching on rewrites it. Only the installed
  `/usr/bin/linvpn` can toggle it (a development build shows why); GNOME has no settings page for it.

### The update chain and the `.deb`

- **The update check** (`pure/update_check.rs`) compiles the update source in (the `.deb` has no Info.plist), as
  WinVPN does; only the installed `/usr/bin/linvpn` checks. The asset is `linvpn_<version>_amd64.deb` or
  `_arm64.deb` (`Product::update_asset`).
- **The app's checks** (`pure/update.rs`, `lin/updater.rs`): the `.deb`, its `.sha256` and `.sig` through
  `/usr/bin/curl` (the shared curl layer) into `$XDG_CACHE_HOME/LinVPN/updates` (0700, files 0600); the hash and
  the Ed25519 signature under `LinVpnV1` and the asset's name; then the quit questions.
- **pkexec:** `/usr/bin/pkexec /usr/libexec/linvpn/linvpn-install-update --deb … --sig … --version … --asset …`
  under the polkit action `local.linvpn.update` (`auth_admin`); its output goes to `install-<version>.log` in the
  updates folder. pkexec's 126 (dismissed) or 127 (not authorized) is `Cancelled`: nothing installed. 127 is also
  pkexec's "could not run the program", so the app first checks that the step and the polkit action file are
  installed (before the download) and again after a 127: a missing one is the helper error, never a silent cancel.
- **The root step** (`crates/helper/src/linux/install_update.rs`) trusts nothing from the caller: it opens the two
  files without following links (regular files of `PKEXEC_UID` in a folder of that user with no group or other
  access), copies the package into a fresh root-owned 0700 folder under `/var/cache/linvpn-update` while hashing
  it, and on that copy verifies the signature itself, the architecture, and `dpkg-deb --field`'s Package
  (`linvpn`), Version (the signed one, newer than the installed one) and Architecture (`macvpn_core::deb_update`).
  Only then `apt-get install -y <copy>` with a clean environment; the copy is removed afterwards. Both files are
  read through their size limits (512 MiB, 1 KiB), also when they grow after the check. "No downgrade" fails
  closed: `dpkg-query` failing, or reporting `linvpn` as not installed, is refused. At its start the step sets
  umask 022 and its own resource limits (no core dumps, no file size limit, at least 1024 open files), since pkexec
  passes the caller's on. Exit codes (stable; a new one takes the next number): 10 bad arguments, 11 not root, 12
  unsafe file (also: too large), 13 bad signature, 14 wrong package, 15 wrong architecture, 16 wrong version, 17 not
  newer, 18 a tool failed, 19 apt failed, 20 `linvpn` not installed.
- **After the update:** the app writes the outcome notice into the updates folder, starts `/usr/bin/linvpn
  --after-update` detached and quits (`HelperLaunched`); the new process waits up to 20 s for the single-instance
  name, then starts; its launch housekeeping reads and removes the notice and posts "LinVPN was updated to X.Y.Z."
  as a desktop notification (`Updater::take_updated_notice`; macOS and Windows show no success notice).
- **The supervisor** (`pure/supervisor.rs`, `lin/supervisor.rs`, called first in `main` through
  `platform::supervise`): the installed LinVPN (`/usr/bin/linvpn`; not the sandbox, not a development build) starts
  itself again as the GUI process (`--supervised`) and only waits for it: no GTK, no Tauri, no instance name, no
  tray. When the GUI ends abnormally (a non-zero exit code, or a signal other than SIGTERM, SIGINT, SIGHUP) while the
  graphical session lives (the `WAYLAND_DISPLAY` socket, else the `DISPLAY` X socket, is there, and logind's
  `/run/systemd/sessions/<id>` is not `STATE=closing`; the id is `XDG_SESSION_ID` or the user's `DISPLAY=` session),
  it starts it again 2 s later with `--supervised --restarted=<reason>`: no files, no `--after-update`, and the launch
  opens no window by itself (no unlock or System Status window: the tray unlocks); the new process logs the reason
  and adopts the tunnels still up as any launch does (`.linvpn-run.json`). At most 5 restarts in 10 minutes, then it
  gives up and logs it. Exit 0 is never restarted: Quit, SIGTERM through the exit hook, and the updater's and the
  package watch's hand-over (`linvpn --after-update` started, then the old GUI exits 0). SIGTERM, SIGINT or SIGHUP to
  the supervisor ends the supervision (not passed on: a logout reaches the whole scope). A launch while the instance
  name has an owner (`linvpn file.ovpn`, the dock) is not supervised: it goes on as a plain launch and forwards its
  files; `--after-update` is supervised although the old process still owns the name (its GUI waits for it). Why:
  GTK 3 exits with `_exit(1)` ("Error reading events from display: Broken pipe") when the compositor closes its
  Wayland connection; on the Ubuntu 26.04 VM mutter closed LinVPN's (and no other app's) connection 0.5 s after a
  gnome-remote-desktop RDP session dropped, without the log line mutter writes for a client that is too slow or made
  a protocol error. The trigger is still open; the supervisor keeps the tray and the secret agent alive whatever it is.
- **A package installed outside the app** (`sudo apt-get install ./linvpn_*.deb`, the Software app; also a
  downgrade): the `.deb`'s `postinst` (`configure`) writes the installed version (`dpkg-query`) to
  `/run/linvpn/package-version` (folder 0755, file 0644, temp file and `mv`; never failing the install). The
  installed LinVPN (`/usr/bin/linvpn`, not the sandbox) reads it every 3 s (`pure/package_watch.rs`,
  `lin/package_watch.rs`, started from the app's `platform::linux::configure_app`). Once it holds a plain X.Y.Z
  other than the running version and other than what it held when the watch began (no restart loop for a package
  whose binary reports another version), the app takes the updater's path (`LinUpdater::restart_after_package`:
  the notice `ok <version>`, `linvpn --after-update` detached) and quits through `commands::terminate`: no quit
  questions, nothing disconnected (the tunnels outlive the app, as with "Quit, Keep Them Running"). It waits while
  the editor has unsaved changes and while the in-app update installs (`UpdateController::is_installing`, set from
  "Download and Install" until the app quits: that update relaunches by itself, so there is never a second
  relaunch). A missing marker (a fresh boot clears `/run`; an older package) is no change. `prerm remove` deletes
  the marker.
- **The `.deb`** is built by `scripts/build-deb.sh` with `dpkg-deb` (not Tauri's bundler: `tauri build
  --no-bundle`), one architecture per run, on Ubuntu 24.04 in CI (so it runs on Ubuntu 24.04+ and Debian 13). Its
  files: `/usr/bin/linvpn`, `/usr/libexec/linvpn/linvpn-install-update`, `/usr/share/applications/linvpn.desktop`
  (`.ovpn`, `.sstp`, `.macvpncatalog`; not `.conf`, which is `text/plain` on Linux), the MIME XML
  `/usr/share/mime/packages/linvpn.xml` (`application/x-linvpn-sstp`, `application/x-macvpn-catalog`; `.ovpn` is
  shared-mime-info's `application/x-openvpn-profile`), the polkit action
  `/usr/share/polkit-1/actions/local.linvpn.update.policy`, the hicolor icons (32, 128, 256), and
  `/usr/share/doc/linvpn/{copyright,THIRD-PARTY-NOTICES.txt}`; since L-b also `/usr/libexec/linvpn/linvpn-logd`
  with `/usr/lib/systemd/system/linvpn-logd.{socket,@.service}`, `/usr/libexec/linvpn/linvpn-xfrmd` with
  `/usr/lib/systemd/system/linvpn-xfrmd.{socket,@.service}`, LinVPN's NetworkManager OpenVPN service
  (`/usr/lib/linvpn/nm-openvpn-service{,-openvpn-helper}`, `/usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name`,
  `/usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf`) and its GPL source in `/usr/share/linvpn/source/`
  (see [LinVPN's OpenVPN service](#linvpns-networkmanager-openvpn-service)); the list is pinned in
  `scripts/bundle-baseline/linvpn-deb-files.txt`. `Depends`: what `dpkg-shlibdeps` finds over all six programs,
  plus `network-manager`, `network-manager-openvpn (>= 1.10)` (the `nm-openvpn` user and chroot LinVPN's service
  uses), `openvpn`, `systemd`, `curl`, `pkexec | policykit-1` and a StatusNotifierItem host
  (`gnome-shell-extension-appindicator | plasma-workspace`); `Recommends`: the NetworkManager VPN plugins (OpenVPN,
  L2TP, strongSwan, SSTP, vpnc). **Exactly two maintainer scripts** (L-b, resolved point 12; L-a had none):
  `postinst` (`configure`: `systemctl daemon-reload` and `systemctl enable --now` of `linvpn-logd.socket` and
  `linvpn-xfrmd.socket` when `/run/systemd/system` exists; the installed version into `/run/linvpn/package-version`)
  and `prerm` (`remove`: `systemctl disable --now` of both sockets; the version record removed), checked byte for
  byte by the gate, which refuses any other; dpkg's file triggers (shared-mime-info, desktop-file-utils, the icon
  cache, NetworkManager's VPN directory, dbus-daemon's `system.d`) do the rest. Further gates: the three
  version numbers, no debug-only markers, SQLCipher on the vendored OpenSSL linked statically (no `libssl`,
  `libcrypto` or `libsqlite3` among the NEEDED libraries), the root step and the two readers linking only libc, libm,
  libgcc_s and the loader, every file `root:root`. The user's data and autostart file stay on removal (the user guide says how to
  remove them).

### The NetworkManager engine

LinVPN drives NetworkManager over the system bus as the desktop user; it runs no VPN program itself (spec decision
3). One `lin::nm::engine::Engine` per process owns the state; its trait implementations are split by file as
WinVPN's are (resolved point 1):

- **The trait split** (WinVPN 2c's): `HelperClient` (`helper_impl.rs`) runs OpenVPN, WireGuard, IKEv2
  (`VPNKind::Strongswan`) and SSTP: each `up` plans the config it is given and activates it. `NativeController` +
  `NativeProfiles` (`native_impl.rs`) run L2TP and Cisco IPsec and the system VPNs. `AuthStateReader` (`auth.rs`)
  reports the agent's pending CRV1 challenge; `NativeSupport` (`support_impl.rs`) gives `nm_plan`'s Linux reasons
  and the editor's notes for every kind at every reload (pure and cached: no D-Bus call). Managed L2TP / Cisco have
  no NM profile: `NativeProfiles::install` writes a secret-free plan record `$XDG_DATA_HOME/LinVPN/nm/<UUID>.json`
  (`plan_store.rs`: dir 0700, file 0600, strict keys, never through a symlink), `needs_approval() = false`,
  `PlatformNotes::no_install_step` (the button reads **Save**), `managed_service_id = linvpn-<UUID>`; `start` builds
  the volatile connection from the record. Cisco runs on Linux (vpnc), unlike Windows.
- **`macvpn_core::nm_plan`** (pure, every OS): `plan(Input)` → `NmPlan { settings, secrets, files, summary, warnings,
  iface, … }` or `Unsupported { reasons, invalid_config }`, one module per backend (`wireguard`, `openvpn`, `l2tp`,
  `vpnc`, `strongswan`, `sstp`, `dns`). `settings` (a neutral value tree, `lin::nm::value` turns it into `a{sa{sv}}`)
  never holds a secret: secrets are `SecretItem`s the agent answers, inline certificates and keys `RuntimeFile`s.
  IKEv2 client certificates imported in the app (G4, `Input::client_cert` = `ImportedCert`): a key-signing config
  without `certs` gets `usercert` / `userkey` = `<runtime dir>/client-cert.pem` / `client-key.pem`, written from the
  vault's PEM `ClientCert` (0600, removed with the runtime dir at down); its passphrase stays the `password` secret
  (`KeyPassword`). charon-nm loads `usercert` as X.509 only, so a PKCS#12 file is converted with the system's
  `/usr/bin/openssl pkcs12` (`lin::pkcs12`: password on fd 3, never argv/env; stdin/stdout, capped, 20 s; `-legacy`
  retried; the key re-encrypted with the same password; output checked by `client_cert::import`): at import
  (`ConnectionsModel::set_pkcs12_converter`, the password asked by the editor, the vault keeps PEM) and, for one
  restored from a Mac, at connect into the runtime files only. `openssl` is a `.deb` Depends. The row's reason and the editor's notes get only the imported
  form (`NativeSupport::{unsupported_reason,editor_notes}_with_cert`, read by app-core from the vault); the editor's
  Certificates section reads `certs` / `cacerts` from `$XDG_DATA_HOME/LinVPN/swanctl` (`platform::swanctl_folder`).
  Every plan has `connection.permissions = ["user:<name>"]`, `autoconnect = false`, the derived UUID, and for
  plugin kinds `vpn.persistent = false` (LinVPN's planner alone reconnects). The plugins' `vpn.data` keys are pinned
  against the Ubuntu 26.04 versions (named in each module); a key a plugin does not know fails its connection.
- **The derived UUID** (`nm_plan::names`, resolved point 3): `nm_uuid = UUIDv8(SHA-256("linvpn-nm-v1\0" ‖ uid as u32
  LE ‖ connection UUID bytes)[..16])`. A stale volatile connection of a crashed run is found and deleted before the
  next add, and `linvpn-logd` proves ownership from it without state. The interface names are `lvw` / `lvo` + the
  first 4 bytes of SHA-256(connection UUID) in hex (11 characters).
- **Activation** (`Engine::activate`, `lin/nm/client.rs`): plan → resolve the secrets from the prepared `Secrets`
  (IKEv2: a PSK under `CHARON_NM_PSK_MIN` = 20 bytes is refused here, charon-nm would refuse it opaquely) → the
  non-interactive polkit pre-check (`lin/nm/polkit.rs`: `CheckAuthorization` with flags 0 for
  `settings.modify.own` and `network-control`, subject = our system-bus name; only "authorized, no challenge" for
  both proceeds, anything else is the "may not change … without asking for a password" refusal; R1, R9) → delete a
  leftover of the same derived UUID → write the runtime files → announce the expected secrets to the agent →
  `AddAndActivateConnection2(settings, "/", "/", {persist: volatile})`, never with the interactive-authorization
  flag. NM deletes the profile on deactivation. The activation is **not** bound to LinVPN's process (no
  `bind-activation`): as on macOS and Windows, "Quit, Keep Them Running" and a crash leave the tunnel up, and the
  user can still take it down from LinVPN's next launch or GNOME's network menu (the profile vanishes then). A
  normal quit disconnects through app-core's quit flow (`down` → `Engine::deactivate`). `nmcli connection import`
  is never used.
- **Adoption at launch** (`Engine::adopt`, once per process: `prepare_engine` at setup, or the first start, stop or
  status, whichever comes first): each run's directory holds a run record (`.linvpn-run.json`: the connection id,
  kind, interface name, keepalive and connect time; never a secret; parsed strictly, our own 0600 file, no
  symlink). A record is adopted only when its directory is the derived UUID of its id, NM reports that UUID
  active, and its profile is volatile with `permissions = ["user:<name>"]` (R9). The run gets its log, journal pump
  and an agent expectation without secrets (a dynamic challenge still reaches the app) and reports `connected`, so
  app-core's adoption, liveness, traffic and reconnect take it over. Then the runtime dir is swept, keeping the
  directories of NM's active connections (OpenVPN may read its files again on a restart); without NM's answer
  nothing is swept. A watcher on NM's `VpnStateChanged` keeps each run's facts
  (connected, reconnecting since, the failure reason) and writes NM's reason with the words `failure_reason.rs`
  already matches (`AUTH_FAILED: …`, `Connection timed out (NetworkManager)`), so failure notices need no app-core
  change.
- **The runtime dir** (`lin/nm/files.rs`): `$XDG_RUNTIME_DIR/linvpn/nm/<nm uuid>`; `linvpn`, `nm` and the run's
  directory must be real directories of ours (never a symlink), tightened to 0700; each file is created
  `O_CREAT|O_EXCL|O_NOFOLLOW` 0600 under one plain path component; the guard removes the directory when the run is
  stopped or ends (a quit that keeps the tunnel leaves it for the next launch's adoption). Without a valid
  `$XDG_RUNTIME_DIR` every connect is refused.

### The secret agent

`lin/nm/agent.rs` registers `org.freedesktop.NetworkManager.SecretAgent` (identifier `local.linvpn.agent`, VPN
hints capability) at first use and again when NetworkManager restarts.

- **The sender rule:** a `GetSecrets` / `CancelGetSecrets` is answered only when its sender is the current unique
  name of `org.freedesktop.NetworkManager` (followed through `NameOwnerChanged`, so an NM restart replaces it), and only for a connection
  UUID the engine announced with `Agent::expect` (its own activation, or a system VPN start with stored secrets).
  Anything else gets "no secrets" (R9). The agent never saves or deletes secrets (`SaveSecrets` / `DeleteSecrets`
  do nothing).
- **The answers:** static secrets (password, PSK, key password, WireGuard private and preshared keys) from the
  expectation, built from `Zeroizing` values and dropped after the reply; nothing is logged. The static challenge
  needs no key of its own: `password` is already app-core's packed `SCRV1:…` / `password+code`. A dynamic
  challenge (CRV1: the `x-dynamic-challenge[-echo]:challenge-response` hint, the text from `x-vpn-message:`, at
  most 512 characters) becomes a pending `AuthUIState` that `AuthStateReader` reports; `HelperClient::respond(id,
  Crv1, code)` answers it, ended by a cancel, `CancelGetSecrets` or `CRV1_DEADLINE_SECS` (110 s). Web
  authentication is not offered on Linux (`WebauthAck` → "No code is being asked for.").
- **Secret mode** (resolved point 8): `pure::nm::agent::DEFAULT_SECRET_MODE = Agent` (every secret flag 1,
  agent-owned; branch A of spike L0-4). `Inline` (branch B: the static secrets put into the volatile in-memory
  connection just before the add, flags 0; CRV1 stays with the agent) is implemented and tested but not the
  default. Both constants are marked `// L0-4:` until spike L0-4 part 2 confirms them on the installed `.deb`.

### LinVPN's NetworkManager OpenVPN service

Stock NM ignores a `redirect-gateway` the server pushes (the `--up` helper never sends `NEVER_DEFAULT`), so LinVPN
ships its own build of upstream NetworkManager-openvpn **1.12.5** plus `packaging/linux/nm-linvpn-openvpn/
linvpn-nm-openvpn.patch` (decision 8, resolved point 6; `packaging/linux/nm-linvpn-openvpn/README.md`):

- **Build:** `scripts/build-nm-linvpn-openvpn.sh` downloads the tarball, checks it against
  `scripts/pins/nm-openvpn.sha256`, applies the patch and builds the service and its helper with upstream's
  autotools (`--libexecdir=/usr/lib/linvpn --without-gnome`); `scripts/test-build-nm-linvpn-openvpn.sh` checks the
  result. Installed next to the untouched stock plugin under its own service name
  `org.freedesktop.NetworkManager.linvpn-openvpn` (`nm-linvpn-openvpn-service.name`, no editor or auth dialog,
  upstream's D-Bus policy for the new name). It still runs OpenVPN as `nm-openvpn` in upstream's chroot.
- **The patch:** the helper's `--redirect-info` sends `NEVER_DEFAULT = false` for IPv4 (IPv6) exactly when OpenVPN
  2.7+ exports `route_redirect_gateway_ipv4` (`_ipv6`) as 1 or 2 (`block-local` routes as a plain full tunnel); the
  service passes `--redirect-info` when `openvpn --version` is ≥ 2.7, accepts four more `vpn.data` keys, each
  validated in C with the Rust side's character rules (`linvpn-redirect-gateway` flags, `linvpn-pull-filter` lines,
  `linvpn-route-nopull`, `linvpn-verb` 0–4, raising only), and starts OpenVPN with `--syslog
  linvpn-ovpn-<NM connection UUID>` so `linvpn-logd` can attribute its lines.
- **"Send all traffic over VPN"** (resolved point 4, `macvpn_core::openvpn_routing`, the editor's three-way control
  `OpenVpnRouting.svelte`, Linux only): stored in the config itself, so it syncs through backups, exports and
  catalogs and means the same to every OpenVPN (R10: no format change): **Always** = a `redirect-gateway def1` line
  (plus `ipv6` when the profile had it), **Never** = `pull-filter ignore "redirect-gateway"`, **Server decides** =
  neither. `nm_plan::openvpn` turns them into the `linvpn-*` keys and `never-default = no`. With OpenVPN < 2.7
  (`Caps::openvpn_push_visible = false`, read from `openvpn --version` as the user) "Server decides" acts as decision
  7: the profile's own `redirect-gateway` → full, else split; the editor and System Status' OpenVPN row say so.
- **The Linux OpenVPN tier** (`platform_reasons(TargetOs::Linux)`, [openvpn-directives.md](openvpn-directives.md#linux-linvpn)):
  69 names NM drops are RISKY "Ignored by NetworkManager on Linux"; the 8 refusals of L0-1 (`peer-fingerprint`,
  `verify-hash`, `remote-cert-ku`, `remote-cert-eku`, a route past the tunnel, an unflattenable `<connection>`, a
  `pull-filter` the service cannot pass, `compress stub*`/`migrate`) are `nm_plan` reasons (resolved point 5): the
  row is greyed, the start refused, the config stays valid for macOS and Windows.
- **The source obligation** (resolved point 13): the `.deb` ships the unmodified tarball, the patch and the README in
  `/usr/share/linvpn/source/`, and `/usr/share/doc/linvpn/copyright` has the GPL-2+ stanza for `/usr/lib/linvpn/nm-*`.
  LinVPN itself stays MIT (aggregation). Upstream security fixes and offering the patch upstream: `docs/RELEASING.md`.

### `linvpn-logd` and the Log tab

`linvpn-logd` (spec decision 6, resolved points 9 to 11) is the only way LinVPN reads the system journal:

- **The unit** (`packaging/linux/systemd/`): `linvpn-logd.socket` listens on `/run/linvpn-logd.sock` (0666,
  `Accept=yes`, at most 4 connections per source and 16 in all); `linvpn-logd@.service` runs one instance per
  connection with `DynamicUser=yes`, `SupplementaryGroups=systemd-journal`, no capabilities, `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX` (the caller's socket, the
  system bus for NetworkManager's read-only properties, the journal stream), a system-call filter and
  `RuntimeMaxSec=20`. **It is not root** (the spec's "the only root component" became "no root component" for logs).
- **One request, one answer** (`macvpn_core::logd`): `linvpn-logd-v1 <connection UUID> <since µs> <cursor or ->`;
  the caller's uid from `SO_PEERCRED` (none: no answer); the NM UUID derived from that uid and the named connection
  (`nm_plan::names::nm_uuid`), so a caller can only reach its own connections' UUIDs, also after NM deleted the
  volatile connection; `/usr/bin/journalctl` with fixed arguments (only validated UUIDs, numbers and a validated
  cursor, each its own argv element; environment cleared; `--after-cursor` *or* `--since`, never both: journalctl
  259 refuses the pair), its output capped and time-limited; lines `L <µs>
  <nm|openvpn|plugin:<ident>> <escaped text>`, an optional `W` (withheld), `C <cursor>`, `E`.
- **The attribution rule** (`logd::select`, fail closed): NetworkManager's lines with `NM_CONNECTION=<nm_uuid>` (NM
  1.54.3 writes it; a `MESSAGE` fallback covers other versions); OpenVPN's lines with `SYSLOG_IDENTIFIER =
  linvpn-ovpn-<nm_uuid>`; the plugins' lines (`charon-nm`, `nm-l2tp-service`, `xl2tpd`, `pppd`, `nm-sstp-service`,
  `sstpc`, `nm-vpnc-service`, `vpnc`, …) only while the caller's connection was active (its own `starting <plugin>`
  line, until its end) and no other VPN connection may have been; otherwise they are withheld (`W`). Who was
  active when (security review M1, reworked after lab run 2): NetworkManager's `VPN`-domain lines since its last
  start (activations; the warning-level lines NM 1.54.3's `nm-vpn-connection.c` writes only as a connection fails:
  `dbus: failure: <reason> (<n>)`, `failed to connect: '…'`, `connect: failed to connect interactively: '…'`, `did
  not receive valid IP config information`, `connect timeout exceeded`, the four secrets failures, `starting: timed
  out …` / `starting: failure to start VPN service: …`; NM logs nothing at its default level when a VPN finishes
  normally) and logd's own *readings*: at every request logd reads NM's `ActiveConnections` (each `Vpn`, `State`,
  `Uuid`; any doubt: no reading) between two clock readings and, when it says something new, records it in its own
  journal at priority notice (`linvpn-logd-vpns-v1 <before µs> <after µs> <uuids>`, trusted by
  `_SYSTEMD_UNIT=linvpn-logd@….service`). A connection active since before a reading began that the reading did not
  list ended by the reading's end; a reading that lists a connection voids an earlier end line of it (no activation
  in between) and opens it back to its last known inactive moment when its activation line is missing; anything else
  stays active. The engine asks logd once right before each activation (`logd_client::mark`, at most 3 s), so
  earlier connections that are gone are recorded as gone before the new one starts. **Residual risk:** a plugin's
  lines journald stamps after NM already dropped that connection (a dying pppd's last lines, journald's delay) can
  reach a caller whose connection is then the only one active; a plugin that reports `Failure` yet keeps its
  connection up and ends it before any reading would have its lines in between attributed the same way; a stopped
  logd, a bus failure or a lost reading only withholds more. Since the sender
  writes `SYSLOG_IDENTIFIER`, `MESSAGE` and `NM_CONNECTION` itself, a line counts only when journald's trusted
  fields name the expected process: NM `_SYSTEMD_UNIT=NetworkManager.service` and `_UID=0`, OpenVPN `_COMM=openvpn`
  and root or `nm-openvpn`, each plugin its own process names and root.
- **The app side** (`lin/nm/logd_client.rs`, `lin/nm/connlog.rs`): the client checks that root owns the socket,
  reads at most `MAX_RESPONSE` bytes within its timeout and parses strictly. Each connection has one log file
  `$XDG_DATA_HOME/LinVPN/logs/<UUID>.log` (dir 0700, file 0600, never through a symlink, capped at 5 MiB by
  dropping its oldest half): the engine's own lines (connect steps, NM's state reasons, in debug mode the plan's
  summary, warnings and effective `vpn.data` with protected keys as `***`) and the *journal pump*'s, which asks
  logd every poll while the run lives and for a linger after it ends, prefixing each line with its journal time
  (`YYYY-MM-DD HH:MM:SS`, so the time filter works) and its source tag, masked with the connection's `Masker`.
  `HelperClient::log_path` / `NativeController::log_source` + `FileLogSource`, "Clear Log…" (`clear_file`, the
  journal untouched) and the time filter work unchanged. Without the socket the log says logd is not installed.

### `linvpn-xfrmd` (IKEv2 traffic and liveness)

strongSwan 6's charon-nm (Ubuntu 26.04: 6.0.4) creates an XFRM interface per connection (`nm-xfrm-<id>`, handed to
NM as the tunnel device, holding the virtual IP; its sysfs counters are user-readable), and LinVPN counts that
interface when there is one (see Traffic below). An older charon-nm creates no interface: IKEv2 is policy-based XFRM,
and the only byte counters of such a tunnel are its IPsec SAs' (`struct xfrm_lifetime_cur`). `linvpn-xfrmd` stays in
the package for those systems. The kernel answers an XFRM dump, even a
read-only one, only to `CAP_NET_ADMIN` in the host's user namespace, so `linvpn-xfrmd` reads them for the user:

- **A service of its own**, not a second query of `linvpn-logd`: it needs what logd must never have (the host's
  network namespace, since XFRM state is per namespace and logd runs with `PrivateNetwork`; `CAP_NET_ADMIN`;
  `AF_NETLINK`) and logd needs what this one must never have (the `systemd-journal` group). Both read NetworkManager's
  properties over the system bus.
- **The unit** (`packaging/linux/systemd/`): `linvpn-xfrmd.socket` listens on `/run/linvpn-xfrmd.sock` (0666,
  `Accept=yes`, at most 4 connections per source and 16 in all); `linvpn-xfrmd@.service` runs one instance per
  connection with `DynamicUser=yes`, `AmbientCapabilities=CAP_NET_ADMIN` and `CapabilityBoundingSet=CAP_NET_ADMIN`
  (nothing else), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `IPAddressDeny=any`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`,
  `RestrictNamespaces`, a system-call filter (`@system-service` without `@privileged @resources`) and
  `RuntimeMaxSec=20`; no `PrivateNetwork` (the host's XFRM state is the one to read) and no `PrivateUsers` (the
  capability must count in the host's user namespace). **It is not root.**
- **One request, one answer** (`macvpn_core::xfrmd`): `linvpn-xfrmd-v1 linvpn <connection id>` or
  `linvpn-xfrmd-v1 system <NM UUID>`, answered `T <rx> <tx>` or `N` (refused, not found, no SA, any error: the same
  `N`). The caller's uid from `SO_PEERCRED` (none: no answer).
- **Ownership** (`xfrmd::authorize`, before any netlink dump): NM's active connections from the system bus (read-only
  properties of `Connection.Active`, `VPN.Connection`, `IP4Config`, `IP6Config`, which NM's D-Bus policy lets every
  user read). A `linvpn` target's NM UUID is derived from the caller's uid and the connection id
  (`nm_plan::names::nm_uuid`, as logd does): a caller only reaches its own LinVPN connections. A `system` target
  counts only when NM shows the service the profile's settings (`GetSettings`) and they are a strongSwan VPN **for
  every user** (empty `connection.permissions`): NM hides a user-restricted profile from the service's dynamic user
  and exposes no "activated by" uid, so whose it is cannot be decided safely, and such IKEv2 system VPNs show no
  traffic. (A system-wide profile's counters are what every local user can already read for the interface-based
  kinds in `/sys/class/net/*/statistics`.) The connection must be an activated NM VPN (`Type` `vpn`, state and VPN
  state activated) with an address, and no other active connection may hold any of its addresses (NM's own
  `loopback` connection excepted: charon-nm installs the virtual IP on `lo`, and NM 1.54 shows it there too).
- **Which SAs** (`xfrmd::counters`): one `XFRM_MSG_GETPOLICY` and one `XFRM_MSG_GETSA` dump (bare headers built from
  constants: nothing the caller sent reaches the netlink socket; never a write). The policies whose selector is
  exactly the connection's NM address (outbound: source /32 or /128; inbound: destination) give `(reqid, tunnel
  endpoint, protocol)` keys from their templates (reqid 0, "any", never); the ESP and AH SAs with those keys are
  summed: outbound `tx`, inbound `rx` (a rekey's old and new SA both). Without an SA in each direction: `N`.
- **The parser** (`xfrmd::DumpParser`): every netlink and attribute length checked against its container, the
  datagram's real length (`MSG_TRUNC`) checked against the buffer, only the kernel's datagrams (`nl_pid` 0), the
  sequence number, the message type, kernel errors (`NLMSG_ERROR`, a negative `NLMSG_DONE`) and at most 16 384
  entries; the SAs' key attributes are skipped, never read, and each receive buffer is wiped after parsing. The
  offsets are Linux's 64-bit layout (`struct xfrm_usersa_info` 224 bytes; checked against `<linux/xfrm.h>`).
- **The app side** (`lin/nm/xfrmd_client.rs`): the client checks that root owns the socket, reads at most
  `MAX_RESPONSE` bytes within 3 s and parses strictly; a reading is reused for 500 ms so one status poll's traffic
  and liveness questions start one instance.
- **Security notes for the L-b plan's Task 31 review:** the capability allows XFRM *writes* too, and no system-call
  filter can tell netlink message types apart: the guarantee that it only reads is the code (`dump_request` builds
  the only two messages ever sent, `Netlink::dump` the only sender). The dynamic user can call any NM method NM's
  D-Bus policy allows every user, but NM's polkit rules refuse a user outside the active session; the code calls
  only `Get` and `GetSettings`. The answer is two sums; the request is never logged (`uid=<n> answer=<T|N>`).
  What only the lab can confirm: the dump under the unit's sandbox (`lab_a_real_xfrm_dump_parses` with `sudo -E`,
  and the checklist's live items), charon-nm's policies carrying the NM address as selector, and NM putting
  charon-nm's virtual IP into the VPN connection's `Ip4Config`.

### The class-based PPP route (`90-linvpn-route`)

Without "Send all traffic", Windows (RAS without the remote default gateway) and macOS' PPP route the network of the
class of the assigned address (A `/8`, B `/16`, C `/24`; `172.16.x.x` is class B: `172.16.0.0/16`) through the
tunnel, besides the routes the server sends; NetworkManager's L2TP and SSTP plugins set never-default and route only
the peer, so the network behind the server was unreachable. NetworkManager offers no user-level way to add a route
once the address is known: a VPN active connection has no Reapply (its routes come from the applied connection copied
at activation, `nm-vpn-connection.c`), `Device.Reapply` on the ppp interface fails because `NMDevicePpp` cannot
generate a connection for an external interface (it is never "connected (externally)"), and neither plugin has a
route or prefix option. So:

- **The mark** (`nm_plan::classful_route_section`): an L2TP (`send_all_traffic` off) or SSTP (`route_all = no`)
  plan carries `user.data` `linvpn.classful = 1`. "Always" (all traffic) carries none; these kinds have no per-entry
  routes. Cisco/vpnc carries none: the server's split networks decide, as on macOS.
- **The script** (`packaging/linux/nm-dispatcher/90-linvpn-route`, POSIX sh, installed root:root 0755 into NM's
  packaged folder `/usr/lib/NetworkManager/dispatcher.d/`, which NM 1.54 reads besides `/etc`; NM runs only root-owned
  scripts that group and others cannot write). It acts only on `vpn-up` with `CONNECTION_USER_LINVPN__CLASSFUL=1`
  (NM's dispatcher encodes the profile's `user.data` keys into `CONNECTION_USER_*` itself, from the activated
  connection; the dispatcher's D-Bus API is NM's only, so the environment is NM's, not the user's; reading the
  profile again with `nmcli` would add a second parser and a race with the volatile profile's removal for the same
  data). `VPN_IP_IFACE` must be `ppp` plus 1–4 digits and exist in `/sys/class/net`; `VPN_IP4_ADDRESS_0`'s address a
  plain dotted quad (no leading zeros, octets ≤ 255) of class A (not 0 or 127), B or C. It adds nothing when the main
  table has a route to exactly that network through another interface (the local network: equal prefix, ours would
  win by metric; a more specific local route still wins by length) or when a default route's gateway is inside it.
  Then `ip -4 route replace <net> dev <ppp> metric 50` (NM's VPN metric), one `logger -t linvpn-route` line, exit 0
  always. The VPN server stays outside the tunnel: NM routes the VPN gateway as a `/32` through the parent device
  (`L3CD_TYPE_GW_EXTERN`), more specific than any class route. The route goes when the kernel removes the ppp
  interface; nothing is done on `vpn-down`. `PATH` is fixed first, no `eval`, globbing off where words are split.
- **Security:** the script runs as root, but grants nothing new: the owner of a private NM VPN profile may already
  set any `ipv4.routes` through its tunnel without an administrator (`settings.modify.own`), and the mark only asks
  for one route through that same connection's own PPP interface. Its inputs are NM's environment, each validated
  before use. Tests: `scripts/test-linvpn-route.sh` (a copy with fake `ip`/`logger` and interface folder; `/bin/sh`
  and dash), `scripts/test-build-deb.sh` (staged 0755, in the file baseline, packaged byte for byte), the nm_plan
  tests.

### System VPNs, status, traffic and liveness

- **System VPNs** (`lin/nm/system_vpns.rs`, `pure::nm::system_vpn`, resolved point 14): NM's `vpn` and `wireguard`
  profiles whose `connection.permissions` is empty or holds `user:<name>`, never a LinVPN-made one (a derived UUID
  or a `linvpn-` id); id = the NM UUID, name = `connection.id`, labels `L2TP`, `Cisco IPsec`, `IKEv2`,
  `WireGuard (app)`, `OpenVPN (app)`, else `VPN`. Read-only: `start` is `ActivateConnection` of the profile (after
  announcing stored L2TP / Cisco secrets to the agent for that activation only), `stop` deactivates it; LinVPN
  never edits or deletes them. `watch` follows NM's profile and active-connection signals (`SystemVpnWatch`).
- **Status:** the runs from NM's active connections and `VpnStateChanged` (`pure::nm::state`); a failed or vanished
  run leaves `status` only after its reason is in the log (a 3 s grace).
- **Traffic** (resolved point 16, `lin/nm/sysfs.rs`, `pure::nm::iface`): `/sys/class/net/<if>/statistics/{rx,tx}_bytes`
  of a *tunnel* interface only (`type` 65534 or 512), every name checked before a path is built: WireGuard and
  OpenVPN by the name LinVPN chose, PPP kinds and system VPNs by the interface holding the VPN's `Ip4Config` address
  (`getifaddrs`). IKEv2 reads charon-nm's XFRM interface the same way (a tunnel interface named `nm-xfrm-*` holding
  the virtual IP; `pure::nm::iface::is_charon_nm_xfrm`; the address is on `lo` too, which is no tunnel); without one
  (an older, policy-based charon-nm) it reads its IPsec SAs' counters from
  [`linvpn-xfrmd`](#linvpn-xfrmd-ikev2-traffic-and-liveness) (`lin/nm/xfrmd_client.rs`; LinVPN's runs as
  `linvpn <connection id>`, system VPNs as `system <NM UUID>`); no answer is no traffic, as before. A rekey's old SA
  leaving makes the sum drop, which `TrafficBook` takes as a restart: the total can overcount by the new SA's
  bytes at the previous reading (one poll's worth, once per rekey).
- **Liveness** (resolved point 15): `Liveness::Counters { rx, tx, keepalive }` (Linux, in-process only; its wire form
  is never sent by a root layer or service): WireGuard always, OpenVPN while NM's VPN state is not "reconnecting
  after having been activated" (then `Liveness::OpenVpn { reconnecting_since }`), IKEv2 from its XFRM interface's
  counters, else its SA counters (`linvpn-xfrmd`), with `keepalive` 0: IKE's DPD and NAT-T keepalives travel outside
  the ESP SAs and the interface, so an idle IKEv2
  tunnel's counters stay still and it is never dead, while one that keeps sending into SAs that bring nothing back
  for 200 s is (the app watches `Strongswan` liveness on Linux only). Pure one-way traffic with no answer at all for
  200 s would also count as dead; TCP's acknowledgements and DNS answers make that practically impossible. app-core's rule: dead when tx grew
  and rx did not change for `COUNTER_SILENCE` = 200 s (spike L0-3: past WireGuard's 180 s session expiry); after a
  live switch `SWITCH_SILENCE` with `KEEPALIVE_BYTES` × keepalives as for WireGuard; an idle tunnel is never dead.
- **The network watcher** (`lin/net.rs`, `pure::net`): `NetworkProbe::snapshot` reads NM's devices (each call
  bounded), keeps Ethernet and Wi-Fi only (never VPN, WireGuard, tun, PPP, bridge or veth, so LinVPN's own tunnels
  are never the network), takes the gateway of the activated device with the best default route, its MAC from
  `/proc/net/arp` and the active access point's SSID; `watch` follows NM's change signals. Sleep and wake come from
  logind's `PrepareForSleep` (L-a).

### PackageKit, System Status and DNS

- **System Status' NetworkManager rows** (`lin/nm/plugins.rs`, `pure::nm::plugins`, `SetupReport::nm` = `NmReport`):
  NetworkManager (its version over D-Bus; at least 1.36 for `AddAndActivateConnection2`), WireGuard (built in from
  1.16), OpenVPN (LinVPN's service files present, the stock plugin's `.name`, `openvpn --version`: "follows the
  server" from 2.7), L2TP, IKEv2 (plus the EAP-MSCHAPv2 plugin of `libcharon-extauth-plugins` and the EAP-Identity plugin of
  `libcharon-extra-plugins`: without it charon-nm answers a server's `eap_id = %any` request with EAP-NAK), Cisco, SSTP (their
  `.name` files under `/usr/lib/NetworkManager/VPN` and `/etc/NetworkManager/VPN`). Read-only, as the user.
  `SetupReport::missing_engine` names a kind's plugin ("Not installed: NetworkManager SSTP plugin"); `needs_service`
  is false for every kind (no service); a system VPN needs only NetworkManager.
- **PackageKit** (`lin/nm/packagekit.rs`, resolved point 17): **Install** on a row asks PackageKit's system D-Bus API
  for exactly that kind's packages from the fixed list `pure::nm::plugins::PACKAGES` (`network-manager-openvpn`,
  `-l2tp`, `-strongswan`, `libcharon-extauth-plugins`, `libcharon-extra-plugins`, `-vpnc`, `-sstp`; any other name is refused before the first
  call): `Resolve` (not installed, newest, this architecture; a name not found is looked up among the installed
  ones), then `InstallPackages` with `ONLY_TRUSTED`. PackageKit itself asks polkit
  (`org.freedesktop.packagekit.package-install`), so the password prompt is the system's; LinVPN never runs
  `pkexec` or `apt` for plugins.
- **DNS** (`nm_plan::dns`): no DNS manager. NM and systemd-resolved apply and restore it. A split tunnel uses the
  connection's DNS only for its domains (routing-only `~domain` entries); a full tunnel takes every query (`~.`) with
  a negative `dns-priority`. Pushed DNS (OpenVPN's `dhcp-option`, PPP, IKEv2's configuration payload) is applied by
  NM itself; SSTP's `peer_dns = no` → `ignore-auto-dns`.
- **Tested where:** `nm_plan`, `logd`, `openvpn_routing`, the Linux tier, `pure::nm` and `pure::net` on every OS;
  the NM client, the agent, the engine, the system VPNs, PackageKit, sysfs and logd against fakes on a private bus
  (`dbus-run-session`) on the VM and in CI; the smoke run's NetworkManager rows (`scripts/smoke/nm.js`) over the
  sandbox's stand-ins; real connections against the VPN lab (the L-b plan's Tasks 26–28, run at the maintainer's
  checkpoints) and the "LinVPN (L-b)" section of `docs/manual-test-checklist.md`.

## The 2.0 features

Four user-facing features from the same code on both OSes (the plan: `superpowers/plans/2026-10-25-features-2-0.md`),
plus the macOS DNS manager, the log caps and the engine updates of the 2b fixes
(`superpowers/plans/2026-10-22-winvpn-2b-service-openvpn-wireguard.md`, the "As built" notes of 2026-10-24). The
pure decisions live in core and app-core with their tests; the platform crates only probe and watch; the app wires
them. None of it adds an OS `cfg` or `unsafe` outside the allowed places, a view-model field to the 1.4 JSON, or an
entry to the backup.

**Preferences** (new keys of the existing `PreferenceStore`: `CFPreferences` domain `local.macvpn` on macOS,
`preferences.json` on Windows; none of them is in the backup, `BackupPreferences` is frozen):
`appearance` (`system` | `light` | `dark`, anything else = system), `connectionNotifications` (bool, default on),
`autoReconnectOff` (the sorted, comma-separated UUIDs of the connections switched off; default on needs no entry),
`lastBrewUpdate` (macOS: the time of the last successful `brew update`).

### Appearance

- `macvpn_app_core::appearance`: `Appearance::{System, Light, Dark}`, `APPEARANCE_KEY`, strict `parse`, `load` /
  `store`; the view model's `appearance` field (absent until the app sets it).
- `app/src-tauri/src/appearance.rs`: `apply(&AppHandle, Appearance)` calls Tauri's `AppHandle::set_theme` (macOS:
  `NSApp.appearance`, which the popover, every window, the alerts and the WKWebViews follow; Windows: the event
  loop's preferred theme plus a theme message to every window, which switches the title bar and WebView2's
  `PreferredColorScheme`); `None` follows the system. A small plugin (`on_window_ready`, like `corners.rs`) sets the
  theme on every new window. It runs in `.setup()` before `tray::create_menu_window`, and at once from the
  `set_appearance` command. No platform trait, no `cfg`.
- The web side has one mechanism: `app/ui/src/app.css`'s single `@media (prefers-color-scheme: dark)` block, which
  the native theme drives (`app/ui/src/lib/appearance.test.ts` pins it). Windows' own dialogs (COM file dialogs,
  message boxes, UAC) follow Windows' theme; the tray tint stays the taskbar's.

### The Log tab's time filter and "Clear Log…"

- **Time filter:** app-core `logs::line_time` reads a line's local time from the formats the logs contain (a
  `YYYY-MM-DD HH:MM:SS` / `…T…` line start: OpenVPN, `log stream`; wireguard-go's `LEVEL: (iface) YYYY/MM/DD
  HH:MM:SS`; pppd's `Www Mmm d HH:MM:SS YYYY` after an optional `[pppd] `; any `YYYY-MM-DD HH:MM:SS` in a `═══ … ═══`
  header). `LogBuffer` gives a line without one the previous line's time; each `LogLineView` carries it (`time`,
  wall-clock seconds without a time zone, `logs::civil_seconds`). The UI (`logview.ts`) turns the presets and the
  `datetime-local` fields into a `TimeRange` the same way and filters with it; "Copy" sends it (`log_copy`).
- **Clear Log…** (`log_clear` → `logs::clear_log`): `HelperClient::clear_log` for a helper kind, else
  `NativeController::clear_log` (`Ok(false)`: no platform log, so the debug collection is cleared). The first line is
  `core::log::cleared_note`. macOS: the app truncates `/var/log/macvpn/<id>.log` and `.1` itself
  (`core::log::clear_file`: `O_NOFOLLOW`, a regular file of the user only, in place, so the root layer's
  `O_APPEND` writers and the in-place rolling go on); no root-layer change (root layer stays 9). WinVPN: the
  service's `clear-log` and the RAS logs (see above). The view then subscribes again.

### Failure reasons and connection notices

- `macvpn_app_core::failure_reason`: `classify(lines) -> FailureKind` (the last log line that matches a fixed
  substring list: OpenVPN, strongSwan, WinVPN's RAS `Windows error <code>:` lines) and `plain(kind)`, one fixed,
  localized sentence per kind that quotes nothing (lock-screen safe). `worth_retrying` is false for `AuthFailed`
  and `CertificateProblem`. The input is the last 256 KiB of the connection's log through
  `HelperClient::log_source` (the Log tab's source).
- `macvpn_app_core::connection_notices`: `Notice::{Connected, Reconnected, Dropped, Failed, NotReconnected,
  ReconnectFailed, DisconnectedHere}`, the tracker that turns manager state changes into notices (connecting /
  awaiting auth → connected; the planner's own connects become "reconnected"), and `content` / `content_named` →
  `NotificationContent` (titles name only the connection; a redacted name of a locked vault gets the generic title;
  the click's `user_info` is the connection key, routed to the Log tab by `notify::route_click` as before).
  `ENABLED_KEY` = `connectionNotifications`; the view model's `connectionNotifications` is absent until set.
- `app/src-tauri/src/notifications.rs`: `state_changed` (a manager state listener), `event` (the manager's
  `Dropped` / `Failed`), `notice` (the one posting path, behind the switch; prompts and catalog notices are not
  behind it), `classify(key)` through `platform::get().helper_client().log_source(&id)`. A failure of the
  planner's own attempt posts no "connection failed" (the `set_on_event` closure asks `is_attempting` first).
  Posting is the existing `Platform::notifier()` (macOS `UNUserNotificationCenter`, Windows WinRT toasts under
  `local.winvpn`); no `tauri-plugin-notification`.

### Missing engines

- platform-api `SetupReport::missing_engine(kind) -> Option<MissingEngine { name, installed }>` (label
  "Not installed: %@" / "Not ready: %@") and `unavailable_text(kind) -> Option<String>`, the one source of the
  row text, in order: the platform's own reason, `engine_missing` (WinVPN's service text), the later text,
  `missing_engine`. Names: macOS `Homebrew`, "Permissions (root scripts + sudoers)", `OpenVPN`, `WireGuard tools`
  (or `bash`), `strongSwan`, `sstp-client`; Windows `OpenVPN Community`, `WireGuard`, "WinVPN Service", "Windows
  VPN client"; Linux `NetworkManager` (not running or too old), then the kind's plugin ("NetworkManager L2TP plugin",
  "… strongSwan plugin", "… vpnc plugin", "… SSTP plugin", "LinVPN OpenVPN service", "WireGuard (NetworkManager)").
- app-core: `ViewModel::set_unavailable_kinds` (rows: `available = false`, switch disabled,
  `unavailableReason`, `setupLink` when System Status helps), the Connections window's "New" menu filtered
  (`kindsNote` when nothing is left) and the import gate (`connections::KindGate`, checked in
  `import_export::import_file` after `importer::prepare` decided the kind and before anything is saved). Team
  catalogs are not filtered. Before the first setup check (`AppState::setup_checked`) nothing is gated.
- The app: the gate closure in `main.rs` (the current report, so it follows every check);
  `system::recheck_if_incomplete` runs the check on a named thread (`macvpn-setup-recheck`) when the popover or
  the Connections window opens while a kind is unavailable, at most once per `RECHECK_INTERVAL` (60 s). UI: the
  "… – System Status" link in `MenuRow.svelte`, `folders/FolderTree.svelte` (a `span role="link"` inside the row
  button) and the detail header.

### Auto-reconnect

- core `netaddr::IpPrefix` (parse, `from_mask`, `contains`, `overlaps`, `is_default_route`) and
  `vpn_networks::VpnNetworks` (`from_config(kind, config)`: OpenVPN `route`, `route-ipv6`, `dhcp-option
  DNS|DNS6`, `dns server <n> address`; WireGuard `AllowedIPs`, `DNS`; `add_pushed` reads OpenVPN's `PUSH_REPLY`
  log lines). IKEv2, SSTP and the native kinds give no prefixes.
- platform-api `network`: `NetworkSnapshot { gateway: Option<Gateway { ip, mac, interface, ssid }>, connected }`,
  `NetworkProbe::{snapshot, watch}` (`Platform::network()`, default `NoNetworkProbe`: never reconnects) and
  `AppLifecycle::observe_sleep` (default no-op). Tunnel interfaces are never part of a snapshot.
- macOS (`platform-mac`): `net_parse` (pure parsers of `netstat -rn`, `scutil`, `ndp -n -a`, `ipconfig
  getsummary`, fixture-tested), `net_probe` (`MacNetworkProbe`: the default route's gateway, its MAC from the
  dynamic store's `ARPResolvedHardwareAddress` first and `arp -n` as fallback, so nothing is sent and no local
  network permission is asked; `ndp` for IPv6; the SSID where macOS tells it; `getifaddrs` for the connected
  subnets; every command with a 3 s timeout), `net_watch` (an `SCDynamicStore` watcher on
  `State:/Network/Global/IPv4|IPv6`, the run-loop-thread pattern of `sc_watch.rs`), and
  `NSWorkspaceWillSleepNotification` in `app_hooks.rs` next to the wake observer.
- Windows: winsys `net` (IP Helper: `GetIpForwardTable2`, `GetAdaptersAddresses`, `ResolveIpNetEntry2`,
  `NotifyIpInterfaceChange` / `NotifyRouteChange2`; WLAN: `wlanapi.dll` loaded from System32 at the call, so a
  Windows without WLAN still loads the app), platform-win `pure::net` (the physical adapters, the best default
  route, the connected prefixes; tested on every OS) and `win::net::WinNetwork`; the lifecycle window adds
  `PBT_APMSUSPEND` and `RegisterSuspendResumeNotification` (Modern Standby).
- Linux: `lin::net` over NetworkManager's devices (see [System VPNs, status, traffic and
  liveness](#system-vpns-status-traffic-and-liveness)) and logind's `PrepareForSleep`.
- app-core `reconnect`: the pure decision (`fingerprint`, `decide` → `Reconnect` / `Wait` / `Skip(Unidentified |
  DifferentNetwork | DirectlyReachable | DnsDirectlyReachable | VaultLocked)`, `surviving_check`), the per-connection
  switch (`OFF_KEY` = `autoReconnectOff`, `is_enabled` / `set_enabled`) and the `Planner` state machine
  (candidates from a sleep/wake or a network loss, `WAKE_WINDOW` 180 s, `NETWORK_WINDOW` 60 s, `SETTLE` 3 s,
  `RETRY_DELAYS` 10 s / 30 s; `Action::{Connect, Notify, Disconnect}`; the once-per-wake survivor check that
  disconnects a still-connected tunnel whose networks or DNS servers are directly reachable, as a user disconnect).
- `app/src-tauri/src/reconnect.rs`: the driver. `Reconnect` (in `AppState`) holds the event channel, the
  `Planner`, the connection repository and the network watcher's guard; `start(state)` (end of `connect_hooks`)
  adds the manager listeners, starts the watch (not in the sandbox) and the `macvpn-reconnect` thread, which
  feeds the planner (`Event::{Sleep, Wake, NetworkChanged, Failed, Forget, …}`), probes when due and executes the
  actions. Only managed connections enter it. `Reconnect::stop()` runs from `AppState::stop_polling`. UI: the
  "Reconnect Automatically" switch in `manage/Detail.svelte` (`set_auto_reconnect`).

### Dead tunnels and the live network switch

A tunnel that dies while the physical network is there (maintainer decision 2026-10-28), next to the network loss
rule in the same planner:

- **The facts:** `macvpn_core::liveness` (`LIVENESS` = `liveness`): `wireguard <n>` + `peer <handshake> <rx> <tx>
  <keepalive> <endpoint>` lines, or `openvpn up` / `openvpn reconnecting <since>`; times and counters only, strictly
  parsed, at most 64 peers and 8 KiB. `HelperClient::liveness(id)` (default `None`).
- **macOS, root layer 10:** `mvpn liveness <id>` (`crates/helper/src/macos/liveness.rs`): the app passes only the UUID;
  the root layer reads `kind` from its own run directory (`/var/run/macvpn/<ID>`, not a symlink). WireGuard: the
  interface from `iface` → the utun wg-quick recorded → `wg show <utun> dump`; only the numbers are kept and the
  output (it holds the private and preshared keys) is zeroized. OpenVPN: the run file `tunnel` (`up` |
  `reconnecting <t>`, root 0600, read with `O_NOFOLLOW`) that the management bridge writes on `>STATE:…,RECONNECTING`
  after the first `CONNECTED` and on the next `CONNECTED` (`BridgeFiles::tunnel`). Nothing to report: exit 1 without
  output. A root layer 9 answers its usage error (`MvpnClient::liveness` → `None`), and the setup check asks for the
  usual **Update required (9 → 10)**.
- **Windows:** the service's `liveness <id>` (owner only, like `log`; `SERVICE_VERSION` stays 1, an older service
  answers the usage error → `None`): WireGuard from `WireGuardGetConfiguration` (`wg_nt::liveness`, the same decoder
  as the debug peer status, plus `PersistentKeepalive`), OpenVPN from the in-process bridge's state
  (`BridgeState::reconnecting_since`). RAS connections are not asked (`RasHelper::liveness` → `None`).
- **Linux:** `Liveness::Counters` from the tunnel interface's sysfs counters (WireGuard, OpenVPN) and
  `Liveness::OpenVpn` from NM's VPN state; the rule's `COUNTER_SILENCE` (200 s). See [System VPNs, status, traffic
  and liveness](#system-vpns-status-traffic-and-liveness).
- **The rule** (`app-core liveness::Monitor`, pure): WireGuard by its timers: with `PersistentKeepalive` dead after
  `STALE_AFTER` (180 s + one poll) without a handshake; without it dead when the sent bytes grew after the session
  expired (`REJECT_AFTER_TIME`) and no handshake came within `REKEY_ATTEMPT_TIME` (90 s); an idle tunnel is never dead;
  a tunnel is dead only when every peer with an endpoint is. OpenVPN `reconnecting` → `Health::Reconnecting`, dead
  after 120 s. Ages count from the later of the handshake and the start of the watch (restarted at sleep, wake and a
  network outage).
- **The planner** (`reconnect::Planner::{liveness_due, liveness_checked, dead_down, reconnecting, not_responding}`):
  polls every `POLL` (30 s) only awake, with a network, nothing waiting for one and no network check pending (so a
  network loss and a dead tunnel never act on the same event). A dead tunnel: `Action::DisconnectNotResponding`
  (`DisconnectCause::NotResponding`, not the user's) and `Notice::NotResponding { outcome: Reconnects | Disconnected |
  GaveUp }`; with "Reconnect Automatically" on, not a lease's, and where `decide` would reconnect, a held candidate
  that the driver releases after the disconnect (`Event::DeadDown`). At most `MAX_DEAD_RECONNECTS` (3) per
  `DEAD_STABLE` (600 s without being found dead with fresh evidence of life). The same limit makes any other drop
  while the network is there (engine exit, `ping-exit`, DPD) a candidate. A tunnel whose VPN network is directly
  reachable is disconnected as after a wake.
- **The live switch:** `network_checked` compares each active connection's network with the one it was last seen on
  (`seen_on`, cleared at a wake: the wake keeps its same-network rule). A switch moves the connection
  (`fingerprints` = the new network), runs the overlap check, and starts the close watch (`Monitor::switched`: first
  poll `SWITCH_FIRST` after the check, then every `SWITCH_POLL` for `SWITCH_WINDOW`; WireGuard dead when more was sent
  than its keepalives explain and nothing was received for `SWITCH_SILENCE`; OpenVPN restarting for
  `SWITCH_OPENVPN_LIMIT`). A candidate from a drop while awake moves too, and "another network" waits while a change
  is being checked.
- **The slow tier:** when the fast attempts give up (`failed` after the `RETRY_DELAYS`, a drop or a dead tunnel
  beyond `MAX_DEAD_RECONNECTS`), a connection that should be up (switch on, not a lease's, not the user's
  disconnect, not a refused sign-in or certificate) is tried every `SLOW_RETRY` (300 s) for `SLOW_FOR` (3600 s): a
  due slow entry becomes a one-shot candidate (`evaluate`: no network waits; another network or the VPN's own
  network ends it with `NotReconnected`; a locked vault tries again silently). One notice when it starts
  (`Notice::KeepsTrying`, or `NotResponding { KeepsTrying }`) and one when the hour is over (`RetriesEnded`); the
  user's connect or disconnect, the switch off, or `DEAD_STABLE` of proven life end it. `slow_retries()` →
  `RowState::Retrying { at }` ("Retrying in … min"). A drop's notice is queued (`take_actions`).
- **Lease marks across a relaunch:** `reconnect::LEASED_KEY` (`leaseStartedConnections`, a preference of UUIDs)
  holds the connections a lease started while they are up; the driver sets it at a lease's `Started`, clears it at
  the user's own `Started`, at `Event::Down` (any transition from up or connecting to down) and at `Forget`, and
  `Planner::restore_leased` reads it at start, so a connection left up by "Quit, Keep Them Running" stays the
  leases' (never reconnected).
- **IKEv2 dead peer detection (macOS):** `strongswan::default_dpd_block` appends `connections { <conn> { dpd_delay =
  30s } }` to the run copy when the connection sets no `dpd_delay` (the settings parser merges same-named
  sections); `dpd_action` stays the config's (default `clear`), so a dead peer ends the SA and the drop is
  reconnected.
- **Adoption:** a connection already up at launch gets the network it is up on at its first `Connected`
  (`Planner::adopt`).
- **The view:** `RowState::{Reconnecting, NotResponding}`; the tray: reconnecting → `Connecting` (half shield), not
  responding → `Failure` (an authentication wait wins).
- **The driver** (`app/src-tauri/src/reconnect.rs`): asks `state.helper.liveness` for the connected WireGuard and
  OpenVPN connections without the planner's lock; a smoke run can move its clock (`Reconnect::skew`) and force a poll
  (`Event::LivenessNow`).

### Live traffic

Next to a connected row's address and time (maintainer request 2026-10-29): the bytes received and sent since the
connection came up and the current rate, in the menu's cards, the Connections window's detail header and a system
VPN's detail, for every engine on both OSes.

- **The readings** (`platform-api::traffic`): `TrafficReading { generation, rx, tx, width, from_zero }` from
  `HelperClient::traffic(&HelperTunnel)` and `NativeController::traffic(service_id)` (defaults `None`).
  - macOS OpenVPN, WireGuard, SSTP (`platform-mac::if_counters`): the interface `mvpn status` reports (`utun`, `ppp`),
    64-bit `if_data64` through `sysctl` `NET_RT_IFLIST2` for its index, as the user; generation = index + the run's
    `since`.
  - macOS strongSwan (no interface): root layer 11's `mvpn traffic <id>` (`crates/helper/src/macos/traffic.rs`): the
    app passes only the UUID, the root layer reads the connection name it recorded (`<run>/conn`) and
    `swanctl --list-sas --ike <name>` (`strongswan::parse_list_sas`), and prints `strongswan <n>` + `child <id> <rx>
    <tx>` (charon's CHILD_SA numbers and bytes only: no SPI, ID, address or name; `core::traffic`). A rekey makes a
    new CHILD_SA with fresh counters: the app sums them over their numbers (`core::traffic::ChildSums`; a number seen
    before adds its growth, a new or lower one its counters whole), so the totals never drop; generation = the run's
    `since`. A root layer 10 answers its usage error: no traffic. `mvpn status` also reports the IKE SA's first
    virtual IP (IPv4 first) as the strongSwan connection's `ip`.
  - macOS native L2TP / Cisco IPsec and system VPNs (`sc_ffi`, `native_vpn::{statistics_counters, extended_address,
    extended_interface}`): `SCNetworkConnectionCopyStatistics` (`BytesIn` / `BytesOut` of its `PPP` / `IPSec`
    section), else the counters of the interface `SCNetworkConnectionCopyExtendedStatus` names; both user-level.
    `NativeController::address` gives the extended status' IPv4 address; the manager shows it, and the time it saw
    the service connect (a service already up at the first refresh has none: never a guessed time).
  - Windows (`platform-win::{pure,win}::traffic`, `winsys::net::{if_counters, luid_of_alias, luid_of_address}`):
    WireGuard's own adapter by the alias the service reports (`GetIfEntry2`, from zero). OpenVPN: the service's
    `traffic <id>` (owner only, like `liveness`; `SERVICE_VERSION` stays 1, an older service answers its usage error =
    no data, a 2 s timeout): `bytes <rx> <tx> <run>` from OpenVPN's management `>BYTECOUNT`, which the engine's stream
    asks for once OpenVPN reports a state (`bridge_state::ByteCounter` writes `bytecount 1` through
    `OneCommandAtATime`; the bridge ignores the answer and the counter lines); one generation per `openvpn.exe` run.
    Without it, the DCO / TAP adapter holding the tunnel address (`GetUnicastIpAddressTable`; exactly one match or
    nothing), counted from its first reading (the adapter is reused). RAS connections (IKEv2, SSTP, L2TP, system
    VPNs) by `RasGetConnectionStatistics` (`winsys::ras::statistics`, 32-bit), a new generation when a handle value
    comes back with a shorter connected time (`RasGenerations`); their IPv4 address (`NativeController::address`)
    from the dial or `RasGetProjectionInfoEx`.
  - Linux: the tunnel interface's sysfs counters (see [System VPNs, status, traffic and
    liveness](#system-vpns-status-traffic-and-liveness)); none for IKEv2.
- **The totals and the rate** (`app-core::traffic`, pure): per key a session; a new generation adds its counters whole
  (or from its first reading when not `from_zero`), a 64-bit fall is a restart, a 32-bit fall from the upper to the
  lower half a wrap; never down. The rate is the change over the last `RATE_WINDOW` (3 s) of readings, unknown when
  the newest reading is older than 6 s. Counters that never moved show nothing. A fresh connect the reconnect planner
  did not start (`Event::Started`, not `is_attempting`) or a key up without a connect seen restarts the session;
  an auto-reconnect keeps it. Texts: SI units (1000 steps, as macOS), one decimal under 100, the language's decimal
  separator.
- **When** (`app/src-tauri/src/traffic.rs`): `get_traffic` (allowed to the menu and the Connections window) reads a
  round when the popover or a window is shown and the last round is older than 0.8 s; the UI calls it every second
  only while `document.visibilityState` is `visible` and a shown row is connected (`lib/traffic.ts`). The status poll
  (3 s while a connection is active) also reads a round, so restarts while nothing is shown keep the totals (for
  strongSwan that is one more `sudo -n mvpn traffic` per poll). The control API and the tray tooltip carry no
  traffic.

### IKEv2 client certificates (root layer 12)

Client credential audit G2/G4 (`docs/superpowers/reviews/2026-10-29-client-credential-audit.md`), 2.0.7.

- **Import** (`core::client_cert`, `app-core::editor::Draft::import_client_cert`, the app's `editor_import_client_cert`):
  the open panel runs in the backend; each file is read there (`import_export::read_import_bytes`, at most 16 KB, at
  most four files) and checked strictly: a PKCS#12 `PFX` (version 3, PKCS#7 `data` / `signedData`, definite or
  indefinite outer lengths, nothing after it), or PEM blocks (strict base64, matching `END`) with exactly one private
  key (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, traditional `RSA` / `EC PRIVATE KEY`, plain or `Proc-Type: 4,ENCRYPTED`
  + `DEK-Info`) and the one certificate that is not a CA (a bounded DER walk: `Certificate`, `tbsCertificate`,
  basicConstraints). No PKCS#12 decryption and no new crate: swanctl opens the file. The result is one vault secret,
  `SecretField::ClientCert` (`clientcert`; one line: `pem:<cert DER b64>:<key block b64>` or `p12:<file b64>`), so
  backups carry it and an older build skips it. The web view gets `EditorView::client_cert` (`pubkey`, the form, the
  SHA-256 fingerprint, `needsPassword`, how many certificates were left out, whether import is offered); never the key.
- **Connect** (`manager::connect_root`): a stored value that no longer parses fails the connect; `credentials::
  client_cert_fields` adds **Private key password** to the prompt when a `local…` round signs with a key
  (`StrongSwanValidator::local_rounds`, no `auth` = `pubkey`) and the key is encrypted (PKCS#12: always).
  `Secrets::client_cert` turns into the frame lines `x509=` + `private=` or `pkcs12=` after the other secrets
  (`Secrets::stdin_payload`).
- **Root layer 12** (`helper::shared::framing`, `macos::strongswan`): the three new keys, each at most once (the
  secrets section stays at most 64 KiB); `strongswan::client_cert` re-checks them with the same `core::client_cert`
  parser (a certificate without its key, both forms, bad base64: **The imported client certificate is invalid**, no
  run directory left). After Homebrew's copies (`stage_creds`) the credential goes in as `x509/mvpn-<id>.crt` (DER) +
  `private/mvpn-<id>.pem`, or `pkcs12/mvpn-<id>.p12` (0600, directories 0700, an existing same-named copy replaced).
  A PEM certificate is merged into the connection's `auth = pubkey` rounds without `certs` (`certs_block`, appended
  like the DPD block). `keypass=` becomes `<dir>-mvpn-<id>-<n> { file = "<name>"  secret = "…" }` (`key_secrets`):
  swanctl's `load_creds.c` decrypts a file of `<dir>` with the secrets whose section starts with `<dir>` and whose
  `file` is its name; these never reach charon. Bound to the imported key, or (without one) to every key file staged
  from Homebrew. The value is escaped like the PSK and masked in the log (`keypass` is in the masker since root layer
  8). Because `--load-all --file F` reads the credentials next to F, `load_together` first copies the other active
  connections' `mvpn-*` files next to its load file (`adopt_client_certs`), and down removes the connection's own
  ones before it reloads the others (`remove_own_client_cert`).
- **Windows:** RAS IKEv2 signs with a computer certificate from LocalMachine\My (`Auth::MachineCertificate`); the
  key and its password stay in Windows' store (an administrator imports the `.p12` with Windows' own wizard, which asks
  for the password). The editor shows a grey note (`ras_editor::machine_certificate_note`). The app turns the import
  on for macOS only (`ConnectionsModel::set_client_cert_import`): elsewhere `ClientCertView::import` is false and
  `import_client_cert` refuses.

### macOS DNS manager (root layer)

`crates/helper/src/macos/dns.rs` owns every DNS change of OpenVPN and SSTP (through the `ovpn-dns` hook) and
WireGuard (in-process; `wireguard::strip_dns` takes the `DNS =` lines out of the conf `wg-quick` sees). A
persistent root-only ledger `/var/db/macvpn/dns/ledger` (directory 0700, file 0600 written through a temp file and
rename, never through a symlink, strict line format, one `flock`) holds the true originals per network service
(captured only by the first owner) and the owners (connection id + servers/domains, newest last). The newest owner's
DNS is in effect; the last owner's leaving restores the originals and deletes the ledger. Every set and restore is
read back with `networksetup -getdnsservers/-getsearchdomains`, retried once and logged. **Reconcile** (owners whose
run directory is gone or whose engine is failed are dropped) runs at every `up`, `down`, `mvpn status` (non-blocking)
and `mvpn dns-reconcile`, so a crash or a reboot while connected is repaired at the app's next status poll. strongSwan
(charon's volatile dynamic-store DNS) and native VPNs are not touched. Test mode never runs the real `networksetup`
(`MVPN_NETWORKSETUP`, `MVPN_DNS_BASE`). A DNS left by a root layer before this one is in no ledger: the user resets it
once by hand (the user guide, 5.6).

### Log caps

- macOS (`crates/helper/src/macos/log.rs`): a connection log is at most `LOG_MAX` 5 MiB plus one generation
  `<id>.log.1`, rolled in place (newest whole lines to `.1`, the live file truncated, so `O_APPEND` writers go on),
  checked on every `mvpn` write, every `mask-stream` line (SSTP), every `status`, and every 30 s by the management
  bridge. The engines' own run-directory logs (`openvpn.log`, `pppd.log`) are cut to their newest 1 MiB above
  5 MiB, keeping the decision lines `status` needs.
- Windows (`crates/helper/src/windows/logs.rs`): `FileLogStore` rolls at `LOG_MAX` 8 MiB to `<ID>.log.1` with a
  localized first line; `.1` goes with the next `up` and with `remove`; `service.log` is 1 MiB + `.1`.
- OpenVPN gets `--mute 20` after `--config` on both OSes, so a config cannot raise the volume.

### Engine updates

- macOS: `platform-mac/src/brew.rs` (`BrewOutdated`: `brew outdated --json=v2 --formula …` with
  `HOMEBREW_NO_AUTO_UPDATE=1`, only our formulae; `brew upgrade <outdated>` from System Status' "Update";
  `BrewUpdate`: `brew update` with `BREW_GUARD` against a running install) and app-core `package_index`
  (`PackageIndexSchedule`: 60 s after launch, then hourly, runs when the last success is ≥ 24 h old, stores
  `lastBrewUpdate` only on success, then runs the system check again). `SetupReport::outdated_packages` keeps the
  row green.
- Windows, without a WinVPN release: OpenVPN Community through `pure::openvpn_install` / `win::openvpn_install`
  (winget's offer or the newest official MSI from `openvpn.net`'s page, Authenticode signer `OpenVPN Inc.`, never a
  downgrade); wireguard-nt through the service (`crates/helper/src/windows/wg_update.rs`, the `wireguard-check` /
  `wireguard-update` commands: the newest SDK zip from `download.wireguard.com`, the DLL checked for signer
  `WireGuard LLC`, version and machine, swapped only while no WireGuard connection is up), offered by
  `pure::wireguard_update` on System Status' WireGuard row.

## The rules and the tests that enforce them

| Rule | Enforced by |
|---|---|
| An OS `cfg` (`cfg(target_os …)`, `cfg(unix)`, `cfg(windows)`, their `not` / `any` / `all` forms, `cfg_attr` and `cfg!` with one of them, `target_os =`) appears in production code only in `crates/core/src/fsx/`, `crates/platform-mac/`, `crates/platform-win/`, `crates/platform-linux/`, `crates/winsys/`, `crates/unixsys/`, `crates/helper/src/{macos,windows,linux}/`, `crates/helper/src/main.rs` and `app/src-tauri/src/platform/` (`CFG_ALLOWED`; LinVPN plan Task 9 added the Linux entries). Tests, `examples/`, build scripts and Cargo target tables are outside the rule; `debug_assertions`, `test` and `feature` are not OS `cfg`s. | `crates/app-core/tests/cfg_rule.rs` (`os_cfgs_only_in_the_platform_places`; it scans `crates/*/src` and `app/src-tauri/src`, ignoring comments, strings and `#[cfg(test)]` items; `target_env` and `target_family` count as OS words, and a `cfg($metavariable)`, `#[path = …]` and `include!` count as violations, because the scan cannot see their code) |
| `unsafe`, and an `allow`/`expect`/`warn` of the `unsafe_code` lint, appear only in `crates/platform-mac`, `crates/platform-win`, `crates/platform-linux`, `crates/winsys`, `crates/unixsys` and `crates/helper` (`UNSAFE_ALLOWED`). The workspace lint `unsafe_code = "deny"` holds everywhere else; platform-api also `#![forbid(unsafe_code)]`, platform-win allows `unsafe` only in its `win` module and platform-linux only in its `lin` module and the debug-only `smoke::send_terminate`. | `cfg_rule.rs` (`unsafe_only_in_the_platform_crates_and_the_helper`) |
| No test is ignored on one OS only: the ignored tests are exactly the entries of `scripts/ignored-everywhere.txt` that are built on this OS (the fixture writers, a timing measurement, a manual Windows test), and no `cfg_attr(windows, ignore …)` is left in the sources. | `scripts/check-ignored.sh` (both CI test jobs; on Windows `scripts/check-ignored.sh --target x86_64-pc-windows-msvc`) |
| No Windows crate in a macOS binary. | `cargo tree --locked -e normal --target aarch64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none \| grep -E '^(windows\|macvpn-winsys)'` prints nothing (and the same for `x86_64-apple-darwin`) |
| No Linux-only crate in a macOS or Windows binary. | `cargo tree --locked -e normal --target aarch64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none \| grep -E '^(zbus\|ksni\|macvpn-platform-linux) '` prints nothing (and the same for `x86_64-pc-windows-msvc`) |
| MacVPN's data formats, view model and IPC payloads stay as in 1.4.0. | `crates/app-core/tests/compat_1_4.rs` (the fixtures normalize the version) |
| Every macOS text that 1.4.0 had stays byte-identical (newer texts are counted, not compared). | `node scripts/l10n-baseline.mjs --check` (against `scripts/bundle-baseline/1.4.0/l10n-macos.json`), and the same comparison in `crates/core/tests/l10n.rs` and `app/ui/src/lib/l10n.test.ts` |
| The built bundle looks the same from outside (Info.plist, files, linked libraries, entitlements, Tauri config). | `scripts/bundle-baseline.sh dist/MacVPN.app` (compare with `scripts/bundle-baseline/1.4.0/`) |
| No OpenSSL in a macOS binary. | `cargo tree --locked --target aarch64-apple-darwin -i openssl-sys` prints nothing; the release gate in `scripts/build-dmg.sh` |

## Product identity and the per-OS Tauri config

`Product` (`crates/platform-api/src/product.rs`) is the identity: `name` (`MacVPN` / `WinVPN` / `LinVPN`, also the
data directory's name), `os`, `app_id` (`local.macvpn` / `local.winvpn` / `local.linvpn`), `repo` (`SepsiG/MacVPN`
for all three: one repository, one version number), `user_guide_stem` (`user-guide` / `winvpn-user-guide` /
`linvpn-user-guide`) and `signature_domain` (`MacVpnV1` / `WinVpnV1` / `LinVpnV1`). The constants are `MACVPN`,
`WINVPN` and `LINVPN`. From these:

- `data_dir(app_data_root)`: `<root>/<name>`; the platform gives the root (macOS:
  `~/Library/Application Support`, so `~/Library/Application Support/MacVPN` as before).
- `update_asset(version, arch)`: `MacVPN-<version>.dmg`; `WinVPN-<version>-x64.msi` or `-arm64.msi`;
  `linvpn_<version>_amd64.deb` or `_arm64.deb` (the Debian package name, not the product name).
- `text_platform()`: the OS and product the texts are worded for.

The update signature is bound to the product (`crates/core/src/update.rs`, `SignatureDomain`). MacVPN keeps
`macvpn-update-v1\n<version>\n<sha256>\n` byte for byte. WinVPN signs `winvpn-update-v1\n<asset>\n<version>\n<sha256>\n`
with the asset's file name, which must be exactly `WinVPN-<version>-x64.msi` or `WinVPN-<version>-arm64.msi`
(anything else has no message and never verifies). Same keys; the domains make a signature of one product or one
architecture useless for another. LinVPN signs `linvpn-update-v1\n<asset>\n<version>\n<sha256>\n` with the asset
exactly `linvpn_<version>_amd64.deb` or `linvpn_<version>_arm64.deb` (`SignatureDomain::LinVpnV1`,
`UpdateSignature::LINVPN_DOMAIN`). `scripts/sign-release.sh` signs each asset with its product's message. The
WinVPN updater (download, verify, `msiexec` through UAC, the relauncher) is in platform-win (2b); LinVPN's (download,
verify, pkexec, the root step, the relaunch) in platform-linux and the helper's `src/linux/` (see [the update
chain](#the-update-chain-and-the-deb)).

The Tauri config is split: `app/src-tauri/tauri.conf.json` holds everything shared and the macOS identity as the
default (product name, identifier, version, windows, CSP); `tauri.macos.conf.json` adds the macOS bundle settings
(`macOSPrivateApi`, the `app` target, the icons with `icon.icns`, the minimum macOS version);
`tauri.windows.conf.json` sets `WinVPN`, `local.winvpn`, the `msi` target, the icons with `icon.ico`, the popover
window titled `WinVPN`, the notices as a resource, the file associations (`.ovpn`, `.sstp`, `.macvpncatalog`), the
WebView2 bootstrapper embedded in the MSI (`embedBootstrapper`: no download into the user's `%TEMP%`), no downgrades
(`allowDowngrades: false`; the same version still reinstalls), the fixed WiX `UpgradeCode` and the WiX fragment
`wix/file-associations.wxs` (`.conf` under "Open with" only; `build-msi.sh` adds `wix/service.wxs.in`, which also pins
the install folder to `<Program Files>\WinVPN` and gives it a protected, admin-only ACL), `useHttpsScheme` on the popover window and IPC over `https://ipc.localhost` in the CSP's
`connect-src`. `tauri.linux.conf.json` sets `LinVPN`, `local.linvpn`, the binary name `linvpn` (`mainBinaryName`),
the popover window titled `LinVPN` and transparent (the overlay panel), and turns the bundler off (`bundle.active:
false`: `tauri build --no-bundle`, the `.deb` is `scripts/build-deb.sh`'s). Tauri merges the OS file over the base (JSON merge patch, which replaces arrays whole).
`app/src-tauri/tests/tauri_config.rs` checks that base + macOS equals the 1.4.0 config.

Every web view only navigates within the app's origin (`app/src-tauri/src/navigation.rs`, the `on_navigation`
handler of every window): `tauri://localhost` on macOS and Linux, `https://tauri.localhost` on Windows, where WebView2 serves
the embedded UI under a special host and every window (the config's popover and the windows built in code, through
`navigation::uses_https_scheme`) uses the https scheme. `navigation::app_origin()` picks the origin by the running
product's OS (`Product::os`), so `navigation.rs` has no OS `cfg`.

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

The glossary for Linux variants (GNOME words): Keychain → the login keyring („bejelentkezési kulcstartó”), Finder →
Files („Fájlok”), this Mac → this computer („ez a számítógép”, with the right case), System Settings → Settings
(„Beállítások”), Login Items / Open at Login → launch at login („automatikus indítás bejelentkezéskor”), menu bar →
top bar („felső sáv”), Dock → dash („dokk”), Option-click → Alt-click („Alt+kattintás”), Homebrew-only texts stay
`only: ["macos"]`. `no_macos_term_reaches_linux` and `no_windows_term_reaches_linux` check the resolved texts.

The coverage test `macos_terms_are_classified` in `crates/app-core/tests/l10n_coverage.rs` fails for any text that
names a macOS facility (Keychain, Finder, Mac, System Settings, Dock, menu bar, …) unless, for Windows and for
Linux each, `only` leaves that OS out or the entry has that OS's variant. Every variant keeps its base's format specifiers (`crates/core/tests/l10n.rs`).

## The control API transport

app-core's `ControlServer` runs over platform-api's transport traits, not over `UnixStream`:
`ControlTransport::bind(dir)` gives a `BoundEndpoint` (a `ControlListener`, the text of the "listening on …" log
line, the socket file to remove at stop, a guard); `ControlListener::accept(poll)` returns
`Accepted::Client { stream, peer }` or `Idle`. The listener identifies the peer at accept time (`PeerIdentity`
with `PeerUser::Uid(n)` or `PeerUser::Sid(…)`), so a named pipe needs no stream downcast later. `PeerUser::Uid(501)`
displays as `uid 501`, so every audit log line keeps its 1.4 text.

macOS implements it over the Unix socket (`crates/platform-mac/src/api/control.rs` over `macvpn_unixsys`'s
`control_socket` and `transport`, which platform-mac re-exports as `control_socket`). Linux uses the same code at
`$XDG_RUNTIME_DIR/linvpn/control/linvpn.sock` (see [LinVPN on Linux](#linvpn-on-linux)). Windows
implements it over the named pipe `\\.\pipe\WinVPN-control-<user SID>` (`crates/platform-win/src/win/control.rs`
over `macvpn_winsys::pipe`; not `\\.\pipe\WinVPN`, which the spec reserves for the 2b service): `display` is the pipe
name, there is no socket file, and the first pipe instance is the guard. A name already taken leaves the control API
off with its error shown, as on macOS. The peer is `PeerUser::Sid` from the client's token (identification-level
impersonation), never from its PID. The pipe denies network logons, so only the user's own desktop session can
pair; an SSH session of the same user cannot.

The app-core tests run the whole server suite over a Unix-socket, a TCP loopback and, on Windows, a named-pipe
transport (`Kind::Pipe` in `crates/app-core/tests/control_support/`; the suite keeps its fake peer identity, the
real identity is tested in `crates/winsys/tests/pipe.rs` and `crates/platform-win/tests/control_pipe.rs`). The
example client (`examples/macvpn-control-client`) has a Unix transport and, on Windows, a pipe transport over
`macvpn-winsys` (`default_endpoint()` returns the pipe name); it refuses a pipe served by another user.

## Checking Windows

The C dependencies (SQLCipher with a vendored OpenSSL, the app's Windows resource) need an MSVC toolchain, which a
Mac does not have ([the Windows check spike](superpowers/spikes/2026-10-20-windows-check-spike.md)). So there are
three levels:

- **On a Mac:** `scripts/check-windows.sh` runs `cargo check --all-targets` for `x86_64-pc-windows-msvc` and
  `aarch64-pc-windows-msvc`, debug and release, on `macvpn-core` (without `vault`), `macvpn-helper` and
  `macvpn-control-client`. It installs nothing: the targets come from `rust-toolchain.toml`.
- **On the Windows test machine:** `scripts/win-remote.sh` (below) runs the full Windows test set, clippy, the
  ignored-tests check and `scripts/build-msi.sh` from the Mac, as a standard user.
- **In CI:** the `windows` and `windows-node` jobs in `.github/workflows/ci.yml` (on `windows-latest`) check, lint
  and test the workspace and run the UI tests on Windows; `scripts/check-ignored.sh` runs in both test jobs.

What only a person at a Windows desktop can check (the notification-area icon, the popover, toasts, file dialogs,
logoff, Credential Manager in an interactive logon, a second user account, the installed MSI, the service's admin
tests, real VPN servers) is the WinVPN sections of `docs/manual-test-checklist.md`, run against the VPN lab
(`scripts/vpn-lab/`, its README). The UI smoke driver runs on both OSes
(`app/src-tauri/src/platform/smoke/`): `scripts/win-smoke.sh en|hu` runs it in the logged-on standard user's desktop
session through a one-shot scheduled task (only with the maintainer's OK). CI's `windows-admin` job installs OpenVPN
Community (`scripts/ci-install-openvpn.sh`) and the MSI on GitHub's administrator runner and runs the admin test set;
`scripts/fetch-wireguard-nt.sh` fetches the pinned wireguard-nt SDK for builds and tests.

On Windows the vault uses `bundled-sqlcipher-vendored-openssl` (a `[target.'cfg(windows)'.dependencies]` line in
`crates/core/Cargo.toml`). That puts `openssl-src` and `openssl-sys` into `Cargo.lock`, but resolver 3 never
activates them for a macOS target. `scripts/third-party-notices.mjs` still walks `cargo metadata` for the two macOS
targets and leaves out the crates that only a Windows build links, so `THIRD-PARTY-NOTICES.txt` did not change;
`--os windows` writes `THIRD-PARTY-NOTICES.windows.txt` (the crates of the two Windows targets, the SQLCipher and
OpenSSL notices, the UI's packages), which the MSI installs as `THIRD-PARTY-NOTICES.txt`. The vault routes
SQLCipher's log to the system log device once per process, before any connection (`PRAGMA cipher_log = device`):
on macOS that is SQLCipher's default (os_log); on Windows the default, stderr, recursed until the stack overflowed
once `VirtualLock` ran out of working-set quota.

### The WinVPN MSIs

`scripts/build-msi.sh` (Git Bash on Windows; from the Mac through `scripts/win-remote.sh`, see below) builds
`dist/windows/WinVPN-<version>-x64.msi` and `-arm64.msi` with their `.sha256`, unsigned, with gates that mirror
`build-dmg.sh`: the three version numbers agree; no build-changing variable is set; `THIRD-PARTY-NOTICES.windows.txt`
is current (`node scripts/third-party-notices.mjs --os windows --check`); per architecture the binary's PE machine,
its PE subsystem (2, a GUI program: `windows_subsystem = "windows"` in release builds, so no console window opens),
no debug-only markers (`MACVPN_SANDBOX_HOME`, `MACVPN_SMOKE`), SQLCipher with the vendored OpenSSL 3 linked
statically (no crypto or SQLite DLL imported, `scripts/pe-imports.mjs`); the WiX tools against pinned SHA-256s
(before `tauri build` when they are there already, so a replaced tool never runs, and after it; `--check-tools` and
`scripts/test-build-msi.sh` test that check);
and the MSI's tables read without installing (`scripts/msi-query.ps1`): ProductName, ProductVersion, the fixed
UpgradeCode, the Start-menu shortcut with the AppUserModelID `local.winvpn`, `.ovpn`, `.sstp` and `.macvpncatalog`
as default associations and `.conf` under "Open with" only. Its files, unpacked with WiX's `dark.exe -x`, must equal
`scripts/bundle-baseline/winvpn-msi-files.txt` (`WinVPN.exe`, `WinVPNService.exe`, `wireguard.dll` and
`THIRD-PARTY-NOTICES.txt` in `PFiles/WinVPN`), the
notices inside must equal the committed file. The binary gates above run on the `WinVPN.exe` unpacked from the MSI
(what ships), which must equal cargo's `target/<triple>/release/WinVPN.exe` but for the bundle-type marker the Tauri
bundler patches into the copy it bundles (`__TAURI_BUNDLE_TYPE_VAR_UNK` → `…_MSI`; it restores the unpatched exe
after a successful bundle; not compared in a signed build). `--arch x64|arm64|both`
picks the architectures. From 2b the MSI also carries the service (WiX fragment `wix/service.wxs.in`: `ServiceInstall`
LocalSystem automatic, `ServiceControl`, no failure-actions table) and the pinned `wireguard.dll`; their gates check
the service exe (machine, subsystem, no debug markers, no SQLite, an exact import list) and the DLL (the pinned SHA-256
and the `WireGuard LLC` signer), before the build and again on the unpacked MSI. Authenticode signing runs only when `WINVPN_SIGN_THUMBPRINT` and
`WINVPN_SIGN_TIMESTAMP_URL` are set (off by default and in CI). Where the Windows Installer service cannot be
reached (an OpenSSH key logon), `WINVPN_WIX_NO_ICE=1` links the MSI without ICE validation (refused when `CI` is
set; CI validates). `scripts/win-remote.sh` runs every command with `CI=1` except `msi`, which runs
`scripts/build-msi.sh` (with its options, e.g. `--arch x64`) without `CI` and with `WINVPN_WIX_NO_ICE=1`, and says
that ICE validation is skipped: on the test machine run `scripts/win-remote.sh msi` (`scripts/test-win-remote.sh`
checks this in print mode, in CI too). ARM64 is built and checked for
contents, but not run.

### The Windows test machine

The coordinator reaches a Windows 11 x64 machine over SSH as a **standard user** (no admin rights). The machine has
rustup (the toolchain comes from `rust-toolchain.toml` on the first `cargo` call), Visual Studio Build Tools (the C++
workload with the x64 and ARM64 compilers), Git for Windows (Git Bash), Strawberry Perl and Node 26.8.2.

Setup (done 2026-10-21): the standard account `winvpn-dev` has a key-only `authorized_keys` entry for the
Mac's `~/.ssh/winvpn_dev`; the host key is pinned in `~/.ssh/winvpn_known_hosts`. Nothing in `~/.ssh/config` and
no change to OpenSSH's `DefaultShell` (that needs an administrator): the script starts Git Bash explicitly
(`C:\Program Files\Git\bin\bash.exe -lc …`) for every remote command. The machine's address is not in the
repository: `WINVPN_SSH=winvpn-dev@<host>` names it.

`scripts/win-remote.sh` then syncs the working tree (HEAD plus uncommitted changes of tracked files; `git add -N`
a new file first) and runs commands there:

    scripts/win-remote.sh test                      # the CI windows job's test set
    scripts/win-remote.sh ignored                   # the tests ignored on Windows
    scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys'
    scripts/win-remote.sh msi --arch x64            # build-msi.sh without CI, WINVPN_WIX_NO_ICE=1
    scripts/win-remote.sh fetch dist/windows ./dist/windows

`test` and `ignored` cover the CI windows job's packages plus `macvpn-winsys` and `macvpn-control-client` (each
only once its crate exists). The remote checkout keeps `target/` between runs, so only the first build is cold
(about 11 minutes). Remote commands run in Git Bash, which rewrites arguments that look like Unix paths
(`/target` becomes `C:/Program Files/Git/target`) before a native program sees them; prefix such a command with
`MSYS_NO_PATHCONV=1` (or write the path so it does not start with `/`). A remote command's stdin is `/dev/null`. Every
command syncs first, so run one command at a time per remote checkout: a second `sync` checks out under a running
build. Steps that need an administrator (installing the MSI, from 2b the service) are the
maintainer's; they are in the WinVPN section of `docs/manual-test-checklist.md`. Several worktrees use separate remote checkouts:
`WINVPN_REMOTE_DIR=winvpn-work-<name>`.

## Checking Linux

### The Linux test machine

The coordinator reaches an Ubuntu 26.04 desktop VM (GNOME, Wayland) over SSH as the **non-admin** user `linvpn-dev`
(key `~/.ssh/linvpn_dev` on the Mac, host key pinned in `~/.ssh/linvpn_known_hosts`, no alias in `~/.ssh/config`;
the address is never in the repository: `LINVPN_SSH=linvpn-dev@<VM address>`). The maintainer installed the build
dependencies and the NetworkManager VPN plugins with apt (LinVPN plan, CP0); rustup lives in the user's home.
Anything that needs root (apt, installing the `.deb`, a polkit password) is the maintainer's, at a checkpoint.

`scripts/lin-remote.sh` syncs the working tree (HEAD plus uncommitted changes of tracked files; `git add -N` a new
file first) and runs every command as a **job**: detached on the VM, its output in `<checkout>/.lin-jobs/<id>.log`,
polled from the Mac over short SSH calls, so a hanging SSH session loses nothing (`attach <id>` continues):

    scripts/lin-remote.sh test                      # the CI linux job's test set (dbus-run-session, CI=1)
    scripts/lin-remote.sh run 'cargo test --locked -p macvpn-platform-linux'
    scripts/lin-remote.sh desktop 'cargo test --locked -p macvpn-platform-linux -- --ignored desktop'
    scripts/lin-remote.sh run 'scripts/build-deb.sh'
    scripts/lin-remote.sh fetch dist/linux ./dist/linux

`desktop` runs the job with `systemd-run --user` in the user's systemd instance, which has the desktop session's
display and session bus and which polkit counts as the graphical session; `linvpn-dev` must be logged in at the VM's
desktop (the screen may be locked). Several worktrees use separate remote checkouts:
`LINVPN_REMOTE_DIR=linvpn-work-slot<N>` (warm build directories, reused, never deleted after a task).

**The smoke run on Linux** (LinVPN plan, Task 23): `scripts/lin-smoke.sh en|hu` builds the debug app on the VM and runs
`scripts/smoke-manage.sh` in `linvpn-dev`'s desktop session (through `lin-remote.sh desktop`), so it needs the
checkpoint **CP-desktop login**: `linvpn-dev` logged in at the VM's desktop (the screen may be locked). Every JS step
runs on Linux except what is AppKit's or RAS's (the Dock icon, the screenshots, the appearance print), which says
"skipped on Linux"; the system's quit request is the SIGTERM the driver sends to its own process. The sandbox never asks
NetworkManager: the driver's stand-in report and stand-in engines let `scripts/smoke/nm.js` (L-b Task 25) check the
NetworkManager rows with Install, a greyed OpenVPN connection with its Linux reason, the "Send all traffic over VPN"
control, an L2TP connection's Save / Connect / Disconnect and the Log tab.

There is no `scripts/check-linux.sh` on the Mac: unlike Windows, every Linux crate needs C code built for Linux
(SQLCipher, GTK, WebKitGTK), so the VM and CI check it. What only a person at the Linux desktop can check (the tray
clicks, the panel's place, the keyring's unlock prompt, notifications, logout, the installed `.deb`, the pkexec
prompt of an update, and since L-b the real VPN connections, PackageKit's prompt and the system VPNs) is the
LinVPN sections of `docs/manual-test-checklist.md`.

## Adding a platform

Phase 2 (WinVPN) followed this list, and LinVPN follows it too. For Windows, steps 1–4, 6–8 and 10–12 were done in
phase 2a ([the plan](superpowers/plans/2026-10-21-winvpn-2a-foundations.md)), step 5 (the helper, as the WinVPN
Service) and step 9 (the Windows OpenVPN tier, `FORBIDDEN_WINDOWS` in the validator) in 2b, and the native VPNs (the
platform's own VPN client, step 13 below) in 2c.

For Linux, L-a ([the plan](superpowers/plans/2026-10-29-linvpn-l0-la.md)) did steps 1–4, 6–8 and 10–12: `LINVPN`
(1), `crates/platform-linux` with `crates/unixsys` (2), `platform/linux.rs` (3), fsx's Unix code, which Linux shares
with macOS (4), the Linux entries of the cfg rule (6), the Linux variants and the Linux-only texts (7),
`tauri.linux.conf.json` (8), the VM harness, `scripts/build-deb.sh` and CI's Linux jobs (10), `linvpn-update-v1` (11),
and the importer, whose Unix rules hold on Linux (12). L-b ([the plan](superpowers/plans/2026-10-29-linvpn-lb.md))
did steps 5, 9 and 13: step 5 is the root update step `linvpn-install-update` (L-a) plus `linvpn-logd` (a
socket-activated journal reader that is not root; LinVPN has no root layer for its VPNs: NetworkManager runs them),
step 9 the Linux OpenVPN tier (`PLATFORM_LINUX`: 69 names RISKY "Ignored by NetworkManager on Linux", `setcon`
"Not supported on Linux", the 8 refusals as `nm_plan` reasons), step 13 the VPNs through NetworkManager
(`NativeController`, `NativeProfiles` and `NativeSupport` over NM; no `AdminSteps`: nothing needs an administrator
except PackageKit's own prompt) and the system VPNs. The parity audit is L-c.

1. **Product.** Add a `Product` constant in `crates/platform-api/src/product.rs` (name, OS, app id, repo, user
   guide stem) and its `update_asset` rule, with tests in `crates/platform-api/tests/product.rs`.
2. **Platform crate.** A new `crates/platform-<os>` that implements `Platform` (start from `platform-win`: every
   method is there). Put the OS bindings under target-specific dependency tables and the crate under a crate-level
   `#![cfg(target_os = …)]` once it calls the OS. Keep the storage identifiers literal.
3. **App selection.** In `app/src-tauri/src/platform/mod.rs`, a module for the OS with `init`, `get`,
   `native_window`, `configure_app`, `set_window_presence`, `on_run_event` and `supported`; the dependency in
   `app/src-tauri/Cargo.toml` under the OS's target table.
4. **fsx.** Implement `Access::Private`, `owner` and `has_access` for the OS, so the tests that create private
   files or a vault run on that OS too. *Windows: done in 2a* (ACLs from the open handle through `macvpn-winsys`,
   see [core](#core)); no test is ignored on Windows only any more (`scripts/check-ignored.sh`).
5. **Helper.** A backend in `crates/helper/src/<os>/` over `shared`, and its `main` in `src/main.rs`. *Linux: no
   VPN backend (NetworkManager runs the VPNs): the binaries `linvpn-install-update` and `linvpn-logd`.*
6. **The cfg rule.** Add the new directories to `CFG_ALLOWED` (and `UNSAFE_ALLOWED` if needed) in
   `crates/app-core/tests/cfg_rule.rs`. Nowhere else.
7. **Texts.** Write the OS's `variants` for every text the coverage test flags, and new texts for the OS's own
   flows (with `only`).
8. **Tauri config.** `app/src-tauri/tauri.<os>.conf.json` with the identity and bundle settings.
9. **OpenVPN tier.** Review `platform_reasons(os)`, and refuse what the OS's engine cannot run as a per-connection
   reason, not a tier (the config stays valid elsewhere). *Linux: done in L-b* (see [LinVPN's OpenVPN
   service](#linvpns-networkmanager-openvpn-service)).
10. **Checks.** Extend `scripts/check-windows.sh` or the CI job, and the release gates of the OS's build script.
11. **Update signature (phase 2 blocker).** Before the first signed asset of a new product, give it its own
    signature domain. *Windows: done in 2a* (`winvpn-update-v1\n<asset>\n<version>\n<sha256>\n`, see
    [Product identity](#product-identity-and-the-per-os-tauri-config)); MacVPN rejects a WinVPN-domain signature and
    WinVPN rejects the x64 MSI's signature for the arm64 asset (`crates/core/tests/update.rs`).
12. **Importer paths (phase 2 blocker).** Referenced files of an imported config must resolve with the OS's paths.
    *Windows: done in 2a*: `importer::read_inline_data` joins with `Path` and checks containment against the
    canonical base plus the platform separator (`\\?\C:\…` on both sides on Windows; on Unix the decisions are
    those of 1.5.0, pinned by `unix_decisions_are_unchanged`); on Windows UNC, device, `\\?\` and `\??\` forms and a
    root without a drive are refused before any file system call, and so are alternate data streams. The 24
    importer tests run on Windows. *Links inside the folder (review M1):* on Windows `fsx::canonicalize_reference`
    refuses a reference that is not lexically below the folder before any file system call, then opens each name
    below the folder as itself and refuses any symlink, junction or mount point (whatever its target) before
    canonicalizing: a link to `\\server\share\…` (say inside a double-clicked VHDX, which Windows mounts with its
    NTFS links) would otherwise open an SMB session, and send the user's NTLM credentials, while the path is
    resolved. On macOS a symlink inside the folder is still followed, as in 1.5.0 (accepted): a link to an autofs
    path (`/net/…`) or an already mounted share reaches it with the credentials macOS already holds, and no new
    credentials go to a server the config names; the containment check on the canonical path then refuses it.
13. **Native VPNs.** `NativeController`, `NativeProfiles`, `NativeSupport` and `AdminSteps` over the OS's own VPN
    client; per-connection reasons for what it cannot run; a parity audit against MacVPN
    ([Windows' audit](superpowers/specs/2026-10-25-winvpn-parity-audit.md)). *Linux: L-b* runs every kind through
    NetworkManager (the helper kinds through `HelperClient` in-process, as WinVPN's RAS IKEv2 and SSTP), with
    `nm_plan`'s reasons; the parity audit is L-c.
