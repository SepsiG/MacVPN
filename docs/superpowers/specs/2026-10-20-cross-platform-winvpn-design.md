# Cross-platform MacVPN: WinVPN (Windows), then Linux — design

**Date:** 2026-10-20
**Status:** design agreed in conversation; this written spec awaits review.
**Base:** MacVPN 1.4.0 (`develop`). This spec does not change any existing security rule. Every rule in the earlier specs still applies on every platform: the vault, the control API, team catalogs, the validators, the untrusted-input rules and the update signing.

## 1. Goals

- **One codebase, three products:**
  - **MacVPN** (macOS, existing)
  - **WinVPN** (Windows, new)
  - **Linux** (later; working name to be decided)
- **One app, one UI and the same logic.** Only a thin platform layer differs per OS.
- **Small and robust.** No duplicated app code. Native OS facilities are used where they exist, and the installer does not bundle large third-party stacks.
- **Dependencies are handled automatically.** Every product installs what it needs itself, with a pinned, verified source.
- **Data is portable.** A vault backup, an export or a team catalog made on one OS works on the others.

**Not goals:**
- Feature changes to MacVPN beyond what the restructuring needs.
- Windows versions older than 10 22H2.
- Code signing of the Windows installer for now. It is unsigned at first, and the build is ready to sign later (see section 7).

## 2. Decisions

| Topic | Decision |
|---|---|
| Windows versions | Windows 10 22H2+ and Windows 11, **x64 and ARM64** |
| VPN types on Windows | **native where possible**: IKEv2, L2TP/IPsec, SSTP and Cisco-style IPsec through the Windows RAS client; WireGuard through the bundled official **wireguard-nt** DLL; OpenVPN through the official **OpenVPN Community** package (with the DCO driver), installed and updated by WinVPN |
| strongSwan configs on Windows | translated to native IKEv2 where the settings are supported; anything unsupported gets a precise error |
| Signing | unsigned installer at first (SmartScreen warns once); updates stay protected by the maintainer's Ed25519 key |
| Repository and versions | **same repo, same version number.** One release carries `MacVPN-X.Y.Z.dmg` and `WinVPN-X.Y.Z-x64.msi` / `-arm64.msi`, each with `.sha256` and `.sig` |
| Architecture | **platform layers behind one app** (section 3) |

## 3. Architecture

```
crates/
  core/          shared logic. Unix-only file operations move behind a small `fsx` module
                 (O_NOFOLLOW / modes on Unix; FILE_FLAG_OPEN_REPARSE_POINT / ACLs on Windows).
  app-core/      shared app logic. The control-API transport becomes a trait
                 (Unix socket | named pipe); macOS concepts get neutral names
                 (SystemService → SystemVpn, mobileconfig → native profile).
  platform-api/  NEW: the platform traits and shared types (key store, notifications, tray/popover,
                 file panels, native VPN, privileged helper client, login item, updater, clipboard,
                 download mark, setup/dependency checker, product identity and paths).
  platform-mac/  existing; implements platform-api.
  platform-win/  NEW; implements platform-api with Windows APIs.
  helper/        the current `mvpn` (renamed crate; the macOS binary keeps its name and install path).
                 Shared: CLI/protocol, framing, masking, validation, locks, management bridge.
                 Backends: `macos` (sudo, networksetup, wg-quick, sstpc, swanctl) and
                 `windows` (service: OpenVPN, wireguard-nt, DNS).
app/src-tauri/   one app. The platform crate is chosen once with `cfg(target_os)` in a single
                 `platform` module; the rest of the app uses only platform-api traits.
app/ui/          one UI. OS-specific wording comes from l10n keys with per-OS variants
                 (e.g. "Keychain" → "Credential Manager", "Finder" → "File Explorer").
```

**Product identity** is configuration, not code:
- name: MacVPN / WinVPN
- bundle or app id: `local.macvpn` / a Windows AppUserModelID
- icons
- the data directory: `~/Library/Application Support/MacVPN` / `%APPDATA%\WinVPN`
- the update asset name
- the help URLs

It comes from per-OS Tauri config files (`tauri.macos.conf.json`, `tauri.windows.conf.json`) and a `Product` struct in platform-api.

**Rule:** `cfg(target_os)` appears only in the platform selection, in `fsx`, and inside the platform and helper backends.

## 4. Windows specifics

### 4.1 WinVPN Service (privileged helper)

- **What it is:** a Windows service running as LocalSystem, installed by the MSI. It replaces the macOS `sudo mvpn` model.
- **Endpoint:** one named pipe, `\\.\pipe\WinVPN`.
  - The DACL grants access only to interactive users and SYSTEM.
  - Each request is checked against the client's token: the caller's user SID owns that request's connections.
- **Protocol:** the same framed stdin-style protocol as root layer 8 (config plus secrets), with the same validators. Secrets are zeroized and never logged.
- **Scope:** only its own operations:
  - OpenVPN up/down, through `openvpn.exe` with DCO and the management bridge
  - WireGuard up/down, through wireguard-nt
  - DNS on its own adapters
  - status
  
  It never runs arbitrary commands.
- **Files:** state and logs live in `C:\ProgramData\WinVPN`, readable only by SYSTEM and Administrators. The user's own log lines reach the app through the service, as on macOS.
- **Versioning:** the service has a VERSION like root layer 8. The app checks it, and the MSI updates it.

### 4.2 Native VPNs (no service needed)

- **Start and stop:** IKEv2, L2TP/IPsec, SSTP and Cisco-style IPsec use RAS phonebook entries in the user's own phonebook. They start through `RasDial` and stop through `RasHangUp` in the user context. This is the counterpart of SCNetworkConnection plus `.mobileconfig`.
- **Credentials:** RAS dial parameters supply them at connect time, so nothing is stored in the phonebook. This matches the macOS rule that MacVPN's copies live in the vault.
- **Live list:** a change watcher on the phonebook file plus RAS connection notifications, the counterpart of the SCPreferences watcher.

### 4.3 Platform mapping

| Concern | macOS | Windows |
|---|---|---|
| Vault key (auto-unlock) | Keychain item | Credential Manager generic credential (DPAPI, current user) |
| Control API transport | Unix socket + `getpeereid` | named pipe + client token SID + process image path |
| Tray | menu bar icon + popover | notification-area icon + borderless rounded popover |
| Window presence | Dock icon while a window is open | taskbar button while a window is open |
| Notifications | UNUserNotificationCenter | Toast notifications (AppUserModelID) |
| Launch at login | SMAppService / LaunchAgent | per-user Run key (or Task Scheduler) |
| File panels | NSOpenPanel / NSSavePanel | IFileOpenDialog / IFileSaveDialog |
| Clipboard secrets | concealed, local-only | `ExcludeClipboardContentFromMonitorProcessing` + `CanIncludeInClipboardHistory=0` + `CanUploadToCloudClipboard=0` |
| Downloaded-file mark | `com.apple.quarantine` | Mark-of-the-Web (`Zone.Identifier` stream) |
| File associations | Info.plist UTIs | MSI ProgId / registry associations (same extensions and ranks: `.ovpn`, `.sstp` and `.macvpncatalog` default; `.conf` only in "Open with") |
| Quit and logout handling | `applicationShouldTerminate` | `WM_QUERYENDSESSION` / `WM_ENDSESSION` |
| Updater | DMG, verify, replace | MSI, verify, `msiexec /i … /qn`, restart |

### 4.4 Dependencies (automatic)

- **Native VPNs:** none.
- **WireGuard:** the official signed `wireguard.dll` (wireguard-nt), shipped in the MSI. Its version is pinned and its hash is checked at build time.
- **OpenVPN:** when an OpenVPN connection exists and OpenVPN Community is missing or too old, System Status offers a one-click install. It uses `winget install OpenVPNTechnologies.OpenVPN` first. If winget is unavailable, it downloads the official MSI and runs it only when it matches a pinned SHA-256. Updates are offered the same way.
- **macOS:** unchanged (Homebrew).
- **Linux, later:** apt / dnf through the same "dependency checker" trait.

## 5. Data compatibility

- The vault, the full backup, the per-connection export and the team catalog use the same formats on every OS.
- **On restore or import on Windows:**
  - L2TP/Cisco native settings become RAS entries.
  - strongSwan configs are translated to native IKEv2 where they are supported. Otherwise the connection is kept, but marked "not supported on Windows" with the reason.
- **The OpenVPN platform tiers** (`REASON_PLATFORM`) become per-OS. Directives that are Windows-only become allowed on Windows, and the macOS-only ones are refused there.

## 6. UI

- The same Svelte UI.
- OS-specific behaviour and wording come from:
  - the `Product` identity;
  - l10n keys with per-OS variants;
  - a few platform flags in the view model, for example whether a native profile needs an install step.
- The keyboard shortcuts use the platform's primary modifier: Cmd on macOS, Ctrl on Windows.
- Fonts use the system stack on each OS (Segoe UI Variable on Windows).

## 7. Build, CI, release

- **Toolchain:** `rust-toolchain.toml` adds the targets `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.
- **Windows build script:** `scripts/build-msi.ps1`, the counterpart of `build-dmg.sh`. It runs the release gates:
  - no smoke or debug markers
  - SQLCipher crypto provider check
  - THIRD-PARTY-NOTICES included
  - the bundled wireguard.dll hash
  - the MSI contents
- **SQLCipher on Windows:** `bundled-sqlcipher-vendored-openssl`, as planned in the vault spike. A gate checks the provider.
- **CI:** a `windows-latest` job runs fmt, clippy, tests, UI tests, the helper protocol tests and both MSIs (ARM64 cross-compiled). The macOS jobs are unchanged.
- **Release:** the Release workflow builds the DMG on macOS and the MSIs on Windows, and puts all assets into one draft.
- **Signing:** `sign-release.sh` signs every asset with Ed25519 on the maintainer's machine.
- **Authenticode:** the build has an optional signing step that is off by default.

**Phase 2 blockers** (from the phase 1 review):

- **Update signature domain.** The signed message `macvpn-update-v1\n<version>\n<sha256>\n` binds the bytes, not
  the product or the asset name, and both products share one repo, version line and keys. Before the first signed
  WinVPN asset: keep `macvpn-update-v1` byte for byte for MacVPN; WinVPN gets its own domain that includes the asset
  name, e.g. `winvpn-update-v1\n<asset>\n<version>\n<sha256>\n` (or separate keys). Tests: MacVPN rejects a
  WinVPN-domain signature; WinVPN rejects the x64 signature for the arm64 asset.
- **Importer paths.** `importer::read_inline_data` joins referenced-file paths with `/` as strings and compares the
  canonical path with the base folder as text. On Windows canonical paths are `\\?\C:\…`, so referenced files
  (e.g. `cert user.pem`) resolve to `MissingFile` / `OutsideBaseDirectory`; 24 importer tests are
  `cfg_attr(windows, ignore)` for it.

## 8. Testing

- **Unit tests** run on all OSes in CI.
- **Helper tests:** the black-box tests (`test-root.sh`) are split into shared protocol cases and per-backend cases. The Windows backend gets a PowerShell or Rust harness with fake tools.
- **Smoke test:** the sandboxed UI smoke run also runs on Windows.
- **Manual checklist:** a real Windows 10 and a Windows 11 machine (or VMs), covering:
  - every VPN type
  - the service install and update
  - the vault key in Credential Manager
  - file associations, Mark-of-the-Web, notifications, the tray and launch at login
  - a MacVPN backup restored on WinVPN, and a team catalog shared between both

## 9. Phases

1. **Platform-neutral refactor (release 1.5.0, macOS only).**
   - Add `platform-api`, `fsx`, the transport trait, product identity, per-OS l10n variants, and the `helper` crate split into shared logic plus a macOS backend.
   - MacVPN behaviour is unchanged, and every existing test stays green.
   - The workspace also compiles (`cargo check`) for the Windows targets with a stub platform.
2. **WinVPN core.** `platform-win`, the WinVPN Service, native RAS VPNs, WireGuard, OpenVPN with automatic install, the vault key in Credential Manager, the tray and popover, notifications, file panels and associations, and the MSI.
3. **Release 2.0.0.** MacVPN and WinVPN together, after an independent security review and manual testing on Windows.
4. **Linux.** A `platform-linux` crate on the same base: NetworkManager for native types, wg-quick/OpenVPN, the Secret Service for the vault key, and apt/dnf for dependencies.

Each phase gets its own implementation plan.
