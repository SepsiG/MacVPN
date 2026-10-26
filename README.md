# MacVPN

[English](#english) | [Magyar](#magyar)

---

## English

MacVPN is a menu bar app for macOS that manages OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec and Cisco IPsec connections in one place. **WinVPN** is the same app for Windows 10 and 11, built from this repository and released together with MacVPN. Both are written in Rust with a Tauri user interface. The current version is **2.0.0**, the first full release of both: MacVPN on macOS and WinVPN on Windows.

### What's new in 2.0

**MacVPN and WinVPN**
- **Appearance:** Settings → **Appearance**: **Match System**, **Light** or **Dark**, for the menu and every window.
- **Connection notifications:** when a connection connects, drops, is reconnected or fails, with the reason in plain words; a click opens its Log tab. Settings → **Connection Notifications** turns them off.
- **Missing VPN tools:** a connection whose tool or engine is not installed stays in the list, greyed, with **Not installed: <tool> – System Status**; New and import offer only the types that can be used here.
- **Reconnect automatically** after sleep or a network loss. The app first checks that none of the VPN's own networks or DNS servers is directly reachable on the network (at the office, the VPN stays down), then that it is the same network the connection came up on. A **Reconnect Automatically** switch per connection.
- **Security fixes:** every OpenVPN configuration line is limited to 255 bytes (**Line too long**): a crafted 255-byte line inside an inline block could smuggle forbidden directives past the check in MacVPN 1.5.0 and earlier. A nested `setenv opt` chain is refused too. Update to 2.0.0, especially if you import configurations from others or use team catalogs.

**MacVPN (macOS)**
- **DNS after disconnecting:** one DNS manager in the root layer keeps the original DNS settings on disk and restores them when the last connection that changed them goes down, also after a crash or a restart while connected. A VPN may set at most 16 DNS servers and 32 search domains.
- **Log size:** a connection's log is capped at 5 MiB plus one older part, also while it runs; OpenVPN runs with `--mute 20`.
- **VPN tools up to date:** System Status offers Homebrew updates of the VPN tools (**Update**), and MacVPN runs `brew update` once a day.
- **strongSwan (IKEv2):** the CA, certificates and keys in Homebrew's `etc/swanctl` folders are used at every connect, and two IKEv2 connections at once no longer unload each other.
- **Root layer 9:** after updating from 1.x, System Status shows **Update required (8 → 9)**; click **Authorize** and enter your admin password once.

**WinVPN (Windows): the first WinVPN that connects**
- **OpenVPN and WireGuard** through the **WinVPN Service** that the installer adds. OpenVPN Community is installed from System Status when you need it; wireguard-nt comes with WinVPN.
- **L2TP/IPsec, IKEv2 and SSTP** through Windows' own VPN client, from your own account, without an administrator for the normal case. **Your own Windows VPNs** (Settings → Network & internet → VPN) are listed as system VPNs.
- **Engines update without a new WinVPN:** System Status offers the newest OpenVPN Community and wireguard-nt (checked daily); the Windows VPN client is updated by Windows Update.
- **WinVPN updates itself** from releases signed with the maintainer's offline key; an administrator confirms the installation.
- **HTTPS team catalogs**, and **Remove WinVPN from This Account…** (a clean-up before uninstalling).
- **Hardening:** the WinVPN Service runs only from the administrators-only `C:\Program Files\WinVPN`; downloaded WireGuard and OpenVPN components are checked against their publishers' pinned certificate authorities; a CA added with **Trust This CA in Windows…** is trusted only for server and client authentication. Connection logs are capped at 8 MiB, and OpenVPN `setenv` takes only an allowlist of names.

**Known limits on Windows**
- **Cisco IPsec cannot connect:** Windows has no IKEv1 XAUTH client. Cisco connections from a Mac stay, and **Make an L2TP/IPsec Copy** creates an L2TP/IPsec connection to the same server.
- **IKEv2 with a pre-shared key** is not supported by the Windows IKEv2 client; such connections are kept and shown greyed with the reason.
- **L2TP/IPsec to a server behind NAT** needs a one-time administrator step: **Allow L2TP Behind NAT…** in the error, then a Windows restart.
- The MSI is not Authenticode-signed: SmartScreen warns once.
- The ARM64 MSI is built and checked but not tested on ARM hardware.

Full list: the [2.0.0 release notes](docs/release-notes/2.0.0.md); in the guides: [MacVPN](docs/user-guide.en.md#whats-new-in-20), [WinVPN](docs/winvpn-user-guide.en.md#whats-new-in-20).

### Earlier versions
- **1.5:** the workspace split into shared logic and a platform layer per OS, and the first WinVPN preview (without a VPN engine).
- **1.4:** search in the Connections window, opening VPN files from Finder, a question before importing downloaded files; **1.4.1:** OpenVPN configs whose `cert` and `key` are the same PEM file.
- **1.3:** team catalogs: signed and encrypted connection sets that an administrator publishes.
- **1.2:** the encrypted vault, folders and colours, shared credentials, full backup and restore.
- **1.1:** the control API for paired apps, the credential prompt, the live system VPN list.

Details: the "What's new" chapters of the [user guide](docs/user-guide.en.md) and the [Releases](https://github.com/SepsiG/MacVPN/releases) page.

### Features
- **Six VPN types.** OpenVPN, WireGuard, IKEv2 (strongSwan) and SSTP run through Homebrew tools and MacVPN's root helper. L2TP/IPsec and Cisco IPsec use the built-in macOS VPN. VPNs set up elsewhere in macOS show up as system VPNs, and you can start and stop them from MacVPN too. The list is live: a VPN added, renamed or deleted in System Settings shows up in the menu and the Connections window without reopening them.
- **Encrypted vault.** Connections, configs, passwords, PSKs and key passwords are kept in one encrypted vault (SQLCipher), protected by a master password and a recovery key. With **Unlock automatically** the vault key stays in the macOS Keychain and MacVPN opens without asking; otherwise it asks at launch. **Lock Now** locks it while VPNs keep running.
- **Folders and colours.** Nested folders for your connections and system VPNs, 12 colours, drag and drop, collapsible folders in the menu with a count of active connections.
- **Shared credentials.** A named user name and password that several connections use; change it once for all of them.
- **Full backup and restore.** **Back Up Everything…** writes one encrypted file with every connection, secret, folder and shared credential (and, from 1.3, the team catalog subscriptions and admin keys); **Restore from Backup…** merges it or replaces everything, here or on a new Mac.
- **Team catalogs.** Share connections with a team through one signed (Ed25519) and encrypted (XChaCha20-Poly1305) file, fetched over HTTPS or from a file share or synced folder: refreshed at launch, every 15 minutes and on wake, with rollback protection, credential slots that each member fills in once, and a team key you rotate to revoke access.
- **Import and export.** Choose or drag in one or more files, or double-click a `.ovpn` / `.sstp` file in Finder (a `.conf` through **Open With**). Referenced key files, PKCS#12 files and MikroTik RouterOS configs are handled. Credential files go into the vault if you confirm. Exports never contain passwords, and they only contain private keys if you choose that. Folders and the name of a shared credential travel with the export; a shared credential is never linked on import without asking.
- **Editors.** A config editor with line-numbered errors and a panel for risky OpenVPN settings. Forms for SSTP, L2TP and Cisco IPsec. Passwords, PSKs and key passwords are stored in the vault.
- **Multi-factor authentication.** OpenVPN static and dynamic challenges, sign-in in the browser (SAML, SSO, push), and a one-time code appended to the password for every type that has a password, including system VPNs.
- **Credential prompt.** A user name, password, PSK or key password that is needed but not saved is asked for before connecting, and saved in the vault only after the connection is up (or not at all). A rejected sign-in is asked again once.
- **Other apps can control VPNs.** With the [control API](docs/control-api.md) ([Hungarian](docs/control-api.hu.md)), a program of your user account that you pair, for example a Remote Desktop app, can list the connections you allow and hold one up through a local socket; when it quits, the VPN goes down unless it was up before. It never sees configs or passwords, and you can revoke it any time. Off by default.
- **Order.** Pin connections to the top of their folder and drag them into order. The rest are ranked by how often you use them.
- **Card interface.** Every connection is a card with a coloured type bubble and a state badge, in the menu and in the Connections window. While the Connections, System Status or Update window is open, MacVPN also shows a Dock icon, so Cmd+Tab reaches it.
- **Log.** Every connection has a live log with a filter, search and save. Option-click a switch to connect in debug mode.
- **System Status window.** Installs Homebrew, the VPN tools and the root helper, and uninstalls MacVPN.
- **Reconnect after sleep.** A connection that went down because the Mac slept or the network went away comes back on the same network, unless the VPN's own networks are directly reachable there.
- **Also:** connection notifications, Light and Dark appearance, Launch at Login, signed in-app updates, and an English and Hungarian interface.

### Download and install
Both installers are on the [Releases](https://github.com/SepsiG/MacVPN/releases) page.

**MacVPN (macOS)**
1. Download `MacVPN-x.y.z.dmg`.
2. Open the DMG and drag `MacVPN.app` to the Applications folder.
3. The app is ad-hoc signed, not signed with a Developer ID, so Gatekeeper blocks the first launch. On macOS 14, Control-click (right-click) the app in Applications, choose **Open**, then **Open** again. On macOS 15 or later, open System Settings → Privacy & Security and click **Open Anyway**.
4. In the System Status window, install the missing Homebrew packages and click **Authorize** to install the root helper (one admin password prompt).

**Updating MacVPN from 1.x:** use the in-app update (**Check for Updates Now** in Settings) or install the new DMG over the old app. 2.0 brings root layer 9: System Status shows **Update required (8 → 9)**; click **Authorize** and enter your admin password once. Until then OpenVPN, WireGuard, IKEv2 and SSTP connections are greyed. See [Upgrading from 1.5](docs/user-guide.en.md#84-upgrading-from-15); for older versions [1.2](docs/user-guide.en.md#83-upgrading-from-12), [1.1](docs/user-guide.en.md#82-upgrading-from-11) and [0.x](docs/user-guide.en.md#81-upgrading-from-0x).

**WinVPN (Windows)**
1. Download `WinVPN-x.y.z-x64.msi` (Intel and AMD, most PCs) or `WinVPN-x.y.z-arm64.msi` (ARM, for example Snapdragon).
2. The MSI is not Authenticode-signed, so SmartScreen may warn once: **More info** → **Run anyway**.
3. An administrator installs it, for every user of the PC, into `C:\Program Files\WinVPN`, with the **WinVPN Service**. If the Microsoft Edge WebView2 Runtime is missing (Windows 10), the installer downloads it.
4. Start **WinVPN** from the Start menu; its icon is in the notification area. OpenVPN Community is optional: install it from System Status only if you use OpenVPN connections. WireGuard, L2TP/IPsec, IKEv2 and SSTP need nothing extra.

**Updating WinVPN:** WinVPN offers new versions itself (an administrator confirms the installation), or install the new MSI over the old one. It updates the 1.5.0 preview in place and keeps your data, which is in `%LOCALAPPDATA%\WinVPN`. See [Upgrading from the 1.5 preview](docs/winvpn-user-guide.en.md#81-upgrading-from-the-15-preview).

Step by step: How-to guides for [MacVPN](docs/how-to.en.md) and [WinVPN](docs/winvpn-how-to.en.md).

### Requirements
- **MacVPN:** macOS 14 or later, Apple silicon or Intel; an administrator account (for the one-time root helper install); [Homebrew](https://brew.sh) for OpenVPN, WireGuard, IKEv2 and SSTP. MacVPN installs the packages it needs (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`). L2TP and Cisco IPsec need nothing extra.
- **WinVPN:** Windows 10 or 11, x64 or ARM64; an administrator for the installation and its updates. OpenVPN connections need OpenVPN Community 2.6.0 or later, which System Status installs.

### Documentation
- How-to guide: [English](docs/how-to.en.md), [Hungarian](docs/how-to.hu.md)
- User guide: [English](docs/user-guide.en.md), [Hungarian](docs/user-guide.hu.md) (the menu's **Help** opens it)
- WinVPN user guide (Windows): [English](docs/winvpn-user-guide.en.md), [Hungarian](docs/winvpn-user-guide.hu.md); WinVPN How-to: [English](docs/winvpn-how-to.en.md), [Hungarian](docs/winvpn-how-to.hu.md)
- [OpenVPN directive policy](docs/openvpn-directives.md)
- Control API for other apps on the same Mac or PC: [English](docs/control-api.md), [Hungarian](docs/control-api.hu.md), with an [example client](examples/macvpn-control-client/)
- Release notes: [2.0.0](docs/release-notes/2.0.0.md); all releases on the [Releases](https://github.com/SepsiG/MacVPN/releases) page

### Security note
Root operations are performed by a single binary, `/usr/local/libexec/macvpn/mvpn`, through a sudoers rule. The Homebrew directory is writable by the user, so this setup does not protect against malware running inside your own user account. For SSTP, the password is handed to `sstpc` on its command line (it masks it right away). The vault protects your data at rest; a full backup is as sensitive as the vault, so keep the file and its password apart. A team catalog is signed and encrypted, but everyone with the team key can read it, and whoever holds the admin key decides what your team connects to: see the [team catalog security model](docs/user-guide.en.md#1611-security-model). Details: [Security notes in the user guide](docs/user-guide.en.md#10-security-notes).

On Windows, the WinVPN Service runs as the system (LocalSystem) only from the administrators-only `C:\Program Files\WinVPN`, and serves each user only their own connections. It starts `openvpn.exe` only when OpenVPN Inc. signed it, and `wireguard.dll` only when WireGuard LLC signed it. The MSI is not Authenticode-signed; WinVPN's own updates are checked with the maintainer's offline signature. Details: [Security notes in the WinVPN user guide](docs/winvpn-user-guide.en.md#10-security-notes).

### WinVPN
WinVPN is the same app for Windows 10 and 11 (x64 and ARM64), built from this repository and released together with MacVPN from 2.0.0. Its icon is in the notification area. It connects OpenVPN and WireGuard through the **WinVPN Service** that its MSI installs (OpenVPN Community is installed from System Status; wireguard-nt is bundled), and **L2TP/IPsec, IKEv2 and SSTP** through Windows' own VPN client from the user's account; the user's own Windows VPNs appear as system VPNs. Everything else matches MacVPN: the vault (its auto-unlock key in Windows Credential Manager), the notification-area popover and windows, MFA and credential prompts, debug mode and the live log, import, export, backup, file and HTTPS team catalogs, the control API over a named pipe, and signed self-updates. **Cisco IPsec** connections are kept but cannot connect on Windows (**Make an L2TP/IPsec Copy**), and IKEv2 with a pre-shared key is not supported by Windows. Its data is in `%LOCALAPPDATA%\WinVPN`; the WinVPN Service keeps the OpenVPN and WireGuard logs in `C:\ProgramData\WinVPN`. Guide: [WinVPN user guide](docs/winvpn-user-guide.en.md) ([magyarul](docs/winvpn-user-guide.hu.md)).

### Development
MacVPN is a Cargo workspace with a Tauri 2 user interface (Svelte + TypeScript). The workspace is split into shared logic and a thin platform layer per operating system; the same code ships as MacVPN on macOS and as WinVPN on Windows (a Linux version may follow). Start with [`docs/architecture.md`](docs/architecture.md): the crates, the `cfg` and `unsafe` rules, the per-OS texts and how a platform plugs in.

**Toolchain.** `rust-toolchain.toml` pins the exact Rust version (currently 1.99.1) with clippy, rustfmt, both macOS targets and both Windows targets (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, for the compile check). `rustup` uses it automatically inside the repository; if it is not installed yet, run `rustup toolchain install` there. CI and the release workflow use Node.js 26.8.2 (`app/ui/package.json` needs at least 22.12).

**Build.**
- `scripts/build-dmg.sh` builds the universal `dist/MacVPN.app` and `dist/MacVPN-x.y.z.dmg`: the UI, the app, and the `mvpn` root binary, all signed ad-hoc with the hardened runtime.
- `scripts/build-msi.sh` (in Git Bash on Windows) builds `WinVPN-x.y.z-x64.msi` and `WinVPN-x.y.z-arm64.msi`: the app, the WinVPN Service and wireguard-nt. See [The WinVPN MSIs](docs/architecture.md#the-winvpn-msis).
- Development run without touching real data: `cargo build -p macvpn-app --features custom-protocol` (after `npm run build` in `app/ui`), then `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app`. See [`app/README.md`](app/README.md).

**Tests.**
- `cargo test --workspace`: unit and compatibility tests; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`
- `scripts/test-root.sh`: black-box tests of the root binary (dry run, no root needed)
- `cd app/ui && npm ci && npm test && npm run build`: UI tests (language rule, l10n coverage) and the UI build
- `scripts/check-l10n.sh`: every text (UI and Rust) has a Hungarian translation
- `scripts/check-windows.sh`: `cargo check` of `macvpn-core` (without the vault), `macvpn-helper` and the control client for both Windows targets, from the Mac. The full Windows check (the vault, platform-api, platform-win, winsys, app-core and the app, which need an MSVC toolchain for their C code) runs in CI (the `windows` and `windows-node` jobs in `.github/workflows/ci.yml`) and on a Windows test machine through `scripts/win-remote.sh` (`test`, `run '…'`), see [Checking Windows](docs/architecture.md#checking-windows)
- `scripts/check-ignored.sh`: no test is ignored on one OS only (the list is `scripts/ignored-everywhere.txt`)
- `crates/app-core/tests/cfg_rule.rs` (part of `cargo test`): an OS `cfg` only in the platform places, `unsafe` only in the platform crates, `crates/winsys` and the helper
- `node scripts/l10n-baseline.mjs --check` and `scripts/bundle-baseline.sh dist/MacVPN.app`: the macOS texts and the built bundle compared with the 1.4.0 baseline
- `scripts/smoke-manage.sh`: smoke test of the real windows in a sandbox; run it with `SMOKE_LANG=en` and `SMOKE_LANG=hu`
- `scripts/test-sign-release.sh`: the release signing script, dry run with a throwaway key
- Manual GUI checklist: [`docs/manual-test-checklist.md`](docs/manual-test-checklist.md) (with WinVPN sections for a Windows desktop)

**Repository layout.**
- `crates/core`: platform-independent logic (models, the vault behind the `vault` feature, validators, import/export, MFA, update checks, ranking), the safe file operations (`fsx`, its only OS-specific module) and the EN/HU text table `crates/core/l10n/strings.json`
- `crates/platform-api`: the traits every platform implements, the shared types and the product identity (`Product`)
- `crates/platform-mac`: the macOS platform (Keychain for the vault key, native VPN, login item, dialogs, installers, updater); `crates/platform-win`: the Windows platform (Credential Manager for the vault key, notification-area icon, file dialogs, toasts, launch at login, the control pipe, the WinVPN Service's client, the native VPNs through the Windows VPN client, OpenVPN Community and wireguard-nt installs, the updater); `crates/winsys`: the Win32 calls core and platform-win share (SIDs, ACLs, file identity, randomness, named pipes)
- `crates/helper`: on macOS the root binary `mvpn` (`/usr/local/libexec/macvpn/mvpn`, root layer version in `crates/helper/VERSION`), on Windows the WinVPN Service (`WinVPNService.exe`): shared protocol logic in `src/shared`, the backends in `src/macos` and `src/windows`
- `crates/app-core`: the app logic without a UI
- `app/src-tauri`: the Tauri app (its `src/platform` module picks the platform crate); `app/ui`: its web UI
- `scripts/`: build, test, signing and icon scripts; `Tests/Fixtures`: OpenVPN and MikroTik fixtures
- The 0.x Swift app is only in the git history (up to tag `v0.4.0`); `crates/core/tests/fixtures/swift` keeps data it wrote, frozen, for the compatibility and migration tests.

**Localization.** English is the source language and Hungarian the translation. Every text (UI, app, root binary) is in `crates/core/l10n/strings.json`, keyed by the English (macOS) text; an entry can carry per-OS variants (`variants`, `only`, see [`docs/architecture.md`](docs/architecture.md#texts-per-os)). The app follows the system's preferred languages (the first Hungarian or English one, otherwise English; on macOS a per-app language in System Settings works too). The root binary gets the language through `--lang en|hu`.

**Releasing.** See [`docs/RELEASING.md`](docs/RELEASING.md) for the release procedure and the repository security settings.

### License
MIT – see [LICENSE](LICENSE). Third-party components (among them SQLCipher, BSD-style, © Zetetic LLC) are listed with their licences in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt), which also ships inside the app bundle.

---

## Magyar

A MacVPN egy menüsor-alkalmazás macOS-re, amely egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec és Cisco IPsec kapcsolatokat. A **WinVPN** ugyanez az app Windows 10-re és 11-re, ugyanebből a repóból, a MacVPN-nel együtt kiadva. Mindkettő Rustban készült, Tauri felülettel. A jelenlegi verzió a **2.0.0**, mindkettő első teljes kiadása: a MacVPN macOS-en és a WinVPN Windowson.

### Újdonságok a 2.0-ban

**MacVPN és WinVPN**
- **Megjelenés:** Beállítások → **Megjelenés**: **Rendszer szerint**, **Világos** vagy **Sötét**, a menüre és minden ablakra.
- **Kapcsolatértesítések:** ha egy kapcsolat csatlakozott, megszakadt, újracsatlakozott vagy sikertelen, közérthető okkal; kattintásra a Napló füle nyílik meg. A Beállítások → **Kapcsolatértesítések** kikapcsolja őket.
- **Hiányzó VPN-eszközök:** ha egy kapcsolat eszköze vagy motorja nincs telepítve, a kapcsolat a listában marad, kiszürkítve, **Nincs telepítve: <eszköz> – Rendszerállapot** felirattal; az Új menü és az import csak az itt használható típusokat kínálja.
- **Automatikus újracsatlakozás** alvás vagy a hálózat elvesztése után. Az app először azt nézi, hogy a VPN saját hálózatai és DNS-szerverei közül egyik sem érhető-e el közvetlenül a hálózaton (az irodában a VPN bontva marad), aztán azt, hogy ugyanaz-e a hálózat, amelyen a kapcsolat felépült. Kapcsolatonként **Automatikus újracsatlakozás** kapcsoló.
- **Biztonsági javítások:** minden OpenVPN-konfigurációs sor legfeljebb 255 bájt (**Túl hosszú sor**): egy szándékosan 255 bájtos sor egy beágyazott blokkban a MacVPN 1.5.0-ban és a korábbiakban tiltott direktívákat csempészhetett át az ellenőrzésen. Az egymásba ágyazott `setenv opt` láncot is elutasítja. Frissíts 2.0.0-ra, főleg ha mástól kapott konfigurációt vagy csapatkatalógust használsz.

**MacVPN (macOS)**
- **DNS a bontás után:** a root réteg egyetlen DNS-kezelője lemezen tartja az eredeti DNS-beállításokat, és visszaállítja őket, amikor az utolsó, DNS-t módosító kapcsolat bont, akkor is, ha kapcsolat közben összeomlás vagy újraindítás történt. Egy VPN legfeljebb 16 DNS-szervert és 32 keresési tartományt állíthat be.
- **Naplóméret:** egy kapcsolat naplója futás közben is legfeljebb 5 MiB, plusz egy régebbi rész; az OpenVPN `--mute 20`-szal fut.
- **Friss VPN-eszközök:** a Rendszerállapot felkínálja a VPN-eszközök Homebrew-frissítését (**Frissítés**), és a MacVPN naponta egyszer lefuttatja a `brew update`-et.
- **strongSwan (IKEv2):** a Homebrew `etc/swanctl` mappáiban lévő CA, tanúsítványok és kulcsok minden csatlakozáskor betöltődnek, és két egyszerre élő IKEv2-kapcsolat már nem tölti ki egymást.
- **9-es root réteg:** 1.x-ről frissítve a Rendszerállapot **Frissítés szükséges (8 → 9)** sort mutat; kattints az **Engedélyezés** gombra, és add meg egyszer az admin jelszót.

**WinVPN (Windows): az első WinVPN, amely csatlakozni is tud**
- **OpenVPN és WireGuard** a telepítő által felvett **WinVPN szolgáltatáson** keresztül. Az OpenVPN Communityt a Rendszerállapot telepíti, ha szükséged van rá; a wireguard-nt a WinVPN-nel érkezik.
- **L2TP/IPsec, IKEv2 és SSTP** a Windows saját VPN-kliensével, a saját fiókodból, a szokásos esetben rendszergazda nélkül. **A saját Windows VPN-jeid** (Gépház → Hálózat és internet → VPN) rendszer VPN-ként látszanak.
- **Motorfrissítés új WinVPN nélkül:** a Rendszerállapot a legújabb OpenVPN Communityt és wireguard-nt-t kínálja (naponta ellenőrzi); a Windows VPN-kliensét a Windows Update frissíti.
- **A WinVPN frissíti magát** a fejlesztő offline kulcsával aláírt kiadásokból; a telepítést egy rendszergazda erősíti meg.
- **HTTPS-es csapatkatalógusok**, és **WinVPN eltávolítása erről a fiókról…** (rendbetétel az eltávolítás előtt).
- **Megerősítés:** a WinVPN szolgáltatás csak a rendszergazdák által írható `C:\Program Files\WinVPN`-ből fut; a letöltött WireGuard- és OpenVPN-összetevőket a kiadóik rögzített tanúsítványkiadóihoz ellenőrzi; az **A CA megbízhatóvá tétele a Windowsban…** gombbal hozzáadott CA csak szerver- és kliens-hitelesítésre megbízható. A kapcsolatnaplók legfeljebb 8 MiB-osak, az OpenVPN `setenv` pedig csak egy engedélyezett névlistát fogad el.

**Ismert korlátok Windowson**
- **A Cisco IPsec nem csatlakozik:** a Windowsban nincs IKEv1 XAUTH kliens. A Macről jött Cisco kapcsolatok megmaradnak, és az **L2TP/IPsec másolat készítése** ugyanarra a szerverre L2TP/IPsec kapcsolatot készít.
- **Az előre megosztott kulcsos IKEv2-t** a Windows IKEv2-kliense nem támogatja; az ilyen kapcsolatok megmaradnak, és az okkal együtt szürkén látszanak.
- **NAT mögötti szerverhez az L2TP/IPsec** egyszeri rendszergazdai lépést kér: **L2TP engedélyezése NAT mögött…** a hibaüzenetben, utána a Windows újraindítása.
- Az MSI nincs Authenticode-dal aláírva: a SmartScreen egyszer figyelmeztet.
- Az ARM64 MSI elkészül és ellenőrizzük, de ARM-hardveren még nem teszteltük.

A teljes lista: a [2.0.0 kiadási jegyzete](docs/release-notes/2.0.0.md#magyar); az útmutatókban: [MacVPN](docs/user-guide.hu.md#újdonságok-a-20-ban), [WinVPN](docs/winvpn-user-guide.hu.md#újdonságok-a-20-ban).

### Korábbi verziók
- **1.5:** a workspace közös logikára és operációs rendszerenkénti platformrétegre oszlott, és megjelent az első WinVPN-előzetes (VPN-motor nélkül).
- **1.4:** keresés a Kapcsolatok ablakban, VPN-fájlok megnyitása a Finderből, kérdés a letöltött fájlok importja előtt; **1.4.1:** az az OpenVPN config, amelynek `cert` és `key` sora ugyanaz a PEM fájl.
- **1.3:** csapatkatalógusok: a rendszergazda által közzétett, aláírt és titkosított kapcsolatkészletek.
- **1.2:** a titkosított széf, mappák és színek, közös hitelesítő adatok, teljes biztonsági mentés és visszaállítás.
- **1.1:** a vezérlő API a párosított appoknak, a hitelesítő adatok bekérése, az élő rendszer-VPN lista.

Részletek: az [útmutató](docs/user-guide.hu.md) „Újdonságok” fejezetei és a [Releases](https://github.com/SepsiG/MacVPN/releases) oldal.

### Funkciók
- **Hat VPN-típus.** Az OpenVPN, a WireGuard, az IKEv2 (strongSwan) és az SSTP Homebrew eszközökkel és a MacVPN root segédjével fut. Az L2TP/IPsec és a Cisco IPsec a macOS beépített VPN-jét használja. A macOS-ben máshol beállított VPN-ek rendszer VPN-ként jelennek meg, ezeket is indíthatod és bonthatod a MacVPN-ből. A lista élő: a Rendszerbeállításokban felvett, átnevezett vagy törölt VPN újranyitás nélkül megjelenik a menüben és a Kapcsolatok ablakban.
- **Titkosított széf.** A kapcsolatok, a configok, a jelszavak, a PSK-k és a kulcsjelszavak egyetlen titkosított széfben (SQLCipher) vannak, amelyet mesterjelszó és helyreállítási kulcs véd. **Automatikus feloldás** mellett a széfkulcs a macOS Keychainben marad, és a MacVPN kérdés nélkül megnyílik; különben induláskor kérdez. A **Széf zárolása most** zárol, a VPN-ek közben futnak tovább.
- **Mappák és színek.** Egymásba ágyazható mappák a kapcsolatoknak és a rendszer VPN-eknek, 12 szín, húzás, a menüben csukható mappák az aktív kapcsolatok számával.
- **Közös hitelesítő adatok.** Névvel ellátott felhasználónév és jelszó, amelyet több kapcsolat használ; egyszer módosítod mindegyiknek.
- **Teljes biztonsági mentés és visszaállítás.** A **Teljes biztonsági mentés…** egyetlen titkosított fájlba írja az összes kapcsolatot, titkot, mappát és közös hitelesítő adatot (az 1.3-tól a csapatkatalógus-feliratkozásokat és az aláírókulcsokat is); a **Visszaállítás biztonsági mentésből…** összefésüli vagy mindent lecserél, itt vagy egy új Macen.
- **Csapatkatalógusok.** Kapcsolatok megosztása egy csapattal egyetlen aláírt (Ed25519) és titkosított (XChaCha20-Poly1305) fájlon át, HTTPS-ről, fájlmegosztásról vagy szinkronizált mappából: frissítés induláskor, 15 percenként és ébredéskor, visszaléptetés elleni védelemmel, közös belépési adatok helyeivel, amelyeket minden tag egyszer tölt ki, és cserélhető csapatkulccsal a hozzáférés visszavonásához.
- **Import és export.** Válassz ki vagy húzz be egy vagy több fájlt, vagy kattints duplán egy `.ovpn` / `.sstp` fájlra a Finderben (`.conf` fájlt a **Megnyitás ezzel** menüből). A hivatkozott kulcsfájlokat, a PKCS#12 fájlokat és a MikroTik RouterOS configokat is kezeli. A hitelesítőadat-fájlok tartalma megerősítés után a széfbe kerül. Az export soha nem tartalmaz jelszót, privát kulcsot pedig csak akkor, ha ezt választod. A mappa és a közös hitelesítő adat neve az exporttal utazik; importáláskor a közös hitelesítő adat sosem kapcsolódik kérdés nélkül.
- **Szerkesztők.** Config szerkesztő sorszámozott hibalistával és egy panellel a kockázatos OpenVPN beállításokhoz. Űrlap az SSTP-hez, az L2TP-hez és a Cisco IPsec-hez. A jelszavak, a PSK-k és a kulcsjelszavak a széfbe kerülnek.
- **Többfaktoros hitelesítés.** OpenVPN statikus és dinamikus challenge, böngészős bejelentkezés (SAML, SSO, push), és a jelszó végére fűzött egyszer használatos kód minden jelszavas típusnál, a rendszer VPN-eknél is.
- **Hitelesítő adatok bekérése.** A szükséges, de el nem mentett felhasználónevet, jelszót, PSK-t vagy kulcsjelszót csatlakozás előtt bekéri, és csak a sikeres csatlakozás után menti a széfbe (vagy egyáltalán nem). Elutasított bejelentkezésnél egyszer újra kérdez.
- **Más appok is vezérelhetik a VPN-eket.** A [vezérlő API-val](docs/control-api.hu.md) ([angolul](docs/control-api.md)) a felhasználói fiókod egy általad párosított programja, például egy Remote Desktop app, listázhatja az engedélyezett kapcsolatokat, és egy helyi socketen át fenntarthat egyet; ha kilép, a VPN lebomlik, hacsak nem állt fenn már előtte. Configot és jelszót sosem lát, és bármikor visszavonhatod. Alapból ki van kapcsolva.
- **Sorrend.** A kapcsolatokat kitűzheted a mappájuk elejére, és húzással rendezheted. A többit a használat gyakorisága szerint rendezi.
- **Kártyás felület.** Minden kapcsolat egy kártya színes típusbuborékkal és állapotjelvénnyel, a menüben és a Kapcsolatok ablakban is. Amíg a Kapcsolatok, a Rendszerállapot vagy a Frissítés ablak nyitva van, a MacVPN a Dockban is megjelenik, így Cmd+Tabbal is elérhető.
- **Napló.** Minden kapcsolatnak élő naplója van szűréssel, kereséssel és mentéssel. Option+kattintás a kapcsolón: csatlakozás debug módban.
- **Rendszerállapot ablak.** Telepíti a Homebrew-t, a VPN-eszközöket és a root segédet, és innen távolíthatod el a MacVPN-t.
- **Újracsatlakozás alvás után.** Az a kapcsolat, amely azért bomlott, mert a Mac alvó állapotba került vagy elment a hálózat, ugyanazon a hálózaton visszajön, hacsak a VPN saját hálózatai ott nem érhetők el közvetlenül.
- **Továbbá:** kapcsolatértesítések, világos és sötét megjelenés, indítás bejelentkezéskor, aláírt frissítés az appon belül, magyar és angol felület.

### Letöltés és telepítés
Mindkét telepítő a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalon van.

**MacVPN (macOS)**
1. Töltsd le a `MacVPN-x.y.z.dmg` fájlt.
2. Nyisd meg a DMG-t, és húzd a `MacVPN.app`-ot az Applications mappába.
3. Az app ad-hoc aláírású, nincs Developer ID-vel aláírva, ezért a Gatekeeper az első indításkor letiltja. macOS 14-en kattints a Control billentyűvel (jobb gombbal) az appra az Applications mappában, válaszd a **Megnyitás** pontot, majd újra a **Megnyitás** gombot. macOS 15-ön és újabbon: Rendszerbeállítások → Adatvédelem és biztonság → **Megnyitás mindenképp**.
4. A Rendszerállapot ablakban telepítsd a hiányzó Homebrew csomagokat, majd az **Engedélyezés** gombbal telepítsd a root segédet (egy admin jelszó).

**A MacVPN frissítése 1.x-ről:** használd az appon belüli frissítést (**Frissítések keresése most** a Beállításokban), vagy telepítsd az új DMG-t a régi app fölé. A 2.0 a 9-es root réteget hozza: a Rendszerállapot **Frissítés szükséges (8 → 9)** sort mutat; kattints az **Engedélyezés** gombra, és add meg egyszer az admin jelszót. Addig az OpenVPN-, WireGuard-, IKEv2- és SSTP-kapcsolatok szürkék. Lásd [Frissítés 1.5-ről](docs/user-guide.hu.md#84-frissítés-15-ről); a régebbi verziókhoz: [1.2](docs/user-guide.hu.md#83-frissítés-12-ről), [1.1](docs/user-guide.hu.md#82-frissítés-11-ről) és [0.x](docs/user-guide.hu.md#81-frissítés-0x-verzióról).

**WinVPN (Windows)**
1. Töltsd le a `WinVPN-x.y.z-x64.msi` (Intel és AMD, a legtöbb számítógép) vagy a `WinVPN-x.y.z-arm64.msi` (ARM, például Snapdragon) fájlt.
2. Az MSI nincs Authenticode-dal aláírva, ezért a SmartScreen egyszer figyelmeztethet: **További információ** → **Futtatás mindenképp**.
3. Rendszergazda telepíti, a számítógép minden felhasználójának, a `C:\Program Files\WinVPN` mappába, a **WinVPN szolgáltatással** együtt. Ha a Microsoft Edge WebView2 Runtime hiányzik (Windows 10), a telepítő letölti.
4. Indítsd a **WinVPN**-t a Start menüből; az ikonja az értesítési területen van. Az OpenVPN Community nem kötelező: csak akkor telepítsd a Rendszerállapotból, ha OpenVPN-kapcsolatokat használsz. A WireGuardhoz, az L2TP/IPsec-hez, az IKEv2-höz és az SSTP-hez nem kell semmi más.

**A WinVPN frissítése:** a WinVPN maga kínálja fel az új verziókat (a telepítést egy rendszergazda erősíti meg), vagy telepítsd az új MSI-t a régi fölé. Az 1.5.0-s előzetest helyben frissíti, és megtartja az adataidat, amelyek a `%LOCALAPPDATA%\WinVPN` mappában vannak. Lásd [Frissítés az 1.5-ös előzetesről](docs/winvpn-user-guide.hu.md#81-frissítés-az-15-ös-előzetesről).

Lépésről lépésre: Hogyan használd – [MacVPN](docs/how-to.hu.md) és [WinVPN](docs/winvpn-how-to.hu.md).

### Követelmények
- **MacVPN:** macOS 14 vagy újabb, Apple processzoros vagy Intel Mac; rendszergazdai fiók (a root segéd egyszeri telepítéséhez); [Homebrew](https://brew.sh) az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokhoz. A szükséges csomagokat (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`) a MacVPN telepíti. Az L2TP-hez és a Cisco IPsec-hez nem kell semmi más.
- **WinVPN:** Windows 10 vagy 11, x64 vagy ARM64; rendszergazda a telepítéshez és a frissítésekhez. Az OpenVPN-kapcsolatokhoz OpenVPN Community 2.6.0 vagy újabb kell, ezt a Rendszerállapot telepíti.

### Dokumentáció
- Hogyan használd: [magyar](docs/how-to.hu.md), [angol](docs/how-to.en.md)
- Felhasználói útmutató: [magyar](docs/user-guide.hu.md), [angol](docs/user-guide.en.md) (a menü **Súgó** pontja ezt nyitja meg)
- A WinVPN felhasználói útmutatója (Windows): [magyar](docs/winvpn-user-guide.hu.md), [angol](docs/winvpn-user-guide.en.md); WinVPN – Hogyan csináld: [magyar](docs/winvpn-how-to.hu.md), [angol](docs/winvpn-how-to.en.md)
- [OpenVPN direktíva-szabályok](docs/openvpn-directives.md) (angolul, magyar összefoglalóval)
- Vezérlő API más appoknak ugyanazon a Macen vagy számítógépen: [magyar](docs/control-api.hu.md), [angol](docs/control-api.md), [példaklienssel](examples/macvpn-control-client/) (angolul)
- Kiadási jegyzetek: [2.0.0](docs/release-notes/2.0.0.md#magyar); az összes kiadás a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalon

### Biztonsági megjegyzés
A root műveleteket egyetlen bináris, a `/usr/local/libexec/macvpn/mvpn` végzi egy sudoers szabályon keresztül. A Homebrew könyvtára a felhasználó által írható, ezért a megoldás nem véd a felhasználói fiókon belül futó kártevő ellen. SSTP-nél a jelszó az `sstpc` parancssorában adódik át (az azonnal kicsillagozza). A széf a tárolt adatokat védi; a teljes biztonsági mentés ugyanolyan érzékeny, mint a széf, ezért a fájlt és a jelszavát tartsd külön. A csapatkatalógus alá van írva és titkosítva van, de akinél megvan a csapatkulcs, elolvashatja, és aki az aláírókulcsot birtokolja, az dönti el, mihez csatlakozik a csapatod: lásd [a csapatkatalógusok biztonsági modelljét](docs/user-guide.hu.md#1611-biztonsági-modell). Részletek: [Biztonsági megjegyzések az útmutatóban](docs/user-guide.hu.md#10-biztonsági-megjegyzések).

Windowson a WinVPN szolgáltatás a rendszer nevében (LocalSystem) fut, csak a rendszergazdák által írható `C:\Program Files\WinVPN`-ből, és minden felhasználónak csak a saját kapcsolatait szolgálja ki. Az `openvpn.exe`-t csak az OpenVPN Inc., a `wireguard.dll`-t csak a WireGuard LLC aláírásával indítja. Az MSI nincs Authenticode-dal aláírva; a WinVPN saját frissítéseit a fejlesztő offline aláírása védi. Részletek: [Biztonsági megjegyzések a WinVPN útmutatójában](docs/winvpn-user-guide.hu.md#10-biztonsági-megjegyzések).

### WinVPN
A WinVPN ugyanez az app Windows 10-re és 11-re (x64 és ARM64), ugyanebből a repóból, a 2.0.0-tól a MacVPN-nel együtt kiadva. Az ikonja az értesítési területen van. Az OpenVPN- és WireGuard-kapcsolatokat az MSI által telepített **WinVPN szolgáltatáson** keresztül építi fel (az OpenVPN Communityt a Rendszerállapot telepíti, a wireguard-nt a csomag része), az **L2TP/IPsec, IKEv2 és SSTP** kapcsolatokat pedig a Windows saját VPN-kliensével, a felhasználó fiókjából; a felhasználó saját Windows VPN-jei rendszer VPN-ként jelennek meg. Minden más olyan, mint a MacVPN-ben: a széf (az automatikus feloldás kulcsa a Windows Hitelesítőadat-kezelőjében), a popover és az ablakok az értesítési területen, MFA és hitelesítőadat-bekérés, debug mód és élő napló, import, export, mentés, fájl- és HTTPS-alapú csapatkatalógusok, a vezérlő API névvel ellátott csövön, és aláírt önfrissítés. A **Cisco IPsec** kapcsolatok megmaradnak, de Windowson nem csatlakoznak (**L2TP/IPsec másolat készítése**), a PSK-s IKEv2-t pedig a Windows nem támogatja. Az adatai a `%LOCALAPPDATA%\WinVPN` mappában vannak; az OpenVPN- és WireGuard-naplókat a WinVPN szolgáltatás a `C:\ProgramData\WinVPN` mappában tartja. Útmutató: [WinVPN felhasználói útmutató](docs/winvpn-user-guide.hu.md) ([angolul](docs/winvpn-user-guide.en.md)).

### Fejlesztés
A MacVPN egy Cargo workspace, Tauri 2 felülettel (Svelte + TypeScript). A workspace közös logikára és operációs rendszerenként egy vékony platformrétegre oszlik; ugyanez a kód macOS-en MacVPN, Windowson WinVPN néven fut (később Linux-változat is jöhet). Kezdd a [`docs/architecture.md`](docs/architecture.md) leírással (angolul): a crate-ek, a `cfg` és az `unsafe` szabályai, az operációs rendszerenkénti szövegek, és hogyan csatlakozik egy új platform.

**Eszközök.** A `rust-toolchain.toml` rögzíti a pontos Rust verziót (jelenleg 1.99.1) a clippyvel, a rustfmt-vel, mindkét macOS és mindkét Windows targettel (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, a fordítási ellenőrzéshez). A repón belül a `rustup` automatikusan ezt használja; ha még nincs telepítve, futtasd ott: `rustup toolchain install`. A CI és a kiadási workflow Node.js 26.8.2-t használ (az `app/ui/package.json` legalább 22.12-t kér).

**Build.**
- `scripts/build-dmg.sh`: a universal `dist/MacVPN.app` és `dist/MacVPN-x.y.z.dmg`: a felület, az app és a `mvpn` root bináris, mind ad-hoc aláírva, hardened runtime-mal.
- `scripts/build-msi.sh` (a Windowson futó Git Bashben): a `WinVPN-x.y.z-x64.msi` és a `WinVPN-x.y.z-arm64.msi`: az app, a WinVPN szolgáltatás és a wireguard-nt. Lásd [The WinVPN MSIs](docs/architecture.md#the-winvpn-msis) (angolul).
- Fejlesztői futtatás a valódi adatok érintése nélkül: `cargo build -p macvpn-app --features custom-protocol` (az `app/ui`-ban futtatott `npm run build` után), majd `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app`. Lásd [`app/README.md`](app/README.md) (angolul).

**Tesztek.**
- `cargo test --workspace`: unit- és kompatibilitási tesztek; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`
- `scripts/test-root.sh`: a root bináris fekete dobozos tesztje (dry-run, nem kell root)
- `cd app/ui && npm ci && npm test && npm run build`: a felület tesztjei (nyelvválasztás, lokalizáció-lefedettség) és buildje
- `scripts/check-l10n.sh`: minden szövegnek (felület és Rust) van magyar fordítása
- `scripts/check-windows.sh`: a `macvpn-core` (széf nélkül), a `macvpn-helper` és a vezérlő kliens `cargo check`-je mindkét Windows targetre, a Macen. A teljes Windows-ellenőrzés (a széf, a platform-api, a platform-win, a winsys, az app-core és az app, amelyek C kódjához MSVC eszközlánc kell) a CI-ban fut (a `.github/workflows/ci.yml` `windows` és `windows-node` jobja), és egy windowsos tesztgépen a `scripts/win-remote.sh`-val (`test`, `run '…'`), lásd [Checking Windows](docs/architecture.md#checking-windows) (angolul)
- `scripts/check-ignored.sh`: egyetlen teszt sincs csak az egyik operációs rendszeren kihagyva (a lista: `scripts/ignored-everywhere.txt`)
- `crates/app-core/tests/cfg_rule.rs` (a `cargo test` része): operációsrendszer-függő `cfg` csak a platformrétegben, `unsafe` csak a platform crate-ekben, a `crates/winsys`-ban és a helperben
- `node scripts/l10n-baseline.mjs --check` és `scripts/bundle-baseline.sh dist/MacVPN.app`: a macOS-es szövegek és a kész app összevetése az 1.4.0-s alapállapottal
- `scripts/smoke-manage.sh`: a valódi ablakok smoke tesztje egy sandboxban; futtasd `SMOKE_LANG=en` és `SMOKE_LANG=hu` mellett is
- `scripts/test-sign-release.sh`: a kiadás-aláíró script próbafuttatása eldobható kulccsal
- Kézi GUI tesztlista: [`docs/manual-test-checklist.md`](docs/manual-test-checklist.md) (WinVPN-részekkel a windowsos asztali ellenőrzésekhez)

**A repó felépítése.**
- `crates/core`: platformfüggetlen logika (modellek, a `vault` feature mögötti széf, validátorok, import/export, MFA, frissítés-ellenőrzés, rangsor), a biztonságos fájlműveletek (`fsx`, az egyetlen operációsrendszer-függő modulja) és az EN/HU szövegtábla, a `crates/core/l10n/strings.json`
- `crates/platform-api`: a trait-ek, amelyeket minden platform megvalósít, a közös típusok és a termékazonosság (`Product`)
- `crates/platform-mac`: a macOS-platform (Keychain a széfkulcsnak, natív VPN, bejelentkezési elem, párbeszédablakok, telepítők, frissítő); `crates/platform-win`: a Windows-platform (a Hitelesítőadat-kezelő a széfkulcsnak, ikon az értesítési területen, fájlpárbeszédek, értesítések, indítás bejelentkezéskor, a vezérlő cső, a WinVPN szolgáltatás kliense, a natív VPN-ek a Windows VPN-kliensén át, az OpenVPN Community és a wireguard-nt telepítése, a frissítő); `crates/winsys`: a core és a platform-win közös Win32-hívásai (SID-ek, ACL-ek, fájlazonosítás, véletlenszámok, named pipe-ok)
- `crates/helper`: macOS-en az `mvpn` root bináris (`/usr/local/libexec/macvpn/mvpn`, a root réteg verziója a `crates/helper/VERSION`-ben), Windowson a WinVPN szolgáltatás (`WinVPNService.exe`): a közös protokollogika az `src/shared`, a backendek az `src/macos` és az `src/windows` alatt
- `crates/app-core`: az app logikája felület nélkül
- `app/src-tauri`: a Tauri app (az `src/platform` modulja választja ki a platform crate-et); `app/ui`: a webes felülete
- `scripts/`: build-, teszt-, aláíró és ikon scriptek; `Tests/Fixtures`: OpenVPN és MikroTik tesztadatok
- A 0.x Swift app csak a git történetben van meg (a `v0.4.0` tagig); a `crates/core/tests/fixtures/swift` az általa írt adatokat őrzi, befagyasztva, a kompatibilitási és migrációs tesztekhez.

**Lokalizáció.** Az angol a forrásnyelv, a magyar a fordítás. Minden szöveg (felület, app, root bináris) a `crates/core/l10n/strings.json`-ban van, a kulcs az angol (macOS-es) szöveg; egy bejegyzésnek lehetnek operációs rendszerenkénti változatai (`variants`, `only`, lásd [`docs/architecture.md`](docs/architecture.md#texts-per-os)). Az app a rendszer preferált nyelveit követi (az első magyar vagy angol, különben angol; macOS-en a Rendszerbeállításokban appra beállított nyelv is működik). A root bináris a `--lang en|hu` kapcsolóból kapja a nyelvet.

**Kiadás.** A kiadás menete és a repó biztonsági beállításai: [`docs/RELEASING.md`](docs/RELEASING.md) (angolul).

### Licenc
MIT – lásd [LICENSE](LICENSE). A külső összetevők (köztük az SQLCipher, BSD-típusú, © Zetetic LLC) licencei a [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) fájlban vannak, amely az app csomagjában is megtalálható.

---

## Support / Támogatás

If you find MacVPN useful, you can buy me a coffee. / Ha tetszik a MacVPN, egy kávéval támogathatod a fejlesztést.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/X8X01DODMO)
