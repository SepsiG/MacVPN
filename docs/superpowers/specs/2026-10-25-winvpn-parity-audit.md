# WinVPN parity audit: every MacVPN feature and its Windows state after 2b

**Date:** 2026-10-25 · **Plan:** `docs/superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md`, Task 1 · **Code base audited:** `winvpn-2b` at `e39d036` (2b Tasks 1–21 and fixes merged; features plan Task 1 merged). Features plan Tasks 2 and 4 were merged into `winvpn-2b` after this base (`00e485e`, `3ff4a6f`); they are named where they matter.

**The requirement (maintainer, 2026-10-24, binding):** "A Windows-os verziónak is teljesnek kell lennie, mint az eredeti Mac-esnek" — WinVPN 2.0.0 must be as complete as MacVPN. Cisco IPsec on Windows: option A (kept, cannot connect, a clear message and **Make an L2TP/IPsec Copy**). A cross-platform Docker VPN lab exists (2c Task 4).

## Method

The MacVPN feature list was derived from the sources, not from memory: `docs/user-guide.en.md` (every section, "What's new in 1.1–1.5"), `docs/how-to.en.md`, `docs/control-api.md`, `docs/manual-test-checklist.md` (every macOS section), `docs/architecture.md`; the app's 140 Tauri commands (`grep -A1 '#\[tauri::command\]' app/src-tauri/src/*.rs`), the tray (`app/src-tauri/src/tray.rs`), the app menu (`app/src-tauri/src/main.rs:445`), the UI (`app/ui/src/**`: every OS branch is in `keys.ts` and the l10n variants; the components are OS-neutral), the platform traits (`crates/platform-api/src/*.rs`), `platform-mac` versus `platform-win` (every `Inert`, `unsupported(…)`, `io_unsupported(…)`, `NoEngine`, "later" and `None` answer of `crates/platform-win/src/win/platform.rs`), the WinVPN Service (`crates/helper/src/windows/**`) versus the macOS root layer (`crates/helper/src/macos/**`), the l10n table (`crates/core/l10n/strings.json`: every macOS-worded text and its `only` / `variants.windows`), and the smoke run (`app/src-tauri/src/platform/smoke/mod.rs`, `scripts/smoke-manage.sh`: every "skipped on Windows").

**Status legend**

| Status | Meaning |
|---|---|
| **Done** | works on Windows after 2b with MacVPN's behaviour (some items still have an open desktop checkpoint, noted) |
| **Equivalent** | intentionally OS-specific; the Windows counterpart is named |
| **By design** | a documented deviation (the reason is given); no work |
| **2c Tn** | a gap an existing task of the 2c plan closes |
| **FP Tn** | a gap the features plan (`2026-10-25-features-2-0.md`) closes |
| **G-n** | a gap no plan covered: a new sub-task of 2c Task 15 |

## Summary

- **Features audited: 112** (rows 1–112 below).
- Done: 50 · Equivalent: 18 · By design: 7 · maintainer decision: 2 (rows 11 and 103 → G-9) · gaps: 35, of which 21 are closed by existing 2c tasks (row 38 also needs G-3), 4 by the features plan (rows 8, 9, 53, 97, both OSes), 9 only by the new G-items (rows 6, 14, 43, 45, 65, 66, 68, 73, 112), and 1 shared (row 111: G-8, 2c Task 14, features plan Task 15). **New gaps: G-1 … G-11.**
- **New gaps (2c Task 15):**

| Gap | What | Closed by |
|---|---|---|
| G-1 | No daily background re-check of engine versions on Windows (macOS runs `brew update` daily, `e13affa`) | 2c Task 15 (G-1) |
| G-2 | The Log tab and debug mode of L2TP/Cisco use the macOS `log stream` collector; on Windows it is inert and the RAS log would never show | 2c Task 15 (G-2), with Task 8 |
| G-3 | Deleting a native connection (or a folder with one) opens Settings → VPN and tells the user to remove the entry; after 2c WinVPN deletes its own entry | 2c Task 15 (G-3), with Task 6 |
| G-4 | A missing / broken WinVPN Service still blocks native and system VPN connects in the `connect` command and the control API (`engine_missing` gates outside `SetupReport::is_available`) | 2c Task 15 (G-4), with Task 6 |
| G-5 | The credential re-prompt after a rejected sign-in (IKEv2 EAP, SSTP) needs the RAS `up` to wait for the dial result and the auth error texts to be sign-in failures | 2c Task 15 (G-5), with Tasks 7/8 |
| G-6 | Debug mode on Windows has no "diagnostics (before/after)" block and no WireGuard peer status (`wg show`) | 2c Task 15 (G-6) |
| G-7 | The tray icon keeps its old tint when the taskbar switches light/dark while WinVPN is idle | 2c Task 15 (G-7) |
| G-8 | The Windows smoke skips the logout quit request and the popover's rounded corners | 2c Task 15 (G-8) |
| G-9 | No in-app uninstall / clean-up on Windows (MacVPN: **Uninstall MacVPN…** with "Also delete user data"); after 2c also RAS entries and their PSKs stay | **maintainer decision**, then 2c Task 15 (G-9) |
| G-10 | Documentation parity: the WinVPN guide has no debug/log, troubleshooting, MFA and credential-prompt sections; no WinVPN How-to; `control-api.md` is macOS-only | 2c Task 15 (G-10) → Task 16 |
| G-11 | Importing a `.mobileconfig` on Windows shows the macOS-only "Double-click it in Finder" text | 2c Task 15 (G-11) |

- **Maintainer decisions needed:** G-9 (in-app clean-up on Windows, revisiting the 2a "by design" decision); and a confirmation for row 21 (under option A the features plan's engine gate hides **New → Cisco IPsec** on Windows; restored, imported and catalog Cisco connections stay, greyed).
- **Corrections to the 2c plan's preliminary table:** row 8 — `SystemVpnWatch::start` on Windows returns an inert `Ok` guard (`platform.rs:439`), not an `io::Error`; row 20 is a real gap (G-1); row 31 is G-9 (decision); row 32 gains G-8.

---

## A. Installation, System Status, engines

| # | MacVPN feature (source) | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 1 | Installer (guide 1.1–1.2) | DMG, drag to Applications, Gatekeeper's first-launch approval | MSI (WiX, `tauri.windows.conf.json`), SmartScreen note (guide 1.2) | Equivalent | – |
| 2 | Package manager and VPN tools (guide 1.3) | System Status installs Homebrew and `openvpn`, `wireguard-tools`, `strongswan`, `sstp-client` | the WinVPN Service and wireguard.dll come with the MSI; OpenVPN Community installed from System Status (`win/openvpn_install.rs`, 2b T17) | Equivalent | – |
| 3 | Privileged layer (root layer 8 + sudoers) | "Allow" installs `mvpn` with one admin prompt; upgrade 6→7→8 | the WinVPN Service (LocalSystem, `\\.\pipe\WinVPN`), installed and upgraded by the MSI; `install_helper` / `uninstall_helper` answer unsupported (`platform.rs:400`, `:404`) | Equivalent | – |
| 4 | System Status rows (guide 2) | Homebrew, tools, root layer rows; "!" mark on the tile while incomplete; opens by itself when incomplete | service, OpenVPN, WireGuard rows (`pure/engine.rs`, `SystemSetup::check` `platform.rs:359`); the tile mark and auto-open follow `SetupReport::is_complete` (neutral) | Done | native rows: 2c T6, T9, T11 |
| 5 | Engine updates offered (2b fix5, fix4) | `brew outdated` → "Update" in System Status | OpenVPN: winget / newest official MSI (`openvpn_install::upgrade`); wireguard-nt: the service updates it (`service_client.rs:106`, `:113`) | Done | – |
| 6 | Daily package-index refresh (`e13affa`, guide 1.3) | `brew update` a minute after launch when > 24 h old, then daily; System Status re-checked after a success | `SystemSetup::update_package_index` keeps its default `Unavailable` (`platform-api/src/setup.rs:188`); `check` asks winget / the service only when System Status opens or "Check Again" (`platform.rs:363`: `ask = !launch`) | **Gap** | **G-1** |
| 7 | Native VPN engine (spec 4.2) | macOS' own VPN client, no install | `NoEngine` for `native_controller` / `native_profiles` (`platform.rs:190`, `:194`; `win/not_yet.rs`); `later_kinds` for L2TP, Cisco, IKEv2, SSTP (`pure/engine.rs:25`); `later_note` (`platform.rs:417`) | Gap | 2c T5–T9, T11 |
| 8 | "Missing tool" rows and their System Status link | "%@ · Missing tool", kind not creatable | same text; the named engine and link are new for both OSes | Gap (both OSes) | FP T4 (merged after base), T8, T13 |
| 9 | Kinds whose engine is missing hidden from "New" and import | – (new in 2.0.0) | – | Gap (both OSes) | FP T8, T13; RAS row: 2c T6 |
| 10 | System Status keeps working while an install runs (checklist "Életciklus") | `brew install` continues with the window closed | OpenVPN install runs elevated in its own process (`--winvpn-openvpn-step`, `app/src-tauri/src/platform/windows.rs` `helper_mode`) | Equivalent | – |
| 11 | Uninstall note in System Status | "Uninstall MacVPN…" button | "Open Installed Apps…" note (`platform.rs:422`, `:426`) | By design (2a) / decision | see row 103, **G-9** |

## B. Menu bar / tray, windows, keyboard

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 12 | Menu bar icon and popover (guide 2) | template icon; click opens the popover below it | tray icon, tinted for the taskbar (`chrome.rs:120`); left click opens the popover above it (`tray.rs:272`, `placement`) | Equivalent | – |
| 13 | Icon states | idle / connecting / connected / waiting for authentication | the same images, recoloured (`tray.rs:198`) | Done | – |
| 14 | Icon follows the system appearance | template image: automatic | tint read again only when the icon changes (`chrome.rs:119`); an idle taskbar theme switch keeps the old tint | **Gap** | **G-7** |
| 15 | Popover cards, tiles, Settings group, Help, Lock Now, Quit (guide 2, checklist "kártyás felület") | – | same UI (`Menu.svelte`, OS-neutral) | Done | – |
| 16 | Popover rounded corners | AppKit layer mask, radius 12 | Windows 11 DWM rounded corners (`WindowChrome::round_corners`, `window_corner_radius`) | Equivalent | smoke check: **G-8** |
| 17 | Dock icon while a window is open (1.1) | Dock icon + Cmd+Tab; Dock click restores windows | a taskbar button per window (`platform/windows.rs` `set_window_presence` no-op); a second launch brings windows forward (`show_yourself`) | Equivalent | – |
| 18 | App menu: Quit (Cmd+Q), Edit menu, Close Window (Cmd+W) (`main.rs:445`) | – | no app menu (`uses_app_menu() = false`); Quit in the popover; Alt+F4 closes a window through the same unsaved-changes guard (`manage.rs` `CloseRequested`); WebView2 handles Ctrl+C/V/X/A/Z | Equivalent | – |
| 19 | Cmd+S / Cmd+F | save in an editor, search | Ctrl+S / Ctrl+F (`keys.ts:12`) | Done | – |
| 20 | Option-click = debug connect | Option-click on a switch | Alt-click (`MenuRow.svelte:22`; l10n `variants.windows` "Alt-click a switch: debug mode") | Equivalent | – |
| 21 | New connection of each kind (guide 3) | New → OpenVPN, WireGuard, IKEv2, SSTP, L2TP, Cisco IPsec | all six offered; native kinds save but cannot connect yet | Done (editing) | connecting: 2c; Cisco under A: the FP T8 gate hides **New → Cisco IPsec** on Windows once `is_available(Cisco)` is false (2c T6) — **maintainer to confirm** |
| 22 | Appearance (light/dark) | follows macOS | follows Windows (`prefers-color-scheme` in WebView2) | Done | Theme setting: FP T3 |
| 23 | Reduce motion | no animation | `prefers-reduced-motion` follows Windows' "Animation effects" | Equivalent | – |
| 24 | Single instance | macOS opens one instance | per-user instance claim and file forwarding (`win/instance.rs:55`) | Equivalent | – |

## C. Connections and editors

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 25 | OpenVPN editor, three directive tiers, argument checks (guide 3.1) | validated, risky panel, forbidden list | the same validator with the Windows tier (`validate_for(TargetOs::Windows)`, 2b T2) | Done | – |
| 26 | OpenVPN key password, PKCS#12, encrypted PEM, combined PEM (1.4.1) | key password from the vault | `ovpn_args::argv(…, keypass)` (`helper/src/windows/ovpn_args.rs:112`) | Done | CP3 desktop items open |
| 27 | WireGuard editor (guide 3.2) | `wg-quick` keys checked | the same validator; wireguard-nt plan (`wg_plan.rs`); `FwMark`/`Table` limits documented (2b) | Done | – |
| 28 | IKEv2 editor (guide 3.3) | `swanctl.conf`, default-deny | same editor; cannot connect (`later_kinds`) | Gap | 2c T3, T7, T8, T11 |
| 29 | IKEv2 features Windows lacks (EAP-TLS, certificate files, IKEv1, `remote id` ≠ address) | supported by strongSwan | – | By design | reasons: 2c T3, T11 |
| 30 | SSTP form (guide 3.6) | System CA / Custom CA / No verification, route all, server DNS | same form; cannot connect | Gap | 2c T3, T8, T11, T12 |
| 31 | SSTP "No verification" | `--cert-warn` | – (Windows always checks) | By design | reason: 2c T3, T11 |
| 32 | SSTP "Use the server's DNS" off | DNS untouched | – (best effort through the metric) | By design | 2c T3, T16 |
| 33 | L2TP/IPsec form, **Save and Install Profile** (guide 3.4) | `.mobileconfig` staged, approved in System Settings | saves; `install` answers "later" (`not_yet.rs:39`) | Gap | 2c T5–T8, T11 (Save without approval) |
| 34 | Cisco IPsec form (guide 3.4) | IKEv1 XAUTH through macOS | saves; cannot connect | Gap (option A) | 2c T12 (message, **Make an L2TP/IPsec Copy**) |
| 35 | Unsaved-changes question (Save / Discard / Cancel) on switch, close, quit | – | neutral (`ConnectionsModel::should_close_window`) | Done | – |
| 36 | Stored secrets never shown, "Remove saved password" | – | neutral | Done | – |
| 37 | Save errors with line numbers (guide 3.6) | – | neutral | Done | – |
| 38 | Delete a connection | confirmation; a native one opens the Profiles pane ("remove the profile yourself") | the same path opens `ms-settings:network-vpn` (`manage.rs:243`, `folders.rs:87`) with a Windows variant "remove it yourself in Settings → VPN" (`Detail.svelte:138`) | Gap after 2c | entry removal: 2c T6/T8; the Settings page and text: **G-3** |
| 39 | Several connections up at once (checklist "Életciklus") | e.g. WireGuard + IKEv2 | service kinds side by side (2b); RAS + service: untested | Gap (verification) | 2c T16 checklist |

## D. Connecting, credentials, MFA

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 40 | Connect / disconnect OpenVPN, WireGuard (guide 5) | through the root layer | through the WinVPN Service (`service_client.rs`, `helper/src/windows/sys/{openvpn,wireguard}.rs`) | Done | – |
| 41 | Connect IKEv2 / SSTP | `charon` / `sstpc` | the service answers "Not available on this system yet" | Gap | 2c T8 |
| 42 | Connect L2TP / Cisco (native) | `SCNetworkConnectionStart`, PSK in-process | `NoEngine::start` → `native_later` (`not_yet.rs:23`) | Gap | 2c T8; Cisco: T12 (A) |
| 43 | Connect gate when the privileged layer is missing | root layer missing greys the root kinds only; native kinds and system VPNs need nothing (`control.rs` `setup_ready_for`) | `engine_missing` (no / broken service) blocks every connect, also native and system VPNs: `commands.rs:116`, `app/src-tauri/src/control.rs:414` (`connect_key`), `crates/app-core/src/control.rs:1474` | **Gap** | **G-4** (with 2c T6) |
| 44 | Credentials asked when connecting (guide 5.3) | missing user / password / PSK / key password asked; saved after success | neutral (`credential_prompt.rs`, `credentials::required_fields`: L2TP/Cisco user + password + PSK, SSTP password, IKEv2 EAP user + password) | Done | RAS kinds verified: 2c T8 |
| 45 | One re-prompt after a rejected sign-in (1.1, 1.2: IKEv2 EAP too) | `credentials::is_sign_in_failure` on the `up` error (`manager.rs:1660`, `credentials.rs:254`) | OpenVPN through the service: same; RAS kinds: their `up` result and texts are not yet defined | **Gap** | **G-5** (with 2c T7/T8) |
| 46 | OTP code appended to the password (guide 5.2, checklist MFA) | all kinds incl. system VPNs; separators none / `,` / `:` | neutral (manager builds the password) | Done | RAS kinds: 2c T8 test |
| 47 | OpenVPN static challenge, CRV1, CR_TEXT, web sign-in (guide 5.2, 7.11) | the root layer's management bridge | the service's in-process bridge (`helper/src/windows/sys/mgmt.rs`), `auth-state` over the pipe (`platform.rs:199`) | Done | 2b CP3 desktop items open |
| 48 | MFA prompt window (no focus theft, arm delay, timeout) | – | neutral (`prompt.rs`, prompt windows) | Done | – |
| 49 | Connection order: pins, usage score (guide 5.1) | – | neutral | Done | – |
| 50 | Status after a relaunch ("keep running") | root layer connections found again | service connections found again (2b); RAS: not yet | Done / Gap | RAS: 2c T8 (`a_relaunch_finds_a_running_dial`) |
| 51 | IP address and uptime on the card | – | service kinds: done; RAS: `RasGetProjectionInfoEx` | Done / Gap | RAS: 2c T8 |
| 52 | DNS restored after disconnect (2b `f562e4e`) | DNS ledger | WireGuard adapter-bound DNS cleared (`288bfae`); OpenVPN's own; RAS: Windows owns the adapter | Done / Equivalent | RAS checklist: 2c T16 |
| 53 | Auto-reconnect after sleep / network loss | – (new in 2.0.0) | – | Gap (both OSes) | FP T5, T6, T10, T11, T14; RAS through the same `up`/`start` (2c T8) |

## E. System VPNs

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 54 | System VPNs listed with type and status (guide 3.5) | `scutil --nc list`, "· System VPN" | none listed (`not_yet.rs:15`) | Gap | 2c T9 |
| 55 | Connect / disconnect a system VPN | `SCNetworkConnection` | `native_later` | Gap | 2c T9 |
| 56 | Stored PSK / password for L2TP/Cisco system VPNs, "Forget Saved Secrets" | vault, keyed by the service UUID | neutral code (`editor::save_system_secrets`); needs GUID ids | Gap | 2c T9 (GUID id, `RasSetCredentialsW` for the PSK) |
| 57 | PSK hint when a system L2TP VPN fails without one | `manager.rs:1444` | neutral; works with L2TP labels | Done once T9 lists | 2c T9 |
| 58 | Live list (1.1): watcher + poll fallback | `SCPreferences` watcher, poll | `SystemVpnWatch::start` returns an inert `Ok` guard (`platform.rs:439`); poll only (nothing listed) | Gap | 2c T5, T9 |
| 59 | "This VPN was removed from macOS" banner | – | Windows variant exists ("removed from Windows") | Done (text) | 2c T9 (removal detection) |
| 60 | System VPNs in folders and the order | – | neutral | Done | – |
| 61 | Settings link of a system VPN | "Its settings are in System Settings" | Windows variant ("Settings"); `open_native_profile_settings` = `ms-settings:network-vpn` (`platform.rs:343`) | Done | – |

## F. Logs and debug mode

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 62 | Live Log tab, last 5000 lines, filters, search, follow, Copy, Save… (guide 6) | `/var/log/macvpn/<id>.log` tail | the service's `log <id> <offset>` (`service_client.rs:187` `PipeLogSource`) | Done | – |
| 63 | Log masking and size caps (2b `288bfae`) | – | same masks and caps in the service (2b) | Done | RAS logs: 2c T8 |
| 64 | Debug mode: OpenVPN `--verb 5` | – | `--verb 5` (`ovpn_args.rs:118`) | Done | – |
| 65 | Debug mode: WireGuard `wg show` after connect | `wireguard.rs:92` (macOS) | nothing (no peer status in the service log) | **Gap** | **G-6** |
| 66 | Debug mode: diagnostics before/after (server resolution, routing table, DNS, interfaces) | `updown.rs:128` `snapshot` | nothing in `helper/src/windows/**` | **Gap** | **G-6** |
| 67 | Debug mode: IKEv2 IKE log, SSTP `sstpc`/`pppd` log | charon / sstpc | – | Gap | 2c T7, T8 (RAS dial states, the entry's settings in debug) |
| 68 | Native (L2TP/Cisco) debug log: `log stream` for 60 s; outside debug "Native connections only have a log when connected in debug mode." | `NativeLogCollector` (`app-core/src/logs.rs:136`), started in `commands.rs:137` | `log_streams` is `Inert` (`platform.rs:203`: "Not available on this system yet"); `LogFeed::new` always uses the collector for native kinds (`logs.rs:362`), so Task 8's RAS log for L2TP would never reach the Log tab | **Gap** | **G-2** (with 2c T8) |
| 69 | Saved log is private (0600) | – | `exporter::write` with the private ACL (2a) | Done | – |

## G. Import, export, files

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 70 | Import from file / drag and drop, referenced files embedded (guide 4) | – | neutral; Tauri drop on Windows | Done | – |
| 71 | Export without passwords; keys question (guide 4) | – | neutral | Done | – |
| 72 | Native export as `.mobileconfig` | installable by a double-click on a Mac | the same `.mobileconfig` (`import_export.rs:210`); Windows cannot install it | By design (spec 5: no Windows-only format) | guide note: G-10 |
| 73 | `.mobileconfig` import refused with a hint | "Double-click it in Finder…" (`importer.rs:50`, `only: ["macos"]`) | the macOS-only text is shown on Windows too | **Gap** | **G-11** |
| 74 | File associations (1.4): `.ovpn`, `.sstp` default, `.conf` Open With, `.macvpncatalog` | Info.plist ranks | `fileAssociations` + `wix/file-associations.wxs` (`.conf` OpenWithProgids only) | Done | – |
| 75 | Downloaded-file question (1.4) | quarantine attribute | Mark of the Web `Zone.Identifier` (`pure/zone.rs:45`) | Equivalent | – |
| 76 | Files opened while locked / many files refused (1.4) | – | neutral (`open_files.rs`); second launch forwards files (`platform/windows.rs` `configure_app`) | Done | – |

## H. Vault

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 77 | Master password, recovery key, change password, new recovery key (guide 11) | – | neutral | Done | – |
| 78 | Unlock automatically | key in the Keychain, released only to MacVPN's signature | Credential Manager generic credential `local.winvpn.vault` (`keystore.rs:89`), no per-app ACL | Equivalent (documented weaker isolation) | 2a desktop item open |
| 79 | Lock Now, the locked menu, unlock delays | – | neutral | Done | – |
| 80 | 1.1 → 1.2 migration of Keychain items (guide 8.2) | legacy Keychain read | `legacy_keychain` / `legacy_secrets` `Inert` (`platform.rs:234`, `:238`): no 1.1 data can exist on Windows | By design | – |
| 81 | Pagefile / swap of vault pages | swap | best effort, BitLocker advice (guide 8) | Equivalent | – |
| 82 | Secrets on the clipboard (recovery key, team key, subscription) | concealed pasteboard types, cleared after 60 s | `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory` (`clipboard.rs:17`, `:143`) | Equivalent | – |

## I. Folders, colours, search; J. Shared credentials

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 83 | Folders, colours, drag and drop, delete folder (guide 12) | – | neutral | Done | native contents on delete: G-3 |
| 84 | Search (1.4) | – | neutral | Done | – |
| 85 | Shared credentials (guide 13) | – | neutral | Done | – |

## K. Backup and restore

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 86 | Back Up Everything / Restore (guide 14), also a MacVPN backup | – | neutral; MacVPN backups restore (2a) | Done | – |
| 87 | "After a restore": Reinstall N native profiles (`restore_reinstall_profile`) | profiles staged for approval | `install` answers "later" | Gap | 2c T13 (`needs_approval() = false`) |
| 88 | Restore preferences | – | neutral | Done | – |

## L. Team catalogs

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 89 | Subscribe from a file source / HTTPS with token (guide 16) | – | file (2a), HTTPS through System32's curl (`https.rs:22`, 2b T19) | Done | – |
| 90 | Admin key, publish, rotate team key, backup key (guide 16.7–16.10) | – | neutral | Done | – |
| 91 | Catalog native connections: "Install profile" / "Is the New Profile Installed?" | approval in System Settings | `catalog_install_profile` reaches `NoEngine::install` | Gap | 2c T13 |

## M. Control API and pairing

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 92 | Paired apps, pairing window, leases, revoke, activity (guide 5.4, control-api.md) | Unix socket `0600` | named pipe `\\.\pipe\WinVPN-control-<SID>` (`win/control.rs:105`); fails closed without a SID (`platform.rs:178`) | Equivalent | – |
| 93 | `up` of a managed connection (incl. MFA, credentials) | – | OpenVPN / WireGuard: done; native: "later" | Gap | 2c T8; gate: G-4 |
| 94 | `up` of a system VPN | starts with its stored secrets | blocked by `engine_missing` and nothing listed | Gap | 2c T9; gate: G-4 |
| 95 | App quitting ends client sessions (`app_quitting`) | – | neutral | Done | – |

## N. Notifications

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 96 | Failure / drop notifications, click → Log tab; MFA and credential prompts; catalog updates | `UNUserNotificationCenter` | WinRT toasts with AUMID `local.winvpn` (`win/toast.rs:53`); neutral routing (`notify.rs`) | Done | – |
| 97 | Connected / reconnected notifications, plain-words reasons, Settings switch | – (new in 2.0.0) | – | Gap (both OSes) | FP T2 (merged after base), T7, T12; RAS reasons: 2c T7 |

## O. Updates

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 98 | Update check, signed release, Download and Install, relaunch (guide 8) | DMG swap | MSI through UAC + relauncher (`updater.rs:174`, `:276`) | Done | – |
| 99 | Check automatically / only offer updates ≥ 24 h old | – | neutral (`set_update_option`) | Done | – |
| 100 | Interrupted update notice | one-time notice | `write_notice` (`updater.rs:266`) | Done | – |

## P. Lifecycle

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 101 | Quit with active connections: Disconnect / Keep Running; paired apps named | – | neutral quit guard; service connections survive a quit (2b) | Done | RAS: 2c T8 |
| 102 | Logout / shutdown asks first (unsaved changes, active VPNs) | `applicationShouldTerminate` → later | `WM_QUERYENDSESSION` → `ShutdownBlockReasonCreate` (`lifecycle.rs:27`); logoff ends the user's service connections (`helper/src/windows/sys/session.rs:20`) | Equivalent | RAS at logoff: 2c T8 (`WM_ENDSESSION`), T10; smoke: G-8 |
| 103 | In-app uninstall (guide 9): disconnect, remove login item, optionally user data incl. the vault key | **Uninstall MacVPN…** | Installed apps; the user unticks Launch at Login, deletes `%LOCALAPPDATA%\WinVPN` and `local.winvpn.vault` by hand (guide 7); `setup_uninstall` refused with the note (`system.rs:170`). After 2c: RAS entries and their PSKs would also stay | By design (2a) → **decision** | **G-9** |
| 104 | Sleep / wake refresh, catalog check after wake | `NSWorkspaceDidWake` | `PBT_APMRESUMEAUTOMATIC` (`lifecycle.rs:40`) | Done | sleep announcement: FP T10 |
| 105 | Launch at login (guide 2.1), approval notes | `SMAppService` / LaunchAgent | HKCU Run value + StartupApproved state (`win/login_item.rs:2`, `:14`) | Equivalent | – |
| 106 | Help opens the guide in the UI language | `user-guide.<lang>.md` | `winvpn-user-guide.<lang>.md` (`product.rs:43`, `app.rs:309`) | Done | content: G-10 |
| 107 | Language EN/HU, root-side texts in the UI language | `-AppleLanguages` | preferred UI languages; the service gets `--lang` (2b) | Done | – |

## Q. Security properties

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 108 | Code signing of the app | ad hoc / Developer ID; hardened `mvpn` | MSI not Authenticode-signed; the service checks its engines' signatures (2b T4) | By design (2b decision) | – |
| 109 | Engines newest without an app release | Homebrew | OpenVPN newest MSI, wireguard-nt by the service (2b fix4); RAS = Windows Update | Done | – |
| 110 | ARM64 | Apple silicon tested | built and gated, untested | By design ("nem tesztelt") | – |

## R. Test coverage and documentation

| # | MacVPN feature | MacVPN behaviour | WinVPN after 2b (evidence) | Status | Closed by |
|---|---|---|---|---|---|
| 111 | Smoke run sections (`smoke/mod.rs:423–475`, `smoke-manage.sh`) | every section incl. Dock, menu shape, screenshots, appearance, the logout quit request | Dock (Equivalent: windows closed instead), screenshots and appearance skipped; **menu shape and the quit request skipped** (`smoke-manage.sh:487`); no staged native profile | Partly gap | quit request + corners: **G-8**; native sections: 2c T14; appearance: FP T15 |
| 112 | User documentation | user guide (16 sections), How-to, Control API guide, troubleshooting | WinVPN guide still the 2a preview text (2b T22 pending); no debug/troubleshooting/MFA/credential sections, no How-to, `control-api.md` describes only the Unix socket and the Keychain token example | **Gap** | 2b T22, 2c T16, **G-10** |

---

## Checks the 2c plan asked for (Task 1, Step 2)

- **Row 20 (daily engine re-check):** missing on Windows → G-1.
- **`Shell::open_native_profile_settings` on Windows:** opens `ms-settings:network-vpn` (`platform.rs:343`); its only callers are the two delete paths (`manage.rs:243`, `folders.rs:87`), which must stop calling it for WinVPN's own entries after 2c (G-3); 2c T9's system VPN "Settings" link may keep using it.
- **`SystemInfo::user_owner` and the auth-state reader:** `FileOwner::current_user` (`platform.rs:289`); `auth_state` is the service's `auth-state` (`platform.rs:199`). Done.
- **`LegacySecrets` / `legacy_keychain`:** `Inert` (`platform.rs:234`, `:238`): by design (row 80).
- **The control API's `up` of a native connection and of a system VPN:** blocked by the `engine_missing` gates (G-4), then by `NoEngine` (2c T8, T9).
- **The credential prompt for L2TP and system VPNs:** neutral; L2TP asks user, password and PSK (`credentials.rs:149`); system VPNs ask nothing (macOS rule, checklist "Rendszer VPN (L2TP) mentett PSK nélkül → nincs ablak"). The re-prompt for RAS kinds: G-5.
- **"Unsaved changes" / quit flows with RAS connections:** neutral guards; RAS connections counted once 2c T8 reports their status.
- **Smoke sections not run on Windows:** Dock (Equivalent), menu shape and the logout quit request (G-8), screenshots and appearance (FP T15 for the theme; screenshots not required on Windows), the staged native profile (2c T14).
