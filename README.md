# MacVPN

[English](#english) | [Magyar](#magyar)

---

## English

MacVPN is a menu bar app for macOS that manages OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec and Cisco IPsec connections in one place. It is written in Rust with a Tauri user interface (since 1.0); the current version is 1.5.

### What's new in 1.5
- **Under the hood:** prepared for a Windows version; MacVPN works exactly as before. The root layer stays 8: updating from 1.4 needs no admin password.

### What's new in 1.4
- **Search in the Connections window.** The **Search connections** field at the top of the sidebar (**⌘F**) filters as you type, ignoring case and accents. It finds a connection by its name, its type, its server (from the settings or the config, such as OpenVPN's first `remote`; the host only), its team catalog and its folders. **↑** / **↓** and Return move through the results. See [search](docs/user-guide.en.md#128-searching-connections).
- **Open VPN files from Finder.** Double-click a `.ovpn` or `.sstp` file: MacVPN is their default app and imports it with the same checks and questions as **Import from File…**; nothing connects. A WireGuard or strongSwan `.conf` opens through **Open With → MacVPN** (MacVPN does not take `.conf` over). A `.macvpncatalog` file opens the **Add team catalog…** dialog with that file as the source; the team key and the fingerprint check stay yours. While the vault is locked, the files wait for the unlock. See [opening VPN files from Finder](docs/user-guide.en.md#41-opening-vpn-files-from-finder).
- **Downloaded files ask first.** A file you downloaded (a browser, Mail, Messages, AirDrop) is imported only after one question: **Import N downloaded files?** with their names and "Only import files you trust." `.ovpn` and `.sstp` are declared as data, not text, so Safari never opens them by itself.
- **For developers:** the old 0.x Swift code is no longer in the repository (it stays in the git history up to `v0.4.0`); the frozen Swift-written fixtures stay for the compatibility tests.
- The root layer stays 8: updating from 1.3 needs no admin password.
- **1.4.1:** an OpenVPN config whose `cert` and `key` point to the same PEM file (certificate plus private key, also an encrypted key or Windows line ends) imports; MacVPN asks for the private key password when you connect. See [Other](docs/user-guide.en.md#78-other).

### What's new in 1.3
- **Team catalogs.** An administrator publishes a set of connections, with their folders, colours and named sign-ins, as one signed and encrypted file on an HTTPS server, a file share or a synced folder (iCloud Drive, OneDrive, Dropbox). Every subscribed MacVPN picks up additions, changes and removals by itself; each member signs in with their own user name and password, which never leave their vault. See [team catalogs](docs/user-guide.en.md#16-team-catalogs).
- **Subscribe in one step.** Paste a subscription string, compare the publisher fingerprint, done. Catalog connections are read-only and carry a **Team** badge; **Duplicate as personal connection…** makes your own editable copy.
- **For administrators:** the **Publishing** section: an admin key with an offline backup key, a publish wizard (team secrets only when you tick them) that writes the file where you choose, and **Rotate Team Key…** to cut off someone who left. MacVPN never uploads anything.
- **Upgrading from 1.2:** the vault is updated on the first launch (the old one is kept as `vault.db.bak-v1`); the root layer stays 8, so no admin password is needed. See [Upgrading from 1.2](docs/user-guide.en.md#83-upgrading-from-12).

### What's new in 1.2
- **Encrypted vault.** Connections and their passwords are kept in one encrypted vault, protected by a master password, with a recovery key shown once. **Unlock automatically** opens it without asking; **Lock Now** locks it. See [the vault chapter](docs/user-guide.en.md#11-vault).
- **Folders and colours.** Nested folders for connections and system VPNs, 12 colours, drag and drop. See [folders](docs/user-guide.en.md#12-folders-and-colours).
- **Shared credentials.** One user name and password for several connections, changed in one place. See [shared credentials](docs/user-guide.en.md#13-shared-credentials).
- **Full backup and restore.** One encrypted file with everything, restorable on this Mac or a new one. See [backup and restore](docs/user-guide.en.md#14-backup-and-restore).
- **Upgrading from 1.1:** back up `~/Library/Application Support/MacVPN` first. The first launch moves your data into the vault (macOS may ask for Keychain access once per old item: choose **Always Allow**), and the root layer goes from 7 to 8 (one admin password). See [Upgrading from 1.1](docs/user-guide.en.md#82-upgrading-from-11).

### What's new in 1.1
- **Control API.** Other apps of your user account that you pair (for example a Remote Desktop app) can bring the connections you allow up and down; the VPN stays up only while the app needs it. Off by default. See the [Control API guide](docs/control-api.md) and the [user guide](docs/user-guide.en.md#54-paired-apps-control-api).
- **Credential prompt.** Missing user names, passwords, PSKs and key passwords are asked for at connect, and saved only after the connection is up.
- **Live system VPN list.** Changes in System Settings show up at once.
- **New card look** for the menu and every window, and a **Dock icon** while a window is open.
- Same root layer (7): updating from 1.0 needs no admin password.

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
- **Also:** notifications, Launch at Login, signed in-app updates, and an English and Hungarian interface.

### Download and install
1. Download the latest `MacVPN-x.y.z.dmg` from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Open the DMG and drag `MacVPN.app` to the Applications folder.
3. The app is ad-hoc signed, not signed with a Developer ID, so Gatekeeper blocks the first launch. On macOS 14, Control-click (right-click) the app in Applications, choose **Open**, then **Open** again. On macOS 15 or later, open System Settings → Privacy & Security and click **Open Anyway**.
4. In the System Status window, install the missing Homebrew packages and click **Authorize** to install the root helper (one admin password prompt).

Step by step: [How-to guide](docs/how-to.en.md). Already using MacVPN 1.2? See [Upgrading from 1.2](docs/user-guide.en.md#83-upgrading-from-12). Coming from 1.1? See [Upgrading from 1.1](docs/user-guide.en.md#82-upgrading-from-11). Coming from 0.x? See [Upgrading from 0.x](docs/user-guide.en.md#81-upgrading-from-0x).

### Requirements
- macOS 14 or later, Apple silicon or Intel
- An administrator account (for the one-time root helper install)
- [Homebrew](https://brew.sh) for OpenVPN, WireGuard, IKEv2 and SSTP. MacVPN installs the packages it needs (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`). L2TP and Cisco IPsec need nothing extra.

### Documentation
- How-to guide: [English](docs/how-to.en.md), [Hungarian](docs/how-to.hu.md)
- User guide: [English](docs/user-guide.en.md), [Hungarian](docs/user-guide.hu.md) (the menu's **Help** opens it)
- [OpenVPN directive policy](docs/openvpn-directives.md)
- Control API for other apps on the same Mac: [English](docs/control-api.md), [Hungarian](docs/control-api.hu.md), with an [example client](examples/macvpn-control-client/)

### Security note
Root operations are performed by a single binary, `/usr/local/libexec/macvpn/mvpn`, through a sudoers rule. The Homebrew directory is writable by the user, so this setup does not protect against malware running inside your own user account. For SSTP, the password is handed to `sstpc` on its command line (it masks it right away). The vault protects your data at rest; a full backup is as sensitive as the vault, so keep the file and its password apart. A team catalog is signed and encrypted, but everyone with the team key can read it, and whoever holds the admin key decides what your team connects to: see the [team catalog security model](docs/user-guide.en.md#1611-security-model). Details: [Security notes in the user guide](docs/user-guide.en.md#10-security-notes).

### Development
MacVPN is a Cargo workspace with a Tauri 2 user interface (Svelte + TypeScript). Since 1.5 the workspace is split into shared logic and a thin platform layer per operating system, so the same code can later ship as WinVPN on Windows; MacVPN is the only product so far. Start with [`docs/architecture.md`](docs/architecture.md): the crates, the `cfg` and `unsafe` rules, the per-OS texts and how a platform plugs in.

**Toolchain.** `rust-toolchain.toml` pins the exact Rust version (currently 1.99.1) with clippy, rustfmt, both macOS targets and both Windows targets (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, for the compile check). `rustup` uses it automatically inside the repository; if it is not installed yet, run `rustup toolchain install` there. CI and the release workflow use Node.js 26.8.2 (`app/ui/package.json` needs at least 22.12).

**Build.**
- `scripts/build-dmg.sh` builds the universal `dist/MacVPN.app` and `dist/MacVPN-x.y.z.dmg`: the UI, the app, and the `mvpn` root binary, all signed ad-hoc with the hardened runtime.
- Development run without touching real data: `cargo build -p macvpn-app --features custom-protocol` (after `npm run build` in `app/ui`), then `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app`. See [`app/README.md`](app/README.md).

**Tests.**
- `cargo test --workspace`: unit and compatibility tests; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`
- `scripts/test-root.sh`: black-box tests of the root binary (dry run, no root needed)
- `cd app/ui && npm ci && npm test && npm run build`: UI tests (language rule, l10n coverage) and the UI build
- `scripts/check-l10n.sh`: every text (UI and Rust) has a Hungarian translation
- `scripts/check-windows.sh`: `cargo check` of `macvpn-core` (without the vault), `macvpn-helper` and the control client for both Windows targets, from the Mac. The full Windows check (the vault, platform-api, platform-win, app-core and the app, which need an MSVC toolchain for their C code) runs only in CI: the `windows` and `windows-node` jobs in `.github/workflows/ci.yml`
- `crates/app-core/tests/cfg_rule.rs` (part of `cargo test`): an OS `cfg` only in the platform places, `unsafe` only in the platform crates and the helper
- `node scripts/l10n-baseline.mjs --check` and `scripts/bundle-baseline.sh dist/MacVPN.app`: the macOS texts and the built bundle compared with the 1.4.0 baseline
- `scripts/smoke-manage.sh`: smoke test of the real windows in a sandbox; run it with `SMOKE_LANG=en` and `SMOKE_LANG=hu`
- `scripts/test-sign-release.sh`: the release signing script, dry run with a throwaway key
- Manual GUI checklist: [`docs/manual-test-checklist.md`](docs/manual-test-checklist.md)

**Repository layout.**
- `crates/core`: platform-independent logic (models, the vault behind the `vault` feature, validators, import/export, MFA, update checks, ranking), the safe file operations (`fsx`, its only OS-specific module) and the EN/HU text table `crates/core/l10n/strings.json`
- `crates/platform-api`: the traits every platform implements, the shared types and the product identity (`Product`)
- `crates/platform-mac`: the macOS platform (Keychain for the vault key, native VPN, login item, dialogs, installers, updater); `crates/platform-win`: the Windows platform, a stub that answers "not supported" for now
- `crates/helper`: the root binary `mvpn` (`/usr/local/libexec/macvpn/mvpn`, root layer version in `crates/helper/VERSION`): shared protocol logic in `src/shared`, the macOS backend in `src/macos`
- `crates/app-core`: the app logic without a UI
- `app/src-tauri`: the Tauri app (its `src/platform` module picks the platform crate); `app/ui`: its web UI
- `scripts/`: build, test, signing and icon scripts; `Tests/Fixtures`: OpenVPN and MikroTik fixtures
- The 0.x Swift app is only in the git history (up to tag `v0.4.0`); `crates/core/tests/fixtures/swift` keeps data it wrote, frozen, for the compatibility and migration tests.

**Localization.** English is the source language and Hungarian the translation. Every text (UI, app, root binary) is in `crates/core/l10n/strings.json`, keyed by the English (macOS) text; an entry can carry per-OS variants (`variants`, `only`, see [`docs/architecture.md`](docs/architecture.md#texts-per-os)). The app follows the macOS preferred languages (the first Hungarian or English one, otherwise English; a per-app language in System Settings works too). The root binary gets the language through `--lang en|hu`.

**Releasing.** See [`docs/RELEASING.md`](docs/RELEASING.md) for the release procedure and the repository security settings.

### License
MIT – see [LICENSE](LICENSE). Third-party components (among them SQLCipher, BSD-style, © Zetetic LLC) are listed with their licences in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt), which also ships inside the app bundle.

---

## Magyar

A MacVPN egy menüsor-alkalmazás macOS-re, amely egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec és Cisco IPsec kapcsolatokat. Rustban készült, Tauri felülettel (az 1.0 óta); a jelenlegi verzió az 1.5.

### Újdonságok az 1.5-ben
- **A háttérben:** felkészülés egy Windows-változatra; a MacVPN pontosan úgy működik, mint eddig. A root réteg 8 marad: az 1.4-ről frissítve nem kell admin jelszó.

### Újdonságok az 1.4-ben
- **Keresés a Kapcsolatok ablakban.** Az oldalsáv tetején a **Kapcsolatok keresése** mező (**⌘F**) gépelés közben szűr, a kis- és nagybetűtől és az ékezetektől függetlenül. Megtalálja a kapcsolatot a neve, a típusa, a szervere (a beállításokból vagy a configból, például az OpenVPN első `remote` sora; csak a gépnév), a csapatkatalógusa és a mappái alapján. A **↑** / **↓** és a Return a találatok között lépked. Lásd [keresés](docs/user-guide.hu.md#128-kapcsolatok-keresése).
- **VPN-fájlok megnyitása a Finderből.** Kattints duplán egy `.ovpn` vagy `.sstp` fájlra: a MacVPN az alapértelmezett appjuk, és ugyanazokkal az ellenőrzésekkel és kérdésekkel importálja, mint az **Import fájlból…**; semmi nem csatlakozik. WireGuard vagy strongSwan `.conf` fájl a **Megnyitás ezzel → MacVPN** úton nyílik (a `.conf` fájlokat a MacVPN nem veszi át). A `.macvpncatalog` fájl a **Csapatkatalógus hozzáadása…** ablakot nyitja meg ezzel a fájllal mint forrással; a csapatkulcs és az ujjlenyomat ellenőrzése a tiéd marad. Zárolt széfnél a fájlok a feloldásig várnak. Lásd [VPN-fájlok megnyitása a Finderből](docs/user-guide.hu.md#41-vpn-fájlok-megnyitása-a-finderből).
- **A letöltött fájlokra előbb rákérdez.** A letöltött fájl (böngésző, Mail, Üzenetek, AirDrop) csak egy kérdés után importálódik: **Importálod a(z) N letöltött fájlt?**, a nevükkel és a figyelmeztetéssel: „Csak olyan fájlt importálj, amelyben megbízol.” A `.ovpn` és a `.sstp` adatként van bejelentve, nem szövegként, így a Safari soha nem nyitja meg magától.
- **Fejlesztőknek:** a régi 0.x Swift kód már nincs a tárolóban (a git történetben a `v0.4.0`-ig megvan); a befagyasztott, Swift által írt tesztadatok a kompatibilitási tesztekhez megmaradnak.
- A root réteg 8 marad: az 1.3-ról frissítve nem kell admin jelszó.
- **1.4.1:** importálható az az OpenVPN config, amelynek `cert` és `key` sora ugyanarra a PEM fájlra mutat (tanúsítvány és privát kulcs, titkosított kulccsal vagy Windowsos sorvégekkel is); a privát kulcs jelszavát a MacVPN csatlakozáskor kéri. Lásd [Egyéb](docs/user-guide.hu.md#78-egyéb).

### Újdonságok az 1.3-ban
- **Csapatkatalógusok.** A rendszergazda egy kapcsolatkészletet, a mappáival, színeivel és névvel ellátott bejelentkezési helyeivel együtt, egyetlen aláírt és titkosított fájlként tesz közzé egy HTTPS-szerveren, egy fájlmegosztáson vagy egy szinkronizált mappában (iCloud Drive, OneDrive, Dropbox). Minden feliratkozott MacVPN magától átveszi az új, a módosult és a törölt kapcsolatokat; mindenki a saját felhasználónevével és jelszavával jelentkezik be, ezek sosem hagyják el a széfjét. Lásd [csapatkatalógusok](docs/user-guide.hu.md#16-csapatkatalógusok).
- **Feliratkozás egy lépésben.** Beilleszted a feliratkozási kódot, összeveted a közzétevő ujjlenyomatát, kész. A katalógus kapcsolatai csak olvashatók, és **Csapat** jelvényt viselnek; a **Másolat saját kapcsolatként…** saját, szerkeszthető példányt készít.
- **Rendszergazdáknak:** a **Közzététel** rész: adminisztrátori aláírókulcs offline tartalék kulccsal, közzétételi varázsló (csapattitok csak külön jelölésre), amely oda írja a fájlt, ahová választod, és **Csapatkulcs cseréje…** a csapatot elhagyók kizárására. A MacVPN semmit nem tölt fel.
- **Frissítés 1.2-ről:** az első indítás frissíti a széfet (a régi `vault.db.bak-v1` néven megmarad); a root réteg 8 marad, így nem kell admin jelszó. Lásd [Frissítés 1.2-ről](docs/user-guide.hu.md#83-frissítés-12-ről).

### Újdonságok az 1.2-ben
- **Titkosított széf.** A kapcsolatok és jelszavaik egy titkosított széfben vannak, amelyet mesterjelszó véd, és van egy csak egyszer megjelenő helyreállítási kulcs. Az **Automatikus feloldás** kérdés nélkül megnyitja, a **Széf zárolása most** zárolja. Lásd [a széf fejezetet](docs/user-guide.hu.md#11-széf).
- **Mappák és színek.** Egymásba ágyazható mappák a kapcsolatoknak és a rendszer VPN-eknek, 12 szín, húzással rendezés. Lásd [mappák](docs/user-guide.hu.md#12-mappák-és-színek).
- **Közös hitelesítő adatok.** Egy felhasználónév és jelszó több kapcsolatnak, egy helyen módosítva. Lásd [közös hitelesítő adatok](docs/user-guide.hu.md#13-közös-hitelesítő-adatok).
- **Teljes biztonsági mentés és visszaállítás.** Egyetlen titkosított fájl mindennel, ezen vagy egy új Macen visszaállítható. Lásd [mentés és visszaállítás](docs/user-guide.hu.md#14-biztonsági-mentés-és-visszaállítás).
- **Frissítés 1.1-ről:** előbb mentsd le a `~/Library/Application Support/MacVPN` mappát. Az első indítás a széfbe költözteti az adataidat (a macOS régi elemenként egyszer Keychain-hozzáférést kérhet: válaszd a **Mindig engedélyez** gombot), a root réteg pedig 7-ről 8-ra vált (egy admin jelszó). Lásd [Frissítés 1.1-ről](docs/user-guide.hu.md#82-frissítés-11-ről).

### Újdonságok az 1.1-ben
- **Vezérlő API.** A felhasználói fiókod általad párosított appjai (például egy Remote Desktop app) fel- és lekapcsolhatják az általad engedélyezett kapcsolatokat; a VPN csak addig marad fenn, amíg az appnak kell. Alapból ki van kapcsolva. Lásd [a vezérlő API leírását](docs/control-api.hu.md) és [az útmutatót](docs/user-guide.hu.md#54-párosított-appok-vezérlő-api).
- **Hitelesítő adatok bekérése.** A hiányzó felhasználónevet, jelszót, PSK-t és kulcsjelszót csatlakozáskor bekéri, és csak a sikeres csatlakozás után menti.
- **Élő rendszer-VPN lista.** A Rendszerbeállításokban végzett változások azonnal megjelennek.
- **Új, kártyás megjelenés** a menüben és minden ablakban, és **Dock ikon**, amíg egy ablak nyitva van.
- A root réteg ugyanaz (7): az 1.0-ról frissítve nem kell admin jelszó.

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
- **Továbbá:** értesítések, indítás bejelentkezéskor, aláírt frissítés az appon belül, magyar és angol felület.

### Letöltés és telepítés
1. Töltsd le a legfrissebb `MacVPN-x.y.z.dmg` fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Nyisd meg a DMG-t, és húzd a `MacVPN.app`-ot az Applications mappába.
3. Az app ad-hoc aláírású, nincs Developer ID-vel aláírva, ezért a Gatekeeper az első indításkor letiltja. macOS 14-en kattints a Control billentyűvel (jobb gombbal) az appra az Applications mappában, válaszd a **Megnyitás** pontot, majd újra a **Megnyitás** gombot. macOS 15-ön és újabbon: Rendszerbeállítások → Adatvédelem és biztonság → **Megnyitás mindenképp**.
4. A Rendszerállapot ablakban telepítsd a hiányzó Homebrew csomagokat, majd az **Engedélyezés** gombbal telepítsd a root segédet (egy admin jelszó).

Lépésről lépésre: [Hogyan használd](docs/how-to.hu.md). Az 1.2-t használod? Lásd: [Frissítés 1.2-ről](docs/user-guide.hu.md#83-frissítés-12-ről). Az 1.1-ről jössz? Lásd: [Frissítés 1.1-ről](docs/user-guide.hu.md#82-frissítés-11-ről). 0.x verzióról jössz? Lásd: [Frissítés 0.x verzióról](docs/user-guide.hu.md#81-frissítés-0x-verzióról).

### Követelmények
- macOS 14 vagy újabb, Apple processzoros vagy Intel Mac
- Rendszergazdai fiók (a root segéd egyszeri telepítéséhez)
- [Homebrew](https://brew.sh) az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokhoz. A szükséges csomagokat (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`) a MacVPN telepíti. Az L2TP-hez és a Cisco IPsec-hez nem kell semmi más.

### Dokumentáció
- Hogyan használd: [magyar](docs/how-to.hu.md), [angol](docs/how-to.en.md)
- Felhasználói útmutató: [magyar](docs/user-guide.hu.md), [angol](docs/user-guide.en.md) (a menü **Súgó** pontja ezt nyitja meg)
- [OpenVPN direktíva-szabályok](docs/openvpn-directives.md) (angolul, magyar összefoglalóval)
- Vezérlő API más appoknak ugyanazon a Macen: [magyar](docs/control-api.hu.md), [angol](docs/control-api.md), [példaklienssel](examples/macvpn-control-client/) (angolul)

### Biztonsági megjegyzés
A root műveleteket egyetlen bináris, a `/usr/local/libexec/macvpn/mvpn` végzi egy sudoers szabályon keresztül. A Homebrew könyvtára a felhasználó által írható, ezért a megoldás nem véd a felhasználói fiókon belül futó kártevő ellen. SSTP-nél a jelszó az `sstpc` parancssorában adódik át (az azonnal kicsillagozza). A széf a tárolt adatokat védi; a teljes biztonsági mentés ugyanolyan érzékeny, mint a széf, ezért a fájlt és a jelszavát tartsd külön. A csapatkatalógus alá van írva és titkosítva van, de akinél megvan a csapatkulcs, elolvashatja, és aki az aláírókulcsot birtokolja, az dönti el, mihez csatlakozik a csapatod: lásd [a csapatkatalógusok biztonsági modelljét](docs/user-guide.hu.md#1611-biztonsági-modell). Részletek: [Biztonsági megjegyzések az útmutatóban](docs/user-guide.hu.md#10-biztonsági-megjegyzések).

### Fejlesztés
A MacVPN egy Cargo workspace, Tauri 2 felülettel (Svelte + TypeScript). Az 1.5 óta a workspace közös logikára és operációs rendszerenként egy vékony platformrétegre oszlik, hogy ugyanaz a kód később WinVPN néven Windowson is megjelenhessen; egyelőre a MacVPN az egyetlen termék. Kezdd a [`docs/architecture.md`](docs/architecture.md) leírással (angolul): a crate-ek, a `cfg` és az `unsafe` szabályai, az operációs rendszerenkénti szövegek, és hogyan csatlakozik egy új platform.

**Eszközök.** A `rust-toolchain.toml` rögzíti a pontos Rust verziót (jelenleg 1.99.1) a clippyvel, a rustfmt-vel, mindkét macOS és mindkét Windows targettel (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, a fordítási ellenőrzéshez). A repón belül a `rustup` automatikusan ezt használja; ha még nincs telepítve, futtasd ott: `rustup toolchain install`. A CI és a kiadási workflow Node.js 26.8.2-t használ (az `app/ui/package.json` legalább 22.12-t kér).

**Build.**
- `scripts/build-dmg.sh`: a universal `dist/MacVPN.app` és `dist/MacVPN-x.y.z.dmg`: a felület, az app és a `mvpn` root bináris, mind ad-hoc aláírva, hardened runtime-mal.
- Fejlesztői futtatás a valódi adatok érintése nélkül: `cargo build -p macvpn-app --features custom-protocol` (az `app/ui`-ban futtatott `npm run build` után), majd `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app`. Lásd [`app/README.md`](app/README.md) (angolul).

**Tesztek.**
- `cargo test --workspace`: unit- és kompatibilitási tesztek; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`
- `scripts/test-root.sh`: a root bináris fekete dobozos tesztje (dry-run, nem kell root)
- `cd app/ui && npm ci && npm test && npm run build`: a felület tesztjei (nyelvválasztás, lokalizáció-lefedettség) és buildje
- `scripts/check-l10n.sh`: minden szövegnek (felület és Rust) van magyar fordítása
- `scripts/check-windows.sh`: a `macvpn-core` (széf nélkül), a `macvpn-helper` és a vezérlő kliens `cargo check`-je mindkét Windows targetre, a Macen. A teljes Windows-ellenőrzés (a széf, a platform-api, a platform-win, az app-core és az app, amelyek C kódjához MSVC eszközlánc kell) csak a CI-ban fut: a `.github/workflows/ci.yml` `windows` és `windows-node` jobja
- `crates/app-core/tests/cfg_rule.rs` (a `cargo test` része): operációsrendszer-függő `cfg` csak a platformrétegben, `unsafe` csak a platform crate-ekben és a helperben
- `node scripts/l10n-baseline.mjs --check` és `scripts/bundle-baseline.sh dist/MacVPN.app`: a macOS-es szövegek és a kész app összevetése az 1.4.0-s alapállapottal
- `scripts/smoke-manage.sh`: a valódi ablakok smoke tesztje egy sandboxban; futtasd `SMOKE_LANG=en` és `SMOKE_LANG=hu` mellett is
- `scripts/test-sign-release.sh`: a kiadás-aláíró script próbafuttatása eldobható kulccsal
- Kézi GUI tesztlista: [`docs/manual-test-checklist.md`](docs/manual-test-checklist.md)

**A repó felépítése.**
- `crates/core`: platformfüggetlen logika (modellek, a `vault` feature mögötti széf, validátorok, import/export, MFA, frissítés-ellenőrzés, rangsor), a biztonságos fájlműveletek (`fsx`, az egyetlen operációsrendszer-függő modulja) és az EN/HU szövegtábla, a `crates/core/l10n/strings.json`
- `crates/platform-api`: a trait-ek, amelyeket minden platform megvalósít, a közös típusok és a termékazonosság (`Product`)
- `crates/platform-mac`: a macOS-platform (Keychain a széfkulcsnak, natív VPN, bejelentkezési elem, párbeszédablakok, telepítők, frissítő); `crates/platform-win`: a Windows-platform, egyelőre csonk, amely mindenre azt feleli, hogy „nem támogatott”
- `crates/helper`: az `mvpn` root bináris (`/usr/local/libexec/macvpn/mvpn`, a root réteg verziója a `crates/helper/VERSION`-ben): a közös protokollogika az `src/shared`, a macOS-backend az `src/macos` alatt
- `crates/app-core`: az app logikája felület nélkül
- `app/src-tauri`: a Tauri app (az `src/platform` modulja választja ki a platform crate-et); `app/ui`: a webes felülete
- `scripts/`: build-, teszt-, aláíró és ikon scriptek; `Tests/Fixtures`: OpenVPN és MikroTik tesztadatok
- A 0.x Swift app csak a git történetben van meg (a `v0.4.0` tagig); a `crates/core/tests/fixtures/swift` az általa írt adatokat őrzi, befagyasztva, a kompatibilitási és migrációs tesztekhez.

**Lokalizáció.** Az angol a forrásnyelv, a magyar a fordítás. Minden szöveg (felület, app, root bináris) a `crates/core/l10n/strings.json`-ban van, a kulcs az angol (macOS-es) szöveg; egy bejegyzésnek lehetnek operációs rendszerenkénti változatai (`variants`, `only`, lásd [`docs/architecture.md`](docs/architecture.md#texts-per-os)). Az app a macOS preferált nyelveit követi (az első magyar vagy angol, különben angol; a Rendszerbeállításokban appra beállított nyelv is működik). A root bináris a `--lang en|hu` kapcsolóból kapja a nyelvet.

**Kiadás.** A kiadás menete és a repó biztonsági beállításai: [`docs/RELEASING.md`](docs/RELEASING.md) (angolul).

### Licenc
MIT – lásd [LICENSE](LICENSE). A külső összetevők (köztük az SQLCipher, BSD-típusú, © Zetetic LLC) licencei a [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) fájlban vannak, amely az app csomagjában is megtalálható.

---

## Support / Támogatás

If you find MacVPN useful, you can buy me a coffee. / Ha tetszik a MacVPN, egy kávéval támogathatod a fejlesztést.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/X8X01DODMO)
