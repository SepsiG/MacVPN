# MacVPN

[English](#english) | [Magyar](#magyar)

---

## English

MacVPN is a menu bar app for macOS that manages OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec and Cisco IPsec connections in one place. Version 1.0 is written in Rust with a Tauri user interface.

### Features
- **Six VPN types.** OpenVPN, WireGuard, IKEv2 (strongSwan) and SSTP run through Homebrew tools and MacVPN's root helper. L2TP/IPsec and Cisco IPsec use the built-in macOS VPN. VPNs set up elsewhere in macOS show up as system VPNs, and you can start and stop them from MacVPN too.
- **Import and export.** Choose or drag in one or more files. Referenced key files, PKCS#12 files and MikroTik RouterOS configs are handled. Credential files go into the Keychain if you confirm. Exports never contain passwords, and they only contain private keys if you choose that.
- **Editors.** A config editor with line-numbered errors and a panel for risky OpenVPN settings. Forms for SSTP, L2TP and Cisco IPsec. Passwords, PSKs and key passwords are stored in the Keychain.
- **Multi-factor authentication.** OpenVPN static and dynamic challenges, sign-in in the browser (SAML, SSO, push), and a one-time code appended to the password for every type that has a password, including system VPNs.
- **Order.** Pin connections to the top and drag them into order. The rest are ranked by how often you use them.
- **Log.** Every connection has a live log with a filter, search and save. Option-click a switch to connect in debug mode.
- **System Status window.** Installs Homebrew, the VPN tools and the root helper, and uninstalls MacVPN.
- **Also:** notifications, Launch at Login, signed in-app updates, and an English and Hungarian interface.

### Download and install
1. Download the latest `MacVPN-x.y.z.dmg` from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Open the DMG and drag `MacVPN.app` to the Applications folder.
3. The app is ad-hoc signed, not signed with a Developer ID, so Gatekeeper blocks the first launch. On macOS 14, Control-click (right-click) the app in Applications, choose **Open**, then **Open** again. On macOS 15 or later, open System Settings → Privacy & Security and click **Open Anyway**.
4. In the System Status window, install the missing Homebrew packages and click **Authorize** to install the root helper (one admin password prompt).

Step by step: [How-to guide](docs/how-to.en.md). Already using MacVPN 0.x? See [Upgrading from 0.x](docs/user-guide.en.md#81-upgrading-from-0x).

### Requirements
- macOS 14 or later, Apple silicon or Intel
- An administrator account (for the one-time root helper install)
- [Homebrew](https://brew.sh) for OpenVPN, WireGuard, IKEv2 and SSTP. MacVPN installs the packages it needs (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`). L2TP and Cisco IPsec need nothing extra.

### Documentation
- How-to guide: [English](docs/how-to.en.md), [Hungarian](docs/how-to.hu.md)
- User guide: [English](docs/user-guide.en.md), [Hungarian](docs/user-guide.hu.md) (the menu's **Help** opens it)
- [OpenVPN directive policy](docs/openvpn-directives.md)

### Security note
Root operations are performed by a single binary, `/usr/local/libexec/macvpn/mvpn`, through a sudoers rule. The Homebrew directory is writable by the user, so this setup does not protect against malware running inside your own user account. For SSTP, the password is handed to `sstpc` on its command line (it masks it right away). Details: [Security notes in the user guide](docs/user-guide.en.md#10-security-notes).

### Development
MacVPN is a Cargo workspace with a Tauri 2 user interface (Svelte + TypeScript).

**Toolchain.** `rust-toolchain.toml` pins the exact Rust version (currently 1.99.1) with clippy, rustfmt and both macOS targets. `rustup` uses it automatically inside the repository; if it is not installed yet, run `rustup toolchain install` there. CI and the release workflow use Node.js 26.8.2 (`app/ui/package.json` needs at least 22.12).

**Build.**
- `scripts/build-dmg.sh` builds the universal `dist/MacVPN.app` and `dist/MacVPN-x.y.z.dmg`: the UI, the app, and the `mvpn` root binary, all signed ad-hoc with the hardened runtime.
- Development run without touching real data: `cargo build -p macvpn-app --features custom-protocol` (after `npm run build` in `app/ui`), then `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app`. See [`app/README.md`](app/README.md).

**Tests.**
- `cargo test --workspace`: unit and compatibility tests; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`
- `scripts/test-root.sh`: black-box tests of the root binary (dry run, no root needed)
- `cd app/ui && npm ci && npm test && npm run build`: UI tests (language rule, l10n coverage) and the UI build
- `scripts/check-l10n.sh`: every text (UI and Rust) has a Hungarian translation
- `scripts/smoke-manage.sh`: smoke test of the real windows in a sandbox; run it with `SMOKE_LANG=en` and `SMOKE_LANG=hu`
- `scripts/test-sign-release.sh`: the release signing script, dry run with a throwaway key
- Manual GUI checklist: [`docs/manual-test-checklist.md`](docs/manual-test-checklist.md)

**Repository layout.**
- `crates/core`: platform-independent logic (models, storage, validators, import/export, MFA, update checks, ranking) and the EN/HU text table `crates/core/l10n/strings.json`
- `crates/mvpn`: the root binary (`/usr/local/libexec/macvpn/mvpn`, root layer version in `crates/mvpn/VERSION`)
- `crates/platform-mac`: macOS services (Keychain, native VPN, login item, dialogs, installers)
- `crates/app-core`: the app logic without a UI
- `app/src-tauri`: the Tauri app; `app/ui`: its web UI
- `scripts/`: build, test, signing and icon scripts; `Tests/Fixtures`: OpenVPN and MikroTik fixtures
- `legacy/swift`: the 0.x Swift app, kept only as a reference for a few compatibility tests. It is not built and will be removed.

**Localization.** English is the source language and Hungarian the translation. Every text (UI, app, root binary) is in `crates/core/l10n/strings.json`, keyed by the English text. The app follows the macOS preferred languages (the first Hungarian or English one, otherwise English; a per-app language in System Settings works too). The root binary gets the language through `--lang en|hu`.

**Releasing.** See [`docs/RELEASING.md`](docs/RELEASING.md) for the release procedure and the repository security settings.

### License
MIT – see [LICENSE](LICENSE).

---

## Magyar

A MacVPN egy menüsor-alkalmazás macOS-re, amely egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec és Cisco IPsec kapcsolatokat. Az 1.0-s verzió Rustban készült, Tauri felülettel.

### Funkciók
- **Hat VPN-típus.** Az OpenVPN, a WireGuard, az IKEv2 (strongSwan) és az SSTP Homebrew eszközökkel és a MacVPN root segédjével fut. Az L2TP/IPsec és a Cisco IPsec a macOS beépített VPN-jét használja. A macOS-ben máshol beállított VPN-ek rendszer VPN-ként jelennek meg, ezeket is indíthatod és bonthatod a MacVPN-ből.
- **Import és export.** Válassz ki vagy húzz be egy vagy több fájlt. A hivatkozott kulcsfájlokat, a PKCS#12 fájlokat és a MikroTik RouterOS configokat is kezeli. A hitelesítőadat-fájlok tartalma megerősítés után a Keychainbe kerül. Az export soha nem tartalmaz jelszót, privát kulcsot pedig csak akkor, ha ezt választod.
- **Szerkesztők.** Config szerkesztő sorszámozott hibalistával és egy panellel a kockázatos OpenVPN beállításokhoz. Űrlap az SSTP-hez, az L2TP-hez és a Cisco IPsec-hez. A jelszavak, a PSK-k és a kulcsjelszavak a Keychainbe kerülnek.
- **Többfaktoros hitelesítés.** OpenVPN statikus és dinamikus challenge, böngészős bejelentkezés (SAML, SSO, push), és a jelszó végére fűzött egyszer használatos kód minden jelszavas típusnál, a rendszer VPN-eknél is.
- **Sorrend.** A kapcsolatokat kitűzheted a lista elejére, és húzással rendezheted. A többit a használat gyakorisága szerint rendezi.
- **Napló.** Minden kapcsolatnak élő naplója van szűréssel, kereséssel és mentéssel. Option+kattintás a kapcsolón: csatlakozás debug módban.
- **Rendszerállapot ablak.** Telepíti a Homebrew-t, a VPN-eszközöket és a root segédet, és innen távolíthatod el a MacVPN-t.
- **Továbbá:** értesítések, indítás bejelentkezéskor, aláírt frissítés az appon belül, magyar és angol felület.

### Letöltés és telepítés
1. Töltsd le a legfrissebb `MacVPN-x.y.z.dmg` fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Nyisd meg a DMG-t, és húzd a `MacVPN.app`-ot az Applications mappába.
3. Az app ad-hoc aláírású, nincs Developer ID-vel aláírva, ezért a Gatekeeper az első indításkor letiltja. macOS 14-en kattints a Control billentyűvel (jobb gombbal) az appra az Applications mappában, válaszd a **Megnyitás** pontot, majd újra a **Megnyitás** gombot. macOS 15-ön és újabbon: Rendszerbeállítások → Adatvédelem és biztonság → **Megnyitás mindenképp**.
4. A Rendszerállapot ablakban telepítsd a hiányzó Homebrew csomagokat, majd az **Engedélyezés** gombbal telepítsd a root segédet (egy admin jelszó).

Lépésről lépésre: [Hogyan használd](docs/how-to.hu.md). Már a 0.x verziót használod? Lásd: [Frissítés 0.x verzióról](docs/user-guide.hu.md#81-frissítés-0x-verzióról).

### Követelmények
- macOS 14 vagy újabb, Apple processzoros vagy Intel Mac
- Rendszergazdai fiók (a root segéd egyszeri telepítéséhez)
- [Homebrew](https://brew.sh) az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokhoz. A szükséges csomagokat (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`) a MacVPN telepíti. Az L2TP-hez és a Cisco IPsec-hez nem kell semmi más.

### Dokumentáció
- Hogyan használd: [magyar](docs/how-to.hu.md), [angol](docs/how-to.en.md)
- Felhasználói útmutató: [magyar](docs/user-guide.hu.md), [angol](docs/user-guide.en.md) (a menü **Súgó** pontja ezt nyitja meg)
- [OpenVPN direktíva-szabályok](docs/openvpn-directives.md) (angolul, magyar összefoglalóval)

### Biztonsági megjegyzés
A root műveleteket egyetlen bináris, a `/usr/local/libexec/macvpn/mvpn` végzi egy sudoers szabályon keresztül. A Homebrew könyvtára a felhasználó által írható, ezért a megoldás nem véd a felhasználói fiókon belül futó kártevő ellen. SSTP-nél a jelszó az `sstpc` parancssorában adódik át (az azonnal kicsillagozza). Részletek: [Biztonsági megjegyzések az útmutatóban](docs/user-guide.hu.md#10-biztonsági-megjegyzések).

### Fejlesztés
A MacVPN egy Cargo workspace, Tauri 2 felülettel (Svelte + TypeScript).

**Eszközök.** A `rust-toolchain.toml` rögzíti a pontos Rust verziót (jelenleg 1.99.1) a clippyvel, a rustfmt-vel és mindkét macOS targettel. A repón belül a `rustup` automatikusan ezt használja; ha még nincs telepítve, futtasd ott: `rustup toolchain install`. A CI és a kiadási workflow Node.js 26.8.2-t használ (az `app/ui/package.json` legalább 22.12-t kér).

**Build.**
- `scripts/build-dmg.sh`: a universal `dist/MacVPN.app` és `dist/MacVPN-x.y.z.dmg`: a felület, az app és a `mvpn` root bináris, mind ad-hoc aláírva, hardened runtime-mal.
- Fejlesztői futtatás a valódi adatok érintése nélkül: `cargo build -p macvpn-app --features custom-protocol` (az `app/ui`-ban futtatott `npm run build` után), majd `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app`. Lásd [`app/README.md`](app/README.md) (angolul).

**Tesztek.**
- `cargo test --workspace`: unit- és kompatibilitási tesztek; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`
- `scripts/test-root.sh`: a root bináris fekete dobozos tesztje (dry-run, nem kell root)
- `cd app/ui && npm ci && npm test && npm run build`: a felület tesztjei (nyelvválasztás, lokalizáció-lefedettség) és buildje
- `scripts/check-l10n.sh`: minden szövegnek (felület és Rust) van magyar fordítása
- `scripts/smoke-manage.sh`: a valódi ablakok smoke tesztje egy sandboxban; futtasd `SMOKE_LANG=en` és `SMOKE_LANG=hu` mellett is
- `scripts/test-sign-release.sh`: a kiadás-aláíró script próbafuttatása eldobható kulccsal
- Kézi GUI tesztlista: [`docs/manual-test-checklist.md`](docs/manual-test-checklist.md)

**A repó felépítése.**
- `crates/core`: platformfüggetlen logika (modellek, tárolás, validátorok, import/export, MFA, frissítés-ellenőrzés, rangsor) és az EN/HU szövegtábla, a `crates/core/l10n/strings.json`
- `crates/mvpn`: a root bináris (`/usr/local/libexec/macvpn/mvpn`, a root réteg verziója a `crates/mvpn/VERSION`-ben)
- `crates/platform-mac`: macOS-szolgáltatások (Keychain, natív VPN, bejelentkezési elem, párbeszédablakok, telepítők)
- `crates/app-core`: az app logikája felület nélkül
- `app/src-tauri`: a Tauri app; `app/ui`: a webes felülete
- `scripts/`: build-, teszt-, aláíró és ikon scriptek; `Tests/Fixtures`: OpenVPN és MikroTik tesztadatok
- `legacy/swift`: a 0.x Swift app, csak néhány kompatibilitási teszt referenciájaként marad meg. Nem fordul, és törölni fogjuk.

**Lokalizáció.** Az angol a forrásnyelv, a magyar a fordítás. Minden szöveg (felület, app, root bináris) a `crates/core/l10n/strings.json`-ban van, a kulcs az angol szöveg. Az app a macOS preferált nyelveit követi (az első magyar vagy angol, különben angol; a Rendszerbeállításokban appra beállított nyelv is működik). A root bináris a `--lang en|hu` kapcsolóból kapja a nyelvet.

**Kiadás.** A kiadás menete és a repó biztonsági beállításai: [`docs/RELEASING.md`](docs/RELEASING.md) (angolul).

### Licenc
MIT – lásd [LICENSE](LICENSE).

---

## Support / Támogatás

If you find MacVPN useful, you can buy me a coffee. / Ha tetszik a MacVPN, egy kávéval támogathatod a fejlesztést.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/X8X01DODMO)
