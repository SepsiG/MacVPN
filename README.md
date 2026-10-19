# MacVPN

[English](#english) | [Magyar](#magyar)

---

## English

MacVPN is a menu bar app for macOS 14+ that manages OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP and Cisco IPsec connections in one place. It includes a config editor, Keychain-based secret storage, multi-factor authentication (one-time codes, OpenVPN challenge/response and web / SAML sign-in), and a live/debug log.

### Download and install
1. Download the latest `MacVPN-x.y.z.dmg` from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Open the DMG and drag `MacVPN.app` to the Applications folder.
3. The app is not signed with a Developer ID, so Gatekeeper blocks the first launch. Open System Settings → Privacy & Security and click **Open Anyway**.
4. In the System Status window, install the missing Homebrew packages and enable the root layer (one admin password prompt).

### Requirements
- macOS 14 or later
- [Homebrew](https://brew.sh) – the VPN tools (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`) are installed through it.

### Security note
Root operations are performed by `/usr/local/libexec/macvpn/mvpn` through a sudoers rule. The Homebrew directory is writable by the user, so this setup does not protect against malware running inside your own user account. For SSTP, the password is handed to `sstpc` on its command line (it masks it right away). Details: [Security notes in the user guide](docs/user-guide.en.md#10-security-notes).

### User guide
- [English user guide](docs/user-guide.en.md)
- [Hungarian user guide](docs/user-guide.hu.md)

### Development
MacVPN 1.0 is written in Rust (a Cargo workspace) with a Tauri 2 user interface (Svelte + TypeScript). Needs Rust stable (`rustup`; for the universal build also `rustup target add aarch64-apple-darwin x86_64-apple-darwin`) and Node.js 22.12+.
- `crates/core` – platform-independent logic (models, storage, validators, import/export, MFA, update checks, the EN/HU text table `crates/core/l10n/strings.json`); `crates/mvpn` – the root helper (`/usr/local/libexec/macvpn/mvpn`); `crates/platform-mac` – macOS services (Keychain, native VPN, login item, installers); `crates/app-core` – the app logic without a UI; `app/` – the Tauri app (`app/src-tauri`) and its web UI (`app/ui`). Details: [`app/README.md`](app/README.md).
- `cargo test --workspace` – unit and compatibility tests; `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`
- `scripts/test-root.sh` – black-box tests of the root helper (dry-run, no root needed)
- `cd app/ui && npm ci && npm test && npm run build` – UI tests (language rule, l10n coverage) and the UI build
- `scripts/check-l10n.sh` – checks that every text (UI and Rust) has a Hungarian translation
- Development run without touching real data: `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app` after `cargo build -p macvpn-app --features custom-protocol` (see `app/README.md`); `scripts/smoke-manage.sh` drives the windows in such a sandbox (`SMOKE_LANG=en|hu`)
- `scripts/build-dmg.sh` – builds the universal `dist/MacVPN.app` and `dist/MacVPN-x.y.z.dmg`
- Localization: English is the source language, Hungarian the translation; every text (UI, app, root helper) is in `crates/core/l10n/strings.json` (the key is the English text). The language follows the macOS preferred languages (the first Hungarian or English one, else English; per-app language in System Settings works too); the root helper gets it via `--lang en|hu`.
- The Swift implementation (up to 0.4.0) stays in `legacy/swift` until 1.0.0 ships, as the reference for the compatibility tests; CI does not build it (`cd legacy/swift && swift test` runs locally).
- Manual GUI checklist: `docs/manual-test-checklist.md`
- Release procedure and repository security settings: `docs/RELEASING.md`

### License
MIT – see [LICENSE](LICENSE).

---

## Magyar

A MacVPN egy menüsor-alkalmazás macOS-re (14+), amely egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP és Cisco IPsec kapcsolatokat. Tartalmaz config szerkesztőt, Keychain alapú titoktárolást, többfaktoros hitelesítést (egyszer használatos kód, OpenVPN challenge/response, webes / SAML bejelentkezés), valamint élő és debug naplót.

### Letöltés és telepítés
1. Töltsd le a legfrissebb `MacVPN-x.y.z.dmg` fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Nyisd meg a DMG-t, és húzd a `MacVPN.app`-ot az Applications mappába.
3. Az app nincs Developer ID-vel aláírva, ezért a Gatekeeper az első indításkor letiltja. Rendszerbeállítások → Adatvédelem és biztonság → **„Megnyitás mindenképp"**.
4. A Rendszerállapot ablakban telepítsd a hiányzó Homebrew csomagokat, és engedélyezd a root réteget (egy admin jelszó).

### Követelmények
- macOS 14 vagy újabb
- [Homebrew](https://brew.sh) – a VPN eszközök (`openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`) ezen keresztül települnek.

### Biztonsági megjegyzés
A root műveleteket a `/usr/local/libexec/macvpn/mvpn` végzi egy sudoers szabályon keresztül. A Homebrew könyvtára a felhasználó által írható, ezért a megoldás nem véd a felhasználói fiókon belül futó kártevő ellen. SSTP-nél a jelszó az `sstpc` parancssorában adódik át (az azonnal kicsillagozza). Részletek: [Biztonsági megjegyzések az útmutatóban](docs/user-guide.hu.md#10-biztonsági-megjegyzések).

### Felhasználói útmutató
- [Magyar útmutató](docs/user-guide.hu.md)
- [Angol útmutató](docs/user-guide.en.md)

### Fejlesztés
A MacVPN 1.0 Rustban készül (Cargo workspace), a felület Tauri 2 (Svelte + TypeScript). Kell hozzá Rust stable (`rustup`; a universal buildhez `rustup target add aarch64-apple-darwin x86_64-apple-darwin` is) és Node.js 22.12+.
- `crates/core` – platformfüggetlen logika (modellek, tárolás, validátorok, import/export, MFA, frissítés-ellenőrzés, az EN/HU szövegtábla: `crates/core/l10n/strings.json`); `crates/mvpn` – a root segédprogram (`/usr/local/libexec/macvpn/mvpn`); `crates/platform-mac` – macOS-szolgáltatások (Keychain, natív VPN, bejelentkezési elem, telepítők); `crates/app-core` – az app logikája felület nélkül; `app/` – a Tauri app (`app/src-tauri`) és a webes felülete (`app/ui`). Részletek: [`app/README.md`](app/README.md) (angolul).
- `cargo test --workspace` – unit- és kompatibilitási tesztek; `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`
- `scripts/test-root.sh` – a root segédprogram fekete dobozos tesztje (dry-run, nem kell root)
- `cd app/ui && npm ci && npm test && npm run build` – a felület tesztjei (nyelvválasztás, lokalizáció-lefedettség) és buildje
- `scripts/check-l10n.sh` – ellenőrzi, hogy minden szövegnek (felület és Rust) van magyar fordítása
- Fejlesztői futtatás a valódi adatok érintése nélkül: `cargo build -p macvpn-app --features custom-protocol` után `MACVPN_SANDBOX_HOME="$PWD/target/sandbox-home" target/debug/macvpn-app` (lásd `app/README.md`); a `scripts/smoke-manage.sh` egy ilyen sandboxban végigkattintja az ablakokat (`SMOKE_LANG=en|hu`)
- `scripts/build-dmg.sh` – a universal `dist/MacVPN.app` és `dist/MacVPN-x.y.z.dmg`
- Lokalizáció: az angol a forrásnyelv, a magyar a fordítás; minden szöveg (felület, app, root segédprogram) a `crates/core/l10n/strings.json`-ban van (a kulcs az angol szöveg). A nyelv a macOS preferált nyelveit követi (az első magyar vagy angol, különben angol; a Rendszerbeállításokban appra beállított nyelv is működik); a root segédprogram a `--lang en|hu` kapcsolóból kapja.
- A Swift-változat (0.4.0-ig) a `legacy/swift` alatt marad az 1.0.0 kiadásáig, a kompatibilitási tesztek referenciájaként; a CI nem fordítja (helyben: `cd legacy/swift && swift test`).
- Kézi GUI tesztlista: `docs/manual-test-checklist.md`
- Kiadás menete és a repó biztonsági beállításai: `docs/RELEASING.md` (angolul)

### Licenc
MIT – lásd [LICENSE](LICENSE).

---

## Support / Támogatás

If you find MacVPN useful, you can buy me a coffee. / Ha tetszik a MacVPN, egy kávéval támogathatod a fejlesztést.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/X8X01DODMO)
