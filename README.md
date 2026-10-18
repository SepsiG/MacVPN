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
- `swift test` – unit tests
- `scripts/test-root.sh` – tests of the root scripts (dry-run, no root needed)
- `scripts/check-l10n.sh` – checks that every UI string has a Hungarian translation in the catalog
- `swift run MacVPN` – run during development. To install the root layer from a `swift run` build, first build the validator and the management bridge and copy them next to the root scripts: `swift build --product mvpn-validate && swift build --product mvpn-mgmt && cp .build/debug/mvpn-validate .build/debug/mvpn-mgmt Resources/root/` (`.build/debug` is the bin path that `swift build --show-bin-path` prints; the copy is git-ignored)
- `scripts/build-dmg.sh` – builds `dist/MacVPN-x.y.z.dmg`
- Localization: English is the source language, Hungarian the translation. App UI strings live in `Sources/MacVPN/Resources/Localizable.xcstrings` (keys are the English text); the catalog is not a SwiftPM resource: `build-dmg.sh` compiles it with `xcrun xcstringstool compile` straight into `MacVPN.app/Contents/Resources/<lang>.lproj`, and the app reads it from the main bundle. `swift run MacVPN` therefore always shows English. MacVPNCore and `mvpn-validate` messages live in an embedded table (`Sources/MacVPNCore/L10n.swift`); the root scripts get the language via `--lang en|hu` and keep both languages next to each other (`msg "English" "Magyar"`).
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
- `swift test` – unit tesztek
- `scripts/test-root.sh` – a root scriptek tesztje (dry-run, nem kell root)
- `scripts/check-l10n.sh` – ellenőrzi, hogy az app minden szövegének van magyar fordítása a catalogban
- `swift run MacVPN` – futtatás fejlesztéskor. Ha egy `swift run` buildből telepíted a root réteget, előbb fordítsd le a validátort és a management közvetítőt, és másold őket a root scriptek mellé: `swift build --product mvpn-validate && swift build --product mvpn-mgmt && cp .build/debug/mvpn-validate .build/debug/mvpn-mgmt Resources/root/` (a `.build/debug` a `swift build --show-bin-path` által kiírt bin könyvtár; a másolatot a git figyelmen kívül hagyja)
- `scripts/build-dmg.sh` – `dist/MacVPN-x.y.z.dmg`
- Lokalizáció: az angol a forrásnyelv, a magyar a fordítás. Az app szövegei a `Sources/MacVPN/Resources/Localizable.xcstrings` fájlban vannak (a kulcs az angol szöveg); a catalog nem SwiftPM resource: a `build-dmg.sh` `xcrun xcstringstool compile`-lal közvetlenül a `MacVPN.app/Contents/Resources/<nyelv>.lproj`-ba fordítja, és az app a main bundle-ből olvassa. Ezért a `swift run MacVPN` mindig angol. A MacVPNCore és a `mvpn-validate` üzenetei egy beágyazott táblában vannak (`Sources/MacVPNCore/L10n.swift`); a root scriptek a nyelvet a `--lang en|hu` kapcsolóból kapják, és a két nyelvet egymás mellett tartják (`msg "English" "Magyar"`).
- Kézi GUI tesztlista: `docs/manual-test-checklist.md`
- Kiadás menete és a repó biztonsági beállításai: `docs/RELEASING.md` (angolul)

### Licenc
MIT – lásd [LICENSE](LICENSE).

---

## Support / Támogatás

If you find MacVPN useful, you can buy me a coffee. / Ha tetszik a MacVPN, egy kávéval támogathatod a fejlesztést.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/X8X01DODMO)
