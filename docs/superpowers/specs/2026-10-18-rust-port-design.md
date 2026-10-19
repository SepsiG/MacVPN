# MacVPN – Rust/Tauri port – tervezési specifikáció

**Dátum:** 2026-10-18
**Állapot:** jóváhagyott terv
**Kiinduló állapot:** a Swift-változat v0.4.0 (branch `feat/macvpn-v1`, publikusan `main`). A funkcionális és biztonsági követelmények forrása továbbra is `docs/superpowers/specs/2026-10-16-macvpn-design.md` (a továbbiakban: **fő spec**), az `docs/openvpn-directives.md` és a meglévő tesztkészletek. Ez a dokumentum csak azt rögzíti, ami a porttal változik.

## 1. Cél

- A teljes megoldás (app + root réteg) átírása Rustra, a felület Tauri 2-vel.
- **Funkcionális paritás** a v0.4.0-val: minden VPN-típus, validálás (OpenVPN-szintek, WireGuard, strongSwan, SSTP), import/export, Keychain, natív L2TP/Cisco, MFA (mind a négy módszer), sorrend, napló/debug, telepítő varázsló, eltávolítás, bejelentkezéskori indítás, aláírt frissítés, EN/HU lokalizáció.
- **Biztonsági paritás:** a fő spec 3. fejezetének minden szabálya és az összes audit-javítás változatlanul érvényes.
- **Frissítésként érkezik:** a v0.4.0 (Swift) appon belüli frissítője telepíti, adatvesztés nélkül.
- **Felkészülés** a későbbi Windows/Linux portra (most nem cél).

### Nem cél
- Windows/Linux változat.
- Új funkció (a port alatt nincs funkcióbővítés).
- A titkosítási/aláírási modell megváltoztatása.

## 2. Felépítés (Cargo workspace)

```
macvpn/
├─ Cargo.toml                 (workspace)
├─ crates/
│  ├─ core/                   platformfüggetlen logika, a teljes tesztkészlettel
│  │   models, storage (meta.json, config, ranking JSON), validators
│  │   (openvpn tiers + argumentSpecs, wireguard, strongswan, sstp),
│  │   importer/exporter, ranking, mfa (SCRV1, CRV1, URL-validálás, szöveg-
│  │   tisztítás), management protocol (parser + allowlistes parancsépítő),
│  │   update (semver, release-parse, asset-útvonal, SHA-256, Ed25519),
│  │   l10n (EN/HU tábla), log line osztályozás, root status JSON
│  ├─ platform-mac/           macOS-specifikus: Keychain (security-framework),
│  │   SCNetworkConnection + scutil (natív VPN), SMAppService/LaunchAgent,
│  │   osascript-os root-telepítő/eltávolító, update installer (hdiutil,
│  │   codesign, helper script), notifications
│  └─ mvpn/                   EGY root bináris (a bash mvpn + mvpn-validate +
│      mvpn-mgmt + ovpn-dns utódja), alparancsokkal
├─ app/                       Tauri 2: src-tauri (Rust parancsok a core és a
│   platform-mac fölött) + ui (Svelte + TypeScript)
├─ scripts/                   build-dmg.sh, test-root.sh (a Rust mvpn ellen),
│                             sign-release.sh, check-l10n, make-icon
└─ Tests / fixtures           a Swift-tesztek fixture-jei (OpenVPN 2.7.8 opció-
                              listák, MikroTik, stb.) változatlanul
```

A platform-specifikus kód csak a `platform-mac` crate-ben és az app platformrétegében lehet; a `core` nem hivatkozhat macOS API-ra. A későbbi port új `platform-windows`/`platform-linux` crate-eket jelent.

## 3. Root réteg: `mvpn` (Rust)

- Telepítési hely és sudoers-szabály **változatlan**: `/usr/local/libexec/macvpn/mvpn`, `<user> ALL=(root) NOPASSWD: /usr/local/libexec/macvpn/mvpn` + a meglévő `env_reset`/`env_delete` sorok.
- Alparancsok (a meglévő CLI-interfész megtartásával, hogy a v0.4.0 tesztjei és az app hívásai ugyanúgy működjenek):
  - `up|down <kind> <id> [--debug] [--dry-run] [--accept-risky a,b] --lang xx` (secrets a stdin-en: `username`, `password`, `psk`, `keypass`, `otp`, `challenge`…)
  - `status`, `version`, `respond openvpn <id>`
  - `validate <kind> <file> [--accept-risky …] [--sstp-params|--sstp-ca|--swan-names]` (a régi `mvpn-validate` funkciói; a régi binárisnév is működjön szimlink nélkül a telepítőben nem szükséges)
  - `hook ovpn-dns <run> <log>` (az OpenVPN `--up/--down` ezt hívja; a környezetből csak az engedélyezett változókat olvassa)
  - `mgmt-bridge …` (a régi `mvpn-mgmt`; háttérfolyamatként indul)
- Minden biztonsági szabály a fő spec 3. fejezete és az audit-javítások szerint: UUID-validálás, felhasználói jogú config-másolás (`sudo -u … cat`), méretkorlát, symlink/hardlink-védelem, root-only futási könyvtár, zárak (stale-lock reaper), SIGTERM-takarítás, maszkolás (minden nem üres titok), root-only OpenVPN/pppd napló, ECHO-szűrés, horgonyzott completion-minta (`us=` is), `LC_ALL=C`-nek megfelelő determinisztikus feldolgozás, `--accept-risky` regex, askpass, MFA-bridge allowlist, `/var/run/macvpn-ui` állapotfájlok, TEST_MODE hookok csak `uid != 0` esetén.
- **Paritás-ellenőrzés:** a meglévő `scripts/test-root.sh` (~370 eset) a Rust bináris ellen fut (minimális harness-módosítással: `$MVPN` a binárisra mutat). Minden eset zöld kell legyen.
- Root VERSION: **7**. A telepítő egyetlen binárist + `VERSION`-t telepít (SHA-256 ellenőrzéssel, a meglévő integritás-szabályokkal), és eltávolítja a régi `ovpn-dns`, `mvpn-validate`, `mvpn-mgmt` fájlokat. Az eltávolító ezeket is törli.

## 4. Adat- és frissítés-kompatibilitás (kötelező)

- **Bundle:** `MacVPN.app`, `CFBundleIdentifier = local.macvpn`, `LSUIElement = true`, `CFBundleDevelopmentRegion = en`, `CFBundleLocalizations = [en, hu]`, `MacVPNUpdateRepo = SepsiG/MacVPN`, `MacVPNUpdateRepoID = 1422472799`, verzió **1.0.0**. Ad-hoc aláírás; `codesign --verify --strict` sikeres; nincs a bundle-ből kifelé mutató symlink.
- **Release-artefaktok** azonosak: `MacVPN-<v>.dmg`, `.dmg.sha256` (`<hash>  <név>`), `.dmg.sig` (Ed25519, üzenet: `macvpn-update-v1\n<v>\n<sha256>\n`), ugyanazokkal a beágyazott publikus kulcsokkal. Így a v0.4.0 updatere (repo-ID, útvonal-ellenőrzés, aláírás, bundle ID, verzió, codesign, csere) elfogadja.
- **Adatok:** a Rust-változat ugyanazokat olvassa/írja: `~/Library/Application Support/MacVPN/connections/<UUID>/{meta.json,config}`, `connection-order.json`, `system-otp.json`, Keychain service `local.macvpn.secrets`, account `<UUID>.<mező>`, UserDefaults-kulcsok (vagy azok egyszeri átvétele). A `meta.json` formátum (ISO8601 dátumok, mezőnevek, hiányzó mezők alapértékei) bitre kompatibilis; tesztek Swift által írt fixture-ökkel.
- **Keychain ACL:** az új bináris ad-hoc aláírása miatt a macOS egyszer engedélyt kérhet; dokumentálva.
- **Bejelentkezési elem:** a LaunchAgent-plist (`local.macvpn.launcher`, `open -b local.macvpn`) változatlanul működik.

## 5. Felület (Tauri 2)

- Tálca/menüsor ikon állapot szerint (szürke/zöld/piros/kulcs), a menü-ablak a v0.4.0 tartalmával (sorrend, kapcsolók, Option+kattintás = debug, státuszhiba-sor, frissítés, auto-frissítés, 24 órás késleltetés, bejelentkezéskori indítás, Súgó, Kilépés).
- Ablakok: Kapcsolatok (lista kitűzés/húzás, szerkesztők: szöveges + hibalista + kockázatos-panel, natív L2TP/Cisco űrlap, SSTP űrlap, rendszer-VPN PSK/OTP; Napló fül élő követéssel/szűréssel/mentéssel; mentetlen-változás védelem), Rendszerállapot (brew, eszközök, root réteg, eltávolítás, bejelentkezési elem), Frissítés, MFA-kódbekérő és webes jóváhagyás (fókuszlopás nélkül).
- Lokalizáció: EN/HU, a rendszer nyelve szerint (első `hu*`/`en*`, különben angol); a szövegtábla egyetlen forrásból (core) az UI-nak is.
- A Tauri webview csak helyi tartalmat tölt (CSP: nincs távoli forrás, nincs `eval`); a Rust-parancsok listája szűk, minden bemenet validálva; külső URL csak a meglévő megerősítéses folyamaton át nyílik.

## 6. Build, CI, kiadás

- `scripts/build-dmg.sh`: `cargo` (universal: aarch64 + x86_64, `lipo`), Tauri bundle → `MacVPN.app` (egyedi Info.plist-kulcsok összefésülve), a `mvpn` root bináris a `Contents/Resources/root/` alá, ad-hoc aláírás, hdiutil DMG – ugyanaz a kimeneti név.
- CI/Release: a meglévő megerősített workflow-k Rust/Node lépésekkel (SHA-pinned actionök, legkisebb jogosultság, draft release, offline aláírás `scripts/sign-release.sh`-sel – a publikus kulcsok forrása a Rust core lesz).
- Tesztek: `cargo test` (a ~470 Swift-teszt megfelelői), `scripts/test-root.sh` a Rust `mvpn` ellen, l10n-lefedettség, clippy `-D warnings`, `cargo fmt --check`.

## 7. Átállás menete

1. **Fázis 1 – core + mvpn + platform-mac**, teljes tesztparitással; biztonsági review.
2. **Fázis 2 – Tauri felület.**
3. **Fázis 3 – csomagolás, CI, migrációs próba:** a v0.4.0 frissítő ellenőrzéseinek lefuttatása az új DMG-n (bundle ID, verzió, codesign, symlink, aláírás), adatkompatibilitás valódi `connections/` másolaton; végső biztonsági review; kiadás **1.0.0**.

A Swift-változat a `main`-en marad a v1.0.0 kiadásáig; a port a `rust-port` branchen készül.
