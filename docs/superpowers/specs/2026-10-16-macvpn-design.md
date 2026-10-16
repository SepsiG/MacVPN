# MacVPN – tervezési specifikáció

**Dátum:** 2026-10-16
**Állapot:** jóváhagyott terv, implementációs terv előtt

## 1. Cél

Egyszerű, gyors, natív macOS menüsor-alkalmazás, amely egy helyen kezeli a felhasználó VPN-kapcsolatait:

- **OpenVPN** (a Tunnelblick kiváltása, `openvpn` CLI-vel)
- **WireGuard** (a WireGuard.app kiváltása, `wg-quick` CLI-vel)
- **IPsec**: L2TP/IPsec, Cisco IPsec (IKEv1 + XAuth), IKEv2

Funkciók: kapcsolatok listázása, indítása/leállítása, állapot kijelzése, config import / létrehozás / szerkesztés, jelszavak Keychainben. Terjesztés: egyetlen DMG, Developer ID nélkül.

### Nem cél (YAGNI)

- Automatikus újracsatlakozás, kill switch, split-tunnel szerkesztő
- OTP / 2FA bekérés
- Privileged helper (SMAppService) – később cserélhető, a backend-réteg erre fel van készítve
- VPN binárisok beágyazása az app bundle-be (Homebrew-ból jönnek)
- Kapcsolatok közötti kizárólagosság / ütközéskezelés (csak naplózzuk)

## 2. Architektúra

```
┌──────────────────────────────────────┐
│  MacVPN.app (menüsor, user jogon)    │
│  ├─ UI: MenuBarExtra + kezelő ablak  │
│  ├─ ConnectionStore (Application     │
│  │   Support/MacVPN/connections)     │
│  ├─ KeychainStore                    │
│  ├─ SetupChecker (brew, eszközök,    │
│  │   root scriptek)                  │
│  └─ VPNBackend implementációk:       │
│     OpenVPN │ WireGuard │ StrongSwan │
│     NativeMac                        │
└───────┬──────────────────┬───────────┘
        │ sudo -n mvpn …   │ scutil --nc …
        ▼                  ▼
┌────────────────────────┐ ┌───────────────────┐
│ /usr/local/libexec/    │ │ macOS natív VPN   │
│   macvpn/ (root:wheel) │ │ (L2TP, Cisco,     │
│ ├ mvpn  (dispatcher)   │ │  meglévők pl.     │
│ └ ovpn-dns (up/down)   │ │  Office L2TP)     │
│ /etc/sudoers.d/macvpn  │ └───────────────────┘
│ /var/run/macvpn/ (700) │
│ /var/log/macvpn/       │
└────────────────────────┘
```

### Backend → eszköz hozzárendelés

| Típus | Backend | Eszköz | Config az appban |
|---|---|---|---|
| OpenVPN | `OpenVPNBackend` | `openvpn` (brew) via `mvpn` | szövegszerkesztő (`.ovpn`) |
| WireGuard | `WireGuardBackend` | `wg-quick`, `wg`, `wireguard-go`, `bash` (brew) via `mvpn` | szövegszerkesztő (`.conf`) |
| IKEv2 | `StrongSwanBackend` | `charon`, `swanctl` (brew `strongswan`) via `mvpn` | szövegszerkesztő (`swanctl.conf` szintaxis) |
| L2TP/IPsec | `NativeMacBackend` | `scutil --nc` | űrlap → `.mobileconfig` |
| Cisco IPsec | `NativeMacBackend` | `scutil --nc` | űrlap → `.mobileconfig` |
| Meglévő natív (nem az app hozta létre) | `NativeMacBackend` | `scutil --nc` | csak vezérlés, szerkesztés nincs |

### `VPNBackend` protokoll

```swift
protocol VPNBackend {
    var kind: VPNKind { get }
    func validate(_ config: String) -> [ValidationIssue]
    func connect(_ connection: Connection, secrets: Secrets) async throws
    func disconnect(_ connection: Connection) async throws
}
```

Az állapotot nem backendenként, hanem egy közös `StatusPoller` kérdezi le (lásd 5. fejezet). Minden külső parancs egy `CommandRunner` protokollon megy át, így tesztben mockolható.

## 3. Root réteg (sudoers + scriptek)

### Telepített fájlok

- `/usr/local/libexec/macvpn/mvpn` – egyetlen dispatcher script, `root:wheel 755`
- `/usr/local/libexec/macvpn/ovpn-dns` – OpenVPN up/down script a DNS beállításához (`scutil`-lal), `root:wheel 755`
- `/usr/local/libexec/macvpn/VERSION` – a telepített scriptek verziója
- `/etc/sudoers.d/macvpn` – `root:wheel 440`, tartalma:
  ```
  <felhasználó> ALL=(root) NOPASSWD: /usr/local/libexec/macvpn/mvpn
  ```
- Futási könyvtár: `/var/run/macvpn/<id>/` (`root 700`), napló: `/var/log/macvpn/<id>.log`

A telepítés egyetlen `osascript … with administrator privileges` hívással történik. A telepítő a scripteket az app bundle `Resources/root/` mappájából másolja, majd `visudo -c -f`-fel ellenőrzi a sudoers fájlt, mielőtt a helyére tenné.

### `mvpn` interfész

```
mvpn up     <openvpn|wireguard|strongswan> <id>    # secrets JSON a stdin-en
mvpn down   <openvpn|wireguard|strongswan> <id>
mvpn status                                        # JSON az összes aktív kapcsolatról
mvpn version
```

### Biztonsági szabályok (kötelező)

1. Az `<id>` csak UUID formátumú lehet (regex), egyébként hiba.
2. A forrás config útvonalát a script **maga állítja elő**: `~$SUDO_USER/Library/Application Support/MacVPN/connections/<id>/config`. Paraméterként útvonalat nem fogad el.
3. A forrás nem lehet symlink. A script átmásolja a `/var/run/macvpn/<id>/` könyvtárba, és **a másolatot** validálja és használja.
4. A binárisokat fix útvonalakon keresi (`/opt/homebrew/bin`, `/opt/homebrew/sbin`, `/opt/homebrew/opt/strongswan/libexec`, `/usr/local/bin`, `/usr/local/sbin`). A `PATH`-ra nem hagyatkozik.
5. A jelszavak stdin-en érkeznek, és `600`-as fájlba kerülnek a futási könyvtárban. A `down` parancs, illetve hiba esetén ezek törlődnek.
6. **Engedélyezőlista (allowlist).** Csak ismert, biztonságos OpenVPN-direktívák és WireGuard-kulcsok engedettek, minden más hiba. Vezérlőkarakter (a tabulátoron kívül) sehol nem lehet a configban. Az OpenVPN-direktíva neve csak `[a-z0-9-]` lehet, így idézőjeles vagy escape-elt direktívával nem lehet megkerülni a szabályt. Az inline blokkok neve szintén engedélyezőlistán van. A záró tag csak pontos egyezéssel fogadható el, a lezáratlan blokk hiba. strongSwan esetén a kommenteket idézőjel-tudatosan kezeljük, az `include` pedig bárhol tiltott. A pontos listák a `Validators.swift`-ben vannak, a `mvpn` ezeket tükrözi. Explicit tiltott direktívák, ezekre külön hibaüzenet jön:
   - **OpenVPN:** `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `auth-user-pass-verify`, `client-connect`, `client-disconnect`, `learn-address`, `plugin`, `script-security`, `config`, `cd`, `chroot`, `daemon`, `log`, `log-append`, `writepid`, `management`, `status`, `setenv`, `iproute`, `ifconfig-noexec`, `route-noexec`, `user`, `group`, `pkcs11-providers`, `providers`, `engine`, `dns-updown`, `tls-export-cert`, `tmp-dir`, `tls-crypt-v2-verify` (az utóbbi kettő miatt a down script nem tudná visszaállítani a DNS-t). Külső fájlhivatkozás (`ca`, `cert`, `key`, `tls-auth`, `tls-crypt`, `pkcs12`, `secret`, `auth-user-pass <fájl>`) sem engedett: minden tanúsítvány inline blokkban (`<ca>…</ca>`) legyen.
   - **WireGuard:** `PreUp`, `PostUp`, `PreDown`, `PostDown`, `SaveConfig`.
   - **strongSwan:** `updown`, `include`, valamint `secrets` blokk fájlhivatkozással (`file =`).
7. Az OpenVPN-t a script mindig ezekkel a kötelező opciókkal indítja: `--script-security 2 --up /usr/local/libexec/macvpn/ovpn-dns --down /usr/local/libexec/macvpn/ovpn-dns --writepid /var/run/macvpn/<id>/pid --log /var/log/macvpn/<id>.log --daemon`, valamint ha van jelszó, `--auth-user-pass /var/run/macvpn/<id>/auth`. Ez a fájl (root, `600`, a `700`-as futási könyvtárban) a bontásig megmarad, hogy újracsatlakozáskor (ping-restart, hálózatváltás) az OpenVPN újraolvashassa; a `down` és minden sikertelen `up` törli. Sikertelen vagy megszakított `up` után a `mvpn` lebontja a félig felépült kapcsolatot, visszaállítja a DNS-t és törli a futási könyvtárat.
8. A WireGuard interfész neve `mv` + az id első 8 hex karaktere (például `mv1a2b3c4d.conf`). A wg-quick ezt az utun-hoz rendeli.
9. A strongSwan esetén a script elindítja a `charon`-t, ha még nem fut, aztán `swanctl --load-all --file <másolat>`, majd `swanctl --initiate --child <első child>`. A PSK és az EAP jelszó a stdin-ről a másolatba kerül.
10. `--dry-run` kapcsoló: validál és kiírja, mit futtatna, de nem indít semmit. Ezt a teszteléshez használjuk.
11. `--debug` kapcsoló (`mvpn up --debug …`): bőbeszédű csatlakozás, részletesen a 6. fejezet „Debug mód" pontjában.
12. A napló (`/var/log/macvpn/<id>.log`) tulajdonosa `$SUDO_USER`, jogosultsága `600`. Jelszó, PSK és privát kulcs soha nem kerül bele: a `mvpn` a saját kiírásaiban maszkol (`***`), az eszközök kimenetét pedig a jelszómezők értékeire szűri, mielőtt a naplóba írná.

### Ismert korlát

A Homebrew könyvtára (`/opt/homebrew`) a felhasználó által írható. Aki a felhasználó nevében kódot futtat, kicserélheti például az `openvpn` binárist, és a `mvpn` ezt rootként futtatja. A sudoers-alapú megoldás ezért **nem véd a felhasználói fiókon belül futó kártevő ellen**: a gyakorlatban jelszó nélküli root-elérést ad a VPN-eszközökön keresztül. A direktíva-tiltás a véletlen vagy importált veszélyes configok ellen véd. A teljes védelemhez root tulajdonú binárisok és privileged helper kellenének (lásd 11. fejezet). Egyfelhasználós, adminisztrátor által használt gépre ezt elfogadott kockázatnak tekintjük.

A szabályok egyetlen forrása a `Validators.swift`. A root oldalon a `/usr/local/libexec/macvpn/mvpn-validate` bináris (root:wheel 755, ugyanebből a kódból fordítva) futtatja őket, így nincs külön bash-tükör, ami elcsúszhatna. Az app oldali validátor ugyanezeket a szabályokat ellenőrzi (gyors visszajelzés a szerkesztőben). A **hiteles ellenőrzés a root scriptben van**.

### Import segítség

OpenVPN importnál, ha a `.ovpn` külső fájlokra hivatkozik (`ca ca.crt`), az app a fájl mellől beolvassa és inline blokká alakítja. Ha a fájl nem található, hibát jelez.

## 4. Adattárolás

- `~/Library/Application Support/MacVPN/connections/<uuid>/`
  - `meta.json`: `{ id, name, kind, createdAt, nativeServiceName? }`
  - `config`: a nyers config (OpenVPN / WireGuard / strongSwan esetén)
  - natív típusnál `profile.mobileconfig` (a generált profil)
- Jelszavak: Keychain, service = `macvpn`, account = `<uuid>.<mező>` (például `.password`, `.psk`, `.username`).
- A meglévő natív kapcsolatok (`scutil --nc list`) nem kerülnek tárolásra, futásidőben jelennek meg a listában.

### Natív (L2TP / Cisco) profil

- Űrlapmezők: név, szerver, fióknév, jelszó, PSK (shared secret), Cisco esetén csoportnév (group name), valamint „minden forgalom a VPN-en át".
- Generálás: `com.apple.vpn.managed` payload. `VPNType` értéke `L2TP` vagy `IPSec` (Cisco). Fix `PayloadIdentifier` = `macvpn.<uuid>`, így az újragenerálás felülírja a korábbi profilt.
- Mentés után `open profile.mobileconfig`, a felhasználó a Rendszerbeállításokban hagyja jóvá. Az app `scutil --nc list`-ben keresi a megjelenő szolgáltatást, és a `meta.json`-be menti a nevét.
- A jelszó és a PSK a generált profilba kerül, a macOS a rendszer-kulcskarikában tárolja. Az app is elmenti őket a saját Keychain-bejegyzéseibe, hogy újragenerálásnál ne kelljen újra beírni.
- Csatlakozás: `scutil --nc start <szolgáltatás-ID>` jelszó nélkül. Jelszót parancssori argumentumként nem adunk át, mert a `ps` kimenetében látszana. Bontás: `scutil --nc stop <szolgáltatás-ID>`.
- Törlés: az app törli a saját fájljait, és megnyitja a Profilok panelt, a profilt a felhasználó távolítja el.

## 5. Állapot lekérdezése

- `StatusPoller` 3 másodpercenként (és ébredéskor, illetve minden connect/disconnect után azonnal):
  - `sudo -n mvpn status` → JSON: `[{id, kind, state: connecting|connected|failed, iface, ip, since}]`
    - OpenVPN: él-e a pid, és a naplóban szerepel-e az `Initialization Sequence Completed`
    - WireGuard: `wg show <iface> latest-handshakes`
    - strongSwan: `swanctl --list-sas`
  - `scutil --nc list` és `scutil --nc status <név>` a natív kapcsolatokhoz
- A poller csak akkor fut, ha van aktív vagy épp csatlakozó kapcsolat, vagy ha nyitva van a menü. Ezen kívül 30 másodpercenként fut.
- Az app kilépés és újraindítás után a fenti forrásokból felismeri a már futó kapcsolatokat.

## 6. Felület

### Menüsor (`MenuBarExtra`, `LSUIElement = true`)

```
 🛡  szürke: nincs kapcsolat · zöld: van aktív · piros: hiba
 ┌──────────────────────────────┐
 │ ● Home        WireGuard  [⏻] │  zöld pont, IP, uptime
 │ ○ Iroda       OpenVPN    [⏻] │
 │ ◌ Office      L2TP       [⏻] │  ◌ = csatlakozás folyamatban
 │ ○ Partner     IKEv2      [⏻] │
 ├──────────────────────────────┤
 │ ＋ Új kapcsolat / Import…     │
 │ ⚙ Kapcsolatok kezelése…       │
 │ Rendszerállapot · Kilépés    │
 └──────────────────────────────┘
```

- Ha egy VPN-típushoz hiányzik eszköz, az adott típusú kapcsolatok kiszürkülnek, rajtuk a „Hiányzó eszköz" jelzés.
- Egyszerre több kapcsolat is aktív lehet.

### Kezelő ablak

- Bal oldalt kapcsolatlista (+ / − gomb), jobb oldalt a kijelölt kapcsolat szerkesztője.
- **Szöveges típusok:** monospace szerkesztő. Mentéskor validál, a hibás vagy tiltott sorokat pirosan jelöli, ilyenkor nem ment. A szerkesztő alatt külön felhasználónév-, jelszó- és PSK-mezők vannak, ezek a Keychainbe mennek.
- **Natív típusok:** űrlap (lásd 4. fejezet).
- **Import:** drag & drop vagy fájlválasztó. A típust kiterjesztés és tartalom alapján ismeri fel: `.ovpn` → OpenVPN; `[Interface]` + `PrivateKey` → WireGuard; `connections {` → strongSwan.
- **Export:** kapcsolatonként egy „Exportálás…" gomb. A config az eredeti formátumában menthető ki: `.ovpn`, WireGuard `.conf`, strongSwan `swanctl.conf`, natívnál `.mobileconfig`. Jelszó, PSK és felhasználónév **nem** kerül az exportba (natív profilban ezek üresen maradnak), így az exportált fájl bárkinek átadható. A WireGuard `PrivateKey` része a confignak, ezért arra figyelmeztetés jelenik meg. A `.ovpn`, `.conf` és `swanctl.conf` export visszaimportálható; a `.mobileconfig` nem: azt a Finderben dupla kattintással a macOS Profilok telepítik, a MacVPN importja erre külön hibaüzenettel utal.
- **Import több fájlból:** a fájlválasztó és a drag & drop egyszerre több fájlt is elfogad.
- **Napló fül:** a kapcsolat naplója élőben, a fájl tail-elésével (`DispatchSource` file watcher). A napló minden csatlakozásnál új szakasszal (fejléccel) kezdődik.

### Debug mód

Cél: ha egy kapcsolat nem jön létre, lépésről lépésre látszódjon, mi történt.

- **Indítás:** a menüben Option+kattintás a kapcsolóra, vagy a kezelő ablakban a „Csatlakozás debug módban" gomb. A Napló fül ekkor automatikusan megnyílik, és élőben követi az eseményeket.
- **A napló sortípusai, színkóddal:**
  - `▶ [mvpn]` – a `mvpn` saját lépései: config másolása, validálás, a talált binárisok útvonala
  - `$ …` – **minden lefuttatott parancs** teljes parancssorral (a jelszavak maszkolva)
  - eszköz kimenet – az `openvpn`, `wg-quick`, `charon`/`swanctl` saját sorai
  - `✗` – hiba és kilépési kód
- **Eszközönként emelt részletesség debug módban:**
  - **OpenVPN:** `--verb 5` (alapból `--verb 3`). Látszik a TLS handshake, a push reply, a route-ok és a DNS opciók, valamint az `ovpn-dns` script parancsai.
  - **WireGuard:** a `wg-quick` alapból kiírja az általa futtatott parancsokat (`[#] …` sorok). Debug módban ezen felül `LOG_LEVEL=debug` a `wireguard-go`-nak, és a csatlakozás után a `wg show <iface>` kimenete (handshake, átvitt bájtok, kulcsok nélkül).
  - **strongSwan:** `swanctl --initiate --loglevel 2` (alapból 1). A vici log stream megmutatja az IKE_SA_INIT, az AUTH és a CHILD_SA egyeztetését.
  - **Natív (L2TP, Cisco):** nincs saját naplófájl. Az app debug csatlakozáskor `log stream --style compact --predicate 'process IN {"racoon","pppd","neagent","nesessionmanager"} OR subsystem == "com.apple.networkextension"'` kimenetét gyűjti a Napló fülre a csatlakozás idejére (legfeljebb 60 mp-ig vagy a sikeres kapcsolatig).
- **Diagnosztikai pillanatkép** debug módban, a `mvpn` írja a naplóba csatlakozás előtt és után:
  - a szerver nevének feloldása (`dscacheutil -q host -a name <szerver>`)
  - route tábla (`netstat -rn -f inet`)
  - DNS állapot (`scutil --dns`, az első resolverek)
  - aktív interfészek (`ifconfig -l`, a VPN interfész címe)
- **Napló műveletek:** keresés vagy szűrés (csak parancsok / csak hibák), „Másolás", „Mentés fájlba…". A mentett napló is maszkolt.
- A debug mód csak az adott csatlakozásra érvényes, bontás után a következő csatlakozás normál módban indul.

### Telepítő varázsló / Rendszerállapot

Indításkor fut, ha bármi hiányzik. Később a menüből is elérhető.

1. **Homebrew** (`/opt/homebrew/bin/brew` vagy `/usr/local/bin/brew`). Ha hiányzik: figyelmeztetés, és a „Telepítés" gomb Terminált nyit a hivatalos install paranccsal. Ezután „Újraellenőrzés".
2. **Eszközök:** `openvpn`, `wg`, `wg-quick`, `wireguard-go`, `swanctl`, `charon`, `bash` (4-es vagy újabb verzió). A hiányzók listája mellett „Telepítés" gomb van: `brew install openvpn wireguard-tools strongswan bash` user jogon fut, a kimenet élőben látszik egy panelen.
3. **Root scriptek + sudoers:** ha hiányoznak vagy a `VERSION` eltér az app bundle-ben lévőtől, „Engedélyezés" gomb jelenik meg, ami egyszer kéri az admin jelszót (lásd 3. fejezet).

Mindhárom pont zöld/piros jelzést kap.

## 7. Hibakezelés

| Helyzet | Viselkedés |
|---|---|
| Hibás vagy tiltott config | Mentés nem történik, a hibás sorok pirosan jelölve |
| Csatlakozási hiba | Piros ikon, macOS értesítés rövid okkal (napló alapján: `AUTH_FAILED`, `TLS handshake failed`, timeout). Kattintásra a Napló fül nyílik meg |
| Nincs kapcsolat 30 s alatt | A `mvpn` leállítja a folyamatot, az app „Időtúllépés" hibát mutat |
| Váratlan bontás (a folyamat leáll, az interfész eltűnik) | Értesítés, nincs automatikus újracsatlakozás |
| `sudo -n` sikertelen | „Rendszerállapot" ablak, újratelepítés felajánlása |
| Kilépés aktív kapcsolattal | Kérdés: „Leállítsam az aktív kapcsolatokat?" Ha nem, futnak tovább |
| Alvás / ébredés | Ébredéskor azonnali állapot-újraellenőrzés |
| Default route ütközés | Csak napló-bejegyzés, nincs tiltás |

## 8. Projektstruktúra

```
macvpn/
├─ Package.swift                  # SwiftPM, macOS 14+
├─ Sources/
│  ├─ MacVPN/                     # executable: SwiftUI app, UI réteg
│  └─ MacVPNCore/                 # library: modellek, store-ok, validátorok,
│                                 #   backendek, CommandRunner, StatusPoller,
│                                 #   MobileconfigGenerator, SetupChecker
├─ Tests/MacVPNCoreTests/
├─ Resources/
│  ├─ Info.plist                  # LSUIElement=true
│  ├─ AppIcon.icns
│  └─ root/ (mvpn, ovpn-dns, VERSION)
├─ scripts/
│  ├─ build-dmg.sh
│  └─ test-root.sh                # mvpn --dry-run tesztek
└─ docs/
```

## 9. Tesztelés

- **Unit tesztek** (`swift test`, `MacVPNCoreTests`):
  - validátorok: minden tiltott direktívára külön teszteset, plusz kis- és nagybetű, szóközök, kommentek kezelése
  - típusfelismerés importnál
  - OpenVPN külső fájl → inline átalakítás
  - `.mobileconfig` generálás (érvényes plist, helyes `VPNType`, fix `PayloadIdentifier`)
  - backend parancsösszeállítás mock `CommandRunner`-rel
  - `mvpn status` JSON parse
  - naplósor-osztályozás (`▶ [mvpn]`, `$`, kimenet, `✗`) és jelszó-maszkolás
- **Root script tesztek** (`scripts/test-root.sh`, `mvpn --dry-run`). Mindet el kell utasítania:
  - tiltott direktívát tartalmazó config
  - symlinkként megadott config
  - nem UUID id (például `../etc`)
  - külső fájlhivatkozás az `.ovpn`-ben

  Ezen felül ellenőrzi, hogy `--debug` módban a stdin-en kapott jelszó nem jelenik meg a naplóban.
- **Kézi tesztlista:**
  - típusonként egy valódi kapcsolat fel és le
  - alvás és ébredés
  - kilépés aktív kapcsolattal, majd újraindítás (felismerés)
  - tiszta telepítés DMG-ből: Gatekeeper, varázsló, brew install, sudoers
  - a meglévő `Office L2TP` és `Home` kapcsolat kezelése

## 10. Build és terjesztés

`scripts/build-dmg.sh`:

1. `swift build -c release --arch arm64 --arch x86_64`
2. `MacVPN.app` összeállítása: bináris, `Info.plist`, ikon, `Resources/root/*`
3. `codesign --force --deep --sign -` (ad-hoc aláírás)
4. `hdiutil create`: `MacVPN.dmg` az appal és egy `/Applications` symlinkkel

**Telepítés a felhasználónak:**

1. Megnyitja a DMG-t, és áthúzza az appot az Applications mappába.
2. Első indításkor a Gatekeeper letiltja az appot. A Rendszerbeállítások → Adatvédelem és biztonság → „Megnyitás mindenképp" gombbal engedélyezi.
3. A varázsló telepíti a brew csomagokat és a root réteget (egy admin jelszó).
4. Kész.

## 10b. Lokalizáció

- Nyelvek: **angol** (alap és tartalék) és **magyar**. Az app a macOS nyelvi beállítását követi (Rendszerbeállítások → Általános → Nyelv és régió, illetve az appra beállított nyelv). Ha a preferált nyelvek között nincs se magyar, se angol, az app angolul jelenik meg.
- A forrásnyelv az angol: a kódban angol kulcsok szerepelnek. Az app (`MacVPN`) magyar fordítása String Catalogban (`Sources/MacVPN/Resources/Localizable.xcstrings`) van; a `build-dmg.sh` `xcstringstool compile`-lal a `MacVPN.app/Contents/Resources/<nyelv>.lproj`-ba fordítja, és az app a main bundle-ből olvassa (nincs `Bundle.module`). A `MacVPNCore` szövegei (validátor-, hiba-, telepítő-üzenetek) beágyazott kétnyelvű táblában vannak (`L10n.swift`), mert ugyanez a kód rootként, resource bundle nélkül fut a `mvpn-validate`-ben.
- `Info.plist`: `CFBundleDevelopmentRegion = en`, `CFBundleLocalizations = [en, hu]`.
- A validátor- és hibaüzenetek is lokalizáltak. A root oldali `mvpn` és `mvpn-validate` a nyelvet a `--lang <en|hu>` kapcsolóból kapja (az app adja át), mert a `sudo` nem viszi át a felhasználó locale-ját. Ismeretlen érték esetén angol.
- A naplósorok előtagjai (`▶ [mvpn]`, `$`, `✗`, `═══`) nyelvfüggetlenek, a naplósor-osztályozás ezekre épül.

## 10c. Frissítés, dokumentáció, eltávolítás

**Frissítés**
- Forrás: a GitHub Releases API (`/repos/<owner>/<repo>/releases/latest`). Az app induláskor, majd 24 óránként ellenőriz. A menüben kikapcsolható („Frissítések automatikus keresése").
- Ha a tag (`vX.Y.Z`) nagyobb, mint a `CFBundleShortVersionString`, a menüben megjelenik a „Frissítés elérhető: vX.Y.Z" sor, a release notes egy ablakban látható, mellette a „Letöltés és telepítés" gomb.
- Telepítés:
  1. A DMG és a hozzá tartozó `.sha256` letöltése, az SHA-256 ellenőrzése.
  2. `hdiutil attach -nobrowse -readonly`.
  3. A csatolt `MacVPN.app` ellenőrzése: bundle ID `local.macvpn`, verzió = a tag.
  4. Egy segédscript (a `/tmp`-be írva, 0700) megvárja, hogy az app kilépjen, `ditto`-val lecseréli a `/Applications/MacVPN.app`-ot, eltávolítja a quarantine attribútumot, leválasztja a DMG-t, és újraindítja az appot.
  5. Aktív kapcsolatoknál előtte rákérdez (mint kilépésnél).
- Ha a root scriptek `VERSION`-je változott, a Rendszerállapot ablak „Frissítés szükséges" jelzést ad, és egy admin jelszóval frissít.
- **Korlát:** Developer ID és aláírt frissítési feed nélkül a letöltés hitelességét a HTTPS és az ugyanabból a release-ből jövő SHA-256 adja. Egy kompromittált GitHub-fiók rosszindulatú frissítést tehet közzé. Ezt a dokumentáció jelzi.

**Dokumentáció**
- `docs/user-guide.hu.md` és `docs/user-guide.en.md`. Fejezetek: telepítés, első indítás, VPN-típusonként a beállítás, import/export, debug mód, hibaelhárítás (tipikus hibák a naplóból), frissítés, eltávolítás, biztonsági megjegyzések.
- A README röviden mindkét nyelven, linkkel az útmutatókra.
- Az appban a Súgó menüpont a nyelvnek megfelelő útmutatót nyitja meg a GitHubon.

**Eltávolítás**
- A Rendszerállapot ablakban „MacVPN eltávolítása…" gomb. Egy admin jelszóval törli a `/usr/local/libexec/macvpn`, `/etc/sudoers.d/macvpn`, `/var/run/macvpn` és `/var/log/macvpn` útvonalakat, előtte bontja az aktív kapcsolatokat.
- Opcionálisan a felhasználói adatokat is törli (`~/Library/Application Support/MacVPN`, Keychain bejegyzések).
- A Homebrew csomagokat nem törli, és ezt jelzi.

## 11. Későbbi bővítési lehetőségek (nem része ennek a körnek)

- Developer ID esetén: `SMAppService` daemon + XPC a sudoers helyett. Csak a backendek mögötti végrehajtó réteg cserélődik.
- Automatikus újracsatlakozás, OTP-támogatás, „Csatlakozás indításkor" opció.
