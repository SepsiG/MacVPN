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
  Defaults!/usr/local/libexec/macvpn/mvpn env_reset, !env_keep
  Defaults!/usr/local/libexec/macvpn/mvpn env_delete += "LANG LANGUAGE LC_* CHARSET"
  ```
  A `mvpn` így tiszta környezettel indul (a macOS alap `env_keep` listája – LANG, LC_* stb. – sem jut át); a `mvpn` és az `ovpn-dns` ezen felül `export LC_ALL=C`-vel bájt-alapú, locale-független viselkedést kényszerít.
- Futási könyvtár: `/var/run/macvpn/<id>/` (`root 700`), napló: `/var/log/macvpn/<id>.log`

A telepítés egyetlen `osascript … with administrator privileges` hívással történik. A telepítő a scripteket az app bundle `Resources/root/` mappájából másolja, majd `visudo -c -f`-fel ellenőrzi a sudoers fájlt, mielőtt a helyére tenné. Mélységi védelem a telepítőben:
- A `/usr/local`, `/usr/local/libexec` és `/usr/local/libexec/macvpn` symlink vagy nem könyvtár → megszakítás; hiányzó → `install -d` root tulajdonnal. Ha a `/usr/local` vagy a `/usr/local/libexec` nem root tulajdonú vagy csoport/mások által írható → megszakítás EN/HU üzenettel (a nem-root által írható szülő miatt a root scriptek kicserélhetők; kézi javítás: `sudo chown root:wheel <dir> && sudo chmod go-w <dir>`, Intel Macen érintheti a Homebrew-t). Ezeket nem írjuk át, mert Intel Macen a Homebrew-é lehetnek. Csak a saját `/usr/local/libexec/macvpn` kap `chown root:wheel` + `chmod go-w`-t.
- Az app közvetlenül a script megírása előtt kiszámolja a `mvpn`, `ovpn-dns`, `mvpn-validate` és `VERSION` SHA-256-ját, és beágyazza a scriptbe. A script rootként egy root tulajdonú átmeneti könyvtárba (`/var/run/macvpn-install.XXXXXX`) másolja a fájlokat, `shasum -a 256`-tal ellenőrzi a másolatot, és csak onnan telepít; eltérésnél semmi nem települ. Így a felhasználó által írható forrás a script megírása és a root futás között nem cserélhető ki észrevétlenül.
- A root réteg verziója (`VERSION`, `MVPN_VERSION`) 4: a korábban telepített rétegnél a Rendszerállapot frissítést kér.

### `mvpn` interfész

```
mvpn up     <openvpn|wireguard|strongswan|sstp> <id>    # secrets a stdin-en (kulcs=érték)
mvpn down   <openvpn|wireguard|strongswan|sstp> <id>
mvpn status                                        # JSON az összes aktív kapcsolatról
mvpn version
```

### Biztonsági szabályok (kötelező)

1. Az `<id>` csak UUID formátumú lehet (regex), egyébként hiba.
2. A forrás config útvonalát a script **maga állítja elő**: `~$SUDO_USER/Library/Application Support/MacVPN/connections/<id>/config`. Paraméterként útvonalat nem fogad el.
3. A forrás nem lehet symlink. A script átmásolja a `/var/run/macvpn/<id>/` könyvtárba, és **a másolatot** validálja és használja.
4. A binárisokat fix útvonalakon keresi (`/opt/homebrew/bin`, `/opt/homebrew/sbin`, `/opt/homebrew/opt/strongswan/libexec`, `/usr/local/bin`, `/usr/local/sbin`). A `PATH`-ra nem hagyatkozik.
5. A jelszavak stdin-en érkeznek, és `600`-as fájlba kerülnek a futási könyvtárban. A `down` parancs, illetve hiba esetén ezek törlődnek. Kivétel az SSTP: ott a jelszó az `sstpc` parancssorába kerül (lásd „Ismert korlát” és 10d).
6. **Engedélyezőlista (allowlist).** Csak ismert, biztonságos OpenVPN-direktívák és WireGuard-kulcsok engedettek, minden más hiba. Vezérlőkarakter (a tabulátoron kívül) sehol nem lehet a configban. Az OpenVPN-direktíva neve csak `[a-z0-9-]` lehet, így idézőjeles vagy escape-elt direktívával nem lehet megkerülni a szabályt. Az inline blokkok neve szintén engedélyezőlistán van. A záró tag csak pontos egyezéssel fogadható el, a lezáratlan blokk hiba. strongSwan esetén a kommenteket idézőjel-tudatosan kezeljük, az `include` pedig bárhol tiltott. A pontos listák a `Validators.swift`-ben vannak, a `mvpn` ezeket tükrözi. **Argumentumok és értékek is engedélyezőlistán vannak:**
   - **OpenVPN:** minden engedett direktívához táblázat (`argumentSpecs`: argumentumszám-tartomány + pozíciónkénti regex/számtartomány/szöveg). Például `dev` csak `tun|tap|utunN|tunN|tapN` (különben az openvpn rootként megnyithatná a `/dev/<dev>` eszközt), `dev-type` csak `tun|tap`, `remote` host + port + proto, `proto` enum, portok és időzítők számok, `cipher`/`data-ciphers`/`auth` szigorú karakterkészlet, `route`/`route-ipv6`/`ifconfig` címek és maszkok, `redirect-gateway` flagek, `verify-x509-name` (idézett) név + típus enum, `pull-filter` accept/ignore/reject + szöveg, `dhcp-option` típus + érték, `static-challenge` szöveg + 0/1, `http-proxy`/`socks-proxy` host + port. Általános szabály: nincs vezető `-`, `/` csak maszkban/CIDR-ben. A tokenizálás az OpenVPN `parse_line` tükre (`"…"`/`'…'` token elején, token elején álló `#`/`;` komment); backslash és lezáratlan idézőjel hiba. A hibaüzenet csak a direktíva nevét idézi.
   - **OpenVPN `<connection>` blokk:** engedett (csak legfelső szinten). A belső sorok ugyanazon az ellenőrzésen mennek át, de csak az OpenVPN által megengedett connection-direktívák (`remote`, `proto`, `port`, `nobind`, `http-proxy`, `socks-proxy`, … metszve az engedélyezőlistával); benne adatblokk csak `<http-proxy-user-pass>` lehet, beágyazott `<connection>` nem. Egy érvényes `remote` a blokkban is kielégíti a „remote kötelező” szabályt.
   - **WireGuard:** `Address`/`AllowedIPs` CIDR-lista, `DNS` IP-k vagy domainek, `MTU` (576–9000), `ListenPort`, `PersistentKeepalive` (szám vagy `off`), `Table` (`off`/`auto`/szám), `FwMark` (szám/hex/`off`), `Endpoint` `host:port` vagy `[v6]:port`, kulcsok 44 karakteres base64; egyik érték sem kezdődhet `-`-szal.
   - **strongSwan (default-deny):** a config a strongSwan settings-szintaxis szerint szakaszokra és kulcsokra bomlik, és szakasztípusonként (connections, conn, local/remote, cert/cacert alszakasz, children/child, secrets típusai, pools, authorities) csak a telepített `swanctl.conf(5)` kulcsai engedettek. A `certs`, `cacerts`, `cacert`, `pubkeys` értéke csak sima fájlnév-lista (nincs `/`, `..`, vezető `.`), így a swanctl csak a saját x509/pubkey könyvtáraiból olvas. Az `include`/`updown`/`file` csak kulcs- vagy szakasznévként számít (értékként nem: a régi szó-alapú keresés téves riasztásai megszűntek). Az önálló `=` vagy idézőjelen kívüli `{` egy értékben hiba (kulcs-csempészés gyanúja); a többsoros idézőjel és a backslash tiltása marad.

   Explicit tiltott direktívák, ezekre külön hibaüzenet jön:
   - **OpenVPN:** `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `auth-user-pass-verify`, `client-connect`, `client-disconnect`, `learn-address`, `plugin`, `script-security`, `config`, `cd`, `chroot`, `daemon`, `log`, `log-append`, `writepid`, `management`, `status`, `setenv`, `iproute`, `ifconfig-noexec`, `route-noexec`, `user`, `group`, `pkcs11-providers`, `providers`, `engine`, `dns-updown`, `tls-export-cert`, `tmp-dir`, `tls-crypt-v2-verify` (az utóbbi kettő miatt a down script nem tudná visszaállítani a DNS-t). Külső fájlhivatkozás (`ca`, `cert`, `key`, `tls-auth`, `tls-crypt`, `pkcs12`, `secret`, `auth-user-pass <fájl>`) sem engedett: minden tanúsítvány inline blokkban (`<ca>…</ca>`) legyen.
   - **WireGuard:** `PreUp`, `PostUp`, `PreDown`, `PostDown`, `SaveConfig`.
   - **strongSwan:** `updown`, `include`, `file` (bármely szakaszban, például `secrets` vagy `cert`/`cacert` alszakasz), `crl_uris`, `ocsp_uris`, valamint bármely `file:` URI.
7. Az OpenVPN-t a script mindig ezekkel a kötelező opciókkal indítja: `--script-security 2 --up /usr/local/libexec/macvpn/ovpn-dns --down /usr/local/libexec/macvpn/ovpn-dns --writepid /var/run/macvpn/<id>/pid --log-append /var/run/macvpn/<id>/openvpn.log --daemon`, valamint ha van jelszó, `--auth-user-pass /var/run/macvpn/<id>/auth`. Ez a fájl (root, `600`, a `700`-as futási könyvtárban) a bontásig megmarad, hogy újracsatlakozáskor (ping-restart, hálózatváltás) az OpenVPN újraolvashassa; a `down` és minden sikertelen `up` törli. Sikertelen vagy megszakított `up` után a `mvpn` lebontja a félig felépült kapcsolatot, visszaállítja a DNS-t és törli a futási könyvtárat. Az OpenVPN naplója a root-only `openvpn.log` (600): a felépülésről (`Initialization Sequence Completed`), az `AUTH_FAILED`-ről, a kilépés okáról és a `status` „connected” állapotáról (interfész + inicializálás kész) csak ez dönt, a felhasználó által írható kapcsolatnapló soha. A tartalmát a `mvpn` maszkolva átmásolja a kapcsolat naplójába (közös `flush_root_log`, mint az SSTP `pppd.log`-nál): a várakozás alatt másodpercenként, a végén, bontáskor, és felépült kapcsolatnál minden `status` hívásnál (ha éppen nem fut up/down ugyanarra az id-re). A várakozás `UP_TIMEOUT` (30 mp).
8. A WireGuard interfész neve `mv` + az id első 8 hex karaktere (például `mv1a2b3c4d.conf`). A wg-quick ezt az utun-hoz rendeli.
9. A strongSwan esetén a script elindítja a `charon`-t, ha még nem fut (csak root tulajdonú, a várt brew útvonalról futó `charon` számít: `pgrep -U 0 -x charon` + a `ps` comm útvonalának egyezése; bontáskor is csak ezeket állítja le), aztán `swanctl --load-all --file <másolat>`, majd `swanctl --initiate --child <első child>`. A PSK és az EAP jelszó a stdin-ről a másolatba kerül.
10. `--dry-run` kapcsoló: validál és kiírja, mit futtatna, de nem indít semmit. Ezt a teszteléshez használjuk.
11. `--debug` kapcsoló (`mvpn up --debug …`): bőbeszédű csatlakozás, részletesen a 6. fejezet „Debug mód" pontjában.
12. A napló (`/var/log/macvpn/<id>.log`) tulajdonosa `$SUDO_USER`, jogosultsága `600`. Jelszó, PSK és privát kulcs soha nem kerül bele: a `mvpn` a saját kiírásaiban maszkol (`***`), az eszközök kimenetét pedig a jelszómezők értékeire szűri, mielőtt a naplóba írná. Minden nem üres titok maszkolódik; a 3 karakternél rövidebbek csak önálló tokenként (előttük és utánuk nem betű/számjegy áll), hogy egy 1–2 karakteres jelszó ne bontsa szét a napló minden szavát.

### Ismert korlát

A Homebrew könyvtára (`/opt/homebrew`) a felhasználó által írható. Aki a felhasználó nevében kódot futtat, kicserélheti például az `openvpn` binárist, és a `mvpn` ezt rootként futtatja. A sudoers-alapú megoldás ezért **nem véd a felhasználói fiókon belül futó kártevő ellen**: a gyakorlatban jelszó nélküli root-elérést ad a VPN-eszközökön keresztül. Kimondva: **bármely folyamat, amely a felhasználó nevében fut, a brew binárisok cseréjével és a NOPASSWD szabállyal ténylegesen rootjogot szerezhet.** A validátorok, a root-only naplók és a telepítő integritás-ellenőrzése a config- és fájlalapú támadások ellen védenek, ez ellen nem. A direktíva-tiltás a véletlen vagy importált veszélyes configok ellen véd. A teljes védelemhez root tulajdonú binárisok és privileged helper kellenének (lásd 11. fejezet). Egyfelhasználós, adminisztrátor által használt gépre ezt elfogadott kockázatnak tekintjük.

**SSTP jelszó a parancssorban.** A Homebrew `sstpc` (1.0.20) pppd plugin (`sstp-pppd-plugin.so`) nélkül épül, ezért az SSTP crypto bindinghoz szükséges MPPE kulcsokat maga számolja a jelszóból, és `--user` + `--password` nélkül el sem indul („The username and password must be specified”), `--nolaunchpppd` (pppd `pty`) módban sem. A jelszó tehát az `sstpc` parancssorába kerül. Az `sstpc` a beolvasás után azonnal kicsillagozza a saját argv-jét, így csak az indulás első pillanatában láthatja más helyi felhasználó a `ps`-ben (macOS-en a root folyamatok argumentumai mindenki számára láthatók). A pppd a jelszót az `sstpc` saját, ideiglenes 600-as opciófájljából kapja, nem parancssorból. A `mvpn` naplójába és a dry-run kimenetbe csak `***` kerül, az `sstpc` kimenete a maszkon át megy a naplóba, és a jelszó nincs exportálva semmilyen folyamat környezetébe. Egyfelhasználós gépen ezt elfogadott kockázatnak tekintjük; a felhasználói útmutatók biztonsági fejezete is leírja.

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
- Forrás: a GitHub Releases API a repó megváltoztathatatlan numerikus ID-jével (`/repositories/<id>/releases/latest`, az ID az `Info.plist` `MacVPNUpdateRepoID` kulcsában: `1422472799` = SepsiG/MacVPN). A név (`MacVPNUpdateRepo`) csak a Súgó linkjeihez és az asset útvonalak ellenőrzéséhez kell. Ha az ID hiányzik vagy érvénytelen, nincs frissítés-ellenőrzés (nincs visszaesés a névre); a `release.yml` nem írja át, csak ellenőrzi, hogy egyezik a `github.repository_id`-vel. Az app induláskor, majd 24 óránként ellenőriz. A menüben kikapcsolható („Frissítések automatikus keresése").
- Asset ellenőrzés: a `browser_download_url` hostja `github.com`, útvonala pontosan `/<owner>/<repo>/releases/download/<tag_name>/<asset név>` (owner/repo a `MacVPNUpdateRepo`-ból, kis-nagybetű függetlenül); query, fragment, `%`-kódolás, üres vagy `..` elem nem lehet benne. A `html_url` csak `https://github.com/<owner>/<repo>/releases/…` lehet, különben nincs link. Átirányítás csak HTTPS-re és a `github.com`, `api.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` hostokra.
- Opcionális késleltetés („Csak a legalább 24 órája megjelent frissítések felajánlása", alapból ki): a `published_at` alapján csak a legalább 24 órás kiadást ajánlja fel; ismeretlen közzétételi idő mellett bekapcsolt késleltetéssel nem ajánl fel.
- Offline aláírás (0.2.2-től): minden kiadásnak `MacVPN-X.Y.Z.dmg.sig` assetje is van (ugyanazzal az útvonal-ellenőrzéssel). A `.sig` egyetlen sor: a 64 bájtos Ed25519 aláírás base64-ben + újsor, legfeljebb 1 KB. Az aláírt üzenet bájtra pontosan `"macvpn-update-v1\n" + X.Y.Z + "\n" + sha256hex (kisbetűs) + "\n"`; tiszta Ed25519 (OpenSSL 3 `pkeyutl -sign -rawin`, ellenőrzés: CryptoKit `Curve25519.Signing.PublicKey.isValidSignature`). Két nyilvános kulcs van beágyazva (`UpdateSignature`, nyers 32 bájt base64): az elsődleges (a karbantartó login Keychainjében) és a tartalék (offline, jelszókezelőben); bármelyikkel érvényes aláírás elfogadott. `.sig` nélküli újabb kiadást az app nem ajánl fel (a kézi ellenőrzés „A frissítés aláírásra vár" üzenetet ad). A privát kulcs soha nincs a GitHubon vagy a CI-ban, így egy feltört GitHub-fiók sem tud a 0.2.2-es és újabb appoknak frissítést kiadni. A 0.2.1-es és régebbi appok nem ellenőrzik az aláírást.
- Ha a tag (`vX.Y.Z`) nagyobb, mint a `CFBundleShortVersionString`, és van `.sig` asset, a menüben megjelenik a „Frissítés elérhető: vX.Y.Z" sor, a release notes egy ablakban látható, mellette a „Letöltés és telepítés" gomb.
- Telepítés:
  1. A DMG, a `.sha256` és a `.sig` letöltése, az SHA-256 ellenőrzése, majd az Ed25519 aláírás ellenőrzése a **helyben számolt** hash-re (`UpdateSignature.verify(version:sha256Hex:signatureBase64:publicKeys:)`, tiszta függvény). Hiányzó vagy érvénytelen aláírásnál nincs telepítés: „A frissítést nem a MacVPN fejlesztője írta alá".
  2. `hdiutil attach -nobrowse -readonly`.
  3. A csatolt `MacVPN.app` ellenőrzése: bundle ID `local.macvpn`, verzió = a tag.
  4. Egy segédscript (a `/tmp`-be írva, 0700) megvárja, hogy az app kilépjen, `ditto`-val lecseréli a `/Applications/MacVPN.app`-ot, eltávolítja a quarantine attribútumot, leválasztja a DMG-t, és újraindítja az appot. A két átnevezés alatt a TERM/INT jelzést figyelmen kívül hagyja (kijelentkezéskor sem maradhat app nélkül a cél). Az app induláskor törli a bundle melletti `.<App>.update-*` / `.<App>.old-*` maradványokat, és ha a napló szerint az előző frissítés megszakadt (30 mp alatt nem lépett ki) vagy hibás volt, egyszer jelzi.
  5. Aktív kapcsolatoknál előtte rákérdez (mint kilépésnél).
- Ha a root scriptek `VERSION`-je változott, a Rendszerállapot ablak „Frissítés szükséges" jelzést ad, és egy admin jelszóval frissít.
- **Maradék kockázat:** a frissítés hitelességét a karbantartó offline Ed25519 kulcsa adja, nem a GitHub. Ha maga az aláíró kulcs kompromittálódik, azzal frissítés adható ki; ilyenkor a tartalék kulccsal aláírt új verzió veszi ki a kompromittált kulcsot (`docs/RELEASING.md`). A 0.2.1-es és régebbi appok csak a HTTPS-re és az ugyanabból a release-ből jövő SHA-256-ra támaszkodnak. Az ad-hoc aláírás miatt a macOS frissítés után egyszer rákérdezhet a Keychain-hozzáférésre (a release notes és az útmutatók leírják).
- **Ellátási lánc (CI):** `ci.yml` és `release.yml` minimális `permissions`-szel; minden action teljes commit SHA-ra rögzítve (`# vX.Y.Z` megjegyzéssel), Dependabot hetente frissíti őket. A `release.yml` két job: `build` (`contents: read`, `persist-credentials: false`, szigorú `vX.Y.Z` tag, a tagelt commit a `main` őse, tesztek, DMG, `.sha256`, artifact feltöltés) és `release` (`needs: build`, `contents: write`, checkout és repó kód nélkül: artifact letöltés, `gh release create --repo --draft`). A CI csak **piszkozat** (draft) kiadást készít a DMG-vel és a `.sha256`-tal; a `.sig`-et nem, mert a CI soha nem fér hozzá az aláíró kulcshoz. A karbantartó a saját Macjén futtatja a `scripts/sign-release.sh vX.Y.Z`-t: letölti a draftot, helyben ellenőrzi a hash-t, megerősítés után aláír (a Keychainből process substitutionnel, lemezre írás nélkül), a beágyazott kulccsal ellenőriz, feltölti a `.sig`-et és közzéteszi a kiadást (`draft=false`, `make_latest=true`). Teszt: `scripts/test-sign-release.sh` (`--dry-run`, eldobható kulcs, hálózat nélkül). A repó beállításai (hardverkulcsos 2FA, immutable releases, tag ruleset) és a kiadás menete: `docs/RELEASING.md`.

**Dokumentáció**
- `docs/user-guide.hu.md` és `docs/user-guide.en.md`. Fejezetek: telepítés, első indítás, VPN-típusonként a beállítás, import/export, debug mód, hibaelhárítás (tipikus hibák a naplóból), frissítés, eltávolítás, biztonsági megjegyzések.
- A README röviden mindkét nyelven, linkkel az útmutatókra.
- Az appban a Súgó menüpont a nyelvnek megfelelő útmutatót nyitja meg a GitHubon.

**Eltávolítás**
- A Rendszerállapot ablakban „MacVPN eltávolítása…" gomb. Egy admin jelszóval törli a `/usr/local/libexec/macvpn`, `/etc/sudoers.d/macvpn`, `/var/run/macvpn` és `/var/log/macvpn` útvonalakat, előtte bontja az aktív kapcsolatokat. A `/etc/ppp/options`-t csak akkor törli, ha a `mvpn` hozta létre (jelölő: `/usr/local/libexec/macvpn/.created-ppp-options`), és a fájl még mindig üres.
- Opcionálisan a felhasználói adatokat is törli (`~/Library/Application Support/MacVPN`, Keychain bejegyzések).
- A Homebrew csomagokat nem törli, és ezt jelzi.

## 10d. SSTP (v0.2.0)

- Új típus: `VPNKind.sstp` („SSTP”). Root rétegen fut a Homebrew `sstp-client` (`sstpc`) és a macOS beépített `/usr/sbin/pppd` segítségével.
- **Űrlapos szerkesztő** (mint az L2TP-nél): szerver (`host` vagy `host:port`, alapból 443), felhasználónév, jelszó (Keychain), tanúsítvány-mód (`system` = rendszer CA-k; `ca` = saját CA PEM, a configban inline tárolva; `insecure` = `--cert-warn`, piros figyelmeztetéssel), „minden forgalom a VPN-en át” (`defaultroute`, alapból be), „a szerver DNS-ének használata” (`usepeerdns`, alapból be).
- **Config formátum** (`config` fájl, export/import `.sstp`): `kulcs=érték` sorok: `server`, `port`, `user`, `cert` (`system|ca|insecure`), `route_all` (`yes|no`), `peer_dns` (`yes|no`), valamint opcionális `<ca>…</ca>` PEM blokk. Ismeretlen kulcs, vezérlőkarakter, szóköz/idézőjel/`\` a hoszt- vagy felhasználónévben hiba. A `server` csak hosztnév vagy IPv4/IPv6 cím, a `port` 1–65535. Jelszó soha nincs a configban, az export azt sem tartalmazza.
- **mvpn**: `mvpn up|down sstp <id>`. A config a `mvpn-validate sstp`-n megy át, a paramétereket a `mvpn-validate --sstp-params`, a CA-t a `--sstp-ca` adja (validálva). Indítás: `sstpc --log-stderr --log-level <2|4 debugnál> --tls-ext --save-server-route [--ca-cert <run>/ca.pem | --cert-warn] --user <u> --password <jelszó> <host>:<port> -- logfile <run>/pppd.log require-mschap-v2 refuse-pap refuse-chap refuse-mschap refuse-eap noauth nodetach [usepeerdns] [defaultroute] [debug]` (IPv6 cél: `[cím]:port`). A jelszó azért a parancssorban van, mert a brew `sstpc` csak így indul (lásd 3. „Ismert korlát”); a naplóban és a dry-run kimenetben `***`. A `refuse-pap` debug módban is bent van, az `sstpc` kimenete (a PAP csomag-dump is) a maszkon át megy a naplóba; a háttérben maradó maszk a titkot egy root 600-as fájlból olvassa, amit az up végén töröl. Hiányzó `/etc/ppp/options` esetén a `mvpn` létrehozza (root, 644; brew caveat), és jelölőt hagy (`/usr/local/libexec/macvpn/.created-ppp-options`) az eltávolítónak. A jelszóban `"`, `\` és vezérlőkarakter tiltott (app és `mvpn` is), mert az `sstpc` escape nélkül írja a pppd opciófájljába. A `pppd` naplója (`logfile`) a root-only `<run>/pppd.log` (600); az interfész (`Using interface pppN`), a cím és a szerver DNS-e csak ebből jön, horgonyzott mintákkal (időbélyeg-előtag tűrve), az interfész létezését `ifconfig` ellenőrzi; a tartalma maszkolva, `[pppd]` előtaggal a kapcsolat naplójába is átkerül. Bontáskor (és részleges hibánál) a /1 útvonalak törlődnek; a sstpc-hez nem köthető pppd-t (ppid-ellenőrzés) soha nem állítjuk le; a maszk-fájlt az awk beolvasás után törli; a régi `sstp-pppd.XXXXXX` fájlok takarítva. Interfész nélküli „connecting” UP_TIMEOUT+30 mp után failed. A szerver nem lehet `0.0.0.0`, `::`, `127.0.0.0/8`, `::1` (localhost); a felhasználónév nem lehet csak pont, és nem végződhet ponttal. Az IPv6 `[cím]:port` cél valódi szerverrel még nem ellenőrzött. Állapot: `sstpc` pid él + `pppN` interfész van → connected; él, de még nincs interfész → connecting. A macOS `pppd` önállóan sem a `usepeerdns`-t, sem (meglévő alapútvonal mellett) a `defaultroute`-ot nem érvényesíti, ezért: `peer_dns=yes` → a DNS a közös `ovpn-dns` hookon (networksetup mentés/visszaállítás) megy át; `route_all=yes` → `0.0.0.0/1` és `128.0.0.0/1` a ppp interfészre (a szerver útvonalát a `--save-server-route` tartja). Timeout 30 mp; hitelesítési hiba (`authentication failed`, `E=691`) és tanúsítványhiba (`certificate verification failed`) gyors hibával, takarítással (pppd, majd sstpc leállítása, DNS visszaállítás, futási könyvtár törlése). Debug: `--log-level 4` + pppd `debug`.
- **SetupChecker**: az `sstpc` (brew `sstp-client`) bekerül a szükséges eszközök közé, csak az SSTP típushoz; a „Telepítés” gomb ezt is telepíti.
- Lokalizáció (EN/HU), dokumentáció (mindkét útmutató), tesztek (validátor, mvpn dry-run, opciófájl jogosultság, jelszó nincs argv-ben/naplóban), kiadás v0.2.0.

## 11. Későbbi bővítési lehetőségek (nem része ennek a körnek)

- Developer ID esetén: `SMAppService` daemon + XPC a sudoers helyett. Csak a backendek mögötti végrehajtó réteg cserélődik.
- Automatikus újracsatlakozás, OTP-támogatás, „Csatlakozás indításkor" opció.
