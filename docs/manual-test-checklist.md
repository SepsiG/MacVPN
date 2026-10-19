# MacVPN – kézi tesztlista (1.0.0, Rust/Tauri)

Előfeltétel: `scripts/build-dmg.sh` lefutott (`dist/MacVPN-1.0.0.dmg`), zöld: `cargo test --workspace`,
`scripts/test-root.sh` (Rust `mvpn`), `cd app/ui && npm test && npm run build`, `scripts/test-sign-release.sh`, a
smoke teszt mindkét nyelven (`SMOKE_LANG=en scripts/smoke-manage.sh`, `SMOKE_LANG=hu scripts/smoke-manage.sh`), és
a régi updater elfogadási próbája (lásd lent, „Frissítés v0.4.0 → v1.0.0”).

## 1.0.0: csomag és aláírás
- [ ] `plutil -p dist/MacVPN.app/Contents/Info.plist`: `CFBundleIdentifier` `local.macvpn`, `CFBundleName` / `CFBundleDisplayName` `MacVPN`, `CFBundleExecutable` `MacVPN`, `CFBundleShortVersionString` = `CFBundleVersion` = `1.0.0`, `LSMinimumSystemVersion` `14.0`, `LSUIElement` true, `CFBundleDevelopmentRegion` `en`, `CFBundleLocalizations` `[en, hu]`, `MacVPNUpdateRepo` `SepsiG/MacVPN`, `MacVPNUpdateRepoID` `1422472799`, `CFBundleIconFile` `AppIcon`
- [ ] `lipo -archs` a `Contents/MacOS/MacVPN`-re és a `Contents/Resources/root/mvpn`-re: `x86_64 arm64`; a `Contents/Resources/root` alatt csak `mvpn` és `VERSION` (7)
- [ ] `codesign --verify --strict --verbose=2 dist/MacVPN.app` sikeres; `codesign -dv …/root/mvpn` → `flags=…(adhoc,runtime)`
- [ ] Intel Macen (vagy `arch -x86_64`) is elindul az app; a Finder az ikont mutatja; a Dockban nem jelenik meg (LSUIElement)
- [ ] Rendszerbeállítások → Általános → Nyelv és régió → Alkalmazások: a MacVPN-hez magyar / angol választható, és az app újraindítás után azt használja

## Telepítés tiszta állapotból
- [ ] `sudo rm -rf /usr/local/libexec/macvpn /etc/sudoers.d/macvpn` (előző telepítés törlése)
- [ ] DMG megnyitása, MacVPN.app húzása az Applications mappába
- [ ] Első indítás: a Gatekeeper letiltja → Rendszerbeállítások → Adatvédelem és biztonság → „Megnyitás mindenképp"
- [ ] Megnyílik a Rendszerállapot ablak; a hiányzó eszközök listája helyes
- [ ] „Telepítés" → brew kimenet élőben, a végén zöld
- [ ] Homebrew hiányában „Telepítés…" → Terminál nyílik egy `$TMPDIR/macvpn-brew.XXXXXXXX/install-homebrew.command` scripttel (0700); hálózat nélkül a script hibaüzenettel kilép, a mappa a futás végén törlődik
- [ ] „Engedélyezés" → egy admin jelszókérés → zöld
- [ ] `sudo -n /usr/local/libexec/macvpn/mvpn status` jelszó nélkül `[]`
- [ ] A telepítő egyetlen binárist és a `VERSION`-t másolja (`ls /usr/local/libexec/macvpn` → `VERSION mvpn`; `root:wheel 755`; `cat /usr/local/libexec/macvpn/VERSION` = 7); a `sudo -n -u` alapú másolás rootként működik
- [ ] 0.4.0-s (root 6) rétegről indulva a Rendszerállapot frissítést kér; „Engedélyezés” után a régi `ovpn-dns`, `mvpn-validate`, `mvpn-mgmt` törlődik, `sudo -n /usr/local/libexec/macvpn/mvpn version` = 7
- [ ] A telepített `mvpn` hardened runtime-mal aláírt: `codesign -dv /usr/local/libexec/macvpn/mvpn` → `flags=…runtime`; `sudo DYLD_INSERT_LIBRARIES=/tmp/x.dylib -n /usr/local/libexec/macvpn/mvpn status` nem tölt be idegen könyvtárat (a sudo amúgy is törli a `DYLD_*` változókat)
- [ ] Régi/elakadt lock fájl (stale lock) nem blokkolja a telepítést vagy a műveleteket

## Kapcsolatok típusonként
- [ ] Export: mindegyik típus exportja → a fájlban nincs jelszó/PSK; a gomb súgója „Exportálás… (jelszavak sosem kerülnek bele)”
- [ ] OpenVPN `<key>`/`<tls-auth>` blokkos config exportja → „A config privát kulcsokat vagy hitelesítő adatokat tartalmaz” kérdés; „Exportálás kulcsok nélkül” → a fájlban nincs kulcsblokk, a `<ca>` megvan; „Exportálás kulcsokkal” → változatlan config; „Mégse” → nincs mentési ablak
- [ ] WireGuard export ugyanez (`PrivateKey =` üresen marad); strongSwan `secrets { }` szakasszal → a szakasz kimarad
- [ ] OpenVPN / WireGuard / strongSwan export (kulcsokkal) visszaimportálva ugyanaz a config
- [ ] `.ovpn` import `ca ../x.crt`, `key /etc/hosts`, kifelé mutató symlink, rossz formátumú (`ca` → szövegfájl) vagy 1 MB-nál nagyobb hivatkozott fájllal → érthető hibaüzenet, nem importálódik; helyes `ca ca.crt` + `tls-auth ta.key 1` → „Importálva, beemelt fájlok: ca.crt, ta.key”
- [ ] Hibás config (pl. `up /x` sor) importja → importálódik, a szerkesztő rögtön a piros hibalistával nyílik meg
- [ ] Kockázatos direktívás `.ovpn` (`user nobody`, `group nogroup`, `setenv CONFIG_VERSION "2.0.4"`, `remap-usr1 SIGTERM`) importja → „Importálva. Kockázatos beállításokat tartalmaz (group, user)…”; a szerkesztőben sárga „Kockázatos beállítások” panel, soronként indoklással, a négyzet üres; Mentés négyzet nélkül → hiba („Mentés előtt vedd tudomásul…”); bejelölve → mentődik, a `meta.json`-ban `"acknowledgedRiskyDirectives" : ["group", "user"]`
- [ ] Tudomásulvétel után új kockázatos sor (pl. `route-noexec`) → a négyzet magától üres lesz; mentés nélkül csatlakozás → „A kockázatos beállítások nincsenek tudomásul véve: …”
- [ ] Tudomásul vett `user nobody` + `persist-tun` csatlakozás → felépül; bontás után a DNS visszaáll (`scutil --dns`); a naplóban „tudomásul vett kockázatos direktívák: group,user”
- [ ] `chroot`, `echo`, `pkcs11-id`, `setenv LD_PRELOAD x` → piros „Tiltott” hiba, a négyzet nem segít
- [ ] Régi (0.2.x) `meta.json` → a kapcsolat betöltődik, kockázatos direktíva nélkül változatlanul csatlakozik
- [ ] `pkcs12 client.p12` import (jelszó nélkül és jelszóval) → `<pkcs12>` base64 blokk; jelszavasnál a „Privát kulcs jelszava” mező kitöltése után csatlakozás sikerül; rossz jelszóval érthető hiba a naplóban; a naplóban és a `ps`-ben nincs jelszó; bontás után nincs `/var/run/macvpn/<id>/askpass`
- [ ] Titkosított PEM kulcs (`-----BEGIN ENCRYPTED PRIVATE KEY-----` és `Proc-Type: 4,ENCRYPTED`) → a „Privát kulcs jelszava” mezővel csatlakozik
- [ ] Export `<pkcs12>`-vel → „Exportálás kulcsok nélkül” levágja a blokkot
- [ ] MikroTik RouterOS v7: `/interface ovpn-server server export-client-config` kimenetének importja → nincs piros hiba, nincs sárga panel; „A privát kulcs titkosított…” üzenet; a Privát kulcs jelszava (export-jelszó) + felhasználó/jelszó megadása után csatlakozás sikerül (UDP és TCP szerverrel is)
- [ ] MikroTik v6 wiki config külön fájlokkal (`ca.crt`, `client.crt`, titkosított `client.key`, `auth-user-pass auth.cfg`) → „beemelt fájlok: ca.crt, client.crt, client.key”, „A(z) auth.cfg fájlban lévő felhasználónév és jelszó a Keychainbe került…”; a szerkesztőben a mezők kitöltve, a configban `auth-user-pass` fájlnév nélkül
- [ ] `auth-user-pass auth.cfg` import → „Használod a(z) auth.cfg … hitelesítő adatokat…?” kérdés; „Mellőzés” → a mezők üresek, az üzenet szerint nincs felhasználva; „Használat” → a mezők kitöltve
- [ ] `askpass pass.txt` import („Használat”) → a Privát kulcs jelszava mező kitöltve, a configban csak `askpass`
- [ ] Config `echo msg Initialization Sequence Completed` / `parameter …` sorral → piros „Tiltott direktíva”; szerver által küldött `echo` nem teszi „csatlakozott”-tá a kapcsolatot
- [ ] Root réteg: az OpenVPN `--up/--down` a `mvpn hook ovpn-dns`-t hívja, a hook csak az engedélyezett környezeti változókat olvassa (a `scripts/test-root.sh` ellenőrzi)
- [ ] `auth-user-pass` fájl 3 sorral / mappán kívül / hiányzik → importálódik, az üzenet kéri a hitelesítő adatok kézi megadását
- [ ] `script-security 1` sor → nincs hiba; `script-security 2` → piros „Tiltott direktíva”
- [ ] Root réteg frissítés 6 → 7: a Rendszerállapot frissítést kér; frissítés után `sudo -n /usr/local/libexec/macvpn/mvpn version` = 7
- [ ] Felhasználónév / jelszó / PSK sortöréssel (beillesztve) → mentéskor hibaüzenet, nem mentődik (minden típusnál, a rendszer VPN PSK mezőjénél is)
- [ ] Natív (L2TP / Cisco) `.mobileconfig` export: Finderben dupla kattintás → macOS Profilok telepíti; MacVPN-be importálva érthető hibaüzenet („nem importálható… Finder…”), nem „Nem ismerhető fel a config típusa”
- [ ] OpenVPN: `.ovpn` import (külső ca fájllal is) → felhasználó/jelszó → csatlakozás → zöld, IP és uptime látszik → bontás
- [ ] OpenVPN DNS: csatlakozás után `scutil --dns` a szerver DNS-ét mutatja; bontás után visszaáll
- [ ] WireGuard: config import → csatlakozás → `wg show` az interfészt mutatja → bontás
- [ ] IKEv2: swanctl config + jelszó/PSK → csatlakozás → ESTABLISHED → bontás
- [ ] L2TP: új kapcsolat, űrlap kitöltése → profil jóváhagyása → csatlakozás → bontás
- [ ] Natív mentés után a profil a `$TMPDIR/macvpn-profile.XXXXXXXX/` alatt van (mappa 0700, fájl 0600), benne `SharedSecret`, de nincs `AuthPassword` / `XAuthPassword`; a `connections/<UUID>/` alatt nincs `profile.mobileconfig`; a jóváhagyás után (a szolgáltatás megjelenésekor) az ideiglenes mappa törlődik, a `meta.json`-ban megjelenik a `nativeServiceID`
- [ ] Régi verzióból maradt `connections/<UUID>/profile.mobileconfig` és `$TMPDIR/macvpn-profile.*` mappa → az app indulásakor törlődik
- [ ] Natív kapcsolat a Rendszerbeállításokból indítva → a macOS kéri a jelszót; MacVPN-ből indítva nem
- [ ] Két azonos nevű L2TP szolgáltatás (az egyik nem a MacVPN-é, más szerverrel) → a MacVPN a sajátját köti (azonos szervercím), a másik rendszer VPN-ként („· Rendszer-VPN”) látszik; kötés nélkül (azonos szervercím sincs) a csatlakozás hibát ad („Több … nevű VPN szolgáltatás van…”), jelszót nem ad át
- [ ] Cisco IPsec: ugyanez csoportnévvel
- [ ] Meglévő `Office L2TP` rendszer VPN indítása és bontása a menüből
- [ ] L2TP (MacVPN-ben létrehozott) csatlakozás: a PSK-t a MacVPN in-process adja át (`SCNetworkConnectionStart`), a naplóban nincs `L2TP: incorrect user shared secret found`; a `ps`/argv-ben nincs PSK vagy jelszó
- [ ] `Office L2TP` rendszer VPN mentett PSK nélkül, ha a macOS nem találja a kulcsot → kb. 5–45 mp-en belül piros hiba a PSK-tippel („…add meg a közös kulcsát (PSK) itt: MacVPN → Kapcsolatok → Office L2TP."), értesítéssel; nem csendes „bontva"
- [ ] `Office L2TP` → Kapcsolatok ablak: „Közös kulcs (PSK)" és „Jelszó (nem kötelező…)" mező, Mentés → csatlakozás sikerül; „Mentett titkok törlése" után a mezők üresek, a Keychainben nincs `local.macvpn.secrets` bejegyzés a szolgáltatás UUID-jával
- [ ] Rendszer VPN PSK mezőjének mentetlen módosítása, majd másik kapcsolat kijelölése / Cmd+W → Mentés / Elvetés / Mégse kérdés
- [ ] WireGuard / IKEv2 rendszer VPN-nél nincs PSK mező
- [ ] Natív (L2TP / Cisco) kapcsolat fut, kilépés „fussanak tovább" → a VPN a MacVPN kilépése után is fennmarad (linger)
- [ ] Cisco IPsec csatlakozás mentett PSK-val és jelszóval (XAuth) sikerül

## SSTP (valódi SSTP szerver kell)
- [ ] Rendszerállapot: `sstp-client` nélkül „Hiányzó: sstpc”, az SSTP kapcsolat szürke („Hiányzó eszköz”), a többi típus használható; „Telepítés” után zöld
- [ ] Root réteg frissítése: a 6-os VERSION-ről „Frissítés szükséges”, „Engedélyezés” után zöld (`mvpn version` = 7)
- [ ] Új → SSTP: űrlap (Név, Szerver, Port, Felhasználónév, Jelszó, Szervertanúsítvány, két kapcsoló); mentetlen változásnál Mentés / Elvetés / Mégse kérdés, ⌘S ment
- [ ] Hibás szerver (`vpn example.com`), port (`0`), felhasználónév (`DOMAIN\user`) → mentéskor piros hiba, nem ment
- [ ] Rendszer CA, ismert CA-val aláírt szerver → csatlakozás → zöld, IP (`ppp0`) és uptime látszik → bontás
- [ ] Saját CA fájl: „PEM fájl kiválasztása…” → „Betöltött tanúsítványok: 1”; DER `.cer` → érthető hiba; csatlakozás céges CA-s szerverre sikerül
- [ ] Nincs ellenőrzés: piros figyelmeztetés; a naplóban `FIGYELEM: … --cert-warn`; csatlakozás önaláírt tanúsítvánnyal sikerül
- [ ] Rossz CA / rossz hosztnév → „Szervertanúsítvány-hiba…”, nincs futási könyvtár (`/var/run/macvpn/<id>`), nem fut `sstpc`/`pppd`
- [ ] Rossz jelszó → „Hitelesítési hiba (rossz felhasználónév vagy jelszó)”, értesítés, takarítás
- [ ] Minden forgalom be: `netstat -rn` → `0/1` és `128.0/1` a `pppN`-en, a szerver hoszt-útvonala a régi átjárón; ki: nincsenek /1 útvonalak
- [ ] Szerver DNS be: `scutil --dns` a szerver DNS-ét mutatja; bontás után visszaáll. Ki: a DNS változatlan
- [ ] `ps -axo args | grep sstpc` csatlakozás után: a jelszó helyén `xxxx…` (az `sstpc` kicsillagozta); a naplóban (normál és debug) sehol nincs a jelszó
- [ ] Debug mód: `--log-level 4` és pppd `debug` sorok (LCP, MS-CHAPv2, IPCP), `refuse-pap` a parancssorban
- [ ] `/etc/ppp/options` hiányában (`sudo mv /etc/ppp/options /tmp/`) a csatlakozás létrehozza (root, 644), a naplóban „/etc/ppp/options létrehozása”
- [ ] Futó kapcsolat közben `sudo kill <pppd pid>` → értesítés a megszakadásról; `sudo kill <sstpc pid>` → ugyanez
- [ ] Kilépés „fussanak tovább” → újraindítás után az SSTP kapcsolat aktívként jelenik meg, bontható
- [ ] `.sstp` export → nincs benne jelszó; visszaimportálva ugyanaz a kapcsolat (SSTP típusként)
- [ ] IPv6 szervercím (`server=<IPv6>`): a `[cím]:port` alakot az `sstpc` elfogadja-e és felépül-e a kapcsolat (még nem ellenőrzött)
- [ ] `"`, `\` vagy tabulátor a jelszóban → az űrlap piros hibát mutat, nem ment; a mvpn is elutasítja
- [ ] A `/var/run/macvpn/<id>/pppd.log` root, 600; a felhasználói naplóban a pppd sorai `[pppd]` előtaggal; a pppd logfile sorformátuma (időbélyeg + ` : `) egyezik a horgonyzott mintákkal
- [ ] Bontás után a `0/1` és `128.0/1` útvonalak eltűntek; `/tmp/sstp-pppd.*` nem marad (az sstpc hová írja: `/private/tmp` vagy `/var/run/sstpc`?)
- [ ] Debug napló: tartalmazza az MS-CHAPv2 cserét → csak bizalmasan kezelendő

## Szerkesztés és mentetlen változások
- [ ] Mentetlen módosítással másik kapcsolat kijelölése → megerősítő párbeszédablak (Mentés / Elvetés / Mégse), mindhárom ág helyes
- [ ] Mentetlen módosítással Cmd+W → ugyanez a párbeszédablak; „Mégse" után az ablak nyitva marad
- [ ] Mentetlen módosítással kilépés (Cmd+Q / menü) → a párbeszédablak megjelenik; „Mégse" után az app fut tovább
- [ ] A párbeszédablakból mentés hibája (pl. érvénytelen config) látható hibaként jelenik meg, nem nyelődik el
- [ ] Kényszerített váltás a Napló fülre (pl. Option+kattintás) szerkesztés közben → a szerkesztett, mentetlen tartalom megmarad, visszaváltva is

## Debug mód
- [ ] Option+kattintás a menüben → a Kapcsolatok ablak a Napló fülön nyílik
- [ ] Option+kattintás debug esetén is a Napló fülön nyílik az ablak (zárt és már nyitott ablaknál is)
- [ ] OpenVPN debug: `$ …/openvpn --config …` sor, `--verb 5` kimenet, `diagnosztika (előtte/utána)` blokkok
- [ ] WireGuard debug: `[#] …` sorok és a `wg show` kimenete
- [ ] IKEv2 debug: IKE_SA_INIT / IKE_AUTH sorok
- [ ] L2TP debug: `log stream` sorok jönnek, sikeres kapcsolat után leáll
- [ ] Szűrő (Parancsok / Hibák), keresés, Másolás, Mentés… működik; a mentett napló `600`-as jogosultságú; nem írható helyre mentve hibaablak jelenik meg
- [ ] A naplóban sehol nem szerepel a jelszó vagy a PSK (`grep` a mentett naplóban)
- [ ] Az OpenVPN napló `verb 5` mellett sem tartalmazza a jelszót (`grep` a jelszóra a teljes naplóban és a root logfájlban)

## Kapcsolatok sorrendje
- [ ] Friss telepítés (nincs `connection-order.json`): a menü és a Kapcsolatok ablak listája név szerint, a rendszer VPN-ek a sajátokkal egy listában („· Rendszer-VPN” / „· System VPN” jelöléssel)
- [ ] Jobb klikk → **Kitűzés** / **Pin to Top**: a kapcsolat a **Kitűzött** részbe kerül, gombostű ikonnal az ablakban és a menüben; **Kitűzés megszüntetése** / **Unpin** visszateszi
- [ ] Két kitűzött kapcsolat sorrendje húzással megfordítható; a menü is követi; újraindítás után megmarad
- [ ] Egy nem kitűzött kapcsolathoz kétszer csatlakozva (és bontva) a többi nem kitűzött elé kerül; a fennálló kapcsolat pollingja nem viszi tovább előre
- [ ] Rendszer VPN (pl. `Office L2TP`) a MacVPN-ből indítva szintén előrébb kerül; a Rendszerbeállításokból indítva nem
- [ ] Kitűzött kapcsolat törlése után a `connection-order.json`-ból eltűnik a bejegyzése; a fájl jogai `600`
- [ ] Export: a kitűzés és a pontszám nem kerül az exportba

## MFA (valódi szerver kell)
Előfeltétel: OpenVPN 2.6/2.7 szerver (pl. `openvpn-auth-*` plugin, `auth-user-pass-verify` script vagy OpenVPN Access Server), amely a lent jelölt módszert adja.
- [ ] Sima felhasználónév/jelszó MFA nélkül: felépül; `sudo ls -l /var/run/macvpn/<id>/` → nincs `auth` és `mgmt-creds`, van `mgmt.sock` (`srwx------`, root); `ps -o args= -p $(sudo cat /var/run/macvpn/<id>/mgmt.pid)` → `mvpn-mgmt …` (a `mvpn` bináris, `mvpn-mgmt` néven indítva)
- [ ] Hálózatváltás / `ping-restart` / `auth-nocache` mellett az újracsatlakozás jelszókérés nélkül sikerül (a közvetítő a memóriából válaszol, a `hold release` újra megy)
- [ ] **Statikus challenge** (`static-challenge "OTP" 1` a configban, szerveroldalon SCRV1-et értő ellenőrzés): csatlakozás előtt kódbekérő (látható mező), helyes kóddal felépül, rossz kóddal „Hitelesítési hiba”; `static-challenge … 0` → rejtett mező; `concat` formátummal is
- [ ] **Dinamikus challenge (CRV1)**: a szerver `AUTH_FAILED,CRV1:R,E:…` választ ad → csatlakozás közben kódbekérő a szerver szövegével; helyes kóddal felépül; rossz kóddal hiba, és a szerver naplója szerint nincs ismételt próbálkozás
- [ ] **CR_TEXT** (`client-pending-auth … CR_TEXT:R,E:…`): kódbekérő, `cr-response` után felépül
- [ ] **Webes / SAML / push** (`OPEN_URL:https://…` vagy `WEB_AUTH::https://…`): az ablak a hosztot mutatja; „Megnyitás a böngészőben” → az alapértelmezett böngésző a helyes címmel; bejelentkezés után felépül; a menüsor addig „Hitelesítésre vár” (kulcs ikon); „Mégse” → „A hitelesítés megszakítva”, takarítás
- [ ] Push jóváhagyás telefonon (pl. Duo / Microsoft Authenticator a szerver mögött): jóváhagyás után felépül, elutasítás után hiba
- [ ] `http://` URL-t küldő szerver: nem nyílik böngésző, a naplóban `web authentication URL dropped (only https with a plain ASCII host is accepted)`, a szerver határideje után hiba
- [ ] A kódbekérő megjelenésekor egy másik appban gépelve a leütések ott maradnak (a panel nem lesz kulcsablak); „…: hitelesítés szükséges” értesítés jön, rákattintva a panel fókuszt kap; a menüsor ikonja kulcs; az első másodpercben a mező és a gombok tiltottak; Enter nem nyitja meg a böngészőt
- [ ] `WEB_AUTH::https://xn--pple-43d.com/…` → a megerősítő ablak `xn--pple-43d.com`-ot és a teljes ASCII címet mutatja (nem „аpple.com”-ot); `https://%D0%B0pple.com/` → eldobva
- [ ] CR_TEXT válasz után `verb 4`-gyel (debug): a naplóban nincs `cr-response` és `CR_RESPONSE,` sor
- [ ] Kódbekérő 2 percig érintetlen → bezárul, „A hitelesítés nem fejeződött be időben”; nincs futási könyvtár, nincs `/var/run/macvpn-ui/<id>.json`
- [ ] Bontás a kódbekérő nyitva tartása közben: az ablak bezárul, a bontás pár másodperc alatt kész (nem várja ki a zárat)
- [ ] `/var/run/macvpn-ui` `root:wheel 755`, a `<id>.json` a felhasználóé, `600`, benne nincs jelszó, kód, token; a naplóban (debug módban is, `verb 5`) nincs kód és jelszó, csak `[mgmt]` eseménysorok
- [ ] **Kód a jelszó végén** (szerveroldalon jelszó+OTP-t váró RADIUS / LDAP): OpenVPN, IKEv2 (EAP), SSTP, L2TP, Cisco IPsec és egy rendszer-VPN mentett jelszóval; mindhárom elválasztóval (nincs, `,`, `:`); a kód nem kerül a Keychainbe és a `meta.json`-ba (csak `otp.enabled` / `otp.separator`)
- [ ] L2TP: a kód-beállítás puszta módosítása nem nyit új profilt jóváhagyásra
- [ ] SSTP: `"`-t tartalmazó kódnál hibaüzenet, nincs csatlakozás

## Hibák
- [ ] Rossz jelszó (OpenVPN) → piros ikon, értesítés „AUTH_FAILED", kattintásra Napló
- [ ] Elérhetetlen szerver → 30 mp után „Időtúllépés"
- [ ] `up /tmp/x` a configban → mentéskor piros hiba, nem ment
- [ ] Futó kapcsolat közben `sudo kill <openvpn pid>` → értesítés a megszakadásról

## Értesítések
- [ ] Az app előtérben (megnyitott ablakkal) is megjelennek az értesítések (csatlakozás, megszakadás, hiba)
- [ ] Sikertelen csatlakozás értesítésének szövege általános („Részletek a MacVPN-ben” / „Open MacVPN for details”), a hibaüzenet csak az appban látszik

## Életciklus
- [ ] Kilépés aktív kapcsolattal → kérdés; „fussanak tovább" → újraindítás után a kapcsolat aktívként jelenik meg
- [ ] Kilépés aktív rendszer VPN-nel (pl. `Office L2TP`) → helyes kérdés, a rendszer VPN nem bomlik meg indokolatlanul
- [ ] Az ablak bezárása után (delegate visszaállítás) az ablak a menüből újra megnyitható, és megfelelően működik
- [ ] `brew install` futása közben az ablak bezárása → a telepítés tovább fut, újranyitva a kimenet és az állapot helyes
- [ ] `brew install` közben `ps eww <brew pid>` → a környezetben csak HOME, USER, LOGNAME, TMPDIR, LANG, PATH és HOMEBREW_NO_ENV_HINTS van; az app más `HOMEBREW_*` változói nem jutnak át
- [ ] Alvás/ébredés után az állapot frissül
- [ ] Két kapcsolat egyszerre aktív (pl. WireGuard + IKEv2)

## Indítás bejelentkezéskor
- [ ] Új felhasználó / első indítás: az „Indítás bejelentkezéskor” négyzet ki van kapcsolva, a Rendszerbeállítások → Általános → Bejelentkezési elemek között nincs MacVPN
- [ ] `/Applications`-ből futó app: bekapcsolás a menüben → a négyzet bejelölve, a MacVPN megjelenik a Rendszerbeállítások → Általános → Bejelentkezési elemek listájában
- [ ] Bekapcsolva kijelentkezés, majd bejelentkezés → a MacVPN magától elindul (pajzs a menüsorban)
- [ ] Kikapcsolás → a MacVPN eltűnik a Bejelentkezési elemek közül; kijelentkezés/bejelentkezés után nem indul el
- [ ] A Rendszerállapot ablakban ugyanaz a négyzet és ugyanaz az állapot látszik; a Rendszerbeállításokban végzett kikapcsolás a menü újranyitásakor / az ablak megnyitásakor megjelenik
- [ ] requiresApproval: a Bejelentkezési elemek között a MacVPN-t kikapcsolva (vagy MDM-mel jóváhagyáshoz kötve) → „Engedélyezd a MacVPN-t a Rendszerbeállítások → Általános → Bejelentkezési elemek alatt.” megjegyzés és „Bejelentkezési elemek beállításai…” gomb; a gomb a megfelelő beállításoldalt nyitja; jóváhagyás után a megjegyzés eltűnik
- [ ] A DMG-ről (vagy a Letöltések mappából / App Translocation alól) indított app → a négyzet nem kattintható, alatta a „csak az Alkalmazások mappából” / „ideiglenes hely” magyarázat
- [ ] Ad-hoc aláírt build `/Applications`-ből (az `SMAppService` `.notFound`): a négyzet kattintható és ki van kapcsolva, nincs „a macOS nem találja” megjegyzés
- [ ] Ad-hoc build, bekapcsolás → létrejön a `~/Library/LaunchAgents/local.macvpn.launcher.plist` (0644, `Label` `local.macvpn.launcher`, `ProgramArguments` `/usr/bin/open -b local.macvpn`, `RunAtLoad` true; `plutil -p` ellenőrzés); a négyzet bejelölve, alatta „Bejelentkezési LaunchAgenttel bekapcsolva (a következő bejelentkezéstől érvényes).”; az app nem indul újra
- [ ] LaunchAgenttel bekapcsolva kijelentkezés, majd bejelentkezés → a MacVPN magától elindul; az app áthelyezése (pl. `~/Applications`-be) után is
- [ ] LaunchAgenttel bekapcsolva kikapcsolás → a plist törlődik; egy kézzel odatett, más `Label`-ű `local.macvpn.launcher.plist` megmarad
- [ ] A `local.macvpn.launcher.plist` helyén symlink → bekapcsoláskor riasztás („szimbolikus link vagy nem szabályos fájl”), a link célja érintetlen
- [ ] Regisztrálási hiba mindkét úton (pl. nem írható `~/Library/LaunchAgents`) → riasztás a hibaüzenettel, a négyzet a valós állapotot mutatja
- [ ] Angol felülettel (`/Applications/MacVPN.app/Contents/MacOS/MacVPN -AppleLanguages '(en)'`) ugyanezek a szövegek angolul

## Frissítés
- [ ] Régebbi verzió (pl. `0.0.1`-re állított `CFBundleShortVersionString`) a `/Applications`-ben → induláskor „Frissítés elérhető: vX.Y.Z" sor a menüben
- [ ] Az ablakban a release notes látszik; „Letöltés és telepítés" → lépések kijelezve, kilépés, csere, az új verzió újraindul, a quarantine attribútum nincs rajta
- [ ] Aktív kapcsolat / nem mentett szerkesztés mellett a telepítés ugyanazt kérdezi, mint a kilépés; „Mégse" → nincs kilépés, a DMG leválasztva
- [ ] Nem írható helyről (pl. App Translocation, a DMG-ről indítva) futó app → hibaüzenet, nincs jogosultság-emelés
- [ ] „Frissítések keresése most" naprakész appal → „A MacVPN naprakész"; hálózat nélkül → hibaüzenet
- [ ] „Frissítések automatikus keresése" kikapcsolva → induláskor nincs ellenőrzés; bundle nélküli fejlesztői build (`target/debug/macvpn-app`) alatt a frissítés menüpontok nem látszanak
- [ ] `~/Library/Caches/MacVPN/update.log` tartalmazza a csere lépéseit, a segédscript könyvtára törlődött
- [ ] Az `Info.plist`-ből törölt `MacVPNUpdateRepoID` → a frissítés menüpontok nem látszanak (nincs visszaesés a névre)
- [ ] „Csak a legalább 24 órája megjelent frissítések felajánlása" bekapcsolva, 24 óránál frissebb kiadás → nincs „Frissítés elérhető" sor; „Frissítések keresése most" → jelzi, hogy később lesz felajánlva; kikapcsolva → azonnal megjelenik
- [ ] A frissítés közben a régi app nem lép ki 30 mp-en belül (pl. egy modális ablak nyitva marad) → a következő indításkor egyszeri értesítés a megszakadt frissítésről, a második indításkor már nincs
- [ ] Kézzel létrehozott `.MacVPN.app.old-TESZT` mappa az app mellett → induláskor törlődik
- [ ] Frissítés után a macOS Keychain kérdése (ha megjelenik) a MacVPN nevét és útvonalát mutatja; „Mindig engedélyezés" után nem kérdez újra

## Súgó és eltávolítás
- [ ] „Súgó" / „Help": ha a preferált nyelvek közül az első magyar vagy angol a magyar, a `user-guide.hu.md`-t, egyébként az `user-guide.en.md`-t nyitja meg a GitHubon
- [ ] Nyelv: `MacVPN.app/Contents/MacOS/MacVPN -AppleLanguages '(hu)'` → magyar felület (menü, ablakok, NSAlert-ek, értesítések, validátor-hibák); `'(en)'` → angol; `'(de)'` → angol; `'(de, hu)'` → magyar
- [ ] Nyelv, root oldal: magyar felülettel egy hibás config csatlakozásakor a hiba és a Napló `▶ [mvpn]` sorai magyarok, angol felülettel angolok
- [ ] „MacVPN eltávolítása…" aktív OpenVPN kapcsolattal → a kapcsolat lebomlik, a négy útvonal törlődik, a Homebrew csomagok megmaradnak
- [ ] Régi verzió `macvpn` szolgáltatású Keychain bejegyzései az első indításkor átkerülnek a `local.macvpn.secrets` szolgáltatásba (a régiek törlődnek); a mentett jelszavak megmaradnak
- [ ] A „felhasználói adatok" jelölővel az Application Support/MacVPN és a Keychain `local.macvpn.secrets` bejegyzései (és a régi `macvpn` szolgáltatás `<UUID>.<mező>` maradékai) is törlődnek (a rendszer VPN-ekhez mentett PSK/jelszó is); nélküle megmaradnak
- [ ] Az admin jelszókérés megszakítása → „Az eltávolítás megszakítva", semmi nem törlődik
- [ ] Bekapcsolt „Indítás bejelentkezéskor” mellett eltávolítás → a MacVPN eltűnik a Bejelentkezési elemek közül, a `~/Library/LaunchAgents/local.macvpn.launcher.plist` is törlődik; kikapcsolt állapotnál nincs változás

## Frissítés v0.4.0 → v1.0.0 (Swift → Rust)

Automatikus előpróba (a kiadás előtt, a karbantartó gépén, a valódi kulcs nélkül): a v0.4.0 updater kódja
(`git archive v0.4.0 Sources/MacVPNCore`) egy harnessbe fordítva lefut a `dist/MacVPN-1.0.0.dmg`-n (release.yml
szerinti `.sha256`, `sign-release.sh --dry-run` aláírás eldobható kulccsal; a harness másolatában csak az elsődleges
nyilvános kulcs van kicserélve): kiadás-JSON és URL-szabály, felajánlás (24 órás késleltetéssel is), letöltés +
SHA-256 + Ed25519, `hdiutil attach`, `verifyApp` (bundle ID, a tag verziója, symlinkek, `codesign --verify
--strict`), és a v0.4.0 segédscript egy sandbox Applications mappában (megvárja az appot, cserél, `done`, takarít;
az `open` csonk). Ellenőrzés: az idegen kulccsal készült aláírást és a tagtől eltérő verziót elutasítja.

A valódi frissítés csak a közzététel után próbálható (a v0.4.0 app a `releases/latest`-et kérdezi, a draftot nem
látja, és csak a beágyazott kulcsokkal aláírt kiadást fogadja el). Közvetlenül a `scripts/sign-release.sh v1.0.0`
után, egy 0.4.0-s telepítésen:

- [ ] Előkészítés: `/Applications/MacVPN.app` a v0.4.0 (`defaults read /Applications/MacVPN.app/Contents/Info.plist CFBundleShortVersionString` → `0.4.0`), a root réteg 6, legalább egy kapcsolat típusonként, egy kitűzött kapcsolat, egy rendszer VPN OTP-beállítással, bekapcsolt „Indítás bejelentkezéskor”. Biztonsági mentés: `cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-0.4.0` és `defaults export local.macvpn ~/MacVPN-backup-0.4.0/defaults.plist`
- [ ] A tesztgépen a „Csak a legalább 24 órája megjelent frissítések felajánlása” legyen kikapcsolva (a felhasználók többsége így is csak 24 óra múlva kapja meg, ha bekapcsolta)
- [ ] v0.4.0 menü → „Frissítések keresése most” → „Frissítés elérhető: v1.0.0”; a Frissítés ablakban a kiadási jegyzet
- [ ] Egy aktív VPN kapcsolattal „Letöltés és telepítés” → a lépések (hely, letöltés, csatolás, ellenőrzés, előkészítés) után a kilépési kérdés; „fussanak tovább” → a v0.4.0 kilép, pár másodpercen belül az 1.0.0 elindul (menüsor ikon), a futó kapcsolat aktívként látszik
- [ ] `defaults read /Applications/MacVPN.app/Contents/Info.plist CFBundleShortVersionString` → `1.0.0`; `codesign --verify --strict /Applications/MacVPN.app` sikeres; `xattr -l /Applications/MacVPN.app` → nincs `com.apple.quarantine`; az Applications mappában nincs `.MacVPN.app.update-*` / `.old-*`
- [ ] `tail ~/Library/Caches/MacVPN/update.log`: az utolsó blokk `=== … update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===` és `done`; az 1.0.0 nem jelez „Az előző frissítés nem fejeződött be” hibát; a DMG le van választva (`hdiutil info`)
- [ ] Keychain: a macOS egyszer rákérdezhet a `local.macvpn.secrets` elemekre (az új ad-hoc aláírás miatt); „Mindig engedélyezés” csak akkor, ha a kérdés a MacVPN-től jön (`/Applications/MacVPN.app`); utána minden kapcsolatnál „Mentve – írj be újat a cseréhez” látszik, és csatlakozáskor nincs újabb kérdés
- [ ] Adatok: minden kapcsolat megvan ugyanazzal a névvel, a kitűzés és a sorrend megmaradt, a rendszer VPN OTP-beállítása megmaradt; típusonként egy csatlakozás és bontás sikerül
- [ ] Beállítások: a „Frissítések automatikus keresése” és a 24 órás késleltetés értéke a régi; az „Indítás bejelentkezéskor” bekapcsolva marad (kijelentkezés / bejelentkezés után az 1.0.0 indul)
- [ ] Rendszerállapot: a root réteg „Frissítés szükséges” (6 → 7); „Engedélyezés” → egy admin jelszó → zöld; `ls /usr/local/libexec/macvpn` → `VERSION mvpn`; `sudo -n /usr/local/libexec/macvpn/mvpn version` → `7`; a régi `ovpn-dns`, `mvpn-validate`, `mvpn-mgmt` nincs meg
- [ ] Értesítések: a csatlakozás / megszakadás értesítései megjelennek (ha a macOS újra engedélyt kér, az a MacVPN-től jön)
- [ ] Nyelv: magyar rendszernyelvnél a teljes felület magyar, `-AppleLanguages '(en)'`-nel angol
- [ ] Hiba esetén: a segédscript visszaállítja a régi appot (`update.log`: „old app restored”); a kiadást azonnal vissza kell vonni (törlés vagy egy javított kiadás „latest”-té tétele), a 0.4.0 DMG kézzel újratelepíthető, az adatok a mentésből visszamásolhatók
