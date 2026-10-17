# MacVPN – kézi tesztlista

Előfeltétel: `scripts/build-dmg.sh` lefutott, `swift test` és `scripts/test-root.sh` zöld.

## Telepítés tiszta állapotból
- [ ] `sudo rm -rf /usr/local/libexec/macvpn /etc/sudoers.d/macvpn` (előző telepítés törlése)
- [ ] DMG megnyitása, MacVPN.app húzása az Applications mappába
- [ ] Első indítás: a Gatekeeper letiltja → Rendszerbeállítások → Adatvédelem és biztonság → „Megnyitás mindenképp"
- [ ] Megnyílik a Rendszerállapot ablak; a hiányzó eszközök listája helyes
- [ ] „Telepítés" → brew kimenet élőben, a végén zöld
- [ ] Homebrew hiányában „Telepítés…" → Terminál nyílik egy `$TMPDIR/macvpn-brew.XXXXXXXX/install-homebrew.command` scripttel (0700); hálózat nélkül a script hibaüzenettel kilép, a mappa a futás végén törlődik
- [ ] „Engedélyezés" → egy admin jelszókérés → zöld
- [ ] `sudo -n /usr/local/libexec/macvpn/mvpn status` jelszó nélkül `[]`
- [ ] A telepítő a `Contents/Resources/root/mvpn-validate` binárist is felmásolja, és a `sudo -n -u` alapú másolás rootként működik
- [ ] Régi/elakadt lock fájl (stale lock) nem blokkolja a telepítést vagy a műveleteket

## Kapcsolatok típusonként
- [ ] Export: mindegyik típus exportja → a fájlban nincs jelszó/PSK; a gomb súgója „Exportálás… (jelszavak sosem kerülnek bele)”
- [ ] OpenVPN `<key>`/`<tls-auth>` blokkos config exportja → „A config privát kulcsokat tartalmaz” kérdés; „Exportálás kulcsok nélkül” → a fájlban nincs kulcsblokk, a `<ca>` megvan; „Exportálás kulcsokkal” → változatlan config; „Mégse” → nincs mentési ablak
- [ ] WireGuard export ugyanez (`PrivateKey =` üresen marad); strongSwan `secrets { }` szakasszal → a szakasz kimarad
- [ ] OpenVPN / WireGuard / strongSwan export (kulcsokkal) visszaimportálva ugyanaz a config
- [ ] `.ovpn` import `ca ../x.crt`, `key /etc/hosts`, kifelé mutató symlink, rossz formátumú (`ca` → szövegfájl) vagy 1 MB-nál nagyobb hivatkozott fájllal → érthető hibaüzenet, nem importálódik; helyes `ca ca.crt` + `tls-auth ta.key 1` → „Importálva, beemelt fájlok: ca.crt, ta.key”
- [ ] Hibás config (pl. `up /x` sor) importja → importálódik, a szerkesztő rögtön a piros hibalistával nyílik meg
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
- [ ] Két azonos nevű L2TP szolgáltatás (az egyik nem a MacVPN-é, más szerverrel) → a MacVPN a sajátját köti (azonos szervercím), a másik a Rendszer VPN-ek között látszik; kötés nélkül (azonos szervercím sincs) a csatlakozás hibát ad („Több … nevű VPN szolgáltatás van…”), jelszót nem ad át
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
- [ ] Root réteg frissítése: a 2-es VERSION-ről „Frissítés szükséges”, „Engedélyezés” után zöld (`mvpn version` = 3)
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
- [ ] Regisztrálási hiba (pl. nem aláírt / sérült app) → riasztás a rendszer hibaüzenetével, a négyzet a valós állapotot mutatja
- [ ] Angol felülettel (`-AppleLanguages '(en)'`) ugyanezek a szövegek angolul

## Frissítés
- [ ] Régebbi verzió (pl. `0.0.1`-re állított `CFBundleShortVersionString`) a `/Applications`-ben → induláskor „Frissítés elérhető: vX.Y.Z" sor a menüben
- [ ] Az ablakban a release notes látszik; „Letöltés és telepítés" → lépések kijelezve, kilépés, csere, az új verzió újraindul, a quarantine attribútum nincs rajta
- [ ] Aktív kapcsolat / nem mentett szerkesztés mellett a telepítés ugyanazt kérdezi, mint a kilépés; „Mégse" → nincs kilépés, a DMG leválasztva
- [ ] Nem írható helyről (pl. App Translocation, a DMG-ről indítva) futó app → hibaüzenet, nincs jogosultság-emelés
- [ ] „Frissítések keresése most" naprakész appal → „A MacVPN naprakész"; hálózat nélkül → hibaüzenet
- [ ] „Frissítések automatikus keresése" kikapcsolva → induláskor nincs ellenőrzés; `swift run` alatt a frissítés menüpontok nem látszanak
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
- [ ] Bekapcsolt „Indítás bejelentkezéskor” mellett eltávolítás → a MacVPN eltűnik a Bejelentkezési elemek közül; kikapcsolt állapotnál nincs változás
