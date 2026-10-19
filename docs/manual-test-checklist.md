# MacVPN – kézi tesztlista (1.2.0 és 1.1.0, Rust/Tauri)

Előfeltétel: `scripts/build-dmg.sh` lefutott (`dist/MacVPN-1.1.0.dmg`), zöld: `cargo test --workspace`,
`scripts/test-root.sh` (Rust `mvpn`), `cd app/ui && npm test && npm run build`, `scripts/test-sign-release.sh`, a
smoke teszt mindkét nyelven (`SMOKE_LANG=en scripts/smoke-manage.sh`, `SMOKE_LANG=hu scripts/smoke-manage.sh`), és
az 1.0.0-s updater ellenőrzései a kész appon (lásd lent, „Frissítés v1.0.0 → v1.1.0”).

## 1.2.0: széf, mappák, közös hitelesítő adatok, mentés

Előfeltétel: `scripts/build-dmg.sh` hiba nélkül lefutott (`dist/MacVPN-1.2.0.dmg`), a „release gate (SQLCipher with CommonCrypto, no OpenSSL; no SQLite in mvpn)” lépés mindkét architektúrára „SQLCipher with CommonCrypto, no OpenSSL” sort ír; a fenti tesztek és a smoke teszt mindkét nyelven zöld. A tesztet egy valódi 1.1.0-s telepítésen, valódi adatokkal végezd.

### Csomag
- [ ] `Contents/Resources/root/VERSION` = 8; `CFBundleShortVersionString` = `CFBundleVersion` = `1.2.0`
- [ ] A bundle-ben ott van a `THIRD-PARTY-NOTICES.txt`, benne az SQLCipher BSD-licence (Zetetic LLC) és az MIT-értesítések; a repóban ott van a `LICENSE`
- [ ] `otool -L dist/MacVPN.app/Contents/MacOS/MacVPN` nem listáz `libcrypto`/`libssl`/`openssl` könyvtárat; `grep -a -c sqlcipher …/root/mvpn` = 0

### Mentés a frissítés előtt
- [ ] Az 1.1.0-ban: legalább egy kapcsolat típusonként, egy kitűzött kapcsolat, egy rendszer VPN OTP-beállítással és mentett PSK-val, egy párosított app, bekapcsolt „Indítás bejelentkezéskor”
- [ ] Kilépés az 1.1.0-ból, majd `cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.1.0`; a Keychain `local.macvpn.secrets` bejegyzéseinek száma feljegyezve (`security dump-keychain | grep -c local.macvpn.secrets`, csak nevek, **soha `-d`**)

### Frissítés 1.1 → 1.2 az appon belül
- [ ] 1.1.0 menü → „Frissítések keresése most” → „Frissítés elérhető: v1.2.0”; „Letöltés és telepítés” egy futó kapcsolattal → „Kilépés, fussanak tovább” → az 1.2.0 indul, a futó kapcsolat aktívként látszik
- [ ] `update.log` → `done`; nincs `com.apple.quarantine`, nincs `.MacVPN.app.update-*` / `.old-*`

### Root 7 → 8
- [ ] A Rendszerállapot „Frissítés szükséges (7 → 8)”; „Engedélyezés” → egy admin jelszó → „Telepítve (verzió 8)”; `sudo -n /usr/local/libexec/macvpn/mvpn version` = 8
- [ ] Előtte az OpenVPN/WireGuard/IKEv2/SSTP kapcsolatokon „Hiányzó eszköz”, az L2TP/Cisco/rendszer VPN működik

### Széf létrehozása és a valódi adatok átköltöztetése
- [ ] Induláskor megnyílik a „Széf beállítása” ablak; jelzi az átköltöztetést és a várható Keychain kérdések számát („legfeljebb N alkalommal”); N egyezik a feljegyzett bejegyzésszámmal
- [ ] 10 karakternél rövidebb mesterjelszó → „Túl rövid”, a „Széf létrehozása” tiltva; eltérő ismétlés → „A két jelszó nem egyezik”; az erősségjelzés változik
- [ ] A helyreállítási kulcs `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` alakú; „Másolás” → „Kimásolva”; rossz csoport → „Ez nem a helyreállítási kulcs N. csoportja”; jó csoport → tovább
- [ ] Átköltöztetés közben a Keychain kérdések: **a ténylegesen megjelent kérdések száma: ___** (≤ N); mindegyik a MacVPN-t és a `/Applications/MacVPN.app`-ot nevezi meg; „Mindig engedélyez”
- [ ] Eredmény: „Az adataid a széfben vannak”, a kapcsolatok és titkok száma helyes; nincs „nem olvasható” elem
- [ ] Utána: a régi kapcsolatmappák és a `connection-order.json` eltűnt, van `vault.db` és `vault.keys` (0600, a mappa 0700); a `local.macvpn.secrets` bejegyzések törlődtek, egy `local.macvpn.vault` / `dek` bejegyzés van
- [ ] Megmaradt: kitűzés és sorrend, rendszer VPN OTP-beállítás és PSK, a párosított app (újra kapcsolódik), „Indítás bejelentkezéskor”, frissítési beállítások
- [ ] Hibaág (külön profilon / sandboxban): egy olvashatatlan elemmel vagy megszakított átköltöztetéssel → „Az átköltöztetés nem fejeződött be”, semmi sem törlődött; a menüben „Az átköltöztetés a széfbe nem fejeződött be. Újrapróbálás…” sáv; csatlakozni lehet, szerkeszteni nem („…írásvédetten használja…”); „Újra” új mesterjelszóval sikerül

### Minden kapcsolat működik
- [ ] Típusonként csatlakozás és bontás a menüből és a Kapcsolatok ablakból; a szerkesztőkben „Mentve – írj be újat a cseréhez”; csatlakozáskor nincs jelszókérés
- [ ] Hiányzó jelszó → „Hitelesítő adatok szükségesek”, „Mentés a széfbe” bejelölve; rossz jelszó OpenVPN/SSTP/IKEv2 EAP esetén egyszer újra kérdez; a jó jelszó a széfbe kerül
- [ ] A vezérlő API: a párosított app fel- és lekapcsol egy engedélyezett kapcsolatot

### Zárolás és feloldás
- [ ] Bekapcsolt „Automatikus feloldás” mellett a „Széf zárolása most” rejtett; a „„Széf zárolása most” megjelenítése” kapcsolóval megjelenik
- [ ] „Széf zárolása most” futó VPN-nel → a menüben csak „Széf feloldása…”, „1 kapcsolat aktív”, „Kilépés”; nevek nem látszanak; a VPN fennmarad; a Kapcsolatok ablak nem mentett változása elveszett; a vezérlő API `locked`-ot ad, a `down` működik
- [ ] „Széf feloldása…” → hibás jelszó → „Hibás jelszó vagy helyreállítási kulcs”, a várakozás nő (1, 2, 4 … 30 mp), nincs kizárás; jó jelszó → minden visszajön, a mappák is
- [ ] Zárolás után az app újraindítása bekapcsolt automatikus feloldással → kérdés nélkül nyílik
- [ ] „Automatikus feloldás” ki → „Kikapcsolod az automatikus feloldást?” → „Kikapcsolás”; a `local.macvpn.vault` bejegyzés törlődött; újraindítás → „A MacVPN feloldása” ablak; vissza be → mesterjelszó → „Bekapcsolás”, a bejegyzés újra ott van
- [ ] „Mesterjelszó módosítása…”: rossz jelenlegi jelszó → elutasítás és várakozás; jóval → „A mesterjelszó megváltozott”; zárolás után csak az új jelszó nyit; a helyreállítási kulcs változatlanul működik
- [ ] Helyreállítás: „Helyreállítási kulcs használata” → kulcs (kisbetűvel, kötőjelek nélkül is) + új jelszó → „Visszaállítás és feloldás”; a kapcsolatok változatlanok
- [ ] „Új helyreállítási kulcs…” → mesterjelszó → új kulcs, csoport-ellenőrzés → „Az új helyreállítási kulcs elkészült”; a régi kulcs már nem működik, az új igen

### Mappák
- [ ] „Új” → „Új mappa”, átnevezés helyben; 65 karakteres név → „A mappa neve 1–64 karakter lehet, vezérlőkarakter nélkül”
- [ ] Helyi menük: mappa (Új mappa, Átnevezés, Szín…, Áthelyezés a legfelső szintre, Törlés…), kapcsolat (Kitűzés / Kitűzés megszüntetése, Szín…, Áthelyezés a legfelső szintre, Új mappa)
- [ ] 12 szín + „Nincs” a mappánál; a kapcsolat örökli a mappa színét; saját szín → „Saját szín” pötty; „A mappa színe” visszaállítja; világos és sötét módban is olvasható
- [ ] Húzás: mappa mappába (beágyazás) és mappák közé (sorrend); kapcsolat mappára (áthelyezés); kitűzött kapcsolat egy másik kitűzöttre ugyanabban a mappában (sorrend); a „Legfelső szint” célterület húzás közben megjelenik; mappa a saját almappájába → „Egy mappa nem helyezhető önmagába vagy a saját almappájába”
- [ ] Sorrend egy mappán belül: almappák, kitűzöttek, használat, név
- [ ] Törlés: alapból a tartalom a szülőbe / legfelső szintre kerül; „A kapcsolatok is törlődjenek” → második megerősítés, a kapcsolatok és jelszavaik törlődnek, a rendszer VPN-ek a legfelső szintre kerülnek; aktív kapcsolattal → „Előbb bontsd a mappában lévő kapcsolatokat…”
- [ ] Menü: a mappa csukható, újraindítás után is csukva marad; a jelvény az aktív kapcsolatok számát mutatja („2 aktív”); 4+ szint mélyen a behúzás 3 szintnél megáll
- [ ] Export mappában lévő kapcsolatból → első sor `# macvpn-meta: {"folder":[…]}`; törölt mappa után import → a mappa újra létrejön, a kapcsolat benne
- [ ] Rendszer VPN mappában → a Rendszerbeállításokban törölve, majd újra felvéve (30 napon belül) → visszakerül a mappájába
- [ ] Zárolt széf mellett a mappák nem látszanak és nem módosíthatók

### Közös hitelesítő adatok
- [ ] Kapcsolatok ablak → „Hitelesítő adatok” → „Hitelesítő adat hozzáadása…”; névszabály (1–64 karakter), azonos név → „Már van … nevű hitelesítő adat”
- [ ] „Létrehozás kapcsolatból…” egy OpenVPN kapcsolatból → „Összekapcsolod az azonos bejelentkezéseket?” felsorolja az azonos adatú kapcsolatokat, értékek nem látszanak; „Létrehozás és összekapcsolás” → „N kapcsolat használja”
- [ ] Szerkesztőben „Jelszó forrása” → „Hitelesítő adat: …” → megerősítés → a saját mezők eltűnnek; a kapcsolat mentése nem változtatja a közös adatot
- [ ] Jelszó nélküli közös adat → csatlakozáskor „A(z) … jelszava — N kapcsolat használja”; „Mentés a széfbe” → a közös adatba kerül, a többi kapcsolat is használja
- [ ] Jelszócsere a „Szerkesztés…”-ben → minden kapcsolat az újjal jelentkezik be
- [ ] Használatban lévő adat törlése → „Másolás minden kapcsolatba” → a kapcsolatok saját adatot kapnak és működnek
- [ ] Export → `credentialName` a meta sorban, jelszó nincs; import → „Használod a(z) „…” közös hitelesítő adatot ehhez a(z) <szerver> szerverre csatlakozó kapcsolathoz?”, a szerver a fájlból jön; alapból a saját adatok maradnak
- [ ] L2TP közös adattal: a profil a fióknevet tartalmazza, a csatlakozás a közös adattal sikerül

### Mentés és visszaállítás friss profilon
- [ ] „Teljes biztonsági mentés…” → 10 karakternél rövidebb jelszó elutasítva; „A mesterjelszavam használata…” → megerősítés; a fájl `MacVPN-backup-<dátum>.macvpnbackup`, `600`
- [ ] Friss profil (új macOS felhasználó, vagy a `~/Library/Application Support/MacVPN` és a `local.macvpn.vault` bejegyzés félretéve): „Széf beállítása” → „Visszaállítás biztonsági mentésből…” → hibás jelszó → „A mentés nem nyitható meg…”; jó jelszó → új mesterjelszó és új helyreállítási kulcs → minden kapcsolat, mappa, szín, sorrend, közös adat és titok visszajött
- [ ] Friss visszaállítás 1.1-es adatok fölé (az 1.1-es adatmappa és `local.macvpn.secrets` bejegyzések megvannak, széf nincs): „Széf beállítása” → „Visszaállítás biztonsági mentésből…” → figyelmeztetés: „A MacVPN 1.1 adataid nem kerülnek át. A mentés visszaállítása után törlődnek.” → „Mégse” visszavisz; megerősítve → mentés, új mesterjelszó, kulcs, visszaállítás → csak a mentés tartalma van a széfben; az 1.1-es `connections` mappa, `connection-order.json`, `system-otp.json` törlődött, a `local.macvpn.secrets` bejegyzések is (`security dump-keychain | grep -c local.macvpn.secrets` → 0), a `migrated-to-vault` jelölő megvan; újraindítás után nincs „Széf beállítása” ablak, nincs írásvédett mód; hibás mentésjelszónál / megszakított visszaállításnál az 1.1-es adatok érintetlenek
- [ ] Visszaállítás után a beállítások csak bejelölve lépnek életbe; „Más appok vezérelhetik a VPN-eket” nincs előre bejelölve; a párosított appok nincsenek benne
- [ ] „N natív profil újratelepítése” → a macOS mindegyik jóváhagyását kéri; utána az L2TP/Cisco csatlakozik
- [ ] Meglévő széfbe: „Összefésülés” mindhárom ütközési móddal (felülírás, megtartás, mindkettő „(backup)” névvel); „Minden cseréje…” → a törlendő elemek száma, „Előbb a jelenlegi állapot mentése…” működik; jóváhagyott kockázatos OpenVPN-beállítás: összefésülésnél újra kérdez, cserénél megmarad
- [ ] Módosított (egy bájtban elrontott) mentésfájl → ugyanaz az általános hibaüzenet; semmi sem változott

### Keychain kérdések egy későbbi frissítés után
- [ ] Egy újabb (1.2.x tesztverziós) build telepítése frissítésként, bekapcsolt automatikus feloldással: a macOS legfeljebb **egyszer** kérdez (a `local.macvpn.vault` miatt); **ténylegesen: ___**; kikapcsolt automatikus feloldással egyszer sem

### Eltávolítás
- [ ] „A felhasználói adatok törlése is” jelöléssel: a `vault.db`, a `vault.keys`, a `local.macvpn.vault` bejegyzés és a maradék `local.macvpn.secrets` bejegyzések is törlődnek; jelölés nélkül megmaradnak, és újratelepítés után a széf megnyílik
- [ ] A felületen tárolt titkokra a „széf” szó szerepel, nem a „Keychain” (a Keychain csak a széfkulcsnál és a macOS kérdéseinél)

### Opcionális: natív L2TP/Cisco profil PSK nélkül
- [ ] A `docs/superpowers/spikes/2026-10-19-vault-spike.md` D.3 lépései (alapállapot a System keychainben csak nevekkel, PSK nélküli profil telepítése, indítás a MacVPN-ből és a Rendszerbeállításokból, takarítás); az eredmény feljegyezve, és ha mindkét indítás működik mindkét típussal, a „PSK only at start” ág mehet

## 1.1.0: csomag és aláírás
- [ ] `plutil -p dist/MacVPN.app/Contents/Info.plist`: `CFBundleIdentifier` `local.macvpn`, `CFBundleName` / `CFBundleDisplayName` `MacVPN`, `CFBundleExecutable` `MacVPN`, `CFBundleShortVersionString` = `CFBundleVersion` = `1.1.0`, `LSMinimumSystemVersion` `14.0`, `LSUIElement` true, `CFBundleDevelopmentRegion` `en`, `CFBundleLocalizations` `[en, hu]`, `MacVPNUpdateRepo` `SepsiG/MacVPN`, `MacVPNUpdateRepoID` `1422472799`, `CFBundleIconFile` `AppIcon`
- [ ] `lipo -archs` a `Contents/MacOS/MacVPN`-re és a `Contents/Resources/root/mvpn`-re: `x86_64 arm64`; a `Contents/Resources/root` alatt csak `mvpn` és `VERSION` (7)
- [ ] `codesign --verify --strict --verbose=2 dist/MacVPN.app` sikeres; `codesign -dv …/root/mvpn` → `flags=…(adhoc,runtime)`
- [ ] Intel Macen (vagy `arch -x86_64`) is elindul az app; a Finder az ikont mutatja; ablak nélkül a Dockban nem jelenik meg (LSUIElement; ablakkal lásd „1.1: Dock ikon”)
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
- [ ] MikroTik v6 wiki config külön fájlokkal (`ca.crt`, `client.crt`, titkosított `client.key`, `auth-user-pass auth.cfg`) → „beemelt fájlok: ca.crt, client.crt, client.key”, „A(z) auth.cfg fájlban lévő felhasználónév és jelszó a széfbe került…”; a szerkesztőben a mezők kitöltve, a configban `auth-user-pass` fájlnév nélkül
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
- [ ] `Office L2TP` → Kapcsolatok ablak: „Közös kulcs (PSK)" és „Jelszó (nem kötelező…)" mező, Mentés → csatlakozás sikerül; „Mentett titkok törlése" után a mezők üresek, és a széfben nincs mentett titok a szolgáltatás UUID-jával (a Keychainben sincs `local.macvpn.secrets` bejegyzés)
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

## 1.1: élő rendszer-VPN lista
A figyelő (SCPreferences) valódi VPN-változásokon még nincs igazolva (`docs/superpowers/spikes/2026-10-19-live-system-list.md`): addig a lassabb lekérdezés is fut. Minden lépés macOS 14-en és 15-ön, ha lehet 10-ből 10-szer.
- [ ] `cargo test -p macvpn-platform-mac --test sc_watch -- --ignored --nocapture`, közben a Rendszerbeállítások → VPN-ben L2TP és IKEv2 VPN felvétele, átnevezése, törlése: minden lépésre kb. 1 s-on belül kiír egy sort (a késést írd a spike fájlba)
- [ ] Nyitott menü mellett VPN felvétele / átnevezése / törlése a Rendszerbeállításokban: a sor kb. 1 s-on belül megjelenik / átnevezve látszik / eltűnik, a menü újranyitása nélkül
- [ ] Nyitott Kapcsolatok ablakban egy rendszer VPN kiválasztva, majd törölve a Rendszerbeállításokban: a részletező megmarad, „Ezt a VPN-t eltávolították a macOS-ből” / „This VPN was removed from macOS” sáv, minden mező és a Csatlakozás / Mentés / Mentett titkok törlése gomb tiltva; másik kapcsolatot kiválasztva eltűnik
- [ ] Nyitott Kapcsolatok ablak mellett új VPN felvétele a Rendszerbeállításokban: a sora újranyitás nélkül megjelenik
- [ ] Egy MacVPN-ből mentett L2TP profil telepítése és eltávolítása után a lista követi a változást
- [ ] Zárt menü és ablakok mellett 10 perc tétlenség: legfeljebb 30 s-onként egy `scutil --nc list` (pl. `sudo fs_usage -w -f exec | grep scutil`), nincs pörgés
- [ ] Ha a figyelő mind a 10 próbán megbízható volt, `WATCHER_TRUSTED` (`crates/app-core/src/live.rs`) átállítható `true`-ra

## 1.1: vezérlő API (párosított appok)
A Remote Desktop app helyett a példakliens is megfelel: `cargo build -p macvpn-control-client`, `BIN=$PWD/target/debug/macvpn-control-client` (a párosítás ehhez az útvonalhoz kötődik). A token sose kerüljön az argv-be: `MACVPN_TOKEN` vagy stdin. Előtte: egy OpenVPN kapcsolat MFA-val (pl. `static-challenge` vagy CRV1 szerver), egy másik, egyszerű kapcsolat (pl. WireGuard).
- [ ] Alapállapot: Kapcsolatok → **Párosított appok** / **Paired apps**, a kapcsoló ki; `ls ~/Library/Application\ Support/MacVPN/control/` → nincs `macvpn.sock`; `$BIN list` → érthető hiba (nincs socket)
- [ ] Bekapcsolás → `ls -la ~/Library/Application\ Support/MacVPN/control/`: a mappa `drwx------`, a `macvpn.sock` `srw-------`, a felhasználóé
- [ ] `$BIN pair "Remote Desktop teszt"` → a párosító ablak nem lopja el a fókuszt (egy másik appban gépelve a leütések ott maradnak), az első másodpercben nem kattintható, nincs alapértelmezett gomb (Enter nem enged); „Név (a program saját megnevezése)”, a `$BIN` teljes útvonala monospace-szel, kapcsolatonként egy üres négyzet; az **Engedélyezés** csak bejelölt kapcsolatnál aktív
- [ ] A két kapcsolatot bejelölve **Engedélyezés** → a token egyszer, a stdoutra; a Párosított appok listában a név, az útvonal, „Még nem használta”, „Párosítva: …”, az engedélyezett kapcsolatok; a **Tevékenység** listában a párosítás; a naplókban (`~/Library/Logs`, debug kimenet) nincs token
- [ ] Ablak bezárása / **Elutasítás** → a kliens `denied`; 3 elutasítás után 10 percig minden párosítás `denied`
- [ ] Token a Keychainbe: `security add-generic-password -U -s local.test.macvpn-client -a control-token -w` (a jelszót a `security` kéri be), utána `export MACVPN_TOKEN="$(security find-generic-password -s local.test.macvpn-client -a control-token -w)"`
- [ ] `$BIN list` → csak a két engedélyezett kapcsolat (id, állapot, típus, név); egy engedélyezésből kivett kapcsolat azonnal eltűnik a listából
- [ ] **OpenVPN `up` MFA-val:** `$BIN hold <openvpn-id>` → `connecting`, majd `waiting_for_mfa`; a MacVPN a saját kódbekérő ablakát nyitja (a kliens nem látja a kérdést és a kódot); helyes kóddal `connected`; a menüben és a Kapcsolatok ablakban a kártyán „Használja: Remote Desktop teszt” / „Held by …”
- [ ] **A kliens kilép → a VPN lebomlik:** Ctrl-C (vagy Ctrl-D) a `hold`-ban → pár másodpercen belül `disconnected`, a menü szerint bontva; ugyanez `kill -9 <kliens pid>`-del (összeomlás)
- [ ] **Már fennálló kapcsolat fennmarad:** a WireGuard kapcsolatot a menüből felépítve `$BIN hold <wg-id>` → azonnal `connected`; Ctrl-C után a VPN fent marad, nincs „Használja” felirat
- [ ] Két `hold` ugyanarra a kapcsolatra (két terminál) → az első kilépése után fent marad, a második után lebomlik
- [ ] A felhasználó bontja a menüből a `hold` alatt → a kliens `disconnecting` / `disconnected` eseményt kap, kilép 1-es kóddal; a MacVPN nem csatlakozik újra
- [ ] Hitelesítő adat kell (mentett jelszó nélküli OpenVPN): `hold` → `waiting_for_credentials`; Mégse → `credentials_cancelled`
- [ ] Kilépés a MacVPN-ből `hold` alatt → a kilépési kérdés megnevezi az appot („Más appok is használják a MacVPN-en keresztül: …”); a kliens `closing` eseményt kap `app_quitting` okkal
- [ ] **Visszavonás:** `hold` alatt **Visszavonás** → megerősítés után a kliens kapcsolata azonnal megszakad, a csak általa felépített VPN lebomlik; utána `$BIN list` → `unauthorized` (kb. 1 s késleltetéssel); a lista üres, a Tevékenységben ott a visszavonás
- [ ] Útvonalváltás: a binárist máshová másolva (`cp $BIN /tmp/mcc && MACVPN_TOKEN=… /tmp/mcc list`) → `unauthorized`; az eredeti útvonalon újrafordítva működik
- [ ] **A beállítás kikapcsolása:** `hold` alatt a kapcsoló ki → a kliens `closing` (`disabled`) eseményt kap, a csak általa tartott VPN lebomlik; `ls ~/Library/Application\ Support/MacVPN/control/` → nincs `macvpn.sock`; `$BIN list` → hiba; visszakapcsolva a régi token újra működik
- [ ] Másik felhasználóként (`sudo -u <másik> …`) a socket nem érhető el
- [ ] Angol felülettel (`-AppleLanguages '(en)'`) a párosító ablak és a Párosított appok szövegei angolul

## 1.1: Dock ikon
- [ ] Indulás után (ablak nélkül) nincs Dock ikon, a Cmd+Tab listában sincs MacVPN
- [ ] Kapcsolatok / Rendszerállapot / Frissítés ablak megnyitása → megjelenik a Dock ikon, Cmd+Tabbal elérhető; az ikonra kattintva a nyitott ablak előjön (új ablak nem nyílik)
- [ ] Két ablak nyitva, az egyik bezárva → az ikon marad; az utolsó bezárásakor eltűnik; minimalizált ablakkal is helyes
- [ ] A kódbekérő, a hitelesítőadat-bekérő és a párosító ablak nem hoz elő Dock ikont, és nem lopja el a fókuszt
- [ ] Gyors egymás utáni nyitás/zárás után az ikon állapota a valóságot követi

## 1.1: kártyás felület
- [ ] Menü: minden kapcsolat kártya (típusbuborék, név, típus és állapot, kapcsoló: kapcsolódva zöld, csatlakozás közben borostyánsárga); a csempék (Új kapcsolat / Import…, Kapcsolatok kezelése…, Rendszerállapot), a lenyitható Beállítások csoport, a Súgó és a Kilépés működik; sok kapcsolatnál a lista görget, a menü nem lóg ki a képernyőről
- [ ] Világos és sötét módban is olvasható; „Mozgás csökkentése” mellett nincs animáció
- [ ] Kapcsolatok ablak, Rendszerállapot, Frissítés, kódbekérő: a kártyás megjelenés, a funkciók változatlanok; billentyűzettel (Tab) a fókuszkeret látszik

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
- [ ] **Kód a jelszó végén** (szerveroldalon jelszó+OTP-t váró RADIUS / LDAP): OpenVPN, IKEv2 (EAP), SSTP, L2TP, Cisco IPsec és egy rendszer-VPN mentett jelszóval; mindhárom elválasztóval (nincs, `,`, `:`); a kód nem kerül a széfbe (a kapcsolat adataiban csak `otp.enabled` / `otp.separator`)
- [ ] L2TP: a kód-beállítás puszta módosítása nem nyit új profilt jóváhagyásra
- [ ] SSTP: `"`-t tartalmazó kódnál hibaüzenet, nincs csatlakozás

## 1.1: hitelesítő adatok bekérése (valódi OpenVPN szerver kell)
- [ ] Valódi OpenVPN config `auth-user-pass` sorral (fájlnév és inline blokk nélkül), mentett felhasználónév és jelszó nélkül: csatlakozáskor „Hitelesítő adatok szükségesek” ablak csak a felhasználónév és jelszó mezővel; Csatlakozás, Mentés bepipálva → felépül; a következő csatlakozás már nem kérdez
- [ ] Rossz jelszó → egyszer újra kérdez a „Sikertelen bejelentkezés — ellenőrizd a felhasználónevet és a jelszót” sorral (a felhasználónév kitöltve) → helyes jelszóval felépül, és csak a helyes jelszó kerül a széfbe; második rossz jelszó → a szokásos hiba és értesítés, harmadik ablak nincs
- [ ] Mentés pipa nélkül → felépül, de a széfben nincs új mentett titok; legközelebb újra kérdez
- [ ] Mégse (és Escape, és az ablak bezárása) → nincs hiba, nincs értesítés; a sor „Nincs csatlakozva”
- [ ] Az ablak megjelenésekor egy másik appban gépelve a leütések ott maradnak; „…: hitelesítő adatok szükségesek” értesítés jön, rákattintva az ablak fókuszt kap; az első másodpercben a mezők tiltottak; Enter a mezőkben nem küld
- [ ] Bontás nyitott ablak mellett → az ablak bezárul, nincs `up`
- [ ] Vezérlő API kliens `up`-ja nyitott ablak mellett → `waiting_for_credentials` esemény; Mégse → `credentials_cancelled`
- [ ] Debug módban (`verb 5`) a naplóban nincs felhasználónév és jelszó
- [ ] Rendszer VPN (L2TP) mentett PSK nélkül → nincs ablak (a macOS profilja dönt)

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
- [ ] Frissítés után a macOS Keychain kérdése (ha megjelenik) a MacVPN nevét és útvonalát mutatja; „Mindig engedélyez" után nem kérdez újra

## Súgó és eltávolítás
- [ ] „Súgó" / „Help": ha a preferált nyelvek közül az első magyar vagy angol a magyar, a `user-guide.hu.md`-t, egyébként az `user-guide.en.md`-t nyitja meg a GitHubon
- [ ] Nyelv: `MacVPN.app/Contents/MacOS/MacVPN -AppleLanguages '(hu)'` → magyar felület (menü, ablakok, NSAlert-ek, értesítések, validátor-hibák); `'(en)'` → angol; `'(de)'` → angol; `'(de, hu)'` → magyar
- [ ] Nyelv, root oldal: magyar felülettel egy hibás config csatlakozásakor a hiba és a Napló `▶ [mvpn]` sorai magyarok, angol felülettel angolok
- [ ] „MacVPN eltávolítása…" aktív OpenVPN kapcsolattal → a kapcsolat lebomlik, a négy útvonal törlődik, a Homebrew csomagok megmaradnak
- [ ] Régi verzió `macvpn` szolgáltatású Keychain bejegyzései az első indításkor átkerülnek a `local.macvpn.secrets` szolgáltatásba, onnan az átköltöztetés a széfbe viszi őket (a régiek törlődnek); a mentett jelszavak megmaradnak
- [ ] A „felhasználói adatok" jelölővel törlődik az Application Support/MacVPN a széffel (`vault.db`, `vault.keys`; benne a rendszer VPN-ekhez mentett PSK/jelszó is), a Keychainből a széfkulcs (`local.macvpn.vault`) és a régi 1.1-es `local.macvpn.secrets` bejegyzések (írásvédett módban is), valamint a régi `macvpn` szolgáltatás `<UUID>.<mező>` maradékai; nélküle mind megmarad
- [ ] Az admin jelszókérés megszakítása → „Az eltávolítás megszakítva", semmi nem törlődik
- [ ] Bekapcsolt „Indítás bejelentkezéskor” mellett eltávolítás → a MacVPN eltűnik a Bejelentkezési elemek közül, a `~/Library/LaunchAgents/local.macvpn.launcher.plist` is törlődik; kikapcsolt állapotnál nincs változás

## Frissítés v1.0.0 → v1.1.0

Előpróba a kész appon (a kiadás előtt): az 1.0.0-s updater (`crates/platform-mac/src/update_installer.rs`, `verify_bundle` és `verify_app` a `v1.0.0` tagen) ugyanezeket nézi a csatolt DMG-ben:

```
hdiutil attach -nobrowse -readonly -mountpoint /tmp/macvpn-rc dist/MacVPN-1.1.0.dmg
A=/tmp/macvpn-rc/MacVPN.app
plutil -extract CFBundleIdentifier raw "$A/Contents/Info.plist"          # local.macvpn
plutil -extract CFBundleShortVersionString raw "$A/Contents/Info.plist"  # 1.1.0
codesign --verify --strict --deep --verbose=2 "$A"                        # valid on disk, satisfies its Designated Requirement
find "$A" -type l                                                         # üres: nincs symlink
codesign -dv "$A" 2>&1 | grep flags                                      # flags=0x10002(adhoc,runtime)
codesign -dv "$A/Contents/Resources/root/mvpn" 2>&1 | grep flags         # flags=0x10002(adhoc,runtime)
codesign -d --entitlements - --xml "$A" 2>/dev/null | wc -c               # 0: nincs entitlement
hdiutil detach /tmp/macvpn-rc
```

A `scripts/build-dmg.sh` kimenetében a „release gate (no debug-only code in the app binary)” lépés hiba nélkül fut le.

A valódi frissítés csak a közzététel után próbálható (az 1.0.0 a `releases/latest`-et kérdezi, és csak aláírt kiadást fogad el). Közvetlenül a `scripts/sign-release.sh v1.1.0` után, egy 1.0.0-s telepítésen:

- [ ] Előkészítés: `/Applications/MacVPN.app` az 1.0.0 (`defaults read /Applications/MacVPN.app/Contents/Info.plist CFBundleShortVersionString` → `1.0.0`), root réteg 7, legalább egy kapcsolat típusonként, egy kitűzött kapcsolat, egy rendszer VPN OTP-beállítással, bekapcsolt „Indítás bejelentkezéskor”; a 24 órás késleltetés kikapcsolva. Biztonsági mentés: `cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.0.0`
- [ ] 1.0.0 menü → „Frissítések keresése most” → „Frissítés elérhető: v1.1.0”; a Frissítés ablakban a kiadási jegyzet
- [ ] Egy aktív VPN kapcsolattal „Letöltés és telepítés” → a lépések után a kilépési kérdés; „fussanak tovább” → az 1.0.0 kilép, pár másodpercen belül az 1.1.0 indul, a futó kapcsolat aktívként látszik
- [ ] `defaults read /Applications/MacVPN.app/Contents/Info.plist CFBundleShortVersionString` → `1.1.0`; `codesign --verify --strict /Applications/MacVPN.app` sikeres; nincs `com.apple.quarantine`; az Applications mappában nincs `.MacVPN.app.update-*` / `.old-*`; `tail ~/Library/Caches/MacVPN/update.log` → `done`
- [ ] Keychain: a macOS egyszer rákérdezhet (új ad-hoc aláírás); „Mindig engedélyez” csak a `/Applications/MacVPN.app` MacVPN-nek; utána nincs újabb kérdés
- [ ] Adatok és beállítások megmaradtak (kapcsolatok, kitűzés, sorrend, OTP-beállítás, frissítési beállítások, „Indítás bejelentkezéskor”); a „Más appok vezérelhetik a VPN-eket” kikapcsolva indul
- [ ] Rendszerállapot: a root réteg zöld („Telepítve (verzió 7)”), nem kér admin jelszót
- [ ] Az új kártyás menü, a Dock ikon és a Párosított appok szakasz megjelenik; típusonként egy csatlakozás és bontás sikerül
- [ ] Hiba esetén: a segédscript visszaállítja a régi appot (`update.log`: „old app restored”); a kiadást azonnal vissza kell vonni, az 1.0.0 DMG kézzel újratelepíthető
