# MacVPN – kézi tesztlista

Előfeltétel: `scripts/build-dmg.sh` lefutott, `swift test` és `scripts/test-root.sh` zöld.

## Telepítés tiszta állapotból
- [ ] `sudo rm -rf /usr/local/libexec/macvpn /etc/sudoers.d/macvpn` (előző telepítés törlése)
- [ ] DMG megnyitása, MacVPN.app húzása az Applications mappába
- [ ] Első indítás: a Gatekeeper letiltja → Rendszerbeállítások → Adatvédelem és biztonság → „Megnyitás mindenképp"
- [ ] Megnyílik a Rendszerállapot ablak; a hiányzó eszközök listája helyes
- [ ] „Telepítés" → brew kimenet élőben, a végén zöld
- [ ] „Engedélyezés" → egy admin jelszókérés → zöld
- [ ] `sudo -n /usr/local/libexec/macvpn/mvpn status` jelszó nélkül `[]`
- [ ] A telepítő a `Contents/Resources/root/mvpn-validate` binárist is felmásolja, és a `sudo -n -u` alapú másolás rootként működik
- [ ] Régi/elakadt lock fájl (stale lock) nem blokkolja a telepítést vagy a műveleteket

## Kapcsolatok típusonként
- [ ] Export: mindegyik típus exportja → a fájlban nincs jelszó/PSK
- [ ] OpenVPN / WireGuard / strongSwan export visszaimportálva ugyanaz a config
- [ ] Natív (L2TP / Cisco) `.mobileconfig` export: Finderben dupla kattintás → macOS Profilok telepíti; MacVPN-be importálva érthető hibaüzenet („nem importálható… Finder…”), nem „Nem ismerhető fel a config típusa”
- [ ] OpenVPN: `.ovpn` import (külső ca fájllal is) → felhasználó/jelszó → csatlakozás → zöld, IP és uptime látszik → bontás
- [ ] OpenVPN DNS: csatlakozás után `scutil --dns` a szerver DNS-ét mutatja; bontás után visszaáll
- [ ] WireGuard: config import → csatlakozás → `wg show` az interfészt mutatja → bontás
- [ ] IKEv2: swanctl config + jelszó/PSK → csatlakozás → ESTABLISHED → bontás
- [ ] L2TP: új kapcsolat, űrlap kitöltése → profil jóváhagyása → csatlakozás → bontás
- [ ] Cisco IPsec: ugyanez csoportnévvel
- [ ] Meglévő `Office L2TP` rendszer VPN indítása és bontása a menüből

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
- [ ] Szűrő (Parancsok / Hibák), keresés, Másolás, Mentés… működik
- [ ] A naplóban sehol nem szerepel a jelszó vagy a PSK (`grep` a mentett naplóban)
- [ ] Az OpenVPN napló `verb 5` mellett sem tartalmazza a jelszót (`grep` a jelszóra a teljes naplóban és a root logfájlban)

## Hibák
- [ ] Rossz jelszó (OpenVPN) → piros ikon, értesítés „AUTH_FAILED", kattintásra Napló
- [ ] Elérhetetlen szerver → 30 mp után „Időtúllépés"
- [ ] `up /tmp/x` a configban → mentéskor piros hiba, nem ment
- [ ] Futó kapcsolat közben `sudo kill <openvpn pid>` → értesítés a megszakadásról

## Értesítések
- [ ] Az app előtérben (megnyitott ablakkal) is megjelennek az értesítések (csatlakozás, megszakadás, hiba)

## Életciklus
- [ ] Kilépés aktív kapcsolattal → kérdés; „fussanak tovább" → újraindítás után a kapcsolat aktívként jelenik meg
- [ ] Kilépés aktív rendszer VPN-nel (pl. `Office L2TP`) → helyes kérdés, a rendszer VPN nem bomlik meg indokolatlanul
- [ ] Az ablak bezárása után (delegate visszaállítás) az ablak a menüből újra megnyitható, és megfelelően működik
- [ ] `brew install` futása közben az ablak bezárása → a telepítés tovább fut, újranyitva a kimenet és az állapot helyes
- [ ] Alvás/ébredés után az állapot frissül
- [ ] Két kapcsolat egyszerre aktív (pl. WireGuard + IKEv2)

## Frissítés
- [ ] Régebbi verzió (pl. `0.0.1`-re állított `CFBundleShortVersionString`) a `/Applications`-ben → induláskor „Frissítés elérhető: vX.Y.Z" sor a menüben
- [ ] Az ablakban a release notes látszik; „Letöltés és telepítés" → lépések kijelezve, kilépés, csere, az új verzió újraindul, a quarantine attribútum nincs rajta
- [ ] Aktív kapcsolat / nem mentett szerkesztés mellett a telepítés ugyanazt kérdezi, mint a kilépés; „Mégse" → nincs kilépés, a DMG leválasztva
- [ ] Nem írható helyről (pl. App Translocation, a DMG-ről indítva) futó app → hibaüzenet, nincs jogosultság-emelés
- [ ] „Frissítések keresése most" naprakész appal → „A MacVPN naprakész"; hálózat nélkül → hibaüzenet
- [ ] „Frissítések automatikus keresése" kikapcsolva → induláskor nincs ellenőrzés; `swift run` alatt a frissítés menüpontok nem látszanak
- [ ] `~/Library/Caches/MacVPN/update.log` tartalmazza a csere lépéseit, a segédscript könyvtára törlődött

## Súgó és eltávolítás
- [ ] „Súgó" / „Help": ha a preferált nyelvek közül az első magyar vagy angol a magyar, a `user-guide.hu.md`-t, egyébként az `user-guide.en.md`-t nyitja meg a GitHubon
- [ ] Nyelv: `MacVPN.app/Contents/MacOS/MacVPN -AppleLanguages '(hu)'` → magyar felület (menü, ablakok, NSAlert-ek, értesítések, validátor-hibák); `'(en)'` → angol; `'(de)'` → angol; `'(de, hu)'` → magyar
- [ ] Nyelv, root oldal: magyar felülettel egy hibás config csatlakozásakor a hiba és a Napló `▶ [mvpn]` sorai magyarok, angol felülettel angolok
- [ ] „MacVPN eltávolítása…" aktív OpenVPN kapcsolattal → a kapcsolat lebomlik, a négy útvonal törlődik, a Homebrew csomagok megmaradnak
- [ ] A „felhasználói adatok" jelölővel az Application Support/MacVPN és a Keychain `macvpn` bejegyzései is törlődnek; nélküle megmaradnak
- [ ] Az admin jelszókérés megszakítása → „Az eltávolítás megszakítva", semmi nem törlődik
