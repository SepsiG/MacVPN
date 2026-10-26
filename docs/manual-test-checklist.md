# MacVPN és WinVPN 2.0.0 – kézi tesztlista

A kiadás utáni kézi ellenőrzések a MacVPN 2.0.0-hoz (macOS) és a WinVPN 2.0.0-hoz (Windows), a kiadott `MacVPN-2.0.0.dmg`-vel és `WinVPN-2.0.0-x64.msi`-vel. Ami eltér, az hiba: a javító feladatával együtt jegyezd fel. Az elvárt eredmény a „→” után áll. A PowerShell-parancsokban mindig a teljes `.exe` nevet írd (`sc.exe`, `reg.exe`, `icacls.exe`, `certutil.exe`, `msiexec.exe`, `pnputil.exe`, `rasdial.exe`, `cmdkey.exe`): PowerShellben az `sc` a `Set-Content` álneve. A példahálózatok: 10.20.30.0/24 (egy „irodai” hálózat) és a VPN-labor címei (a szolgáltatások: 10.99.0.0/24, a kliensek: 10.99.11.0–10.99.17.0/24); valódi címet ne írj a jegyzetekbe.

Ami a kiadás előtt már automatikusan lefutott, azt itt nem kell megismételni: a CI (`.github/workflows/ci.yml`: `cargo test --workspace` macOS-en és Windowson, `scripts/test-root.sh`, `scripts/test-sign-release.sh`, `cd app/ui && npm test`, a `msi` és a `windows-admin` job), a kiadás előtti helyi ellenőrzések (`docs/RELEASING.md`, 2. lépés: a smoke teszt mindkét nyelven a Macen és Windowson, `scripts/check-windows.sh`, `node scripts/l10n-baseline.mjs --check`) és a kiadási workflow ellenőrzései (a csomag azonosítója, verziója, aláírása; a release gate-ek). Az ezekkel lefedett pontoknál „(automatikus: …)” áll; ezeket csak akkor futtasd kézzel, ha valami gyanús.

Részek: a 2.0.0 új funkciói (mindkét termék), a VPN-labor, a MacVPN a laborral, a WinVPN (szolgáltatás és Homebrew-mentes motorok; natív VPN-ek; alapok), a MacVPN korábbi funkcióinak regressziója, végül a frissítés régebbi MacVPN-ről.

## 2.0.0 – új funkciók (mindkét termék)

A 2.0.0 négy új funkciója (megjelenés, kapcsolatértesítések, hiányzó motorok, automatikus újracsatlakozás; a terv: `docs/superpowers/plans/2026-10-25-features-2-0.md`), a macOS DNS-kezelő, a naplóméret-korlát (macOS: 5 MiB, Windows: 8 MiB) és a motorfrissítések. A macOS-es strongSwan-javítások (F1, F2) a „MacVPN a laborral” részben vannak. A funkciók mindkét terméket érintik: ahol nincs „macOS:” vagy „Windows:” jelölés, ott mindkettőn ellenőrizd. A smoke teszt (`scripts/smoke/appearance.js`, `notices.js`, `engines.js`, `reconnect.js`) ezek felületét modellezett állapotokkal már ellenőrizte; itt a valódi rendszer viselkedése a kérdés.

Előfeltétel: a Macen a 2.0.0-s DMG-ből telepített MacVPN, a Windows-gépen a kiadott `WinVPN-2.0.0-x64.msi` telepítve (a tesztek asztali bejelentkezéssel, nem SSH-n). Kell egy „Office VPN” nevű OpenVPN-kapcsolat jelszóval, amely a `route 10.20.30.0 255.255.255.0` sorral a 10.20.30.0/24 „irodai” hálózatot vezeti a VPN-be, egy WireGuard-kapcsolat `DNS =` sorral, egy SSTP- vagy IKEv2-kapcsolat, és egy második router (vagy egy hálózat), amely a 10.20.30.0/24-ből ad címet (az „iroda”), valamint egy másik Wi-Fi vagy telefonos hotspot (a „kávézó”). A teszt-VPN-ekhez a labor használható (lásd „A VPN-labor előkészítése”). Windows **build száma: ___**, macOS **verzió: ___**

### Megjelenés

- [ ] Nyitva a popover, a Kapcsolatok, a Rendszerállapot és egy MFA kódbekérő ablak (például a labor `openvpn-static-challenge.ovpn` kapcsolatával); **Beállítások → Megjelenés → Sötét** → mind egyszerre sötét lesz, Windowson a címsorok is
- [ ] Ugyanígy **Világos** → mind egyszerre világos; **Rendszer szerint** → mind a rendszer módját veszi fel
- [ ] Kilépés és újraindítás után a választott mód megmarad (a popover és az elsőként megnyitott ablak is ebben jelenik meg)
- [ ] **Rendszer szerint** mellett a rendszer módjának átváltása futás közben (macOS: Rendszerbeállítások → Megjelenés; Windows: Gépház → Személyre szabás → Színek → Alapértelmezett alkalmazásmód) → a nyitott ablakok és a popover azonnal követik
- [ ] A mód váltása után először megnyitott ablak (például a Rendszerállapot, ha addig nem volt nyitva) már az új módban nyílik
- [ ] Windows: **Sötét** módban világos Windowson a fájlválasztó ablak (Import fájlból…) és a rendszergazdai megerősítés világos marad (ismert korlát), az értesítési terület ikonja a tálca színét követi

### Kapcsolatértesítések

- [ ] Az „Office VPN” csatlakoztatása → értesítés „Office VPN: csatlakozva” (angolul „Office VPN connected”), a szövegben „Kattints a naplóért.”
- [ ] A WinVPN/MacVPN indulásakor már élő kapcsolatról nem jön „csatlakozva” értesítés
- [ ] macOS: élő OpenVPN-kapcsolatnál `sudo pkill -f 'openvpn.*<azonosító>'`; Windows: a labor OpenVPN-szerverének leállítása (vagy a hálózati kábel kihúzása) → „Office VPN: megszakadt a kapcsolat”, alatta „A szerver nem válaszol.” (vagy „Kattints a naplóért.”)
- [ ] Kattintás az értesítésre → a Kapcsolatok ablak a kapcsolat **Napló** fülén nyílik meg
- [ ] Rossz jelszóval csatlakozva → „Office VPN: sikertelen csatlakozás”, alatta „A szerver elutasította a bejelentkezést.”
- [ ] A saját **Bontás** és a „Leállítás és kilépés” → nincs értesítés
- [ ] **Beállítások → Kapcsolatértesítések** ki → a fenti esetek egyikénél sem jön értesítés; egy MFA-kapcsolat „…: hitelesítés szükséges” értesítése továbbra is megjelenik; visszakapcsolva újra jönnek
- [ ] A zárolási képernyőn (macOS: lezárt képernyő; Windows: Win+L) megjelenő értesítésben nincs szervernév, cím vagy felhasználónév, csak a kapcsolat neve és az általános ok
- [ ] Zárolt széf mellett megszakadó kapcsolat → a cím általános: „Egy VPN-kapcsolat megszakadt”, a kapcsolat neve nem látszik
- [ ] Windows: a telepített MSI-ből (Start menüből) indított WinVPN értesítése megjelenik (fejlesztői buildből nem jön értesítés), és a rá kattintás futó WinVPN mellett a Napló fület nyitja

### Hiányzó motorok

- [ ] macOS: `brew uninstall sstp-client` → az SSTP-kapcsolatok a popoverben, a Kapcsolatok listájában és a részleteknél szürkék, „SSTP · Nincs telepítve: sstp-client – Rendszerállapot” felirattal; a kapcsoló és a **Csatlakozás** gomb tiltott
- [ ] macOS: a sorban a **Rendszerállapot** linkre kattintva megnyílik a Rendszerállapot ablak (a listában a sor nem lesz kijelölve, és nem indul húzás)
- [ ] macOS: a Kapcsolatok ablak **Új** menüjében nincs SSTP; egy `.sstp` fájl importja (**Import fájlból…**) → „<fájl>: A(z) sstp-client nincs telepítve. Előbb telepítsd a Rendszerállapot ablakban.”, semmi nem mentődik; az ablakra ejtve és a Finderből megnyitva is ugyanez; egy `.sstp` és egy `.ovpn` együttes importjánál az `.ovpn` bekerül
- [ ] macOS: `brew install sstp-client` a Terminálban, utána a popover megnyitása → egy percen belül az SSTP-sorok normálak, **Újraellenőrzés** nélkül
- [ ] macOS: Homebrew nélküli gépen vagy tesztfiókban (ha van ilyen) → minden Homebrew-s típus sora „Nincs telepítve: Homebrew – Rendszerállapot”, az L2TP és a Cisco IPsec kapcsolatok használhatók; ha egyik Homebrew-s típus sem használható, az **Új** menü csak a használható típusokat mutatja
- [ ] Windows: az OpenVPN Community eltávolítva (Gépház → Alkalmazások → Telepített alkalmazások) → az OpenVPN-sorok „Nincs telepítve: OpenVPN Community – Rendszerállapot”, a WireGuard-sorok normálak; az **Új** menüben nincs OpenVPN; egy `.ovpn` importja elutasítva a szöveggel
- [ ] Windows: a szolgáltatás leállítva (rendszergazdai PowerShell: `sc.exe stop WinVPN`) → minden sor a szolgáltatás szövegét mutatja („A WinVPN szolgáltatás nem érhető el.”); `sc.exe start WinVPN` és a popover újranyitása → egy percen belül a sorok normálak
- [ ] Windows: OpenVPN Community nélkül indítva a WinVPN-t → a Rendszerállapot **nem** nyílik meg magától, a popover Rendszerállapot-csempéjén nincs „!” (az OpenVPN választható motor); a WinVPN szolgáltatás nélkül (`sc.exe stop WinVPN`, majd a WinVPN újraindítása) → a Rendszerállapot magától megnyílik, a csempén „!”; `sc.exe start WinVPN`
- [ ] Egy csapatkatalógus, amelyben OpenVPN-kapcsolat van, hiányzó OpenVPN mellett is szinkronizál, a kapcsolat szürkén látszik; az OpenVPN telepítése után új szinkronizálás nélkül csatlakozik

### Automatikus újracsatlakozás

- [ ] Egy MacVPN-ben/WinVPN-ben létrehozott kapcsolat részleteinél (Kapcsolatok ablak) ott az **Automatikus újracsatlakozás** kapcsoló, alapból bekapcsolva; rendszer VPN-nél nincs ilyen kapcsoló
- [ ] A kikapcsolt állapot kilépés és újraindítás után megmarad; a kapcsolat törlése és ugyanannak a fájlnak az újraimportálása után a kapcsoló ismét be van kapcsolva
- [ ] (a) Otthoni Wi-Fin egy SSTP- vagy IKEv2-kapcsolat él, a fedél 2 percre lecsukva, majd felnyitva → néhány másodpercen belül „…: újracsatlakozva”
- [ ] (b) Ugyanez, de a fedelet egy másik Wi-Fin vagy telefonos hotspoton nyitod fel → nem csatlakozik újra, „…: nem csatlakozott újra”, alatta „Másik hálózaton vagy.”
- [ ] (c) Az „Office VPN” otthonról felépítve, a fedél lecsukva, a gép az „irodában” (a 10.20.30.0/24-et adó második routeren) felnyitva, ha a kapcsolat közben megszakadt → nem csatlakozik újra, „A VPN hálózata itt közvetlenül elérhető.” (az elérhetőségi ellenőrzés megelőzi a hálózat összevetését); ha a kapcsolat túlélte az alvást, az (f2) szerint bomlik
- [ ] (c2) Ugyanazon a hálózaton egy WireGuard-kapcsolat, amelynek `DNS =` sora a helyi router címére mutat: csatlakoztatva, fedél lecsukva, a kapcsolat alvás közben megszakad (például a labor WireGuard-szervere leállítva), felnyitva → „…: nem csatlakozott újra”, alatta „A VPN DNS-szervere itt közvetlenül elérhető.”
- [ ] (d) Kézi **Bontás**, alvás, ébresztés → a kapcsolat bontva marad, nincs értesítés
- [ ] (e) A kapcsolat **Automatikus újracsatlakozás** kapcsolója kikapcsolva, a kapcsolat alvás közben megszakad → nincs újracsatlakozás
- [ ] (f) OpenVPN `ping-restart`-tal (a labor OpenVPN-kapcsolata): 30 másodperc alvás, ébresztés → a kapcsolat végig „Csatlakozva”, nincs értesítés, a naplóban az OpenVPN saját újraindulása (`Inactivity timeout (--ping-restart)` vagy `Restart pause`)
- [ ] (f2) A 10.20.30.0/24-et route-oló WireGuard- vagy OpenVPN-kapcsolat otthon felépítve, a fedél lecsukva, a 10.20.30.0/24-es hálózaton („iroda”, vagy a második router) felnyitva → néhány másodpercen belül bontva, „…: megszakadt a kapcsolat”, alatta „A VPN hálózata itt közvetlenül elérhető, ezért a kapcsolat bontva lett.”; utána otthon egy újabb alvás után is bontva marad, amíg kézzel nem csatlakoztatod
- [ ] (f3) Ugyanez a kapcsolat egy „kávézóban” (másik Wi-Fi vagy telefonos hotspot) felnyitva → csatlakozva marad, nincs értesítés
- [ ] (g) Az Ethernet-kábel 20 másodpercre kihúzva egy olyan kapcsolattal, amely ettől megszakad → a kábel visszadugása után néhány másodpercen belül „…: újracsatlakozva”
- [ ] (h) Windows: Modern Standby laptopon (csak ha van ilyen gép), különben a VM alvó állapotával: ugyanaz, mint (a)
- [ ] Zárolt széffel ébresztve (macOS: **Széf zárolása most** alvás előtt) → „…: nem csatlakozott újra”, alatta „Az újracsatlakozáshoz oldd fel a széfet.”
- [ ] Egyszer használatos kódos (MFA) kapcsolat újracsatlakozásakor a kódbekérő ablak újra megjelenik; **Mégse** → nincs további próbálkozás és nincs „nem sikerült újracsatlakozni” értesítés
- [ ] Wi-Fin a hálózati próba élő futtatása (csak olvas) → az átjáró címe és MAC-je látszik; az SSID csak helymeghatározási engedéllyel, különben üres (akkor a MAC dönt). macOS: `cargo test --locked -p macvpn-platform-mac --test net_probe live_snapshot_of_this_mac -- --ignored --nocapture`; Windows (a laptopon, Git Bashben): `cargo test --locked -p macvpn-platform-win --test windows probe_the_network_snapshot -- --ignored --nocapture`
- [ ] Windows: Modern Standby gépen (csak ha van ilyen gép) az alvás és az ébredés után az (a) eset működik; ha nem, jegyezd fel, hogy a Wi-Fi visszatérése (hálózatváltás) indította-e az újracsatlakozást

### DNS-visszaállítás (macOS)

- [ ] OpenVPN DNS-sel: csatlakozás → `scutil --dns` és `networksetup -getdnsservers Wi-Fi` a VPN DNS-ét mutatja, a naplóban „DNS set and verified on … network service(s)”; `sudo ls -l /var/db/macvpn/dns/` → a `ledger` fájl root tulajdonú, `-rw-------`, a mappa `drwx------`
- [ ] Bontás → a DNS az eredeti (`networksetup -getdnsservers Wi-Fi` ugyanaz, mint csatlakozás előtt), a naplóban „original DNS restored and verified”, a `ledger` eltűnt
- [ ] WireGuard `DNS =` sorral ugyanígy: csatlakozáskor a VPN DNS-e, bontáskor az eredeti, mindkettő ellenőrizve a naplóban
- [ ] Két kapcsolat, A (OpenVPN) majd B (WireGuard), mindkettő DNS-sel: B DNS-e érvényes; A bontása → B DNS-e marad; B bontása → az eredeti DNS
- [ ] Fordított sorrend: A, majd B, B bontása → A DNS-e jön vissza; A bontása → az eredeti DNS
- [ ] Újraindítás kapcsolódás közben (**Kilépés, fussanak tovább**, majd az Apple-menü → Újraindítás): bejelentkezés és a MacVPN indítása után → a DNS az eredeti, a `ledger` eltűnt
- [ ] `kill -9`: élő OpenVPN-kapcsolatnál `sudo pkill -9 -f 'openvpn.*<azonosító>'` → néhány másodpercen belül (a következő állapotlekérdezéskor) az eredeti DNS, a naplóban „original DNS restored and verified”; WireGuardnál `sudo pkill -9 wireguard-go` ugyanígy
- [ ] Ha egy régebbi verzió VPN-DNS-t hagyott beállítva (ha előfordult): a Rendszerbeállítások → Hálózat → a szolgáltatás → Részletek… → DNS alatt kézzel visszaállítva → a weboldalak VPN nélkül megnyílnak; a 2.0 ezután nem hagy maradványt

### Naplóméret-korlát

- [ ] macOS: élő OpenVPN-kapcsolatnál `ps -ww -o args= -p $(pgrep -x openvpn)` → a parancssorban `--mute 20` a `--config` után
- [ ] macOS: élő kapcsolat naplóját mesterségesen 5 MiB fölé növelve (`sudo sh -c 'head -c 6000000 /dev/zero | tr "\0" "x" | fold -w 100 >> /var/log/macvpn/<azonosító>.log'`) → a következő állapotlekérdezés után `ls -l /var/log/macvpn/<azonosító>.log*`: a `.log` kicsi, a `.log.1` legfeljebb 5 MiB; a kapcsolat él, a Napló fül tovább követi
- [ ] macOS: egy régebbi verzióból maradt, 5 MiB-nál nagyobb `<azonosító>.log.1` a kapcsolat következő csatlakozásakor vagy bontásakor 5 MiB-ra rövidül
- [ ] Windows: élő OpenVPN-kapcsolatnál rendszergazdai PowerShellben `Get-CimInstance Win32_Process -Filter "Name='openvpn.exe'" | Select-Object -ExpandProperty CommandLine` → benne `--mute 20`
- [ ] Windows: hosszú, hibakereső módú OpenVPN-kapcsolat, amíg a napló eléri a 8 MiB-ot (`Get-Item C:\ProgramData\WinVPN\logs\<AZONOSÍTÓ>.log`) → megjelenik az `<AZONOSÍTÓ>.log.1`, az új napló első sora erről szól, a Napló fül elölről indul; a kapcsolat újbóli csatlakoztatása után a `.log.1` eltűnik

### Motorfrissítések

- [ ] macOS: ha `brew outdated openvpn wireguard-tools strongswan sstp-client bash` listáz valamit (ha nincs elavult csomag: **nem tesztelhető**) → a Rendszerállapot VPN-eszközök sora zöld marad, „openvpn: Frissítés elérhető: x → y”, és **Frissítés** gombot mutat; a gomb csak ezekre fut `brew upgrade`-et, a kimenet élőben; utána a sor ajánlat nélkül zöld
- [ ] macOS: napi `brew update`: a MacVPN indítása után kb. egy perccel `defaults read local.macvpn lastBrewUpdate` friss időt mutat; 24 órán belüli újraindításkor nem fut újra (az érték nem változik); `defaults delete local.macvpn lastBrewUpdate` és újraindítás után kb. egy perccel újra lefut
- [ ] macOS: hálózat nélkül indítva a `brew update` nem okoz hibasort a Rendszerállapotban; a hálózat visszatérése után legkésőbb egy órán belül lefut
- [ ] Windows: a Rendszerállapot megnyitása után néhány másodperccel a WireGuard-sor „wireguard-nt 1.1.0” ajánlat nélkül (ha az 1.1 a legújabb), az OpenVPN-sor a winget vagy a hivatalos oldal ajánlatát mutatja, ha van újabb
- [ ] Windows (rendszergazdai PowerShell): a Rendszerállapot megnyitása után a `C:\ProgramData\WinVPN\engines\wireguard-nt` mappa létezik és üres; `icacls.exe C:\ProgramData\WinVPN\engines\wireguard-nt` → csak SYSTEM és Administrators, védett; a `service.log`-ban nincs „wireguard-nt check:” sor
- [ ] Windows: hálózat nélkül a Rendszerállapotban nincs hibasor és nincs **Frissítés**; a `service.log`-ban egy „wireguard-nt check: the listing: …” sor
- [ ] Windows (ha megjelent újabb wireguard-nt): **Frissítés** élő WireGuard-kapcsolat mellett → „A wireguard-nt csak akkor frissíthető, ha ezen a gépen nincs élő WireGuard-kapcsolat. …”; bontás után → „A(z) <v> wireguard-nt telepítve.”, a sor `<v>`-t mutat, `Get-AuthenticodeSignature C:\ProgramData\WinVPN\engines\wireguard-nt\wireguard.dll` → WireGuard LLC, egy WireGuard-kapcsolat működik; `sc.exe stop WinVPN`, `sc.exe start WinVPN` → a sor továbbra is `<v>`, a `service.log`-ban „wireguard.dll <v> loaded (downloaded)”
- [ ] Windows (ha a rögzítettnél újabb OpenVPN jelent meg, és a winget nem kínál újabbat): **Frissítés** → az `OpenVPN-<új>-I<nnn>-amd64.msi` a `%LOCALAPPDATA%\WinVPN\downloads` mappába töltődik, egy UAC-kérdés, az msiexec telepíti, utána a sor zöld az új verzióval

### Frissítés 1.5 → 2.0 (macOS)

- [ ] Az 1.5.0-ról a 2.0.0-ra frissítve a Rendszerállapot „Frissítés szükséges (8 → 9)” sort mutat; addig az OpenVPN-, WireGuard-, IKEv2- és SSTP-sorok „Nem használható: Jogosultság (root scriptek + sudoers) – Rendszerállapot”; **Engedélyezés** és egy admin jelszó után minden sor normál
- [ ] A frissítés után a **Kapcsolatértesítések** be van kapcsolva, a **Megjelenés** „Rendszer szerint”, minden kapcsolatnál az **Automatikus újracsatlakozás** be van kapcsolva; a széf, a kapcsolatok és a mappák változatlanok
- [ ] (automatikus: a kiadás előtti `node scripts/l10n-baseline.mjs --check`, `docs/RELEASING.md` 2. lépés) egyetlen régi macOS-szöveg sem változott

## A VPN-labor előkészítése

A labor a Macen fut (Dockerrel), a kézikönyve a `scripts/vpn-lab/README.md`. A szolgáltatásai a 10.99.0.0/24-ben vannak (a weboldal: 10.99.0.10), a kliensek a 10.99.11–17.x címeket kapják; az összes jelszó, a PSK, a csoportnév és az egyszeri kód a `scripts/vpn-lab/.state/client/CREDENTIALS.txt`-ben van. A WinVPN részeinek előkészítése a Windows-gépre másolja a profilokat.

- [ ] Docker Desktop fut; a Mac LAN-címe: `ipconfig getifaddr en0`; `scripts/vpn-lab/up.sh --bind <LAN-cím>` → „lab up on …”; `scripts/vpn-lab/check.sh --selftest` → minden sor `ok` (macOS-en az „UDP …:500 from this Mac itself” sor lehet `info`), a végén `0 failed` mindhárom blokkban
- [ ] Ha a macOS tűzfala megkérdezi, a Docker bejövő kapcsolatai engedélyezve
- [ ] A Windows-profilok a teszt-gépen: `scp -r scripts/vpn-lab/.state/client/windows "$WINVPN_SSH":lab-client` (a jelszavak, a PSK, a csoportnév és az egyszeri kód a `scripts/vpn-lab/.state/client/CREDENTIALS.txt`-ben vannak; azt ne másold át)
- [ ] A teszt-gépen böngészőben a `http://<a Mac LAN-címe>:8081/ca.crl` letölthető (a CRL; az SSTP visszavonás-ellenőrzéséhez kell)
- [ ] Minden csatlakozás után ellenőrizhető: böngészőben `http://10.99.0.10/` → „MacVPN lab: OK” és „via: …”; `nslookup whoami.lab.test` → `10.99.0.10` (L2TP-nél és SSTP-nél a DNS-szerver az átjáró: `nslookup whoami.lab.test 10.99.16.1`, illetve `10.99.17.1`). „Minden forgalom a VPN-en” bekapcsolva a labor nem ad internetet (szándékos)

## MacVPN a laborral (macOS)

A laborgépen (a Macen) futó laborral az OpenVPN, a WireGuard, az SSTP és (a 4510-es porton) az IKEv2 tesztelhető; az L2TP és a Cisco IPsec csak más gépen futó laborral (a macOS saját IKE-szolgáltatása az 500/4500-as portot használja, amit a Docker foglal) — ugyanezek a szkriptek egy LAN-on lévő Linux gépen (Dockerrel) vagy egy másik Macen futnak. A profilok: `scripts/vpn-lab/.state/client/macos/`. A részletes lépések (F1 és F2 is) a 2c terv (`docs/superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md`) „MacVPN a laborral” szakaszában vannak. F1: a Homebrew `etc/swanctl` mappáiban lévő CA, tanúsítványok és kulcsok minden csatlakozáskor betöltődnek; F2: két IKEv2-kapcsolat egyszerre nem tölti ki egymást.

- [ ] **OpenVPN:** `openvpn-tun-dco.ovpn` (`labuser` + jelszó) → csatlakozik, `http://10.99.0.10/` → „via: openvpn”, `http://whoami.lab.test/` is betölt; `openvpn-tun-cbc.ovpn` → csatlakozik; `openvpn-static-challenge.ovpn` `labotp`-vel → a kódablak csatlakozás előtt jön; `openvpn-tun-dco.ovpn` `labotp`-vel → a kódablak csatlakozás közben jön (CRV1); rossz jelszóval → `AUTH_FAILED`
- [ ] **WireGuard:** `wireguard-macos.conf` → csatlakozik, „via: wireguard”
- [ ] **SSTP:** `sstp-ca.sstp` és `sstp-ca-alt-port.sstp` → csatlakozik; `sstp-system-ca.sstp` → tanúsítványhiba (elvárt: a Homebrew OpenSSL nem ismeri a labor CA-ját); `sstp-no-verification.sstp` → piros figyelmeztetéssel csatlakozik
- [ ] **IKEv2 (F1):** a labor szabványos IKE-portok nélkül (`up.sh --bind <LAN-cím> --no-ike-standard-ports`), a labor CA-ja, kliens-tanúsítványa és kulcsa a `$(brew --prefix)/etc/swanctl/` alatt → PSK, EAP és tanúsítvány elsőre csatlakozik `sudo swanctl --load-creds` nélkül; a CA elvétele után az EAP nem csatlakozik, visszatéve igen
- [ ] **Két IKEv2 egyszerre (F2):** a PSK és az EAP kapcsolat egyszerre „Csatlakozva”, `sudo swanctl --rekey --ike lab-psk --reauth` mindkét állapotban sikerül; az ütköző nevű másolat „Egy másik aktív strongSwan-kapcsolat már definiálja ezt: connections.lab-psk” üzenettel nem csatlakozik
- [ ] **L2TP és Cisco IPsec** (más gépen futó laborral): a `l2tp.txt` / `cisco-ipsec.txt` értékeivel **Mentés és profil telepítése** → jóváhagyás → csatlakozik, „via: ipsec”; `labotp`-vel és kódkiegészítéssel is
- [ ] **Takarítás:** a laborprofilok törlése a MacVPN-ből (L2TP/Cisco profilok a Rendszerbeállítások → Általános → Eszközkezelés alatt), a `$(brew --prefix)/etc/swanctl/` labor-fájljai törölve, `scripts/vpn-lab/down.sh`

## WinVPN: a szolgáltatás, OpenVPN, WireGuard, frissítés

A WinVPN szolgáltatás, az OpenVPN, a WireGuard, a frissítés és a HTTPS-katalógusok (a terv: `docs/superpowers/plans/2026-10-22-winvpn-2b-service-openvpn-wireguard.md`; a fejlesztés közbeni CP1 és CP2 lefutott, lásd a terv „CP1 result” és „CP2 result” jegyzetét; az ott elmaradt pontok itt **(CP1-ből)** jelöltek).

Előfeltétel: a kiadott `WinVPN-2.0.0-x64.msi`; egy rendszergazdai fiók, egy normál fiók (asztali bejelentkezéssel, nem SSH-n) és egy második normál fiók; a VPN-labor OpenVPN- és WireGuard-profiljai (lásd „A VPN-labor előkészítése”). Windows **build száma: ___**

### Telepítés és szolgáltatás (rendszergazda)

- [ ] A 2.0.0-s MSI a korábbi WinVPN (1.5.0) fölé telepítve → frissít, nem második példány; a széf és a kapcsolatok megmaradnak
- [ ] `sc.exe qc WinVPN` → `SERVICE_START_NAME : LocalSystem`, `START_TYPE : 2 AUTO_START`, `BINARY_PATH_NAME : "C:\Program Files\WinVPN\WinVPNService.exe" service`; `sc.exe query WinVPN` → `RUNNING`
- [ ] `sc.exe qfailure WinVPN` → `RESET_PERIOD 86400`, `RESTART -- Delay = 5000` és `30000`; `sc.exe qfailureflag WinVPN` → TRUE; a `C:\ProgramData\WinVPN\service.log`-ban nincs „cannot set the recovery actions” sor
- [ ] `icacls.exe C:\ProgramData\WinVPN` → csak SYSTEM és Administrators, védett (öröklés nélkül)
- [ ] A `C:\Program Files\WinVPN` tartalma: `WinVPN.exe`, `WinVPNService.exe`, `wireguard.dll`, `THIRD-PARTY-NOTICES.txt`; `Get-AuthenticodeSignature "C:\Program Files\WinVPN\wireguard.dll"` → `Valid`, WireGuard LLC
- [ ] `icacls.exe "C:\Program Files\WinVPN"` → védett (egyik sor sem `(I)`): SYSTEM és Administrators `(OI)(CI)(F)`, Users, Authenticated Users és a két „ALL … APPLICATION PACKAGES” csoport `(OI)(CI)(RX)`, más nincs; `icacls.exe "C:\Program Files\WinVPN\WinVPNService.exe"` → ugyanezek `(I)`-vel (biztonsági áttekintés 2. rész, P2-M2)
- [ ] `msiexec.exe /i WinVPN-2.0.0-x64.msi INSTALLDIR=C:\WinVPN` (és a grafikus telepítő) → mappaválasztó nincs (Üdvözlő → Kész), a WinVPN mégis a `C:\Program Files\WinVPN` alá kerül, `C:\WinVPN` nem jön létre
- [ ] Ugyanaz a 2.0.0-s MSI újra → lefut (azonos verzió frissítésként, P2-L2). Visszaléptetés: a tiltást a telepítendő csomag hordozza, ezért csak a 2.0.0-tól kiadott MSI-k tagadják meg; ha már van újabb kiadás (2.0.1+), a 2.0.0-s MSI fölötte → „A newer version of WinVPN is already installed.”, semmi nem változik (ha nincs: **nem tesztelhető**). Az 1.x MSI-k (még `AllowDowngrades`) továbbra is visszaléptetnének: ezeket ne kínáld letöltésre
- [ ] `icacls.exe "C:\Program Files\WinVPN" /grant "*S-1-5-32-545:(OI)(CI)M"`, majd `sc.exe stop WinVPN`, `sc.exe start WinVPN` → nem indul; a `C:\ProgramData\WinVPN\service.log` utolsó sora „refusing to start: C:\Program Files\WinVPN\WinVPNService.exe is not admin-only …”; a 2.0.0-s MSI újratelepítése visszaállítja a jogosultságokat, a szolgáltatás fut
- [ ] Élő OpenVPN-kapcsolat mellett `sc.exe stop WinVPN` → az alagút és az `openvpn.exe` eltűnik (Feladatkezelő); `sc.exe start WinVPN` → az app a kapcsolatot megszakadtként mutatja
- [ ] Egy normál felhasználó által a telepítés **előtt** létrehozott `C:\ProgramData\WinVPN` (saját jogosultságokkal) → a szolgáltatás nem javítja; a Rendszerállapot „A(z) … mappa jogosultságai nem biztonságosak…” szöveget mutat, az OpenVPN/WireGuard kapcsolódás ezzel tér vissza; a rendszergazda törli a mappát, `sc.exe stop WinVPN`, `sc.exe start WinVPN` → rendben

### Az admin teszthalmaz

- [ ] (automatikus: CI `windows-admin` job, a telepített x64 MSI-vel; kézzel csak ha az a job nem volt zöld) Emelt Git Bashben a 2.0.0-s forrással: `cargo test --locked -p macvpn-helper --test service_admin --test wireguard_admin --test openvpn_installed --test openvpn_e2e -- --ignored --test-threads=1` és `cargo test --locked -p macvpn-winsys --test service_pipe --test cert_store_admin -- --ignored` → mind zöld (a `cert_store_admin` a teszt-CA-t a gép Root tárolójába teszi csak szerver- és klienshitelesítésre, majd eltávolítja)

### OpenVPN telepítése és frissítése

- [ ] OpenVPN nélkül **Telepítés** (Windows 11, winget) → a winget UAC-kérdése, a kimenet élőben, utána a WinVPN második UAC-kérdése; a sor zöld, a két illesztőprogramot verzióval mutatja; `pnputil.exe /enum-drivers` → ovpn-dco és tap0901, Wintun nincs; a `C:\Program Files\OpenVPN` alatt nincs GUI
- [ ] `sc.exe qc OpenVPNServiceInteractive` → `START_TYPE : 4 DISABLED`, `sc.exe query OpenVPNServiceInteractive` → `STATE : 1 STOPPED`; `reg.exe query HKLM\SOFTWARE\WinVPN /v OpenVpnInstalledByWinVpn` → `0x1`
- [ ] UAC elutasítva → „Megszakítva”, semmi nem települ
- [ ] A TAP-Windows6 eltávolítva (Telepített alkalmazások → OpenVPN → Módosítás) → „Javítás” gomb, egy TAP-os kapcsolat érthető hibát ad, a DCO-s működik; **Javítás** → visszakerül, az interaktív szolgáltatás újra letiltva
- [ ] Kézzel (GUI-val) telepített OpenVPN (`reg.exe delete HKLM\SOFTWARE\WinVPN /v OpenVpnInstalledByWinVpn /f` után) → a WinVPN használja; „Javítás”/„Frissítés” után is `OpenVPNServiceInteractive` `AUTO_START` és `RUNNING` marad
- [ ] winget nélküli gépen (ha van ilyen) a hivatalos MSI egy UAC-kérdéssel települ; ha nincs ilyen gép: **nem tesztelt**
- [ ] Hálózat nélkül **Telepítés** → hibaüzenet, semmi nem települ
- [ ] Ha a telepítettnél újabb OpenVPN jelent meg: a sor „Frissítés elérhető: x → y”, a **Frissítés** egy UAC-kérdéssel telepíti, utána zöld az új verzióval (ha nincs újabb: **nem tesztelhető**)

### Illesztőprogram kapcsolatonként (CP1-ből)

- [ ] A labor `openvpn-tun-dco.ovpn` → DCO-val csatlakozik (a Napló fülön az OpenVPN saját sorai a DCO-t mutatják), „via: openvpn”
- [ ] `openvpn-tun-cbc.ovpn` (`cipher AES-256-CBC`) → TAP-Windows6-tal csatlakozik
- [ ] `openvpn-tap-l2.ovpn` (`dev tap`) → TAP-Windows6-tal csatlakozik (`10.99.12.x`)
- [ ] Egy szerver, amely tömörítést küld (push) → az első DCO-s kísérlet után a naplóban „[WinVPN] DCO cannot run this connection (pushed options); retrying with TAP-Windows6”, és csatlakozik (ha nincs ilyen szerver: **nem tesztelhető**)
- [ ] Két TAP-os kapcsolat egyszerre → a második érthető hibát ad
- [ ] `windows-driver`, `win-sys` vagy `cryptoapicert` sor importáláskor → „Tiltott direktíva”, nyugtázással sem menthető

### OpenVPN-kapcsolatok és MFA (CP1-ből)

- [ ] Jelszavas kapcsolat (`labuser`) → csatlakozik; rossz jelszóval → „Hitelesítési hiba (AUTH_FAILED)”, a hitelesítőadat-ablak egyszer újra megnyílik
- [ ] Statikus challenge (`openvpn-static-challenge.ovpn`, `labotp`) → a kódablak csatlakozás előtt jön, a kóddal csatlakozik
- [ ] Dinamikus challenge (`openvpn-tun-dco.ovpn` `labotp`-vel) → a kódablak csatlakozás közben jön („Enter the lab one-time code”), a kóddal csatlakozik
- [ ] Webes bejelentkezés (`OPEN_URL`) egy ilyen szerverrel → a böngésző a címmel nyílik, a bejelentkezés után csatlakozik (ha nincs ilyen szerver: **nem tesztelhető**)
- [ ] A Napló fül élőben; jelszó és kód sehol, a `C:\ProgramData\WinVPN\logs` fájljaiban sem (rendszergazdaként megnyitva)
- [ ] Debug csatlakozás (Alt+kattintás) → bővebb napló (`--verb 5`), előtte és utána „▶ [WinVPN] diagnosztika” blokk

### WireGuard

- [ ] `wireguard-windows.conf` → csatlakozik, „via: wireguard”; debug módban a „WireGuard peer status” sor kulcs nélkül
- [ ] Teljes alagút (`AllowedIPs = 0.0.0.0/0, ::/0`, egy saját szerverrel, ha van) → a böngészés megy, `nslookup` az alagút DNS-ét használja, `route.exe print` mutatja az útvonalat
- [ ] `Table = off` → nem kerül fel útvonal
- [ ] Bontás → az adapter eltűnik (`Get-NetAdapter`)
- [ ] Hosztnévvel megadott végpont → feloldódik, csatlakozik

### Több felhasználó (CP1-ből)

- [ ] Egy második normál fiók (gyors felhasználóváltás) nem látja és nem bontja az első OpenVPN-kapcsolatát (a vezérlő API-n sem)
- [ ] Az első felhasználó kijelentkezik → az OpenVPN- és WireGuard-kapcsolatai bomlanak (a `service.log` szerint), a második felhasználóé él
- [ ] Zárolás és felhasználóváltás → a kapcsolatok maradnak

### Frissítés

- [ ] A popover **Beállítások** csoportjában **Frissítések keresése most** → „A WinVPN naprakész” (vagy a 2.0.0-nál újabb kiadás felajánlva); hálózat nélkül → tiszta hibaüzenet
- [ ] Egy későbbi kiadásnál (2.0.1 vagy újabb, ha megjelent): **Letöltés és telepítés** → kilépési kérdések, „A WinVPN frissítése bontja az aktív VPN-kapcsolatokat.”, UAC, a frissítés lefut, a szolgáltatás újraindul (`sc.exe query WinVPN`), a WinVPN magától visszajön; ha még nincs újabb kiadás: **nem tesztelhető**
- [ ] Egy későbbi kiadás telepítése közben (a UAC-ablak nyitva, majd az msiexec futása alatt): a `WinVPN-relaunch.exe` fut, az `updates` mappa `WinVPN-<verzió>-x64.msi` és `msiexec-<verzió>.log` fájlja nem törölhető és nem nevezhető át, az `updates` mappa sem (P2-L3); UAC elutasítva → a `WinVPN-relaunch.exe` kilép, az MSI törlődik; ha még nincs újabb kiadás: **nem tesztelhető**
- [ ] A `%LOCALAPPDATA%\WinVPN\updates` alatt a `msiexec-<verzió>.log` megvan; egy sikertelen frissítés után a következő indításkor egyszeri értesítés a napló útvonalával (csak ha előfordul)

### Csapatkatalógus HTTPS-en

- [ ] Feliratkozás egy HTTPS-forrásra tokennel → előnézet, feliratkozás; a **Frissítés most** és egy nem változott fájl („nem változott”) rendben
- [ ] A token nem látszik a Feladatkezelő „Parancssor” oszlopában a `curl.exe`-nél, és a `service.log`-ban, az app naplójában sem
- [ ] Rossz token → „A csapatkatalógus nem olvasható: hozzáférés megtagadva (ellenőrizd a hozzáférési tokent)”

### Eltávolítás

- [ ] Az MSI eltávolítása után (előtte a „WinVPN eltávolítása erről a fiókról” pontjai) a szolgáltatás és a `wireguard.dll` eltűnik (`sc.exe query WinVPN` → nincs ilyen); az OpenVPN Community a két illesztőprogrammal és a TAP-adapterekkel, valamint a `C:\ProgramData\WinVPN` megmarad

### Smoke

- [ ] (automatikus: a kiadás előtti `scripts/win-smoke.sh en` és `hu`, `docs/RELEASING.md` 2. lépés) a smoke teszt a natív szakaszokkal zöld volt

## WinVPN: natív VPN-ek (L2TP/IPsec, IKEv2, SSTP, Cisco IPsec), rendszer VPN-ek és paritás

A Windows saját VPN-kliensével futó típusok, a felhasználó saját Windows VPN-jei és a MacVPN-nel való egyezés pontjai. A terv: `docs/superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md` (CP1 és CP2), a paritás-audit: `docs/superpowers/specs/2026-10-25-winvpn-parity-audit.md`.

Előfeltétel: a `WinVPN-2.0.0-x64.msi` telepítve (rendszergazda), a tesztek egy normál felhasználó **asztali** munkamenetében (nem SSH-n); a VPN-labor fut (lásd „A VPN-labor előkészítése”). Windows **build száma: ___**

### Telepítés és Rendszerállapot

- [ ] Normál felhasználóként megnyitva a **Rendszerállapot** négy sort mutat: WinVPN szolgáltatás („Fut (2.0.0. verzió)”), OpenVPN Community, WireGuard és **Windows VPN-kliens** („A Windows része”), mind zölden; nincs „a WinVPN egy későbbi verziójában érkeznek” megjegyzés
- [ ] Rendszergazdai PowerShellben `sc.exe qc RasMan` → `START_TYPE` `3 DEMAND_START`
- [ ] Rendszergazdaként `sc.exe config SstpSvc start= disabled` → a **Rendszerállapot** (Újraellenőrzés után) a Windows VPN-kliens sort pirosan mutatja a szolgáltatás nevével („A(z) Secure Socket Tunneling Protocol Service (SstpSvc) Windows-szolgáltatás le van tiltva…”), az SSTP-kapcsolatok szürkék ezzel az okkal, az L2TP és az IKEv2 nem; `sc.exe config SstpSvc start= demand` → újra zöld
- [ ] Az **Új** menüben nincs **Cisco IPsec**; OpenVPN, WireGuard, IKEv2, SSTP és L2TP van

### L2TP/IPsec

- [ ] A `lab-client\l2tp.txt` értékeivel új L2TP kapcsolat (szerver, fióknév, jelszó, PSK, „Minden forgalom a VPN-en”), **Mentés** → nincs profiljóváhagyás, az űrlapon a „Mentéskor a kapcsolat Windows VPN-bejegyzése azonnal elkészül…” megjegyzés
- [ ] Csatlakozás → a labor NAT mögött van, ezért előbb a 809-es hiba szövege jön **L2TP engedélyezése NAT mögött…** gombbal → UAC (rendszergazda) → „Az L2TP/IPsec NAT mögött engedélyezve. Az érvényesítéshez indítsd újra a Windowst.”; rendszergazdaként `reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v AssumeUDPEncapsulationContextOnSendRule` → `0x2`
- [ ] A UAC-kérdés elutasítása → „Megszakítva”, a beállítás nem változik
- [ ] Újraindítás után csatlakozás → „Csatlakozva”, az IP-cím (`10.99.16.x`) a kártyán; `http://10.99.0.10/` → „via: ipsec”; `ipconfig.exe` → „PPP adapter WinVPN-…”
- [ ] A kapcsolat a Gépház → Hálózat és internet → VPN listájában **nem** jelenik meg
- [ ] A `%LOCALAPPDATA%\WinVPN\ras\WinVPN.pbk` fájlban (Jegyzettömb) sem a jelszó, sem a PSK nincs benne
- [ ] Bontás → „Bontva”; ugyanez „Minden forgalom” nélkül → `route.exe print` szerint az alapértelmezett útvonal a fizikai adapteren marad
- [ ] Rossz jelszó → „Hitelesítési hiba (rossz felhasználónév vagy jelszó)”; a Napló fülön a `Windows error 691: …` sor és a lépések, jelszó nélkül; L2TP-nél nincs második kérdés
- [ ] A Napló fülön debug mód nélkül is látszanak a tárcsázás lépései („Kapcsolódás ide: …”, „Hitelesítés…”, „Csatlakozva, IPv4: …”); debug módban (Alt+kattintás) a „Windows VPN-bejegyzés (hibakereső mód):” blokk, PSK és jelszó nélkül
- [ ] Rossz PSK → 789-es hiba szövege („Az IPsec-egyeztetés a szerverrel nem sikerült…”)
- [ ] Az L2TP-kapcsolat törlése → a megerősítés „…és a Windows VPN-bejegyzése is.”; nem nyílik meg a Gépház; a `WinVPN.pbk`-ból eltűnik a `[WinVPN-…]` szakasz

### IKEv2

- [ ] **EAP-MSCHAPv2:** a `lab-client\ikev2-eap.swanctl.conf` importálva, felhasználónév `labuser`, jelszó a `CREDENTIALS.txt`-ből; a szerkesztő alatt „Windowson: EAP-MSCHAPv2 · AES-256, SHA-256, DH-csoport 14; …” sor
- [ ] **A CA megbízhatóvá tétele a Windowsban…** a `lab-client\lab-ca.pem`-mel → a megerősítő ablakban a tulajdonos („MacVPN Lab CA (throwaway)”), az érvényesség, az SHA-256 ujjlenyomat és a „A számítógép minden programja meg fog bízni…” figyelmeztetés → **Megbízom benne** → UAC (a telepített WinVPN.exe kéri) → „A Windows mostantól megbízik a CA-ban.”; `certutil.exe -store Root` listázza a labor-CA-t, és `certlm.msc` → a CA tulajdonságai → csak „Kiszolgálóhitelesítés” és „Ügyfélhitelesítés” célra engedélyezett (kódaláírásra nem)
- [ ] Csatlakozás → „Csatlakozva”, `http://10.99.0.10/` → „via: ipsec”; osztott alagútnál `route.exe print` a `remote_ts` hálózatát mutatja; bontás
- [ ] Rossz jelszó → „Hitelesítési hiba (EAP)”, és a hitelesítőadat-ablak **egyszer** újra megnyílik „Sikertelen bejelentkezés — …” sorral; jó jelszóval csatlakozik, a **Mentés a széfbe** után a jelszó a széfben marad
- [ ] **PSK** (`ikev2-psk.swanctl.conf`) → a kártya szürke, mellette „Windowson nem támogatott: local auth = psk (…)”, a szerkesztőben sárga megjegyzés; a mentés működik
- [ ] **Gépi tanúsítvány** (`ikev2-cert.swanctl.conf`): előbb tanúsítvány nélkül csatlakozva → „Nem található számítógép-tanúsítvány az IKEv2-höz…”; a `lab-client\lab-client.p12`-t rendszergazdaként a `certlm.msc` → Személyes tárolóba importálva (jelszava a `CREDENTIALS.txt`-ben) → csatlakozik, „via: ipsec”, jelszót nem kér
- [ ] Nem támogatott beállítás (`local { auth = eap-tls }` vagy `version = 1`) → a kártya szürke „Windowson nem támogatott: …” szöveggel, pontosan a kulccsal; a mentés működik
- [ ] `dpd_action = restart` a configban → szürke „Windowson figyelmen kívül marad: …” megjegyzés a szerkesztő alatt, a kapcsolat csatlakozik
- [ ] Olyan `proposals` sor, amelyet a labor szervere nem fogad el (például `aes128-sha1-modp2048`) → a 13868-as hiba szövege, a WinVPN által kínált javaslat megnevezésével

### SSTP

- [ ] „Saját CA fájl” (`sstp-ca.sstp`; a CA a fenti lépésben már megbízható) → az űrlapon „A Windows megbízik benne”, csatlakozik, `http://10.99.0.10/` → „via: sstp”
- [ ] „Rendszer CA” (`sstp-system-ca.sstp`) → csatlakozik (a CA a gép megbízható gyökerei között van)
- [ ] A 8443-as port (`sstp-ca-alt-port.sstp`) → csatlakozik
- [ ] „Nincs ellenőrzés” (`sstp-no-verification.sstp`) → a kártya szürke az indoklással; az űrlapon a „Nincs ellenőrzés” tiltva, a címében az ok
- [ ] Ugyanez a CA nélkül (előbb `certlm.msc`-ben töröld a labor-CA-t) → „A szerver hitelesítésszolgáltatójában (CA) a Windows nem bízik meg…” hiba **A CA megbízhatóvá tétele a Windowsban…** gombbal; a gombbal újra megbízható, utána csatlakozik
- [ ] IP-címmel megadott szerver (a tanúsítvány nevével nem egyező cím) → „A szerver tanúsítványa nem egyezik a szerver címével…”
- [ ] „A szerver DNS-ének használata” kikapcsolva → `nslookup` először a fizikai adapter DNS-szerverét kérdezi (a „lehetőségekhez mérten” leírás szerint)
- [ ] Rossz jelszó → „Hitelesítési hiba (rossz felhasználónév vagy jelszó)”, a hitelesítőadat-ablak egyszer újra megnyílik

### Egyszeri kód (OTP)

- [ ] Egy L2TP és egy SSTP kapcsolat `labotp` felhasználóval (jelszó ugyanaz, elválasztó „,”, a kód a `CREDENTIALS.txt`-ben), **Egyszer használatos kód kérése csatlakozáskor…** bekapcsolva → a kódbekérő ablak után csatlakozik; rossz kóddal → hitelesítési hiba

### Rendszer VPN-ek

- [ ] A Gépház → VPN alatt egy saját L2TP VPN felvéve (a labor adataival) → a WinVPN listájában másodperceken belül megjelenik „Rendszer-VPN”-ként „L2TP” típussal; törlése után eltűnik
- [ ] Mentett jelszó nélkül, a Windowsban sem mentve → a Windows saját bejelentkező ablaka nyílik; kitöltve csatlakozik
- [ ] A WinVPN-ben tárolt jelszóval és PSK-val (a részletező nézetben; a „A Windows a saját PSK-ját használja…” megjegyzés látszik) → csatlakozik; a bejegyzés a Gépházban változatlan (a WinVPN nem írja át, nem törli)
- [ ] Egy saját IKEv2 VPN (gépi tanúsítvánnyal) a Gépházból → a WinVPN-ből csatlakozik és bont
- [ ] Bontás a Gépházból → a WinVPN-ben is „Bontva” lesz (néhány másodpercen belül)

### Cisco IPsec

- [ ] Egy Cisco IPsec kapcsolat (egy MacVPN-mentésből vagy a `cisco-ipsec.txt` értékeivel a Macen készített mentésből) → a kártya szürke: „A Windows nem támogatja a Cisco IPsec-et. …”, a kapcsoló tiltott
- [ ] A szerkesztőben **L2TP/IPsec másolat készítése** → új „<név> (L2TP)” kapcsolat ugyanabban a mappában, ugyanazzal a szerverrel, fióknévvel, jelszóval és PSK-val; a laborban csatlakozik; az eredeti Cisco kapcsolat változatlan

### Titkok

- [ ] A `WinVPN.pbk` egyetlen jelszót, PSK-t vagy kódot sem tartalmaz (Jegyzettömbbel keresve)
- [ ] A Napló fülön és a `%LOCALAPPDATA%\WinVPN\logs\ras\*.log` fájlokban nincs jelszó, PSK vagy egyszeri kód (a tárcsázás debug módban is)
- [ ] A Feladatkezelő „Parancssor” oszlopában egy csatlakozás közben egyik folyamatnál sincs titok

### Életciklus

- [ ] Kilépés aktív L2TP kapcsolattal → „Aktív VPN-kapcsolatok vannak” kérdés; „Kilépés, fussanak tovább” után a kapcsolat él, a WinVPN újraindítása után „Csatlakozva” látszik
- [ ] Kijelentkezés aktív L2TP és IKEv2 kapcsolattal → újra bejelentkezve egyik sincs fenn
- [ ] Kijelentkezés `KeepRasConnections` mellett: rendszergazdaként `reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v KeepRasConnections /t REG_SZ /d 1 /f`; normál felhasználóként egy WinVPN L2TP kapcsolat **és** egy saját rendszer VPN fel; kijelentkezés (nem zárolás); újra bejelentkezve → a WinVPN-kapcsolat nincs fenn, a `C:\ProgramData\WinVPN\service.log` végén „RAS connection of a logged-off user ended: WinVPN-xxxxxxxx” (vagy a kapcsolatot már a WinVPN bontotta); a rendszer VPN-hez a szolgáltatás nem nyúlt. Ha „could not be ended … 668” sor jön, jelezd a fejlesztőnek. Végül `reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v KeepRasConnections /f`
- [ ] Zárolás és felhasználóváltás után a kapcsolatok megmaradnak
- [ ] Egy második normál felhasználó (gyors felhasználóváltás) a saját WinVPN-jében nem látja az első felhasználó L2TP kapcsolatát, és nem bonthatja (a RAS rendszerszinten listázza, a WinVPN csak a sajátját mutatja)
- [ ] Egy L2TP és egy OpenVPN (vagy WireGuard) kapcsolat egyszerre él, mindkettő forgalmaz
- [ ] A WinVPN szolgáltatás leállítva (rendszergazdaként `sc.exe stop WinVPN`) → az OpenVPN és a WireGuard szürke a szolgáltatás szövegével, az L2TP, az IKEv2, az SSTP és a rendszer VPN-ek csatlakoznak a popoverből és a `macvpn-control-client.exe hold`-dal is; `sc.exe start WinVPN`

### Mentés, import, katalógus

- [ ] Egy MacVPN-mentés L2TP, IKEv2, SSTP és Cisco kapcsolatokkal visszaállítva → a „Visszaállítás után” lapon az L2TP „Kész”, a szöveg „A WinVPN megírta az L2TP kapcsolatok Windows VPN-bejegyzéseit…”; az L2TP azonnal csatlakozik, az IKEv2/SSTP az első csatlakozáskor; a Cisco szürke, megjegyzéssel
- [ ] Egy MacVPN-ből közzétett csapatkatalógus L2TP kapcsolata → jóváhagyás nélkül használható
- [ ] A széf zárolása és feloldása után egy bejegyzés sem vész el; egy kézzel a `WinVPN.pbk`-ba másolt, nem létező azonosítójú `[WinVPN-…]` szakasz a következő feloldás után eltűnik, más nevű szakasz megmarad
- [ ] Egy `.mobileconfig` importálása → „A .mobileconfig profil nem importálható a WinVPN-be. Hozd létre a kapcsolatot az Új → L2TP menüponttal…”

### Vezérlő API

- [ ] `macvpn-control-client.exe hold <egy L2TP kapcsolat azonosítója>` (a token a programnak a bemenetén megadva, nem parancssorban) → a kapcsolat felépül, a program kilépésekor lebomlik

### Paritás (a 2c terv 15. feladatának pontjai)

- [ ] **G-1:** a WinVPN fut, az utolsó motorellenőrzés 24 óránál régebbi → egy újabb OpenVPN (winget) vagy wireguard-nt a Rendszerállapot megnyitása nélkül „Frissítés elérhető” sorként jelenik meg (ha nincs újabb: **nem tesztelhető**)
- [ ] **G-2:** egy L2TP kapcsolat Napló füle debug mód nélkül is a tárcsázás sorait mutatja (nincs „csak debug csatlakozáskor” szöveg)
- [ ] **G-3:** egy L2TP kapcsolatot tartalmazó mappa törlése a kapcsolatokkal együtt → nem nyílik meg a Gépház, a bejegyzés eltűnik
- [ ] **G-5:** rossz jelszó IKEv2 EAP-nál és SSTP-nél → egyszer újra kér (lásd fent)
- [ ] **G-6:** OpenVPN és WireGuard debug módban → a naplóban „▶ [WinVPN] diagnosztika (előtte)” és „(utána)” blokk; WireGuardnál „▶ [WinVPN] WireGuard peer status (…)” sor, kulcs nélkül
- [ ] **G-7:** a WinVPN tétlen, Gépház → Személyre szabás → Színek → mód váltása → az értesítési terület ikonja egy másodpercen belül átszíneződik
- [ ] **G-8:** a kiadás előtti `scripts/win-smoke.sh en` és `hu` futás a kijelentkezési kilépéskérést és a popover kerek sarkait jelentette, nem „skipped”-et
- [ ] **G-12:** az SSTP-labor leállított szerverével csatlakozva → „A szerver nem válaszolt a portján…”; egy L2TP-bejegyzés PSK nélkül (a PSK törlése után mentés nélkül tárcsázva, ha előállítható) → „A Windows nem tárol előre megosztott kulcsot…”

### WinVPN eltávolítása erről a fiókról (G-9)

- [ ] Legyen egy aktív L2TP és egy aktív OpenVPN vagy WireGuard kapcsolat, és a Gépház → VPN alatt egy saját Windows VPN. **Rendszerállapot** → a Telepített alkalmazások megjegyzés alatt **WinVPN eltávolítása erről a fiókról…** → a megerősítő ablak felsorolja, mi törlődik; **Mégse** → semmi nem változik
- [ ] Újra, a négyzet nélkül → **Eltávolítás** → minden kapcsolat bont, „A WinVPN eltávolítva erről a fiókról” üzenet, megnyílik a Gépház → Alkalmazások → Telepített alkalmazások; a `%LOCALAPPDATA%\WinVPN` megmaradt, de a `ras\WinVPN.pbk`-ban nincs `[WinVPN-…]` szakasz; a saját Windows VPN megvan
- [ ] **Kilépés**, a WinVPN újraindítása után a kapcsolatok megvannak (az L2TP-t egyszer újra menteni kell)
- [ ] Ismételve **A felhasználói adatok törlése is** bejelölésével → **Kilépés** után a `%LOCALAPPDATA%\WinVPN` nincs meg; a Hitelesítőadat-kezelőben nincs `local.winvpn.vault`; `reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` nem mutat WinVPN értéket; `rasdial.exe` szerint nincs WinVPN-kapcsolat
- [ ] Végül az MSI eltávolítása a Telepített alkalmazások alatt → `sc.exe query WinVPN` → nincs ilyen szolgáltatás, a `C:\Program Files\WinVPN` eltűnt; a Gépház → VPN alatt semmi WinVPN-es

### Takarítás és egyéb

- [ ] `certlm.msc` → Megbízható legfelső szintű hitelesítésszolgáltatók → „MacVPN Lab CA (throwaway)” törölve, Személyes → „client.lab.test” törölve; ha nem kell NAT mögötti L2TP: `reg.exe delete HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v AssumeUDPEncapsulationContextOnSendRule /f`; a Macen `scripts/vpn-lab/down.sh`
- [ ] Az SSH-n nem futtatható (tárcsázó és bontó) tesztek a forráskóddal, normál felhasználóként az asztalon, Git Bashben: `cargo test --locked -p macvpn-winsys --test ras -- --ignored` és `cargo test --locked -p macvpn-platform-win --test ras_engine --test system_vpns --test admin_steps -- --ignored` → mind zöld (az `admin_steps` UAC-kérdést hoz, és ehhez a build MSI-jének telepítve kell lennie; utána rendszergazdaként `certutil.exe -delstore Root 53cdc417ceda8000a2fcfd50eb98f4d80c9cde2f`)

## WinVPN: alapok (telepítés, széf, fájlok, ablakok)

Minden, ami nem a csatlakozásról szól (a terv: `docs/superpowers/plans/2026-10-21-winvpn-2a-foundations.md`; az 1.5.0-s előzetesen 2026-10-21-én egyszer már lefutott). Ezek az ellenőrzések asztali munkamenetet kívánnak: egy SSH-kapcsolatnak nincs asztala, nincs Hitelesítőadat-kezelő munkamenete, és a vezérlő cső nem engedi be.

Előfeltétel: a kiadott `WinVPN-2.0.0-x64.msi` (és az `-arm64.msi`). Kell egy Windows 11 x64 gép (ha van, egy Windows 10 is), rajta egy rendszergazdai fiók a telepítéshez, egy normál fiók a teszthez (**asztali** bejelentkezéssel, nem SSH-n), és egy második normál fiók. Kell egy `.ovpn` (mellette `ca.crt`, egy `sub\client.key` és egy kétsoros `auth.cfg`), egy `.sstp`, egy WireGuard `.conf`, egy `.macvpncatalog` egy SMB-megosztáson, egy `.macvpnadminkey`, egy `.macvpnbackup` és egy MacVPN-nel (Macen) készült teljes biztonsági mentés. Példanevek: „Office VPN”, „Acme VPN”, `vpn.example.com`. Windows **build száma: ___**

### Telepítés (rendszergazda)

- [ ] Dupla kattintás a `WinVPN-2.0.0-x64.msi`-re egy tiszta Windows 11-en: a SmartScreen egyszer figyelmeztet („A Windows megvédte a számítógépet” → **További információ** → **Futtatás mindenképp**), utána a rendszergazdai megerősítés → a telepítés hiba nélkül lefut (a mappa és a szolgáltatás ellenőrzése: „WinVPN: a szolgáltatás, OpenVPN, WireGuard, frissítés” → „Telepítés és szolgáltatás”)
- [ ] A `C:\Program Files\WinVPN\THIRD-PARTY-NOTICES.txt` azonos a repó `THIRD-PARTY-NOTICES.windows.txt` fájljával
- [ ] A Start menüben „WinVPN”; PowerShellben `Get-StartApps WinVPN` → az AppID `local.winvpn` (az értesítések ezt az AppUserModelID-t használják)
- [ ] `reg.exe query HKLM\Software\Classes\.ovpn`, `.sstp` és `.macvpncatalog` → az alapérték a `WinVPN.ovpn`, `WinVPN.sstp`, `WinVPN.macvpncatalog` ProgId; `reg.exe query HKLM\Software\Classes\.conf /s` → csak az `OpenWithProgids` alatt egy `WinVPN.conf` érték, a `.conf` alapértéke nem változott; a `.macvpnadminkey`, `.macvpnbackup` és `.mobileconfig` kiterjesztéshez nincs WinVPN-bejegyzés
- [ ] WebView2 nélküli gépen (ha van ilyen, például egy régebbi Windows 10) a telepítő letölti a WebView2 Runtime-ot, utána a WinVPN ablakai megjelennek
- [ ] Az arm64 MSI egy ARM64 gépen ugyanígy (ha nincs ilyen gép, jelöld: **nem tesztelt**)

### Első indítás, ikon és popover

- [ ] Indítás a Start menüből → nem nyílik konzolablak; az ikon megjelenik a tálca értesítési területén (ha a **^** alatt van, áthúzható a tálcára); fölé víve „WinVPN”
- [ ] A popover és minden ablak (Kapcsolatok, Rendszerállapot, a széf ablakai) a WinVPN felületét mutatja, nem üres fehér lapot
- [ ] Sötét tálcán az ikon fehér, világos tálcán fekete (a mód váltását a „Paritás” rész G-7 pontja nézi)
- [ ] A popover alján „WinVPN 2.0.0” áll (nem MacVPN)
- [ ] A popover az ikon **fölött** nyílik, a képernyőn belül; a Beállítások kinyitásakor felfelé nő, becsukáskor az alja a tálcánál marad
- [ ] Windows 11-en **minden** WinVPN-ablak és a popover lekerekített sarkú, Windows 10-en szögletes. **Valódi hardveren** ellenőrizendő: alap kijelző-adapterrel (VM, Microsoft Basic Display Adapter) a Windows 11 semmit nem kerekít le, a Fájlkezelőt sem
- [ ] Egyik WinVPN-ablakban sincs menüsor; a popover **Beállítások** csoportjában ott a **Frissítések keresése most**; a **Kilépés** kilép (a Feladatkezelőben nem marad `WinVPN.exe`)
- [ ] A Kapcsolatok, a Rendszerállapot és a széf ablakainak saját tálcagombja van, Alt+Tabbal elérhetők; ha csak a popover van nyitva, nincs tálcagomb
- [ ] Szövegmezőkben (config szerkesztő, keresőmező, jelszómező) a Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+A és Ctrl+Z működik; a **Ctrl+S** ment a szerkesztőben, a **Ctrl+F** a keresőmezőbe ugrik
- [ ] A **Rendszerállapot** Homebrew-, eszköz- és jogosultság-sorok nélkül, a Windows-sorokkal nyílik (a sorokat a natív VPN-ek része nézi)
- [ ] **Súgó** → a böngészőben a GitHubon a `docs/winvpn-user-guide.hu.md` nyílik meg (angol nyelvű Windowson a `winvpn-user-guide.en.md`), nem a MacVPN útmutatója
- [ ] A Windows megjelenítési nyelve magyar → a WinVPN magyarul szól; angol → angolul (kilépés és újraindítás után)

### Széf és Hitelesítőadat-kezelő

- [ ] A Windows gépen, **asztali** munkamenetben (nem SSH-n), a 2.0.0-s forrás mappájában: `cargo test --locked -p macvpn-platform-win --test windows` → minden teszt zöld, és a `the_credential_key_store_round_trips_and_deletes` **nem** írja ki, hogy „skipped: no Credential Manager logon session”; utána a `cmdkey.exe /list` nem mutat `local.winvpn.test.` kezdetű bejegyzést
- [ ] Széf létrehozása, a helyreállítási kulcs ellenőrzése → `cmdkey.exe /list` → `LegacyGeneric:target=local.winvpn.vault`, típusa általános (Generic), felhasználója `dek`, tárolása helyi gépi (Local machine persistence)
- [ ] Kilépés és újraindítás → a széf kérdés nélkül feloldódik
- [ ] **Automatikus feloldás** ki → a `local.winvpn.vault` eltűnik a `cmdkey.exe /list` listából, a következő indításkor a WinVPN a mesterjelszót kéri; vissza bekapcsolva → a bejegyzés újra megjelenik
- [ ] A `local.winvpn.vault` kézi törlése a Hitelesítőadat-kezelőben (Windows hitelesítő adatai) → a következő indításkor a WinVPN a mesterjelszót kéri, nem omlik össze
- [ ] `icacls.exe $env:LOCALAPPDATA\WinVPN` → csak két bejegyzés: a felhasználó és a SYSTEM (`NT AUTHORITY\SYSTEM`), mindkettő `(OI)(CI)(F)`, öröklött `(I)` bejegyzés nélkül; a `vault.db`, a `vault.keys`, a `preferences.json` (és futás közben a `vault.db-wal`) ugyanígy, csak `(F)`
- [ ] Rendszergazdaként, emelt PowerShellben: `Get-ChildItem C:\Users\<a tesztfelhasználó>\AppData\Local\WinVPN` → hozzáférés megtagadva (a Rendszergazdák csoport nincs a listán); a második normál fiókból ugyanígy
- [ ] **Széf zárolása most**, feloldás, hibás jelszó után a várakozás, **Mesterjelszó módosítása…**, **Új helyreállítási kulcs…**, elfelejtett jelszó a helyreállítási kulccsal → mind működik
- [ ] A Win+V vágólap-előzmények bekapcsolva: a helyreállítási kulcs **Másolás** gombja után a kulcs beilleszthető (Ctrl+V a Jegyzettömbbe), de a Win+V előzményeiben **nem** jelenik meg; bekapcsolt felhőalapú vágólap-szinkronizálásnál egy másik eszközön sem (ha van ilyen)
- [ ] 60 másodperc múlva a vágólap üres (a Ctrl+V semmit nem illeszt be); ha közben mást másoltál, az megmarad; a **Széf zárolása most** és a **Kilépés** is törli a még ott lévő titkot

### Kapcsolatok

- [ ] `.ovpn` importálása a mellékelt fájlokkal (`ca.crt`, `sub\client.key`, `auth.cfg`) → beolvasva, beemelve, a hitelesítőadat-fájlra rákérdez
- [ ] `..\ca.crt` hivatkozás → elutasítva („A hivatkozott fájl a config mappáján kívül van”); `\\<szerver>\<megosztás>\ca.crt` hivatkozás → elutasítva, hálózati forgalom nélkül; `ca.crt:hidden` (alternatív adatfolyam) → hiányzó fájlként elutasítva
- [ ] OneDrive-mappából importálás, a fájl csak online → letöltődik és beolvasódik
- [ ] Exportálás (`.ovpn`, kulcsokkal és kulcsok nélkül) → `icacls.exe <fájl>` → csak a felhasználó és a SYSTEM
- [ ] A fájlpárbeszédek (**Import fájlból…** több fájllal, exportálás, **PEM fájl kiválasztása…**, a mentés helye, a katalógusfájl kiválasztása) a Windows saját ablakai, a WinVPN ablaka előtt nyílnak; a **Mégse** semmit nem változtat; a párbeszéd alatt a többi WinVPN-ablak nem fagy le
- [ ] Húzás a Fájlkezelőből a Kapcsolatok ablakba → import

### Mentés és visszaállítás
- [ ] Teljes biztonsági mentés WinVPN-ből → a mentés helyének ablaka a `WinVPN-backup-<dátum>.macvpnbackup` nevet ajánlja; a fájl elkészül, `icacls.exe` szerint csak a felhasználó és a SYSTEM olvashatja
- [ ] Egy MacVPN-mentés visszaállítása új WinVPN-széfbe (**Széf beállítása** → **Visszaállítás biztonsági mentésből…**) → a kapcsolatok, mappák, színek és közös hitelesítő adatok átjönnek, a beállítások csak bejelölés után lépnek életbe (a natív típusokét a natív VPN-ek része nézi)
- [ ] Egy WinVPN-mentés visszaállítása MacVPN-ben (a Macen) → ugyanígy

### Csapatkatalógus fájlforrással
- [ ] Feliratkozás fájlforrásra (SMB-megosztás, majd egy OneDrive-mappa) → előnézet, ujjlenyomat, feliratkozás; egy új közzétett verzió a **Frissítés most** gombbal és magától is megjön, értesítéssel (a HTTPS-forrás: „Csapatkatalógus HTTPS-en”)
- [ ] Közzététel WinVPN-ből egy megosztásra → egy Macen és egy másik Windows-fiókban feliratkozható; a kiírt fájlra `icacls.exe` → a felhasználó és a SYSTEM teljes, a `BUILTIN\Users` olvasási joggal
- [ ] **Feliratkozási kód másolása…** → nincs a Win+V előzményekben, 60 másodperc múlva törlődik

### Vezérlő API (named pipe)
- [ ] **Más appok vezérelhetik a VPN-eket** be; a saját asztali munkamenetben `cargo build -p macvpn-control-client`, majd `target\debug\macvpn-control-client.exe pair "Teszt"` → a párosító ablak megjelenik, a **Futtatható fájl** a kliens teljes útvonala; engedélyezés után a token kiíródik; `$env:MACVPN_TOKEN = '…'` és `macvpn-control-client.exe list` → az engedélyezett kapcsolatok (a `hold` a natív VPN-ek „Vezérlő API” pontjában)
- [ ] Ugyanaz a felhasználó SSH-n bejelentkezve: `macvpn-control-client.exe list` → nem csatlakozhat (hozzáférés megtagadva), a WinVPN nem mutat párosító ablakot
- [ ] A második fiókban (`runas.exe /user:<második fiók> powershell.exe`), `whoami.exe /user`-rel kiolvasott SID-del: `$env:MACVPN_SOCKET = '\\.\pipe\WinVPN-control-<az első felhasználó SID-je>'` és `macvpn-control-client.exe list` → nem csatlakozhat (hozzáférés megtagadva); ez a `another_user_is_refused_both_ways` kézi párja
- [ ] A kapcsoló kikapcsolása → a kliens nem csatlakozik; a **Visszavonás** után a token nem működik

### Fájltársítások és a Mark of the Web
- [ ] Dupla kattintás egy `.ovpn`-re és egy `.sstp`-re → a WinVPN importálja; ha nem futott, elindul; ha futott, a futó példány kapja (a Feladatkezelőben egy `WinVPN.exe`)
- [ ] Dupla kattintás egy `.macvpncatalog`-ra → **Csapatkatalógusok** → **Csapatkatalógus hozzáadása…**, a forrás **Fájl**, a fájl kiválasztva, a kulcs és az ujjlenyomat üres
- [ ] A WireGuard `.conf` dupla kattintásra **nem** a WinVPN-ben nyílik; jobb gomb → **Társítás** listában ott a WinVPN, azzal megnyitva importálódik
- [ ] `.macvpnadminkey` és `.macvpnbackup`: nem a WinVPN nyitja meg; **Társítás → Másik alkalmazás választása → WinVPN** úton → „Ezt a fájlt a WinVPN saját paneljén kell megnyitni, nem a Fájlkezelőből.”, semmi nem változik
- [ ] Edge-ből letöltött `.ovpn`: PowerShellben `Get-Content <fájl> -Stream Zone.Identifier` → `ZoneId=3`; dupla kattintás → „Importálod a letöltött fájlt?” a fájl nevével; **Mégse** → nincs új kapcsolat; **Importálás** → import, utána a `Zone.Identifier` adatfolyam megmarad
- [ ] Két letöltött és egy helyben létrehozott fájl együtt megnyitva → egy kérdés csak a két letöltött fájl nevével; egy helyben létrehozott fájl kérdés nélkül importálódik
- [ ] Zárolt széfnél egy letöltött fájl → előbb a feloldó ablak, utána a kérdés, csak utána az import

### Egy példány felhasználónként
- [ ] Második indítás fájl nélkül (Start menü), nyitott Kapcsolatok ablakkal → az ablak előjön, nem indul második `WinVPN.exe`
- [ ] Második indítás fájl nélkül, amikor csak az ikon fut (nincs nyitott ablak) → megnyílik a Kapcsolatok ablak
- [ ] Ugyanez zárolt széffel → a feloldó ablak nyílik meg (széf nélkül a beállító ablak)
- [ ] Második indítás fájllal (parancssorból `"C:\Program Files\WinVPN\WinVPN.exe" C:\…\teszt.ovpn`) → a futó példány importálja, a második folyamat kilép (`echo %ERRORLEVEL%` → `0`)

### Indítás bejelentkezéskor
- [ ] **Indítás bejelentkezéskor** be → `reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WinVPN` → `"C:\Program Files\WinVPN\WinVPN.exe"` (idézőjelekkel); kijelentkezés és bejelentkezés után a WinVPN magától elindul
- [ ] **Gépház → Alkalmazások → Indítás** alatt a WinVPN kikapcsolva → a WinVPN-ben a kapcsoló ki, alatta „Kikapcsolva: Gépház → Alkalmazások → Indítás.”, az **Indítási alkalmazások beállításai…** gomb megnyitja ezt a Gépház-oldalt; bejelentkezéskor nem indul el
- [ ] A WinVPN-ben újra bekapcsolva → a Gépházban is bekapcsolt; kikapcsolva → a `Run` érték eltűnik
- [ ] Fejlesztői buildben (`target\debug\macvpn-app.exe`) a kapcsoló nem kattintható

### Értesítések
- [ ] A telepített MSI-ből (a Start menüből) indítva egy katalógusfrissítés értesítése megjelenik, „WinVPN” feladóval; a Gépház → Rendszer → Értesítések listájában ott a WinVPN
- [ ] Kattintás az értesítésre futó WinVPN mellett → a hozzá tartozó ablak előjön; kilépés után kattintva → a WinVPN elindul
- [ ] Egyetlen értesítésben sincs jelszó, kulcs, token vagy config-tartalom

### Kijelentkezés, leállítás, alvás
- [ ] A Kapcsolatok ablakban nem mentett változás, majd kijelentkezés → a „Nem mentett változások” kérdés megjelenik, a Windows a WinVPN-t „A WinVPN bezárása…” szöveggel mutatja a kijelentkezést feltartó alkalmazások között; **Mégse** → a kijelentkezés megszakítható, a WinVPN fut tovább; **Elvetés** → a kijelentkezés folytatódik
- [ ] Nem mentett változás nélkül → a kijelentkezés várakozás nélkül megy
- [ ] Újraindítás és leállítás ugyanígy
- [ ] Alvás és ébresztés → a WinVPN fut tovább, a katalógus legutóbbi frissítésének ideje az ébredés ideje

### Eltávolítás
- [ ] A **Rendszerállapot** ablakban nincs MacVPN-féle eltávolító gomb; helyette „A WinVPN-t a Windowsban távolíthatod el: Gépház → Alkalmazások → Telepített alkalmazások → WinVPN → Eltávolítás. …” szöveg, a **Telepített alkalmazások megnyitása…** gomb (a Gépház **Telepített alkalmazások** oldalát nyitja meg) és a **WinVPN eltávolítása erről a fiókról…** gomb (lásd a natív VPN-ek részét); sehol nem jelenik meg „no user name”
- [ ] Eltávolítás a Gépházból → a `C:\Program Files\WinVPN` mappa, a Start menü bejegyzése és a fájltársítások registry-bejegyzései eltűnnek; a `%LOCALAPPDATA%\WinVPN` és a `local.winvpn.vault` hitelesítő adat megmarad; újratelepítés után a széf kérdés nélkül megnyílik
- [ ] Eltávolítás a Gépházból, előtte **Indítás bejelentkezéskor** ki → a `Run` érték nem marad meg; ha bekapcsolva maradt, a `Run` érték megmarad (jegyezd fel; a **WinVPN eltávolítása erről a fiókról…** törli)

### Nyelv
- [ ] Mindez magyarul és angolul (a Windows megjelenítési nyelvének átállításával): a WinVPN-szövegek Windows-szavakat használnak (Hitelesítőadat-kezelő, Fájlkezelő, Gépház, értesítési terület), sehol nincs „Mac”, „Finder”, „Keychain” vagy „menüsor”

## MacVPN: a korábbi kiadások funkciói (regresszió, macOS)

Ezek a részek az 1.1–1.4 kiadások funkcióit nézik a 2.0.0-s MacVPN-ben; a címükben a zárójeles szám (ha van) az a kiadás, amelyben a funkció megjelent. A WinVPN megfelelői a fenti WinVPN-részekben vannak. Futtasd azokat, amelyeket a 2.0.0 változásai érinthettek (a root réteg, a DNS, a naplók és a Rendszerállapot körül mindet), a többit szúrópróbaszerűen.

## Csomag és aláírás
- [ ] (az azonosító, a verzió és a repó-ID automatikus: a kiadási workflow „A kész bundle ellenőrzése” lépése) `plutil -p /Applications/MacVPN.app/Contents/Info.plist`: `CFBundleIdentifier` `local.macvpn`, `CFBundleName` / `CFBundleDisplayName` `MacVPN`, `CFBundleExecutable` `MacVPN`, `CFBundleShortVersionString` = `CFBundleVersion` = `2.0.0`, `LSMinimumSystemVersion` `14.0`, `LSUIElement` true, `CFBundleDevelopmentRegion` `en`, `CFBundleLocalizations` `[en, hu]`, `MacVPNUpdateRepo` `SepsiG/MacVPN`, `MacVPNUpdateRepoID` `1422472799`, `CFBundleIconFile` `AppIcon`
- [ ] `lipo -archs` a `Contents/MacOS/MacVPN`-re és a `Contents/Resources/root/mvpn`-re: `x86_64 arm64`; a `Contents/Resources/root` alatt csak `mvpn` és `VERSION` (9)
- [ ] `codesign --verify --strict --verbose=2 /Applications/MacVPN.app` sikeres (automatikus: a kiadási workflow és a `scripts/sign-release.sh` előtti összevetés, `docs/RELEASING.md` 5. lépés); `codesign -dv …/root/mvpn` → `flags=…(adhoc,runtime)`
- [ ] Intel Macen (vagy `arch -x86_64`) is elindul az app; a Finder az ikont mutatja; ablak nélkül a Dockban nem jelenik meg (LSUIElement; ablakkal lásd „Dock ikon”)
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
- [ ] A telepítő egyetlen binárist és a `VERSION`-t másolja (`ls /usr/local/libexec/macvpn` → `VERSION mvpn`; `root:wheel 755`; `cat /usr/local/libexec/macvpn/VERSION` = 9); a `sudo -n -u` alapú másolás rootként működik
- [ ] Régebbi root rétegről (például egy 0.4.0-s, 6-os telepítésről) indulva a Rendszerállapot frissítést kér; „Engedélyezés” után a régi `ovpn-dns`, `mvpn-validate`, `mvpn-mgmt` törlődik, `sudo -n /usr/local/libexec/macvpn/mvpn version` = 9
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
- [ ] Rendszerállapot: `sstp-client` nélkül a VPN-eszközök sora „Hiányzik: sstp-client”, az SSTP kapcsolat szürke (lásd „Hiányzó motorok”), a többi típus használható; „Telepítés” után zöld
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

## Élő rendszer-VPN lista (1.1)
A figyelő (SCPreferences) valódi VPN-változásokon még nincs igazolva (`docs/superpowers/spikes/2026-10-19-live-system-list.md`): addig a lassabb lekérdezés is fut. Minden lépés macOS 14-en és 15-ön, ha lehet 10-ből 10-szer.
- [ ] `cargo test -p macvpn-platform-mac --test sc_watch -- --ignored --nocapture`, közben a Rendszerbeállítások → VPN-ben L2TP és IKEv2 VPN felvétele, átnevezése, törlése: minden lépésre kb. 1 s-on belül kiír egy sort (a késést írd a spike fájlba)
- [ ] Nyitott menü mellett VPN felvétele / átnevezése / törlése a Rendszerbeállításokban: a sor kb. 1 s-on belül megjelenik / átnevezve látszik / eltűnik, a menü újranyitása nélkül
- [ ] Nyitott Kapcsolatok ablakban egy rendszer VPN kiválasztva, majd törölve a Rendszerbeállításokban: a részletező megmarad, „Ezt a VPN-t eltávolították a macOS-ből” / „This VPN was removed from macOS” sáv, minden mező és a Csatlakozás / Mentés / Mentett titkok törlése gomb tiltva; másik kapcsolatot kiválasztva eltűnik
- [ ] Nyitott Kapcsolatok ablak mellett új VPN felvétele a Rendszerbeállításokban: a sora újranyitás nélkül megjelenik
- [ ] Egy MacVPN-ből mentett L2TP profil telepítése és eltávolítása után a lista követi a változást
- [ ] Zárt menü és ablakok mellett 10 perc tétlenség: legfeljebb 30 s-onként egy `scutil --nc list` (pl. `sudo fs_usage -w -f exec | grep scutil`), nincs pörgés
- [ ] Ha a figyelő mind a 10 próbán megbízható volt, `WATCHER_TRUSTED` (`crates/app-core/src/live.rs`) átállítható `true`-ra

## Vezérlő API, párosított appok (1.1)
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

## Dock ikon (1.1)
- [ ] Indulás után (ablak nélkül) nincs Dock ikon, a Cmd+Tab listában sincs MacVPN
- [ ] Kapcsolatok / Rendszerállapot / Frissítés ablak megnyitása → megjelenik a Dock ikon, Cmd+Tabbal elérhető; az ikonra kattintva a nyitott ablak előjön (új ablak nem nyílik)
- [ ] Két ablak nyitva, az egyik bezárva → az ikon marad; az utolsó bezárásakor eltűnik; minimalizált ablakkal is helyes
- [ ] A kódbekérő, a hitelesítőadat-bekérő és a párosító ablak nem hoz elő Dock ikont, és nem lopja el a fókuszt
- [ ] Gyors egymás utáni nyitás/zárás után az ikon állapota a valóságot követi

## Kártyás felület (1.1)
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

## Hitelesítő adatok bekérése (valódi OpenVPN szerver kell; 1.1)
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
- [ ] Rossz jelszó (OpenVPN) → piros ikon, a kapcsolat sorában „Hitelesítési hiba (AUTH_FAILED)”; értesítés „<név>: sikertelen csatlakozás”, alatta „A szerver elutasította a bejelentkezést.”; kattintásra a Napló fül
- [ ] Elérhetetlen szerver → 30 mp után „Időtúllépés"
- [ ] `up /tmp/x` a configban → mentéskor piros hiba, nem ment
- [ ] Futó kapcsolat közben `sudo kill <openvpn pid>` → értesítés a megszakadásról

## Értesítések
- [ ] Az app előtérben (megnyitott ablakkal) is megjelennek az értesítések (csatlakozás, megszakadás, hiba)
- [ ] Sikertelen csatlakozás értesítésében csak a kapcsolat neve és egy általános ok áll (például „A szerver nem válaszol.”; ha nincs ismert ok: „Részletek a MacVPN-ben” / „Open MacVPN for details”), a nyers hibaüzenet csak az appban látszik

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

## Keresés, VPN-fájlok megnyitása a Finderből, letöltött fájlok (1.4)

Kell egy saját HTTPS-oldal (vagy `python3 -m http.server` egy másik gépen), ahonnan egy `.ovpn` és egy `.sstp` letölthető.

### Keresés a Kapcsolatok ablakban
- [ ] **⌘F** a Kapcsolatok ablakban a keresőmezőbe ugrik; az „arvizturo” megtalálja az „Árvíztűrő” nevű kapcsolatot; a típus („wireguard”), egy mappa neve és egy csapatkatalógus neve is talál
- [ ] Egy OpenVPN kapcsolat a configja első `remote` gépnevére is megtalálható, a port, a felhasználónév és a config többi része nem (például `1194` vagy `auth-user-pass` nem talál rá); egy L2TP kapcsolat a szervercímére
- [ ] **↑** / **↓** lépked, a Return megnyitja a kijelöltet, az Esc törli a mezőt, a második Esc elhagyja; nincs találat: a **Keresés törlése** visszahozza a listát; keresés közben nincs húzás
- [ ] Egy config szerkesztése és mentése után a keresés az új szervert találja; a széf zárolása után a lista üres, feloldás után a keresés újra működik

### Letöltött fájlok (Safari)
- [ ] (automatikus: a `scripts/build-dmg.sh` ellenőrzi a kész `Info.plist`-ben) `plutil -p /Applications/MacVPN.app/Contents/Info.plist`: a `local.macvpn.ovpn` és a `local.macvpn.sstp` `UTTypeConformsTo` értéke `public.data`, `public.item`; sehol nincs `public.plain-text` vagy `public.text`
- [ ] Safari → Beállítások → Általános: **Biztonságos fájlok megnyitása letöltés után** bekapcsolva. A tesztoldalról letöltött `.ovpn` és `.sstp` a Letöltések mappában marad, a MacVPN **nem** nyílik meg, és semmi nem importálódik. (A beállítást utána állítsd vissza.)
- [ ] `xattr -p com.apple.quarantine ~/Downloads/<fájl>.ovpn` kiír egy értéket (a fájl jelölt)
- [ ] Dupla kattintás a letöltött `.ovpn`-re: a Kapcsolatok ablakban egy kérdés: **Importálod a letöltött fájlt?**, alatta a fájl neve és „Csak olyan fájlt importálj, amelyben megbízol.”, **Importálás** / **Mégse**. **Mégse** → semmi nem importálódik, nincs új kapcsolat
- [ ] Ugyanez **Importálás**-sal: az import a szokásos kérdésekkel és összesítővel lefut; utána az `xattr -p com.apple.quarantine` továbbra is kiírja a jelölést (a MacVPN nem törli)
- [ ] Két letöltött fájl és egy helyben létrehozott `.ovpn` együtt kijelölve, ⌘↓: **egy** kérdés („Importálod a(z) 2 letöltött fájlt?”) csak a két letöltött fájl nevével; **Mégse** → csak a helyi fájl importálódik
- [ ] Egy helyben létrehozott (nem letöltött) `.ovpn` dupla kattintásra kérdés nélkül importálódik
- [ ] Zárolt széfnél egy letöltött fájl: előbb a feloldó ablak, a feloldás után a kérdés, és csak utána az import
- [ ] Sok fájl egyszerre (például 300 `.ovpn` egy mappában kijelölve, ⌘↓): legfeljebb 64 importálódik, egy összesítő; zárolt széfnél a feloldó ablak egyszer jön elő, és legfeljebb 32 fájl vár
- [ ] Egy `.macvpncatalog` megnyitása után a feliratkozás **Szerkesztés → Forrás** ablakában a fájl **nincs** előre kiválasztva (a megnyitott fájlt csak a hozzáadás ablak kapja meg)
- [ ] Mindez angolul is (**Import the downloaded file?**, **Import 2 downloaded files?**, „Only import files you trust.”)

### VPN-fájlok megnyitása a Finderből

Előfeltétel: a DMG-ből az app az **Alkalmazások** mappában, és egyszer elindult (a LaunchServices ekkor regisztrálja a fájltípusokat). Kell egy `.ovpn` (mellette egy `ca.crt`-vel és egy kétsoros `auth.cfg`-vel), egy `.sstp`, egy WireGuard `.conf`, egy `.macvpncatalog` (a B gépen), egy `.macvpnadminkey` és egy `.macvpnbackup`. Ha a Tunnelblick vagy az OpenVPN Connect telepítve van, jegyezd fel, melyik nyitja meg alapból a `.ovpn`-t.

- [ ] (automatikus: `scripts/build-dmg.sh`) `plutil -p /Applications/MacVPN.app/Contents/Info.plist`: négy `CFBundleDocumentTypes` (`local.macvpn.ovpn` Default, `local.macvpn.sstp` Default, `local.macvpn.catalog` Owner, `conf` kiterjesztés Alternate), két importált (`local.macvpn.ovpn`, `local.macvpn.sstp`) és egy exportált (`local.macvpn.catalog`) típus; nincs `macvpnadminkey`, `macvpnbackup`, `mobileconfig`
- [ ] A Finderben a `.ovpn` és a `.sstp` fájl **Információ** ablakában a **Megnyitás ezzel** alatt a MacVPN az alapértelmezett (vagy, ha egy másik VPN-app az, az **Összes módosítása…** után az lesz)
- [ ] Dupla kattintás a `.ovpn`-re, a MacVPN fut, a széf nyitva: a Kapcsolatok ablak előjön, a hitelesítőadat-fájl kérdése megjelenik (**Használat** / **Mellőzés**), utána az összesítő („Importálva, beemelt fájlok: ca.crt”, a hitelesítő adatok sora); az új kapcsolat ki van jelölve, **nem** csatlakozik
- [ ] Egy `# macvpn-meta` sort (mappa + `credentialName`) tartalmazó exportált `.ovpn` dupla kattintásra: a mappa létrejön, a közös hitelesítő adatra a MacVPN rákérdez, csak **Használat** után kapcsol hozzá
- [ ] Egy kockázatos direktívát (`user nobody`) tartalmazó `.ovpn`: az összesítő jelzi, a szerkesztőben a sárga panel, a csatlakozás csak a jóváhagyás után
- [ ] Két fájl (`.ovpn` + `.sstp`) kijelölve, ⌘↓: egy import, egy összesítő, mindkét kapcsolat megjelenik
- [ ] Egy 1 MB-nál nagyobb, `.ovpn` kiterjesztésű fájl és egy `.ovpn` nevű mappa: „A fájl nem olvasható”, más nem változik
- [ ] A WireGuard `.conf` dupla kattintásra **nem** a MacVPN-ben nyílik; Control-kattintás → **Megnyitás ezzel** listában ott a MacVPN, azzal megnyitva importálódik
- [ ] A MacVPN nem fut: dupla kattintás a `.ovpn`-re elindítja, és (automatikus feloldással) importál; automatikus feloldás nélkül előbb a feloldó ablak jön, a feloldás után importál
- [ ] **Széf zárolása most**, majd dupla kattintás egy `.ovpn`-re: a feloldó ablak jön, a feloldásig semmi nem importálódik; feloldás után az import és az összesítő
- [ ] **Széf zárolása most**, dupla kattintás, a feloldó ablak bezárása **Mégse**-vel: semmi nem importálódik, egy későbbi feloldás után sem
- [ ] Széf nélkül (új felhasználói fiók, vagy `~/Library/Application Support/MacVPN` nélkül): dupla kattintás → a széf beállító ablaka; a helyreállítási kulcs ellenőrzése és az ablak bezárása után importál
- [ ] B gépen dupla kattintás a `.macvpncatalog`-ra: **Csapatkatalógusok** → **Csapatkatalógus hozzáadása…**, a forrás **Fájl**, a fájl neve kitöltve, a csapatkulcs és az ujjlenyomat üres, az **Ellenőrzés** tiltva; kitöltés után az előnézet, a négyzet bejelölése nélkül nem lehet feliratkozni; **Mégse** → semmi nem iratkozott fel
- [ ] Dupla kattintás a `.macvpnadminkey`-re és a `.macvpnbackup`-ra: nem a MacVPN nyitja meg; **Megnyitás ezzel → Másik…** úton a MacVPN-nel megnyitva: „Ezt a fájlt a MacVPN saját paneljén kell megnyitni, nem a Finderből.”, semmi nem változik
- [ ] `.mobileconfig` dupla kattintásra továbbra is a Rendszerbeállítások profiltelepítője nyílik
- [ ] A naplóban (Console, `MacVPN`) nincs a megnyitott fájlok útvonala vagy tartalma
- [ ] Mindez magyarul és angolul (az összesítő szövegei, a katalógus ablak)

## Kombinált PEM fájl: cert és key egy fájlban (1.4.1)

- [ ] Egy `.ovpn` `cert user.pem` és `key user.pem` sorral, a `user.pem`-ben tanúsítvány és titkosított privát kulcs: az import hiba nélkül lefut, az „Importálva, beágyazva” lista a `user.pem`-et egyszer mutatja
- [ ] A szerkesztőben a `<cert>` blokkban csak `CERTIFICATE`, a `<key>` blokkban csak a kulcs van
- [ ] Csatlakozáskor a MacVPN kéri a **Privát kulcs jelszava** értékét; jó jelszóval felépül a kapcsolat, rossz jelszóval érthető hiba
- [ ] Ugyanez Windowson készült (CRLF) fájllal

## Csapatkatalógusok (1.3)

Automatikus: a `scripts/build-dmg.sh` release gate-je (az `mvpn`-ben nincs `MVPNCAT1` és `macvpn-catalog-v1`) és a smoke teszt katalógus módja (`catalog.js`, `publish.js`). Két valódi Mac kell: **A** (rendszergazda, közzétevő) és **B** (felhasználó, feliratkozó), mindkettőn MacVPN 2.0.0; egy SMB-megosztás, amelyet mindkettő csatol; egy általad üzemeltetett HTTPS-szerver (érvényes tanúsítvánnyal, a naplója olvasható, bearer tokent tud kérni). Példanevek: „Acme VPN”, „Office AD”, `vpn.example.com`.

### A: aláírókulcs és közzététel
- [ ] **Közzététel** → **Adminisztrátori aláírókulcs létrehozása** → az ujjlenyomat 8 csoportban, a **Másolás** működik
- [ ] **Tartalék aláírókulcs létrehozása** → **Tartalék kulcs exportálása…**: 10 karakternél rövidebb jelszó elutasítva; a `.macvpnadminkey` `600`; a „törlés erről a Macről” jelölővel a tartalék kulcs csak a fájl megírása után tűnik el a listából
- [ ] **Katalógus közzététele…**: egy OpenVPN (`auth-user-pass`, egy „Office AD” közös hitelesítő adathoz kötve), egy L2TP (mentett PSK-val) és egy SSTP kapcsolat egy színes almappában; a rendszer VPN-ek és más katalógus kapcsolatai nem választhatók
- [ ] Titkok lépés: alapból semmi nincs bejelölve; az L2TP PSK bejelölésekor a figyelmeztetés („Mindenki, akinél megvan a csapatkulcs, elolvashatja ezt a titkot”); egy OpenVPN `<tls-crypt>` blokk külön jelölendő tételként jelenik meg
- [ ] Egy WireGuard kapcsolat `PrivateKey`-jel: a varázsló a „mindenki ugyanazt a WireGuard kulcsot használja” jelölés nélkül nem enged tovább; egy inline `<auth-user-pass>` blokkos OpenVPN config elutasítva, a varázsló megnevezi
- [ ] A közös belépési adatok helyei lépésben az „Office AD” bejelölve, felhasználónév és jelszó nélkül
- [ ] Mentés az SMB-megosztásra `Acme VPN.macvpncatalog` néven → a fájl `644`; `grep -a -c 'vpn.example.com\|Office AD\|auth-user-pass' <fájl>` → 0 (a tartalom titkosított)
- [ ] A csapatkulcs **egyszer** jelenik meg: **Másolás**, **Elmentettem**, a kért csoport beírása; rossz csoportra nem lép tovább; utána a kulcs sehol nem látható
- [ ] Vágólap: futó vágólapkezelővel (pl. Maccy) a csapatkulcs, a feliratkozási kód és a helyreállítási kulcs **Másolás**a után a kezelő nem rögzíti (rejtett, átmeneti típus), egy másik, azonos Apple ID-s eszközre nem kerül át (Universal Clipboard); **Zárolás most** vagy kilépés után a vágólap üres, de ha közben mást másoltál, az megmarad; egy perc után magától is üres
- [ ] **Feliratkozási kód másolása** → mesterjelszót kér (hibásra lassít, mint a feloldás), a forrás megadása után a vágólapon `macvpn-sub:…`, a képernyőn sehol
- [ ] Ugyanez a katalógus a HTTPS-szerverre is felkerül (a fájl feltöltve), bearer tokent kérő helyre
- [ ] A forráskapcsolatok A-n szerkeszthetők maradnak, rajtuk „Közzétéve: „Acme VPN” (v1)”; egy config módosítása után „módosult a legutóbbi közzététel óta”, a közzétételek listájában „1 módosult”
- [ ] A naplókban (`~/Library/Logs`, debug kimenet) nincs csapatkulcs, feliratkozási kód, config sor vagy jelszó, csak események („published v1”)

### B: feliratkozás fájlmegosztáson át
- [ ] **Csapatkatalógusok** → **Csapatkatalógus hozzáadása…** → a feliratkozási kód beillesztése: a forrás és az ujjlenyomat kitöltődik, a csapatkulcs nem látszik
- [ ] Egy levelezőprogramból több sorba tört kód → elutasítva; egy karakterében elírt csapatkulcs → elírásként jelzett, nem „rossz kulcs”
- [ ] **Ellenőrzés** → az előnézet: név, v1, ujjlenyomat, 3 kapcsolat, 1 mappa, az „Office AD” hely; az ujjlenyomatot **telefonon** vetettük össze A-val
- [ ] Egy rossz ujjlenyomattal → „A katalógust más kulcs írta alá, mint amelynek az ujjlenyomatát megadtad.”, semmi nem tárolódik; ujjlenyomat nélkül nem lehet feliratkozni
- [ ] **Feliratkozás** → „Acme VPN” mappa **Csapat** jelvénnyel, benne a színes almappa; a menüben is
- [ ] A szerkesztőben a név, a config, a mappa és a szín le van tiltva („A(z) „Acme VPN” csapatkatalógus kezeli”); a kitűzés, a saját szín („A csapat színének használata” visszaállítja) és a mappa csukása működik
- [ ] Első csatlakozás az OpenVPN-nel → a bekérő ablak: „Office AD („Acme VPN” csapatkatalógus) — …”, **Mentés a széfbe** → a **Hitelesítő adatok** részben az „Office AD” kitöltve; a második, ugyanezt a helyet használó kapcsolat kérdés nélkül csatlakozik
- [ ] Az L2TP profil telepítése egyszer kér jóváhagyást; a fióknév a hely felhasználóneve
- [ ] Az SSTP kapcsolat a hely felhasználónevével jelentkezik be (szerveroldali napló), a tárolt config `user=` sora nem változott
- [ ] **Másolat saját kapcsolatként…** → „<név> (saját)” a legfelső szinten, szerkeszthető, nincs Csapat jelvény; a katalógus kapcsolata változatlan

### B: feliratkozás HTTPS-en át, tokennel
- [ ] Második feliratkozás a HTTPS-forrásra a tokennel (egy másik katalógussal, vagy az elsőről leiratkozva) → működik; token nélkül „hozzáférés megtagadva (ellenőrizd a hozzáférési tokent)”
- [ ] Egy **Frissítés most** alatt `ps -ww -o args= -p $(pgrep -n curl)` → a token nem szerepel
- [ ] A szerver naplójában a változatlan frissítéseknél `304`
- [ ] A forrás átírása másik hostra a **Forrás szerkesztése…** ablakban → a tárolt token törlődik, az ablak kéri az újat; a régi host naplójában ezután nincs token az új címre irányuló kéréseknél
- [ ] Egy `http://`-re átirányító URL → „átirányítás nem HTTPS-címre”; nem megbízható tanúsítvány → „a tanúsítvány nem megbízható”
- [ ] Beállított rendszerproxy mellett (és `https_proxy` a környezetben) a proxy naplójában nincs kérés: a MacVPN közvetlenül kapcsolódik, vagy „nem érhető el”

### Frissítés: v2 egy törölt kapcsolattal
- [ ] B-n az SSTP kapcsolat fennáll; A-n az OpenVPN átnevezve, az SSTP törölve a kiválasztásból, egy új kapcsolat felvéve → **Új verzió közzététele** ugyanoda
- [ ] B: **Frissítés most** → értesítés: „A(z) „Acme VPN” csapatkatalógus frissült: 1 hozzáadva, 1 módosítva, 1 eltávolítva”
- [ ] Az SSTP fent marad, átkerül a katalógus legfelső mappájába, rajta „Törölve a csapatkatalógusból — a bontás után eltűnik”; bontás után eltűnik a kitűzésével együtt
- [ ] Az átnevezett OpenVPN kitűzése, saját színe és a kitöltött hely megmaradt
- [ ] Egy fennálló kapcsolat configját változtató verzió → a kapcsolat fent marad, az új config a következő csatlakozáskor él; ha kockázatos direktíva változott, a csatlakozás előtt újra kéri a jóváhagyást
- [ ] Ugyanaz a fájl újra feltöltve (azonos verzió) → nincs értesítés, nincs változás
- [ ] B altatva 20 percre, közben A közzéteszi a v3-at; B ébresztése után **Frissítés most** nélkül megjön

### Visszaléptetés elutasítása
- [ ] A v1 fájlt a v3 helyére másolva (megosztás és HTTPS is) → B: **Frissítés most** → „A(z) „Acme VPN” csapatkatalógus régebbi verziót kínált (v1 a v3 után), ezért nem lett alkalmazva.” egyszer; a kapcsolatok változatlanok; további frissítéseknél nincs újabb értesítés ugyanarra a verzióra
- [ ] Egy bájtjában módosított fájl → „A csapatkatalógus aláírása érvénytelen: módosították.”, a kapcsolatok változatlanok
- [ ] A jó fájl visszatéve, vagy A egy újabb verziót tesz közzé → B rendben frissül

### Csapatkulcs cseréje
- [ ] A: **Csapatkulcs cseréje** → a magyarázat kimondja, hogy ez az egyetlen visszavonási mód; a fájlhely megerősítése után az új verzió kiírva, az új kulcs egyszer látszik
- [ ] B: frissítés után „A(z) „Acme VPN” csapatkulcsa megváltozott. Kérd el a rendszergazdától az új kulcsot.” egyszer; az állapot „A csapatkulcs nem nyitja meg ezt a katalógust…”; a kapcsolatok változatlanok
- [ ] B: **Csapatkulcs cseréje…** → az új csapatkulcs → a következő frissítés alkalmazza
- [ ] A régi kulccsal (egy harmadik, régi kulcsos feliratkozás vagy sandbox) az új fájl nem nyílik meg

### Váltás a tartalék kulcsra
- [ ] A: **Aláírókulcs importálása…** a `.macvpnadminkey` fájllal (rossz jelszó → általános hibaüzenet) → **Váltás a tartalék kulcsra** → új verzió közzététele
- [ ] B (a tartalék kulcs létrehozása óta frissített): újrafeliratkozás nélkül követi, a feliratkozásnál az új ujjlenyomat látszik; egy ezután a régi kulccsal aláírt fájl → „A csapatkatalógust más közzétevő írta alá, mint akiben megbízol.”

### Leiratkozás
- [ ] Egy fennálló katalóguskapcsolattal **Leiratkozás** → a megerősítés megnevezi a katalógust és a kapcsolatok számát; a fennálló kapcsolat előbb bontódik
- [ ] Utána a katalógus mappája és kapcsolatai eltűntek; a kitöltött „Office AD” megmaradt a **Hitelesítő adatok** részben, a ki nem töltött helyek törlődtek
- [ ] Újrafeliratkozás ugyanarra a katalógusra → ugyanazok a kapcsolatok, de egy párosított app nem kap hozzájuk automatikusan hozzáférést

### Mentés és visszaállítás feliratkozással
- [ ] B: **Teljes biztonsági mentés…**; A: ugyanez az aláírókulccsal és a közzétételekkel
- [ ] B mentése egy friss felhasználói fiókban visszaállítva → a feliratkozás visszajön; az első frissítés újra létrehozza a kapcsolatokat a kitöltött „Office AD”-vel, a kitűzésekkel és a sorrenddel; nem kér újra felhasználónevet
- [ ] Egy régebbi mentés összefésülése → az alkalmazott verzió nem csökken (egy régi fájl ezután is elutasítva)
- [ ] Ugyanez **Minden cseréje** móddal: egy régebbi 1.3-as mentés (v2 alkalmazva) a v3-at alkalmazó B-n → az alkalmazott verzió v3 marad, a v2 fájl ezután is elutasítva
- [ ] A-n (közzétevő) **Minden cseréje** egy 1.2-es mentéssel → a megerősítés megnevezi a törlődő feliratkozásokat, az aláírókulcsokat és a közzétételeket nem; utána az aláírókulcs ujjlenyomata és minden közzététel megvan, a következő közzététel a régi tagoknál gond nélkül megjön
- [ ] A-n **Minden cseréje** egy régebbi 1.3-as mentéssel, amelyben más elsődleges aláírókulcs van → a megerősítés „A mentésben lévőre cserélt aláírókulcsok: 1”-et ír; utána a mentés kulcsa az elsődleges, a közzétételek verziója nem csökkent
- [ ] Egy 1.3-as széfről az 1.2-vel készített mentés összefésülése B-n **Felülírás** móddal → a katalógus kapcsolatai és mappái nem változnak, az eredmény felsorolja őket („Ezeket egy csapatkatalógus adja…”)
- [ ] A mentése egy friss fiókban → az aláírókulcs ujjlenyomata és a közzétételek megvannak; a következő közzététel a régi tagoknál gond nélkül megjön
- [ ] Egy 1.2.0-s app a v2-es mentést elutasítja („újabb MacVPN készítette”)

### Vezérlő API katalóguskapcsolattal
- [ ] B-n egy párosított app (példakliens): a katalógus egyik kapcsolatát engedélyezve `$BIN list` → megjelenik az azonosítójával; `$BIN hold <id>` → csatlakozik, a bekérő ablak a MacVPN-ben jelenik meg, ha a hely nincs kitöltve
- [ ] A kapcsolat törlése a katalógusból (új verzió) vagy leiratkozás → az app engedélyezett kapcsolatai közül eltűnik; `$BIN list` már nem mutatja
- [ ] Az azonosító a verziók között nem változik (`$BIN list` v2 előtt és után)

### Fájlforrás-ellenőrzések (a spike kézi lépései)
Lásd `docs/superpowers/spikes/2026-10-19-catalog-spike.md`, „Manual checks for the maintainer”. Az eredményeket a spike riportba is írd be; ha egy errno nincs a B2 listán, jelezd.

- [ ] **SMB:** a katalógus a megosztáson; `stat -f '%d %i %z %m' <fájl>` feljegyezve; a fájl lecserélve egy másik Macről (atomikus átnevezés), újra `stat`; B frissítése megtalálja a változást
- [ ] **SMB, leállított szerver:** a szerver hálózatát lekapcsolva `time python3 -c 'import os;os.open("<fájl>", os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)'` és `time cat <fájl>` → errno: \__\_, idő: \__\_; B-n „nem érhető el”, nincs értesítésözön, a menü közben is reagál (legfeljebb 20 s-os olvasás a háttérben); a szerver visszakapcsolása után a következő frissítés rendben
- [ ] **NFS vagy AFP** (ha van): ugyanaz, mint az SMB-nél
- [ ] **Le nem csatolt megosztás** (`/Volumes/<név>` nincs) → „nem érhető el”, nem hiba
- [ ] **iCloud Drive:** a katalógus egy iCloud-mappában, Finderben „Letöltés eltávolítása”; online az `open` letölti (blokkol? meddig: \__\_); offline: errno \__\_; B-n „nem érhető el”, értesítés nélkül
- [ ] **OneDrive:** csak online elérhető fájl, ugyanaz, mint az iCloudnál; errno/idő: \__\_
- [ ] **Dropbox:** csak online elérhető fájl, ugyanaz; errno/idő: \__\_
- [ ] Egy szinkronizálási ütközés vagy egy régi példány visszaállítása a felhőben → B-n a régebbi verzióra figyelmeztet, nem alkalmazza
- [ ] A forrásfájl helyén symlink, illetve egy könyvtár → „nem szabályos fájl” jellegű hiba, a symlink célja nem olvasódik be
- [ ] **Élő HTTPS teszt:** `MACVPN_CATALOG_TEST_URL=https://… cargo test -p macvpn-platform-mac --test catalog_http -- --ignored` érvényes tanúsítvánnyal sikeres; `http://`-re átirányító szerverbeállítással elutasít

### Nyelv
- [ ] Angol felülettel (`-AppleLanguages '(en)'`) a Csapatkatalógusok, a Közzététel, a varázsló és az értesítések szövegei angolul; magyarral magyarul, „csapatkatalógus”, „csapatkulcs”, „ujjlenyomat”, „közzétevő” szóhasználattal

## Széf, mappák, közös hitelesítő adatok, mentés (1.2)

Automatikus: a `scripts/build-dmg.sh` „release gate (SQLCipher with CommonCrypto, no OpenSSL; no SQLite in mvpn)” lépése mindkét architektúrára. A tesztet valódi adatokkal végezd; az 1.1-es adatok átköltöztetése a „Frissítés régebbi MacVPN-ről” részben van.

### Csomag
- [ ] A bundle-ben ott van a `THIRD-PARTY-NOTICES.txt`, benne az SQLCipher BSD-licence (Zetetic LLC) és az MIT-értesítések; a repóban ott van a `LICENSE`
- [ ] `otool -L /Applications/MacVPN.app/Contents/MacOS/MacVPN` nem listáz `libcrypto`/`libssl`/`openssl` könyvtárat; `grep -a -c sqlcipher …/root/mvpn` = 0

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
- [ ] Egy újabb kiadás (2.0.1 vagy újabb, ha megjelent; különben **nem tesztelhető**) telepítése frissítésként, bekapcsolt automatikus feloldással: a macOS legfeljebb **egyszer** kérdez (a `local.macvpn.vault` miatt); **ténylegesen: ___**; kikapcsolt automatikus feloldással egyszer sem

### Eltávolítás
- [ ] „A felhasználói adatok törlése is” jelöléssel: a `vault.db`, a `vault.keys`, a `local.macvpn.vault` bejegyzés és a maradék `local.macvpn.secrets` bejegyzések is törlődnek; jelölés nélkül megmaradnak, és újratelepítés után a széf megnyílik
- [ ] A felületen tárolt titkokra a „széf” szó szerepel, nem a „Keychain” (a Keychain csak a széfkulcsnál és a macOS kérdéseinél)

### Opcionális: natív L2TP/Cisco profil PSK nélkül
- [ ] A `docs/superpowers/spikes/2026-10-19-vault-spike.md` D.3 lépései (alapállapot a System keychainben csak nevekkel, PSK nélküli profil telepítése, indítás a MacVPN-ből és a Rendszerbeállításokból, takarítás); az eredmény feljegyezve, és ha mindkét indítás működik mindkét típussal, a „PSK only at start” ág mehet

## Frissítés régebbi MacVPN-ről (csak ha van régi telepítés)

A 2.0.0 a régebbi adatokat is átveszi. Ezekhez egy tesztfiók vagy egy második Mac kell a régi verzióval (a DMG-k a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalon); a frissítés után a root réteg mindig 9 (**Engedélyezés**, egy admin jelszó). Az 1.5 → 2.0 frissítés a „2.0.0 – új funkciók” részben van.

### 1.2-es széfből (séma v1 → v2)
- [ ] Az 1.2.0 telepítése és a széf feltöltése, majd frissítés 2.0.0-ra, bekapcsolt automatikus feloldással: a macOS legfeljebb **egyszer** kérdez (a `local.macvpn.vault` miatt); **ténylegesen: ___**; kikapcsolt automatikus feloldással egyszer sem
- [ ] Az első indítás után a `vault.db` mellett ott a `vault.db.bak-v1` (`600`); minden kapcsolat, mappa, közös hitelesítő adat és titok megvan. Futó app mellett a `vault.db-wal` és a `vault.db-shm` is ott lehet (`600`): ezek a SQLite naplófájljai, a `vault.db` részei; a `shasum` összevetés előtt lépj ki a MacVPN-ből, hogy a napló beíródjon
- [ ] Az 1.2.0 visszatelepítve a v2-es széfet írásvédetten nyitja meg (csatlakozik, szerkeszteni nem enged), a `vault.db` nem változik (`shasum` előtte és utána); utána újra 2.0.0

### 1.1-es adatokból (széf nélkül)
- [ ] Az 1.1.0-ban: legalább egy kapcsolat típusonként, egy kitűzött kapcsolat, egy rendszer VPN OTP-beállítással és mentett PSK-val, egy párosított app, bekapcsolt „Indítás bejelentkezéskor”
- [ ] Kilépés az 1.1.0-ból, majd `cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.1.0`; a Keychain `local.macvpn.secrets` bejegyzéseinek száma feljegyezve (`security dump-keychain | grep -c local.macvpn.secrets`, csak nevek, **soha `-d`**)
- [ ] A 2.0.0 telepítése (a DMG-ből, vagy az 1.1.0 **Frissítések keresése most** gombjával) → a Rendszerállapot „Frissítés szükséges (7 → 9)”; **Engedélyezés** után „Telepítve (verzió 9)”; addig az OpenVPN-, WireGuard-, IKEv2- és SSTP-kapcsolatok szürkék, az L2TP, a Cisco IPsec és a rendszer VPN-ek működnek
- [ ] Induláskor megnyílik a „Széf beállítása” ablak; jelzi az átköltöztetést és a várható Keychain kérdések számát („legfeljebb N alkalommal”); N egyezik a feljegyzett bejegyzésszámmal
- [ ] 10 karakternél rövidebb mesterjelszó → „Túl rövid”, a „Széf létrehozása” tiltva; eltérő ismétlés → „A két jelszó nem egyezik”; az erősségjelzés változik
- [ ] A helyreállítási kulcs `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` alakú; „Másolás” → „Kimásolva”; rossz csoport → „Ez nem a helyreállítási kulcs N. csoportja”; jó csoport → tovább
- [ ] Átköltöztetés közben a Keychain kérdések: **a ténylegesen megjelent kérdések száma: ___** (≤ N); mindegyik a MacVPN-t és a `/Applications/MacVPN.app`-ot nevezi meg; „Mindig engedélyez”
- [ ] Eredmény: „Az adataid a széfben vannak”, a kapcsolatok és titkok száma helyes; nincs „nem olvasható” elem
- [ ] Utána: a régi kapcsolatmappák és a `connection-order.json` eltűnt, van `vault.db` és `vault.keys` (0600, a mappa 0700); a `local.macvpn.secrets` bejegyzések törlődtek, egy `local.macvpn.vault` / `dek` bejegyzés van
- [ ] Megmaradt: kitűzés és sorrend, rendszer VPN OTP-beállítás és PSK, a párosított app (újra kapcsolódik), „Indítás bejelentkezéskor”, frissítési beállítások
- [ ] Hibaág (külön profilon / sandboxban): egy olvashatatlan elemmel vagy megszakított átköltöztetéssel → „Az átköltöztetés nem fejeződött be”, semmi sem törlődött; a menüben „Az átköltöztetés a széfbe nem fejeződött be. Újrapróbálás…” sáv; csatlakozni lehet, szerkeszteni nem („…írásvédetten használja…”); „Újra” új mesterjelszóval sikerül (a migrációs ablakot a smoke teszt `vault-create.js` része is végigjárja, sandboxban)
