# MacVPN – felhasználói útmutató

[English version](user-guide.en.md)

A MacVPN egy menüsor-alkalmazás macOS-re (14 vagy újabb, Apple processzoros vagy Intel Mac). Egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec és Cisco IPsec kapcsolatokat. Itt importálhatod és szerkesztheted a configokat, mappákba rendezheted őket, és minden kapcsolatnak van élő naplója. A kapcsolatok és jelszavaik egy titkosított széfben vannak. Ez az útmutató az 1.2-es verziót írja le (lásd: [Újdonságok az 1.2-ben](#újdonságok-az-12-ben)). A menü **Súgó** pontja ezt nyitja meg.

Rövid, lépésenkénti leírások: [Hogyan használd](how-to.hu.md). Ez az útmutató a teljes referencia. Ha fejlesztőként azt szeretnéd, hogy egy másik program ezen a Macen fel- és lekapcsolhassa a MacVPN kapcsolatait (**Párosított appok** a Kapcsolatok ablakban), olvasd el a [vezérlő API leírását](control-api.hu.md).

> **Nyelv:** a MacVPN a macOS nyelvi beállítását követi (Rendszerbeállítások → Általános → Nyelv és régió, illetve az appra beállított nyelv). Magyarul és angolul érhető el; ha a preferált nyelvek között egyik sincs, angolul jelenik meg. Ez az útmutató a magyar feliratokat használja, az [angol útmutató](user-guide.en.md) az angolokat.

## Újdonságok az 1.2-ben

- **Titkosított széf.** A kapcsolataid, a jelszavaik és a MacVPN többi adata mostantól egyetlen titkosított fájlban, a széfben vannak, amelyet mesterjelszó véd. Ha elfelejted a jelszót, a helyreállítási kulccsal juthatsz vissza. Az **Automatikus feloldás** (alapból be van kapcsolva) mellett a MacVPN kérdés nélkül megnyílik; a **Széf zárolása most** azonnal zárol. Lásd [11.](#11-széf)
- **Átállás az 1.1-ről.** Az 1.2 első indításakor a MacVPN a széfbe költözteti az 1.1-es kapcsolataidat és mentett jelszavaidat, ellenőrzi őket, és csak ezután törli a régi példányokat. A macOS régi elemenként egyszer Keychain-hozzáférést kérhet. A root réteg 7-ről 8-ra vált, ehhez egyszer kell az admin jelszó. Előbb készíts mentést: lásd [8.2](#82-frissítés-11-ről).
- **Mappák és színek.** A kapcsolatokat és a rendszer VPN-eket egymásba ágyazható mappákba rendezheted, a mappáknak és a kapcsolatoknak 12 szín közül adhatsz színt, és húzással oda teheted őket, ahová akarod. Lásd [12.](#12-mappák-és-színek)
- **Közös hitelesítő adatok.** Egy felhasználónév és jelszó, amelyet több kapcsolat használ. Elég egyszer módosítani, és minden kapcsolat, amely használja, az újjal jelentkezik be. Lásd [13.](#13-közös-hitelesítő-adatok)
- **Teljes biztonsági mentés és visszaállítás.** A **Teljes biztonsági mentés…** egyetlen titkosított fájlba írja az összes kapcsolatot, titkot, mappát és közös hitelesítő adatot; a **Visszaállítás biztonsági mentésből…** ezen vagy egy új Macen visszahozza. Lásd [14.](#14-biztonsági-mentés-és-visszaállítás)
- **Hitelesítő adatok bekérése.** A jelölőnégyzet neve mostantól **Mentés a széfbe**. Az EAP-bejelentkezéses IKEv2 elutasított jelszó után egyszer újra kérdez, mint az OpenVPN és az SSTP. Lásd [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor).
- **Licencek.** Az app csomagjában van egy `THIRD-PARTY-NOTICES.txt` a MacVPN-nel szállított összetevők (köztük az SQLCipher) licenceivel.

## Újdonságok az 1.1-ben

- **Más appok is vezérelhetik a VPN-eket (vezérlő API).** Alapból ki van kapcsolva. A felhasználói fiókod egy általad párosított programja, például egy Remote Desktop app, fel- és lekapcsolhatja az általad engedélyezett kapcsolatokat; a VPN csak addig marad fenn, amíg a programnak kell. Lásd [5.4](#54-párosított-appok-vezérlő-api), fejlesztőknek pedig [a vezérlő API leírását](control-api.hu.md).
- **Hitelesítő adatok bekérése csatlakozáskor.** A szükséges, de el nem mentett felhasználónevet, jelszót, PSK-t vagy kulcsjelszót csatlakozás előtt bekéri, csak a sikeres csatlakozás után menti (vagy egyáltalán nem), és elutasított bejelentkezésnél egyszer újra kérdez. Lásd [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor).
- **Élő rendszer-VPN lista.** A Rendszerbeállításokban felvett, átnevezett vagy törölt VPN újranyitás nélkül megjelenik a menüben és a Kapcsolatok ablakban. Lásd [3.5](#35-rendszer-vpn-ek-közös-kulcs-l2tp--cisco-esetén).
- **Új megjelenés.** A menü, a Kapcsolatok ablak, a Rendszerállapot, a Frissítés és a bekérő ablakok lekerekített kártyákat használnak. Minden kapcsolatnak színes buboréka van a típusával és egy állapotjelvénnyel. Lásd [2](#2-első-indítás-és-a-rendszerállapot-ablak) és [5](#5-csatlakozás).
- **Dock ikon.** Amíg a Kapcsolatok, a Rendszerállapot vagy a Frissítés ablak nyitva van, a MacVPN a Dockban is megjelenik, így Cmd+Tabbal is elérhető. Lásd [2](#2-első-indítás-és-a-rendszerállapot-ablak).
- A root réteg nem változott (7-es verzió): az 1.0-ról frissítve nem kell admin jelszó.

## Tartalom

1. [Telepítés](#1-telepítés)
2. [Első indítás és a Rendszerállapot ablak](#2-első-indítás-és-a-rendszerállapot-ablak)
3. [Kapcsolatok felvétele típusonként](#3-kapcsolatok-felvétele-típusonként)
4. [Import és export](#4-import-és-export)
5. [Csatlakozás](#5-csatlakozás)
6. [Debug mód és a napló](#6-debug-mód-és-a-napló)
7. [Hibaelhárítás a napló alapján](#7-hibaelhárítás-a-napló-alapján)
8. [Frissítés](#8-frissítés) ([Frissítés 0.x verzióról](#81-frissítés-0x-verzióról), [Frissítés 1.1-ről](#82-frissítés-11-ről))
9. [Eltávolítás](#9-eltávolítás)
10. [Biztonsági megjegyzések](#10-biztonsági-megjegyzések)
11. [Széf](#11-széf)
12. [Mappák és színek](#12-mappák-és-színek)
13. [Közös hitelesítő adatok](#13-közös-hitelesítő-adatok)
14. [Biztonsági mentés és visszaállítás](#14-biztonsági-mentés-és-visszaállítás)
15. [Gyakori kérdések a széfről](#15-gyakori-kérdések-a-széfről)

---

## 1. Telepítés

### 1.1 A DMG letöltése

1. Töltsd le a legfrissebb `MacVPN-x.y.z.dmg` fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Nyisd meg a DMG-t, és húzd a **MacVPN** ikont az **Applications** mappára.
3. Dobd ki (Eject) a DMG-t a Finderben.

### 1.2 Az első indítás engedélyezése (Gatekeeper)

Az app ad-hoc aláírású (hardened runtime-mal), nincs Apple Developer ID-vel aláírva és notarizálva, ezért az első indításkor a macOS letiltja („nem nyitható meg, mert az Apple nem tudja ellenőrizni…”). Engedélyezése:

**macOS 14:**

1. Nyisd meg a Finderben az Applications mappát.
2. Kattints a Control billentyűvel (vagy jobb gombbal) a **MacVPN**-re, és válaszd a **Megnyitás** pontot.
3. A megjelenő ablakban kattints a **Megnyitás** gombra.

**macOS 15 és újabb** (itt a Control+kattintás már nem működik):

1. Indítsd el egyszer a MacVPN-t az Applications mappából. Zárd be a figyelmeztetést (**Kész** vagy **OK**).
2. Nyisd meg: **Rendszerbeállítások → Adatvédelem és biztonság**.
3. Görgess le a **Biztonság** részhez. Ott ezt látod: „A(z) MacVPN blokkolva lett…”. Kattints a **Megnyitás mindenképp** gombra.
4. Add meg a jelszavadat, majd a megjelenő ablakban kattints újra a **Megnyitás mindenképp** gombra.

Ezt csak egyszer kell megtenni. A későbbi frissítések az appon belül települnek (lásd [8. fejezet](#8-frissítés)).

### 1.3 Homebrew és a VPN-eszközök

Az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokhoz a MacVPN a [Homebrew](https://brew.sh) csomagkezelőből telepített eszközöket használja. Ezeket a Rendszerállapot ablakból telepítheted (lásd a következő fejezetet).

| Típus | Homebrew csomag | Eszközök, amelyeket a MacVPN keres |
|---|---|---|
| OpenVPN | `openvpn` | `openvpn` |
| WireGuard | `wireguard-tools`, `bash` | `wg`, `wg-quick`, `wireguard-go`, `bash` (4-es vagy újabb, a `wg-quick`-hez) |
| IKEv2 (strongSwan) | `strongswan` | `swanctl`, `charon` |
| SSTP | `sstp-client` | `sstpc` (és a macOS beépített `pppd`-je) |
| L2TP/IPsec, Cisco IPsec | nincs | a macOS beépített VPN-je |

Ha már van Homebrew-d, Terminálban egyszerre is telepítheted mindet:

```
brew install openvpn wireguard-tools strongswan sstp-client bash
```

Ha egy eszköz hiányzik, csak az adott típusú kapcsolatok szürkülnek ki, a többi típus működik.

---

## 2. Első indítás és a Rendszerállapot ablak

Indítás után a MacVPN a menüsorban egy pajzs ikonként jelenik meg. Amíg valamelyik ablaka (Kapcsolatok, Rendszerállapot vagy Frissítés) nyitva van, a Dockban is megjelenik az ikonja, így Cmd+Tabbal vagy az ikonra kattintva előhozhatod az ablakot; az utolsó ilyen ablak bezárásakor az ikon eltűnik.

- **szürke pajzs:** nincs aktív kapcsolat
- **pajzs pipával:** van aktív kapcsolat
- **pajzs felkiáltójellel:** hiba (sikertelen csatlakozás, vagy az állapot nem kérdezhető le)
- **kulcs:** egy kapcsolat hitelesítésre vár (lásd [5.2](#52-többfaktoros-hitelesítés-mfa))

Az ikonra kattintva nyílik meg a menü. Minden kapcsolat egy kártya a típusa színes buborékával, a nevével, a típusával és az állapotával, valamint egy kapcsolóval (lásd [5](#5-csatlakozás)); sok kapcsolatnál a lista görgethető. A mappák nyitható-csukható sorokként jelennek meg (lásd [12.](#12-mappák-és-színek)). A kártyák alatt:

- három csempe: **Új kapcsolat / Import…**, **Kapcsolatok kezelése…** és **Rendszerállapot**;
- a **Beállítások** csoport (kattintásra nyílik és csukódik): **Frissítések automatikus keresése**, **Csak a legalább 24 órája megjelent frissítések felajánlása**, **Frissítések keresése most** és **Indítás bejelentkezéskor**; utána a széf beállításai: **Automatikus feloldás**, **„Széf zárolása most” megjelenítése**, **Mesterjelszó módosítása…** és **Új helyreállítási kulcs…** (lásd [11.](#11-széf)), végül **Teljes biztonsági mentés…** és **Visszaállítás biztonsági mentésből…** (lásd [14.](#14-biztonsági-mentés-és-visszaállítás));
- **Súgó** (ezt az útmutatót nyitja meg), **Széf zárolása most** (ha látszik, lásd [11.4](#114-széf-zárolása-most)) és **Kilépés**.

Amíg a széf zárolva van, a menüben csak egy **Széf feloldása…** sor, az aktív kapcsolatok száma és a **Kilépés** látszik (lásd [11.5](#115-a-zárolt-menü)). Amíg a széf nem létezik, a sor felirata **Széf beállítása…**.

Ha van frissítés, a **Frissítés elérhető: vX.Y.Z** sáv is megjelenik. Az alján egy emlékeztető: **Option+kattintás a kapcsolón: debug mód**.

Ha valami hiányzik, induláskor automatikusan megnyílik a **Rendszerállapot** ablak. Bármikor megnyithatod a menüből is (**Rendszerállapot**). Három ellenőrzést mutat, mindegyik zöld vagy piros:

1. **Homebrew.** Ha hiányzik, a **Telepítés…** gomb Terminált nyit a hivatalos telepítővel. A telepítő a rendszergazdai jelszavadat kéri. Ha a telepítő nem tölthető le, a Terminál ablak ezt kiírja, és semmit nem futtat. Ha végzett, térj vissza, és nyomd meg az **Újraellenőrzés** gombot.
2. **VPN eszközök.** A hiányzó eszközök listája mellett a **Telepítés** gomb lefuttatja a `brew install` parancsot. A kimenet élőben látszik az ablakban. A telepítés akkor is folytatódik, ha közben bezárod az ablakot.
3. **Jogosultság (root scriptek + sudoers).** Az **Engedélyezés** gomb egyszer kéri az admin jelszót. Telepíti a MacVPN root rétegét: az egyetlen root binárist, a `/usr/local/libexec/macvpn/mvpn`-t a `VERSION` fájljával (a MacVPN 1.2-ben 8-as root réteg), valamint a `/etc/sudoers.d/macvpn` szabályt. Ezután a csatlakozás és a bontás jelszó nélkül működik. Ha naprakész, a sorban **Telepítve (verzió 8)** áll. Ha egy app-frissítés újabb root réteget hoz, **Frissítés szükséges (7 → 8)** jelenik meg (a telepített és az új verzióval); ha egy fájl hiányzik, **Hiányos telepítés**. Ilyenkor nyomd meg újra az **Engedélyezés** gombot. Ha van aktív kapcsolat, az ablak előbb figyelmeztet: **A rendszerkomponens frissítése bontja az aktív VPN-kapcsolatokat.**

Ha mindhárom zöld, kész a telepítés. Az L2TP és a Cisco IPsec ezek nélkül is működik.

### 2.1 Indítás bejelentkezéskor

A MacVPN alapból nem indul el magától. Ha minden bejelentkezéskor el szeretnéd indítani, jelöld be az **Indítás bejelentkezéskor** négyzetet a menü **Beállítások** csoportjában vagy a **Rendszerállapot** ablakban. Kikapcsolni a jelölés törlésével lehet. A négyzet azt mutatja, amit a macOS jelez, így a **Rendszerbeállítások → Általános → Bejelentkezési elemek** alatt végzett változásokat is követi.

- Ha a macOS jóváhagyást kér, megjegyzés jelenik meg: „Engedélyezd a MacVPN-t a Rendszerbeállítások → Általános → Bejelentkezési elemek alatt.” A **Bejelentkezési elemek beállításai…** gomb megnyitja ezt az oldalt. Ott kapcsold be a MacVPN-t.
- A MacVPN nincs Apple Developer ID-val aláírva, ezért a macOS gyakran nem tudja a szokásos módon regisztrálni. Ilyenkor a MacVPN helyette egy kis bejelentkezési LaunchAgentet hoz létre (`~/Library/LaunchAgents/local.macvpn.launcher.plist`, amely az `open -b local.macvpn` parancsot futtatja). A négyzet bejelölve marad, alatta a megjegyzés: „Bejelentkezési LaunchAgenttel bekapcsolva (a következő bejelentkezéstől érvényes).” A MacVPN ilyenkor nem indul el azonnal, csak a következő bejelentkezéskor. A LaunchAgent a bundle azonosító alapján nyitja meg az appot, így az app áthelyezése után is működik. A **Rendszerbeállítások → Általános → Bejelentkezési elemek** alatt a **Háttérben való futás engedélyezése** listában is megjelenhet. A jelölés törlése (vagy az eltávolítás) törli a fájlt.
- Ha a bekapcsolás egyik módon sem sikerül, egy riasztás mutatja az okát, és a négyzet jelöletlen marad.
- A négyzet nem kattintható, ha a MacVPN nem az Alkalmazások mappából (`/Applications` vagy `~/Applications`) fut, például közvetlenül a DMG-ről vagy a Letöltések mappából. Húzd az appot az Alkalmazások mappába, onnan nyisd meg, és próbáld újra.

---

## 3. Kapcsolatok felvétele típusonként

Kapcsolatot a **Kapcsolatok** ablakban veszel fel. Megnyitása: menü → **Kapcsolatok kezelése…** vagy **Új kapcsolat / Import…**.

- Bal oldalt a lista: a MacVPN-ben létrehozott kapcsolatok és a **rendszer VPN-ek** (a macOS-ben máshonnan beállított VPN-ek, a nevük alatt **Rendszer-VPN** jelöléssel) egy fában, a mappáiddal együtt, minden mappában a kitűzöttek felül (lásd [5.1](#51-a-kapcsolatok-sorrendje) és [12.](#12-mappák-és-színek)). A lista alatt a **Hitelesítő adatok** (lásd [13.](#13-közös-hitelesítő-adatok)) és a **Párosított appok** (lásd [5.4](#54-párosított-appok-vezérlő-api)) található. A rendszer VPN-eket csak indítani és bontani lehet. L2TP és Cisco IPsec rendszer VPN-nél a közös kulcsot (PSK) is eltárolhatod a MacVPN-ben (lásd [3.5](#35-rendszer-vpn-ek-közös-kulcs-l2tp--cisco-esetén)).
- Az eszköztár **Új** (+) menüjéből választhatsz típust (OpenVPN, WireGuard, IKEv2, SSTP, L2TP, Cisco IPsec), **Új mappa** vagy **Import fájlból…** pontot. Ugyanitt van a **Teljes biztonsági mentés…** és a **Visszaállítás biztonsági mentésből…** is (lásd [14.](#14-biztonsági-mentés-és-visszaállítás)). Az új kapcsolat sablonnal és „Új OpenVPN”-hez hasonló névvel indul; a névmezőben átnevezheted.
- A kijelölt kapcsolat fejlécében van a **Csatlakozás** / **Bontás**, a **Csatlakozás debug módban**, az export ikon és a törlés ikon (**Törlés**, megerősítéssel). Alatta két fül: **Beállítások** és **Napló**.
- Ha az állapot nem kérdezhető le (például hiányzik a root réteg), az ablak tetején figyelmeztető sáv jelenik meg egy **Rendszerállapot** gombbal.

A szöveges típusoknál (OpenVPN, WireGuard, IKEv2) monospace szerkesztő van. A **Mentés** (⌘S) előbb ellenőrzi a configot. Ha hibát talál, a szerkesztő alatt pirosan, sorszámmal sorolja fel őket (például `3. sor: Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort`), és a mentés nem történik meg. A kockázatos OpenVPN beállítások már gépelés közben megjelennek egy sárga panelen (lásd [3.1](#31-openvpn)). A jelszavak külön mezőkben vannak, a **Hitelesítés** részben. Ezek a MacVPN titkosított széfjébe kerülnek, nem a configba. Ahol a kapcsolat felhasználónévvel és jelszóval jelentkezik be, a **Jelszó forrása** választóval a **Saját felhasználónév és jelszó** és egy közös hitelesítő adat között választhatsz (lásd [13.](#13-közös-hitelesítő-adatok)).

Az SSTP-nek, az L2TP-nek és a Cisco IPsec-nek szöveges szerkesztő helyett űrlapja van (lásd [3.4](#34-l2tpipsec-és-cisco-ipsec) és [3.6](#36-sstp)).

**A mentett jelszavak sosem látszanak.** Ha egy jelszómezőnek van mentett értéke, a mezőben **Mentve – írj be újat a cseréhez** áll. Ha nem nyúlsz hozzá, a mentett érték marad; ha beírsz valamit, lecseréli; a **Mentett jelszó törlése** gombbal és mentéssel törölheted. A szerkesztő alatti állapotsor **Nem mentett változások** vagy **Mentve: <idő>** szöveget mutat.

Ha nem mentett változással váltasz kapcsolatot vagy zárod be az ablakot, az app rákérdez: **Mentés**, **Elvetés** vagy **Mégse**.

### 3.1 OpenVPN

A legegyszerűbb, ha a szolgáltatótól kapott `.ovpn` fájlt importálod (**Új → Import fájlból…**, vagy húzd a fájlt a listára).

- Ha a `.ovpn` külső fájlokra hivatkozik (például `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), az import a `.ovpn` mellől beolvassa és beágyazza őket (`<ca>…</ca>` blokkokba). Ezért importálás előtt a fájlok legyenek a `.ovpn` mellett. Ha egy fájl hiányzik, az import hibát jelez.
- Ha a szerver felhasználónevet és jelszót kér (`auth-user-pass` sor), töltsd ki a **Felhasználónév** és **Jelszó** mezőket.
- Ha a privát kulcs jelszóval védett (jelszavas PKCS#12 fájl, vagy titkosított PEM kulcs: `-----BEGIN ENCRYPTED PRIVATE KEY-----` vagy `Proc-Type: 4,ENCRYPTED`), add meg a **Privát kulcs jelszava** mezőben. A széfbe kerül, és az OpenVPN csak csatlakozáskor kapja meg.
- A MacVPN minden direktívát három szintbe sorol (a teljes lista: [openvpn-directives.md](openvpn-directives.md)):
  - Az **engedett** direktívák a megszokott módon működnek, például `setenv CONFIG_VERSION "2.0.4"`, `remap-usr1 SIGTERM`, `pull-filter`, `machine-readable-output`.
  - A **kockázatos beállítások** (például `user nobody`, `group nogroup`, `route-noexec`, szerveroldali vagy csak Windowson működő opciók, és minden direktíva, amelyet a MacVPN nem ismer) egy sárga **Kockázatos beállítások** panelen jelennek meg, mindegyik rövid indoklással. Mentéshez és csatlakozáshoz jelöld be: **Tudomásul veszem a beállításokat és a biztonsági kockázatokat**. A tudomásulvétel pontosan a mentéskor jelen lévő kockázatos direktívákra szól: ha később újat adsz hozzá, újra be kell jelölnöd.
  - A **tiltott** direktívák, például `up`, `down`, `script-security`, `plugin`, `log`, `chroot` és `echo`, sosem engedettek (külső scriptet futtatnának, kódot töltenének be, rootként olvasnának vagy írnának fájlt, vagy a MacVPN saját beállításait írnák felül). A DNS-t a MacVPN maga állítja be. Részletek a [7.7 fejezetben](#77-nem-engedélyezett-direktíva--tiltott-direktíva).
- `user` / `group` mellett az OpenVPN a kapcsolódás után eldobja a root jogot: tegyél a configba `persist-tun` sort, hogy az újracsatlakozás működjön. A DNS-t a MacVPN-ben való bontás állítja vissza; ha az OpenVPN magától lép ki, bontsd a kapcsolatot a MacVPN-ben.
- Az engedélyezett direktívák argumentumait is ellenőrzi: például a `dev` csak `tun`, `tap` vagy `utunN` lehet, a port és az időzítők számok, a hosztnév és a titkosító neve nem tartalmazhat `/` jelet, és nem kezdődhet `-` jellel. A `<connection>` blokkok használhatók, a soraik ugyanezen az ellenőrzésen mennek át.

### 3.2 WireGuard

Importáld a `.conf` fájlt, vagy hozz létre újat (**Új → WireGuard**), és töltsd ki a sablont:

```
[Interface]
PrivateKey = <a te privát kulcsod>
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <a szerver nyilvános kulcsa>
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
```

- Az `AllowedIPs = 0.0.0.0/0` minden forgalmat a VPN-re küld. Ha csak egy belső hálózatot akarsz elérni, add meg azt (például `10.10.0.0/16`).
- A `PreUp`, `PostUp`, `PreDown`, `PostDown` és `SaveConfig` kulcs nem engedett.
- Az értékeket is ellenőrzi: a kulcsok 44 karakteres base64 szövegek, az `Address`/`AllowedIPs` IP-címek opcionális prefixszel (`10.0.0.2/32`), az `Endpoint` `hoszt:port` vagy `[IPv6]:port`, az `MTU`/`ListenPort`/`PersistentKeepalive` számok. Egyik érték sem kezdődhet `-` jellel.
- A WireGuard-hoz nem kell felhasználónév és jelszó, a hitelesítés a kulcspárral történik.

### 3.3 IKEv2 (strongSwan)

Az IKEv2 configot strongSwan `swanctl.conf` szintaxisban kell megadni. Új kapcsolatnál (**Új → IKEv2**) egy sablon jelenik meg. Felhasználónév és jelszó (EAP-MSCHAPv2) esetén:

```
connections {
  iroda {
    remote_addrs = vpn.example.com
    vips = 0.0.0.0
    local {
      auth = eap-mschapv2
      eap_id = kovacs.janos
    }
    remote {
      auth = pubkey
      id = vpn.example.com
    }
    children {
      iroda {
        remote_ts = 0.0.0.0/0
      }
    }
  }
}
```

- A **Felhasználónév** mező értéke egyezzen az `eap_id`-val, a jelszót a **Jelszó** mezőbe írd. Ezek nem kerülnek a configba, a MacVPN csatlakozáskor adja hozzá őket egy `secrets` blokkban.
- Ha a szerver előre megosztott kulcsot (PSK) használ, mindkét oldalon `auth = psk` legyen, a kulcs pedig a **Pre-shared key (PSK)** mezőbe kerül.
- Ha a szerver tanúsítványát nem egy általánosan ismert hitelesítő írta alá, a CA tanúsítványát a strongSwan tanúsítványkönyvtárába kell tenni (Homebrew alatt általában `/opt/homebrew/etc/swanctl/x509ca/`). Ebben kérd az üzemeltető segítségét.
- Az `include`, az `updown` és a fájlra hivatkozó `secrets` (`file = …`) nem engedett.
- Csak a dokumentált `swanctl.conf` kulcsok fogadhatók el, mindegyik a saját szakaszában. A `certs`, `cacerts`, `cacert` és `pubkeys` értéke csak sima fájlnév lehet (`/` és `..` nélkül); a strongSwan a saját tanúsítványkönyvtáraiban keresi őket (például `x509ca/`). A `crl_uris`, az `ocsp_uris` és a `file:` URI nem engedett.

### 3.4 L2TP/IPsec és Cisco IPsec

Ezek a macOS beépített VPN-jét használják. A beállítás űrlapon történik (**Új → L2TP** vagy **Új → Cisco IPsec**):

- **Név**, **Szerver**, **Fióknév**, **Jelszó**, **Pre-shared key (PSK)**
- Cisco esetén a **Csoportnév (group name)** is
- **Minden forgalom a VPN-en keresztül**: ha be van kapcsolva, minden forgalom a VPN-en megy

**Profil jóváhagyása:** a **Mentés és profil telepítése** gomb egy konfigurációs profilt készít és nyit meg. A macOS ezt nem telepíti magától:

1. Nyisd meg: **Rendszerbeállítások → Általános → Eszközkezelés** (régebbi macOS-en: **Profilok**).
2. Kattints duplán a MacVPN profilra, majd a **Telepítés…** gombra, és add meg a jelszavadat.

Minden módosítás után újra jóvá kell hagyni a profilt. Kapcsolat törlésekor a MacVPN megnyitja a Profilok panelt, ahol a profilt neked kell eltávolítanod.

**Mi van a profilban.** A profil a szervert, a fióknevet és a PSK-t tartalmazza, a **jelszót nem**. MacVPN-ből csatlakozva az app a mentett PSK-t és jelszót közvetlenül átadja a macOS-nek, így a kapcsolat nem azon múlik, hogy a macOS megtalálja-e őket a Rendszer kulcskarikában. Ha a Rendszerbeállításokból indítod a VPN-t, a macOS rákérdez a jelszóra. A PSK azért marad a profilban, mert nélküle a VPN szolgáltatás a Rendszerbeállításokból nem működne.

A profilfájl egy privát ideiglenes mappába kerül (csak te olvashatod), nem a kapcsolatok mellé. A MacVPN törli, amint a VPN megjelenik a macOS-ben, legkésőbb a MacVPN következő indításakor. Ha ennél később hagyod jóvá a profilt, kattints újra a **Mentés és profil telepítése** gombra. A régebbi MacVPN verziók a kapcsolat mappájában tartottak egy `profile.mobileconfig` fájlt (benne a jelszóval); ezeket a MacVPN induláskor törli.

**A macOS szolgáltatás azonosítása.** A profil telepítése után a MacVPN megjegyzi a macOS VPN szolgáltatás azonosítóját (azonos nevű és szervercímű szolgáltatás), és onnantól ezzel csatlakozik, bont és kérdezi le az állapotot. Egy véletlenül azonos nevű másik VPN így rendszer VPN-ként (**Rendszer-VPN** jelöléssel) jelenik meg a listában. Ha a MacVPN nem tudja eldönteni, hogy több azonos nevű szolgáltatás közül melyik az övé, nem csatlakozik (és nem adja át a jelszót), hanem ezt írja ki: **Több „<név>” nevű VPN szolgáltatás van…**. Nevezd át vagy töröld a másikat a **Rendszerbeállítások → Hálózat** alatt.

A **fióknév** a kapcsolat beállításaival tárolódik: nem titok, és a profilba is bekerül. A jelszó és a PSK a széfben van. Közös hitelesítő adatnál a fióknév csak a profilba kerül, a MacVPN a közös hitelesítő adattal jelentkezik be (lásd [13.](#13-közös-hitelesítő-adatok)).

### 3.5 Rendszer VPN-ek: közös kulcs L2TP / Cisco esetén

A Rendszerbeállításokban felvett VPN (például **Office L2TP**) **Rendszer-VPN** jelöléssel jelenik meg a listában. A MacVPN nem módosítja a beállításait. Előfordul, hogy a macOS nem tudja kiolvasni egy ilyen VPN közös kulcsát, ha másik alkalmazás indítja: a kapcsolat nem jön létre, és a macOS „a szerver nem érhető el” jellegű üzenetet mutathat, holott a Rendszerbeállításokból indítva működik.

L2TP és Cisco IPsec rendszer VPN-nél a részletező nézetben két mező van:

- **Közös kulcs (PSK)**
- **Jelszó (nem kötelező, ha nincs elmentve a macOS-ben)**

Kattints a **Mentés** gombra. A MacVPN széfjében tárolódnak (nem a VPN saját beállításaiban), és minden MacVPN-ből indított csatlakozáskor átadja őket a macOS-nek. A **Mentett titkok törlése** gomb törli őket. Üresen hagyott mező szintén törlődik.

Ha itt mentetlen módosítással váltasz vagy zárod be az ablakot, az app ugyanúgy rákérdez (**Mentés / Elvetés / Mégse**), mint a többi kapcsolatnál.

**A lista élő.** Ha a Rendszerbeállításokban (vagy egy profil telepítésével) VPN-t veszel fel, nevezel át vagy törölsz, a menü és a **Kapcsolatok** ablak újranyitás nélkül követi: általában egy másodpercen belül, legkésőbb 5 másodpercen belül, amíg a menü vagy egy MacVPN-ablak nyitva van (egyébként 30 másodpercen belül).

Ha egy rendszer VPN-t törölnek, miközben a részletező nézete látszik, a nézet megmarad **Ezt a VPN-t eltávolították a macOS-ből** sávval: a mezői és a **Csatlakozás**, **Mentés** és **Mentett titkok törlése** gomb le van tiltva. Másik kapcsolatot kiválasztva bezárul. A MacVPN-ben mentett közös kulcs és jelszó nem törlődik, így ha ugyanaz a VPN visszakerül, újra érvényes. Ha már nincs rájuk szükség, a VPN Rendszerbeállításokban való törlése előtt kattints a **Mentett titkok törlése** gombra (a felhasználói adatokkal együtt végzett eltávolítás is törli őket, lásd [9](#9-eltávolítás)).

### 3.6 SSTP

Az SSTP (Secure Socket Tunneling Protocol, a Microsoft HTTPS fölötti VPN-je, 443-as port) a root rétegen fut, a Homebrew `sstp-client` csomag (`sstpc`) és a macOS beépített `pppd`-je segítségével. Az `sstp-client` csomagot a **Rendszerállapot** ablakból telepítheted (vagy `brew install sstp-client`).

Létrehozás: **Új → SSTP**, vagy importálj egy `.sstp` fájlt. Szöveges szerkesztő helyett űrlapja van:

- **Név**, **Szerver** (hosztnév vagy IPv4/IPv6 cím, port nélkül), **Port** (alapból 443). IPv6 címre csatlakozást valódi szerverrel még nem teszteltünk; inkább a hosztnevet add meg.
- **Felhasználónév** és **Jelszó**. A jelszó a széfbe kerül. `DOMAIN\user` helyett `user@domain` formát használj: a felhasználónévben nem lehet fordított perjel, szóköz és idézőjel. **Az SSTP jelszóban nem lehet idézőjel (`"`), fordított perjel (`\`) és vezérlőkarakter**: az `sstpc` a jelszót escape nélkül adja át a `pppd`-nek, így ezek a karakterek a `pppd` beállításait módosíthatnák. Az űrlap ilyenkor hibát jelez, és nem ment; szükség esetén változtasd meg a jelszót a szerveren.
- **Szervertanúsítvány**:
  - **Rendszer CA**: a szerver tanúsítványát ismert hitelesítő kell, hogy aláírja. Ez a Homebrew OpenSSL CA-tanúsítványait használja, nem a macOS kulcskarikát, így egy csak a kulcskarikába telepített céges CA itt nem számít megbízhatónak.
  - **Saját CA fájl**: a **PEM fájl kiválasztása…** gomb betölti a CA tanúsítványt (`-----BEGIN CERTIFICATE-----`). A kapcsolat configjában tárolódik. Bináris (DER) `.cer` fájlt előbb alakíts PEM-re, például: `openssl x509 -inform der -in ca.cer -out ca.pem`.
  - **Nincs ellenőrzés**: a szerver tanúsítványát semmi nem ellenőrzi (pirossal jelölve). Bárki, aki közted és a szerver között van, kiadhatja magát a szervernek, és megszerezheti a bejelentkezési adataidat. Csak tesztelésre használd.
- **Minden forgalom a VPN-en keresztül** (alapból be): minden IPv4 forgalom a VPN-en megy. Kikapcsolva csak a VPN túloldalának címe megy rajta.
- **A szerver DNS-ének használata** (alapból be): a szerver által küldött DNS-szerverek a kapcsolat idejére minden hálózati szolgáltatáson beállítódnak, bontáskor visszaállnak (ugyanúgy, mint OpenVPN-nél).

A hitelesítés MS-CHAPv2, felhasználónévvel és jelszóval. A PAP, CHAP és EAP tiltott, így tanúsítványos (EAP-TLS) belépés nem támogatott.

A config (és a `.sstp` export) egyszerű `kulcs=érték` szöveg, jelszó nélkül:

```
server=vpn.example.com
port=443
user=kovacs.janos@ceg.example
cert=system
route_all=yes
peer_dns=yes
```

`cert=ca` mellett a CA tanúsítvány egy `<ca>…</ca>` blokkban következik.

---

## 4. Import és export

**Import.** **Új → Import fájlból…** (több fájlt is kijelölhetsz), vagy húzz egy vagy több fájlt a Kapcsolatok ablakba (az üres ablakban ez áll: **Vagy húzz ide egy .ovpn / .conf / .sstp fájlt.**). Minden fájl legfeljebb 1 MB-os, szabályos UTF-8 szövegfájl legyen. A típust a kiterjesztés és a tartalom alapján ismeri fel:

- `.ovpn`, vagy `client` / `dev tun` + `remote` sor → OpenVPN
- `[Interface]` + `PrivateKey` → WireGuard
- `connections {` → IKEv2 (strongSwan)
- `.sstp`, vagy `server=…` sor + `user=`, `cert=`, `route_all=` vagy `peer_dns=` sor → SSTP

Ha egy fájl nem ismerhető fel vagy nem importálható, a többi fájl attól még importálódik. A hibákat egy közös ablak sorolja fel.

**Más fájlokra hivatkozó OpenVPN configok** (`ca ca.crt`, `tls-auth ta.key 1`, …): a MacVPN a hivatkozott fájlokat inline blokként beemeli a configba, és az import után felsorolja őket, például **Importálva, beemelt fájlok: ca.crt, ta.key**. Biztonsági okból a hivatkozott fájlt csak akkor olvassa be, ha:

- az `.ovpn` fájl mappájában (vagy annak almappájában) van. A `../` útvonalakat, a mappán kívülre mutató abszolút útvonalakat és symlinkeket elutasítja: **A hivatkozott fájl a config mappáján kívül van**;
- legfeljebb 1 MB;
- a tartalma megfelel a direktívának: `ca`, `cert`, `extra-certs` → PEM tanúsítvány; `key` → PEM privát kulcs (`-----BEGIN … PRIVATE KEY-----`); `tls-auth`, `tls-crypt`, `secret` → OpenVPN statikus kulcs (`-----BEGIN OpenVPN Static key V1-----`); `tls-crypt-v2` → tls-crypt-v2 kliens kulcs; `dh` → DH paraméterek. Különben: **A(z) … direktíva fájlja (…) nem a várt formátumú**.

A `pkcs12 client.p12` fájlt ugyanígy beemeli, base64-ként egy `<pkcs12>` blokkba (PKCS#12 fájl legyen, a mappán belül, legfeljebb 1 MB). Ha jelszavas, az import után add meg a **Privát kulcs jelszava** mezőben. Az `auth-user-pass` mellett megadott felhasználónév/jelszó fájl (például `auth-user-pass auth.cfg`) sosem kerül a configba: ha a mappán belül van, legfeljebb 1 KB, és pontosan két sora van (felhasználónév, jelszó), a MacVPN megkérdezi: **Használod a(z) … fájlban lévő hitelesítő adatokat ehhez a kapcsolathoz?**; **Használat** esetén a kapcsolat **Felhasználónév** és **Jelszó** mezőjébe (a széfbe) teszi, és ezt az import üzenete jelzi; különben add meg kézzel. Az `askpass pass.txt` fájlt ugyanígy a **Privát kulcs jelszava** mezőbe teszi. Ha a privát kulcs titkosított, az import üzenete emlékeztet a **Privát kulcs jelszava** kitöltésére.

**MikroTik RouterOS.** A RouterOS v7 exportja (`/interface ovpn-server server export-client-config`) és a klasszikus v6 wiki szerinti configok (a `.ovpn` mellett `ca.crt`, `client.crt`, titkosított `client.key` és `auth-user-pass auth.cfg`) hiba és kockázatos beállítás nélkül importálódnak. A kulcs export-jelszavát add meg a **Privát kulcs jelszava** mezőben.

**Az importált config ellenőrzése.** Az importált configot a MacVPN rögtön ugyanazokkal a szabályokkal ellenőrzi, mint a **Mentés**. Ha hibás, attól még importálódik, és a szerkesztője pirossal jelölt hibalistával nyílik meg, így javíthatod és mentheted. Ha kockázatos beállítást tartalmaz, az import üzenete jelzi (**Importálva. Kockázatos beállításokat tartalmaz (…)**), a szerkesztő pedig a sárga **Kockázatos beállítások** panelen mutatja: csatlakozás előtt jelöld be a négyzetet, és mentsd.

**Export.** A kapcsolat fejlécében az export ikon (**Exportálás… (jelszavak sosem kerülnek bele)**) az eredeti formátumban menti ki a configot: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, `.sstp`, natív kapcsolatnál `.mobileconfig`.

- A jelszó, a PSK és a felhasználónév **nem** kerül az exportba. A natív profilban ezek üresen maradnak. Az SSTP felhasználónév a config része, ezért benne van a `.sstp` exportban; a jelszó nincs.
- **Privát kulcsok:** a config részét képező kulcsok viszont belekerülhetnek. Ha a configban OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<pkcs12>`, `<auth-user-pass>` vagy `<http-proxy-user-pass>` blokk, WireGuard `PrivateKey` / `PresharedKey`, vagy strongSwan `secrets` szakasz van, a MacVPN figyelmeztet (**A config privát kulcsokat vagy hitelesítő adatokat tartalmaz**), és három lehetőséget ad: **Exportálás kulcsok nélkül** (alapértelmezett: ezek az OpenVPN blokkok és a strongSwan `secrets` szakasz kimarad, a WireGuard kulcsok üresen maradnak), **Exportálás kulcsokkal**, vagy **Mégse**. Aki a kulcsokat birtokolja, a te nevedben csatlakozhat: csak akkor exportáld őket, ha a címzettnek szüksége van rájuk, és a fájlt megbízható helyen tartsd.
- Az exportált fájl `600`-as jogosultsággal jön létre (csak te olvashatod).
- **Mappa és közös hitelesítő adat.** Ha a kapcsolat mappában van, vagy közös hitelesítő adatot használ, a szöveges export (`.ovpn`, `.conf`, `.swanctl.conf`, `.sstp`) egy megjegyzéssorral kezdődik, például `# macvpn-meta: {"folder":["Munka","Ügyfelek"],"credentialName":"Iroda AD"}`. Ebben csak ezek a nevek vannak, titok soha. Importáláskor a MacVPN létrehozza a hiányzó mappákat, és oda teszi a kapcsolatot (ha egy mappa nem hozható létre, a kapcsolat a legfelső szintre kerül, és az üzenet ezt jelzi). A `credentialName` sosem kapcsolódik csendben: a MacVPN előbb rákérdez, és megnevezi a szervert (lásd [13.4](#134-import-és-export)). Az ilyen sor nélküli fájlok a legfelső szintre kerülnek, mint eddig. A `.mobileconfig` exportban nincs ilyen sor.
- Mindennek a jelszavakkal együtt történő mentése egy másik funkció: lásd [14.](#14-biztonsági-mentés-és-visszaállítás)
- A `.ovpn`, a WireGuard `.conf`, a `.swanctl.conf` és a `.sstp` export visszaimportálható a MacVPN-be.
- A `.mobileconfig` export (L2TP, Cisco IPSec) a MacVPN-be **nem** importálható. Másik Macen dupla kattintással nyisd meg a Finderben: a macOS profilként telepíti, utána a **Rendszerbeállítások → Általános → Eszközkezelés** (Profilok) alatt hagyd jóvá. Ha `.mobileconfig` fájlt próbálsz importálni a MacVPN-be, az app is ezt írja ki.

---

## 5. Csatlakozás

- **Menüből:** kattints a kapcsolat kártyáján a kapcsolóra. Az állapotot a típusbuborék jelvénye és a név alatti sor mutatja:
  - **zöld:** kapcsolódva (mellette az IP és az eltelt idő); a kapcsoló is zöld
  - **borostyánsárga, lüktet:** **Csatlakozás…** vagy **Bontás…** (a kapcsoló borostyánsárga), illetve **Hitelesítésre vár**: egyszer használatos kódra, böngészős bejelentkezésre vagy hiányzó hitelesítő adatokra (lásd [5.2](#52-többfaktoros-hitelesítés-mfa) és [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor))
  - **piros:** hiba (mellette a rövid ok)
  - **szürke:** nincs kapcsolat
  - **Használja: …** a kártyán: egy párosított app tartja fenn a kapcsolatot (lásd [5.4](#54-párosított-appok-vezérlő-api))
- **A Kapcsolatok ablakból:** **Csatlakozás** / **Bontás** gomb.
- Egyszerre több kapcsolat is aktív lehet.
- Ha egy típushoz hiányzik eszköz, a kapcsolat kiszürkül, és a **Hiányzó eszköz** felirat jelenik meg rajta. Ilyenkor nézd meg a **Rendszerállapot** ablakot.
- **Értesítések.** Sikertelen csatlakozásnál macOS értesítés jelenik meg („…: sikertelen csatlakozás”, **Részletek a MacVPN-ben** szöveggel). Maga a hibaüzenet nem kerül az értesítésbe, mert az a lezárt képernyőn is látszhat; a teljes ok a MacVPN-ben látszik. Kattintásra a kapcsolat a **Kapcsolatok** ablakban, a **Napló** fülön nyílik meg. Akkor is értesítés jön, ha egy élő kapcsolat váratlanul megszakad („…: a kapcsolat megszakadt”), és ha egy kapcsolat kódra vagy bejelentkezésre vár („…: hitelesítés szükséges”; kattintásra előjön a kódbekérő ablak). Az értesítésekhez a macOS egyszer engedélyt kér. Automatikus újracsatlakozás nincs.
- **Kilépéskor** (**Kilépés**, ⌘Q, valamint kijelentkezés, újraindítás vagy leállítás) a MacVPN előbb a Kapcsolatok ablak nem mentett változásaira kérdez rá (**Mentés**, **Elvetés** vagy **Mégse**). Utána, ha van aktív kapcsolat, megkérdezi: **Leállítás és kilépés**, **Kilépés, fussanak tovább** vagy **Mégse**. A Mégse esetén a MacVPN fut tovább (és a kijelentkezés megszakad). A tovább futó kapcsolatokat a MacVPN következő indításkor felismeri.

### 5.1 A kapcsolatok sorrendje

A menü és a **Kapcsolatok** ablak listája ugyanazt a sorrendet használja. A MacVPN-ben létrehozott kapcsolatok és a rendszer VPN-ek közös rangsorban vannak. Mappák esetén ugyanezek a szabályok érvényesek minden mappán belül, az almappák után (lásd [12.3](#123-sorrend-egy-mappán-belül)).

- **Elöl a kitűzött kapcsolatok**, a te sorrendedben. Kitűzéshez kattints jobb gombbal a kapcsolatra a **Kapcsolatok** ablakban, és válaszd a **Kitűzés** pontot; levenni a **Kitűzés megszüntetése** ponttal lehet. Ha egy kitűzött kapcsolatot ugyanannak a mappának egy másik kitűzött kapcsolatára húzol, a sorrendjük megváltozik. A kitűzött kapcsolatok mellett kis gombostű ikon látszik, a menüben is.
- **Utánuk a többi, a leggyakrabban használt elöl.** Minden sikeres, a MacVPN-ből indított csatlakozás 1 pontot ér. A pontok értéke 14 naponta a felére csökken, így egy múlt hónapban sokat használt kapcsolat hátrébb kerül annál, amit most használsz. Csak a kapcsolat létrejöttének pillanata számít: a fennálló kapcsolat állapotlekérdezései és a MacVPN-en kívül (például a Rendszerbeállításokban) indított kapcsolatok nem. Az azonos pontszámú kapcsolatok (például az új, még pont nélküliek) név szerint követik egymást.
- A sorrend a széfben tárolódik (az 1.1-ig a `connection-order.json` fájlban). Az egyes kapcsolatok exportja nem viszi, a teljes biztonsági mentés igen. Ha törölsz egy kapcsolatot, a bejegyzése is törlődik.

### 5.2 Többfaktoros hitelesítés (MFA)

A MacVPN kezeli az egyszer használatos kódokat (OTP, TOTP, token PIN) és a böngészős bejelentkezést (SAML / SSO, push jóváhagyás). A kód soha nem tárolódik, és nem kerül a naplóba.

**A kódbekérő ablak.** Ha kód kell, egy kis ablak nyílik meg a kapcsolat nevével, a szerver (vagy a config) kérdésével, egy **Kód** mezővel, **Mégse** és **Tovább** gombbal. A mező elrejti a beírt kódot, hacsak a szerver nem kéri a megjelenítését. Az ablak 2 perc után lejár, ilyenkor a csatlakozás **A hitelesítés nem fejeződött be időben** hibával ér véget. Amíg a MacVPN vár, a menüben a kapcsolat sorában **Hitelesítésre vár** áll, és a menüsor ikonja kulcs lesz. Az ablak nem veszi el a billentyűzetet attól az apptól, amelyikben éppen dolgozol: értesítés is jön („…: hitelesítés szükséges”); a kód beírásához kattints az értesítésre vagy az ablakra. A szervertől jövő szöveg **A VPN-szerver üzenete:** címkét kap. A megjelenés utáni kb. egy másodpercben az ablak nem fogad bevitelt, így egy véletlen leütés nem válaszol rá. Bontáskor az ablak bezárul, és a csatlakozás leáll.

**OpenVPN: automatikus.** Nincs mit beállítani:

- **Statikus challenge** (`static-challenge "…" 0|1` a configban): a MacVPN csatlakozás előtt bekéri a kódot a config szövegével, és a jelszóval együtt küldi a szervernek (SCRV1 formában, vagy egyszerűen a jelszó végére fűzve, ha a configban `concat` áll).
- **A szerver által küldött challenge** (dinamikus `CRV1` challenge vagy szöveges challenge): a kódbekérő ablak csatlakozás közben nyílik meg, a szerver szövegével.
- **Bejelentkezés a böngészőben** (`OPEN_URL`, `WEB_AUTH`: SAML, SSO, push): a MacVPN megmutatja a cím hosztját (egyszerű ASCII alakban, kisbetűvel) és a teljes címet, és rákérdez: **Megnyitás a böngészőben** (ez nem alapértelmezett gomb: kattints rá). Csak `https://` címet nyit meg, minden más címet figyelmen kívül hagy. A bejelentkezés (vagy a push jóváhagyása a telefonon) után a kapcsolat felépül. A MacVPN legfeljebb 5 percig vár (vagy a szerver rövidebb határidejéig).

**Minden típus: kód a jelszó végén.** Egyes szerverek a jelszó után beírt kódot várják (például `jelszó123456` vagy `jelszó,123456`). A kapcsolat beállításainál kapcsold be: **Egyszer használatos kód kérése csatlakozáskor, a jelszó végére fűzve**, és válaszd ki az **Elválasztó**t: nincs, `,` vagy `:`. OpenVPN, IKEv2, SSTP, L2TP és Cisco IPsec kapcsolatnál érhető el, valamint L2TP / Cisco IPsec rendszer VPN-eknél (a részletező nézetükben, a **Kapcsolatok** ablakban). Csatlakozáskor a MacVPN bekéri a kódot, és jelszó + elválasztó + kód formában küldi. Ha a MacVPN-ben nincs mentett jelszó, jelszóként csak a kód megy át. SSTP-nél a kóddal együtt sem lehet a jelszóban `"`, `\` vagy vezérlőkarakter. `static-challenge`-es OpenVPN confignál a beállítás nem érvényes, mert a statikus challenge már viszi a kódot.

**Hogyan működik (OpenVPN).** A MacVPN az OpenVPN-t a management interfészével indítja, egy csak root által elérhető socketen. Ehhez csak a MacVPN root segédje (a root `mvpn` bináris `mgmt-bridge` alparancsa; a folyamatlistában `mvpn-mgmt` néven látszik) csatlakozik, rögzített parancslistával. A segéd csak a kérdést, a `https` címet és az állapotot adja át az appnak (a `/var/run/macvpn-ui/<id>.json` fájlban, amit csak te olvashatsz), a válaszodat pedig az OpenVPN-nek.

### 5.3 Hitelesítő adatok bekérése csatlakozáskor

Ha egy kapcsolathoz felhasználónév, jelszó, közös kulcs (PSK) vagy privát kulcs jelszó kell, de nincs elmentve a MacVPN-ben, a MacVPN csatlakozás előtt bekéri egy kis **Hitelesítő adatok szükségesek** ablakban. Ehhez semmit nem kell beállítani.

- **Mikor jelenik meg:**
  - **OpenVPN:** a configban `auth-user-pass` van fájl és beágyazott `<auth-user-pass>` blokk nélkül, és nincs elmentve a felhasználónév vagy a jelszó. Titkosított privát kulcs, amelynek a jelszava nincs elmentve.
  - **IKEv2:** EAP bejelentkezés (`auth = eap…` a `local` szakaszban), és nincs elmentve a felhasználónév vagy a jelszó.
  - **SSTP:** nincs elmentve a jelszó (a felhasználónév a kapcsolat beállításai között van).
  - **A MacVPN-ben létrehozott L2TP / Cisco IPsec:** nincs elmentve a fiók, a jelszó vagy a közös kulcs.
  - **WireGuard,** tanúsítványos IKEv2 és a **rendszer VPN-ek** soha nem kérnek: egy rendszer VPN titkait a macOS a profilban is tárolhatja.
- **Az ablak** csak a hiányzó mezőket mutatja. Az elmentett felhasználónév ki van töltve. A **Mentés a széfbe** be van pipálva (**Titkosítva a MacVPN széfjében marad, a következő kapcsolódástól ezt használja**). Ha csak erre a csatlakozásra kell, vedd ki a pipát. Ha a kapcsolat olyan közös hitelesítő adatot használ, amelyhez nincs mentett jelszó, az ablak megnevezi (**A(z) Iroda AD jelszava — 4 kapcsolat használja**), és a **Mentés a széfbe** a közös hitelesítő adatba menti a jelszót, minden kapcsolat számára, amely használja.
- **Mentés csak a sikeres csatlakozás után.** Rossz jelszó soha nem kerül tárolásra.
- **Rossz felhasználónév vagy jelszó:** ha a szerver elutasítja a bejelentkezést (OpenVPN `AUTH_FAILED`, SSTP „rossz felhasználónév vagy jelszó”), az ablak **egyszer** újra megnyílik a **Sikertelen bejelentkezés — ellenőrizd a felhasználónevet és a jelszót** sorral, a felhasználónév kitöltve. A második hiba a szokásos hibával és értesítéssel ér véget. Az 1.2-től az EAP-bejelentkezéses IKEv2 is újra kérdez (a 8-as root réteg **Hitelesítési hiba (EAP)** üzenetet ad). Az L2TP és a Cisco IPsec nem kérdez újra: a macOS nem jelzi a rossz jelszót külön a többi hibától.
- **Mégse** (vagy Escape, vagy az ablak bezárása) hiba és értesítés nélkül leállítja a csatlakozást. Ha nyitott ablak mellett bontasz, az ablak bezárul. 2 perc után lejár, ez Mégsének számít.
- **Mint a kódbekérő,** nem veszi el a billentyűzetet a használt apptól: a gépeléshez kattints az ablakra vagy a „…: hitelesítő adatok szükségesek” értesítésre. Megjelenése után kb. egy másodpercig nem fogad bevitelt, és nincs alapértelmezett gombja: az Enter nem csinál semmit, a **Csatlakozás** gombra kell kattintani. Amíg nyitva van, a sor **Hitelesítésre vár** állapotú.
- **Ismert korlát:** a PKCS#12 csomagban (`<pkcs12>`) lévő privát kulcs jelszavát nem kéri be, mert a MacVPN nem tudja eldönteni, van-e ilyen. Mentsd el a kapcsolat szerkesztőjében (**Privát kulcs jelszava**).
- A beírt adat erre a csatlakozásra jut el a VPN-eszközhöz. A MacVPN használat után törli a saját másolatait; a rendszer útközben készült másolatait (a webes nézet és az app belső üzenetküldése) a MacVPN nem tudja törölni. A beírt adat soha nem kerül a naplóba. Egy vezérlő API kliens csak a `waiting_for_credentials` állapotot látja, és a `credentials_cancelled` hibát, ha megszakítod.

### 5.4 Párosított appok (vezérlő API)

A felhasználói fiókod egy másik programja, például egy Remote Desktop app, párosítás után fel- és lekapcsolhatja helyetted a MacVPN kapcsolatait. Alapból ki van kapcsolva.

1. Nyisd meg a **Kapcsolatok** ablakot (**Kapcsolatok kezelése…**), és az oldalsávban válaszd a **Párosított appok** pontot.
2. Kapcsold be: **Más appok vezérelhetik a VPN-eket**. Kikapcsolva egyetlen program sem érheti el így a MacVPN-t.
3. Indítsd el a párosítást a másik programban. A MacVPN megnyitja az **Engedélyezed, hogy egy app vezérelje a VPN-eket?** ablakot: **Név (a program saját megnevezése)** (a program maga választotta, így semmit nem bizonyít), a **Futtatható fájl** teljes útvonala, és a **Használható kapcsolatok**, kapcsolatonként egy jelölőnégyzettel, egyik sincs bejelölve. Ellenőrizd az útvonalat, jelöld be a kapcsolatokat, és kattints az **Engedélyezés** gombra. Az **Elutasítás**, az ablak bezárása vagy 2 perc válasz nélkül elutasítást jelent. A kódbekérőhöz hasonlóan nem veszi el a billentyűzetet, és kb. egy másodpercig nem fogad bevitelt.

Mit tehet egy párosított program:

- Csak az általad engedélyezett kapcsolatokat látja, és csak fel- és lekapcsolhatja őket. Configot, felhasználónevet és jelszót sosem lát. Ha egy kapcsolathoz kód vagy jelszó kell, azt a MacVPN a saját ablakaiban kérdezi meg tőled, mint a kézi csatlakozásnál.
- A VPN addig marad fenn, amíg a programnak kell, közben a kártyán **Használja: <név>** látszik. Ha a program bezárja a kapcsolatát a MacVPN-nel, kilép vagy összeomlik, a MacVPN bontja a VPN-t, kivéve ha az már a kérése előtt is fennállt, vagy egy másik app még használja.
- Ha te magad bontod a VPN-t, bontva marad; a programnak újra kérnie kell.

A **Párosított appok** alatt minden program látszik a futtatható fájl útvonalával, az **Utoljára használva** (vagy **Még nem használta**) és a **Párosítva:** idejével, és az **Engedélyezett kapcsolatok** listájával, amelyet bármikor módosíthatsz. A **Visszavonás** azonnal megszünteti a párosítást és a program munkameneteit; a csak általa felépített kapcsolatok lebomlanak. Ha a programot más útvonalra fordítod újra vagy áthelyezed, **Megváltozott az útvonal** jelenik meg: vond vissza, és párosítsd újra. A **Tevékenység** a legutóbbi párosításokat, bejelentkezéseket és foglalásokat mutatja (a **Mentés…** fájlba írja). Ha kilépsz a MacVPN-ből, miközben egy párosított app használ egy kapcsolatot, a kilépési kérdés megnevezi az appot.

Fejlesztőknek: a protokoll, a biztonsági modell és egy példakliens [a vezérlő API leírásában](control-api.hu.md) van.

---

## 6. Debug mód és a napló

Ha egy kapcsolat nem jön létre, a debug mód lépésről lépésre megmutatja, mi történt.

**Indítás:**

- a menüben **Option (⌥) + kattintás** a kapcsolón, vagy
- a Kapcsolatok ablakban a **Csatlakozás debug módban** gomb.

Ilyenkor a **Napló** fül automatikusan megnyílik, és élőben követi az eseményeket. A debug mód csak erre az egy csatlakozásra érvényes.

Debug módban:

- **OpenVPN:** bőbeszédűbb kimenet (`--verb 5`): TLS handshake, a szerver által küldött beállítások, route-ok, DNS.
- **WireGuard:** a `wg-quick` lépései, és csatlakozás után a `wg show` kimenete (handshake, átvitt bájtok, kulcsok nélkül).
- **IKEv2:** részletes IKE napló (IKE_SA_INIT, AUTH, CHILD_SA).
- **SSTP:** részletes `sstpc` napló (`--log-level 4`) és a `pppd` egyeztetése (`debug`): TLS, LCP, MS-CHAPv2 és IPCP. A jelszó itt is maszkolva marad, de az MS-CHAPv2 csere (challenge és válasz) benne van a naplóban, és ebből offline jelszótörés is megkísérelhető. A debug naplót óvatosan kezeld: csak a hálózati rendszergazdádnak add át, nyilvánosan soha ne oszd meg. A `pppd` sorai `[pppd]` előtaggal jelennek meg.
- **L2TP / Cisco:** a macOS VPN-folyamatainak naplója (legfeljebb 60 mp-ig, vagy amíg a kapcsolat létre nem jön). Ezeknél debug mód nélkül nincs napló.
- **Diagnosztika** csatlakozás előtt és után: a szerver nevének feloldása, a route tábla, a DNS állapot és az interfészek.

**A napló sorai, színkóddal:**

| Előtag | Jelentés |
|---|---|
| `═══` | új csatlakozás vagy bontás kezdete (dátummal) |
| `▶ [mvpn]` | a MacVPN saját lépései (config másolása, ellenőrzés, talált eszközök) |
| `$ …` | lefuttatott parancs (a jelszavak `***`-gal maszkolva) |
| `✗` | hiba |
| egyéb | az eszköz (openvpn, wg-quick, charon, sstpc, pppd) saját kimenete |

**A Napló fül** a kapcsolat naplójának utolsó 5000 sorát mutatja, és élőben követi, debug módon kívül is (az L2TP-nek és a Cisco IPsec-nek csak debug módban van naplója: **Natív kapcsolatnál csak debug csatlakozáskor van napló.**). Maguk a naplófájlok a `/var/log/macvpn` alatt vannak.

**Napló műveletek:** szűrés (**Minden**, **Parancsok**, **Hibák**), **Keresés**, **Követés** (automatikus görgetés), **Másolás** (a szűrt sorokat másolja), **Mentés…** (a naplót `<név>-naplo.txt` néven menti, csak te olvashatod). Jelszó, PSK és privát kulcs nem kerül a naplóba, így a mentett napló is megosztható (például a rendszergazdával). Kivétel az SSTP debug naplója, lásd fent.

---

## 7. Hibaelhárítás a napló alapján

Először nézd meg a hibaüzenetet a menüben vagy az értesítésben. Ha ez nem elég, csatlakozz debug módban, és keress a **Napló** fülön (a **Hibák** szűrő csak a hibasorokat mutatja).

### 7.1 `AUTH_FAILED` (OpenVPN)

Üzenet: **Hitelesítési hiba (AUTH_FAILED)**. A szerver elutasította a felhasználónevet vagy a jelszót.

- Ellenőrizd a **Felhasználónév** és **Jelszó** mezőket, majd nyomd meg a **Mentés** gombot.
- Lejárt vagy zárolt fiók esetén keresd a szolgáltatót.
- Ha a szerver egyszer használatos kódot kér, lásd az [5.2. fejezetet](#52-többfaktoros-hitelesítés-mfa) és a [7.11. fejezetet](#711-egyszer-használatos-kód-és-böngészős-bejelentkezés-mfa).

### 7.2 `TLS handshake failed` / `TLS Error` (OpenVPN)

A titkosított csatorna nem épült fel. Tipikus sor: `TLS Error: TLS key negotiation failed to occur within 60 seconds`.

- Rossz szervercím, port vagy protokoll (`proto udp` vagy `tcp`). Hasonlítsd össze a szolgáltató adataival.
- Tűzfal vagy szállodai, céges hálózat blokkolja a portot. Próbáld másik hálózatról.
- Nem egyező `<tls-auth>`, `<tls-crypt>` kulcs vagy `key-direction`, vagy rossz `<ca>`. Importáld újra a szolgáltató friss `.ovpn` fájlját.

### 7.3 Időtúllépés

Üzenet: **Időtúllépés: 30 mp alatt nem épült fel a kapcsolat** (natív kapcsolatnál: **Időtúllépés**). A kapcsolat 30 másodperc alatt nem jött létre, ezért a MacVPN leállította.

- Ellenőrizd az internetkapcsolatot és a szerver elérhetőségét. A debug napló diagnosztikája megmutatja, feloldható-e a szerver neve.
- Nézd meg a napló utolsó sorait: gyakran ott van a valódi ok (például TLS hiba vagy elérhetetlen szerver).

### 7.4 Nincs WireGuard handshake

A WireGuard kapcsolat zöldnek látszik (az interfész létrejött), de nincs forgalom. Debug módban a `wg show` kimenetében hiányzik a `latest handshake` sor, vagy a `received` értéke 0.

- Rossz `Endpoint` (cím vagy port), vagy a hálózat blokkolja az UDP-t.
- A `PublicKey` a `[Peer]` részben nem a szerver kulcsa, vagy a szerveren nincs felvéve a te nyilvános kulcsod.
- Az `AllowedIPs` nem fedi le a cél hálózatot.
- Bontsd a kapcsolatot, javítsd a configot, és csatlakozz újra.

### 7.5 IKE AUTH hiba (IKEv2)

Üzenet: **Az IKE egyeztetés sikertelen (részletek a naplóban)**. A naplóban tipikusan: `received AUTHENTICATION_FAILED notify error`, vagy `constraint check failed`.

- Rossz felhasználónév, jelszó vagy PSK. A **Felhasználónév** egyezzen az `eap_id`-val.
- A szerver azonosítója (`remote { id = … }`) nem egyezik a szerver tanúsítványában lévő névvel.
- A szerver tanúsítványát aláíró CA nincs meg (lásd [3.3](#33-ikev2-strongswan)).
- Eltérő `auth` mód (`eap-mschapv2`, `psk` vagy `pubkey`). Kérdezd meg a szerver üzemeltetőjét.

### 7.6 A profil nincs jóváhagyva (L2TP / Cisco)

Üzenet: **A profil nincs telepítve: <név>**. A macOS-ben még nincs telepítve a MacVPN által készített profil.

- Hagyd jóvá a **Rendszerbeállítások → Általános → Eszközkezelés** alatt (lásd [3.4](#34-l2tpipsec-és-cisco-ipsec)).
- Módosítás után a profilt újra jóvá kell hagyni.
- Ha az üzenet **A kapcsolat nem jött létre – részletek: debug csatlakozás**, csatlakozz debug módban, és nézd meg a `racoon` / `pppd` sorokat (tipikusan rossz PSK vagy jelszó).
- **Rendszer VPN** (például **Office L2TP**): az üzenet **A kapcsolat nem jött létre. Ha ez egy L2TP/IPsec VPN, add meg a közös kulcsát (PSK) itt: MacVPN → Kapcsolatok → <név>.** Add meg a PSK-t (és ha a macOS-ben nincs elmentve, a jelszót) a [3.5](#35-rendszer-vpn-ek-közös-kulcs-l2tp--cisco-esetén) szerint, majd csatlakozz újra. A rendszernaplóban ez az eset `L2TP: incorrect user shared secret found` sorként látszik.
- Ha már van mentett PSK, és az üzenet **A kapcsolat nem jött létre.**, ellenőrizd a PSK-t és a jelszót, valamint hogy a szerver elérhető-e.

### 7.7 „Nem engedélyezett direktíva” / „Tiltott direktíva”

Ilyen hibát a **Mentés** vagy a csatlakozás ad, például:

- `3. sor: Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort`
- `5. sor: Kockázatos direktíva, tudomásulvétel szükséges: user` (a beállítás a sárga **Kockázatos beállítások** panelen látszik)
- Csatlakozáskor: `A kockázatos beállítások nincsenek tudomásul véve: user. Nyisd meg a kapcsolatot a MacVPN → Kapcsolatok alatt, és jelöld be a négyzetet a Kockázatos beállítások résznél.`
- `6. sor: Nem engedélyezett setenv: LD_PRELOAD – töröld vagy tedd megjegyzésbe (#) a sort`
- `Külső fájl hivatkozás, inline blokk kell: ca`
- WireGuard: `Tiltott kulcs: postup`, `Nem engedélyezett kulcs: …`
- IKEv2: `Tiltott: include`, `Tiltott kulcs: updown`, `Csak fájlnév adható meg, útvonal nem: cacerts`
- Argumentumok: `4. sor: Érvénytelen argumentum: dev`, `8. sor: Hibás argumentumszám: keepalive`, WireGuard: `3. sor: Érvénytelen érték: address`

A MacVPN rootként indítja a VPN-eszközöket, ezért csak ismert, biztonságos beállításokat enged. Javítás:

- **Tiltott direktíva / kulcs** (például `up`, `down`, `script-security`, `PostUp`): ezek külső parancsot futtatnának. Töröld a sort, vagy tegyél elé `#` jelet. A DNS-t és a route-okat a MacVPN kezeli, ezekre a scriptekre nincs szükség.
- **Kockázatos direktíva, tudomásulvétel szükséges / nincsenek tudomásul véve:** a beállítás csak tudomásulvétel után engedett. Olvasd el az indoklást a sárga panelen; ha kell a beállítás, jelöld be a **Tudomásul veszem a beállításokat és a biztonsági kockázatokat** négyzetet és **Mentés**, különben tedd megjegyzésbe a sort. Ha a tudomásulvétel után új kockázatos sort adtál hozzá, jelöld be újra.
- **Nem engedélyezett setenv:** a változó neve befolyásolhatná a MacVPN root DNS-hookját (például `PATH`, `BASH_ENV`, `LD_*`, `DYLD_*`). Töröld a sort, a kapcsolathoz nem kell.
- **Érvénytelen argumentum** ismeretlen vagy kockázatos direktívánál: az argumentum nem tartalmazhat útvonalat (`/`, `..`, `~`, `file:`), vezető `-` jelet és shell-karaktert (`` ` $ ; | & < > ``).
- **Érvénytelen argumentum / érték, hibás argumentumszám:** a beállítás engedett, de az értéke nem a várt formájú (például eszközútvonal a `dev` után, szám helyett szó). Az üzenet a beállítás nevét mondja meg, az értéket nem. Vesd össze a sort a szolgáltató eredeti configjával.
- **Külső fájl hivatkozás:** a tanúsítvány fájlra hivatkozik (`ca ca.crt`). Importáld újra a `.ovpn` fájlt úgy, hogy a hivatkozott fájlok mellette legyenek, vagy másold be a tartalmukat egy `<ca>…</ca>` blokkba.
- **Nem engedélyezett vezérlőkarakter:** a fájlban láthatatlan karakter van (például Windowsból másolt szöveg). Írd be újra a sort.

### 7.8 Egyéb

- **„A telepítés megszakítva: a(z) /usr/local/libexec nem a root tulajdona, vagy más felhasználó is írhatja…”** (vagy ugyanez a `/usr/local`-ra) az **Engedélyezés** gomb után: a root réteg egyik szülőmappája a felhasználódé, vagy más is írhatja. Így bármi, ami ennek a felhasználónak a nevében fut, kicserélhetné a MacVPN root binárisát, ezért a MacVPN nem telepít oda, és a mappát magától nem módosítja. Javítsd a Terminálban, majd nyomd meg újra az **Engedélyezés** gombot:
  ```
  sudo chown root:wheel /usr/local/libexec && sudo chmod go-w /usr/local/libexec
  ```
  (az üzenetben megnevezett mappával). Intel Macen a `/usr/local/libexec` a Homebrew-é lehet; a változtatás után a Homebrew `sudo` nélkül nem tud oda írni, ami egyes csomagokat érinthet.
- **„Az állapot nem kérdezhető le…”** figyelmeztetés a menüben: a root réteg vagy a sudoers szabály hiányzik vagy elavult. Nyisd meg a **Rendszerállapot** ablakot, és nyomd meg az **Engedélyezés** gombot.
- **„Az openvpn nem található (brew install openvpn)”** és hasonló üzenetek: telepítsd a hiányzó eszközt a **Rendszerállapot** ablakból.

### 7.9 SSTP: tanúsítványhiba

Üzenet: **Szervertanúsítvány-hiba (lásd a naplót; ellenőrizd a tanúsítvány-módot vagy a CA fájlt)**. Tipikus naplósorok: `SSL certificate verification failed`, vagy `The certificate did not match the host`.

- A szerver tanúsítványát céges CA írta alá: válaszd a **Saját CA fájl** módot, és töltsd be a CA tanúsítványt PEM formátumban. A **Rendszer CA** nem a macOS kulcskarikát használja.
- A **Szerver** neve egyezzen a tanúsítványban szereplő névvel. IP-címmel csatlakozva ez az ellenőrzés általában elbukik; használd a hosztnevet.
- Lejárt tanúsítvány, vagy rosszul jár a Mac órája.
- A **Nincs ellenőrzés** csak átmeneti tesztre jó, mindennapi használatra soha.

### 7.10 SSTP: hitelesítési hiba

Üzenet: **Hitelesítési hiba (rossz felhasználónév vagy jelszó)**. Tipikus naplósor: `MS-CHAP authentication failed: E=691`.

- Ellenőrizd a **Felhasználónév** és **Jelszó** mezőket, majd **Mentés**. Windows tartományi fiók `user@domain` formában (nem `DOMAIN\user`).
- A szervernek engedélyeznie kell az MS-CHAPv2-t. Ha csak tanúsítványos (EAP-TLS) vagy PAP belépést fogad el, a MacVPN nem tud rá csatlakozni.
- Ha a naplóban `Az sstpc kilépett` áll IP-cím nélkül, vagy a hitelesítés után időtúllépés jön, a szerver olyan formában kérheti az SSTP crypto bindingot, amit az `sstpc` nem támogat. Csatlakozz debug módban, és küldd el a naplót a szerver üzemeltetőjének.
- **Az SSTP-hez jelszó kell**: üres a jelszó mező. Add meg az űrlapon, és ments.
- **Az sstpc nem található (brew install sstp-client)**: telepítsd az `sstp-client` csomagot a **Rendszerállapot** ablakból.

### 7.11 Egyszer használatos kód és böngészős bejelentkezés (MFA)

- **A hitelesítés nem fejeződött be időben**: 2 percen belül nem érkezett kód, vagy a böngészős bejelentkezés nem fejeződött be a határidőn belül (legfeljebb 5 perc). Csatlakozz újra, és válaszolj hamarabb.
- **A hitelesítés megszakítva**: a kódbekérő vagy a böngészős ablakban a **Mégse** gombra kattintottál, vagy bontottál.
- **Hitelesítési hiba**: a szerver elutasította a kódot vagy a jelszót. A kódok gyorsan lejárnak: használj frisset. A jelszó végére fűzött kódnál ellenőrizd, milyen **Elválasztó**t vár a szolgáltató.
- **Nem jelenik meg a böngészős ablak**: a MacVPN csak egyszerű ASCII hosztnevű `https://` címet nyit meg (nemzetközi név csak `xn--` alakban, az elérési út előtt nincs `%` és `@`). Ilyenkor a naplóban `web authentication URL dropped (only https with a plain ASCII host is accepted)` áll. Kérj ilyen bejelentkezési címet a szolgáltatótól.
- **A management közvetítő leállt**: a MacVPN root segédje bejelentkezés közben váratlanul leállt. Csatlakozz újra; ha ismétlődik, csatlakozz debug módban, és nézd meg a `[mgmt]` sorokat.
- **Nincs hitelesítésre váró kapcsolat**: a csatlakozás már véget ért (határidő vagy hiba), mielőtt a válasz megérkezett. Csatlakozz újra.
- **A mvpn-mgmt nem található** (a root `mvpn` bináris OpenVPN-segédje nem indult el; `mvpn-mgmt` az a név, amelyen fut), vagy **Hiányos telepítés** a **Rendszerállapot** ablakban: a root réteg régebbi verzióé vagy hiányos. Kattints az **Engedélyezés** gombra a **Rendszerállapot** ablakban az újratelepítéshez.
- A naplóban a `[mgmt]` sorok a segéd lépései (például `hold released`, `credentials sent`, `dynamic challenge received`). Soha nem tartalmazzák a kódot vagy a jelszót, a bejelentkezési címnek pedig csak a hosztja kerül a naplóba.

---

## 8. Frissítés

A MacVPN a GitHub Releases oldalon keresi az új verziókat: induláskor, majd 24 óránként egyszer.

- Ha van újabb verzió, a menüben megjelenik a **Frissítés elérhető: vX.Y.Z** sor. Kattintásra megnyílik a **Frissítés** ablak a változások listájával és a telepített verzióval. A **Később** bezárja; a **Kiadás megnyitása a GitHubon** a kiadás oldalát nyitja meg.
- A **Letöltés és telepítés** gomb:
  1. letölti a DMG-t, a hozzá tartozó `.sha256` fájlt és a `.sig` aláírást, ellenőrzi az SHA-256 ellenőrzőösszeget, majd azt, hogy az aláírást a MacVPN fejlesztőjének offline kulcsa készítette, pontosan erre a verzióra és erre a fájlra. Ha az aláírás hiányzik vagy érvénytelen, **A frissítést nem a MacVPN fejlesztője írta alá** üzenettel leáll, és semmit nem telepít;
  2. csatolja a DMG-t, és ellenőrzi, hogy a benne lévő app a MacVPN (`local.macvpn`), a verziója egyezik a kiadáséval, és a kódaláírása érvényes;
  3. a kilépéshez hasonlóan rákérdez a nem mentett változásokra és az aktív kapcsolatokra;
  4. kilép, kicseréli az appot ott, ahonnan fut (általában `/Applications/MacVPN.app`), majd újraindítja.
  Az ablak minden lépést kijelez (**Célhely ellenőrzése…**, **Letöltés…**, **Lemezkép csatolása…**, **Az alkalmazás ellenőrzése…**, **Telepítés előkészítése…**, **Kilépés és újraindítás…**). Ha a kilépés előtt bármi hibára fut, a telepített verzió marad, és a MacVPN tovább fut.
- **Aláírt frissítések:** minden kiadást a fejlesztő egy offline tárolt Ed25519 kulccsal ír alá; a kulcs soha nincs a GitHubon. A MacVPN csak aláírásfájllal rendelkező kiadást ajánl fel, és csak érvényes aláírás esetén telepíti. A még alá nem írt újabb kiadást nem ajánlja fel; a **Frissítések keresése most** ilyenkor **A frissítés aláírásra vár** üzenetet ad.
- Kézi ellenőrzés: menü → **Frissítések keresése most**. Ha nincs újabb verzió, ezt írja: **A MacVPN naprakész**.
- Az automatikus ellenőrzés kikapcsolható: menü → **Frissítések automatikus keresése** jelölőnégyzet.
- **Opcionális késleltetés:** a **Csak a legalább 24 órája megjelent frissítések felajánlása** jelölőnégyzettel (alapból ki van kapcsolva) a MacVPN egy új kiadást csak akkor ajánl fel, ha az már 24 órája nyilvános (a GitHub-kiadás közzétételi ideje alapján). Így marad idő arra, hogy egy hibás vagy rosszindulatú kiadás kiderüljön és lekerüljön, mielőtt telepítenéd. A **Frissítések keresése most** ilyenkor jelzi, ha van újabb verzió, de még nincs felajánlva.
- **Keychain kérdés frissítés után:** mivel a MacVPN ad-hoc aláírású (nincs Developer ID-je), a macOS minden új verziót új programnak tekint. Az 1.2-től a MacVPN egyetlen elemet tart a Keychainben, az **Automatikus feloldás** széfkulcsát, így frissítés után a macOS legfeljebb egyszer kérdez (kikapcsolt **Automatikus feloldás** mellett egyszer sem). A **Mindig engedélyez** (*Always Allow*) gombot csak akkor válaszd, ha a kérdés a MacVPN sajátja: a MacVPN nevét és útvonalát mutatja (általában `/Applications/MacVPN.app`). Ha más programot nevez meg, utasítsd el (*Elutasítás*, *Deny*); a MacVPN ilyenkor a mesterjelszót kéri.
- Ha a frissítés új root réteget hoz, megnyílik a **Rendszerállapot** ablak, és **Frissítés szükséges** jelenik meg. Az **Engedélyezés** gombbal egy admin jelszóval frissíted.
- Ha az app helye nem írható (például közvetlenül a Letöltések mappából vagy a DMG-ről fut), a telepítés hibát jelez. Húzd az appot az Applications mappába, vagy frissíts kézzel: töltsd le az új DMG-t, és írd felül vele az appot.
- A frissítés naplója: `~/Library/Caches/MacVPN/update.log`. Ha az előző frissítés megszakadt (mert a MacVPN 30 másodpercen belül nem lépett ki) vagy hibával leállt, a MacVPN a következő indításkor egyszer jelzi; a telepített verzió megmarad. Induláskor a MacVPN egy megszakadt frissítés maradványait is törli (rejtett `.MacVPN.app.update-…` és `.MacVPN.app.old-…` mappák az app mellett).

### 8.1 Frissítés 0.x verzióról

A MacVPN 1.0 váltotta a 0.x Swift appot, az 1.1 és az 1.2 ennek folytatása. Minden korábbi verzió, a 0.x és az 1.x is, az appon belüli frissítéssel egyenesen az 1.2-re lép, és az 1.2 első indítása a széfbe költözteti az adataidat (a [8.2](#82-frissítés-11-ről) rész átköltöztetése). Frissítés előtt olvasd el a [8.2](#82-frissítés-11-ről) részt, és készíts mentést az adatmappádról.

1. **Frissítés az appon belül.** A MacVPN 0.x-ben válaszd a **Frissítések keresése most** pontot, majd a Frissítés ablakban a **Letöltés és telepítés** gombot. A 0.x frissítője az új kiadás aláírását is ellenőrzi, mint bármelyik frissítésnél. (A 0.2.2 előtti verziók nem ellenőrzik az aláírást: ezeknél inkább töltsd le a DMG-t a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról, lépj ki a MacVPN-ből, és cseréld le az appot az Applications mappában.)
2. **A széf létrehozása.** Az 1.2 első indításakor átköltöztetési módban megnyílik **A széf beállítása** ablak: válassz mesterjelszót, mentsd el a helyreállítási kulcsot, és hagyd, hogy a MacVPN a széfbe költöztesse a kapcsolataidat, a jelszavakat, a kitűzött kapcsolatokat és a sorrendet, valamint a rendszer VPN-ek egyszer használatos kód beállításait ([8.2](#82-frissítés-11-ről), 3–5. lépés). A frissítési beállítások és az **Indítás bejelentkezéskor** változatlanok maradnak. A futva hagyott kapcsolatok kapcsolódva maradnak. Semmit nem kell újra importálni.
3. **A Keychain az átköltöztetés közben kérdez.** Az új verzió aláírása új, ezért a macOS minden régi Keychain-elemnél megkérdezi, hogy a MacVPN olvashatja-e: elemenként legfeljebb egyszer, és az ablak előre megmondja, hányszor. Kattints a **Mindig engedélyez** gombra, ha a kérdés a `/Applications/MacVPN.app` MacVPN-t nevezi meg. (A nagyon régi verziók `macvpn` Keychain-szolgáltatás alatti bejegyzéseit a MacVPN előbb automatikusan áthelyezi a `local.macvpn.secrets` alá.) Az átköltöztetés után a régi elemek törlődnek, a jelszavak csak a széfben vannak.
4. **A root réteg újratelepítése.** Az 1.0 a 0.x különálló root scriptjei helyett egyetlen `mvpn` binárist hozott; az 1.2 a 8-as root réteget hozza. Megnyílik a **Rendszerállapot** ablak **Frissítés szükséges** felirattal, 0.4.0-ról például **Frissítés szükséges (6 → 8)**. Kattints az **Engedélyezés** gombra, és add meg az admin jelszót. Előtte az aktív VPN-kapcsolatok bontódnak; a régi fájlok (`ovpn-dns`, `mvpn-validate`, `mvpn-mgmt`) törlődnek. Amíg ezt nem teszed meg, az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokon **Hiányzó eszköz** áll, és nem csatlakoznak.
5. **Hardened runtime.** Az app és a root binárisa hardened runtime-mal van aláírva, így a macOS nem enged idegen könyvtárat betölteni beléjük. Ez védi a jelszavakat, amelyeket az app a memóriájában tart. Neked ezzel nincs teendőd; az app továbbra is ad-hoc aláírású, ezért a Gatekeeper csak akkor kérdez újra, ha a DMG-ből kézzel telepítesz.

### 8.2 Frissítés 1.1-ről

A MacVPN 1.2 mindent egy titkosított széfbe költöztet (lásd [11.](#11-széf)), és a 8-as root réteget hozza. Maga a frissítés a szokásos, appon belüli frissítés; az első indításra szánj egy kis időt.

1. **Előbb készíts mentést.** Lépj ki a MacVPN 1.1-ből (a kapcsolatok futva maradhatnak), majd másold le az adatmappáját a Terminálban:
   ```
   cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.1
   ```
   A jelszavak a Keychainben vannak, nem ebben a mappában; a frissítés végéig ezeket is tartsd biztonságos helyen (például jelszókezelőben). Indítsd újra a MacVPN 1.1-et.
2. **Frissítés az appon belül.** Menü → **Frissítések keresése most** → **Letöltés és telepítés** (lásd [8.](#8-frissítés)). A MacVPN 1.2-ként indul újra.
3. **A széf létrehozása.** Megnyílik a **Széf beállítása** ablak. Jelzi, hogy a kapcsolataid és mentett jelszavaid a széfbe kerülnek, és hogy a macOS hányszor kérhet Keychain-hozzáférést (például **A macOS legfeljebb 5 alkalommal kérhet hozzáférést a Keychainhez – minden alkalommal válaszd a Mindig engedélyez gombot. Ez csak egyszer történik meg.**). Kattints a **Tovább** gombra, válassz mesterjelszót, állítsd be tetszés szerint az **Automatikus feloldás** jelölőt, és kattints a **Széf létrehozása** gombra. Mentsd el és erősítsd meg a helyreállítási kulcsot (lásd [11.1](#111-mesterjelszó-és-helyreállítási-kulcs)).
4. **Az átköltöztetés.** **Az adatok átköltöztetése a széfbe…**: minden kapcsolatmappa, minden mentett jelszó, PSK és kulcsjelszó, a sorrend és a kitűzések, a rendszer VPN-ek egyszer használatos kód beállításai és a párosított appok egy lépésben a széfbe másolódnak, majd visszaolvasás után összehasonlításra kerülnek. A régi fájlok csak ezután íródnak felül és törlődnek, és csak ezután törlődnek a régi Keychain-elemek. Az eredmény: **Az adataid a széfben vannak**, a kapcsolatok és titkok számával. Ha néhány elem nem olvasható, ezt is jelzi (**1 elem nem olvasható, ez a helyén maradt.**); ezek a régi helyükön maradnak.
5. **Keychain kérdések.** Az átköltöztetés alatt a macOS minden régi Keychain-elemnél egyszer rákérdezhet, mert az 1.2 app új ad-hoc aláírást kapott. Minden kérdés a MacVPN-t és a `/Applications/MacVPN.app` útvonalat nevezi meg: válaszd a **Mindig engedélyez** gombot. Ha az **Elutasítás** gombra kattintasz, az a titok nem olvasható: a Keychainben marad, és a kapcsolat a következő csatlakozáskor bekéri. Ez csak egyszer történik meg: utána a MacVPN legfeljebb egy Keychain-elemet tart (lásd [8.](#8-frissítés)).
6. **Root réteg 7 → 8.** A **Rendszerállapot** ablakban **Frissítés szükséges (7 → 8)** áll. Kattints az **Engedélyezés** gombra, és add meg egyszer az admin jelszót. Előtte az aktív VPN-kapcsolatok bontódnak. Amíg ezt nem teszed meg, az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokon **Hiányzó eszköz** áll; az L2TP, a Cisco IPsec és a rendszer VPN-ek enélkül is működnek.
7. **Ellenőrzés.** Csatlakozz egyszer minden kapcsolattal. A szerkesztőkben a mentett jelszavaknál **Mentve – írj be újat a cseréhez** látszik.

**Ha az átköltöztetés nem sikerül** (**Az átköltöztetés nem fejeződött be**), semmi sem törlődik. A MacVPN törli az új, félig feltöltött széfet, és **írásvédetten** tovább használja az 1.1-es adataidat: csatlakozni tudsz, de felvenni, módosítani és törölni nem (**A MacVPN a régi tárolót írásvédetten használja, amíg az átköltöztetés nem sikerül**). A menüben **Az átköltöztetés a széfbe nem fejeződött be. Újrapróbálás…** sáv jelenik meg. Kattints rá (vagy az ablakban az **Újra** gombra), és hozd létre újra a széfet egy új mesterjelszóval; a sikertelen próbálkozás helyreállítási kulcsa érvénytelen. Ha a beállító ablakot a széf létrehozása előtt bezárod, a MacVPN szintén írásvédetten fut az 1.1-es adatokból, és a menü sávja: **A széf beállításának befejezése…**.

A **párosított appok** (vezérlő API) átkerülnek, és az átköltöztetés után is működnek.

---

## 9. Eltávolítás

1. Nyisd meg a **Rendszerállapot** ablakot, és kattints a **MacVPN eltávolítása…** gombra.
2. A megerősítő ablak felsorolja, mi törlődik:
   - `/usr/local/libexec/macvpn` (root scriptek: a `mvpn` root bináris és a `VERSION` fájlja)
   - `/etc/sudoers.d/macvpn` (sudoers szabály)
   - `/var/run/macvpn`, `/var/run/macvpn-ui` (futási adatok)
   - `/var/log/macvpn` (kapcsolatnaplók)
3. Ha a **A felhasználói adatok törlése is** jelölőnégyzetet bejelölöd, az adataid is törlődnek: a széf minden kapcsolattal, jelszóval, mappával és közös hitelesítő adattal (`~/Library/Application Support/MacVPN`, benne a `vault.db` és a `vault.keys`), az **Automatikus feloldás** Keychainben tartott széfkulcsa (`local.macvpn.vault`), és az 1.1-ből megmaradt MacVPN Keychain-elemek (`local.macvpn.secrets`), a rendszer VPN-ekhez mentett közös kulcsokkal együtt. Jelölés nélkül a széf és a Keychain-kulcsa megmarad, és egy későbbi telepítés újra megnyitja őket. A **Teljes biztonsági mentés…** funkcióval készített fájlokhoz nem nyúl: ha már nincs rájuk szükséged, töröld őket magad.
4. Kattints az **Eltávolítás** gombra, és add meg az admin jelszót. Előtte a MacVPN bontja az aktív kapcsolatokat.
   Ha egy kapcsolat nem bontható, az eltávolítás megszakad („Egy kapcsolat nem bontható, az eltávolítás megszakítva”), és semmi nem törlődik. Bontsd a kapcsolatot (vagy indítsd újra a gépet), majd próbáld újra.
5. A végén egy **A MacVPN eltávolítva** című ablak jelenik meg, ezzel a szöveggel:
   > Az app most áthúzható a Kukába. A Homebrew csomagok megmaradtak (brew uninstall openvpn wireguard-tools strongswan sstp-client).

   Ha volt L2TP vagy Cisco kapcsolatod, egy második bekezdés is megjelenik:
   > Az L2TP / Cisco profilokat a Rendszerbeállítások → Általános → Eszközkezelés alatt távolíthatod el.

   Ha az **Indítás bejelentkezéskor** be volt kapcsolva, a MacVPN eltávolítja magát a bejelentkezési elemek közül (és törli a bejelentkezési LaunchAgentjét, ha azt használta). Ha ez nem sikerül, az ablak jelzi, és a **Rendszerbeállítások → Általános → Bejelentkezési elemek** alatt távolíthatod el.

   A **Kilépés** után húzd a `MacVPN.app`-ot a Kukába.

A Homebrew csomagokat a MacVPN nem törli, mert más programok is használhatják őket. Ha már nincs rájuk szükséged:

```
brew uninstall openvpn wireguard-tools strongswan sstp-client
```

Az L2TP és Cisco profilokat a **Rendszerbeállítások → Általános → Eszközkezelés** alatt távolíthatod el.

Ha a `/etc/ppp/options` fájlt az SSTP miatt a MacVPN hozta létre (ilyenkor jelölőt hagy), és a fájl még mindig üres, az eltávolító azt is törli. A korábban is meglévő vagy tartalommal bíró fájlhoz nem nyúl.

---

## 10. Biztonsági megjegyzések

**Fenyegetési modell.** A MacVPN a veszélyes *configok* ellen véd: egy letöltött vagy importált `.ovpn`, WireGuard vagy IKEv2 fájl nem tud parancsot futtatni, rootként tetszőleges fájlt olvasni vagy írni, és sikeres kapcsolódást sem tud színlelni, mert a root oldal minden beállítást engedélyezőlistán ellenőriz, és csak root által írható fájlokból dönt. A *felhasználói fiókodban már futó programok* ellen viszont **nem** véd: egy ilyen program a gyakorlatban rootjogot szerezhet. Kicserélheti a (felhasználód által írható) Homebrew VPN-eszközöket, majd a MacVPN jelszó nélküli sudo szabályával rootként futtathatja őket. Úgy kezeld a MacVPN-t, mint bármely eszközt, amely a fiókodnak adminisztrátori erejű jogot ad: csak olyan gépen használd, amelynek te vagy az adminisztrátora, és ahol megbízol a fiókod alatt futó programokban.

- **Ad-hoc aláírt app.** A MacVPN nincs Apple Developer ID-vel aláírva és notarizálva, ezért kell az első indításkor a Gatekeeper-lépés (lásd [1.2](#12-az-első-indítás-engedélyezése-gatekeeper)). Csak a hivatalos [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról töltsd le. Az app és a `mvpn` root bináris hardened runtime-mal, jogosultságok (entitlements) nélkül van aláírva, így a macOS nem engedi, hogy más program könyvtárat injektáljon beléjük (például `DYLD_INSERT_LIBRARIES`-szal), és így kiolvassa a jelszavakat, amelyeket a MacVPN a memóriájában tart.
- **A széf (1.2).** A kapcsolatok, a configok, a felhasználónevek, jelszavak, PSK-k, kulcsjelszavak, a közös hitelesítő adatok, a mappák és a sorrend egyetlen titkosított SQLCipher adatbázisban vannak (`vault.db`, AES-256, oldalankénti HMAC-kal; a teljes fájl titkosított). A véletlen 256 bites kulcsa csak becsomagolva tárolódik a `vault.keys` fájlban: egyszer a mesterjelszóból, egyszer a helyreállítási kulcsból származtatott kulccsal (Argon2id, majd XChaCha20-Poly1305). Sem a mesterjelszó, sem a helyreállítási kulcs nincs tárolva. A helyreállítási kulcs csak egyszer, a létrehozásakor látható, többé soha. **Automatikus feloldás** mellett maga a széfkulcs a macOS Keychainben van (`local.macvpn.vault` szolgáltatás), és a MacVPN kódaláírása olvashatja; kapcsold ki, ha minden indításkor a mesterjelszót szeretnéd megadni. A **Széf zárolása most** törli a kulcsot a memóriából. A hibás mesterjelszavakat a MacVPN lassítja (két próba között legfeljebb 30 másodperc), de sosem zár ki. Mindkét széffájl nyugodtan másolható, mert titkosított; előtte lépj ki a MacVPN-ből, hogy az adatbázis mindent beírjon a `vault.db` fájlba (futás közben a legutóbbi változások még a `vault.db-wal` fájlban lehetnek). Részletek: [11.](#11-széf)
- **Jelszavak.** A jelszavak és a PSK a széfben vannak. Az 1.1-ig a macOS Keychainben voltak (`local.macvpn.secrets` szolgáltatás); az 1.2-re való átállás ezeket törli, miután a széfbeli példányukat ellenőrizte (lásd [8.2](#82-frissítés-11-ről)). Az L2TP / Cisco kapcsolatok fiókneve nem titok: a macOS profilba is bekerül. A jelszavak és a PSK a naplóban maszkolva (`***`) jelennek meg, és az export sem tartalmazza őket. A config részét képező kulcsok (WireGuard `PrivateKey`, OpenVPN `<key>` és hasonlók) csak az **Exportálás kulcsokkal** választásával kerülnek az exportba. Az L2TP / Cisco profil tartalmazza a PSK-t (a jelszót nem), és telepítés után törlődik a lemezről. Felhasználónévben, jelszóban és PSK-ban nem lehet sortörés vagy vezérlőkarakter (a MacVPN nem menti el). A mentett napló `600`-as jogosultsággal jön létre. OpenVPN-nél a felhasználónév és a jelszó egy csak root által olvasható fájlon át (`600`-as jogosultság egy `700`-as könyvtárban) jut a MacVPN root segédjéhez (`mvpn mgmt-bridge`, a folyamatlistában `mvpn-mgmt`), amely a fájlt a beolvasás után azonnal törli. A segéd a memóriájában tartja őket, hogy az OpenVPN újracsatlakozáskor újra be tudjon lépni, és a csak root által elérhető management socketen adja át őket az OpenVPN-nek. Az egyszer használatos kód soha nem tárolódik: csak a csatlakozás idejére van a memóriában, és a naplóban maszkolva jelenik meg.
- **Titkok a memóriában.** A MacVPN a mesterjelszó, a helyreállítási kulcs, a széfkulcs és a begépelt jelszavak saját példányait törli, amint már nincs rájuk szüksége. Az útközben keletkező másolatokat, amelyeket az ablakokat megjelenítő webes nézet és az app belső üzenetküldése (IPC) készít, a MacVPN nem tudja törölni; ezek addig maradnak az app memóriájában, amíg az felül nem íródik. A mentett jelszavak egyáltalán nem jutnak el a webes nézetig: a szerkesztők csak azt tudják, hogy van mentett érték.
- **Közös hitelesítő adatok.** A közös hitelesítő adathoz kapcsolt kapcsolat abból veszi a felhasználónevet és a jelszót. A kapcsolat szerkesztője a közös hitelesítő adatot sosem módosítja, akkor sem, ha a kapcsolatot mented: az csak a **Hitelesítő adatok** részben, vagy a hitelesítőadat-bekérő ablak **Mentés a széfbe** jelölőjével változik. Egy importált fájl sosem kapcsolódik csendben közös hitelesítő adathoz, mert a fájl maga választja meg a szerverét: a MacVPN előbb rákérdez, és megmutatja, melyik szerverre menne a jelszó (lásd [13.4](#134-import-és-export)).
- **Biztonsági mentések.** A **Teljes biztonsági mentés…** fájlja minden titkot tartalmaz, a mentés jelszavával titkosítva (Argon2id, XChaCha20-Poly1305). Aki birtokolja a fájlt és a jelszavát, az összes VPN-hitelesítő adatodat elolvashatja: tartsd külön a kettőt. A MacVPN a mentést nem megbízható bemenetként kezeli, mert aki ismeri a jelszavát, készíthet ilyet: mielőtt bármit írna, minden elemét a szerkesztőkkel azonos szabályokkal ellenőrzi, és az érvénytelen mentést egészében elutasítja. A visszaállítás sosem kapcsolja be magától a **Más appok vezérelhetik a VPN-eket** beállítást: a visszaállító ablakban ez nincs bejelölve, és a mentés többi beállítása is csak akkor lép életbe, ha bejelölöd. Részletek: [14.](#14-biztonsági-mentés-és-visszaállítás)
- **L2TP / Cisco profilok és a széf (1.2).** A MacVPN által telepített L2TP / Cisco profil PSK-ját a macOS a rendszer-kulcskarikában (System keychain) tartja, a profil részeként: ezek a profilok a macOS-éi, és PSK nélkül a VPN nem működne, ha a Rendszerbeállításokból indítod. A jelszó soha nincs a profilban. A PSK és a jelszó MacVPN saját példánya (amelyet a szerkesztő mutat, és amelyet a MacVPN minden csatlakozáskor átad a macOS-nek) a MacVPN titkosított széfjében van, nem a Keychainben. Ha a PSK-t a rendszer-kulcskarikából is törölni szeretnéd, töröld a profilt a **Rendszerbeállítások → Általános → Eszközkezelés** alatt.
- **A root réteg sértetlensége.** A telepítő a root fájlokat (`mvpn` és `VERSION`) egy csak root által elérhető átmeneti mappába másolja, és csak akkor telepíti őket, ha a SHA-256-juk egyezik azzal, amit az app közvetlenül az admin jelszó kérése előtt kiszámolt. A `/usr/local/libexec/macvpn` mappát a root tulajdonába adja, és mások számára írhatatlanná teszi. Ha a `/usr/local` vagy a `/usr/local/libexec` nem a root tulajdona, vagy más is írhatja, nem módosítja őket, hanem útmutatással megáll (lásd [7.8](#78-egyéb)). A sudoers szabály tiszta környezettel indítja a `mvpn`-t (a munkameneted `LANG`, `LC_*` és más változói nélkül).
- **Sudoers és Homebrew (ismert korlát).** A csatlakozáshoz a MacVPN egy sudoers szabállyal, jelszó nélkül futtatja rootként a `/usr/local/libexec/macvpn/mvpn` binárist, ez pedig a Homebrew eszközeit (`openvpn`, `wg-quick`, `charon`, `sstpc`). A Homebrew könyvtára (`/opt/homebrew`) a felhasználó által írható. Egy, a felhasználói fiókodban futó kártevő kicserélheti ezeket a programokat, és így rootjogot szerezhet. A configok szűrése a véletlen vagy importált veszélyes beállítások ellen véd, a fiókodon belül futó kártevő ellen nem. Egyfelhasználós, általad adminisztrált gépen ez elfogadható kockázat. Ha nem az, ne engedélyezd a root réteget, és csak L2TP / Cisco kapcsolatot használj.
- **SSTP jelszó a parancssorban (ismert korlát).** A Homebrew `sstpc` az SSTP crypto binding kulcsait maga számolja a jelszóból, ezért csak akkor indul el, ha a jelszót a parancssorában kapja (`--password`). A MacVPN ott adja át, a naplóba soha nem írja (`***`). Az `sstpc` a saját parancssorát a beolvasás után azonnal kicsillagozza, de ebben az első pillanatban a gép más felhasználói a `ps` paranccsal láthatják a jelszót. Egyfelhasználós gépen ez elfogadható kockázat. Ha nálad nem az, ne használj SSTP-t.
- **Párosított appok (vezérlő API).** Alapból ki van kapcsolva. Ha bekapcsolod ezt: **Más appok vezérelhetik a VPN-eket** (Kapcsolatok ablak → **Párosított appok**), a felhasználói fiókod általad párosított programjai egy privát socketen át listázhatják az általad engedélyezett kapcsolatokat, és fel- és lekapcsolhatják őket; configot és jelszót sosem látnak. A párosítás a program futtatható fájljának útvonalához kötődik, és minden művelet megjelenik a **Tevékenység** listában. Részletek és korlátok: [a vezérlő API leírása](control-api.hu.md#4-biztonsági-modell).
- **A frissítés hitelessége.** A MacVPN csak olyan frissítést telepít, amely a fejlesztő offline kulcsával készült érvényes Ed25519 aláírást hordoz. A nyilvános kulcsok (egy elsődleges és egy tartalék) be vannak építve az appba; a privát kulcsok soha nincsenek a GitHubon vagy a build rendszerben. Így ha valaki át is veszi a GitHub-fiókot vagy a repót, a MacVPN-nek nem tud frissítést kiadni: az érvényes aláírás nélküli kiadást az app nem ajánlja fel, vagy **A frissítést nem a MacVPN fejlesztője írta alá** üzenettel elutasítja. Az aláírás a verzióra és a DMG azon SHA-256-jára szól, amelyet a MacVPN a letöltés után maga számol ki. **Maradék kockázat:** aki a fejlesztő aláíró kulcsát birtokolja, aláírhat frissítést.
- **Hogyan szűkíti tovább a kockázatot az updater.**
  - A legfrissebb kiadást a repó rögzített numerikus azonosítójával kéri le a GitHubtól (`MacVPNUpdateRepoID` az app `Info.plist`-jében), nem a nevével. Ha a repót átneveznék vagy törölnék, és valaki a régi néven újat hozna létre, az app onnan nem frissülne. Az azonosító nélkül az app egyáltalán nem keres frissítést.
  - A DMG-t, a `.sha256` fájlt és a `.sig` aláírást csak a `https://github.com/SepsiG/MacVPN/releases/download/<tag>/<fájlnév>` címről fogadja el, pontosan a kiadás tagjével; átirányítás csak a GitHub saját letöltési hostjaira vezethet.
  - A kiadásokat egy megerősített GitHub Actions workflow készíti: commitra rögzített actionök, csak olvasási jogú build, a tagelt commitnak a `main` ágon kell lennie, a kiadást pedig egy külön job hozza létre piszkozatként (draft), amely nem futtat kódot a repóból. A fejlesztő a saját Macjén ellenőrzi az ellenőrzőösszeget, offline aláírja a kiadást, és csak ezután teszi közzé.
  - Az opcionális 24 órás késleltetés (lásd [8.](#8-frissítés)) időt ad egy hibás kiadás észlelésére és visszavonására.
  - Az app ad-hoc aláírású; a macOS minden frissítés után egyszer kérheti a Keychain-hozzáférést a széfkulcshoz (lásd [8.](#8-frissítés)). Csak a MacVPN saját kérdésénél engedélyezd.
- **Külső összetevők licencei.** A MacVPN MIT-licences ([LICENSE](../LICENSE)). Az app csomagjában lévő `THIRD-PARTY-NOTICES.txt` a szállított összetevők licenceit tartalmazza, köztük az SQLCipherét (BSD-típusú, © Zetetic LLC).

---

## 11. Széf

Az 1.2-től a MacVPN egyetlen titkosított fájlban, a **széfben** tárolja a kapcsolataidat, a configjaikat, a felhasználóneveket, jelszavakat, PSK-kat és kulcsjelszavakat, a közös hitelesítő adatokat, a mappákat és színeket, a sorrendet és a kitűzéseket, a rendszer VPN-ek egyszer használatos kód beállításait és a párosított appokat: `~/Library/Application Support/MacVPN/vault.db`, mellette a kulcsfájlja, a `vault.keys`. A teljes adatbázis titkosított; a széfkulcs nélkül semmi sem olvasható ki belőle, még a kapcsolatok neve sem.

### 11.1 Mesterjelszó és helyreállítási kulcs

A **Széf beállítása** ablak az 1.2 első indításakor nyílik meg (később, amíg nincs széf, a menü **Széf beállítása…** sorából).

1. **A széf beállítása.** Elmagyarázza a széfet. Frissítéskor azt is jelzi, hogy az adataid a széfbe kerülnek, és hányszor kérhet a macOS Keychain-hozzáférést (lásd [8.2](#82-frissítés-11-ről)). Új Macen itt a **Visszaállítás biztonsági mentésből…** is választható (lásd [14.3](#143-visszaállítás-új-macen)). Kattints a **Tovább** gombra.
2. **Válassz mesterjelszót.** Legalább 10 karakter; egy hosszú kifejezést könnyebb megjegyezni és nehezebb kitalálni. A mező alatti jelzés értékeli (**Túl rövid**, **Gyenge – könnyű kitalálni**, **Közepes**, **Erős**); a gyenge jelszót elfogadja, de nem ajánlott. Írd be újra **A mesterjelszó még egyszer** mezőbe. Az **Automatikus feloldás** be van jelölve (lásd [11.2](#112-automatikus-feloldás)). Kattints a **Széf létrehozása** gombra.
3. **A helyreállítási kulcsod.** 24 betű és számjegy hat csoportban, például `7K2M-…-QX4T`. Ha elfelejted a mesterjelszót, csak ezzel a kulccsal juthatsz vissza a széfbe. Írd fel, vagy tárold egy jelszókezelőben: **csak most látható**. A **Másolás** kimásolja. Kattints az **Elmentettem** gombra.
4. **A helyreállítási kulcs ellenőrzése.** Írd be a kért csoportot (**Írd be a helyreállítási kulcs 3. csoportját, balról számolva.**), és kattints a **Megerősítés** gombra.
5. **A széf elkészült.** Kattints a **Kész** gombra. Frissítéskor előbb lefut az átköltöztetés (**Az adatok átköltöztetése a széfbe…**, majd **Az adataid a széfben vannak**).

Az ablaknak nincs alapértelmezett gombja: az Enter egy mezőben nem csinál semmit, kattints a gombokra. A helyreállítási kulcsban nem számít a kis- és nagybetű; az `O` `0`-nak, az `I` és az `L` `1`-nek számít, a kötőjelek és szóközök nem számítanak.

### 11.2 Automatikus feloldás

- **Bekapcsolva** (alapértelmezés): a széfkulcs a macOS Keychainben van (`local.macvpn.vault` szolgáltatás), így a MacVPN kérdés nélkül megnyílik. Frissítés után a macOS egyszer megkérdezheti, olvashatja-e a MacVPN: válaszd a **Mindig engedélyez** gombot, ha a kérdés a `/Applications/MacVPN.app` MacVPN-t nevezi meg.
- **Kikapcsolva:** a MacVPN minden indításkor elkéri a mesterjelszót. Kikapcsoláshoz nyisd meg a menü **Beállítások** csoportját, kapcsold ki az **Automatikus feloldás** kapcsolót, és erősítsd meg a **Kikapcsolás** gombbal (**Kikapcsolod az automatikus feloldást?**). A Keychain-elem törlődik.
- **Visszakapcsoláshoz** kapcsold be: **Az automatikus feloldás bekapcsolása** ablak elkéri a mesterjelszót; kattints a **Bekapcsolás** gombra.
- Ha a Keychain-elem nem olvasható (például az **Elutasítás** gombra kattintottál), a MacVPN a mesterjelszót kéri.

### 11.3 Feloldás

**A MacVPN feloldása** ablak induláskor nyílik meg, ha a széf nem oldódik fel automatikusan, illetve a zárolt menü **Széf feloldása…** sorából. Add meg a **Mesterjelszó** mezőben, és kattints a **Feloldás** gombra.

Hibás jelszónál **Hibás jelszó vagy helyreállítási kulcs** jelenik meg. Minden további hibás próba után egyre többet kell várni (1, 2, 4, 8, 16, majd 30 másodperc; a gombon **Újrapróbálás 8 mp múlva** áll). Kizárás nincs. Ha elfelejtetted a jelszót, kattints a **Helyreállítási kulcs használata** gombra (lásd [11.8](#118-elfelejtett-mesterjelszó)).

### 11.4 Széf zárolása most

A menü alján lévő **Széf zárolása most** gomb azonnal zárolja a széfet. Akkor látszik, ha az **Automatikus feloldás** ki van kapcsolva, vagy ha a menü **Beállítások** csoportjában bekapcsolod a **„Széf zárolása most” megjelenítése** kapcsolót.

A zárolás bezárja a széfet, és törli a kulcsát a memóriából. A Keychain-elemet **nem** törli: bekapcsolt **Automatikus feloldás** mellett a következő indítás ismét kérdés nélkül megnyílik. A futó VPN-ek fennmaradnak. A Kapcsolatok ablak nem mentett változásai elvesznek, a mesterjelszó és a helyreállítási kulcs ablakai bezáródnak.

### 11.5 A zárolt menü

Amíg a széf zárolva van, a menüben csak ez látszik:

- egy **Széf feloldása…** sor (**A MacVPN zárolva van**),
- az aktív kapcsolatok száma (**1 kapcsolat aktív**, **3 kapcsolat aktív**), nevek nélkül,
- **Kilépés**.

Zárolt széf mellett semmi sem működik, ami a széfet igényli: csatlakozás, szerkesztés, import, export, a mappák (rejtve vannak, és nem módosíthatók: **A mappák nem módosíthatók, amíg a széf zárolva van**), a közös hitelesítő adatok és a mentések. Ezek válasza: **A széf zárolva van. Oldd fel, és próbáld újra.** A párosított appok `locked` hibát kapnak; egy VPN-t ilyenkor is lebonthatnak (lásd [a vezérlő API leírását](control-api.hu.md)).

### 11.6 A mesterjelszó módosítása

1. Menü → **Beállítások** → **Mesterjelszó módosítása…**.
2. Add meg a **Jelenlegi mesterjelszó** mezőt, majd kétszer az **Új mesterjelszó** mezőt.
3. Kattints a **Jelszó módosítása** gombra. **A mesterjelszó megváltozott**: mostantól az újat használd.

A helyreállítási kulcsod változatlan. A széf nem titkosítódik újra; csak a jelszóval becsomagolt kulcsa íródik újra. A hibás jelenlegi jelszót a feloldáshoz hasonlóan lassítja.

### 11.7 Új helyreállítási kulcs

Ha a helyreállítási kulcsodat valaki láthatta, vagy elvesztetted, de a mesterjelszót még tudod:

1. Menü → **Beállítások** → **Új helyreállítási kulcs…**.
2. Add meg a **Mesterjelszó** mezőt, és kattints az **Új kulcs készítése** gombra. Az új kulcs a régi helyébe lép: a régi azonnal érvényét veszti.
3. Mentsd el az új kulcsot (csak most látható), kattints az **Elmentettem** gombra, írd be a kért csoportot, és kattints a **Megerősítés** gombra.

### 11.8 Elfelejtett mesterjelszó

1. **A MacVPN feloldása** ablakban kattints a **Helyreállítási kulcs használata** gombra.
2. Írd be a **Helyreállítási kulcs** mezőt, majd kétszer az **Új mesterjelszó** mezőt.
3. Kattints a **Visszaállítás és feloldás** gombra.

A kapcsolataid változatlanok maradnak, és a helyreállítási kulcs továbbra is működik. **A mesterjelszó használata** visszavisz a jelszómezőhöz.

---

## 12. Mappák és színek

A mappák csoportosítják a kapcsolatokat a **Kapcsolatok** ablakban és a menüben. Tetszőleges mélységig egymásba ágyazhatók. A MacVPN-ben létrehozott kapcsolatok és a rendszer VPN-ek is mappába tehetők, vagy maradhatnak a legfelső szinten.

### 12.1 Mappák

- **Létrehozás:** eszköztár **Új** (+) → **Új mappa**, vagy jobb klikk egy mappára → **Új mappa** (almappa), vagy jobb klikk egy kapcsolatra vagy üres területre → **Új mappa** (a legfelső szinten). Az új mappa neve „Új mappa”, és a névmezője nyitva van: írd be a nevet, és nyomj Entert.
- **A mappa helyi menüje:** **Új mappa**, **Átnevezés**, **Szín…**, **Áthelyezés a legfelső szintre** (almappánál), **Törlés…**.
- **A kapcsolat helyi menüje:** **Kitűzés** / **Kitűzés megszüntetése**, **Szín…**, **Áthelyezés a legfelső szintre** (mappában lévő kapcsolatnál), **Új mappa**.
- **Nevek:** 1–64 karakter, vezérlőkarakter nélkül (**A mappa neve 1–64 karakter lehet, vezérlőkarakter nélkül**).

### 12.2 Színek

A **Szín…** egy 12 színből álló palettát nyit meg: Piros, Narancs, Borostyán, Sárga, Citromzöld, Zöld, Kékeszöld, Ciánkék, Kék, Indigó, Lila és Rózsaszín. Világos és sötét módban is jól mutatnak.

- **Mappánál** a **Nincs** is választható. A saját szín nélküli mappa a szülőmappája színét kapja.
- A saját szín nélküli **kapcsolat** a legközelebbi színes mappa színét kapja. A saját színű kapcsolaton egy **Saját szín** pötty látszik; a paletta **A mappa színe** pontja eltávolítja.
- A szín egy keskeny sávként látszik a kapcsolat során és a mappa ikonján.

### 12.3 Sorrend egy mappán belül

Minden mappán belül (és a legfelső szinten): elöl az almappák, a húzással beállított sorrendben; utánuk a kitűzött kapcsolatok, a te sorrendedben; aztán a többi, a leggyakrabban használt elöl (lásd [5.1](#51-a-kapcsolatok-sorrendje)); azonos használatnál név szerint.

### 12.4 Húzás

- **A mappák** egy másik mappába ejtve egymásba ágyazódnak, mappák közé ejtve átrendeződnek.
- **A kapcsolatok** csak akkor változtatnak helyet, ha egy mappára ejted őket: ilyenkor abba a mappába kerülnek. Kivétel, ha egy kitűzött kapcsolatot ugyanannak a mappának egy másik kitűzött kapcsolatára ejtesz: ez a kitűzések sorrendjét változtatja meg.
- Húzás közben megjelenik egy **Legfelső szint** célterület: ide ejtve az elem minden mappából kikerül.
- Egy mappa nem ejthető önmagába vagy a saját almappájába: **Egy mappa nem helyezhető önmagába vagy a saját almappájába**.

### 12.5 Mappa törlése

A **Törlés…** megkérdezi: **Mi legyen a tartalmával?**

- Alapértelmezés: **A tartalma kerüljön a szülőmappába** (legfelső szintű mappánál **A tartalma kerüljön a legfelső szintre**). A kapcsolatok és az almappák megmaradnak.
- **A kapcsolatok is törlődjenek**: a mappa és almappái kapcsolatai a mentett jelszavaikkal együtt törlődnek. Előtte egy második megerősítés kérdez (**Törlöd a(z) 3 kapcsolatot?**, **Ez nem vonható vissza.**, **Kapcsolatok törlése**).
- A rendszer VPN-ek így sosem törlődnek: **A rendszer-VPN-ek a legfelső szintre kerülnek.**
- Amíg a mappában van aktív kapcsolat, a mappa nem törölhető: **Előbb bontsd a mappában lévő kapcsolatokat, aztán töröld őket**.

### 12.6 Mappák a menüben

- A mappák nyitható-csukható sorok; a MacVPN megjegyzi, melyik van becsukva.
- A mappa jelvénye mutatja, hány kapcsolat aktív benne (**2 aktív**), becsukva is.
- A beágyazást behúzás jelzi, legfeljebb 3 szintig; a mélyebb mappák is működnek, de nem húzódnak be tovább.

### 12.7 Export, import és rendszer VPN-ek

- Az export a mappa útvonalát a `# macvpn-meta` sorba írja; az import létrehozza a hiányzó mappákat (lásd [4.](#4-import-és-export)).
- Egy rendszer VPN a macOS-ből való eltűnése után 30 napig megtartja a mappáját és a színét, így ha újra telepítik (például visszaállítás után egy új Macen), a helyére kerül.
- Amíg a széf zárolva van, a mappák rejtve vannak, és nem szerkeszthetők.

---

## 13. Közös hitelesítő adatok

A **közös hitelesítő adat** egy névvel ellátott felhasználónév és jelszó, amelyet több kapcsolat használ, például „Iroda AD”. Elég egyszer módosítani, és minden kapcsolat, amely használja, az újjal jelentkezik be. A jelszavak a széfben vannak, és sosem jelennek meg.

### 13.1 A Hitelesítő adatok rész

Nyisd meg a **Kapcsolatok** ablakot, és válaszd az oldalsáv **Hitelesítő adatok** pontját. Minden tételnél látszik a neve, a felhasználóneve (vagy **Nincs felhasználónév**), a **Jelszó mentve** vagy **Nincs mentett jelszó: kapcsolódáskor kérdezi**, és **3 kapcsolat használja**.

- **Hitelesítő adat hozzáadása…** → **Új közös hitelesítő adat**: **Név** (1–64 karakter), **Felhasználónév**, **Jelszó**. A jelszó nem kötelező: jelszó nélkül a MacVPN kapcsolódáskor kéri, és ide mentheti.
- **Szerkesztés…**: a felhasználónév vagy a jelszó módosítása. A jelszómezőben **Mentve – írj be újat a cseréhez** áll, mint a szerkesztőkben.
- **Átnevezés…**: új név; a kapcsolódások megmaradnak.
- **Törlés**: a nem használt hitelesítő adat törlődik. Ha kapcsolatok használják, a MacVPN felsorolja őket, és megkérdezi: **Másolás minden kapcsolatba** (mindegyik saját felhasználónevet és jelszót kap belőle, majd a közös adat törlődik) vagy **Mégse**. Használatban lévő hitelesítő adat sosem törlődik csendben.

### 13.2 Létrehozás kapcsolatból

Frissítéskor semmi sem alakul át magától. Egy kapcsolat bejelentkezési adataiból így lesz közös hitelesítő adat:

1. **Hitelesítő adatok** → **Létrehozás kapcsolatból…**.
2. Válaszd ki a **Kapcsolat** mezőt, adj **Név**-et, és kattints a **Tovább** gombra. A kapcsolat tárolt felhasználónevéből és jelszavából közös hitelesítő adat lesz, amelyet ezután használ. Az értékek nem jelennek meg.
3. Az **Összekapcsolod az azonos bejelentkezéseket?** lépés felsorolja a többi kapcsolatot, amelynek ugyanez a felhasználóneve és jelszava (a MacVPN belül hasonlítja össze, sosem mutatja). Jelöld be, melyek használják szintén, és kattints a **Létrehozás és összekapcsolás** gombra. Ha nincs ilyen: **Más kapcsolatnak nincs ugyanez a felhasználóneve és jelszava.**

### 13.3 Használat egy kapcsolatban

A felhasználónevet és jelszót használó szerkesztőkben (OpenVPN `auth-user-pass`-szal, IKEv2 EAP-pal, SSTP, L2TP, Cisco IPsec, valamint L2TP / Cisco rendszer VPN-ek) van egy **Jelszó forrása** választó:

- **Saját felhasználónév és jelszó** (alapértelmezés): a kapcsolat saját mezői.
- **Hitelesítő adat: Iroda AD**: a MacVPN megkérdezi: **Használod a(z) Iroda AD közös hitelesítő adatot?**, és jelzi, hogy a kapcsolathoz tárolt felhasználónév és jelszó törlődik. Kattints a **Használat** gombra. A kapcsolat saját mezői ezután rejtve vannak, és a szerkesztőben ez áll: **A felhasználónév és a jelszó a(z) Iroda AD közös hitelesítő adatból származik. A Hitelesítő adatok részben módosíthatod őket.**

A többi titok (PSK, privát kulcs jelszava, egyszer használatos kód beállításai) kapcsolatonként marad. **A szerkesztő sosem módosítja a közös hitelesítő adatot**: egy kapcsolat mentése nem változtathatja meg azt, amit a többi kapcsolat használ. A közös hitelesítő adat csak a **Hitelesítő adatok** részben változik, vagy ha a hitelesítőadat-bekérő ablakban bejelölöd a **Mentés a széfbe** négyzetet (lásd [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor)); egy elutasított bejelentkezés után ott mentett új jelszó minden kapcsolatnál frissíti a közös adatot.

### 13.4 Import és export

- Az export csak a hitelesítő adat **nevét** írja ki (`credentialName` a `# macvpn-meta` sorban), a felhasználónevét és jelszavát sosem.
- Az import sosem kapcsol csendben hitelesítő adatot: az importált fájl maga választja a szerverét, és egy csendes kapcsolás oda küldené a közös jelszavadat. Ha van ilyen nevű hitelesítő adat, a MacVPN megkérdezi: **Használod a(z) „Iroda AD” közös hitelesítő adatot ehhez a(z) vpn.example.com szerverre csatlakozó kapcsolathoz?**, a fájlból kiolvasott szerverrel. A **Saját adatok használata** (a biztonságos választás) a kapcsolat saját felhasználónevét és jelszavát hagyja meg; a **Közös hitelesítő adat használata** gombot csak akkor válaszd, ha megbízol a fájlban. Ha nincs ilyen nevű hitelesítő adat, választhatsz egy másikat, vagy a kapcsolat saját adatait.
- A párosított appok (vezérlő API) sosem látják a közös hitelesítő adatokat.

---

## 14. Biztonsági mentés és visszaállítás

A kapcsolatonkénti export (lásd [4.](#4-import-és-export)) sosem tartalmaz jelszót. A macOS újratelepítéséhez vagy egy másik Macre költözéshez **teljes biztonsági mentés** van: egyetlen titkosított fájl, benne minden.

### 14.1 Mi van a mentésben

- minden kapcsolat a configjával és a titkaival,
- a mappák, színek, a sorrend, a kitűzések és a használati rangsor,
- a közös hitelesítő adatok,
- a rendszer VPN-ek egyszer használatos kód beállításai és mappabeli helye,
- az app beállításai: automatikus frissítéskeresés, a 24 órás késleltetés, **Indítás bejelentkezéskor**, **Más appok vezérelhetik a VPN-eket** és **Automatikus feloldás**.

Nincs benne: a **párosított appok** (ezen a Macen lévő programútvonalakhoz kötődnek: visszaállítás után párosítsd őket újra), a széfkulcs és a helyreállítási kulcs, valamint a naplók.

### 14.2 Teljes biztonsági mentés

1. Menü → **Beállítások** → **Teljes biztonsági mentés…** (vagy a Kapcsolatok ablakban **Új** (+) → **Teljes biztonsági mentés…**). Feloldott széf kell hozzá.
2. Olvasd el a figyelmeztetést: **Aki birtokolja ezt a fájlt és a jelszavát, az összes VPN-hitelesítő adatodat elolvashatja.**
3. Válassz egy **A mentés jelszava** jelszót (legalább 10 karakter), és ismételd meg. A MacVPN nem tárolja: nélküle a mentés nem nyitható meg.
   - Helyette a **A mesterjelszavam használata…** gombbal a mesterjelszót is használhatod, a **Mesterjelszó használata** megerősítése után. Akkor viszont bárki, aki megtudja a mesterjelszavadat, ezt a fájlt is megnyithatja, bárhol is tárolod; egy külön mentési jelszó elválasztja a kettőt.
   - Írd be a **Mesterjelszó** mezőbe a mesterjelszót is. A MacVPN minden mentés előtt ellenőrzi (rossz jelszó után ugyanazzal a várakozással, mint a feloldáskor), így egy felügyelet nélkül hagyott, feloldott Mac nem elég ahhoz, hogy valaki minden jelszavadról másolatot vigyen.
4. Kattints a **Mentés…** gombra, és válaszd ki a helyét. A fájl neve `MacVPN-backup-<dátum>.macvpnbackup`, csak te olvashatod.
5. A fájlt és a jelszavát tartsd külön, például a fájlt egy külső lemezen, a jelszót egy jelszókezelőben.

### 14.3 Visszaállítás új Macen

1. Telepítsd a MacVPN 1.2-t vagy újabbat, és indítsd el.
2. A **Széf beállítása** ablakban kattints a **Visszaállítás biztonsági mentésből…** gombra. (Ehhez új, üres széf kell.)
3. **Fájl kiválasztása…**, add meg **A mentés jelszava** mezőt, és kattints a **Mentés megnyitása** gombra.
4. Válassz új mesterjelszót ehhez a Machez, és mentsd el az új helyreállítási kulcsot, ahogy a [11.1](#111-mesterjelszó-és-helyreállítási-kulcs) leírja.
5. Minden egy lépésben visszaáll. Utána kövesd a [14.5](#145-visszaállítás-után) lépéseit.

### 14.4 Visszaállítás meglévő széfbe

1. Menü → **Beállítások** → **Visszaállítás biztonsági mentésből…**. Semmi sem változik, amíg jóvá nem hagyod, mit állítson vissza.
2. **Fájl kiválasztása…**, **A mentés jelszava**, **Mentés megnyitása**. Hibás jelszónál vagy sérült fájlnál egyetlen üzenet jön: **A mentés nem nyitható meg. Hibás a jelszó, vagy sérült a fájl.**
3. Az összesítő megmutatja, mikor és melyik verzió készítette (**Készült: …, MacVPN 1.2.0**), és hány **Kapcsolatok**, **Mappák** és **Közös hitelesítő adatok** tétel van benne. Elöl felsorolja azokat a kapcsolatokat, amelyeknél kockázatos OpenVPN-beállítások (például rootként futó szkriptek) vannak jóváhagyva: csak saját készítésű mentést állíts vissza.
4. Válassz:
   - **Összefésülés**: hozzáadja, ami itt hiányzik. A már létező elemekre egyszer, mindegyikre érvényesen döntesz (**Ha egy elem már létezik:**): **Felülírás a mentésben lévő példánnyal**, **Az itt lévő elem megtartása**, vagy **Mindkettő megtartása (a mentésből származó másolat neve „(backup)” végződést kap)**. Az összefésülés elveti a visszaállított kapcsolatok kockázatos beállításainak jóváhagyását, hacsak ugyanez a kapcsolat ugyanezzel a configgal már nincs itt; ilyenkor a szerkesztő újra rákérdez.
   - **Minden cseréje**: előbb kiüríti a széfet. Egy megerősítés megmondja, hány kapcsolat, mappa és közös hitelesítő adat törlődik; **Ez nem vonható vissza.** Az **Előbb a jelenlegi állapot mentése…** gomb a folytatás előtt elmenti a mostani állapotot. A párosított appok maradnak. A csere megtartja a jóváhagyásokat.
5. **A mentés visszaállítva.**

Ha bármi hibára fut: **A visszaállítás nem sikerült. Semmi sem változott.** Azt a mentést is elutasítja, amelynek mappái kört alkotnának az itteni mappákkal.

### 14.5 Visszaállítás után

- **Beállítások.** **A mentés beállításai maguktól nem lépnek életbe.** Minden sor mutatja a mentés és ennek a Macnek az értékét (**Mentés: Be · Ez a Mac: Ki**). Jelöld be, amelyeket ezen a Macen használnál, és kattints **A kijelölt beállítások alkalmazása** gombra. A **Más appok vezérelhetik a VPN-eket** sosincs előre bejelölve: csak akkor jelöld be, ha ezen a Macen párosított appokat használsz, és párosítsd őket újra.
- **Natív profilok.** Az L2TP és Cisco IPsec kapcsolatoknak profil kell ezen a Macen. A **2 natív profil újratelepítése** megnyitja őket; a macOS mindegyik jóváhagyását kéri a **Rendszerbeállítások → Általános → Eszközkezelés** alatt.
- **Eszközök.** A hiányzó Homebrew eszköz vagy root réteg a szokásos módon a **Rendszerállapot** ablakban látszik.
- **Rendszer VPN-ek**, amelyek ezen a Macen nem léteznek, 30 napig megtartják a mappájukat és a színüket, arra az esetre, ha újra beállítod őket.

### 14.6 A mentés nem megbízható bemenet

Aki ismeri egy mentés jelszavát, készíthet is ilyet, ezért a MacVPN minden elemet a szerkesztőkkel azonos szabályokkal ellenőriz (nevek, felhasználónevek, jelszavak, mappanevek, méretek, a tételek száma, vezérlőkarakterek hiánya), mielőtt bármit írna. Az érvénytelen mentést egészében elutasítja (**Ez a mentés nem állítható vissza: olyan adatot tartalmaz, amelyet a MacVPN nem fogad el.**). Az újabb MacVPN-nel készült mentést ezzel utasítja el: **Ezt a mentést egy újabb MacVPN készítette. A visszaállításhoz frissítsd a MacVPN-t.** A visszaállítás sosem kapcsolja be magától a vezérlő API-t.

---

## 15. Gyakori kérdések a széfről

**Elfelejtettem a mesterjelszót.**
**A MacVPN feloldása** ablakban kattints a **Helyreállítási kulcs használata** gombra, és a helyreállítási kulccsal adj meg új mesterjelszót ([11.8](#118-elfelejtett-mesterjelszó)). Bekapcsolt **Automatikus feloldás** mellett a MacVPN jelszó nélkül is megnyílik, de a **Mesterjelszó módosítása…** és az **Új helyreállítási kulcs…** kéri: zárold a MacVPN-t (**Széf zárolása most**), majd állítsd vissza a jelszót a helyreállítási kulccsal.

**Elvesztettem a helyreállítási kulcsot.**
Ha a mesterjelszót még tudod, azonnal készíts újat: **Beállítások → Új helyreállítási kulcs…** ([11.7](#117-új-helyreállítási-kulcs)). Ha a mesterjelszót és a helyreállítási kulcsot is elvesztetted:

- Bekapcsolt **Automatikus feloldás** mellett a MacVPN továbbra is megnyitja a széfet, és a kapcsolataid működnek, de semmi sem, amihez a mesterjelszó kell (a módosítása, új helyreállítási kulcs, új mentés). Exportáld most a szükséges kapcsolatokat ([4.](#4-import-és-export); a mentett jelszavak nincsenek az exportban).
- Kikapcsolt **Automatikus feloldás** mellett a széfet senki sem tudja megnyitni, a MacVPN sem.
- Egy mentés csak a saját jelszavával nyílik meg. A **A mesterjelszavam használata…** választással készült mentéshez a mentés idején érvényes mesterjelszó kell. A helyreállítási kulcs sosem nyit meg mentést.

Állítsd vissza egy olyan mentésből, amelyet még meg tudsz nyitni ([14.](#14-biztonsági-mentés-és-visszaállítás)), vagy állítsd be újra a MacVPN-t: távolítsd el **A felhasználói adatok törlése is** jelöléssel ([9.](#9-eltávolítás)), és importáld újra a kapcsolataidat.

**A MacVPN azt írja, hogy zárolva van.**
Kattints a menü **Széf feloldása…** sorára, és add meg a mesterjelszót. A futó VPN-ek a zárolás alatt is fennmaradtak. Ha minden indításkor zárolva van, az **Automatikus feloldás** ki van kapcsolva, vagy a macOS megtagadta a Keychain-hozzáférést: kapcsold be a **Beállítások** alatt ([11.2](#112-automatikus-feloldás)).

**Nem sikerült az átköltöztetés az 1.1-ről.**
Semmi sem törlődött, és a MacVPN írásvédetten használja az 1.1-es adataidat. Kattints a menü **Az átköltöztetés a széfbe nem fejeződött be. Újrapróbálás…** sávjára, és hozd létre újra a széfet egy új mesterjelszóval ([8.2](#82-frissítés-11-ről)). Ha újra nem sikerül, lépj ki a MacVPN-ből, ellenőrizd, hogy az 1.1-es adatmappád (és a mentésed) ép, és jelezd az ablakban látott üzenetet.

**Hány Keychain kérdésre számíthatok?**
Az 1.1-ről való átköltöztetéskor régi Keychain-elemenként legfeljebb egyre; a beállító ablak előre megmondja a számukat. Mindig a **Mindig engedélyez** gombot válaszd. Utána frissítésenként legfeljebb egyre (a széfkulcs miatt), kikapcsolt **Automatikus feloldás** mellett egyre sem. Ha a kérdés nem a `/Applications/MacVPN.app` MacVPN-t nevezi meg, nem a MacVPN-é: kattints az **Elutasítás** gombra.

**Az átköltöztetés közben véletlenül az Elutasítás gombra kattintottam.**
Az az elem nem volt olvasható, és a Keychainben maradt; az eredmény megmondja, hány ilyen van. A kapcsolat a következő csatlakozáskor bekéri a hiányzó jelszót (a **Mentés a széfbe** elmenti).

**„A széf sérült, nem nyitható meg.”**
A `vault.db` vagy a `vault.keys` megváltozott vagy hiányos. Állítsd vissza egy mentésből ([14.](#14-biztonsági-mentés-és-visszaállítás)), vagy lépj ki a MacVPN-ből, és tedd vissza mindkét fájl egy másolatát (amelyet a MacVPN futása nélkül készítettél).

**„Ezt a széfet egy újabb MacVPN mentette.”**
Egy újabb után egy régebbi MacVPN-t indítottál. Telepítsd a legújabb verziót.

**Hogyan távolítok el mindent?**
A **MacVPN eltávolítása…** ablakban jelöld be **A felhasználói adatok törlése is** négyzetet: ez törli a széfet, a Keychainben lévő széfkulcsot és az 1.1-ből megmaradt Keychain-elemeket ([9.](#9-eltávolítás)). A `.macvpnbackup` fájlokat töröld magad.
