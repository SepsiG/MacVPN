# MacVPN – felhasználói útmutató

[English version](user-guide.en.md)

A MacVPN egy menüsor-alkalmazás macOS-re (14 vagy újabb, Apple processzoros vagy Intel Mac). Egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec és Cisco IPsec kapcsolatokat. Itt importálhatod és szerkesztheted a configokat, mappákba rendezheted őket, és minden kapcsolatnak van élő naplója. A kapcsolatok és jelszavaik egy titkosított széfben vannak. Ez az útmutató a 2.0-s verziót írja le (lásd: [Újdonságok a 2.0-ban](#újdonságok-a-20-ban)). A menü **Súgó** pontja ezt nyitja meg.

Rövid, lépésenkénti leírások: [Hogyan használd](how-to.hu.md). Ez az útmutató a teljes referencia. Ha fejlesztőként azt szeretnéd, hogy egy másik program ezen a Macen fel- és lekapcsolhassa a MacVPN kapcsolatait (**Párosított appok** a Kapcsolatok ablakban), olvasd el a [vezérlő API leírását](control-api.hu.md).

> **Nyelv:** a MacVPN a macOS nyelvi beállítását követi (Rendszerbeállítások → Általános → Nyelv és régió, illetve az appra beállított nyelv). Magyarul és angolul érhető el; ha a preferált nyelvek között egyik sincs, angolul jelenik meg. Ez az útmutató a magyar feliratokat használja, az [angol útmutató](user-guide.en.md) az angolokat.

## Újdonságok a 2.0-ban

- **Megjelenés.** A **Beállítások → Megjelenés** pontban **Rendszer szerint**, **Világos** vagy **Sötét** választható; egyszerre vált a menü és minden MacVPN-ablak. Lásd [2.2](#22-megjelenés).
- **Kapcsolatértesítések.** Értesítés, ha egy kapcsolat csatlakozott, megszakadt, újracsatlakozott vagy sikertelen, közérthető okkal (például **A szerver nem válaszol.**); kattintásra a kapcsolat **Napló** füle nyílik meg. A **Beállítások → Kapcsolatértesítések** kapcsolja ki őket. Lásd [2.3](#23-kapcsolatértesítések).
- **Hiányzó VPN-eszközök.** Ha egy kapcsolat eszköze nincs telepítve, a kapcsolat a listában marad, kiszürkítve, **Nincs telepítve: OpenVPN – Rendszerállapot** felirattal; a sorban a **Rendszerállapot** megnyitja az ablakot, ahol telepítheted. Addig az **Új** menü és az import nem kínálja ezt a típust. Lásd [2.4](#24-hiányzó-vpn-eszközök).
- **Automatikus újracsatlakozás.** Alvás vagy a hálózat elvesztése után a MacVPN magától újra felépíti a kapcsolatot, de csak ugyanazon a hálózaton, mint korábban, és csak ha a VPN saját hálózatai ott nem érhetők el közvetlenül. Kapcsolatonként kikapcsolható. Lásd [5.5](#55-automatikus-újracsatlakozás).
- **A DNS megbízhatóan visszaáll.** A root réteg egyetlen DNS-kezelője lemezen jegyzi az eredeti DNS-beállításokat, így azok visszaállnak, amikor az utolsó, DNS-t állító kapcsolat bomlik; akkor is, ha kapcsolódás közben összeomlott valami vagy újraindult a Mac, és több kapcsolatnál bármilyen sorrendben. Lásd [5.6](#56-dns-kapcsolat-közben).
- **Naplóméret-korlát.** Egy kapcsolat naplója többé nem töltheti meg a lemezt: legfeljebb 5 MiB, plusz egy régebbi, szintén legfeljebb 5 MiB-os rész. Lásd [6.](#6-debug-mód-és-a-napló)
- **Mindig friss VPN-eszközök.** A **Rendszerállapot** felkínálja a VPN-eszközök Homebrew-frissítését (**Frissítés**), és a MacVPN nagyjából naponta egyszer a háttérben lefuttatja a `brew update`-et. Lásd [2.](#2-első-indítás-és-a-rendszerállapot-ablak)
- **strongSwan (IKEv2):** a Homebrew `etc/swanctl` mappáiban lévő CA, kliens-tanúsítványok és kulcsok működnek (a tanúsítványos belépés is), és két IKEv2 kapcsolat lehet egyszerre aktív. Lásd [3.3](#33-ikev2-strongswan).
- **Szigorúbb OpenVPN-ellenőrzés (biztonsági javítás).** A config minden sora legfeljebb 255 bájt lehet (**Túl hosszú sor**), mert egy hosszabb sor direktívákat rejthetne el az ellenőrzés elől; a szerver által küldött DNS-lista legfeljebb 16 szervert és 32 keresési tartományt tartalmazhat. Lásd [7.7](#77-nem-engedélyezett-direktíva--tiltott-direktíva) és [5.6](#56-dns-kapcsolat-közben).
- **9-es root réteg:** a frissítés után a **Rendszerállapot** egyszer kéri az **Engedélyezés** gombot (admin jelszóval). Lásd [8.4](#84-frissítés-15-ről).

## Újdonságok az 1.5-ben

- A háttérben: előkészítés egy Windowsos változatra. A MacVPN pontosan úgy működik, mint eddig; a root réteg 8 marad, így az 1.4-ről frissítve nem kell admin jelszó.

## Újdonságok az 1.4-ben

- **Keresés.** A Kapcsolatok ablak oldalsávjának tetején a **Kapcsolatok keresése** mező (**⌘F**) név, típus, szerver, csapatkatalógus vagy mappa alapján talál, a kis- és nagybetűtől és az ékezetektől függetlenül. Lásd [12.8](#128-kapcsolatok-keresése).
- **VPN-fájlok megnyitása a Finderből.** Dupla kattintás egy `.ovpn` vagy `.sstp` fájlra importálja; a `.conf` a **Megnyitás ezzel → MacVPN** úton nyílik; a `.macvpncatalog` fájl a **Csapatkatalógus hozzáadása…** ablakot nyitja meg ezzel a fájllal. Lásd [4.1](#41-vpn-fájlok-megnyitása-a-finderből).
- **A letöltött fájlokra előbb rákérdez.** A letöltött fájl csak egy megerősítés után importálódik (**Importálás** / **Mégse**). Lásd [4.1](#41-vpn-fájlok-megnyitása-a-finderből).
- A root réteg 8 marad: az 1.3-ról frissítve nem kell admin jelszó.
- **1.4.1:** a `cert` és a `key` mutathat ugyanarra a PEM fájlra (tanúsítvány és privát kulcs, titkosítva is). Lásd [7.8](#78-egyéb).

## Újdonságok az 1.3-ban

- **Csapatkatalógusok.** A rendszergazda egy kapcsolatkészletet, a mappáival, színeivel és névvel ellátott bejelentkezési helyeivel együtt, egyetlen aláírt és titkosított fájlként tesz közzé egy webszerveren, egy fájlmegosztáson vagy egy szinkronizált mappában. Minden feliratkozott MacVPN magától átveszi az új, a módosult és a törölt kapcsolatokat, és mindenki a saját felhasználónevével és jelszavával jelentkezik be. Lásd [16.](#16-csapatkatalógusok)
- **Rendszergazdáknak:** adminisztrátori aláírókulcs offline tartalék kulccsal, közzétételi varázsló, cserélhető csapatkulcs a csapatot elhagyók kizárására, és egy feliratkozási kód, amely mindent tartalmaz, ami egy tagnak kell. Lásd [16.7](#167-rendszergazdáknak-az-adminisztrátori-aláírókulcs).
- **Teljes biztonsági mentés.** A mentés mostantól a katalógus-feliratkozásokat, az aláírókulcsokat és a közzétételeket is tartalmazza. Lásd [14.1](#141-mi-van-a-mentésben).
- **Frissítés 1.2-ről:** az első indítás frissíti a széfet (a régiről másolat marad), a root réteg 8 marad, így nem kell admin jelszó. Lásd [8.3](#83-frissítés-12-ről).

## Újdonságok az 1.2-ben

- **Titkosított széf.** A kapcsolataid, a jelszavaik és a MacVPN többi adata mostantól egyetlen titkosított fájlban, a széfben vannak, amelyet mesterjelszó véd. Ha elfelejted a jelszót, a helyreállítási kulccsal juthatsz vissza. Az **Automatikus feloldás** (alapból be van kapcsolva) mellett a MacVPN kérdés nélkül megnyílik; a **Széf zárolása most** azonnal zárol. Lásd [11.](#11-széf)
- **Átállás az 1.1-ről.** Az 1.2 első indításakor a MacVPN a széfbe költözteti az 1.1-es kapcsolataidat és mentett jelszavaidat, ellenőrzi őket, és csak ezután törli a régi példányokat. A macOS régi elemenként egyszer Keychain-hozzáférést kérhet. A root réteg 7-ről 8-ra vált, ehhez egyszer kell az admin jelszó. Előbb készíts mentést: lásd [8.2](#82-frissítés-11-ről).
- **Mappák és színek.** A kapcsolatokat és a rendszer VPN-eket egymásba ágyazható mappákba rendezheted, a mappáknak és a kapcsolatoknak 12 szín közül adhatsz színt, és húzással oda teheted őket, ahová akarod. Lásd [12.](#12-mappák-és-színek)
- **Közös hitelesítő adatok.** Egy felhasználónév és jelszó, amelyet több kapcsolat használ. Elég egyszer módosítani, és minden kapcsolat, amely használja, az újjal jelentkezik be. Lásd [13.](#13-közös-hitelesítő-adatok)
- **Teljes biztonsági mentés és visszaállítás.** A **Teljes biztonsági mentés…** egyetlen titkosított fájlba írja az összes kapcsolatot, titkot, mappát és közös hitelesítő adatot; a **Visszaállítás biztonsági mentésből…** ezen vagy egy új Macen visszahozza. Lásd [14.](#14-biztonsági-mentés-és-visszaállítás)
- **Hitelesítő adatok bekérése.** A jelölőnégyzet neve mostantól **Mentés a széfbe**. Az EAP-bejelentkezéses IKEv2 elutasított jelszó után egyszer újra kérdez, mint az OpenVPN és az SSTP. Lásd [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor).
- **Licencek.** Az app csomagjában van egy `THIRD-PARTY-NOTICES.txt` a MacVPN-nel szállított összetevők (köztük az SQLCipher) licenceivel.

## Újdonságok az 1.1-ben

- **Más appok is vezérelhetik a VPN-eket (vezérlő API).** Alapból ki van kapcsolva. A felhasználói fiókod egy általad párosított programja, például a [RemoteDesktop](https://github.com/LovaszCC/RemoteDesktop) társalkalmazás, fel- és lekapcsolhatja az általad engedélyezett kapcsolatokat; a VPN csak addig marad fenn, amíg a programnak kell. Lásd [5.4](#54-párosított-appok-vezérlő-api), fejlesztőknek pedig [a vezérlő API leírását](control-api.hu.md).
- **Hitelesítő adatok bekérése csatlakozáskor.** A szükséges, de el nem mentett felhasználónevet, jelszót, PSK-t vagy kulcsjelszót csatlakozás előtt bekéri, csak a sikeres csatlakozás után menti (vagy egyáltalán nem), és elutasított bejelentkezésnél egyszer újra kérdez. Lásd [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor).
- **Élő rendszer-VPN lista.** A Rendszerbeállításokban felvett, átnevezett vagy törölt VPN újranyitás nélkül megjelenik a menüben és a Kapcsolatok ablakban. Lásd [3.5](#35-rendszer-vpn-ek-közös-kulcs-l2tp--cisco-esetén).
- **Új megjelenés.** A menü, a Kapcsolatok ablak, a Rendszerállapot, a Frissítés és a bekérő ablakok lekerekített kártyákat használnak. Minden kapcsolatnak színes buboréka van a típusával és egy állapotjelvénnyel. Lásd [2](#2-első-indítás-és-a-rendszerállapot-ablak) és [5](#5-csatlakozás).
- **Dock ikon.** Amíg a Kapcsolatok, a Rendszerállapot vagy a Frissítés ablak nyitva van, a MacVPN a Dockban is megjelenik, így Cmd+Tabbal is elérhető. Lásd [2](#2-első-indítás-és-a-rendszerállapot-ablak).
- A root réteg nem változott (7-es verzió): az 1.0-ról frissítve nem kell admin jelszó.

## Tartalom

1. [Telepítés](#1-telepítés)
2. [Első indítás és a Rendszerállapot ablak](#2-első-indítás-és-a-rendszerállapot-ablak) ([Megjelenés](#22-megjelenés), [Kapcsolatértesítések](#23-kapcsolatértesítések), [Hiányzó VPN-eszközök](#24-hiányzó-vpn-eszközök))
3. [Kapcsolatok felvétele típusonként](#3-kapcsolatok-felvétele-típusonként)
4. [Import és export](#4-import-és-export) ([VPN-fájlok megnyitása a Finderből](#41-vpn-fájlok-megnyitása-a-finderből))
5. [Csatlakozás](#5-csatlakozás) ([Automatikus újracsatlakozás](#55-automatikus-újracsatlakozás), [DNS kapcsolat közben](#56-dns-kapcsolat-közben))
6. [Debug mód és a napló](#6-debug-mód-és-a-napló)
7. [Hibaelhárítás a napló alapján](#7-hibaelhárítás-a-napló-alapján)
8. [Frissítés](#8-frissítés) ([Frissítés 0.x verzióról](#81-frissítés-0x-verzióról), [Frissítés 1.1-ről](#82-frissítés-11-ről), [Frissítés 1.2-ről](#83-frissítés-12-ről), [Frissítés 1.5-ről](#84-frissítés-15-ről))
9. [Eltávolítás](#9-eltávolítás)
10. [Biztonsági megjegyzések](#10-biztonsági-megjegyzések)
11. [Széf](#11-széf)
12. [Mappák és színek](#12-mappák-és-színek)
13. [Közös hitelesítő adatok](#13-közös-hitelesítő-adatok)
14. [Biztonsági mentés és visszaállítás](#14-biztonsági-mentés-és-visszaállítás)
15. [Gyakori kérdések a széfről](#15-gyakori-kérdések-a-széfről)
16. [Csapatkatalógusok](#16-csapatkatalógusok) ([felhasználóknak](#161-feliratkozás-egy-katalógusra), [rendszergazdáknak](#167-rendszergazdáknak-az-adminisztrátori-aláírókulcs), [biztonsági modell](#1611-biztonsági-modell))

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

Ha egy eszköz hiányzik, csak az adott típusú kapcsolatok szürkülnek ki, a többi típus működik (lásd [2.4](#24-hiányzó-vpn-eszközök)).

---

## 2. Első indítás és a Rendszerállapot ablak

Indítás után a MacVPN a menüsorban egy pajzs ikonként jelenik meg. Amíg valamelyik ablaka (Kapcsolatok, Rendszerállapot vagy Frissítés) nyitva van, a Dockban is megjelenik az ikonja, így Cmd+Tabbal vagy az ikonra kattintva előhozhatod az ablakot; az utolsó ilyen ablak bezárásakor az ikon eltűnik.

- **szürke pajzs:** nincs aktív kapcsolat
- **félig kitöltött pajzs:** egy kapcsolat még csatlakozik vagy újracsatlakozik (az ikon fölé víve **MacVPN – Csatlakozás…**; akkor is, amikor az OpenVPN magától indítja újra az alagutat, ilyenkor a sorban **Újracsatlakozás…** áll), vagy egy felépült kapcsolat alól eltűnt a hálózat: kikapcsolt Wi-Fi, kihúzott kábel (**MacVPN – Hálózatra vár…**, lásd [5.5](#55-automatikus-újracsatlakozás))
- **pajzs pipával:** legalább egy kapcsolat felépült, és egyik sem csatlakozik még
- **pajzs felkiáltójellel:** hiba (sikertelen csatlakozás, egy nem válaszoló, ezért bontott kapcsolat, vagy az állapot nem kérdezhető le)
- **kulcs:** egy kapcsolat hitelesítésre vár (lásd [5.2](#52-többfaktoros-hitelesítés-mfa))

Az ikonra kattintva nyílik meg a menü. Minden kapcsolat egy kártya a típusa színes buborékával, a nevével, a típusával és az állapotával, valamint egy kapcsolóval (lásd [5](#5-csatlakozás)); sok kapcsolatnál a lista görgethető. A mappák nyitható-csukható sorokként jelennek meg (lásd [12.](#12-mappák-és-színek)). A kártyák alatt:

- három csempe: **Új kapcsolat / Import…**, **Kapcsolatok kezelése…** és **Rendszerállapot**;
- a **Beállítások** csoport (kattintásra nyílik és csukódik): **Megjelenés** (lásd [2.2](#22-megjelenés)), **Kapcsolatértesítések** (lásd [2.3](#23-kapcsolatértesítések)), **Frissítések automatikus keresése**, **Csak a legalább 24 órája megjelent frissítések felajánlása**, **Frissítések keresése most** és **Indítás bejelentkezéskor**; utána a széf beállításai: **Automatikus feloldás**, **„Széf zárolása most” megjelenítése**, **Mesterjelszó módosítása…** és **Új helyreállítási kulcs…** (lásd [11.](#11-széf)), végül **Teljes biztonsági mentés…** és **Visszaállítás biztonsági mentésből…** (lásd [14.](#14-biztonsági-mentés-és-visszaállítás));
- **Súgó** (ezt az útmutatót nyitja meg), **Széf zárolása most** (ha látszik, lásd [11.4](#114-széf-zárolása-most)) és **Kilépés**.

Amíg a széf zárolva van, a menüben csak egy **Széf feloldása…** sor, az aktív kapcsolatok száma és a **Kilépés** látszik (lásd [11.5](#115-a-zárolt-menü)). Amíg a széf nem létezik, a sor felirata **Széf beállítása…**.

Ha van frissítés, a **Frissítés elérhető: vX.Y.Z** sáv is megjelenik. Az alján egy emlékeztető: **Option+kattintás a kapcsolón: debug mód**.

Ha valami hiányzik, induláskor automatikusan megnyílik a **Rendszerállapot** ablak. Bármikor megnyithatod a menüből is (**Rendszerállapot**). Három ellenőrzést mutat, mindegyik zöld vagy piros:

1. **Homebrew.** Ha hiányzik, a **Telepítés…** gomb Terminált nyit a hivatalos telepítővel. A telepítő a rendszergazdai jelszavadat kéri. Ha a telepítő nem tölthető le, a Terminál ablak ezt kiírja, és semmit nem futtat. Ha végzett, térj vissza, és nyomd meg az **Újraellenőrzés** gombot.
2. **VPN eszközök.** A hiányzó eszközök listája mellett a **Telepítés** gomb lefuttatja a `brew install` parancsot. A kimenet élőben látszik az ablakban. A telepítés akkor is folytatódik, ha közben bezárod az ablakot. Ha minden eszköz megvan, de a Homebrew-ban valamelyik csomagnak újabb verziója van, a sor felsorolja (**Frissítés elérhető: 2.6.8 → 2.6.9**), és a **Frissítés** gomb csak ezekre a csomagokra futtatja a `brew upgrade` parancsot. A MacVPN futás közben nagyjából naponta egyszer a háttérben frissíti a Homebrew csomaglistáját (`brew update`), így az ajánlat akkor is naprakész, ha te magad sosem futtatod a `brew update`-et.
3. **Jogosultság (root scriptek + sudoers).** Az **Engedélyezés** gomb egyszer kéri az admin jelszót. Telepíti a MacVPN root rétegét: az egyetlen root binárist, a `/usr/local/libexec/macvpn/mvpn`-t a `VERSION` fájljával (a 2.0.3 utáni MacVPN-kiadástól 11-es root réteg; a 2.0.3-ban 10-es; a 2.0.0–2.0.2-ben 9-es), valamint a `/etc/sudoers.d/macvpn` szabályt. Ezután a csatlakozás és a bontás jelszó nélkül működik. Ha naprakész, a sorban **Telepítve (verzió 11)** áll. Ha egy app-frissítés újabb root réteget hoz, **Frissítés szükséges (10 → 11)** jelenik meg (a telepített és az új verzióval); ha egy fájl hiányzik, **Hiányos telepítés**. Ilyenkor nyomd meg újra az **Engedélyezés** gombot. Ha van aktív kapcsolat, az ablak előbb figyelmeztet: **A rendszerkomponens frissítése bontja az aktív VPN-kapcsolatokat.**

Ha mindhárom zöld, kész a telepítés. Az L2TP és a Cisco IPsec ezek nélkül is működik.

### 2.1 Indítás bejelentkezéskor

A MacVPN alapból nem indul el magától. Ha minden bejelentkezéskor el szeretnéd indítani, jelöld be az **Indítás bejelentkezéskor** négyzetet a menü **Beállítások** csoportjában vagy a **Rendszerállapot** ablakban. Kikapcsolni a jelölés törlésével lehet. A négyzet azt mutatja, amit a macOS jelez, így a **Rendszerbeállítások → Általános → Bejelentkezési elemek** alatt végzett változásokat is követi.

- Ha a macOS jóváhagyást kér, megjegyzés jelenik meg: „Engedélyezd a MacVPN-t a Rendszerbeállítások → Általános → Bejelentkezési elemek alatt.” A **Bejelentkezési elemek beállításai…** gomb megnyitja ezt az oldalt. Ott kapcsold be a MacVPN-t.
- A MacVPN nincs Apple Developer ID-val aláírva, ezért a macOS gyakran nem tudja a szokásos módon regisztrálni. Ilyenkor a MacVPN helyette egy kis bejelentkezési LaunchAgentet hoz létre (`~/Library/LaunchAgents/local.macvpn.launcher.plist`, amely az `open -b local.macvpn` parancsot futtatja). A négyzet bejelölve marad, alatta a megjegyzés: „Bejelentkezési LaunchAgenttel bekapcsolva (a következő bejelentkezéstől érvényes).” A MacVPN ilyenkor nem indul el azonnal, csak a következő bejelentkezéskor. A LaunchAgent a bundle azonosító alapján nyitja meg az appot, így az app áthelyezése után is működik. A **Rendszerbeállítások → Általános → Bejelentkezési elemek** alatt a **Háttérben való futás engedélyezése** listában is megjelenhet. A jelölés törlése (vagy az eltávolítás) törli a fájlt.
- Ha a bekapcsolás egyik módon sem sikerül, egy riasztás mutatja az okát, és a négyzet jelöletlen marad.
- A négyzet nem kattintható, ha a MacVPN nem az Alkalmazások mappából (`/Applications` vagy `~/Applications`) fut, például közvetlenül a DMG-ről vagy a Letöltések mappából. Húzd az appot az Alkalmazások mappába, onnan nyisd meg, és próbáld újra.

### 2.2 Megjelenés

A **Beállítások → Megjelenés** pontban három lehetőség van: **Rendszer szerint** (alapértelmezés: a MacVPN a **Rendszerbeállítások → Megjelenés** beállítását követi, akkor is, ha futás közben váltasz), **Világos** és **Sötét**. A választás azonnal érvényes a menüre és minden nyitott ablakra (Kapcsolatok, Rendszerállapot, Frissítés, a kódbekérő és a hitelesítőadat-ablak, a figyelmeztetések), és minden később megnyíló ablakra. A MacVPN újraindítás után is megjegyzi. Ez ennek a Macnek a beállítása, nem része a biztonsági mentésnek.

### 2.3 Kapcsolatértesítések

A MacVPN macOS értesítést küld, ha:

- egy kapcsolat **csatlakozott** (**Office VPN: csatlakozva**);
- egy kapcsolat automatikusan **újracsatlakozott** (**Office VPN: újracsatlakozva**, lásd [5.5](#55-automatikus-újracsatlakozás));
- egy élő kapcsolat úgy **szakadt meg**, hogy nem te bontottad (**Office VPN: megszakadt a kapcsolat**);
- egy csatlakozás **sikertelen** volt (**Office VPN: sikertelen csatlakozás**);
- egy automatikus újracsatlakozás **elmaradt** (**Office VPN: nem csatlakozott újra**) vagy **nem sikerült** (**Office VPN: nem sikerült újracsatlakozni**);
- egy kapcsolat meglévő hálózat mellett **nem válaszol** (**Office VPN: nem válaszol**, lásd [5.5](#55-automatikus-újracsatlakozás)).

A cím alatt rövid, közérthető ok áll, amelyet a MacVPN a kapcsolat naplójának végéből olvas ki: **A szerver nem válaszol.**, **A szerver nem érhető el.**, **A szerver nevét nem sikerült feloldani.**, **A szerver elutasította a bejelentkezést.**, **Egy tanúsítványt nem fogadott el a kapcsolat.** vagy **Megszakadt a hálózati kapcsolat.** (a mögöttük álló naplósorok: [7.12](#712-az-értesítések-okai)). Ha egyik sem illik, **Kattints a naplóért.** áll ott (sikertelen csatlakozásnál **Részletek a MacVPN-ben**). Az értesítésre kattintva a kapcsolat a **Kapcsolatok** ablakban, a **Napló** fülön nyílik meg.

- **Amit sosem mutat.** Az értesítések a lezárt képernyőn is látszhatnak, ezért csak a kapcsolatot nevezik meg, szervert, címet, felhasználónevet vagy a napló hibaüzenetét soha. Zárolt széfnél még a kapcsolat nevét sem: a cím általános (**Egy VPN-kapcsolat megszakadt**, **Egy VPN-kapcsolat csatlakozott**, …).
- **Amiről nincs értesítés:** az általad indított bontás (a MacVPN-ből való kilépéskor, vagy ha egy párosított app elengedi a kapcsolatot, sem), és a MacVPN indulásakor már élő kapcsolat. Az OpenVPN saját újraindulása egy rövid hálózati kiesés után (`ping-restart`) nem bontja a kapcsolatot, így erről sem jön értesítés.
- **A kapcsoló.** A **Beállítások → Kapcsolatértesítések** (alapból be) mindezeket kikapcsolja. Ami tőled kér valamit, az megmarad: **…: hitelesítés szükséges**, a hitelesítő adatok bekérése és a csapatkatalógusok értesítései.
- **Engedély.** A macOS egyszer megkérdezi, hogy a MacVPN küldhet-e értesítést. Ha nemet mondtál, vagy máshogy szeretnéd látni őket: **Rendszerbeállítások → Értesítések → MacVPN**.

### 2.4 Hiányzó VPN-eszközök

A MacVPN a **Rendszerállapot** ablakban ellenőrzi az egyes kapcsolattípusok eszközeit (Homebrew, a VPN eszközök és a root réteg, lásd fent). Ha egy típus eszköze hiányzik vagy nem használható:

- **Az ilyen típusú kapcsolatok a listában maradnak, kiszürkítve.** A soruk megmondja, miért, például **OpenVPN · Nincs telepítve: OpenVPN – Rendszerállapot**, vagy **Nem használható: …**, ha az eszköz megvan, de nem használható (például a root réteghez **Engedélyezés** kell). A **Rendszerállapot** szó link, a Rendszerállapot ablakot nyitja meg. A kapcsoló és a **Csatlakozás** gomb tiltott. Ez a menüben, a **Kapcsolatok** ablak listájában és a kapcsolat részleteinél is így látszik. A nevek: **Homebrew** (minden Homebrew-s típusnál, ha maga a Homebrew hiányzik), **OpenVPN**, **WireGuard tools** (vagy **bash**), **strongSwan**, **sstp-client** és **Jogosultság (root scriptek + sudoers)**. Az L2TP-hez, a Cisco IPsec-hez és a rendszer VPN-ekhez sosem kell eszköz.
- A Kapcsolatok ablak **Új** menüje csak a használható típusokat kínálja. Ha egyik sem az, ezt mutatja: **Kapcsolat hozzáadásához telepítsd a VPN-eszközöket a Rendszerállapot ablakban.**, és egy **Rendszerállapot…** pontot.
- **Az import elutasítja az ilyen fájlt** (**Import fájlból…**, az ablakra ejtett vagy a Finderből megnyitott fájl), mielőtt bármit mentene: **office.ovpn: A(z) OpenVPN nincs telepítve. Előbb telepítsd a Rendszerállapot ablakban.** Ugyanannak az importnak a többi fájlja bekerül.
- **A csapatkatalógusok megtartják a kapcsolataikat.** Egy hiányzó típusú katalóguskapcsolat megmarad, és ugyanúgy kiszürkítve látszik; az eszköz telepítése után új szinkronizálás nélkül működik.
- **Telepítés a MacVPN-en kívül.** Ha a Terminálban `brew install`-lal telepítettél, nem kell **Újraellenőrzés**: amikor egy típus nem használható, és megnyitod a menüt vagy a Kapcsolatok ablakot, a MacVPN a háttérben újra ellenőriz (legfeljebb percenként egyszer), és a sorok egy percen belül visszaállnak.

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
- `user` / `group` mellett az OpenVPN a kapcsolódás után eldobja a root jogot: tegyél a configba `persist-tun` sort, hogy az újracsatlakozás működjön. A DNS-t a MacVPN-ben való bontás állítja vissza, és akkor is visszaáll, ha az OpenVPN magától lép ki (a MacVPN következő állapotlekérdezésekor, lásd [5.6](#56-dns-kapcsolat-közben)).
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

**Kulcsok.** A config alatt az **Interface-kulcsok** doboz mutatja ennek az eszköznek a kulcsait:

- A **Kulcspár generálása** új privát kulcsot ír a `PrivateKey` sorba. A MacVPN a rendszer biztonságos véletlenszám-forrásából készíti, ahogy a `wg genkey`. Ha a configban már van privát kulcs, a MacVPN előbb rákérdez: **Lecseréled a privát kulcsot? A másik oldalon is be kell állítani az új publikus kulcsot.** Mint minden módosítás, az új kulcs a **Mentés** után marad meg.
- A **Publikus kulcs** a privát kulcsból származik, és követi, ha generálod, beilleszted vagy átírod; hibás privát kulcsnál ez áll: **Érvénytelen privát kulcs**. Erre a kulcsra van szüksége a másik oldalnak (a szerveren az ehhez az eszközhöz tartozó `[Peer]` szakaszban): a **Másolás** a vágólapra teszi.
- A **Privát kulcs** maszkolva látszik: a **Megjelenítés** felfedi, a **Másolás** úgy másolja, mint a feliratkozási kódot: a vágólapkezelők kihagyják, az Univerzális vágólap nem küldi át a többi eszközödre, és 60 másodperc után, a **Széf zárolása most** parancsnál és kilépéskor törlődik (hacsak közben mást nem másoltál). A privát kulcsot senkinek ne add oda.
- Ha pontosan egy `[Peer]` van, a **Peer (másik oldal)** doboz egy nem kötelező **Előre megosztott kulcsot** (`PresharedKey`) is kínál az **Előre megosztott kulcs generálása** gombbal; ugyanígy jeleníthető meg és másolható. A másik oldalon ugyanezt a kulcsot kell megadni.
- A csapatkatalógus kapcsolatánál a kulcsok megjeleníthetők és másolhatók, de új nem generálható.

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
- **A tanúsítványok és kulcsok** a strongSwan saját könyvtáraiba kerülnek a Homebrew mappájában (`/opt/homebrew/etc/swanctl/`, Intel-alapú Macen `/usr/local/etc/swanctl/`): a nem általánosan ismert hitelesítő által aláírt szerver CA tanúsítványa az `x509ca/`-ba; tanúsítványos belépéshez (`auth = pubkey` és `certs = <fájlnév>` a `local` szakaszban) a saját tanúsítványod az `x509/`-be, a titkos kulcsa a `private/`-ba (vagy mindkettő egy PKCS#12 fájlban a `pkcs12/`-be). Ezeket a fájlokat a szerver üzemeltetőjétől kérd.
  - A MacVPN minden csatlakozáskor átmásolja ezeket a kapcsolat saját, csak a rendszer által olvasható mappájába, mert a strongSwan onnan olvassa őket; a kapcsolat bontásakor a másolatok törlődnek. `swanctl --load-creds` nem kell, és egy később hozzáadott fájlt a következő csatlakozás már használ.
  - Csak sima nevű, közönséges fájlok másolódnak (betű, szám, `_`, `.`, `-`; symlink és rejtett fájl nem), egyenként legfeljebb 1 MB.
  - A titkos kulcs nem lehet jelszóval védett (a MacVPN nem tud kulcsjelszót átadni a strongSwannak). Csak te olvashasd: `chmod 700 /opt/homebrew/etc/swanctl/private`.
- Az `include`, az `updown` és a fájlra hivatkozó `secrets` (`file = …`) nem engedett.
- **Több IKEv2 kapcsolat egyszerre** is működik: a MacVPN az összes aktív IKEv2 kapcsolat configját együtt tölti be a strongSwanba, és minden kapcsolat jelszava vagy PSK-ja a saját szerverazonosítójához (`remote.id`) kötött, így egy kapcsolat felépítése vagy bontása a többit nem bontja. Két kapcsolat nem lehet egyszerre aktív, ha ugyanazt a nevet használja a `connections` (vagy a `secrets`, `pools`, `authorities`) alatt, vagy PSK-val, illetve EAP-jelszóval ugyanazt a `remote.id`-t: ezeket a strongSwan nem tudná megkülönböztetni. A második csatlakozás ilyenkor az ütközést megnevező üzenettel áll le, például **Egy másik aktív strongSwan-kapcsolat már definiálja ezt: connections.office**; adj a másolatnak saját neveket és `remote.id`-t.
- **Halott-társ észlelés** (a 2.0.3-tól): ha egy kapcsolat nem ad meg saját `dpd_delay`-t, a MacVPN csatlakozáskor `dpd_delay = 30s`-t tesz hozzá (csak a config saját másolatába). A strongSwan így 30 másodperc forgalom nélküli idő után ellenőrzi a szervert; ha az nem válaszol (a strongSwan újraküldései kb. 3 percig tartanak), a kapcsolat megszakad, és az **Automatikus újracsatlakozás** visszahozza. A saját `dpd_delay`-jel rendelkező config (a kikapcsoló `0s` is) megtartja azt. A `dpd_action` az marad, ami a configban áll (alapértéke `clear`).
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

### 4.1 VPN-fájlok megnyitása a Finderből

Kattints duplán egy `.ovpn` vagy `.sstp` fájlra a Finderben, vagy húzd rá a MacVPN ikonjára: a MacVPN megnyitja a **Kapcsolatok** ablakot, és importálja a fájlt. Ez ugyanaz az import, mint az **Import fájlból…**: ugyanazok az ellenőrzések, ugyanazok a kérdések (a config mellett lévő hitelesítőadat-fájl, a fájlban megnevezett közös hitelesítő adat, az exportált fájl mappája) és ugyanaz az összesítő. Semmi nem csatlakozik: az új kapcsolat lesz kijelölve, és akkor csatlakozol, amikor készen állsz. Ha több fájlt jelölsz ki és nyitsz meg egyszerre, együtt importálódnak, egy összesítővel.

- **Mely fájlok nyílnak a MacVPN-ben.** Ha a MacVPN az **Alkalmazások** mappában van, és egyszer már elindult, a `.ovpn` és a `.sstp` fájlok alapértelmezés szerint benne nyílnak meg. A `.macvpncatalog` fájlok a csapatkatalógus párbeszédablakát nyitják meg (lásd [16.1](#161-feliratkozás-egy-katalógusra)).
- **A `.conf` fájlokat nem veszi át**, mert ezt a kiterjesztést a WireGuard, az nginx és sok más program is használja. WireGuard vagy strongSwan `.conf` fájlnál Control-kattints (jobb kattintás) a fájlra, és válaszd a **Megnyitás ezzel → MacVPN** lehetőséget.
- **Egy másik VPN-app nyitja meg a `.ovpn` fájlokat** (például a Tunnelblick vagy az OpenVPN Connect): Control-kattints egy `.ovpn` fájlra → **Megnyitás ezzel → MacVPN**. Ha a MacVPN legyen az alapértelmezett, jelöld ki a fájlt, válaszd a **Fájl → Információ** menüpontot, a **Megnyitás ezzel** alatt válaszd a **MacVPN**-t, és kattints az **Összes módosítása…** gombra.
- **Nem a Finderből nyílik:** az adminisztrátori kulcsfájl (`.macvpnadminkey`) és a biztonsági mentés (`.macvpnbackup`). Ezekhez a MacVPN saját gombjait használd (lásd [16.7](#167-rendszergazdáknak-az-adminisztrátori-aláírókulcs) és [14.](#14-biztonsági-mentés-és-visszaállítás)). Ha mégis a MacVPN-nel nyitod meg, az összesítő ezt írja: **Ezt a fájlt a MacVPN saját paneljén kell megnyitni, nem a Finderből.** A `.mobileconfig` profil továbbra is a macOS-é (lásd fent).
- **A letöltött fájlokra előbb rákérdez.** A letöltött fájlt (böngészőből, a Mailből, az Üzenetekből vagy AirDroppal; ezeket a macOS megjelöli) a MacVPN nem importálja azonnal: egyszer, az összesre együtt rákérdez – **Importálod a letöltött fájlt?** vagy **Importálod a(z) N letöltött fájlt?** –, felsorolja a fájlokat, és hozzáteszi: **Csak olyan fájlt importálj, amelyben megbízol.** Az **Importálás** importálja őket, a **Mégse** kihagyja őket. Az ugyanakkor megnyitott, nem letöltött fájlok mindkét esetben importálódnak. Így egy weboldal által a gépedre küldött fájl (például a Safari „Biztonságos fájlok megnyitása letöltés után” beállításával) nélküled soha nem lesz kapcsolat. A MacVPN a jelölést csak olvassa, nem törli. A `.ovpn` és a `.sstp` adatfájlként van bejelentve, nem szövegként, így a Safari magától nem nyitja meg őket.
- **A széf zárolva van, vagy még nincs beállítva:** a MacVPN előbb a feloldó (vagy beállító) ablakot mutatja, és a széf megnyitása után importálja a fájlokat. Ha ehelyett bezárod az ablakot, semmi nem importálódik; később nyisd meg újra a fájlokat. Addig a MacVPN csak azt tartja a memóriában, hol vannak a fájlok (legfeljebb 32 fájlt), a tartalmukat soha.
- A megnyitott fájl nem megbízható bemenet, pont úgy, mint egy ablakba húzott fájl: csak akkor importálódik, ha átmegy az ellenőrzéseken.

---

## 5. Csatlakozás

- **Menüből:** kattints a kapcsolat kártyáján a kapcsolóra. Az állapotot a típusbuborék jelvénye és a név alatti sor mutatja:
  - **zöld:** kapcsolódva (mellette az IP és az eltelt idő); a kapcsoló is zöld. Alatta a kapcsolódás óta letöltött és feltöltött adat és az aktuális sebesség: **↓ 12,4 MB  ↑ 1,2 MB · ↓ 350 kB/s  ↑ 20,0 kB/s** (↓ letöltés, ↑ feltöltés; 1 kB = 1000 bájt, ahogy a macOS is számol). Ugyanez a sor a Kapcsolatok ablakban is ott van a kapcsolat neve alatt. Másodpercenként frissül, amíg a menü vagy az ablak nyitva van. Újracsatlakozáskor (automatikusan vagy az OpenVPN sajátjánál) az összeg megmarad; a kapcsolóval újra csatlakozva nulláról indul. Minden típusnál látszik: a strongSwan (IKEv2) a 11-es root réteget igényli (frissítés után **Rendszerállapot** → **Engedélyezés**); a natív L2TP / Cisco IPsec kapcsolatok és a rendszer VPN-ek az IP-címüket is mutatják, és az eltelt időt, ha a MacVPN látta a csatlakozásukat.
  - **borostyánsárga, lüktet:** **Csatlakozás…** vagy **Bontás…** (a kapcsoló borostyánsárga), illetve **Hitelesítésre vár**: egyszer használatos kódra, böngészős bejelentkezésre vagy hiányzó hitelesítő adatokra (lásd [5.2](#52-többfaktoros-hitelesítés-mfa) és [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor))
  - **piros:** hiba (mellette a rövid ok)
  - **szürke:** nincs kapcsolat
  - **Használja: …** a kártyán: egy párosított app tartja fenn a kapcsolatot (lásd [5.4](#54-párosított-appok-vezérlő-api))
- **A Kapcsolatok ablakból:** **Csatlakozás** / **Bontás** gomb.
- Egyszerre több kapcsolat is aktív lehet.
- Ha egy típushoz hiányzik eszköz, a kapcsolat kiszürkül, és a **Nincs telepítve: <eszköz> – Rendszerállapot** felirat jelenik meg rajta (lásd [2.4](#24-hiányzó-vpn-eszközök)).
- **Értesítések** jönnek, ha egy kapcsolat csatlakozott, megszakadt, újracsatlakozott vagy sikertelen, és ha kódra vagy bejelentkezésre vár („…: hitelesítés szükséges”; kattintásra előjön a kódbekérő ablak): lásd [2.3](#23-kapcsolatértesítések). Alvás vagy a hálózat elvesztése után a MacVPN magától is újra felépítheti a kapcsolatot: lásd [5.5](#55-automatikus-újracsatlakozás).
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

### 5.5 Automatikus újracsatlakozás

Ha egy kapcsolat azért bomlik, mert a Mac elaludt vagy elment a hálózat, a MacVPN magától is újra felépítheti. Csak akkor teszi, ha mindkét feltétel teljesül:

1. **Ugyanazon a hálózaton vagy, mint amikor a kapcsolat felépült.** A MacVPN a routert hasonlítja össze (az alapértelmezett átjáró címét és hardvercímét), és ahol a macOS megmondja, a Wi-Fi nevét. A Wi-Fi nevét a macOS csak helymeghatározási engedéllyel rendelkező appnak mutatja; a MacVPN ezt nem kéri, így általában a router hardvercíme dönt. Ha a hálózat nem azonosítható, a MacVPN nem csatlakozik újra.
2. **A VPN saját hálózatai közül egyik sem érhető el ott közvetlenül.** Ezek a kapcsolat útvonalai (OpenVPN `route` sorok és a szerver által küldött útvonalak, WireGuard `AllowedIPs`; a „mindent a VPN-be” útvonal, például a `0.0.0.0/0` nem számít) és a DNS-szerverei. Ha valamelyik olyan hálózat, amelyre a Mac közvetlenül csatlakozik, az alagút elvenné tőled ezt a helyi hálózatot, ezért a MacVPN a kapcsolatot bontva hagyja.

**Egy példa.** Otthon csatlakozol az „Office VPN”-hez, amely az irodai 10.20.30.0/24 hálózatot vezeti a VPN-be. Lecsukod a gépet, és otthon nyitod ki újra: a hálózat ugyanaz, és a 10.20.30.0/24 nem az otthoni hálózatod, így a kapcsolat visszajön (**Office VPN: újracsatlakozva**). Ha viszont az irodában nyitod ki, ahol a Mac a 10.20.30.0/24-ből kap címet: ez másik hálózat, és az irodai hálózat amúgy is közvetlenül elérhető, ezért a MacVPN nem csatlakozik újra: **Office VPN: nem csatlakozott újra** / **A VPN hálózata itt közvetlenül elérhető.** (Ezt nézi meg először. Más hálózaton, ahol a VPN-ből semmi sem helyi – például egy kávézóban –, az ok: **Másik hálózaton vagy.**)

- **Mikor indul.** Ha egy kapcsolat elalváskor élt, és ébredés után nem él (vagy az ébredés utáni 3 percen belül megszakad), ha egy kapcsolat hálózat nélkül vagy egy hálózatváltás utáni egy percen belül szakad meg, és (a 2.0.3-tól) ha egy kapcsolat meglévő hálózat mellett magától szakad meg: leállt a VPN-program, a szerver lezárta a munkamenetet vagy nem válaszol (az OpenVPN `ping-exit`-je, az IKEv2 halott-társ észlelése). A MacVPN ébredés vagy hálózatváltás után néhány másodpercet vár, aztán legfeljebb háromszor próbálkozik (azonnal, 10 és 30 másodperc múlva). Hálózat nélkül megvárja, amíg a hálózat visszajön. Az újra és újra magától megszakadó vagy nem válaszoló kapcsolatot (lásd lent) 10 percen belül legfeljebb háromszor csatlakoztatja azonnal újra.
- **Ha a gyors próbálkozások nem sikerültek** (a 2.0.3-tól): a kapcsolatot, amelynek fenn kell lennie, **5 percenként, legfeljebb egy órán át** újrapróbálja, de csak amíg a Macnek van hálózata, sosem olyan hálózaton, ahol a VPN saját hálózata közvetlenül elérhető, és sosem elutasított bejelentkezés vagy tanúsítvány után. Egy értesítés jön, amikor ez elindul (**Office VPN: nem sikerült újracsatlakozni** / **… 5 percenként újrapróbálja, legfeljebb egy órán át.**), és egy, amikor letelt az óra (**Egy órán át próbálkozott. Csatlakoztasd újra, ha a szerver ismét elérhető.**); a köztes próbálkozásokról nem. Közben a sorában **Újrapróbálás 4 perc múlva** áll. Ha te magad csatlakoztatod vagy bontod, vagy kikapcsolod az **Automatikus újracsatlakozás**t, azonnal abbahagyja.
- **Amit sosem csatlakoztat újra:** egy párosított app által indított kapcsolatot (a **Kilépés, fussanak tovább** és egy újraindítás után sem: a MacVPN megjegyzi, hogy egy párosított app indította, amíg le nem bomlik vagy te nem csatlakoztatod), az általad bontott kapcsolatot (a MacVPN-ből való kilépéssel vagy egy párosított app elengedésével bontottat sem), az általad indított, sikertelen csatlakozást, azt a kapcsolatot, amelynél a szerver elutasította a bejelentkezést vagy nem fogadott el egy tanúsítványt (új jelszó vagy tanúsítvány kell), és azt, amelynek a kódbekérő vagy hitelesítőadat-ablakát megszakítottad. Ha közben te magad csatlakozol vagy bontasz, a MacVPN abbahagyja a próbálkozást.
- **Értesítések** (lásd [2.3](#23-kapcsolatértesítések)): siker után **újracsatlakozva**; **nem csatlakozott újra** az okkal (**Másik hálózaton vagy.**, **A hálózatot nem sikerült azonosítani.**, **A VPN hálózata itt közvetlenül elérhető.**, **A VPN DNS-szervere itt közvetlenül elérhető.**, **Az újracsatlakozáshoz oldd fel a széfet.**); vagy **nem sikerült újracsatlakozni** az utolsó hiba okával. Az újracsatlakozás rendes csatlakozás: egyszer használatos kódos kapcsolatnál újra kéri a kódot, a hiányzó hitelesítő adatokat is bekéri.
- **A széf.** A jelszavak a széfből jönnek, ezért zárolt széfnél nincs újracsatlakozás (**Az újracsatlakozáshoz oldd fel a széfet.**).
- **Alvást túlélő alagutak.** Az OpenVPN saját újraindulása (`ping-restart`) és a WireGuard egy rövid alvást át is vészelhet, így ébredés után a kapcsolat még él. Minden ébredés után egyszer a MacVPN az ilyen kapcsolatot összeveti az új hálózattal: ha valamelyik hálózata vagy DNS-szervere ott közvetlenül elérhető (a fenti példában az iroda), a MacVPN **bontja**, és megírja, miért (**Office VPN: megszakadt a kapcsolat** / **A VPN hálózata itt közvetlenül elérhető, ezért a kapcsolat bontva lett.**), mert ha a helyi hálózat az alagútba menne, elérhetetlenné válna. Minden más hálózaton (kávézó, másik otthoni hálózat) az alagút él tovább. Az így bontott kapcsolat úgy számít, mintha te bontottad volna: nem csatlakozik magától újra, amíg újra nem csatlakoztatod. Ez az ellenőrzés a lenti kapcsolótól függetlenül fut.
- **Ha a kapcsolat alól eltűnik a hálózat.** A WireGuard, az OpenVPN és a strongSwan maga nem veszi észre, hogy kikapcsoltad a Wi-Fit vagy kihúztad a kábelt, így továbbra is csatlakozottnak látszanának. A MacVPN figyeli a Mac hálózatát: kb. 3 másodperccel azután, hogy az utolsó Wi-Fi- vagy Ethernet-hálózat is eltűnt (egy rövidebb kiesés nem látszik), minden felépült vagy csatlakozó kapcsolat sora a menüben és a Kapcsolatok ablakban **Hálózatra vár…**, a menüsor ikonja a félig kitöltött pajzs (**MacVPN – Hálózatra vár…**), sosem a pipás. Magát az alagutat ekkor még nem bontja: egy rövid kiesést gyakran túlél.
  - **2 percen belül visszajön a hálózat:** a túlélő alagút újra csatlakozottnak látszik (ha az új hálózaton a VPN saját hálózata közvetlenül elérhető, alvás utánihoz hasonlóan bontja, lásd lent). A túl nem élő alagút megszakad, és onnan a szokásos szabályok érvényesek: **Automatikus újracsatlakozás** mellett ugyanazon a hálózaton újracsatlakozik (ha másik hálózat jött vissza, azon: lásd **Ha hálózatot váltasz**), kikapcsolt kapcsolóval bontva marad, a szokásos **megszakadt a kapcsolat** értesítéssel.
  - **2 percig nincs hálózat:** a MacVPN bontja a kapcsolatot, hogy a DNS és az útvonalak ne mutassanak egy halott alagútba (**Office VPN: megszakadt a kapcsolat** / **2 percig nem volt hálózat.**). Bekapcsolt **Automatikus újracsatlakozás** mellett a szöveg így folytatódik: **Újracsatlakozik, amikor visszajön a hálózat.**, és amikor visszajön a hálózat, a kapcsolat a fenti szabályok szerint újra felépül (ugyanaz a hálózat, a VPN hálózatai nem érhetők el közvetlenül). Egy párosított app által indított kapcsolatot bont, de sosem csatlakoztat újra.
- **Ha egy alagút nem válaszol** (a 2.0.3-tól). Egy alagút meglévő hálózat mellett is leállhat: eltűnt a WireGuard-szerver, vagy az OpenVPN újra és újra újraindul, mert a szervere nem válaszol. A MacVPN 30 másodpercenként megkérdez erről minden WireGuard- és OpenVPN-kapcsolatot, amíg a Macnek van hálózata (hálózatra várva és alvás közben nem):
  - **WireGuard:** nincs kapcsolatállapota, ezért a MacVPN az időzítőit követi. Ha a configjában van `PersistentKeepalive`, az alagút néhány másodpercenként küld valamit; halott, ha kb. 3½ perce nem volt sikeres kézfogása. `PersistentKeepalive` nélkül a WireGuard semmit sem küld, amíg az alagutat nem használod, így egy tétlen alagút sosem számít halottnak; halott, ha a munkamenete lejárta után (3 perccel az utolsó kézfogás után) küldött valamit, és 1½ perccel később sincs új kézfogás.
  - **OpenVPN:** amíg magától indítja újra az alagutat (`ping-restart`), a sorában **Újracsatlakozás…** áll, a menüsor ikonja a félig kitöltött pajzs, sosem a pipás. Ha 2 percen belül nem jön vissza, halott. (`ping-exit`-tel az OpenVPN inkább leáll: az megszakadás, lásd **Mikor indul**.)
  - **A halott alagutat** a MacVPN bontja, hogy a DNS és az útvonalak ne mutassanak bele. Bekapcsolt **Automatikus újracsatlakozás** mellett azonnal újra csatlakoztatja (**Office VPN: nem válaszol** / **A VPN-szerver nem válaszol. A kapcsolat újracsatlakozik.**, utána **Office VPN: újracsatlakozva**), a fenti szabályok szerint. Kikapcsolt kapcsolóval, vagy ha egy párosított app indította, bontva marad: **A VPN-szerver nem válaszol, ezért a kapcsolat bontva lett.**, a sorában **Nem válaszol** áll, a menüsor ikonján felkiáltójel, amíg nem csatlakoztatod vagy bontod. Az újra és újra leálló alagút 10 percen belül 3 újracsatlakozás után a lassú próbálkozásokra vált: **3 újracsatlakozás után is újra elnémult. 5 percenként újrapróbálja, legfeljebb egy órán át.**
  - Az IKEv2, SSTP, L2TP és Cisco IPsec kapcsolatokat nem kérdezi: ezek maguk bontják a halott kapcsolatot (halott-társ észlelés, PPP echo), és a megszakadást a fentiek szerint csatlakoztatja újra. Az IKEv2-nél a MacVPN a halott-társ észlelést hozzáadja a confighoz, ha az nem tartalmazza (lásd [3.3](#33-ikev2-strongswan)).
  - Ehhez legalább 10-es root réteg kell: amíg a **Rendszerállapot** nem frissítette (**Frissítés szükséges (9 → 11)**), nincs észlelés.
- **Ha hálózatot váltasz** (a 2.0.3-tól: Wi-Fi-ről másik Wi-Fi-re, Wi-Fi-ről kábelre, vagy a hálózat a **Hálózatra vár…** 2 percén belül másik hálózatként jön vissza). A felépült alagút az új hálózaton fut tovább, ha tud; a MacVPN 2 percig közelről figyeli. A WireGuard halott, ha küld, de 20 másodpercig semmit sem kap (egy működő szerver másodperceken belül válaszol), az OpenVPN, ha egy percig újra és újra újraindul. A halott alagutat **az új hálózaton** csatlakoztatja újra: ébren váltottál hálózatot egy felépült kapcsolattal, így az új hálózat lesz a hálózata. Ha a VPN valamelyik hálózata vagy DNS-szervere az új hálózaton közvetlenül elérhető (az iroda), inkább bontja, ahogy alvás után. A pont a váltáskor megszakadó alagutat is az új hálózaton csatlakoztatja újra. Alvás után marad a szabály: csak ugyanazon a hálózaton.
- **A kapcsoló.** Minden MacVPN-ben létrehozott kapcsolat részleteinél a Kapcsolatok ablakban ott az **Automatikus újracsatlakozás** (alapból be; a rendszer VPN-eknél nincs). Kapcsold ki annál a kapcsolatnál, amelynek alvás után bontva kell maradnia. A beállítás ezen a Macen marad (nincs a mentésben és az exportban); egy törölt, majd újra importált kapcsolatnál ismét be van kapcsolva.
- **Korlátok.** Az OpenVPN-szerver által küldött útvonalakat a MacVPN a kapcsolat naplójából olvassa, ezért hagyd meg az alapértelmezett naplószintet (`verb 3`; a `verb 1` vagy `2` elrejti őket). Az IKEv2, SSTP, L2TP és Cisco IPsec kapcsolatok nem adják meg a hálózataik listáját: náluk csak az „ugyanaz a hálózat” szabály érvényes.

### 5.6 DNS kapcsolat közben

Az OpenVPN (a szervertől kapott DNS-sel), a WireGuard (`DNS =` sor) és az SSTP (**A szerver DNS-ének használata**) a kapcsolat idejére a VPN DNS-szervereit állítja be a Mac minden hálózati szolgáltatásán. Mindhármat a MacVPN root rétegének egyetlen DNS-kezelője végzi:

- **Az eredeti beállítások lemezen maradnak** (csak a rendszer olvashatja), még mielőtt az első kapcsolat bármit módosítana. Amikor az utolsó, DNS-t állító kapcsolat bomlik, a MacVPN visszaállítja az eredetit, és ellenőrzi, hogy érvényes lett-e (a naplóban: **original DNS restored and verified**).
- **Több kapcsolat:** a legutóbb felépült kapcsolat DNS-e érvényes. Ha az bomlik, a még élők közül a legújabbé jön vissza; az eredeti csak az utolsóval tér vissza, bármilyen sorrendben bontasz.
- **Összeomlás és újraindítás:** ha egy VPN-program bontás nélkül áll le, vagy a Mac kapcsolódás közben újraindul vagy leáll, a MacVPN a következő állapotlekérdezésekor (induláskor, és futás közben rendszeresen) visszaállítja a DNS-t.
- Minden változtatást visszaolvas, és ha nem lett érvényes, még egyszer beállítja; az eredmény a kapcsolat naplójában áll (**DNS set and verified on 2 network service(s)**, vagy egy **DNS check failed** sor a szolgáltatás nevével).
- **Korlátok.** Egy VPN 1–16 DNS-szervert és legfeljebb 32 keresési tartományt állíthat be (mindegyik legfeljebb 253 bájt). Az ezen kívül eső vagy érvénytelen elemet tartalmazó listát egészében elutasítja, nem rövidíti meg: a DNS nem változik, a kapcsolat a saját DNS-eddel épül fel, és a naplóban ez áll: **a VPN DNS-beállításai túllépik a korlátot (… szerver, … keresési tartomány; legfeljebb 16 és 32): a DNS nem változott**.
- Az IKEv2-t (a strongSwan maga alkalmazza a szerver DNS-ét, a beállításaid módosítása nélkül), az L2TP-t, a Cisco IPsec-et és a rendszer VPN-eket a macOS kezeli.
- **Egyszer, 1.5-ös vagy régebbi verzióról frissítve:** egy régebbi MacVPN kapcsolódás közbeni összeomlás vagy újraindítás után beállítva hagyhatta egy VPN DNS-szerverét. Erről a 2.0 nem tudhat. Ha VPN nélkül, a szokásos hálózatodon nem nyílnak meg a weboldalak, nyisd meg a **Rendszerbeállítások → Hálózat** pontot, válaszd ki a szolgáltatást (Wi-Fi vagy Ethernet) → **Részletek…** → **DNS**, és töröld a VPN DNS-szervereit (vagy állítsd vissza a sajátodat). Ezt csak egyszer kell megtenned.

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

**Naplóméret.** Egy kapcsolat naplója (`/var/log/macvpn/<azonosító>.log`) legfeljebb 5 MiB. Ha megtelik, a legújabb sorai a régebbi részbe, az `<azonosító>.log.1`-be kerülnek (ez is legfeljebb 5 MiB), és a napló újraindul, miközben a kapcsolat fut tovább; így egy kapcsolat akármeddig él, nagyjából 10 MB-nál többet nem foglal. A VPN-programok saját (csak a rendszer által olvasható) munkanaplóit 5 MiB fölött a legújabb 1 MiB-ra vágja. Az OpenVPN `--mute 20`-szal indul: 20 egyforma fajta sor után már csak egy számlálót ír, így a milliószor ismétlődő üzenet (például `Network is unreachable`, amíg nincs hálózat) nem árasztja el a naplót; a config saját `mute` vagy magasabb `verb` sora ezt nem írja felül. Egy régebbi MacVPN által hagyott nagy napló a következő csatlakozáskor vagy bontáskor erre a méretre rövidül.

**Napló műveletek:** szűrés (**Minden**, **Parancsok**, **Hibák**), **Keresés**, időszűrő, **Követés** (automatikus görgetés), **Másolás** (a szűrt sorokat másolja), **Mentés…** (a naplót `<név>-naplo.txt` néven menti, csak te olvashatod), **Napló törlése…**. Jelszó, PSK és privát kulcs nem kerül a naplóba, így a mentett napló is megosztható (például a rendszergazdával). Kivétel az SSTP debug naplója, lásd fent.

**Időszűrő.** A **Keresés** melletti menüvel csak egy időszak sorai látszanak: **Bármikor** (alapértelmezés), **Utolsó 5 perc**, **Utolsó 15 perc**, **Utolsó óra**, **Ma**, vagy **Egyéni időszak**, amely egy **Ettől** és egy **Eddig** mezőt ad (helyi idő; bármelyik üresen maradhat). A szűrőkkel és a kereséssel együtt működik, és a **Másolás** azt másolja, ami látszik. Egy sor ideje az, amellyel kezdődik (az OpenVPN `2026-10-28 14:03:05`, a wireguard-go `2026/10/28 14:03:05`, a pppd `Wed Oct 28 14:03:05 2026` formája, minden csatlakozás `═══ … ═══` fejléce); a saját idő nélküli sor (folytatósor, a MacVPN egy lépése) az előtte lévő sorhoz tartozik. Időszűrővel a nézet első időpontja előtti sorok nem látszanak.

**Napló törlése…** megerősítés után (**Törlöd a naplót: <név>? Ez nem vonható vissza.**) kiüríti a kapcsolat naplóját, a régebbi részével (`<azonosító>.log.1`) együtt. Élő kapcsolatnál is működik: a napló az új sorokkal folytatódik. A kiürített napló első sora **Napló törölve: <idő>**, így aki később olvassa, látja, hová lettek a korábbi sorok. A MacVPN a saját naplófájlodat maga üríti ki (nem kell rendszergazdai jelszó). L2TP-nél és Cisco IPsec-nél a debug módban gyűjtött sorokat törli. Ha még szükséged lehet rá, előbb mentsd el a naplót.

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
- `12. sor: Túl hosszú sor`
- `7. sor: Külső fájl hivatkozás, inline blokk kell: ca`
- WireGuard: `4. sor: Tiltott kulcs: postup`, `6. sor: Nem engedélyezett kulcs: …`
- IKEv2: `2. sor: Tiltott: include`, `9. sor: Tiltott kulcs: updown`, `6. sor: Csak fájlnév adható meg, útvonal nem: cacerts`
- Argumentumok: `4. sor: Érvénytelen argumentum: dev`, `8. sor: Hibás argumentumszám: keepalive`, WireGuard: `3. sor: Érvénytelen érték: address`

A MacVPN rootként indítja a VPN-eszközöket, ezért csak ismert, biztonságos beállításokat enged. Javítás:

- **Tiltott direktíva / kulcs** (például `up`, `down`, `script-security`, `PostUp`): ezek külső parancsot futtatnának. Töröld a sort, vagy tegyél elé `#` jelet. A DNS-t és a route-okat a MacVPN kezeli, ezekre a scriptekre nincs szükség.
- **Kockázatos direktíva, tudomásulvétel szükséges / nincsenek tudomásul véve:** a beállítás csak tudomásulvétel után engedett. Olvasd el az indoklást a sárga panelen; ha kell a beállítás, jelöld be a **Tudomásul veszem a beállításokat és a biztonsági kockázatokat** négyzetet és **Mentés**, különben tedd megjegyzésbe a sort. Ha a tudomásulvétel után új kockázatos sort adtál hozzá, jelöld be újra.
- **Nem engedélyezett setenv:** a változó neve befolyásolhatná a MacVPN root DNS-hookját (például `PATH`, `BASH_ENV`, `LD_*`, `DYLD_*`). Töröld a sort, a kapcsolathoz nem kell.
- **Érvénytelen argumentum** ismeretlen vagy kockázatos direktívánál: az argumentum nem tartalmazhat útvonalat (`/`, `..`, `~`, `file:`), vezető `-` jelet és shell-karaktert (`` ` $ ; | & < > ``).
- **Érvénytelen argumentum / érték, hibás argumentumszám:** a beállítás engedett, de az értéke nem a várt formájú (például eszközútvonal a `dev` után, szám helyett szó). Az üzenet a beállítás nevét mondja meg, az értéket nem. Vesd össze a sort a szolgáltató eredeti configjával.
- **Külső fájl hivatkozás:** a tanúsítvány fájlra hivatkozik (`ca ca.crt`). Importáld újra a `.ovpn` fájlt úgy, hogy a hivatkozott fájlok mellette legyenek, vagy másold be a tartalmukat egy `<ca>…</ca>` blokkba.
- **Nem engedélyezett vezérlőkarakter:** a fájlban láthatatlan karakter van (például Windowsból másolt szöveg). Írd be újra a sort.
- **Túl hosszú sor** (OpenVPN): a config egyik sora 255 bájtnál hosszabb. Az OpenVPN 256 bájtos darabokban olvassa a configot, így egy hosszabb sor maradéka új sornak számítana, amelyet a MacVPN nem ellenőrzött; ez minden sorra érvényes, a megjegyzésekre és a `<ca>` és más beágyazott blokkok soraira is. Rövidítsd a sort, vagy oszd ketté a hosszú megjegyzést. A tanúsítvány- és kulcsblokkok sorai 64 karakteresek, így a szolgáltató fájlja általában átmegy; a túl hosszú sor többnyire kézi szerkesztésből származik.

### 7.8 Egyéb

- **„A telepítés megszakítva: a(z) /usr/local/libexec nem a root tulajdona, vagy más felhasználó is írhatja…”** (vagy ugyanez a `/usr/local`-ra) az **Engedélyezés** gomb után: a root réteg egyik szülőmappája a felhasználódé, vagy más is írhatja. Így bármi, ami ennek a felhasználónak a nevében fut, kicserélhetné a MacVPN root binárisát, ezért a MacVPN nem telepít oda, és a mappát magától nem módosítja. Javítsd a Terminálban, majd nyomd meg újra az **Engedélyezés** gombot:
  ```
  sudo chown root:wheel /usr/local/libexec && sudo chmod go-w /usr/local/libexec
  ```
  (az üzenetben megnevezett mappával). Intel Macen a `/usr/local/libexec` a Homebrew-é lehet; a változtatás után a Homebrew `sudo` nélkül nem tud oda írni, ami egyes csomagokat érinthet.
- **„Az állapot nem kérdezhető le…”** figyelmeztetés a menüben: a root réteg vagy a sudoers szabály hiányzik vagy elavult. Nyisd meg a **Rendszerállapot** ablakot, és nyomd meg az **Engedélyezés** gombot.
- **„Az openvpn nem található (brew install openvpn)”** és hasonló üzenetek: telepítsd a hiányzó eszközt a **Rendszerállapot** ablakból.
- **A `cert` és a `key` ugyanarra a fájlra mutat** (kombinált PEM fájl: tanúsítvány és – akár titkosított – privát kulcs egy fájlban, Windowsos sorvégekkel is): az 1.4.1 óta támogatott. A MacVPN csak a tanúsítványblokkokat teszi a `<cert>`, csak a kulcsot a `<key>` blokkba, és csatlakozáskor kéri a **Privát kulcs jelszava** értékét. Az 1.4.1 előtt ez az import „nem a várt formátumú” hibával leállt.

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

### 7.12 Az értesítések okai

Egy megszakadásról vagy sikertelen csatlakozásról szóló értesítés (lásd [2.3](#23-kapcsolatértesítések)) ezek egyikét adja okként. A MacVPN a kapcsolat naplójának utolsó illeszkedő sorából veszi; nyisd meg a **Napló** fület, és keress a jobb oldali oszlop szövegére.

| Ok | A mögötte álló naplósorok (példák) | Automatikus újracsatlakozás |
|---|---|---|
| **A szerver nem válaszol.** | `Inactivity timeout (--ping-restart)`, `Inactivity timeout (--ping-exit)` (OpenVPN), `giving up after 5 retransmits` (IKEv2), `peer not responding` | megpróbálja |
| **A szerver nem érhető el.** | `TLS key negotiation failed`, `Connection refused`, `Connection timed out` | megpróbálja |
| **A szerver nevét nem sikerült feloldani.** | `Cannot resolve host address` | megpróbálja |
| **A szerver elutasította a bejelentkezést.** | `AUTH_FAILED`, `AUTHENTICATION_FAILED` | nem próbálja |
| **Egy tanúsítványt nem fogadott el a kapcsolat.** | `VERIFY ERROR`, `certificate verify failed` | nem próbálja |
| **Megszakadt a hálózati kapcsolat.** | `Network is unreachable`, `No route to host` | megpróbálja |

Minden más esetben **Kattints a naplóért.** áll ott (sikertelen csatlakozásnál **Részletek a MacVPN-ben**). Az ok csak útmutatás: a fenti szakaszok minden hibát részletesen leírnak.

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

A MacVPN 1.0 váltotta a 0.x Swift appot, az 1.x és a 2.0 ennek folytatása. Minden korábbi verzió, a 0.x és az 1.x is, az appon belüli frissítéssel egyenesen a jelenlegi verzióra (2.0) lép, és az első indítás a széfbe költözteti az adataidat (a [8.2](#82-frissítés-11-ről) rész átköltöztetése). Frissítés előtt olvasd el a [8.2](#82-frissítés-11-ről) részt, és készíts mentést az adatmappádról.

1. **Frissítés az appon belül.** A MacVPN 0.x-ben válaszd a **Frissítések keresése most** pontot, majd a Frissítés ablakban a **Letöltés és telepítés** gombot. A 0.x frissítője az új kiadás aláírását is ellenőrzi, mint bármelyik frissítésnél. (A 0.2.2 előtti verziók nem ellenőrzik az aláírást: ezeknél inkább töltsd le a DMG-t a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról, lépj ki a MacVPN-ből, és cseréld le az appot az Applications mappában.)
2. **A széf létrehozása.** Az új verzió első indításakor átköltöztetési módban megnyílik **A széf beállítása** ablak: válassz mesterjelszót, mentsd el a helyreállítási kulcsot, és hagyd, hogy a MacVPN a széfbe költöztesse a kapcsolataidat, a jelszavakat, a kitűzött kapcsolatokat és a sorrendet, valamint a rendszer VPN-ek egyszer használatos kód beállításait ([8.2](#82-frissítés-11-ről), 3–5. lépés). A frissítési beállítások és az **Indítás bejelentkezéskor** változatlanok maradnak. A futva hagyott kapcsolatok kapcsolódva maradnak. Semmit nem kell újra importálni.
3. **A Keychain az átköltöztetés közben kérdez.** Az új verzió aláírása új, ezért a macOS minden régi Keychain-elemnél megkérdezi, hogy a MacVPN olvashatja-e: elemenként legfeljebb egyszer, és az ablak előre megmondja, hányszor. Kattints a **Mindig engedélyez** gombra, ha a kérdés a `/Applications/MacVPN.app` MacVPN-t nevezi meg. (A nagyon régi verziók `macvpn` Keychain-szolgáltatás alatti bejegyzéseit a MacVPN előbb automatikusan áthelyezi a `local.macvpn.secrets` alá.) Az átköltöztetés után a régi elemek törlődnek, a jelszavak csak a széfben vannak.
4. **A root réteg újratelepítése.** Az 1.0 a 0.x különálló root scriptjei helyett egyetlen `mvpn` binárist hozott; a jelenlegi verzió a 11-es root réteget hozza. Megnyílik a **Rendszerállapot** ablak **Frissítés szükséges** felirattal, 0.4.0-ról például **Frissítés szükséges (6 → 11)**. Kattints az **Engedélyezés** gombra, és add meg az admin jelszót. Előtte az aktív VPN-kapcsolatok bontódnak; a régi fájlok (`ovpn-dns`, `mvpn-validate`, `mvpn-mgmt`) törlődnek. Amíg ezt nem teszed meg, az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokon **Nem használható: Jogosultság (root scriptek + sudoers) – Rendszerállapot** áll, és nem csatlakoznak. A 2.0 többi változása: [8.4](#84-frissítés-15-ről).
5. **Hardened runtime.** Az app és a root binárisa hardened runtime-mal van aláírva, így a macOS nem enged idegen könyvtárat betölteni beléjük. Ez védi a jelszavakat, amelyeket az app a memóriájában tart. Neked ezzel nincs teendőd; az app továbbra is ad-hoc aláírású, ezért a Gatekeeper csak akkor kérdez újra, ha a DMG-ből kézzel telepítesz.

### 8.2 Frissítés 1.1-ről

Az 1.2-től a MacVPN mindent egy titkosított széfben tart (lásd [11.](#11-széf)). Az 1.1-ről az appon belüli frissítés egyenesen a jelenlegi verzióra (2.0, 11-es root réteg) lép, és annak első indítása költözteti a széfbe az adataidat. Maga a frissítés a szokásos, appon belüli frissítés; az első indításra szánj egy kis időt.

1. **Előbb készíts mentést.** Lépj ki a MacVPN 1.1-ből (a kapcsolatok futva maradhatnak), majd másold le az adatmappáját a Terminálban:
   ```
   cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.1
   ```
   A jelszavak a Keychainben vannak, nem ebben a mappában; a frissítés végéig ezeket is tartsd biztonságos helyen (például jelszókezelőben). Indítsd újra a MacVPN 1.1-et.
2. **Frissítés az appon belül.** Menü → **Frissítések keresése most** → **Letöltés és telepítés** (lásd [8.](#8-frissítés)). A MacVPN az új verzióként indul újra.
3. **A széf létrehozása.** Megnyílik a **Széf beállítása** ablak. Jelzi, hogy a kapcsolataid és mentett jelszavaid a széfbe kerülnek, és hogy a macOS hányszor kérhet Keychain-hozzáférést (például **A macOS legfeljebb 5 alkalommal kérhet hozzáférést a Keychainhez – minden alkalommal válaszd a Mindig engedélyez gombot. Ez csak egyszer történik meg.**). Kattints a **Tovább** gombra, válassz mesterjelszót, állítsd be tetszés szerint az **Automatikus feloldás** jelölőt, és kattints a **Széf létrehozása** gombra. Mentsd el és erősítsd meg a helyreállítási kulcsot (lásd [11.1](#111-mesterjelszó-és-helyreállítási-kulcs)).
4. **Az átköltöztetés.** **Az adatok átköltöztetése a széfbe…**: minden kapcsolatmappa, minden mentett jelszó, PSK és kulcsjelszó, a sorrend és a kitűzések, a rendszer VPN-ek egyszer használatos kód beállításai és a párosított appok egy lépésben a széfbe másolódnak, majd visszaolvasás után összehasonlításra kerülnek. A régi fájlok csak ezután íródnak felül és törlődnek, és csak ezután törlődnek a régi Keychain-elemek. Az eredmény: **Az adataid a széfben vannak**, a kapcsolatok és titkok számával. Ha néhány elem nem olvasható, ezt is jelzi (**1 elem nem olvasható, ez a helyén maradt.**); ezek a régi helyükön maradnak.
5. **Keychain kérdések.** Az átköltöztetés alatt a macOS minden régi Keychain-elemnél egyszer rákérdezhet, mert az új app új ad-hoc aláírást kapott. Minden kérdés a MacVPN-t és a `/Applications/MacVPN.app` útvonalat nevezi meg: válaszd a **Mindig engedélyez** gombot. Ha az **Elutasítás** gombra kattintasz, az a titok nem olvasható: a Keychainben marad, és a kapcsolat a következő csatlakozáskor bekéri. Ez csak egyszer történik meg: utána a MacVPN legfeljebb egy Keychain-elemet tart (lásd [8.](#8-frissítés)).
6. **Root réteg 7 → 11.** A **Rendszerállapot** ablakban **Frissítés szükséges (7 → 11)** áll. Kattints az **Engedélyezés** gombra, és add meg egyszer az admin jelszót. Előtte az aktív VPN-kapcsolatok bontódnak. Amíg ezt nem teszed meg, az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokon **Nem használható: Jogosultság (root scriptek + sudoers) – Rendszerállapot** áll; az L2TP, a Cisco IPsec és a rendszer VPN-ek enélkül is működnek.
7. **Ellenőrzés.** Csatlakozz egyszer minden kapcsolattal. A szerkesztőkben a mentett jelszavaknál **Mentve – írj be újat a cseréhez** látszik.

**Ha az átköltöztetés nem sikerül** (**Az átköltöztetés nem fejeződött be**), semmi sem törlődik. A MacVPN törli az új, félig feltöltött széfet, és **írásvédetten** tovább használja az 1.1-es adataidat: csatlakozni tudsz, de felvenni, módosítani és törölni nem (**A MacVPN a régi tárolót írásvédetten használja, amíg az átköltöztetés nem sikerül**). A menüben **Az átköltöztetés a széfbe nem fejeződött be. Újrapróbálás…** sáv jelenik meg. Kattints rá (vagy az ablakban az **Újra** gombra), és hozd létre újra a széfet egy új mesterjelszóval; a sikertelen próbálkozás helyreállítási kulcsa érvénytelen. Ha a beállító ablakot a széf létrehozása előtt bezárod, a MacVPN szintén írásvédetten fut az 1.1-es adatokból, és a menü sávja: **A széf beállításának befejezése…**.

A **párosított appok** (vezérlő API) átkerülnek, és az átköltöztetés után is működnek. Az 1.3–2.0 változásai is érvényesek: lásd [8.3](#83-frissítés-12-ről) és [8.4](#84-frissítés-15-ről).

### 8.3 Frissítés 1.2-ről

A MacVPN 1.3 a szokásos, appon belüli frissítés. Az 1.3-ban a root réteg 8 marad, így a **Rendszerállapot** nem kér admin jelszót. Az 1.2-ről az appon belüli frissítés most egyenesen a 2.0-ra lép: a széf az itt leírtak szerint frissül, a root réteg pedig 8-ról 10-re vált, ahogy a [8.4](#84-frissítés-15-ről) leírja.

- **Az első indítás frissíti a széfet.** A MacVPN 1.3 felveszi a csapatkatalógusok tábláit. Mielőtt bármit módosítana, a még titkosított régi széfről másolatot készít `vault.db.bak-v1` néven a `vault.db` mellé. Az adataidban más nem változik.
- **Visszatérés az 1.2-re** csak írásvédetten működik: az 1.2 a frissített széfet írásvédetten nyitja meg (csatlakozni tud, de szerkeszteni nem, és mentést sem tud visszaállítani bele). A `vault.db.bak-v1` fájlt ne tedd vissza kézzel: ez nem támogatott visszaút. Ha újra szerkesztenéd a kapcsolataidat, frissíts az 1.3-ra.
- **Keychain:** a macOS egyszer megkérdezheti, hogy a MacVPN olvashatja-e a széfkulcsot (csak bekapcsolt **Automatikus feloldás** mellett), mint minden frissítés után. Csak a MacVPN saját kérdésénél engedélyezd (lásd [8.](#8-frissítés)).
- A **csapatkatalógusokhoz** minden közzétevő és feliratkozó Macen MacVPN 1.3 kell.
- **Mikor törölhető a `vault.db.bak-v1`:** ha elégedett vagy az 1.3-mal (nem térsz vissza az 1.2-re, és van friss teljes mentésed, lásd [14.2](#142-teljes-biztonsági-mentés)), töröld. A frissítés előtti állapotában tartalmazza az adataidat, ugyanazzal a széfkulccsal titkosítva, így aki a széfedet meg tudja nyitni, ezt is; a MacVPN sosem frissíti és nem használja.

### 8.4 Frissítés 1.5-ről

A MacVPN 2.0 a szokásos, appon belüli frissítés. Ugyanez érvényes, ha 1.3-ról vagy 1.4-ről jössz. A széf nem változik.

- **Root réteg 8 → 11.** A DNS-kezelő, a naplóméret-korlát, a strongSwan-változások, (a 2.0.3-tól) a halott alagút észlelése és (a 2.0.3 utáni kiadástól) a strongSwan forgalmi adatai a root rétegben vannak, ezért a **Rendszerállapot** **Frissítés szükséges (8 → 11)** sort mutat. A 2.0.0–2.0.2-ről **Frissítés szükséges (9 → 11)**, a 2.0.3-ról **Frissítés szükséges (10 → 11)**: ugyanígy **Engedélyezés**. Kattints az **Engedélyezés** gombra, és add meg egyszer az admin jelszót. Az aktív VPN-kapcsolatok előbb bomlanak. Addig az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokon **Nem használható: Jogosultság (root scriptek + sudoers) – Rendszerállapot** áll.
- **Új beállítások, alapból bekapcsolva:** **Kapcsolatértesítések** ([2.3](#23-kapcsolatértesítések)) és minden kapcsolatnál az **Automatikus újracsatlakozás** ([5.5](#55-automatikus-újracsatlakozás)). A **Megjelenés** **Rendszer szerint** értékkel indul.
- **Régebbi verzió által hagyott DNS:** ha az 1.5 vagy egy régebbi verzió alatt egy összeomlás vagy újraindítás után beállítva maradt egy VPN DNS-szervere, egyszer állítsd vissza kézzel (lásd az [5.6](#56-dns-kapcsolat-közben) végét).
- **Egy régebbi verzió nagyon nagy naplója** (például egy több gigabájtos `.log.1` a `/var/log/macvpn` alatt) a kapcsolat következő csatlakozásakor vagy bontásakor 5 MiB-ra rövidül.

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
- **Csapatkatalógusok (1.3).** A katalógust a rendszergazda adminisztrátori aláírókulcsa aláírja, a csapatkulcs titkosítja; a MacVPN az aláírást a rögzített ujjlenyomattal ellenőrzi, a régebbi verziókat elutasítja, és minden configot úgy ellenőriz, mint egy importnál. Hogy melyik rész mi ellen véd, és mi ellen nem: [16.11](#1611-biztonsági-modell).
- **Nincs proxy (frissítések, csapatkatalógusok).** A MacVPN a frissítéseket és a HTTPS-es csapatkatalógusokat a rendszer `curl` programjával tölti le, kiürített környezetben, ezért a proxybeállításokat (`https_proxy`, `all_proxy`, a macOS proxybeállításai) nem használja: a frissítési szervernek és a katalógus kiszolgálójának közvetlenül elérhetőnek kell lennie. Proxybeállítás egy későbbi verzióban jöhet.
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

### 12.8 Kapcsolatok keresése

A **Kapcsolatok** ablak oldalsávjának tetején lévő **Kapcsolatok keresése** mező (**⌘F**) gépelés közben szűri a listát. A kis- és nagybetű meg az ékezet nem számít: az „arvizturo” megtalálja az „Árvíztűrő”-t. Keres a kapcsolat nevében, típusában (OpenVPN, WireGuard, …), a szerverében (a beállításokból vagy a konfigurációból vett gépnév, például az OpenVPN első `remote` sora), a csapatkatalógusa nevében és a mappái nevében; ha egy mappa neve illeszkedik, a teljes tartalma látszik, a találatok mappái pedig kinyílnak anélkül, hogy a csukva tartott mappáid állapota változna. A **↑** és **↓** a találatok között lép, az Enter megnyitja a kiemeltet, az Esc kiüríti a mezőt (a második Esc kilép belőle). Keresés közben a húzás nem működik; a **Hitelesítő adatok**, **Párosított appok**, **Csapatkatalógusok** és **Közzététel** alul elérhető marad. Ha nincs találat, a **Keresés törlése** visszahozza a teljes listát.

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
- az app beállításai: automatikus frissítéskeresés, a 24 órás késleltetés, **Indítás bejelentkezéskor**, **Más appok vezérelhetik a VPN-eket** és **Automatikus feloldás**,
- az 1.3-tól: a **csapatkatalógus-feliratkozásaid** (forrás, csapatkulcs, hozzáférési token, a rögzített közzétevői kulcs és a legutóbb alkalmazott verzió), az **adminisztrátori aláírókulcsaid** és a **közzétételeid** a csapatkulcsaikkal. Maguk a katalógus kapcsolatai és mappái nincsenek a mentésben: visszaállítás után a következő frissítés visszahozza őket a forrásból, a kitöltött közös belépési adatok helyeivel, a kitűzésekkel és a sorrenddel együtt. Egyetlen visszaállítás, sem az összefésülés, sem a **Minden cseréje**, nem csökkenti egy ezen a Macen már követett katalógus legutóbb alkalmazott verzióját, így a visszaléptetés elleni védelem tovább működik.

Az aláírókulcsot tartalmazó mentéssel katalógust lehet aláírni a csapatodnak: úgy védd, mint magát az aláírókulcsot. Nincs benne: a **párosított appok** (ezen a Macen lévő programútvonalakhoz kötődnek: visszaállítás után párosítsd őket újra), a széfkulcs és a helyreállítási kulcs, valamint a naplók.

### 14.2 Teljes biztonsági mentés

1. Menü → **Beállítások** → **Teljes biztonsági mentés…** (vagy a Kapcsolatok ablakban **Új** (+) → **Teljes biztonsági mentés…**). Feloldott széf kell hozzá.
2. Olvasd el a figyelmeztetést: **Aki birtokolja ezt a fájlt és a jelszavát, az összes VPN-hitelesítő adatodat elolvashatja.**
3. Válassz egy **A mentés jelszava** jelszót (legalább 10 karakter), és ismételd meg. A MacVPN nem tárolja: nélküle a mentés nem nyitható meg.
   - Helyette a **A mesterjelszavam használata…** gombbal a mesterjelszót is használhatod, a **Mesterjelszó használata** megerősítése után. Akkor viszont bárki, aki megtudja a mesterjelszavadat, ezt a fájlt is megnyithatja, bárhol is tárolod; egy külön mentési jelszó elválasztja a kettőt.
   - Írd be a **Mesterjelszó** mezőbe a mesterjelszót is. A MacVPN minden mentés előtt ellenőrzi (rossz jelszó után ugyanazzal a várakozással, mint a feloldáskor), így egy felügyelet nélkül hagyott, feloldott Mac nem elég ahhoz, hogy valaki minden jelszavadról másolatot vigyen.
4. Kattints a **Mentés…** gombra, és válaszd ki a helyét. A fájl neve `MacVPN-backup-<dátum>.macvpnbackup`, csak te olvashatod.
5. A fájlt és a jelszavát tartsd külön, például a fájlt egy külső lemezen, a jelszót egy jelszókezelőben.

### 14.3 Visszaállítás új Macen

1. Telepítsd a MacVPN-t, és indítsd el. Az 1.2 készítette mentéshez 1.2 vagy újabb kell; az 1.3 vagy újabb verzió (a 2.0 is) készítette mentéshez 1.3 vagy újabb (az 1.2 elutasítja, mert újabb MacVPN készítette).
2. A **Széf beállítása** ablakban kattints a **Visszaállítás biztonsági mentésből…** gombra. (Ehhez új, üres széf kell.)
3. **Fájl kiválasztása…**, add meg **A mentés jelszava** mezőt, és kattints a **Mentés megnyitása** gombra.
4. Válassz új mesterjelszót ehhez a Machez, és mentsd el az új helyreállítási kulcsot, ahogy a [11.1](#111-mesterjelszó-és-helyreállítási-kulcs) leírja.
5. Minden egy lépésben visszaáll. Utána kövesd a [14.5](#145-visszaállítás-után) lépéseit.

### 14.4 Visszaállítás meglévő széfbe

1. Menü → **Beállítások** → **Visszaállítás biztonsági mentésből…**. Semmi sem változik, amíg jóvá nem hagyod, mit állítson vissza.
2. **Fájl kiválasztása…**, **A mentés jelszava**, **Mentés megnyitása**. Hibás jelszónál vagy sérült fájlnál egyetlen üzenet jön: **A mentés nem nyitható meg. Hibás a jelszó, vagy sérült a fájl.**
3. Az összesítő megmutatja, mikor és melyik verzió készítette (**Készült: …, MacVPN 1.2.0**), és hány **Kapcsolatok**, **Mappák** és **Közös hitelesítő adatok** tétel van benne. Elöl felsorolja azokat a kapcsolatokat, amelyeknél kockázatos OpenVPN-beállítások (például rootként futó szkriptek) vannak jóváhagyva: csak saját készítésű mentést állíts vissza.
4. Válassz:
   - **Összefésülés**: hozzáadja, ami itt hiányzik. A már létező elemekre egyszer, mindegyikre érvényesen döntesz (**Ha egy elem már létezik:**): **Felülírás a mentésben lévő példánnyal**, **Az itt lévő elem megtartása**, vagy **Mindkettő megtartása (a mentésből származó másolat neve „(backup)” végződést kap)**. Az összefésülés elveti a visszaállított kapcsolatok kockázatos beállításainak jóváhagyását, hacsak ugyanez a kapcsolat ugyanezzel a configgal már nincs itt; ilyenkor a szerkesztő újra rákérdez. Az összefésülés sosem módosítja egy csapatkatalógus kapcsolatait vagy mappáit: az azonos azonosítójú mentett elemet (egy 1.3-as széfről az 1.2 által készített mentés közönséges elemként tartalmazza őket) minden módban kihagyja, és az eredmény megnevezi.
   - **Minden cseréje**: előbb kiüríti a széfet. Egy megerősítés megmondja, hány kapcsolat, mappa és közös hitelesítő adat törlődik; **Ez nem vonható vissza.** Az **Előbb a jelenlegi állapot mentése…** gomb a folytatás előtt elmenti a mostani állapotot. A párosított appok maradnak. A csere megtartja a jóváhagyásokat.
     - A **csapatkatalógus-feliratkozások** helyére a mentésben lévők kerülnek. A megerősítés megnevezi az itteni, a mentésben nem szereplő feliratkozásokat: ezek a kapcsolataikkal és mappáikkal együtt törlődnek. A mindkettőben meglévő katalógus a magasabb alkalmazott verziót tartja meg.
     - Az **aláírókulcsok és a közzétételek** ehhez a Machez tartoznak, mint a párosított appok: az a szerep (elsődleges vagy tartalék kulcs) vagy katalógus, amelyhez a mentésben nincs semmi, megtartja az itteni kulcsot vagy közzétételt (az 1.2-es mentésben egyik sincs, így mind megmarad). Ahol a mentésnek saját van, az kerül a helyére, és a megerősítés megszámolja a lecserélt kulcsokat és megnevezi a lecserélt közzétételeket. Egy közzététel verziója sosem csökken.
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

---

## 16. Csapatkatalógusok

A **csapatkatalógus** VPN-kapcsolatokat oszt meg egy csapattal. A közzétevő (a rendszergazda) egyszer közzétesz egy kapcsolatkészletet, a mappáikkal, színeikkel és névvel ellátott bejelentkezési helyekkel együtt. A csapattagok MacVPN-je feliratkozik rá, és magától átveszi az új, a módosult és a törölt kapcsolatokat. Mindenki megtartja a saját felhasználónevét, jelszavát és egyszer használatos kódjának titkát, valamint a saját kitűzéseit, sorrendjét és csukott mappáit.

- A katalógus egyetlen fájl, `<név>.macvpncatalog`. A rendszergazda **adminisztrátori aláírókulcsa** **aláírja**, a **csapatkulcs** pedig **titkosítja**.
- A MacVPN semmit nem tölt fel. A rendszergazda a fájlt egy HTTPS-es webszerverre, egy fájlmegosztásra vagy egy szinkronizált mappába teszi, és a tagok onnan olvassák.
- Minden csapattagnak MacVPN 1.3 vagy újabb kell, Windowson WinVPN 2.0 vagy újabb (lásd a [WinVPN felhasználói útmutatóját](winvpn-user-guide.hu.md)).
- Több katalógus is használható egyszerre, és ugyanazon a Macen közzé is tehetsz, és fel is iratkozhatsz.

Amit a tag a rendszergazdától kap: a **forrás** (egy `https://` cím vagy egy fájl útvonala), a **csapatkulcs** (`TEAM-`, utána 14 darab 4 karakteres csoport) és a **közzétevő ujjlenyomata** (8 darab 4 hexadecimális jegyből álló csoport). A **feliratkozási kód** (`macvpn-sub:…`) mindhármat egy sorban tartalmazza.

### 16.1 Feliratkozás egy katalógusra

1. Nyisd meg a **Kapcsolatok** ablakot, és az oldalsávban válaszd a **Csapatkatalógusok** részt. Kattints a **Csapatkatalógus hozzáadása…** gombra.
2. Illeszd be a rendszergazdától kapott **feliratkozási kódot**. Ez kitölti a forrást és az ujjlenyomatot; a csapatkulcsot ellenőrzi, és rejtve tartja. Feliratkozási kód nélkül töltsd ki magad a mezőket:
   - **Forrás:** egy `https://` cím, vagy **Fájl** és **Fájl kiválasztása…** egy megosztáson vagy szinkronizált mappában (iCloud Drive, OneDrive, Dropbox) lévő fájlhoz.
   - **Csapatkulcs:** `TEAM-XXXX-…`. A kis- és nagybetű, a kötőjel és a szóköz nem számít; az `O` `0`-nak, az `I` és az `L` `1`-nek számít. Az utolsó csoport ellenőrző csoport, így az elírás már beíráskor kiderül, és szinte sosem téveszthető össze egy rossz kulccsal.
   - **A közzétevő ujjlenyomata:** 8 darab 4 karakteres csoport. Kötelező: a MacVPN nélküle sosem bízik meg az első letöltésben.
3. **Hozzáférési token** (nem kötelező, csak HTTPS-nél): ha a webszerver bearer tokent kér, itt add meg. Nincs benne a feliratkozási kódban, mert a token gyakran személyes; kérd el a rendszergazdától.
4. Kattints az **Ellenőrzés** gombra. A MacVPN letölti a katalógust, a megadott ujjlenyomattal ellenőrzi az aláírását, és a csapatkulccsal megnyitja. Az előnézet mutatja a katalógus nevét, verzióját és ujjlenyomatát, a kapcsolatok és mappák számát, a közös belépési adatok helyeit (lásd [16.3](#163-közös-belépési-adatok-helyei)), és hogy hány kapcsolatban van kockázatos beállítás.
5. **Hasonlítsd össze az ujjlenyomatot** azzal, amit a rendszergazda egy másik csatornán, például telefonon mondott. Ha eltér, ne iratkozz fel.
6. Jelöld be **Az ujjlenyomat egyezik azzal, amit a rendszergazda küldött** négyzetet, és kattints a **Feliratkozás** gombra. A katalógus kapcsolatai azonnal megjelennek, és a **Csapatkatalógusok** rész mutatja az új feliratkozást. A **Mégse** vagy a **Vissza** eldobja a letöltött előnézetet.

**A Finderből.** Kattints duplán egy `.macvpncatalog` fájlra (például a rendszergazda által megadott fájlmegosztáson). A MacVPN megnyitja a **Csapatkatalógusok** részt a **Csapatkatalógus hozzáadása…** ablakkal: a forrás **Fájl**, és ez a fájl van kiválasztva. A csapatkulcsot és a közzétevő ujjlenyomatát ugyanúgy neked kell megadnod, az **Ellenőrzés** után összevetni az ujjlenyomatot és bejelölni a négyzetet: a fájl megnyitása önmagában semmire nem iratkoztat fel. Ha egyszerre két katalógusfájlt nyitsz meg, csak az első számít (**Egyszerre csak egy csapatkatalógus-fájl adható hozzá.**).

Ha egy levelezőprogram több sorba törte a feliratkozási kódot, a MacVPN elutasítja: másold ki újra egy sorban. Az előnézet 10 perc után lejár (**A katalógus előnézete lejárt. Add hozzá újra a katalógust.**). Egy már meglévő katalógusnál: **Erre a katalógusra már feliratkoztál.**

**Források.**
- **HTTPS:** csak `https://`, a macOS megbízható tanúsítványaival ellenőrizve. Átirányítást csak `https://` címre követ, legfeljebb ötöt. A hozzáférési tokent csak a feliratkozási cím saját hostjának és portjának küldi el, átirányítás után más hostnak soha. **Proxy nem támogatott:** a MacVPN a rendszer `curl` programjával, kiürített környezetben tölt le, ezért a `https_proxy`, az `all_proxy` és a macOS proxybeállításai nem érvényesek; a katalógus kiszolgálójának közvetlenül elérhetőnek kell lennie.
- **Fájl:** egy csatolt hálózati megosztáson (SMB, NFS) vagy szinkronizált mappában lévő útvonal. Maga a fájl nem lehet szimbolikus link, szabályos fájlnak kell lennie, legfeljebb 8 MB-osnak. A nem csatolt megosztás, vagy egy éppen le nem tölthető felhőbeli fájl **nem elérhető** állapotot jelent, nem hibát (lásd [16.6](#166-hibaelhárítás-felhasználóknak)).

### 16.2 A katalógus kapcsolatai

- Minden katalógusnak saját, legfelső szintű mappája van a katalógus nevével és **Csapat** jelvénnyel, a menüben és a Kapcsolatok ablakban is. Benne vannak a közzétevő mappái és színei.
- **Csak olvasható:** a név, a config, a mappa és a közzétevő színe. A szerkesztő kiírja: **A(z) „Acme VPN” csapatkatalógus kezeli**, és a mezői le vannak tiltva.
- **Amit te állíthatsz:** csatlakozás és bontás, kitűzés és sorrend, mappák csukása, egy kapcsolat saját színe (**A csapat színének használata** visszaállítja a közzétevőét), és a kockázatos beállítások jelölője (a szerkesztőben csak ezt mented). A felhasználóneved és a jelszavad a katalógus közös belépési adatának helyéből jön (lásd [16.3](#163-közös-belépési-adatok-helyei)), ezt a **Hitelesítő adatok** részben módosíthatod. A katalógus kapcsolatai és mappái nem nevezhetők át, nem helyezhetők át, nem húzhatók és nem törölhetők; a helyi menüjük csak a **Kitűzés** / **Kitűzés megszüntetése**, a **Szín…**, a **Másolat saját kapcsolatként…** és – ha a katalógus megváltoztatott egy natív kapcsolatot – a **Profil telepítése** pontot kínálja.
- **Kockázatos beállításokat** (lásd [7.7](#77-nem-engedélyezett-direktíva--tiltott-direktíva)) a katalógus sosem hagy jóvá: a szerkesztő sárga paneljén te jelölöd be őket. Ha egy új katalógusverzió megváltoztatja a configot, újra rákérdez.
- Az **L2TP és Cisco IPsec** kapcsolatokhoz a szokásos módon kell a macOS profil (**Profil telepítése**, majd jóváhagyás a Rendszerbeállításokban). Ha a katalógus módosít egy ilyen kapcsolatot, a kapcsolat részleteiben ez áll: **A csapatkatalógus megváltoztatta ezt a kapcsolatot: telepítsd újra a profilját**, és a csatlakozás az új profil telepítéséig nem indul. Kattints a **Profil telepítése** gombra, és hagyd jóvá a Rendszerbeállításokban. A jelzés eltűnik, amint a macOS mutatja az új profilt. Ha csak a csoportnév vagy a **Minden forgalom a VPN-en keresztül** változott, a macOS nem mutat különbséget: a profil jóváhagyása után kattints a **Telepítettem** gombra, és erősítsd meg. Csak a jóváhagyás után erősítsd meg: ha még a régi profil van telepítve, a kapcsolat a katalógus által már lecserélt beállításokat használná.
- A **párosított appok** (vezérlő API) a katalógus kapcsolatait ugyanúgy látják, mint a többit; kapcsolatonként engedélyezed őket, mint az [5.4](#54-párosított-appok-vezérlő-api) részben. A katalógus egy kapcsolatának azonosítója a verziók között nem változik.
- A **Másolat saját kapcsolatként…** (a kapcsolat részleteiben vagy helyi menüjében) önálló, szerkeszthető másolatot készít a legfelső szinten, „<név> (saját)” néven, ha nem írsz mást. A másolat megtartja a configot, a saját és a katalógus által adott titkokat, és ugyanazt a közös hitelesítő adatot. A kockázatos beállítások jóváhagyása üresen indul. A másolat a tiéd: a későbbi katalógusverziók nem módosítják.

### 16.3 Közös belépési adatok helyei

A **közös belépési adat helye** egy névvel ellátott bejelentkezés, például „Office AD”, amelyet a katalógus felhasználónév és jelszó nélkül használ. Minden tag a sajátjával tölti ki.

- A katalógus első alkalmazásakor a MacVPN minden helyhez létrehoz egy üres **közös hitelesítő adatot** (lásd [13.](#13-közös-hitelesítő-adatok)) a hely nevével. Ha már van ilyen nevű hitelesítő adatod, az új a katalógus nevét kapja utótagként, például „Office AD (Acme VPN)”. A hely sosem kapcsolódik magától egy meglévő hitelesítő adatodhoz.
- Az első csatlakozáskor a bekérő ablak ezt kérdezi: **Office AD („Acme VPN” csapatkatalógus) — add meg a felhasználóneved és a jelszavad**. A **Mentés a széfbe** jelölővel ebbe a közös hitelesítő adatba kerülnek, és a katalógus többi, ugyanezt a helyet használó kapcsolata már kérdés nélkül csatlakozik. A felhasználóneved és a jelszavad a széfedben marad: sosem jut el a rendszergazdához vagy a katalógusba.
- Az **SSTP** kapcsolatok a config `user=` sora helyett a hely felhasználónevét használják, az **L2TP / Cisco** kapcsolatok pedig fióknévként. A tárolt config nem változik.
- A felhasználónevet és a jelszót később a **Hitelesítő adatok** részben módosíthatod, mint bármely közös hitelesítő adatot. Az a kapcsolat, amelynek már van saját mentett felhasználóneve és jelszava, nem kapcsolódik a helyhez.

### 16.4 Frissítés és változások

A MacVPN minden katalógust ellenőriz:

- induláskor és a széf feloldásakor (zárolt széf mellett semmit),
- 15 percenként,
- amikor a Mac felébred alvásból,
- amikor a **Csapatkatalógusok** részben a **Frissítés most** gombra kattintasz.

Ha egy forrás tartósan hibás, a MacVPN egyre ritkábban próbálkozik: 1, 2, 4, 8, 16, 32 perc múlva, utána óránként (egy kis véletlen késleltetéssel). Az ébredés és a **Frissítés most** mindig azonnal próbálkozik. Ha a HTTPS-szerveren nem változott a fájl, a szerver „nem módosult” választ ad; a fájlforrást a MacVPN beolvassa, és összeveti a legutóbb alkalmazottal.

Az új verzió egyetlen lépésben kerül alkalmazásra: vagy minden, vagy semmi. Egy értesítés felsorolja a változásokat, például: **A(z) „Acme VPN” csapatkatalógus frissült: 2 hozzáadva, 3 módosítva, 1 eltávolítva**.

- Az a kapcsolat, amely a változáskor **fennáll**, fennmarad azokkal a beállításokkal, amelyekkel elindult. Az új configot a következő csatlakozástól használja.
- Az a kapcsolat, amely a katalógusból való törléskor **fennáll**, fennmarad, átkerül a katalógus legfelső mappájába, és ez áll mellette: **Törölve a csapatkatalógusból — a bontás után eltűnik**. A bontás után törlődik, a kitűzésével és a sorrendbeli helyével együtt.
- Ugyanaz a verzió újra feltöltve semmit nem változtat, és nem ad értesítést.

A **Csapatkatalógusok** rész minden feliratkozásnál mutatja a forrást (HTTPS-címnél a lekérdezési rész nélkül), az állapotot, a verziót, a legutóbbi frissítést, a közzétevő ujjlenyomatát és a legutóbbi hibát.

### 16.5 Feliratkozás módosítása és leiratkozás

- A feliratkozás részleteiben a **Csapatkulcs cseréje…** (ha a rendszergazda lecserélte), a **Hozzáférési token cseréje…** és a **Forrás szerkesztése…** található. Ha az új forrás másik hoston vagy porton van, vagy fájl, a tárolt hozzáférési token törlődik: a token sosem megy új címre. Ha az új cím tokent kér, add meg.
- A **Leiratkozás…** megnevezi a katalógust, és hogy hány kapcsolatot töröl. A fennálló kapcsolatokat előbb bontja. Utána a katalógus minden kapcsolata és mappája törlődik, és a párosított appok elveszítik hozzájuk a hozzáférést. A kitöltött közös belépési adatok helyei közönséges közös hitelesítő adatként megmaradnak a **Hitelesítő adatok** részben; az üresek törlődnek.
- Ha egy kapcsolatot a leiratkozás után is meg akarsz tartani, előbb készíts róla másolatot (**Másolat saját kapcsolatként…**).

### 16.6 Hibaelhárítás felhasználóknak

- **A katalógust más kulcs írta alá, mint amelynek az ujjlenyomatát megadtad.** (feliratkozáskor): a fájlt nem az a kulcs írta alá, amelyet a rendszergazda adott. Ellenőrizd az ujjlenyomatot a rendszergazdával telefonon. Soha ne „javítsd” úgy, hogy a fájlban lévő ujjlenyomatot írod be.
- **A csapatkatalógust más közzétevő írta alá, mint akiben megbízol.** (frissítéskor): a forrásban lévő fájlt olyan kulcs írta alá, amelyben a MacVPN-ed nem bízik. Vagy valaki más tett oda egy fájlt, vagy a rendszergazda úgy cserélt kulcsot, hogy a bejelentés nem jutott el hozzád (lásd [16.10](#1610-az-aláírókulcs-cseréje-és-a-kompromittálódás)). Kérdezd meg a rendszergazdát; lehet, hogy le kell iratkoznod, és az új ujjlenyomattal újra fel kell iratkoznod.
- **A csapatkatalógus aláírása érvénytelen: módosították.**: a fájlt az aláírás után módosították, vagy megsérült. A kapcsolatok változatlanok maradnak. Kérd meg a rendszergazdát, hogy tegye közzé újra.
- **A(z) „Acme VPN” csapatkulcsa megváltozott. Kérd el a rendszergazdától az új kulcsot.** (értesítés; az állapot: **A csapatkulcs nem nyitja meg ezt a katalógust (hibás, vagy lecserélték).**): a rendszergazda lecserélte a csapatkulcsot. Kérd el az új kulcsot biztonságos csatornán, majd **Csapatkulcs cseréje…** és **Frissítés most**. Addig a katalógus kapcsolatai változatlanok maradnak.
- **A(z) „Acme VPN” csapatkatalógus régebbi verziót kínált (v3 a v5 után), ezért nem lett alkalmazva.**: a forrásban régebbi verzió van, mint ami nálad már megvan. Ez a visszaléptetés elleni védelem (lásd [16.11](#1611-biztonsági-modell)): egy régi példány került vissza a szerverre (szervermentés visszaállítása, szinkronizálási ütközés), vagy valaki régi beállításokat próbál visszahozni. A kapcsolataid nem változtak. Szólj a rendszergazdának; egy új verzió közzététele megoldja.
- **A csapatkatalógus forrása nem érhető el (…).**: a megosztás nincs csatolva, a szerver vagy a hálózat nem működik, vagy egy felhőbeli fájl éppen nem tölthető le. Erről nincs hibaértesítés; a MacVPN a [16.4](#164-frissítés-és-változások) szerinti, egyre ritkább próbálkozással újra megpróbálja. Csatold a megosztást, vagy töltsd le a fájlt a Finderben, majd kattints a **Frissítés most** gombra.
- **A csapatkatalógus nem olvasható: hozzáférés megtagadva (ellenőrizd a hozzáférési tokent)**: a HTTPS-szerver elutasította a kérést (HTTP 401 vagy 403). A **Hozzáférési token cseréje…** gombbal add meg az érvényes tokent. Ha épp most állítottad át a forrást másik hostra, a token szándékosan törlődött (lásd [16.5](#165-feliratkozás-módosítása-és-leiratkozás)): add meg újra.
- **… a tanúsítvány nem megbízható**: a szerver tanúsítványában a macOS nem bízik meg. Szólj a szerver üzemeltetőjének; a MacVPN-ben nincs lehetőség az ellenőrzés kihagyására.
- **… átirányítás nem HTTPS-címre**: a szerver `http://` címre irányít át. A katalógust végig HTTPS-en kell kiszolgálni.
- **A forrás egy másik csapatkatalógust tartalmaz.**: a forrásban lévő fájl egy másik katalógus. Ellenőrizd a forrást a rendszergazdával.
- **A csapatkatalógust újabb MacVPN készítette.**: frissítsd a MacVPN-t.
- **A csapatkatalógus olyan kapcsolatot tartalmaz, amelyet a MacVPN nem tud használni.**: a katalógus egyik kapcsolata nem megy át a MacVPN ellenőrzésén. Semmi nem lett alkalmazva; szólj a rendszergazdának.
- **Proxy mögött:** proxy nem támogatott (lásd [16.1](#161-feliratkozás-egy-katalógusra)). A katalógus kiszolgálójának közvetlenül elérhetőnek kell lennie, vagy a katalógusnak fájlmegosztáson kell lennie.

### 16.7 Rendszergazdáknak: az adminisztrátori aláírókulcs

A közzétételhez **adminisztrátori aláírókulcs** kell: egy Ed25519 aláírókulcs a széfedben. Az **ujjlenyomatát** veti össze a csapat feliratkozáskor.

1. **Kapcsolatok** ablak → **Közzététel** → **Adminisztrátori aláírókulcs létrehozása**. Az ujjlenyomat 8 csoportban jelenik meg; a **Másolás** kimásolja.
2. **Tartalék aláírókulcs létrehozása**, majd **Tartalék kulcs exportálása…**: válaszd ki a `.macvpnadminkey` fájl helyét, és adj meg (kétszer) egy legalább 10 karakteres jelszót. Jelöld be ezt: **A tartalék kulcs törlése erről a Macről az export után**: így a tartalék kulcs csak abban a fájlban lesz meg. A fájlt offline tartsd (például egy széfben lévő USB-kulcson), a jelszavát máshol (például jelszókezelőben).

Minden közzétett katalógus a fájl aláírt részében bejelenti a tartalék kulcsot a jelenlegi kulcs **utódjaként**. A frissítő feliratkozók eltárolják a bejelentést. Amikor átváltasz a tartalék kulcsra, elfogadják az általa aláírt katalógusokat, és a régi kulcsot többé nem fogadják el.

**Váltás a tartalék kulcsra** (tervezett kulcscsere):
1. Azon a Macen, amelyről ezután közzéteszel: **Közzététel** → **Aláírókulcs importálása…**, válaszd ki a `.macvpnadminkey` fájlt, és add meg a jelszavát. Ezen a Macen a közzétételeidnek (minden katalógus azonosítójának, verziójának és csapatkulcsának) is meg kell lenniük: ezek a széfben vannak, nem a kulcsfájlban, ezért ugyanazt a széfet használd, vagy előbb állíts vissza egy teljes biztonsági mentést. Nélkülük a következő közzététel új katalógust hoz létre, amelyre minden tagnak újra fel kell iratkoznia.
2. **Váltás a tartalék kulcsra…**: a tartalék kulcs lesz az aláírókulcs, a régi aláírókulcs törlődik erről a Macről.
3. Tedd közzé minden katalógus új verzióját. Azok a feliratkozók, akik a tartalék kulcs létrehozása óta frissítettek, automatikusan követik a váltást. A többieknek az új ujjlenyomattal újra fel kell iratkozniuk.
4. Hozz létre és exportálj egy új tartalék kulcsot, hogy a következő csere is elő legyen készítve.

Az aláírókulcsok, a közzétételeid és azok csapatkulcsai a széf részei, így a teljes biztonsági mentés ([14.](#14-biztonsági-mentés-és-visszaállítás)) is tartalmazza őket. A mentéseket ugyanúgy védd, mint magát az aláírókulcsot.

### 16.8 Rendszergazdáknak: katalógus közzététele

A **Közzététel** → **Katalógus közzététele…** megnyitja a varázslót:

1. **Kapcsolatok.** Jelöld be a mappákat és a kapcsolatokat. A bejelölt mappa a teljes tartalmát viszi; az a kapcsolat, amelynek a mappája nincs bejelölve, a katalógus legfelső szintjére kerül. Rendszer VPN-t és más katalógusból származó kapcsolatot nem lehet közzétenni.
2. **Áttekintés.** **A katalógus tartalma** megszámolja a kapcsolatokat, a mappákat, a közös belépési adatok helyeit és a csapattitkokat. Alatta, ha a kiválasztásban van ilyen:
   - Azok a kapcsolatok, amelyeket a MacVPN nem hajlandó közzétenni; ezeket előbb javítsd, vagy vedd ki a jelölésüket. Elutasított: az inline `<auth-user-pass>` vagy `<http-proxy-user-pass>` blokkot tartalmazó OpenVPN config, a `secrets` részt tartalmazó strongSwan config (a katalógus sosem visz felhasználói jelszót; használj helyette közös belépési adat helyet), és a hibás config.
   - **A configokba írt kulcsok:** a configba írt kulcsok (a WireGuard `PrivateKey` vagy `PresharedKey`, az OpenVPN `<key>` / `<pkcs12>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>` és `<secret>` blokkja, és a bejelölt hely nélküli SSTP `user=`). Minden tag változatlanul megkapja őket; a továbblépéshez jelöld be mindegyiket, vagy hagyd ki azokat a kapcsolatokat. A WireGuard privát kulcs jelölése: **A katalógus minden felhasználója ugyanazt a WireGuard kulcsot használja**: a szerver ekkor mindenkit ugyanannak a peernek lát.
   - **Személyes mezők:** ami a kiválasztásban személyes, például az SSTP `user=` sora (bejelölt helynél csatlakozáskor minden tag saját felhasználóneve kerül bele) vagy a WireGuard privát kulcs. Az L2TP / Cisco kapcsolatok fiókneve sosem kerül közzétételre.
   - **Csapattitkok:** a kiválasztás minden tárolt PSK-ja és kulcsjelszava, egyik sincs bejelölve. Csak azokat jelöld be, amelyeket a csapatban mindenki ismerhet, például egy közös L2TP PSK-t; bejelöléskor ez jelenik meg: **Mindenki, akinél megvan a csapatkulcs, elolvashatja ezt a titkot**.
   - **Közös belépési adatok helyei:** a kiválasztott kapcsolatok által használt közös hitelesítő adatok, **felhasználónév és jelszó nélkül**: csak a név és egy azonosító kerül a katalógusba. Hely nélkül minden tagtól az adott kapcsolat bejelentkezését külön kérdezi.
3. **Név és fájl.** Csak új katalógusnál: egy név, és a `<név>.macvpncatalog` mentési helye. **A MacVPN semmit nem tölt fel: a fájlt te tedd a webszerveredre vagy a megosztásra.** Az **Új verzió közzététele…** ugyanabba a fájlba ír, és ezt a lépést kihagyja.
4. **Kész.** Az N. verzió elkészült. A verziószám minden közzétételnél eggyel nő. Új katalógusnál a **csapatkulcs csak egyszer jelenik meg**: **Másold** ki, tartsd biztonságban, kattints az **Elmentettem** gombra, és írd be a kért csoportot. Utána **Feliratkozási kód másolása…** (lásd [16.9](#169-rendszergazdáknak-a-csapatkulcs-és-a-feliratkozási-kód)).

**Hová tedd a fájlt?** Mindig ugyanoda tedd közzé, hogy a tagok forrása érvényes maradjon.
- **Webszerver:** `https://`-en szolgáld ki, a macOS által elfogadott tanúsítvánnyal. Az `ETag` vagy `Last-Modified` fejléc mellett a MacVPN kihagyja a változatlan letöltéseket. Hozzáférési token (`Authorization: Bearer …`) nem kötelező; a tagok a **Csapatkatalógus hozzáadása…** ablakban adják meg.
- **Fájlmegosztás (SMB, NFS):** a tagok csatolják a megosztást, és kiválasztják a fájlt. A fájlt egészében cseréld (a MacVPN így írja, ha közvetlenül oda mented).
- **Szinkronizált mappa (iCloud Drive, OneDrive, Dropbox):** a tagok a saját szinkronizált mappájukban választják ki a fájlt. A csak online elérhető fájlt a MacVPN olvasáskor letölti. Ha egy szinkronizálási ütközés régebbi példányt hoz vissza, a tagoknál megjelenik a régebbi verzióra figyelmeztető üzenet; egy újabb közzététel megoldja.

A fájl mások számára is olvasható (`644`), mert kiszolgálásra készül; alá van írva és titkosítva van.

**A közzététel után.** A közzétett kapcsolatok a te Maceden közönséges, szerkeszthető kapcsolatok maradnak. Mellettük ez áll: **Közzétéve: „Acme VPN” (v12)**, módosítás után pedig: **módosult a legutóbbi közzététel óta**. A **Közzététel** rész minden közzétételt felsorol a verziójával, a legutóbbi közzététel idejével, a fájllal és a módosult kapcsolatok számával; a gombok: **Új verzió közzététele…** (a varázsló a mentett kiválasztással), **Csapatkulcs cseréje…**, **Feliratkozási kód másolása…** és **Elfelejtés…**. A csere előtt átnézett közzététel kell: ha a legutóbbi közzététel óta kapcsolatok módosultak, a MacVPN helyette az **Új verzió közzététele…** gombot kínálja.

### 16.9 Rendszergazdáknak: a csapatkulcs és a feliratkozási kód

- A **csapatkulcs** 256 véletlen bit, a katalógus első közzétételekor készül. **Csak egyszer jelenik meg.** A MacVPN a széfedben tartja a későbbi verziók közzétételéhez, de többé nem mutatja.
- A **Feliratkozási kód másolása…** kéri a **mesterjelszavadat** és azt a forrást, amelyet a csapat használni fog (a címet, vagy az útvonalat úgy, ahogy a tagok Macjén látszik). A `macvpn-sub:…` kódot megjelenítés nélkül a vágólapra teszi. A kód tartalmazza a csapatkulcsot: csak biztonságos csatornán küldd el (jelszókezelő megosztott tárolója, végponttól végpontig titkosított üzenetküldő), sima e-mailben soha. Az ujjlenyomatot külön mondd meg a tagoknak, lehetőleg szóban, hogy össze tudják vetni. A hozzáférési token nincs a kódban.
- **Csapatkulcs cseréje…** (annak kizárására, aki elhagyta a csapatot): új csapatkulcs készül, és a MacVPN azonnal közzéteszi a következő verzióként a legutóbbi fájlhelyre (a mentési ablakban erősítsd meg). Az új kulcs egyszer jelenik meg. Küldd el (vagy egy új feliratkozási kódot) a maradó tagoknak; ők a **Csapatkulcs cseréje…** gombbal adják meg. **A csapatkulcs cseréje az egyetlen módja annak, hogy valakitől visszavond a hozzáférést egy olyan katalógushoz, amely már nála van.** Aki távozott, megtartja, amit már letöltött, a benne lévő csapattitkokkal együtt: ezeket a titkokat (például a szerveren a PSK-t) és a szerveroldali fiókját is változtasd meg.

### 16.10 Az aláírókulcs cseréje és a kompromittálódás

- A **váltás a tartalék kulcsra** ([16.7](#167-rendszergazdáknak-az-adminisztrátori-aláírókulcs)) tervezett kulcscsere. **Nem helyreállítás kompromittálódás után:** akinek kiszivárgott aláírókulcs van a kezében, a saját utódkulcsát is bejelentheti, és olyan új verziókat írhat alá, amelyeket a tagjaid elfogadnak.
- **Ha az aláírókulcs kiszivároghatott** (ellopott Mac zárolatlan széffel, kiszivárgott mentés a jelszavával, exportált kulcsfájl a jelszavával):
  1. Hozz létre új adminisztrátori aláírókulcsot egy megbízható Macen, és tedd közzé a kapcsolatokat **új katalógusként** (új néven, így új katalógusazonosítóval és új csapatkulccsal).
  2. Töröld a régi katalógusfájlt a webszerverről vagy a megosztásról, hogy ott senki ne tehessen közzé a régi feliratkozásnak.
  3. Küldd el minden tagnak az új feliratkozási kódot és az új ujjlenyomatot megbízható csatornán. Ők a **Leiratkozás…** gombbal leiratkoznak a régi katalógusról, és feliratkoznak az újra.
  4. Változtasd meg a régi katalógusban lévő csapattitkokat.
  Amíg a tagok le nem iratkoznak, a régi kulcs birtokosa aláírhat nekik verziókat, ha a forrásban lévő fájlt is tudja írni. A kapcsolatoknak ekkor is át kell menniük a MacVPN ellenőrzésén, és minden kockázatos beállításhoz kell a tagok saját jóváhagyása.
- **Ha csak a csapatkulcs szivárgott ki:** cseréld le ([16.9](#169-rendszergazdáknak-a-csapatkulcs-és-a-feliratkozási-kód)).

### 16.11 Biztonsági modell

- **Aláírás (adminisztrátori aláírókulcs, Ed25519).** Minden katalógus alá van írva. A MacVPN először az aláírást ellenőrzi, azzal a közzétevői kulccsal, amelyet az ujjlenyomattal rögzítettél, és csak utána fejt vissza vagy használ bármit.
  - *Véd:* a módosítás ellen bárkitől, akinek nincs meg az aláírókulcs, azoktól is, akiknél megvan a csapatkulcs, vagy akik írhatják a webszervert vagy a megosztást.
  - *Nem véd:* kiszivárgott aláírókulcs ellen, és az ellen, hogy a rendszergazda rossz dolgot tesz közzé. Úgy bízz a rendszergazdában, mint egy tőle kapott config fájlban.
- **Titkosítás (csapatkulcs, XChaCha20-Poly1305).** A tartalom (kapcsolatok, configok, mappák, a helyek nevei, csapattitkok) a csapatkulccsal titkosított. A kulcs véletlen, nem jelszó, így nem található ki.
  - *Véd:* az ellen, hogy valaki csapatkulcs nélkül elolvassa a katalógust egy kiszivárgott fájlból, webszervernaplóból vagy megosztásról.
  - *Nem véd:* azok ellen, akiknél megvan a csapatkulcs, a csere előtt távozott tagot is beleértve. Ők mindent elolvashatnak a katalógusban, a bejelölt csapattitkokat is. A katalógus azonosítója, neve, verziója, létrehozási ideje, a közzétevő kulcsa és az utódkulcs nyilvános fele a titkosítatlan fejlécben van, és a fájl mérete is látszik.
- **Visszaléptetés elleni védelem (verziószám).** Minden feliratkozás megjegyzi a legutóbb alkalmazott verziót. Alacsonyabb verziót figyelmeztetéssel elutasít, ugyanazt a verziót figyelmen kívül hagyja.
  - *Véd:* az ellen, hogy valaki egy régebbi aláírt verziót tegyen vissza, például egy olyat, amelyben még benne van egy törölt szerver vagy egy lecserélt csapattitok.
  - *Nem véd:* az ellen, hogy a forrás egyszerűen nem mutat új verziót; az állapot a legutóbbi sikeres frissítést mutatja, így egy tag észreveheti. A feliratkozási kód megnevezheti a katalógust és a legalacsonyabb elfogadható verziót, így az első letöltés is kötött.
- **Ellenőrzés, mint importnál.** A katalógus minden configja ugyanazokon a validátorokon megy át, mint egy import, és a kockázatos beállításokhoz minden tag saját jóváhagyása kell. A katalógus nem vihet felhasználói jelszót, és a root rétegben semmi nem változik.
- **A titkaid.** A csapatkulcs és a hozzáférési token a széfben van, és a teljes mentésben (annak jelszavával lezárva, lásd [14.](#14-biztonsági-mentés-és-visszaállítás)); sosem kerülnek naplóba. A feliratkozási kódot a MacVPN sosem tárolja és nem mutatja: a **Feliratkozási kód másolása…** a vágólapra teszi úgy megjelölve, hogy a vágólapkezelők kihagyják, és az univerzális vágólap ne küldje át a többi eszközödre, majd 60 másodperc után, a **Széf zárolása most** parancsnál és kilépéskor törli (hacsak közben mást nem másoltál). A csapatkulcs **Másolás** gombja ugyanígy működik. A hozzáférési token a `curl` szabványos bemenetén megy, sosem a parancssorán, és sosem más hostra. A saját felhasználóneved és jelszavad sosem hagyja el a széfedet.
- **Párosított appok.** Egy katalóguskapcsolat törlése vagy a leiratkozás minden párosított app engedélyezett kapcsolatai közül törli, így egy későbbi újrafeliratkozás sosem ad hozzáférést észrevétlenül egy appnak.
