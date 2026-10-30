# LinVPN – felhasználói útmutató

[English version](linvpn-user-guide.en.md)

A LinVPN a [MacVPN](user-guide.hu.md) és a [WinVPN](winvpn-user-guide.hu.md) linuxos változata: a felső sávban futó alkalmazás Debian- és Ubuntu-alapú asztali rendszerekre (amd64 vagy arm64), ugyanabból a kódból. Egy helyen tartja az OpenVPN, WireGuard, IKEv2 (strongSwan), L2TP/IPsec, Cisco IPsec és SSTP kapcsolatokat, és **a NetworkManageren keresztül**, az asztali rendszer hálózati szolgáltatásán át csatlakoztatja őket, a te nevedben (a csatlakozáshoz nem kell rendszergazda). A GNOME saját hálózati beállításaiban felvett VPN-jeidet is listázza. Ugyanaz a titkosított széf, ugyanazok a kapcsolatok, mappák, közös hitelesítő adatok, biztonsági mentések, csapatkatalógusok és vezérlő API, mint a MacVPN-ben, ugyanabban a formátumban: a MacVPN vagy a WinVPN mentése visszaállítható a LinVPN-ben, és fordítva. Ubuntun, GNOME alatt teszteljük.

Amiről ez az útmutató nem ír, az ugyanúgy működik, mint a MacVPN-ben: a széfről, a mappákról és színekről, a közös hitelesítő adatokról, az importról és exportról, a mentésről és visszaállításról és a csapatkatalógusokról a [MacVPN felhasználói útmutatója](user-guide.hu.md#11-széf) szól. Ez az útmutató a MacVPN-útmutató felépítését követi, és azt írja le, ami Linuxon más.

> **Nyelv:** a LinVPN az asztali környezet nyelvét követi (Beállítások → Rendszer → Terület és nyelv; a LinVPN az asztal által beállított `LANGUAGE`, `LC_ALL`, `LC_MESSAGES` és `LANG` változót olvassa). Magyarul és angolul érhető el; ha a nyelveid között egyik sincs, angolul jelenik meg. Ez az útmutató a magyar feliratokat használja, az [angol útmutató](linvpn-user-guide.en.md) az angolokat.

## Tartalom

1. [Telepítés](#1-telepítés) ([Követelmények](#11-követelmények), [A csomag telepítése](#12-a-csomag-telepítése), [A NetworkManager és a VPN-bővítményei](#13-a-networkmanager-és-a-vpn-bővítményei), [Hol tárolja a LinVPN az adataidat](#14-hol-tárolja-a-linvpn-az-adataidat))
2. [Az ikon, a panel és a Rendszerállapot](#2-az-ikon-a-panel-és-a-rendszerállapot) ([Indítás bejelentkezéskor](#21-indítás-bejelentkezéskor), [Megjelenés](#22-megjelenés), [Értesítések](#23-értesítések), [Hiányzó VPN-bővítmények](#24-hiányzó-vpn-bővítmények))
3. [Kapcsolatok felvétele típusonként](#3-kapcsolatok-felvétele-típusonként) ([OpenVPN](#31-openvpn), [WireGuard](#32-wireguard), [IKEv2](#33-ikev2-strongswan), [L2TP/IPsec és Cisco IPsec](#34-l2tpipsec-és-cisco-ipsec), [Rendszer VPN-ek](#35-rendszer-vpn-ek-a-saját-networkmanager-vpn-jeid), [SSTP](#36-sstp), [„Linuxon nem támogatott”](#37-linuxon-nem-támogatott))
4. [Import és export](#4-import-és-export) ([Fájlok megnyitása a Fájlokból](#41-fájlok-megnyitása-a-fájlokból))
5. [Csatlakozás](#5-csatlakozás) ([MFA](#51-többlépcsős-hitelesítés-mfa), [Hitelesítő adatok](#52-hitelesítő-adatok-bekérése-csatlakozáskor), [Párosított appok](#53-párosított-appok-vezérlő-api), [Automatikus újracsatlakozás](#54-automatikus-újracsatlakozás), [DNS](#55-dns-csatlakozás-közben), [Kilépés és kijelentkezés](#56-kilépés-kijelentkezés-és-alvás))
6. [Debug mód és a napló](#6-debug-mód-és-a-napló)
7. [Hibaelhárítás](#7-hibaelhárítás)
8. [Frissítés](#8-frissítés)
9. [A LinVPN eltávolítása](#9-a-linvpn-eltávolítása)
10. [Biztonsági megjegyzések](#10-biztonsági-megjegyzések)

---

## 1. Telepítés

### 1.1 Követelmények

- **Ubuntu 26.04 vagy újabb**, amd64 (Intel és AMD processzor) vagy arm64 gépen. Más, ezekre épülő disztribúción is működhet, ha legalább 2.39-es glibc van rajta. A LinVPN-t Ubuntu 26.04-en, GNOME alatt, Waylanddel teszteljük; az arm64-es csomag elkészül és átmegy az ellenőrzéseken, de kézzel nem teszteljük.
- **Ikontálca-kiszolgáló** (StatusNotifierItem): az Ubuntu saját AppIndicator-támogatása (alapból be van kapcsolva), más GNOME-os rendszeren az **AppIndicator and KStatusNotifierItem Support** bővítmény, vagy a KDE Plasma, amelybe be van építve. A csomag ezek egyikétől függ. Ilyen kiszolgáló nélkül a LinVPN-nek nincs ikonja.
- **NetworkManager 1.52.2 vagy újabb** (az Ubuntu 26.04-en 1.54 van), amelyen keresztül a LinVPN csatlakozik, a VPN-bővítményeivel együtt (lásd [1.3](#13-a-networkmanager-és-a-vpn-bővítményei)). A WireGuardhoz nem kell bővítmény.
- **OpenVPN 2.7 vagy újabb** ahhoz, hogy az OpenVPN-kapcsolatok kövessék a szerver `redirect-gateway` beállítását (lásd [3.1](#31-openvpn)). Az Ubuntu 26.04-en 2.7 van; régebbi OpenVPN-nel a LinVPN is csatlakozik, de osztott alagúttal, hacsak másként nem állítod be.
- **Rendszergazda** (olyan felhasználó, aki használhatja a `sudo`-t) a telepítéshez, minden frissítéshez és egy hiányzó VPN-bővítmény telepítéséhez. A csatlakozáshoz nem kell rendszergazda.

### 1.2 A csomag telepítése

Töltsd le a `linvpn_<verzió>_amd64.deb` csomagot (ARM-os gépen a `linvpn_<verzió>_arm64.deb`-et) és a hozzá tartozó `.sha256` fájlt. A [Releases](https://github.com/SepsiG/MacVPN/releases) oldalon vannak, a 2.1.0-tól, az első LinVPN-kiadástól a MacVPN-nel és a WinVPN-nel együtt kiadva.

Ellenőrizd a letöltést, majd telepítsd rendszergazdaként:

    sha256sum -c linvpn_<verzió>_amd64.deb.sha256
    sudo apt install ./linvpn_<verzió>_amd64.deb

A `./` fontos: nélküle az apt a tárolóiban keres ilyen nevű csomagot, nem a fájlt telepíti. Az apt a függőségeket is telepíti (a NetworkManagert, az OpenVPN-bővítményét és az OpenVPN-t), alapértelmezés szerint pedig az ajánlott VPN-bővítményeket is. Ha később kézzel telepítenél egy újabb csomagot, futtasd ugyanezt a parancsot az új fájllal; az adataid megmaradnak. Ha közben fut a LinVPN, néhány másodpercen belül magától újraindul a telepített verzióval (régebbi csomagnál is), a kapcsolataid pedig megmaradnak; amíg a Kapcsolatok ablakban nem mentett változás van, megvárja, hogy mentsd vagy elvesd.

A csomag ezeket telepíti:

- az alkalmazást (`/usr/bin/linvpn`), a bejegyzését az alkalmazások között az ikonjával, és a LinVPN által megnyitott fájltípusokat (lásd [4.1](#41-fájlok-megnyitása-a-fájlokból));
- **a LinVPN saját NetworkManager OpenVPN-szolgáltatását** (`/usr/lib/linvpn/nm-openvpn-service` és a segédprogramja, a NetworkManagerben `linvpn-openvpn` néven): ez a NetworkManager szokásos OpenVPN-bővítménye egy kis módosítással, amelytől az OpenVPN-kapcsolatok követik a szerver által küldött `redirect-gateway` beállítást (lásd [3.1](#31-openvpn)). A szokásos bővítmény változatlanul telepítve marad, és a gép minden más OpenVPN-kapcsolatát az futtatja. A forráskódja (GPL-2.0-or-later) a `/usr/share/linvpn/source/` mappában van;
- **a `linvpn-logd`** nevű kis rendszerszolgáltatást, amely a saját VPN-kapcsolataid rendszernaplósorait adja át a LinVPN-nek (lásd [6.](#6-debug-mód-és-a-napló)). Csak akkor indul, amikor szükség van rá, sosem rootként, és a rendszernaplón kívül semmit nem olvashat;
- **a `linvpn-xfrmd`** nevű kis rendszerszolgáltatást, amely a saját IKEv2-kapcsolataid bájtszámlálóit adja át a LinVPN-nek, ha a strongSwan 6-osnál régebbi (lásd [5.](#5-csatlakozás)). Csak akkor indul, amikor szükség van rá, sosem rootként, és egyetlen jogosultsága van: a kernel IPsec-állapotának olvasása;
- a **`90-linvpn-route`** NetworkManager-szkriptet, amely egy L2TP- vagy SSTP-alagút osztály szerinti útvonalát veszi fel, ha nem megy minden forgalom a VPN-en át (lásd [3.4](#34-l2tpipsec-és-cisco-ipsec));
- a frissítési lépést (`/usr/libexec/linvpn/linvpn-install-update`, lásd [8.](#8-frissítés)) és egy rendszerjogosultságot (polkit-műveletet), amellyel a LinVPN frissítéskor rendszergazdai jelszót kérhet.

Telepítéskor a csomag egyetlen saját lépést futtat: bekapcsolja a `linvpn-logd` és a `linvpn-xfrmd` socketjét (`systemctl enable --now linvpn-logd.socket linvpn-xfrmd.socket`); eltávolításkor kikapcsolja őket.

Indítsd el a **LinVPN**-t az alkalmazások közül. A legelső indításkor megnyílik a **Széf beállítása** ablak (lásd [a MacVPN útmutatóját](user-guide.hu.md#111-mesterjelszó-és-helyreállítási-kulcs)).

### 1.3 A NetworkManager és a VPN-bővítményei

A LinVPN maga nem futtat VPN-programot: minden csatlakozáskor egy ideiglenes kapcsolatot ad át a NetworkManagernek, amelyet csak a te felhasználód használhat, és amelyet a NetworkManager a bontáskor elfelejt. A VPN-t a NetworkManager futtatja a bővítményeivel:

| Típus | A NetworkManager ezzel futtatja | Csomag |
|---|---|---|
| WireGuard | saját maga | nem kell |
| OpenVPN | a LinVPN saját OpenVPN-szolgáltatásával (az OpenVPN `nm-openvpn` felhasználóként fut) | `network-manager-openvpn` (a LinVPN függősége) |
| L2TP/IPsec | az L2TP-bővítménnyel | `network-manager-l2tp` |
| IKEv2 | a strongSwan-bővítménnyel (charon-nm) | `network-manager-strongswan`; az EAP-hoz (felhasználónév és jelszó) a `libcharon-extauth-plugins` és a `libcharon-extra-plugins` is |
| Cisco IPsec | a vpnc-bővítménnyel | `network-manager-vpnc` |
| SSTP | az SSTP-bővítménnyel (sstpc) | `network-manager-sstp` |

A LinVPN csomagja ajánlja a bővítményeket, így az apt a LinVPN-nel együtt telepíti őket, hacsak nincs kikapcsolva az ajánlott csomagok telepítése. Ha valamelyik hiányzik, a **Rendszerállapot** jelzi, és onnan telepíthető (lásd [2.4](#24-hiányzó-vpn-bővítmények)).

**Csatlakozáskor nincs jelszókérés.** A NetworkManager megengedi az asztalon bejelentkezett felhasználónak, hogy olyan kapcsolatot vegyen fel és indítson, amely csak az övé. A LinVPN előbb megkérdezi a rendszert (anélkül, hogy bármi megjelenne), hogy ez jelszó nélkül megengedett-e; ha nem (például távoli SSH-munkamenetben, vagy olyan gépen, ahol a rendszergazda korlátozta), a LinVPN nem csatlakoztat semmit, és ezt írja: **A LinVPN jelszókérés nélkül nem módosíthatja a számítógép hálózati beállításait. Jelentkezz be az asztali munkamenetbe, és próbáld újra.** A LinVPN csatlakozáshoz sosem nyit jelszókérő ablakot.

### 1.4 Hol tárolja a LinVPN az adataidat

Minden felhasználónak saját LinVPN-adatai vannak, amelyeket csak ő olvashat:

- **A széf és a kapcsolatok:** `~/.local/share/LinVPN` (a `vault.db` és a kulcsfájlja, a `vault.keys`, valamint a `control/` mappában a vezérlő API naplója).
- **A kapcsolatnaplók:** `~/.local/share/LinVPN/logs` (kapcsolatonként egy `<kapcsolat azonosítója>.log`; lásd [6.](#6-debug-mód-és-a-napló)).
- **Az L2TP és Cisco IPsec kapcsolatok leírásai:** `~/.local/share/LinVPN/nm` (kapcsolatonként egy `<kapcsolat azonosítója>.json`: a típus, a szerver, a fióknév, a csoportnév és a „minden forgalom” beállítás, jelszó és PSK sosem; lásd [3.4](#34-l2tpipsec-és-cisco-ipsec)).
- **Az IKEv2-tanúsítványok és -kulcsok:** az appban importált klienstanúsítvány a széfben van; a `~/.local/share/LinVPN/swanctl` mappába tett fájlok ott maradnak (lásd [3.3](#33-ikev2-strongswan)).
- **A beállítások:** `~/.config/LinVPN` (`preferences.json`).
- **A letöltött frissítések és a naplóik:** `~/.cache/LinVPN/updates`.
- **A széf automatikus feloldásának kulcsa:** a bejelentkezési kulcstartódban (a Secret Service-ben; GNOME alatt a **Jelszavak és kulcsok** mutatja), **LinVPN vault key** néven.
- **Indítás bejelentkezéskor:** `~/.config/autostart/linvpn.desktop`, ha be van kapcsolva.
- **Futás közbeni fájlok:** `$XDG_RUNTIME_DIR/linvpn` (a vezérlő API socketje, és egy kapcsolat ideje alatt a configjában lévő tanúsítványok és kulcsok az `nm/` alatt; csak te olvashatod őket, és a bontáskor törlődnek). A rendszer kijelentkezéskor kiüríti ezt a mappát.

Ha az `XDG_DATA_HOME`, az `XDG_CONFIG_HOME` vagy az `XDG_CACHE_HOME` változó abszolút útvonalra van állítva, a LinVPN azt használja a `~/.local/share`, a `~/.config`, illetve a `~/.cache` helyett.

**A NetworkManagerben semmi nem tárolódik.** A LinVPN által átadott kapcsolatok csak addig léteznek, és csak a memóriában, amíg élnek, és nincs bennük jelszó: a NetworkManager minden csatlakozáskor a LinVPN-től kéri el őket (lásd [10.](#10-biztonsági-megjegyzések)). Ezért a LinVPN kapcsolatai nem jelennek meg a Beállítások → Hálózat alatt, és ott nincs mit eltakarítani.

Az **Automatikus feloldás** (alapból be) a széf kulcsát a bejelentkezési kulcstartódban tartja, így a LinVPN kérdés nélkül megnyílik. A kulcstartót a bejelentkezési jelszavad oldja fel; ha zárolva van (például automatikus bejelentkezés után), a GNOME saját ablaka kéri a jelszavát, amikor a LinVPN-nek először kell a kulcs; ha ezt az ablakot bezárod, a LinVPN a mesterjelszót kéri. Az automatikus feloldás a többi felhasználó és egy ellopott lemez ellen védi a széfet, a nevedben futó programok ellen nem: bármelyik programod elkérheti a kulcsot a kulcstartódtól. Ha ez számít neked, kapcsold ki az **Automatikus feloldás** kapcsolót a **Beállítások** csoportban: a LinVPN ekkor törli a kulcsot a kulcstartóból, és minden indításkor a mesterjelszót kéri.

Másik számítógépre (vagy Macről, Windowsról) teljes biztonsági mentéssel költözhetsz: ott **Teljes biztonsági mentés…**, a LinVPN-ben **Visszaállítás biztonsági mentésből…**.

---

## 2. Az ikon, a panel és a Rendszerállapot

A LinVPN ikonja a felső sáv jobb oldalán van. A kapcsolatokat egy kártyás **panelen** mutatja, mint a MacVPN a menüjében és a WinVPN a popoverében:

- **Egy kattintásra** (bal vagy jobb gombbal) az ikonon egy rövid menü nyílik: **LinVPN megnyitása** (megnyitja a panelt) és **Kilépés a LinVPN-ből**. Az Ubuntu GNOME-ján a menü egy pillanatnyi szünet után jelenik meg: a felső sáv előbb kivárja, nem dupla kattintás-e.
- **Dupla kattintásra vagy középső gombbal** kattintva az ikonon a panel azonnal megnyílik; ugyanez újra bezárja.
- KDE Plasmán egy bal kattintás azonnal megnyitja a panelt, a jobb kattintás a menüt.

A panel annak a képernyőnek a jobb felső sarkában nyílik meg, amelyiken az egérmutató van, közvetlenül a felső sáv alatt. Minden kapcsolat egy kártya a típusa színes buborékával, a nevével, a típusával és az állapotával, valamint egy kapcsolóval; a rendszer VPN-eknek (lásd [3.5](#35-rendszer-vpn-ek-a-saját-networkmanager-vpn-jeid)) is van kártyájuk. A kártyák alatt az **Új kapcsolat / Import…**, a **Kapcsolatok kezelése…** és a **Rendszerállapot** csempe, a **Beállítások** csoport, a **Súgó** (ezt az útmutatót nyitja meg a GitHubon, magyarul, ha a LinVPN nyelve magyar) és a **Kilépés** van. A panel bezárul, ha bárhová kattintasz rajta kívül, vagy másik ablakra váltasz.

A LinVPN felhasználónként egyszer fut: ha újra elindítod (az alkalmazások közül, vagy egy fájl megnyitásával), nem indul második példány, hanem a futó LinVPN jön elő. Egy ablak bezárása nem lépteti ki a LinVPN-t: tovább fut a felső sávban.

**A Rendszerállapot ablak** ezt írja: **A LinVPN a NetworkManageren és a VPN-bővítményein keresztül kapcsolódik (OpenVPN, L2TP, strongSwan, vpnc, SSTP). A hiányzókat innen telepítheted.**, alatta pedig egy sor a NetworkManagernek és egy-egy sor típusonként:

1. **NetworkManager:** a verziója (**NetworkManager 1.54.3**), vagy **A NetworkManager nem fut.** / **NetworkManager 1.36 vagy újabb szükséges.**: ilyenkor egyik típus sem csatlakozhat.
2. **WireGuard:** **A NetworkManager része**.
3. **OpenVPN:** az OpenVPN verziója, és hogy követi-e a szervert: **OpenVPN 2.7.0 · követi a szerver redirect-gateway beállítását**, régebbi OpenVPN-nel **OpenVPN 2.6.14 · osztott alagút, hacsak nem „Mindig” a beállítás (a szerver követéséhez 2.7 kell)** (lásd [3.1](#31-openvpn)). Ha **A LinVPN OpenVPN-szolgáltatása hiányzik: telepítse újra a LinVPN-t.** áll itt, a csomag fájljai sérültek: telepítsd újra a csomagot.
4. **L2TP/IPsec**, **IKEv2**, **Cisco IPsec**, **SSTP:** **Telepítve**, vagy **Nincs telepítve: <csomag>** egy **Telepítés** gombbal. Az IKEv2 sora használható marad, de ezt írja: **Az EAP-hoz szükséges: libcharon-extauth-plugins, libcharon-extra-plugins** (**Telepítés** gombbal; csak a hiányzók szerepelnek), ha csak az EAP-rész hiányzik: tanúsítvánnyal vagy PSK-val az IKEv2 enélkül is működik.

Az **Újraellenőrzés** mindent újra megvizsgál.

### 2.1 Indítás bejelentkezéskor

A LinVPN alapból nem indul el magától. Ha minden bejelentkezéskor el szeretnéd indítani, kapcsold be az **Indítás bejelentkezéskor** kapcsolót a panel **Beállítások** csoportjában; kikapcsolni ugyanott lehet. A LinVPN ilyenkor csak a saját felhasználód számára írja meg (vagy törli) a `~/.config/autostart/linvpn.desktop` fájlt.

- Ha ezt a bejegyzést egy másik eszköz kapcsolta ki (például a GNOME Finomhangolások **Indítási alkalmazások** oldala), a kapcsoló kikapcsolva látszik, alatta a megjegyzés: **Egy másik alkalmazás kikapcsolta.** Ha a LinVPN-ben bekapcsolod, újra bekapcsolódik.
- Csak a telepített LinVPN (`/usr/bin/linvpn`) jegyezhető be. Fejlesztői buildben ez áll: **Az automatikus indítás akkor érhető el, ha a LinVPN a csomagjából van telepítve.**

### 2.2 Megjelenés

A **Beállítások → Megjelenés** pontban három lehetőség van: **Rendszer szerint** (alapértelmezés: a LinVPN az asztal világos vagy sötét stílusát követi, Beállítások → Megjelenés, akkor is, ha futás közben váltasz), **Világos** és **Sötét**. A választás azonnal érvényes a panelre és minden ablakra.

### 2.3 Értesítések

A LinVPN asztali értesítéseket küld: ha egy kapcsolat felépül, megszakad, automatikusan újracsatlakozik, nem sikerül vagy nem válaszol, ha kódra vagy hitelesítő adatokra van szükség, és ha egy csapatkatalógus frissült. Ugyanúgy működnek, mint a MacVPN-ben (lásd [a MacVPN útmutatóját](user-guide.hu.md#23-kapcsolatértesítések)), a **Beállítások** **Kapcsolatértesítések** kapcsolójával együtt. **LinVPN** néven, az ikonjával jelennek meg; GNOME alatt a Beállítások → Értesítések → **LinVPN** pontban kapcsolhatod ki őket. Ha futó LinVPN mellett egy értesítésre kattintasz, megnyílik a hozzá tartozó ablak. Értesítésben sosem jelenik meg jelszó, kulcs, token vagy szervercím.

### 2.4 Hiányzó VPN-bővítmények

Ha egy típus NetworkManager-bővítménye nincs telepítve, a kapcsolatai a listában maradnak, szürkén, és a soruk megmondja, miért, például **Nincs telepítve: NetworkManager SSTP-bővítmény – Rendszerállapot** (vagy **Nincs telepítve: NetworkManager**, ha a NetworkManager nem fut). A sorban a **Rendszerállapot** egy hivatkozás, amely megnyitja az ablakot.

Egy bővítmény sorában a **Telepítés** pontosan a sorban megnevezett csomagokat telepíti a **PackageKit**, a rendszer szoftvertelepítője segítségével: a rendszer saját ablaka kéri a rendszergazdai jelszót (a LinVPN sosem látja). Közben a sorban **Telepítés…** áll, alatta a kimenet; utána a sor zöld lesz, és a kapcsolatok használhatók. **A telepítés megszakadt.** vagy **A telepítés nem kapott engedélyt.**: a jelszókérő ablakot bezárták vagy elutasították, semmi nem települt. A LinVPN csak az [1.3](#13-a-networkmanager-és-a-vpn-bővítményei) táblázatában szereplő NetworkManager VPN-bővítményeket telepítheti, más csomagot soha. Magad is telepítheted őket (`sudo apt install network-manager-sstp`), utána nyomd meg az **Újraellenőrzés** gombot.

---

## 3. Kapcsolatok felvétele típusonként

Kapcsolatot a **Kapcsolatok** ablakban veszel fel (a panelen **Kapcsolatok kezelése…** vagy **Új kapcsolat / Import…**), pontosan úgy, mint a MacVPN-ben: az **Új** (+) menüben OpenVPN, WireGuard, IKEv2, SSTP, L2TP és Cisco IPsec van, az **Import fájlból…** fájlt importál, a szöveges típusoknak szövegszerkesztőjük van, amely mentéskor ellenőrzi a configot, a jelszavak pedig a széfbe kerülnek, nem a configba (lásd [a MacVPN útmutatóját](user-guide.hu.md#3-kapcsolatok-felvétele-típusonként)).

**A config titkai rejtve vannak**, amíg be nem jelölöd a **Titkok megjelenítése** lehetőséget, és a config alatti **Tanúsítványok** doboz felsorolja a kapcsolat tanúsítványait **Másolás** (az SHA-256 ujjlenyomat) és **PEM másolása** gombbal, mint a MacVPN-ben (lásd [a MacVPN útmutatóját, 3.7](user-guide.hu.md#37-tanúsítványok)).

**Amit a Linux másként futtat, az a szerkesztő alatt látszik.** Egy szürke sor mondja meg, hogyan futtatja a NetworkManager a kapcsolatot (például **Linuxon: NetworkManager a LinVPN OpenVPN-szolgáltatásával · a teljes forgalomról a szerver dönt**), utána jönnek a Linuxon figyelmen kívül hagyott beállítások. Az a kapcsolat, amelyet a Linux nem tud futtatni, szürkén, az okkal együtt látszik a listában (lásd [3.7](#37-linuxon-nem-támogatott)).

### 3.1 OpenVPN

Importáld a szolgáltatódtól kapott `.ovpn` fájlt, mint a MacVPN-ben (lásd [a MacVPN útmutatóját](user-guide.hu.md#31-openvpn)). Az OpenVPN-kapcsolatokat a LinVPN saját NetworkManager OpenVPN-szolgáltatása futtatja (lásd [1.2](#12-a-csomag-telepítése)). A config tanúsítványai és kulcsai a kapcsolat idejére egy csak általad olvasható mappába kerülnek (`$XDG_RUNTIME_DIR/linvpn/nm/…`), és a bontáskor törlődnek.

**A direktívák.** A három szint (engedett, **Kockázatos beállítások**, tiltott) ugyanaz, mint a MacVPN-ben; a Linuxnak saját oszlopa van ([openvpn-directives.md](openvpn-directives.md#linux-linvpn)):

- **69 direktívát a Linux figyelmen kívül hagy:** a NetworkManagernek nincs rájuk beállítása (pufferek és socketek hangolása, néhány időzítő és TLS-részlet, a többi rendszer opciói), így nincs hatásuk. A sárga **Kockázatos beállítások** panelen jelennek meg, ezzel az indokkal: **Linuxon a NetworkManager figyelmen kívül hagyja**; a mentéshez jelöld be a **Tudomásul veszem a beállításokat és a biztonsági kockázatokat** négyzetet. A VPN-szerverek szokásos profiljaiban ritkán fordulnak elő.
- **8-féle beállítás Linuxon nem futtatható:** `peer-fingerprint`, `verify-hash`, `remote-cert-ku`, `remote-cert-eku`, alagúton kívüli `route` (`net_gateway`, `remote_host`), olyan `<connection>` blokk, amelyben a `remote`, `proto`, `port` és `nobind` mellett más is van, olyan `pull-filter`, amelyet a szolgáltatás nem tud átadni, és a `compress stub`/`stub-v2`/`migrate`. Ha ezeket elhagyná, gyengülne a szerver ellenőrzése, vagy forgalom menne az alagút mellett, ezért a kapcsolat inkább szürke lesz (lásd [3.7](#37-linuxon-nem-támogatott)).
- Néhány argumentumot a NetworkManager eldob (`redirect-gateway … block-local`, egyes `dns` opciók, gépnévvel megadott `route`): ezeket a szerkesztő alatt **Linuxon a NetworkManager figyelmen kívül hagyja: …** sor sorolja fel.

**Minden forgalom a VPN-en keresztül.** Az OpenVPN szerkesztőjében háromállású beállítás van (csak Linuxon; a configba íródik, így a mentésekkel, exportokkal és csapatkatalógusokkal együtt utazik, és a MacVPN és a WinVPN OpenVPN-je is betartja):

- **A szerver dönt** (alapértelmezés): **A szerver redirect-gateway beállítása dönt.** Ha a szerver `redirect-gateway`-t küld (vagy a profilban benne van), minden forgalom a VPN-en megy, különben csak a VPN hálózatai. macOS-en is így viselkedik az OpenVPN. Ehhez OpenVPN 2.7 kell (lásd [2.](#2-az-ikon-a-panel-és-a-rendszerállapot)): régebbi OpenVPN-nel a szerkesztő ezt írja: **Ennek a rendszernek az OpenVPN-je 2.7-nél régebbi: „A szerver dönt” osztott alagutat tart, hacsak a profil mást nem mond.**
- **Mindig:** **Minden forgalom a VPN-en keresztül megy (redirect-gateway def1).** A LinVPN egy `redirect-gateway def1` sort ír a configba.
- **Soha (osztott alagút):** **Csak a VPN saját hálózatai mennek rajta keresztül; a szervertől érkező redirect-gateway figyelmen kívül marad.** A LinVPN a `pull-filter ignore "redirect-gateway"` sort írja be.

Ha a profilban már benne van ezek egyike, a neki megfelelő választás látszik; **A szerver dönt** kiválasztása kiveszi őket. A váltás közönséges szerkesztés: a **Mentés** tartja meg.

**A felhasználónév, a jelszó, a privát kulcs jelszava, a statikus challenge és a CRV1** ugyanúgy működik, mint a MacVPN-ben (lásd [5.1](#51-többlépcsős-hitelesítés-mfa)). A config `verb` szintjét (legfeljebb 4-ig) a LinVPN átadja az OpenVPN-nek; a sorai a Napló fülön jelennek meg.

### 3.2 WireGuard

Importáld a `.conf` fájlt, vagy hozz létre egy újat, és töltsd ki a sablont, mint a MacVPN-ben (a config alatti kulcsgenerátor ugyanígy működik; lásd [a MacVPN útmutatóját](user-guide.hu.md#32-wireguard)). A WireGuardot maga a NetworkManager futtatja, egy `lvw` kezdetű, utána 8 betűből és számjegyből álló nevű interfészen; a szerkesztő alatti sor megnevezi (**Linuxon: a NetworkManager WireGuard-ja (interfész: lvw1a2b3c4d)**).

- Az `auto`-tól eltérő `Table` nem futtatható: **Linuxon nem támogatott: Table = … (a NetworkManager a saját útválasztási táblázatát használja)**. Kivétel a `Table = off`: ilyenkor nem kerül fel útvonal.
- Ha egy `DNS` szerver olyan IP-verziójú, amilyen `Address` a kapcsolatnak nincs, a LinVPN elhagyja, ezzel a megjegyzéssel: **Linuxon figyelmen kívül hagyva: DNS = … (a kapcsolatnak nincs ilyen IP-verziójú Address értéke)**.
- A privát kulcs és az előre megosztott kulcsok sosem kerülnek a NetworkManager beállításaiba: a NetworkManager csatlakozáskor a LinVPN-től kéri el őket.
- **A privát kulcs másolatát** (**Másolás** a **Privát kulcs** mellett) a LinVPN 60 másodperc után, a **Széf zárolása most** parancsnál és kilépéskor törli a vágólapról (hacsak közben mást nem másoltál), mint a MacVPN. A Linuxon nincs rendszerszintű mód arra, hogy kimaradjon a vágólap-előzményekből: a LinVPN jelszóként jelöli meg (`x-kde-passwordManagerHint`), és csak a jelölést figyelembe vevő vágólapkezelők hagyják ki (a KDE Klippere, az ezt megvalósító GNOME-bővítmények); más vágólapkezelők és GNOME-bővítmények megtarthatják az előzményeik között. Kulcs másolása előtt kapcsold ki az ilyen bővítményt, vagy töröld az előzményeit.

### 3.3 IKEv2 (strongSwan)

Az IKEv2-configok a strongSwan `swanctl.conf` szintaxisát használják, mint a MacVPN-ben, így ugyanaz a kapcsolat minden rendszeren működik. A NetworkManager strongSwan-bővítménye (charon-nm) **a config első kapcsolatát és annak első gyermekét** futtatja:

- **Bejelentkezés:** EAP felhasználónévvel és jelszóval (`local { auth = eap-mschapv2 }` vagy `eap`; ehhez kell a `libcharon-extauth-plugins` és a `libcharon-extra-plugins`, lásd [2.4](#24-hiányzó-vpn-bővítmények)), kliens-tanúsítvány (`auth = pubkey`), vagy előre megosztott kulcs (mindkét oldalon `auth = psk`).
- **Az előre megosztott kulcs Linuxon legalább 20 karakter legyen:** a strongSwan-bővítmény a rövidebbet elutasítja. A LinVPN ezt csatlakozás előtt ellenőrzi: **Linuxon az IKEv2-höz legalább 20 karakteres előre megosztott kulcs (PSK) kell: a strongSwan NetworkManager-bővítménye a rövidebbet elutasítja.**
- **Útvonalak:** `remote_ts` nélkül vagy `0.0.0.0/0`-val minden forgalom a VPN-en megy; más `remote_ts` hálózatokkal osztott alagút lesz.
- **Linuxon nem támogatott** (a kapcsolat szürke, a kulccsal és az értékkel, például **Linuxon nem támogatott: local auth = eap-tls**): a többi EAP-módszer és az XAUTH, az IKEv1 (`version = 1`), egynél több hitelesítési kör (**Linuxon nem támogatott: egynél több hitelesítési kör**), egynél több szervercím (**Linuxon nem támogatott: egynél több távoli cím**), a hiányzó szervercím (**Linuxon kötelező a szerver címe: a remote_addrs értéke a szerver neve vagy címe legyen.**), a transport mód, és egynél több kliens- vagy CA-tanúsítvány.

**Klienstanúsítvány az appban (mint a MacVPN 2.0.7-ben).** Tanúsítványos bejelentkezéshez (`auth = pubkey` a `local` szakaszban, vagy nincs `auth`) nyomd meg a config alatti **Klienstanúsítvány importálása…** gombot, és válassz egy PKCS#12 fájlt (`.p12`, `.pfx`), vagy a tanúsítványodat és a privát kulcsát PEM formában (egy vagy két fájl; a panelen jelöld ki mindkettőt). A LinVPN szigorúan ellenőrzi a fájlokat (egyenként legfeljebb 16 KB), és a tanúsítványt a kulccsal a széfben tartja, sosem a te mappáidban. A szerkesztő ezután a **PEM-tanúsítvány és kulcs** sort mutatja az SHA-256 ujjlenyomattal, az **Eltávolítás** pedig törli a széfből. A PEM-fájlokban lévő CA- vagy lánctanúsítvány nem kerül importálásra (a szerkesztő megírja, hányat hagyott ki): a szerver CA-ját a `cacerts` sorral add meg, lásd lent.

- **A PKCS#12 fájlt a LinVPN magától átalakítja.** A strongSwan NetworkManager-bővítménye csak PEM-fájlokat olvas, ezért a LinVPN elkéri a fájl jelszavát (**A PKCS#12 fájl jelszava**), és a rendszer `openssl` programjával rögtön átalakítja (a régebbi RC2 / 3DES fájlokat is); a széfben ezután a PEM-tanúsítvány és -kulcs van, a kulcs pedig megtartja ezt a jelszót, így ez lesz a **Privát kulcs jelszava**: a LinVPN beírja ebbe a mezőbe, és a kapcsolat mentésekor tárolódik (az **Elvetés** eldobja; üresen csatlakozáskor kérdez rá). Rossz jelszónál **A PKCS#12 fájl jelszava hibás.** látszik, és újra kérdez; a **Mégse** semmit nem importál. Az `openssl` csomag nélkül (a LinVPN csomag függ tőle): **A PKCS#12 fájl olvasásához az openssl csomag kell: telepítsd az openssl-t, majd próbáld újra.** A Macen importált, mentésből visszaállított PKCS#12 tanúsítványt a LinVPN minden csatlakozáskor ugyanígy alakítja át, a kulcs jelszavával.
- **Csatlakozáskor** a LinVPN a tanúsítványt és a kulcsát a kapcsolat saját mappájába írja a `$XDG_RUNTIME_DIR/linvpn` alatt (csak te olvashatod, a memóriában van, bontáskor törlődik), és a NetworkManager strongSwan-bővítménye onnan olvassa. A kulcs sosem kerül a NetworkManager beállításaiba vagy a naplóba. Az importált tanúsítványt akkor használja, ha a config nem ad meg saját `certs` sort; a `certs` sorral rendelkező config a LinVPN mappájában lévő fájlját használja (lent).
- **Privát kulcs jelszava:** a kulccsal aláíró IKEv2-confignál látszik. Ha a kulcs titkosított, mentsd el ide a jelszavát, vagy hagyd üresen, és a LinVPN csatlakozáskor elkéri. A széfben tárolódik, és a strongSwan csak a kulcs megnyitásához kapja meg (a naplóba sosem kerül).
- Ha a configban `auth = pubkey` van, de sem `certs`, sem importált tanúsítvány nincs, ez látszik: **Linuxon kliens-tanúsítvány kell: importáld a Klienstanúsítvány importálása… gombbal, vagy a certs értéke a fájlja legyen a LinVPN strongSwan-mappájában (x509).**

**A LinVPN strongSwan-mappájában lévő tanúsítványok** (mint eddig) továbbra is működnek. A configban megnevezett tanúsítványfájlokat a LinVPN a saját mappádból olvassa, a `~/.local/share/LinVPN/swanctl` alól (ez felel meg Macen a Homebrew `etc/swanctl` mappájának), ugyanazzal a három almappával. Hozd létre, és másold bele a fájlokat úgy, hogy csak te olvashasd őket:

    mkdir -p ~/.local/share/LinVPN/swanctl/{x509,x509ca,private}
    cp client.pem ~/.local/share/LinVPN/swanctl/x509/
    cp client.key ~/.local/share/LinVPN/swanctl/private/
    cp ca.pem ~/.local/share/LinVPN/swanctl/x509ca/
    chmod -R go-rwx ~/.local/share/LinVPN/swanctl

- **A kliens-tanúsítvány:** a `local` szakasz `certs = client.pem` sora → `x509/client.pem`; a privát kulcsa a `private/client.key` legyen (a tanúsítvány neve `.key` végződéssel). Ha a kulcsnak jelszava van, mentsd el a **Privát kulcs jelszava** mezőbe (a LinVPN nem látja, hogy a mappában lévő kulcs titkosított-e, ezért csatlakozáskor nem kérdez rá).
- **A szerver CA-ja:** a `remote` szakasz `cacerts = ca.pem` sora → `x509ca/ca.pem`. `cacerts` nélkül az `x509ca` egyetlen fájlját használja, ha pontosan egy van benne; különben a szervert a rendszer CA-tanúsítványai ellenőrzik, és a szerkesztő ezt írja: **Nincs megnevezett CA-tanúsítvány, és a LinVPN strongSwan-mappájában (x509ca) nem pontosan egy van: a szervert a rendszer CA-tanúsítványai ellenőrzik.**

**Tanúsítványok doboz.** Mint a MacVPN-ben, a config alatti **Tanúsítványok** doboz előbb az importált klienstanúsítványt mutatja, utána a `certs` és `cacerts` által megnevezett fájlokat a LinVPN strongSwan-mappájából (`x509`, `x509ca`), az érvényességükkel: a 30 napon belül lejárót **12 nap múlva lejár**, a lejártat **Lejárt** jelzi. (Az a CA, amelyet a LinVPN `cacerts` nélkül azért választ, mert az egyetlen fájl az `x509ca`-ban, nem szerepel a listán.) Az OpenVPN- és SSTP-tanúsítványokat a configból mutatja, mint a MacVPN, és a soruk a lejárat előtt figyelmeztet.

### 3.4 L2TP/IPsec és Cisco IPsec

Ezeket űrlapon állítod be (**Új → L2TP** vagy **Új → Cisco IPsec**), ugyanazokkal a mezőkkel, mint a MacVPN-ben: **Név**, **Szerver**, **Fióknév**, **Jelszó**, **Közös kulcs (PSK)**, Ciscónál a **Csoportnév (group name)** is, és **Minden forgalom a VPN-en keresztül** (lásd [a MacVPN útmutatóját](user-guide.hu.md#34-l2tpipsec-és-cisco-ipsec)).

- **Nincs jóváhagyandó profil.** A gomb felirata **Mentés**: a LinVPN elmenti a kapcsolatot (a jelszót és a PSK-t a széfbe), és egy titkok nélküli rövid leírást a `~/.local/share/LinVPN/nm` mappába, amelyből minden csatlakozáskor felépíti a NetworkManager-kapcsolatot. A kapcsolat törlése a leírást is törli.
- **Az L2TP/IPsec** az L2TP-bővítménnyel fut, PSK-val és MS-CHAPv2 bejelentkezéssel (**Linuxon: NetworkManager L2TP/IPsec (MS-CHAPv2)**), mint a MacVPN-ben.
- **A Minden forgalom a VPN-en keresztül kikapcsolásakor** (L2TP és SSTP) a VPN-cím osztályának hálózata a VPN-en át megy, mint macOS-en és Windowson: a `10.x.x.x` cím a `10.0.0.0/8`-at kapja, a `172.16.x.x` a `172.16.0.0/16`-ot, a `192.0.2.x` a `192.0.2.0/24`-et (A, B és C osztály), és mellé a szerver által küldött útvonalakat. Így a szerver mögötti hálózat elérhető. Ezt a csomag egy kis NetworkManager-szkriptje veszi fel (`/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route`; a sorai a rendszernaplóban `linvpn-route` néven). Nem vesz fel semmit, ha a saját hálózatod vagy az alapértelmezett átjáród ebbe a hálózatba esik, így a helyi hálózatod működik tovább. A Cisco IPsec a szerver által küldött hálózatokat használja, mint macOS-en.
- **A Cisco IPsec Linuxon működik** (a Windowszal ellentétben): a vpnc-bővítménnyel fut (IKEv1 XAUTH-tal és a csoport PSK-jával: **Linuxon: NetworkManager vpnc (Cisco IPsec)**).
- **A jelszó végére fűzött egyszer használatos kód** mindkettőnél működik (lásd [5.1](#51-többlépcsős-hitelesítés-mfa)).

### 3.5 Rendszer VPN-ek: a saját NetworkManager VPN-jeid

A GNOME-ban (Beállítások → Hálózat → VPN) vagy `nmcli`-vel felvett VPN-ek, amelyeket a felhasználód használhat, a LinVPN-ben rendszer VPN-ként jelennek meg (**rendszer VPN (nem a LinVPN hozta létre)**), a típusukkal: **L2TP**, **Cisco IPsec**, **IKEv2**, **WireGuard (app)**, **OpenVPN (app)** vagy **VPN**. Egy VPN, amelyet a Beállításokban felveszel vagy törölsz, magától megjelenik, illetve eltűnik; ha egyet éppen akkor törölnek, amikor a részleteit nézed, ez áll ott: **Ezt a VPN-t eltávolították a NetworkManagerből**.

- **Csatlakoztatni és bontani** a panelről vagy a Kapcsolatok ablakból lehet, mint bármely más kapcsolatot; a LinVPN mutatja az állapotukat, a címüket és a forgalmukat. A beállításaik a NetworkManagerben maradnak: **Ezt a kapcsolatot csak indítani és bontani lehet innen. A beállításai a Beállítások → Hálózat alatt vagy a saját alkalmazásában vannak.** A LinVPN sosem szerkeszti, nevezi át vagy törli őket.
- **Titkok (L2TP és Cisco IPsec):** mint a MacVPN-ben, a részletező nézetben van **Közös kulcs (PSK)** és **Jelszó (nem kötelező, ha nincs elmentve a NetworkManagerben)** mező. Ezek a LinVPN széfjében maradnak, és a NetworkManager csak a LinVPN által indított csatlakozáshoz kapja meg őket; a NetworkManager saját beállításai nem változnak. A **Mentett titkok törlése** törli őket. Nélkülük a NetworkManager azt használja, amit a VPN-hez elmentett; ha semmit, a GNOME saját jelszókérő ablaka jelenhet meg.
- **Mi kerül a listára:** csak azok a VPN- és WireGuard-profilok, amelyeket a felhasználód használhat (a minden felhasználónak elérhetők és a csak neked szólók); a LinVPN által a saját kapcsolataihoz készített ideiglenes kapcsolatok soha. Egy minden felhasználónak elérhető VPN mentésekor a GNOME rendszergazdai jelszót kérhet; ez a GNOME kérdése, nem a LinVPN-é.
- A rendszer VPN-ek mappába tehetők, kitűzhetők és színezhetők, mint a saját kapcsolataid. **Automatikus újracsatlakozás** kapcsolójuk nincs.

### 3.6 SSTP

Hozd létre az **Új → SSTP** menüponttal, vagy importálj egy `.sstp` fájlt. Az űrlap ugyanaz, mint a MacVPN-ben (**Szerver**, **Port**, **Felhasználónév**, **Jelszó**, **Szervertanúsítvány**, **Minden forgalom a VPN-en keresztül**, **A szerver DNS-ének használata**; lásd [a MacVPN útmutatóját](user-guide.hu.md#36-sstp)); a NetworkManager SSTP-bővítménye `sstpc`-vel és MS-CHAPv2-vel futtatja.

- **Rendszer CA:** a szerver tanúsítványát a rendszer CA-tanúsítványai (`/etc/ssl/certs`) ellenőrzik. Az oda telepített céges CA-ban (`/usr/local/share/ca-certificates`, majd `sudo update-ca-certificates`) a LinVPN is megbízik.
- **Saját CA fájl** (**PEM fájl kiválasztása…**): a CA a kapcsolat configjában marad, és a kapcsolat idejére a privát futási mappádba íródik.
- **Nincs ellenőrzés:** megengedett, mint macOS-en, ezzel a figyelmeztetéssel: **Ellenőrzés nélkül a LinVPN nem vizsgálja a szerver tanúsítványát.** Csak tesztelésre használd.
- **A szerver DNS-ének használata** kikapcsolva: a NetworkManager figyelmen kívül hagyja a szerver által küldött DNS-szervereket.
- **Minden forgalom a VPN-en keresztül** kikapcsolva: a VPN-cím osztályának hálózata a VPN-en át megy, mint macOS-en és Windowson (lásd [3.4](#34-l2tpipsec-és-cisco-ipsec)).

### 3.7 „Linuxon nem támogatott”

Az a kapcsolat, amelynek a beállításait a Linux nem tudja futtatni, minden adatát megtartja: továbbra is szerkesztheted, mentheted, exportálhatod, biztonsági mentésbe teheted és megoszthatod, és ugyanez a kapcsolat a MacVPN-ben és a WinVPN-ben működik. Linuxon szürkén, az okkal együtt látszik a listában (**Linuxon nem támogatott: …**, a pontos beállítással), a szerkesztője sárga megjegyzésben mutatja az okot, és a csatlakozás nem indítható. Változtasd meg a beállítást (például töröld a `peer-fingerprint` sort, és használd helyette a szerver CA-ját), vagy kérj a VPN-rendszergazdádtól olyan profilt, amelyben nincs benne. Az okok a [3.1](#31-openvpn), a [3.2](#32-wireguard) és a [3.3](#33-ikev2-strongswan) részben vannak.

---

## 4. Import és export

Az import és az export ugyanúgy működik, mint a MacVPN-ben (lásd [a MacVPN útmutatóját](user-guide.hu.md#4-import-és-export)), az **Exportálás kulcsok nélkül** is: eltávolítja a személyes kulcsaidat, a szerver közös `<tls-auth>` / `<tls-crypt>` kulcsát viszont megtartja, hogy a másolat csatlakozni tudjon. `.mobileconfig` profilt a LinVPN nem importál: **A .mobileconfig profil nem importálható a LinVPN-be. Hozd létre a kapcsolatot az Új menüből, vagy állíts vissza egy mentést, amelyben benne van.**

### 4.1 Fájlok megnyitása a Fájlokból

Kattints duplán egy `.ovpn` vagy `.sstp` fájlra a Fájlokban (vagy egy másik fájlkezelőben): a LinVPN megnyitja a **Kapcsolatok** ablakot, és importálja a fájlt, ugyanazokkal az ellenőrzésekkel és kérdésekkel, mint az **Import fájlból…**. A `.macvpncatalog` fájl a csapatkatalógus párbeszédablakát nyitja meg. Semmi nem csatlakozik. Ha a LinVPN nem fut, a dupla kattintás elindítja.

- **A `.conf` fájlokat nem veszi át:** Linuxon ezek egyszerű szövegfájlok, és ha a LinVPN igényt tartana rájuk, minden szövegfájlhoz felajánlaná magát. A WireGuard és a strongSwan `.conf` fájljait a Kapcsolatok ablakból importáld. A mentéseket (`.macvpnbackup`) a **Visszaállítás biztonsági mentésből…** állítja vissza.
- **A letöltött fájlokra előbb rákérdez.** A böngészők megjelölik a letöltött fájlokat (a `user.xdg.origin.url` attribútummal). Az ilyen fájlt a LinVPN csak akkor importálja, ha megerősíted (**Importálod a letöltött fájlt?**); a jelölést csak olvassa, sosem törli.

---

## 5. Csatlakozás

A csatlakozás ugyanúgy működik, mint a MacVPN-ben (lásd [a MacVPN útmutatóját](user-guide.hu.md#5-csatlakozás)): a kártya kapcsolójával, vagy a Kapcsolatok ablak **Csatlakozás** / **Bontás** gombjával. A kártya mutatja az állapotot, a címet, a kapcsolódás óta eltelt időt és az élő forgalmat (**↓ 12.4 MB  ↑ 1.2 MB · ↓ 350 kB/s  ↑ 20.0 kB/s**). Egyszerre több kapcsolat is élhet.

- **A forgalmat** a LinVPN a kapcsolat hálózati interfészéről olvassa: WireGuardnál és OpenVPN-nél arról, amelyet ő nevezett el (`lvw…`, `lvo…`), L2TP-nél, Cisco IPsecnél, SSTP-nél és a rendszer VPN-eknél arról, amelyen a VPN címe van. **Az IKEv2-t** strongSwan 6-tal (Ubuntu 26.04) arról az interfészről olvassa, amelyet a strongSwan-bővítmény a kapcsolatnak létrehoz (`nm-xfrm-…`). Régebbi strongSwannál nincs interfész (a bővítmény a kernel IPsec-szabályaival dolgozik), ezért a forgalmat a kernel IPsec-számlálóiból a **`linvpn-xfrmd`** adja át, amely csak a saját kapcsolataidra válaszol; ilyenkor egy IKEv2-es rendszer VPN-nél csak akkor látszik forgalom, ha a gép minden felhasználója számára van beállítva (a NetworkManagerben nincs felhasználóra korlátozva); a csak a te felhasználódnak beállítottnál nem, mert a szolgáltatás nem tudja eldönteni, kié. `linvpn-xfrmd` nélkül (fejlesztői buildben) egy ilyen IKEv2-kapcsolatnál nem látszik forgalom.
- A szürke kapcsolat megmondja, miért az (hiányzó bővítmény: [2.4](#24-hiányzó-vpn-bővítmények); Linuxon nem futtatható beállítás: [3.7](#37-linuxon-nem-támogatott)).

### 5.1 Többlépcsős hitelesítés (MFA)

- **OpenVPN statikus challenge** (`static-challenge` a configban): a LinVPN csatlakozás előtt kéri a kódot, mint a MacVPN.
- **A szerver által küldött OpenVPN-challenge (CRV1):** a kódablak csatlakozás közben nyílik meg, a szerver szövegével. Gyorsan válaszolj: a NetworkManager 2 percnél rövidebb ideig vár.
- **A jelszó végére fűzött kód** (**Egyszer használatos kód kérése csatlakozáskor, a jelszó végére fűzve**, az **Elválasztó** megadásával): OpenVPN, IKEv2, SSTP, L2TP és Cisco IPsec, valamint L2TP / Cisco IPsec rendszer VPN-ek esetén, mint a MacVPN-ben.
- **A böngészős bejelentkezés** (`OPEN_URL`, `WEB_AUTH`: SAML, SSO) Linuxon nem érhető el: a NetworkManager OpenVPN-szolgáltatása nem adja tovább. Kérj a szolgáltatódtól kódos vagy jelszavas bejelentkezést.

Minden kód és jelszó csak a LinVPN saját **titokügynökén** (secret agent) keresztül jut el a NetworkManagerhez: a NetworkManager abban a pillanatban kéri el őket a LinVPN-től, amikor szüksége van rájuk, a LinVPN pedig csak magának a NetworkManagernek válaszol, és csak az általa indított csatlakozáshoz. A LinVPN kapcsolataihoz nem jelennek meg a GNOME saját jelszókérő ablakai.

### 5.2 Hitelesítő adatok bekérése csatlakozáskor

Mint a MacVPN-ben (lásd [a MacVPN útmutatóját](user-guide.hu.md#53-hitelesítő-adatok-bekérése-csatlakozáskor)): a hiányzó felhasználónevet, jelszót, PSK-t vagy privátkulcs-jelszót csatlakozás előtt a **Hitelesítő adatok szükségesek** ablak kéri, és a **Mentés a széfbe** csak azután menti el, hogy a kapcsolat felépült.

### 5.3 Párosított appok (vezérlő API)

A felhasználói fiókod egy másik programja, például a [RemoteDesktop](https://github.com/LovaszCC/RemoteDesktop) társalkalmazás, a [vezérlő API-n](control-api.hu.md#12-linux-linvpn) keresztül párosítva fel- és lekapcsolhatja helyetted a LinVPN kapcsolatait, ugyanúgy, mint a MacVPN-nel (lásd [a MacVPN útmutatóját](user-guide.hu.md#54-párosított-appok-vezérlő-api)). Bekapcsolni a Kapcsolatok ablakban (**Kapcsolatok kezelése…**) lehet, a **Párosított appok** → **Más appok vezérelhetik a VPN-eket** kapcsolóval; alapból ki van kapcsolva. Linuxon a socket helye `$XDG_RUNTIME_DIR/linvpn/control/linvpn.sock` (általában `/run/user/<felhasználói azonosítód>/linvpn/control/linvpn.sock`), és csak te férsz hozzá.

### 5.4 Automatikus újracsatlakozás

A szabályok a MacVPN-éi (lásd [a MacVPN útmutatóját](user-guide.hu.md#55-automatikus-újracsatlakozás)): alvás, hálózatvesztés vagy hálózatváltás után a kapcsolat ugyanazon a hálózaton magától visszajön, ha a saját hálózatai közül egyik sem érhető el ott közvetlenül; a halott alagutat a LinVPN bontja és újracsatlakoztatja; jönnek a lassú, 5 percenkénti próbálkozások legfeljebb egy órán át; kapcsolatonként ott az **Automatikus újracsatlakozás** kapcsoló. A NetworkManager saját automatikus újracsatlakozása a LinVPN kapcsolatainál ki van kapcsolva: egyedül a LinVPN dönt.

- **Újrapróbálás és nem válaszoló alagút:** amíg a lassú próbálkozások tartanak, a sorban **Újrapróbálás 4 perc múlva** áll; a lebontva hagyott halott alagút (kikapcsolt kapcsolóval, vagy ha párosított app indította) sorában **Nem válaszol**, mint a MacVPN-ben.
- **A LinVPN-en kívüli bontás** (a GNOME hálózati menüje, `nmcli connection down`) a saját bontásodnak számít: a kapcsolat kikapcsoltnak látszik, nem csatlakozik újra, és értesítés sem jön. A kapcsolat minden más vége megszakadás, amely a fenti szabályok szerint újracsatlakozik.
- **A hálózat** az, amit a NetworkManager Ethernet- és Wi-Fi-eszközei hordoznak (a router címe és hardvercíme, valamint a Wi-Fi neve); VPN sosem számít hálózatnak. Ha kikapcsolod a hálózatot (a GNOME gyorsbeállításaiban, vagy kihúzod a kábelt), a **Hálózatra vár…** felirat jelenik meg.
- **Halott alagutak.** **WireGuard:** a Linux nem engedi, hogy egy normál felhasználó kiolvassa a WireGuard utolsó kézfogását, ezért a LinVPN az interfész bájtszámlálóit figyeli: az alagút halott, ha folyamatosan küld, de **200 másodperce** semmit nem kapott (ez túl van a WireGuard 3 perces munkamenet-élettartamán). Az üresjáratban lévő, semmit nem küldő alagutat sosem tekinti halottnak. **OpenVPN:** amíg az OpenVPN magától újraindítja az alagutat (`ping-restart`), a NetworkManager ezt jelzi, és a sorban **Újracsatlakozás…** áll; ha az újraindítás 2 percen belül nem sikerül, az alagút halottnak számít. Egyébként az interfészére ugyanez a számlálós szabály vonatkozik. Ha a NetworkManager egy ilyen újraindítás alatt aktívnak hagyja a VPN-t (nem jelzi), a sor csatlakoztatott marad, és a számlálós szabály dönt: ha az alagút folyamatosan küld, de 200 másodperce semmit nem kapott, a LinVPN bontja és újracsatlakoztatja. **IKEv2:** ugyanez a számlálós szabály vonatkozik az interfésze számlálóira (régebbi strongSwannál az IPsec-számlálóira, a `linvpn-xfrmd`-n át): halott, ha folyamatosan küld, de 200 másodperce semmit nem kapott; az üresjáratban lévő IKEv2-alagutat sosem tekinti halottnak (a strongSwan saját szerverellenőrzései nem számítanak forgalomnak). A strongSwan maga is lezárja azt a kapcsolatot, amelynek a szervere nem válaszol az ellenőrzéseire, és a megszakadt kapcsolat a szokásos módon újracsatlakozik. **Az SSTP, az L2TP és a Cisco IPsec** maga zárja le a halott kapcsolatot, és a megszakadt kapcsolat a szokásos módon újracsatlakozik.

### 5.5 DNS csatlakozás közben

Linuxon a LinVPN-nek nincs saját DNS-kezelője: a VPN DNS-ét a NetworkManager és a systemd-resolved állítja be, amíg a kapcsolat él, és bontáskor (összeomlás után is) visszaállítja a tiédet.

- **Osztott alagút:** a VPN DNS-szerverei csak a VPN saját tartományaira válaszolnak (például `corp.example`); minden más név a szokásos DNS-edhez megy.
- **Minden forgalom a VPN-en:** minden nevet a VPN DNS-szerverei oldanak fel.
- A `resolvectl status` megmutatja, melyik interfész melyik DNS-t használja.

### 5.6 Kilépés, kijelentkezés és alvás

- **Kilépéskor** (**Kilépés a LinVPN-ből** a menüben, vagy **Kilépés** a panelen) a LinVPN előbb a Kapcsolatok ablak nem mentett változásaira kérdez rá (**Mentés**, **Elvetés** vagy **Mégse**). Utána, ha van aktív kapcsolat, megkérdezi: **Leállítás és kilépés**, **Kilépés, fussanak tovább** vagy **Mégse**. A **Leállítás és kilépés** lebontja a LinVPN kapcsolatait és az aktív rendszer VPN-eket. A **Kilépés, fussanak tovább** választással tovább élnek, mint macOS-en és Windowson; ez történik akkor is, ha a LinVPN váratlanul leáll. A LinVPN a következő indításakor felismeri a tovább futó kapcsolatokat, és újra csatlakozottként mutatja őket. Amíg a LinVPN nem fut, a GNOME hálózati menüjéből bonthatod őket; a NetworkManager ekkor elfelejti őket, mint minden bontás után.
- **Kijelentkezés:** a LinVPN megkapja a rendszer kilépési kérését. Ha a Kapcsolatok ablakban nem mentett változás van, rákérdez (**Mentés**, **Elvetés** vagy **Mégse**), de a rendszer nem várja meg a válaszodat, egy idő után mindenképp lezárja a munkamenetet, ezért kijelentkezés előtt ments.
- **Alvás:** ébredés után a kapcsolatok az [5.4](#54-automatikus-újracsatlakozás) szabályai szerint jönnek vissza.

---

## 6. Debug mód és a napló

A Kapcsolatok ablakban egy kapcsolat **Napló** füle minden típusnál a LinVPN saját lépéseit és a kapcsolat rendszernaplósorait mutatja:

- A LinVPN sorai: a csatlakozás (**Kapcsolódás a NetworkManagerrel (…)**), a cím (**Csatlakozva, IPv4: …**; a WireGuard és az IKEv2 egy pillanattal később kapja meg: **Csatlakozva (az IPv4-cím még nem ismert)**, majd **IPv4-cím: …**), a NetworkManager állapotváltásai és a hiba oka (például `AUTH_FAILED: the server refused the login (NetworkManager)`, `Connection timed out (NetworkManager)`; ezek a sorok angolul jelennek meg).
- A rendszernapló sorai, a forrásuk jelölésével: `[nm]` a NetworkManager, `[openvpn]` az OpenVPN, és a bővítmény neve (`[charon-nm]`, `[nm-l2tp-service]`, `[pppd]`, `[sstpc]`, `[vpnc]`, …). Ezek a rendszernaplóból a **`linvpn-logd`** szolgáltatáson át érkeznek, amely csak a saját kapcsolataid sorait adja ki. Egy VPN-bővítmény a soraiban nem nevezi meg a kapcsolatot, ezért a sorai csak akkor látszanak, ha ugyanekkor nem volt más VPN aktív a gépen; különben a LinVPN visszatartja őket, és a naplóban ez áll: **A bővítmény néhány sora nem jelenik meg: ugyanekkor egy másik VPN is aktív volt.**
- `linvpn-logd` nélkül (fejlesztői buildben, vagy sérült telepítésnél) csak a LinVPN saját sorai látszanak, ezzel: **A rendszernapló nem érhető el (a linvpn-logd nincs telepítve).**

A napló a `~/.local/share/LinVPN/logs/<kapcsolat azonosítója>.log` fájl (legfeljebb 5 MiB; ha megtelik, a régebbi fele törlődik). A szűrők, a **Keresés**, az időszűrő, a **Követés**, a **Másolás** és a **Mentés…** ugyanúgy működik, mint a MacVPN-ben (lásd [a MacVPN útmutatóját](user-guide.hu.md#6-debug-mód-és-a-napló)); minden sor az idejével kezdődik, a rendszernapló sorai a rendszernaplóbeli idejükkel. Jelszó, PSK, kulcs és kód sosem kerül bele. A **Napló törlése…** csak a LinVPN saját másolatát üríti ki: a rendszernapló nem változik, egy rendszergazda ott továbbra is olvashatja (`journalctl`).

**A debug mód** (**Alt+kattintás** egy kapcsolón, vagy **Csatlakozás debug módban** a Kapcsolatok ablakban) megnyitja a Napló fület, és beírja azokat a beállításokat is, amelyeket a LinVPN a NetworkManagernek átadott (jelszavak nélkül: a védett érték helyén `***` áll). Az OpenVPN akkor naplóz részletesebben, ha a configjában magasabb a `verb` (legfeljebb 4).

---

## 7. Hibaelhárítás

Először olvasd el a kártyán vagy az értesítésben lévő üzenetet, aztán a **Napló** fület. Az okok a MacVPN-éi (lásd [a MacVPN útmutatójának hibaelhárítását](user-guide.hu.md#7-hibaelhárítás-a-napló-alapján)); Linuxon ezek is előfordulhatnak:

- **A LinVPN jelszókérés nélkül nem módosíthatja a számítógép hálózati beállításait. Jelentkezz be az asztali munkamenetbe, és próbáld újra.**: a LinVPN asztali munkamenet nélkül fut (például SSH-n), vagy a rendszergazda korlátozta a NetworkManagert. Lásd [1.3](#13-a-networkmanager-és-a-vpn-bővítményei).
- **A NetworkManager nem fut.**: indítsd el (`systemctl status NetworkManager`); lehet, hogy egy rendszergazdának kell bekapcsolnia.
- **Ehhez a felhasználóhoz már egy másik LinVPN (vagy LinVPN-teszt) regisztrált a NetworkManagernél.**: a NetworkManager felhasználónként egy LinVPN-t fogad el (a jelszósegédjét, a titokügynököt). Lépj ki a másikból (egy másik asztali munkameneted, egy tesztfuttatás), és csatlakozz újra.
- **A kapcsolódáshoz a LinVPN-nek szüksége van a felhasználó futásidejű könyvtárára ($XDG_RUNTIME_DIR).**: a LinVPN nem normál bejelentkezési munkamenetből indult. Indítsd az alkalmazások közül.
- **Nincs telepítve: NetworkManager …-bővítmény – Rendszerállapot**: lásd [2.4](#24-hiányzó-vpn-bővítmények).
- **Linuxon nem támogatott: …**: lásd [3.7](#37-linuxon-nem-támogatott).
- **Linuxon az IKEv2-höz legalább 20 karakteres előre megosztott kulcs (PSK) kell…**: kérj hosszabb PSK-t a VPN-rendszergazdádtól, vagy használj EAP-ot vagy tanúsítványt.
- `AUTH_FAILED: …` a naplóban: a szerver elutasította a felhasználónevet, a jelszót vagy a kódot (lásd [a MacVPN útmutatóját](user-guide.hu.md#71-auth_failed-openvpn)). Az `AUTH_FAILED: no secrets were given (NetworkManager)` azt jelenti, hogy a NetworkManager olyan titkot kért, amely a LinVPN-nek nem volt meg: mentsd el a jelszót (vagy a PSK-t) a kapcsolatban, és csatlakozz újra.
- `NetworkManager: the VPN plugin did not start (…)`: a bővítmény hiányzik vagy hibás. Nézd meg a sorát a Rendszerállapotban, és telepítsd újra a bővítményt.
- **Az IKEv2 EAP-pal azonnal hibára fut**, és a sora ezt írja: **Az EAP-hoz szükséges: …**: telepítsd a megnevezett csomagokat a Rendszerállapotból. (A `libcharon-extra-plugins` nélkül a strongSwan nem tud válaszolni a szerver EAP-azonosító kérésére; a kapcsolatnapló ezt mutatja: `EAP_IDENTITY not supported, sending EAP_NAK`.)
- **A kapcsolat beállításai hiányoznak erről a számítógépről. Nyisd meg, és mentsd újra.**: egy L2TP vagy Cisco IPsec kapcsolat leírása eltűnt (például egy visszaállítás után). Nyisd meg, és kattints a **Mentés** gombra.
- **A NetworkManagerben nincs ilyen azonosítójú VPN, amelyet ez a felhasználó használhat.**: egy rendszer VPN-t töröltek, vagy egy másik felhasználóra korlátoztak.

---

## 8. Frissítés

A LinVPN a GitHub Releases oldalon keresi az új verziókat: induláskor, majd 24 óránként egyszer. Ez a telepített LinVPN-ben működik, fejlesztői buildben nem. A beállítások ugyanazok, mint a MacVPN-ben: **Frissítések keresése most**, **Frissítések automatikus keresése** és **Csak a legalább 24 órája megjelent frissítések felajánlása** a panel **Beállítások** csoportjában.

Ha van újabb verzió, a panelen megjelenik a **Frissítés elérhető: vX.Y.Z** sor; a **Frissítés** ablak **Letöltés és telepítés** gombja:

1. letölti a számítógéped architektúrájához tartozó csomagot (`linvpn_X.Y.Z_amd64.deb` vagy `_arm64.deb`), a `.sha256` fájlját és a `.sig` aláírását a `~/.cache/LinVPN/updates` mappába, és ellenőrzi, hogy a fejlesztő az offline kiadási kulcsával pontosan ezt a verziót és ezt a csomagfájlt írta alá. A fejlesztő által alá nem írt csomag sosem települ;
2. a kilépéshez hasonlóan rákérdez a nem mentett változásokra és az aktív kapcsolatokra (lásd [5.6](#56-kilépés-kijelentkezés-és-alvás): a **Kilépés, fussanak tovább** választással a kapcsolatok tovább élnek, és a frissített LinVPN újra csatlakozottként mutatja őket);
3. **rendszergazdai jelszót** kér a rendszer saját ablakában (az üzenet szerint a LinVPN a frissítését szeretné telepíteni). Ha ezt az ablakot bezárod, a frissítés elmarad, és semmi nem települ.

Ezután a frissítési lépés rootként fut, és a csomag saját másolatán mindent újra ellenőriz (az aláírást, hogy a csomag a `linvpn`, a gépedhez való, az aláírt verziójú és újabb a telepítettnél), mielőtt az apt telepíti. A LinVPN régebbi verziót sosem telepít. A telepítés után a LinVPN magától újraindul, és ezt írja: **A LinVPN frissült erre a verzióra: X.Y.Z.** Ha a frissítés nem sikerül, a telepített verzió marad, a telepítés naplója pedig a `~/.cache/LinVPN/updates` mappában van (`install-<verzió>.log`).

A NetworkManagert, az OpenVPN-t és a VPN-bővítményeket a rendszer saját frissítései (Szoftverfrissítő, `apt upgrade`) frissítik, nem a LinVPN. A LinVPN saját OpenVPN-szolgáltatása a LinVPN csomagjával érkezik.

Újabb csomagot bármikor kézzel is telepíthetsz, ahogy az [1.2](#12-a-csomag-telepítése) részben áll.

## 9. A LinVPN eltávolítása

Lépj ki a LinVPN-ből (**Kilépés a LinVPN-ből** a menüben, vagy **Kilépés** a panelen, majd **Leállítás és kilépés**, hogy a kapcsolatai lebomoljanak), majd távolítsd el a csomagot rendszergazdaként:

    sudo apt remove linvpn

Ez eltávolítja az alkalmazást, a LinVPN OpenVPN-szolgáltatását, a `linvpn-logd`-t és a `linvpn-xfrmd`-t (előbb kikapcsolja a socketjüket), a frissítési lépést, a bejegyzést az alkalmazások között, a fájltípusokat és a frissítési jogosultságot. A NetworkManager, az OpenVPN és a VPN-bővítmények megmaradnak; ha már nem kellenek, az apt-tal távolíthatod el őket. A saját NetworkManager VPN-jeidhez (a rendszer VPN-ekhez) a LinVPN nem nyúl, és a NetworkManagerben nem hagyott kapcsolatot.

**Az adataid megmaradnak**, az `apt purge` után is: a csomagkezelő sosem nyúl a saját mappádban lévő fájlokhoz és a kulcstartódhoz. Ha ezeket is törölnéd, töröld:

- a `~/.local/share/LinVPN` mappát (a széf, a kapcsolatok és a jelszavaik, a kapcsolatnaplók, az L2TP / Cisco IPsec leírások és az IKEv2-tanúsítványok `swanctl` mappája),
- a `~/.config/LinVPN` mappát (a beállítások),
- a `~/.cache/LinVPN` mappát (a letöltött frissítések és a naplóik),
- a `~/.config/autostart/linvpn.desktop` fájlt (indítás bejelentkezéskor, ha be volt kapcsolva),
- a **LinVPN vault key** bejegyzést a **Jelszavak és kulcsok** alkalmazásban (a bejelentkezési kulcstartóban).

A `$XDG_RUNTIME_DIR/linvpn` mappát a rendszer kijelentkezéskor kiüríti. A **Teljes biztonsági mentés…** gombbal készített mentésfájlokat neked kell törölnöd. Ha a számítógép más felhasználója is használta a LinVPN-t, neki mindezekből saját példánya van.

## 10. Biztonsági megjegyzések

- **A LinVPN a te nevedben fut.** Munka közben a LinVPN-ből semmi nem fut rootként, kivéve azokat a VPN-programokat, amelyeket a NetworkManager indít egy kapcsolathoz, mint bármely NetworkManager-VPN-nél: a LinVPN OpenVPN-szolgáltatását a NetworkManager indítja, és az OpenVPN-t `nm-openvpn` felhasználóként, a saját mappájába zárva futtatja, pontosan úgy, mint a szokásos bővítmény; valamint a `90-linvpn-route` útvonalszkriptet, amelyet a NetworkManager egy VPN csatlakozásakor futtat (lásd lent). A frissítési lépés csak azután fut rootként, hogy rendszergazdai jelszóval jóváhagytál egy frissítést; csak a fejlesztő által aláírt, `linvpn` nevű, a gépedhez való csomagot telepít, régebbi verziót sosem.
- **A kapcsolatok,** amelyeket a LinVPN a NetworkManagernek átad, ideiglenesek, csak a memóriában léteznek, és csak a te felhasználód használhatja őket. Nincs bennük jelszó, PSK vagy kulcs: a NetworkManager csatlakozáskor a LinVPN titokügynökétől kéri el őket, az ügynök pedig csak magának a NetworkManagernek válaszol, és csak a LinVPN által indított csatlakozáshoz. Semmi nem kerül a GNOME kulcstartójába vagy a NetworkManager tárolt kapcsolatai közé. A config tanúsítvány- és kulcsfájljai csak a kapcsolat idejére vannak a privát futási mappádban.
- **A `linvpn-logd`** nem root: a systemd kérésenként indítja el, ideiglenes felhasználóként a rendszernapló csoportjában, hálózat és írási jog nélkül. A hívót a kerneltől kapott adatok alapján azonosítja, és csak az ő saját LinVPN-kapcsolatainak sorait adja ki: a kapcsolat NetworkManager-azonosítóját a hívó felhasználói azonosítójából számítja ki, így senki nem kérheti el egy másik felhasználóét.
- **A `90-linvpn-route`** rootként fut, a NetworkManager indítja egy VPN csatlakozásakor: csak a LinVPN által megjelölt, nem minden forgalmat továbbító L2TP- és SSTP-alagutaknál tesz bármit, szigorúan ellenőrzi az interfész nevét és a címet, és egyetlen útvonalat vesz fel a VPN saját interfészén át, amely azzal együtt meg is szűnik. Új jogot nem ad: a felhasználó saját NetworkManager-VPN-je rendszergazda nélkül is bármilyen útvonalat beállíthat az alagútján át.
- **A `linvpn-xfrmd`** sem root: a systemd kérésenként indítja el, ideiglenes felhasználóként, amelynek egyetlen jogosultsága a kernel IPsec-állapotának olvasása (`CAP_NET_ADMIN`; soha semmit nem módosít), írási jog és IP-hálózat nélkül. A hívót a kerneltől kapott adatok alapján azonosítja, a NetworkManagertől kérdezi meg, melyik kapcsolat a hívó sajátja (ugyanazzal a származtatott azonosítóval, mint a `linvpn-logd`; rendszer VPN-t csak akkor, ha az minden felhasználóé), és két számot ad vissza, a fogadott és a küldött bájtokat: kulcsot, címet vagy más kapcsolat adatát soha.
- **A széf** titkosított (SQLCipher), a mesterjelszavaddal és a helyreállítási kulccsal, mint a MacVPN-ben; a kulcstartóban tartott automatikus feloldási kulcs az a kompromisszum, amelyről az [1.4](#14-hol-tárolja-a-linvpn-az-adataidat) rész szól.
- **Az OpenVPN** a MacVPN direktívaszabályait követi (tiltott és kockázatos direktívák); a Linux-oszlop csak azt teszi hozzá, amit a NetworkManager nem tud futtatni.
- **A vezérlő API** csak egy socketen figyel a privát futási mappádban; csak a felhasználói fiókod programjai érik el, és csak azután, hogy párosítottad őket.
- **Az értesítések és az ablakcímek** sosem mutatnak jelszót, kulcsot vagy tokent.
- További részletek a [MacVPN útmutatójának biztonsági megjegyzéseiben](user-guide.hu.md#10-biztonsági-megjegyzések), amelyek a macOS-es root rétegről szólók kivételével a LinVPN-re is érvényesek.
