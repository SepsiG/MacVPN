# WinVPN – felhasználói útmutató

[English version](winvpn-user-guide.en.md)

A WinVPN a [MacVPN](user-guide.hu.md) windowsos változata: a tálca értesítési területén futó alkalmazás Windows 10-re és 11-re (x64 vagy ARM64), amely egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec és Cisco IPsec kapcsolatokat, felépíti őket, és a magában a Windowsban beállított VPN-eket is listázza. A kapcsolatok és jelszavaik egy titkosított széfben vannak. A WinVPN és a MacVPN kódja közös, ugyanaz a széf, a biztonsági mentés és a csapatkatalógus formátuma, és ez az útmutató a MacVPN útmutatójának szerkezetét követi.

- **Rövid, feladat szerinti lépések** (telepítés, csatlakozás, mentés, eltávolítás, …): a [WinVPN – Hogyan csináld](winvpn-how-to.hu.md).
- **Mit hogyan csatlakoztat a WinVPN:** az OpenVPN-t és a WireGuardot a **WinVPN szolgáltatáson** keresztül (lásd [1.3](#13-a-winvpn-szolgáltatás)), az L2TP/IPsec, IKEv2 és SSTP kapcsolatokat a **Windows saját VPN-kliensével** (lásd [1.5](#15-a-wireguard-és-a-windows-vpn-kliens)). A **Cisco IPsec** kapcsolatok megmaradnak, de a Windows nem tudja felépíteni őket (lásd [3.4](#34-l2tpipsec-és-cisco-ipsec)).
- Ha fejlesztőként azt szeretnéd, hogy egy másik program ezen a számítógépen fel- és lekapcsolhassa a WinVPN kapcsolatait (**Párosított appok** a Kapcsolatok ablakban), olvasd el a [vezérlő API leírását](control-api.hu.md#11-windows-winvpn) és a [példaklienst](../examples/macvpn-control-client/README.md#windows) (angolul).

> **Nyelv:** a WinVPN a Windows megjelenítési nyelvét és az előnyben részesített nyelveidet követi (Gépház → Idő és nyelv → Nyelv és régió). Magyarul és angolul érhető el; ha a preferált nyelvek között egyik sincs, angolul jelenik meg. Ez az útmutató a magyar feliratokat használja, az [angol útmutató](winvpn-user-guide.en.md) az angolokat.

## Újdonságok a 2.0-ban

A 2.0 az első WinVPN, amely csatlakozni is tud. A MacVPN 2.0 minden funkciója megvan benne, az útmutatóban megnevezett windowsos eltérésekkel.

- **Csatlakozás.** Az OpenVPN és a WireGuard a telepítő által felvett WinVPN szolgáltatáson keresztül; az L2TP/IPsec, az IKEv2 és az SSTP a Windowsba épített VPN-klienssel, a saját felhasználói fiókodból, a szokásos esetben rendszergazda nélkül. Lásd [5.](#5-csatlakozás)
- **A saját Windows VPN-jeid** (Gépház → Hálózat és internet → VPN) **rendszer VPN**-ként jelennek meg, élő állapottal; a WinVPN fel- és lekapcsolja őket. Lásd [3.5](#35-rendszer-vpn-ek-a-saját-windows-vpn-jeid).
- **Az OpenVPN Communityt** a **Rendszerállapot** telepíti és frissíti (wingettel vagy az OpenVPN hivatalos telepítőjével); a **wireguard-nt** a WinVPN-nel érkezik, és a WinVPN szolgáltatás frissíti. A motorok a megjelenésük után frissülnek, új WinVPN nélkül. Lásd [1.4](#14-openvpn-community) és [2.5](#25-az-openvpn-és-a-wireguard-frissítése).
- **Egyszer használatos kód, böngészős bejelentkezés és hitelesítőadat-bekérés**, mint a MacVPN-ben. Lásd [5.2](#52-többfaktoros-hitelesítés-mfa) és [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor).
- **Debug mód és élő napló** minden típusnál, a Windows VPN-kliensénél is. Lásd [6.](#6-debug-mód-és-a-napló) és [7.](#7-hibaelhárítás-a-napló-alapján)
- **A WinVPN frissíti magát** aláírt kiadásokból. Lásd [8.](#8-frissítés)
- **HTTPS-es csapatkatalógusok.** Lásd [16.1](#161-feliratkozás-egy-katalógusra).
- **WinVPN eltávolítása erről a fiókról…** a Rendszerállapotban: rendet tesz az eltávolítás előtt. Lásd [9.](#9-eltávolítás)
- **Megjelenés**, **kapcsolatértesítések**, **hiányzó VPN-motorok**, **automatikus újracsatlakozás** és **naplóméret-korlát**: ugyanúgy, mint a MacVPN 2.0-ban. Lásd [2.2](#22-megjelenés), [2.3](#23-értesítések), [2.4](#24-hiányzó-vpn-motorok), [5.5](#55-automatikus-újracsatlakozás) és [6.](#6-debug-mód-és-a-napló)

**Ismert korlátok Windowson:**

- **A Cisco IPsec nem csatlakozik:** a Windowsban nincs hozzá kliens. A kapcsolatok megmaradnak (szerkeszthetők, exportálhatók, benne vannak a mentésekben és a katalógusokban), és az **L2TP/IPsec másolat készítése** ugyanarra a szerverre működő L2TP/IPsec kapcsolatot készít. Lásd [3.4](#34-l2tpipsec-és-cisco-ipsec).
- **Az előre megosztott kulcsos (PSK) IKEv2 nem támogatott:** a Windows IKEv2-kliense csak EAP-MSCHAPv2-vel vagy számítógép-tanúsítvánnyal jelentkezik be. Lásd [3.3](#33-ikev2-strongswan).
- **NAT mögötti szerverhez az L2TP/IPsec** egyszeri rendszergazdai lépést kér (**L2TP engedélyezése NAT mögött…**, utána újraindítás). Lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez).
- A Windows tanúsítványtárából vett OpenVPN-tanúsítvány (`cryptoapicert`) nem támogatott; a WireGuard `FwMark` és `Table` kulcsa csak `auto` / `off` lehet. Lásd [3.1](#31-openvpn) és [3.2](#32-wireguard).

## Tartalom

1. [Telepítés](#1-telepítés) ([A WinVPN szolgáltatás](#13-a-winvpn-szolgáltatás), [OpenVPN Community](#14-openvpn-community), [A WireGuard és a Windows VPN-kliens](#15-a-wireguard-és-a-windows-vpn-kliens), [Hol tárolja a WinVPN az adataidat](#16-hol-tárolja-a-winvpn-az-adataidat))
2. [Első indítás és a Rendszerállapot ablak](#2-első-indítás-és-a-rendszerállapot-ablak) ([Megjelenés](#22-megjelenés), [Értesítések](#23-értesítések), [Hiányzó VPN-motorok](#24-hiányzó-vpn-motorok), [Az OpenVPN és a WireGuard frissítése](#25-az-openvpn-és-a-wireguard-frissítése))
3. [Kapcsolatok felvétele típusonként](#3-kapcsolatok-felvétele-típusonként) ([Rendszer VPN-ek](#35-rendszer-vpn-ek-a-saját-windows-vpn-jeid), [Rendszergazdai lépések](#37-rendszergazdai-lépések-a-natív-vpn-ekhez), [Hol vannak a natív VPN-ek](#38-hol-tárolja-a-winvpn-a-natív-vpn-eket))
4. [Import és export](#4-import-és-export) ([VPN-fájlok megnyitása a Fájlkezelőből](#41-vpn-fájlok-megnyitása-a-fájlkezelőből))
5. [Csatlakozás](#5-csatlakozás) ([Sorrend](#51-a-kapcsolatok-sorrendje), [MFA](#52-többfaktoros-hitelesítés-mfa), [Hitelesítő adatok bekérése](#53-hitelesítő-adatok-bekérése-csatlakozáskor), [Párosított appok](#54-párosított-appok-vezérlő-api), [Automatikus újracsatlakozás](#55-automatikus-újracsatlakozás), [DNS](#56-dns-kapcsolat-közben), [Kilépés és kijelentkezés](#57-kilépés-kijelentkezés-és-alvó-állapot))
6. [Debug mód és a napló](#6-debug-mód-és-a-napló)
7. [Hibaelhárítás a napló alapján](#7-hibaelhárítás-a-napló-alapján)
8. [Frissítés](#8-frissítés)
9. [Eltávolítás](#9-eltávolítás)
10. [Biztonsági megjegyzések](#10-biztonsági-megjegyzések)
11. [Széf](#11-széf)
12. [Mappák és színek](#12-mappák-és-színek)
13. [Közös hitelesítő adatok](#13-közös-hitelesítő-adatok)
14. [Biztonsági mentés és visszaállítás](#14-biztonsági-mentés-és-visszaállítás)
15. [Gyakori kérdések a széfről](#15-gyakori-kérdések-a-széfről)
16. [Csapatkatalógusok](#16-csapatkatalógusok)

---

## 1. Telepítés

### 1.1 A telepítő

A WinVPN MSI-telepítőként érkezik, processzortípusonként egy:

- `WinVPN-x.y.z-x64.msi` Intel és AMD processzorhoz (a legtöbb számítógéphez),
- `WinVPN-x.y.z-arm64.msi` ARM processzorhoz (például Snapdragon; elkészül és ellenőrizzük, de ARM-hardveren még nem teszteltük).

**Rendszergazda** telepíti: kattints duplán az MSI-re, és erősítsd meg a rendszergazdai kérdést. A WinVPN a számítógép minden felhasználója számára a `C:\Program Files\WinVPN` mappába települ: `WinVPN.exe` (az alkalmazás), `WinVPNService.exe` (a WinVPN szolgáltatás, lásd [1.3](#13-a-winvpn-szolgáltatás)), `wireguard.dll` (a WireGuard aláírt meghajtókönyvtára) és `THIRD-PARTY-NOTICES.txt` (a mellékelt összetevők licencei), a Start menüben pedig megjelenik a **WinVPN** bejegyzés. A mappa nem változtatható: a WinVPN szolgáltatás teljes jogokkal fut belőle, ezért csak rendszergazda módosíthatja, és más mappából a szolgáltatás nem indul el. Újabb WinVPN fölé régebbi nem telepíthető (előbb el kell távolítani); ugyanaz a verzió újratelepíthető. A WinVPN ablakai a Microsoft Edge WebView2 Runtime-ot használják, amely a Windows 11-en már megvan; ha hiányzik, a telepítő letölti (ehhez internetkapcsolat kell).

Ugyanannak a telepítőnek az ismételt futtatása javítja a telepítést; második példányt sosem telepít. Egy régebbi WinVPN (az 1.5.0-s előzetes is) fölé telepített újabb MSI frissíti azt, és megtartja az adataidat (lásd [8.1](#81-frissítés-az-15-ös-előzetesről)).

### 1.2 SmartScreen

A telepítő nincs kódaláíró tanúsítvánnyal (Authenticode) aláírva, ezért a Microsoft Defender SmartScreen az első alkalommal figyelmeztethet: **A Windows megvédte a számítógépet**. Ellenőrizd, hogy a fájlt a hivatalos helyről töltötted le, majd kattints a **További információ**, aztán a **Futtatás mindenképp** gombra. Ezt telepítőfájlonként csak egyszer kell megtenned. (A WinVPN saját frissítéseit ehelyett a fejlesztő offline aláírása védi, lásd [8.](#8-frissítés))

### 1.3 A WinVPN szolgáltatás

Az OpenVPN-nek és a WireGuardnak rendszerjogok kellenek a hálózati adapterekhez, útvonalakhoz és DNS-beállításokhoz. Ezek egy normál felhasználónak nincsenek meg, ezért a telepítő felveszi a **WinVPN szolgáltatást** (`WinVPN`, megjelenített neve **WinVPN Service**), amely a háttérben, rendszerként (LocalSystem) fut, és a Windowsszal együtt indul. Az app egy csak a számítógép programjai által elérhető helyi csatornán (`\\.\pipe\WinVPN`) kéri tőle a kapcsolat felépítését vagy bontását; a szolgáltatás hálózatról sosem fogad kérést.

- **Minden felhasználó kapcsolatai a sajátjai.** Egy kapcsolat azé a Windows-felhasználóé, aki felépítette: a gép másik felhasználója nem látja, nem bonthatja, nem válaszolhat a kódkérésére, és nem olvashatja a naplóját. Amíg viszont egy VPN él, az egész számítógép forgalmát viszi (így működik minden windowsos VPN).
- **A kijelentkezés bontja őket.** Kijelentkezéskor a szolgáltatás lebontja az OpenVPN- és WireGuard-kapcsolataidat. A képernyő zárolása és a felhasználóváltás után megmaradnak.
- **Ellenőrzi, amit futtat:** az `openvpn.exe`-t csak rendszergazdák által írható mappában lévő telepítésből, **OpenVPN Inc.** aláírással és legalább 2.6.0-s verzióval; a `wireguard.dll`-t csak **WireGuard LLC** aláírással.
- **Az adatai** a `C:\ProgramData\WinVPN` mappában vannak (csak a rendszergazdák és a rendszer olvashatja): a kapcsolatnaplók (`logs`, a jelszavak és kódok maszkolva, lásd [6.](#6-debug-mód-és-a-napló)), a saját naplója (`service.log`) és a letöltött motorok (`engines`). Ha ezt a mappát a telepítés előtt egy normál felhasználó hozta létre, a szolgáltatás nem bízik meg benne: a **Rendszerállapot** ezt írja: **A(z) … mappa jogosultságai nem biztonságosak. Egy rendszergazdának törölnie kell, majd újra kell indítania a WinVPN szolgáltatást.**
- Ha a szolgáltatás váratlanul leáll, a Windows újraindítja (5 mp, majd 30 mp után). Ha hiányzik vagy egy másik WinVPN-verzióé, a **Rendszerállapot** ezt írja: **A WinVPN szolgáltatás hiányzik, vagy egy másik WinVPN-verzióhoz tartozik. Javítsd a WinVPN-t: Gépház → Alkalmazások → Telepített alkalmazások → WinVPN → Módosítás → Javítás.**; ha nem válaszol: **A WinVPN szolgáltatás nem érhető el.** Ilyenkor az OpenVPN- és WireGuard-kapcsolatok nem építhetők fel; az L2TP/IPsec, az IKEv2, az SSTP és a rendszer VPN-ek igen (ezek nem használják a szolgáltatást). Amíg nincs rendbe téve, a **Rendszerállapot** csempéjén **!** jel van, és az ablak indításkor magától megnyílik.

### 1.4 OpenVPN Community

Az OpenVPN-kapcsolatokat a WinVPN az **OpenVPN Community** programmal (`openvpn.exe`) futtatja, amely nem része a WinVPN telepítőjének. Ha szükséged van rá, a **Rendszerállapot** telepíti: az **OpenVPN Community** sor piros, **Telepítés** gombbal.

- A **Telepítés** a **wingettel** (a Windows csomagkezelője, Windows 11-en megvan) a legújabb OpenVPN Communityt telepíti; winget nélkül, vagy ha a winget hibázik vagy kihagy egy illesztőprogramot, letölti az OpenVPN hivatalos telepítőjét, ellenőrzi az aláíróját (**OpenVPN Inc.**), és azt futtatja. Egy rendszergazda megerősíti (a winget útján utána egy második kérdés is jön, magának a WinVPN-nek). A telepítő kimenete élőben látszik a sor alatt; elutasított kérdésnél: **Megszakítva**.
- **Ami települ:** az `openvpn.exe` a könyvtáraival és két hálózati illesztőprogram, a **DCO** (az OpenVPN gyors kernelmeghajtója) és a **TAP-Windows6**. Ami nem: az OpenVPN GUI és az a szolgáltatás, amely magától indítja a configokat.
- **Az OpenVPN interaktív szolgáltatása** (Interactive Service) minden OpenVPN-telepítéssel érkezik. A WinVPN nem használja, ezért ha a WinVPN telepítette (frissítette, javította) az OpenVPN-t, letiltja és leállítja. A korábban (vagy kézzel) telepített OpenVPN Communityt úgy használja, ahogy van: annak interaktív szolgáltatásához sosem nyúl, így az OpenVPN GUI továbbra is működik.
- **Melyik illesztőprogramot kapja egy kapcsolat.** A WinVPN a configból dönt: alapból **DCO**; **TAP-Windows6**, ha a config olyat használ, amit a DCO nem tud (tömörítés, régebbi, nem AEAD titkosító, például `AES-256-CBC`, `fragment`, proxy, statikus kulcs vagy `dev tap`). Ha csatlakozás közben a szerver küld ilyen beállítást, a WinVPN egyszer újrapróbálja TAP-Windows6-tal (a napló jelzi). TAP-Windows6 adapter egy van, így egyszerre csak egy TAP-Windows6-os kapcsolat élhet.
- **Javítás:** ha egy illesztőprogram hiányzik, a sor ezt írja: **Hiányzik: … A Javítás telepíti őket.**; az ilyen illesztőprogramot igénylő kapcsolat ezt: **Ehhez a kapcsolathoz a(z) … illesztőprogram kell. Javítsd az OpenVPN Communityt a Rendszerállapotban.**
- **A tömörítés** (`comp-lzo`, `compress`) engedett, mert néhány szerver még használja, de a tömörített titkosított forgalomból információ szivároghat (VORACLE): kérd meg a szerver rendszergazdáját, hogy kapcsolja ki.
- A WinVPN eltávolítása után az OpenVPN Community, az illesztőprogramjai és a TAP-adapterei megmaradnak (az OpenVPN-hez tartoznak; az OpenVPN-t a Telepített alkalmazások alatt távolíthatod el).

### 1.5 A WireGuard és a Windows VPN-kliens

- **A WireGuardhoz** nem kell semmit telepíteni: a WinVPN a WireGuard saját meghajtókönyvtárát (wireguard-nt, WireGuard LLC aláírással) hozza, a WinVPN szolgáltatás pedig kapcsolatonként egy WireGuard-adaptert hoz létre.
- **Az L2TP/IPsec, az IKEv2 és az SSTP** a **Windows VPN-kliensét** használja (Remote Access, a Windows része, a Windows Update frissíti). A WinVPN a saját felhasználói fiókodból tárcsázza őket, WinVPN szolgáltatás és rendszergazdai jog nélkül. A Rendszerállapotban egy **Windows VPN-kliens** sor látszik: zölden **A Windows része**, vagy pirosan, ha egy szükséges Windows-szolgáltatás le van tiltva (**A(z) … Windows-szolgáltatás le van tiltva. Egy rendszergazdának Kézi indításra kell állítania (services.msc).**): Remote Access Connection Manager (`RasMan`), IKE and AuthIP IPsec Keying Modules (`IKEEXT`, L2TP és IKEv2), IPsec Policy Agent (`PolicyAgent`, L2TP) és Secure Socket Tunneling Protocol Service (`SstpSvc`, SSTP). Ezek igény szerint indulnak: a „leállítva” állapot normális.

### 1.6 Hol tárolja a WinVPN az adataidat

Minden Windows-felhasználónak saját WinVPN-adatai vannak a `%LOCALAPPDATA%\WinVPN` mappában (általában `C:\Users\<te>\AppData\Local\WinVPN`):

- a széf (`vault.db`, mellette a kulcsfájlja, a `vault.keys`) és a beállítások (`preferences.json`);
- `ras\`: a WinVPN saját telefonkönyve a Windows VPN-bejegyzésekkel (`WinVPN.pbk`), és L2TP kapcsolatonként egy kis beállításfájl (lásd [3.8](#38-hol-tárolja-a-winvpn-a-natív-vpn-eket));
- `logs\ras\`: az L2TP/IPsec, IKEv2 és SSTP kapcsolatok naplói;
- `downloads\` és `updates\`: az OpenVPN-telepítők és a WinVPN-frissítések, amíg települnek, és a telepítési naplók.

A mappát és a fájljait csak te és maga a Windows (SYSTEM) olvashatja; a számítógép többi felhasználója nem nyithatja meg őket. A mappa nem része a vándorló (roaming) profilnak: ezen a számítógépen marad. Másik számítógépre (vagy Macről) teljes biztonsági mentéssel költözhetsz (lásd [14.](#14-biztonsági-mentés-és-visszaállítás)). Az OpenVPN- és WireGuard-kapcsolatok naplóit a WinVPN szolgáltatás a `C:\ProgramData\WinVPN\logs` mappában tartja (lásd [6.](#6-debug-mód-és-a-napló)).

---

## 2. Első indítás és a Rendszerállapot ablak

Indítsd el a WinVPN-t a Start menüből. Egy pajzs ikonként jelenik meg a tálca jobb szélén, az értesítési területen; sötét tálcán fehér, világoson fekete. Ha a Windows a **Rejtett ikonok megjelenítése** (a **^** nyíl) alá rejti, áthúzhatod a tálcára, vagy bekapcsolhatod a Gépház → Személyre szabás → Tálca oldalon. Ha az egeret az ikon fölé viszed, a **WinVPN** felirat látszik. Amíg egy kapcsolat még csatlakozik vagy újracsatlakozik, a pajzs félig kitöltött, és fölé víve **WinVPN – Csatlakozás…** látszik; ha egy kapcsolat felépült (és egyik sem csatlakozik még), a pajzson pipa van, a felirat **WinVPN – Csatlakozva**. Ha egy kapcsolat felépült, de a gép alól eltűnt a hálózat (kikapcsolt Wi-Fi, kihúzott kábel), a pajzs szintén félig kitöltött, a felirat **WinVPN – Hálózatra vár…**; így van akkor is, amikor az OpenVPN magától indítja újra az alagutat (a sorában **Újracsatlakozás…** áll). Egy nem válaszoló, ezért bontott kapcsolatnál a pajzson felkiáltójel van (lásd [5.5](#55-automatikus-újracsatlakozás)).

A legelső indításkor megnyílik a **Széf beállítása** ablak (lásd [11.1](#111-mesterjelszó-és-helyreállítási-kulcs)).

Az ikonra kattintva nyílik meg a popover, az ikon fölött (Windows 11-en lekerekített sarkokkal). Minden kapcsolat egy kártya a típusa színes buborékával, a nevével, a típusával és az állapotával, valamint egy kapcsolóval; sok kapcsolatnál a lista görgethető. A mappák nyitható-csukható sorokként jelennek meg (lásd [12.](#12-mappák-és-színek)). A kártyák alatt:

- három csempe: **Új kapcsolat / Import…**, **Kapcsolatok kezelése…** és **Rendszerállapot**;
- a **Beállítások** csoport (kattintásra nyílik és csukódik): **Megjelenés** (lásd [2.2](#22-megjelenés)), **Kapcsolatértesítések** (lásd [2.3](#23-értesítések)), a frissítés beállításai (lásd [8.](#8-frissítés)), **Indítás bejelentkezéskor**; utána a széf beállításai: **Automatikus feloldás**, **„Széf zárolása most” megjelenítése**, **Mesterjelszó módosítása…** és **Új helyreállítási kulcs…** (lásd [11.](#11-széf)), végül **Teljes biztonsági mentés…** és **Visszaállítás biztonsági mentésből…** (lásd [14.](#14-biztonsági-mentés-és-visszaállítás));
- **Súgó**, **Széf zárolása most** (ha látszik, lásd [11.4](#114-széf-zárolása-most)) és **Kilépés**. A **Súgó** ezt az útmutatót nyitja meg a GitHubon (magyarul, ha a WinVPN nyelve magyar).

Amíg a széf zárolva van, a popoverben csak egy **Széf feloldása…** sor, az aktív kapcsolatok száma és a **Kilépés** látszik (lásd [11.5](#115-a-zárolt-popover)). Amíg a széf nem létezik, a sor felirata **Széf beállítása…**.

**A Rendszerállapot ablak** ezt írja: **A WinVPN az OpenVPN- és a WireGuard-kapcsolatokat a WinVPN szolgáltatáson keresztül építi fel. Az OpenVPN Communityt itt telepítheted, ha szükséged van rá.**, és négy sort mutat:

1. **WinVPN szolgáltatás:** **Fut (… verzió)**, vagy hogy miért nem tud kapcsolatot futtatni (lásd [1.3](#13-a-winvpn-szolgáltatás)).
2. **OpenVPN Community:** a telepített verzió és az illesztőprogramjai (**2.7.8. verzió · illesztőprogramok: OpenVPN DCO 2.8.13.0, TAP-Windows6 9.27.0.0**), vagy **Telepítés**, **Javítás** vagy **Frissítés** (lásd [1.4](#14-openvpn-community) és [2.5](#25-az-openvpn-és-a-wireguard-frissítése)).
3. **WireGuard:** a wireguard-nt verziója, és **Frissítés**, ha van újabb.
4. **Windows VPN-kliens:** **A Windows része**, vagy a letiltott Windows-szolgáltatás (lásd [1.5](#15-a-wireguard-és-a-windows-vpn-kliens)).

Amíg egy sornak kell valami, a **Rendszerállapot** csempéjén **!** jel van, és az ablak indításkor magától megnyílik. Az OpenVPN Community nem kötelező: amíg csak nincs telepítve, a sora piros marad a **Telepítés** gombbal, de nincs **!** jel, és az ablak indításkor sem nyílik meg (a telepített OpenVPN, amelyhez **Javítás** kell, vagy **Frissítés**, mert a szolgáltatás nem fogadja el a verzióját, továbbra is számít). A hiányzó vagy nem elérhető WinVPN szolgáltatás mindig számít. Egy újabb motorverzió önmagában nem: a sor zöld marad, és **Frissítés** gombot kínál (lásd [2.5](#25-az-openvpn-és-a-wireguard-frissítése)). Az **Újraellenőrzés** mindent újra megnéz. A sorok alatt van az **Indítás bejelentkezéskor** kapcsoló, az eltávolításról szóló megjegyzés a **Telepített alkalmazások megnyitása…** gombbal, és a **WinVPN eltávolítása erről a fiókról…** (lásd [9.](#9-eltávolítás)).

**Ablakok és billentyűzet.** Minden WinVPN-ablaknak (Kapcsolatok, Rendszerállapot, a széf ablakai) saját gombja van a tálcán, így Alt+Tabbal is elérhető; amíg csak a popover van nyitva, a WinVPN-nek nincs tálcagombja. A WinVPN-nek nincs menüsora: a szövegmezőkben a szokásos billentyűparancsok működnek (Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+A, Ctrl+Z), a **Ctrl+S** ment a szerkesztőben, a **Ctrl+F** pedig a Kapcsolatok ablak keresőmezőjébe ugrik. Ha futás közben újra elindítod a WinVPN-t (például a Start menüből), nem indul második példány: a futó WinVPN előhozza a nyitott ablakait, vagy megnyitja a Kapcsolatok ablakot (zárolt széfnél a széf ablakát).

### 2.1 Indítás bejelentkezéskor

A WinVPN alapból nem indul el magától. Ha minden Windows-bejelentkezéskor el szeretnéd indítani, kapcsold be az **Indítás bejelentkezéskor** kapcsolót a popover **Beállítások** csoportjában vagy a **Rendszerállapot** ablakban. Kikapcsolni ugyanott lehet. A következő bejelentkezéstől érvényes.

- A WinVPN csak a saját felhasználód számára jegyzi be magát (a `WinVPN` érték a `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` alatt).
- A Windowsban a **Gépház → Alkalmazások → Indítás** alatt kikapcsolhatod. Ilyenkor a WinVPN kapcsolója ki van kapcsolva, alatta a megjegyzés: **Kikapcsolva: Gépház → Alkalmazások → Indítás.**, és az **Indítási alkalmazások beállításai…** gomb megnyitja ezt az oldalt. Ha a WinVPN-ben kapcsolod be az **Indítás bejelentkezéskor** kapcsolót, újra bekapcsolódik.
- Csak a telepített WinVPN jegyezhető be; fejlesztői buildben a kapcsoló nem kattintható.

### 2.2 Megjelenés

A **Beállítások → Megjelenés** pontban három lehetőség van: **Rendszer szerint** (alapértelmezés: a WinVPN a Windows alkalmazásmódját követi, Gépház → Személyre szabás → Színek, akkor is, ha futás közben váltasz), **Világos** és **Sötét**. A választás azonnal érvényes a popoverre és minden nyitott ablakra, a címsorokkal együtt, és minden később megnyíló ablakra; a WinVPN megjegyzi. A Windows saját párbeszédablakai (fájl kiválasztása, üzenetablakok, a rendszergazdai megerősítés) továbbra is a Windows módját követik, az értesítési terület ikonja pedig a tálca színét.

### 2.3 Értesítések

A WinVPN Windows-értesítéseket mutat, például ha kód kell, ha egy csapatkatalógus frissült (lásd [16.4](#164-frissítés-és-változások)), és a kapcsolatokról. Ezek a telepített WinVPN-nel működnek (a Start menü bejegyzése hordozza azt az azonosítót, amely a Windowsnak kell hozzájuk). A Gépház → Rendszer → Értesítések → **WinVPN** alatt kikapcsolhatod őket. Ha futó WinVPN mellett kattintasz egy értesítésre, megnyílik a hozzá tartozó ablak; kilépés után a kattintás csak elindítja a WinVPN-t. Értesítésben sosem jelenik meg jelszó, kulcs vagy a szerver hibaszövege.

**Kapcsolatértesítések.** A WinVPN jelzi, ha egy kapcsolat **csatlakozott** (**Office VPN: csatlakozva**), automatikusan **újracsatlakozott** (**Office VPN: újracsatlakozva**, lásd [5.5](#55-automatikus-újracsatlakozás)), úgy **szakadt meg**, hogy nem te bontottad (**Office VPN: megszakadt a kapcsolat**), **sikertelen** volt (**Office VPN: sikertelen csatlakozás**), **nem csatlakozott újra** / **nem sikerült újracsatlakozni**, vagy **nem válaszol** (**Office VPN: nem válaszol**, lásd [5.5](#55-automatikus-újracsatlakozás)). A cím alatt rövid, közérthető ok áll, a kapcsolat naplójának végéből (lásd [7.12](#712-az-értesítések-okai)); különben **Kattints a naplóért.** (sikertelen csatlakozásnál **Részletek a WinVPN-ben**). Kattintásra a kapcsolat **Napló** füle nyílik meg a Kapcsolatok ablakban.

- Csak a kapcsolatot nevezik meg, szervert, címet, felhasználónevet vagy hibaüzenetet soha (az értesítés a zárolási képernyőn is látszhat); zárolt széfnél még a kapcsolatot sem (**Egy VPN-kapcsolat megszakadt**, …).
- Az általad indított bontásról (a WinVPN-ből való kilépés, a kijelentkezés vagy egy párosított app elengedése miatt sem) sosem jön értesítés, és a WinVPN indulásakor már élő kapcsolatról sem.
- A **Beállítások → Kapcsolatértesítések** (alapból be) kikapcsolja őket; ami tőled kér valamit (kód, hitelesítő adatok), és a csapatkatalógusok értesítései megmaradnak.
- Értesítés csak a telepített (a Start menüből indított) WinVPN-től jön. Egy régi értesítésre kattintás, ha közben a WinVPN újraindult, vagy 32-nél több újabb érkezett, nem csinál semmit.

### 2.4 Hiányzó VPN-motorok

Ha egy kapcsolat motorja nem használható, a kapcsolat a listában marad, kiszürkítve, és a sora megmondja, miért: **Nincs telepítve: OpenVPN Community – Rendszerállapot**, ha az OpenVPN Community nincs telepítve, **Nem használható: OpenVPN Community – Rendszerállapot**, ha javítani vagy frissíteni kell, **Nem használható: WinVPN szolgáltatás – Rendszerállapot**, ha a WinVPN szolgáltatás nem tud kapcsolatot futtatni (ezt csak az OpenVPN- és WireGuard-kapcsolatok mutatják). A sorban a **Rendszerállapot** link, az ablakot nyitja meg, ahol a **Telepítés**, a **Javítás** vagy a **Frissítés** rendbe teszi. Ha egy típust vagy kapcsolatot a Windows más okból nem tud futtatni, a saját szövege látszik, link nélkül: például egy Cisco IPsec kapcsolatnál (lásd [3.4](#34-l2tpipsec-és-cisco-ipsec)), egy Windows által nem támogatott beállítást tartalmazó IKEv2 confignál (lásd [3.3](#33-ikev2-strongswan)), vagy SSTP-nél, amíg a Windows-szolgáltatása le van tiltva.

- A kapcsoló és a **Csatlakozás** gomb tiltott; a Kapcsolatok ablak **Új** menüje csak a használható típusokat kínálja (így Windowson a **Cisco IPsec**-et sosem).
- **Az import elutasítja az ilyen fájlt**, mielőtt bármit mentene, például: **office.ovpn: A(z) OpenVPN Community nincs telepítve. Előbb telepítsd a Rendszerállapot ablakban.**; ugyanannak az importnak a többi fájlja bekerül.
- **A csapatkatalógusok és a mentések megtartják a kapcsolataikat:** egy hiányzó típusú kapcsolat ugyanúgy kiszürkítve látszik, és a motor telepítése után működik.
- Ha az OpenVPN Communityt a WinVPN-en kívül telepítetted, nem kell **Újraellenőrzés**: amikor egy típus nem használható, és megnyitod a popovert vagy a Kapcsolatok ablakot, a WinVPN a háttérben újra ellenőriz (legfeljebb percenként egyszer).

### 2.5 Az OpenVPN és a WireGuard frissítése

Újabb VPN-motorhoz nem kell új WinVPN-kiadás. A **Rendszerállapot** megnyitáskor és az **Újraellenőrzés** gombra ellenőriz, a WinVPN pedig naponta egyszer a háttérben is, így az ajánlat az ablak megnyitása nélkül is megjelenik:

- **OpenVPN Community:** ha a wingetben vagy az OpenVPN hivatalos letöltési oldalán (`openvpn.net`) a telepítettnél újabb verzió van, a sor ezt írja: **Frissítés elérhető: 2.7.7 → 2.7.8**, és **Frissítés** gombot kínál. Ez egy rendszergazdai megerősítés után telepíti azt a verziót (wingettel, vagy az OpenVPN szervereiről letöltött hivatalos MSI-vel, amelynek **OpenVPN Inc.** aláíróját a WinVPN előbb ellenőrzi); a kimenet élőben látszik a sor alatt. Régebbi verziót a telepítettnél a WinVPN sosem kínál.
- **WireGuard (wireguard-nt):** a WinVPN szolgáltatás a `download.wireguard.com` oldalon keres újabb meghajtókönyvtárat. Ha van, a sor ezt írja: **Frissítés elérhető: 1.1.0 → 1.2.0**, és **Frissítés** gombot kínál. A szolgáltatás letölti, ellenőrzi az aláíróját (**WireGuard LLC**), a verzióját és a processzortípusát, és csak ezután használja (**A(z) 1.2.0 wireguard-nt telepítve.**); rendszergazdai megerősítés nem kell. Csak akkor frissíthető, ha ezen a gépen egyik felhasználónak sincs élő WireGuard-kapcsolata: **A wireguard-nt csak akkor frissíthető, ha ezen a gépen nincs élő WireGuard-kapcsolat. Bontsd a WireGuard-kapcsolatot, majd próbáld újra.**
- **A Windows VPN-kliensét** a Windows Update frissíti.
- Ha az ellenőrzés nem éri el az internetet, a sorok egyszerűen nem kínálnak semmit.

---

## 3. Kapcsolatok felvétele típusonként

Kapcsolatot a **Kapcsolatok** ablakban veszel fel. Megnyitása: popover → **Kapcsolatok kezelése…** vagy **Új kapcsolat / Import…**.

- Bal oldalt a lista: a kapcsolataid és a Windows VPN-jeid (rendszer VPN-ek, lásd [3.5](#35-rendszer-vpn-ek-a-saját-windows-vpn-jeid)) egy fában a mappáiddal együtt, minden mappában a kitűzöttek felül (lásd [5.1](#51-a-kapcsolatok-sorrendje) és [12.](#12-mappák-és-színek)). A lista alatt a **Hitelesítő adatok** (lásd [13.](#13-közös-hitelesítő-adatok)), a **Párosított appok** (lásd [5.4](#54-párosított-appok-vezérlő-api)), a **Csapatkatalógusok** és a **Közzététel** (lásd [16.](#16-csapatkatalógusok)) található.
- Az eszköztár **Új** (+) menüjéből választhatsz típust (OpenVPN, WireGuard, IKEv2, SSTP, L2TP; a **Cisco IPsec**-et Windowson nem kínálja), **Új mappa** vagy **Import fájlból…** pontot. Ugyanitt van a **Teljes biztonsági mentés…** és a **Visszaállítás biztonsági mentésből…** is (lásd [14.](#14-biztonsági-mentés-és-visszaállítás)). Az új kapcsolat sablonnal és „Új OpenVPN”-hez hasonló névvel indul; a névmezőben átnevezheted.
- A kijelölt kapcsolat fejlécében van a **Csatlakozás** / **Bontás**, a **Csatlakozás debug módban**, az export ikon és a törlés ikon (**Törlés**, megerősítéssel). Alatta két fül: **Beállítások** és **Napló**.

A szöveges típusoknál (OpenVPN, WireGuard, IKEv2) monospace szerkesztő van. A **Mentés** (Ctrl+S) előbb ellenőrzi a configot. Ha hibát talál, a szerkesztő alatt pirosan, sorszámmal sorolja fel őket (például `3. sor: Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort`), és a mentés nem történik meg. A kockázatos OpenVPN beállítások már gépelés közben megjelennek egy sárga panelen (lásd [3.1](#31-openvpn)). A jelszavak külön mezőkben vannak, a **Hitelesítés** részben. Ezek a WinVPN titkosított széfjébe kerülnek, nem a configba. Ahol a kapcsolat felhasználónévvel és jelszóval jelentkezik be, a **Jelszó forrása** választóval a **Saját felhasználónév és jelszó** és egy közös hitelesítő adat között választhatsz (lásd [13.](#13-közös-hitelesítő-adatok)).

Az SSTP-nek, az L2TP-nek és a Cisco IPsec-nek szöveges szerkesztő helyett űrlapja van.

**Amit a Windows nem tud, az látszik, nem rejtett.** Az a kapcsolat, amelynek a beállításait a Windows VPN-kliense nem tudja futtatni (Cisco IPsec kapcsolat, nem támogatott beállítást tartalmazó IKEv2 config, **Nincs ellenőrzés** módú SSTP), a listában kiszürkítve, az okkal együtt látszik, és a szerkesztője ugyanezt az okot sárga megjegyzésben mutatja az űrlap fölött. Ettől még szerkesztheted, mentheted, exportálhatod és mentheted biztonsági mentésbe: ugyanez a kapcsolat a MacVPN-ben működik.

**A mentett jelszavak sosem látszanak.** Ha egy jelszómezőnek van mentett értéke, a mezőben **Mentve – írj be újat a cseréhez** áll. Ha nem nyúlsz hozzá, a mentett érték marad; ha beírsz valamit, lecseréli; a **Mentett jelszó törlése** gombbal és mentéssel törölheted. A szerkesztő alatti állapotsor **Nem mentett változások** vagy **Mentve: <idő>** szöveget mutat.

Ha nem mentett változással váltasz kapcsolatot vagy zárod be az ablakot, az app rákérdez: **Mentés**, **Elvetés** vagy **Mégse**.

**Egy kapcsolat törlése** törli a configját és a mentett jelszavait, L2TP/IPsec, IKEv2 és SSTP esetén a Windows VPN-bejegyzését is (**A config és a mentett jelszavak törlődnek, és a Windows VPN-bejegyzése is.**). A Gépházban semmit nem kell kézzel törölni.

### 3.1 OpenVPN

A legegyszerűbb, ha a szolgáltatótól kapott `.ovpn` fájlt importálod (**Új → Import fájlból…**, vagy húzd a fájlt a listára). Az OpenVPN-kapcsolatokhoz OpenVPN Community kell (lásd [1.4](#14-openvpn-community)).

- Ha a `.ovpn` külső fájlokra hivatkozik (például `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), az import a `.ovpn` mellől beolvassa és beágyazza őket (`<ca>…</ca>` blokkokba). Ezért importálás előtt a fájlok legyenek a `.ovpn` mellett. Ha egy fájl hiányzik, az import hibát jelez.
- Ha a szerver felhasználónevet és jelszót kér (`auth-user-pass` sor), töltsd ki a **Felhasználónév** és **Jelszó** mezőket, vagy hagyd üresen őket: a WinVPN csatlakozáskor megkérdezi (lásd [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor)).
- Ha a privát kulcs jelszóval védett (jelszavas PKCS#12 fájl, vagy titkosított PEM kulcs), add meg a **Privát kulcs jelszava** mezőben. A széfbe kerül.
- A WinVPN a MacVPN-hez hasonlóan minden direktívát három szintbe sorol (a teljes lista: [openvpn-directives.md](openvpn-directives.md), angolul, magyar összefoglalóval):
  - Az **engedett** direktívák a megszokott módon működnek.
  - A **kockázatos beállítások** (például `user nobody`, szerveroldali opciók, és minden direktíva, amelyet a WinVPN nem ismer) egy sárga **Kockázatos beállítások** panelen jelennek meg, mindegyik rövid indoklással. Mentéshez jelöld be: **Tudomásul veszem a beállításokat és a biztonsági kockázatokat**. A tudomásulvétel pontosan a mentéskor jelen lévő kockázatos direktívákra szól: ha később újat adsz hozzá, újra be kell jelölnöd.
  - A **tiltott** direktívák, például `up`, `down`, `script-security`, `plugin`, `log`, `chroot` és `echo`, sosem engedettek (külső scriptet futtatnának, kódot töltenének be, vagy a VPN jogaival olvasnának, illetve írnának fájlt). Windowson ezenfelül azok az opciók, amelyeket a WinVPN szolgáltatás maga állít be (`win-sys`, `service`, `msg-channel`, `allow-nonadmin`, `rdns-internal`, `dhcp-internal`), a `windows-driver` (az illesztőprogramot a WinVPN választja, lásd [1.4](#14-openvpn-community)) és a **`cryptoapicert`**: az `openvpn.exe` rendszerként fut, így a tanúsítványválasztó a számítógép tanúsítványtárát érné el, nem a tiédet. Helyette a tanúsítvány és a kulcs legyen a configban (vagy egy PKCS#12 fájlban). Lásd [3.9](#39-hibák-mentéskor).
- Az engedélyezett direktívák argumentumait is ellenőrzi: például a port és az időzítők számok, a hosztnév és a titkosító neve nem tartalmazhat `/` jelet, és nem kezdődhet `-` jellel. A `<connection>` blokkok használhatók, a soraik ugyanezen az ellenőrzésen mennek át.
- **Egy sor legfeljebb 255 bájt** (a beágyazott blokkokban, például a `<ca>`-ban is), mert az OpenVPN 256 bájtos darabokban olvassa a sorokat; a hosszabb sor hibája: **Túl hosszú sor**. A 16-nál több szóból álló sor hibája: **Hibás argumentumszám**.
- **A `setenv` Windowson** csak azokat a neveket fogadja el, amelyeket maga az OpenVPN olvas (`FORWARD_COMPATIBLE`, `PUSH_PEER_INFO`, `SERVER_POLL_TIMEOUT`, `REMOTE_RANDOM_HOSTNAME`, `CLIENT_CERT`, `CONFIG_VERSION`), valamint az `UV_` vagy `IV_` kezdetű peer-info neveket; minden más név hibája: **Nem engedélyezett setenv**. Az OpenVPN ezeket a változókat átadja a rendszerként futtatott Windows-programoknak, így például egy `SystemRoot` név megváltoztathatná, mit töltenek be. A `setenv opt <direktíva>` sort a WinVPN úgy ellenőrzi, mint magát a direktívát, egyszer.

### 3.2 WireGuard

Importáld a `.conf` fájlt, vagy hozz létre újat (**Új → WireGuard**), és töltsd ki a sablont (`[Interface]` a `PrivateKey`, `Address`, `DNS` sorral; `[Peer]` a `PublicKey`, `AllowedIPs`, `Endpoint` sorral).

- A `PreUp`, `PostUp`, `PreDown`, `PostDown` és `SaveConfig` kulcs nem engedett.
- Az értékeket is ellenőrzi: a kulcsok 44 karakteres base64 szövegek, az `Address`/`AllowedIPs` IP-címek opcionális prefixszel (`10.0.0.2/32`), az `Endpoint` `hoszt:port` vagy `[IPv6]:port`, az `MTU`/`ListenPort`/`PersistentKeepalive` számok. Egyik érték sem kezdődhet `-` jellel.
- Windowson az `FwMark` és a `Table` csak `auto` vagy `off` lehet (`Table = off`: nem kerül fel útvonal); más értéket a mentés elutasít.

### 3.3 IKEv2 (strongSwan)

Az IKEv2 configot a MacVPN-hez hasonlóan strongSwan `swanctl.conf` szintaxisban kell megadni, így ugyanaz a kapcsolat mindkét rendszeren működik. Új kapcsolatnál (**Új → IKEv2**) egy sablon jelenik meg.

- A **Felhasználónév** mező értéke egyezzen az `eap_id`-val, a jelszót a **Jelszó** mezőbe írd. Ezek a széfbe kerülnek, nem a configba.
- Az `include`, az `updown` és a fájlra hivatkozó `secrets` (`file = …`) nem engedett. Csak a dokumentált `swanctl.conf` kulcsok fogadhatók el, mindegyik a saját szakaszában; a `certs`, `cacerts`, `cacert` és `pubkeys` értéke csak sima fájlnév lehet.

**Windowson** a WinVPN a config első kapcsolatát és annak első gyerekét a Windows IKEv2-kliensének egy bejegyzésévé fordítja. A szerkesztő alatt egy szürke sor mutatja, mit használ majd a Windows, például: **Windowson: EAP-MSCHAPv2 · AES-256, SHA-256, DH-csoport 14; ESP AES-256, SHA-256 · osztott alagút** (vagy **számítógép-tanúsítvány**, **minden forgalom**).

- **Bejelentkezés:** `local { auth = eap-mschapv2 }` (vagy `eap` egy `eap_id`-val) és `remote { auth = pubkey }`, vagy **számítógép-tanúsítvány** (`local { auth = pubkey }`). A configban megnevezett tanúsítványfájlokat a Windows nem használja: a kliens-tanúsítványt a számítógép **Személyes** tárolójából veszi, ahová egy rendszergazda importálja (lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)). Ha nincs ott: **Nem található számítógép-tanúsítvány az IKEv2-höz. Egy rendszergazdának kell importálnia (lásd a felhasználói útmutatót).**
- **Előre megosztott kulcs nincs:** a `local { auth = psk }` confignál ez áll: **Windowson nem támogatott: local auth = psk (a Windows IKEv2-kliense nem tud előre megosztott kulccsal hitelesíteni; használj EAP-MSCHAPv2-t vagy számítógép-tanúsítványt)**. Kérj EAP-hozzáférést a VPN-rendszergazdától, vagy használd a PSK-t L2TP/IPsec-kel.
- **A szerver tanúsítványát** a Windows a számítógép **Megbízható legfelső szintű hitelesítésszolgáltatói** alapján ellenőrzi, és a nevének egyeznie kell a `remote_addrs` címével. Egy céges CA-t előbb ott megbízhatóvá kell tenni: **A CA megbízhatóvá tétele a Windowsban…** a szerkesztő alatt, a CA PEM-fájljával (lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)). Ha a `remote { id = … }` eltér a címtől: **Windowson a szerver azonosítójának a címének kell lennie: a remote_addrs értéke a szervertanúsítványban szereplő név legyen.**
- **Útvonalak:** a `remote_ts = 0.0.0.0/0` (vagy hiányzó `remote_ts`) minden forgalmat a VPN-re küld; a többi `remote_ts` hálózatból útvonal lesz (osztott alagút).
- **Javaslatok (proposals):** a Windows egy IKE- és egy ESP-javaslatot használ: a `proposals` / `esp_proposals` első olyan elemét, amelyet ismer, különben: **A Windows ezen IKE-javaslatok egyikét sem támogatja: … A Windows ezeket kínálja: …**. `proposals` nélkül a WinVPN IKE-hez AES-256, SHA-256 és 14-es DH-csoport, ESP-hez AES-256, SHA-256 beállítást használ.
- **Windowson figyelmen kívül marad** (szürke megjegyzés, a kapcsolat működik): a `dpd_action = restart` (**Windowson figyelmen kívül marad: dpd_action = restart (a megszakadt kapcsolatot a Windows maga hívja újra)**) és a `start_action` (a kapcsolat akkor indul, amikor csatlakozol).
- **Windowson nem támogatott** (a kapcsolat szürke, a pontos kulccsal és értékkel, például **Windowson nem támogatott: local auth = eap-tls**): EAP-TLS, EAP-MD5, EAP-GTC, EAP-RADIUS, XAUTH, IKEv1 (`version = 1`), egynél több hitelesítési kör, 500-tól eltérő `remote_port`, rögzített virtuális IP a `vips`-ben, protokollt vagy portot tartalmazó forgalomválasztó, `::/0` `0.0.0.0/0` nélkül, hiányzó `remote_addrs`.

### 3.4 L2TP/IPsec és Cisco IPsec

Az L2TP/IPsec beállítása űrlapon történik (**Új → L2TP**): **Név**, **Szerver**, **Fióknév**, **Jelszó**, **Pre-shared key (PSK)** és **Minden forgalom a VPN-en keresztül**.

- A **Mentés** elmenti a kapcsolatot (a jelszó és a PSK a széfbe kerül), és azonnal megírja a Windows VPN-bejegyzését: nincs mit jóváhagyni (**Mentéskor a kapcsolat Windows VPN-bejegyzése azonnal elkészül, nincs mit jóváhagyni. A jelszó nincs benne: a WinVPN csatlakozáskor adja át.**). A bejegyzés a WinVPN sajátja, és nem jelenik meg a Gépház → VPN listában (lásd [3.8](#38-hol-tárolja-a-winvpn-a-natív-vpn-eket)).
- **NAT mögött:** a Windows nem enged L2TP/IPsec kapcsolatot NAT-router mögötti szerverhez, amíg egy rendszergazda egyszer nem engedélyezi. Ilyenkor a hibaüzenet felkínálja: **L2TP engedélyezése NAT mögött…** (lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)).
- A szervernek MS-CHAPv2 bejelentkezést és előre megosztott kulcsot kell elfogadnia (mint a MacVPN-ben; tanúsítványos L2TP nincs).

**A Cisco IPsec Windowson.** A Windowsban nincs Cisco IPsec (IKEv1 XAUTH-tal) kliens, és nincs olyan karbantartott, aláírt kliens sem, amelyet a WinVPN telepíthetne. Ezért egy Cisco IPsec kapcsolat (MacVPN-mentésből, MacVPN-export importjából vagy csapatkatalógusból) Windowson megmarad: szerkesztheted, exportálhatod, mentheted és megoszthatod, és Macen működik. Itt viszont nem csatlakozik: a kártyája szürke, ezzel a szöveggel: **A Windows nem támogatja a Cisco IPsec-et. Kérj L2TP/IPsec vagy IKEv2 hozzáférést a VPN-rendszergazdádtól, vagy készíts L2TP/IPsec másolatot erről a kapcsolatról.**, és az **Új** menü nem kínál Cisco IPsec-et.

- A Cisco szerkesztőjében az **L2TP/IPsec másolat készítése** egy új L2TP/IPsec kapcsolatot készít „<név> (L2TP)” néven ugyanabba a mappába, ugyanazzal a szerverrel, fióknévvel, jelszóval és PSK-val (vagy ugyanazzal a közös hitelesítő adattal), a **Minden forgalom a VPN-en keresztül** beállítással; a csoportnév kimarad. A Cisco kapcsolat változatlan marad. A másolat akkor működik, ha a szerver ugyanazzal a PSK-val L2TP/IPsec-et is kínál: kérdezd a VPN-rendszergazdát.

### 3.5 Rendszer VPN-ek: a saját Windows VPN-jeid

A Windowsban beállított VPN-ek (Gépház → Hálózat és internet → VPN, a saját felhasználódnak vagy a gép minden felhasználójának) a WinVPN-ben **Rendszer-VPN**-ként jelennek meg, a típusukkal (**L2TP**, **IKEv2**, **SSTP** vagy **VPN**) és élő állapotukkal. A Gépházban felvett vagy törölt VPN másodperceken belül megjelenik vagy eltűnik. Ha egy listázott VPN-t törölnek, miközben nézed, a részleteinél ez áll: **Ezt a VPN-t eltávolították a Windowsból**.

- **Csatlakozás / bontás** a popoverből vagy a Kapcsolatok ablakból, mint bármely más kapcsolatnál. A beállításaik a Windowsban maradnak: **Ezt a kapcsolatot csak indítani és bontani lehet innen. A beállításai a Gépházban vagy a saját alkalmazásában vannak.** A WinVPN sosem szerkeszti, nevezi át vagy törli őket.
- **Titkok:** egy L2TP rendszer VPN-hez **jelszót** és **előre megosztott kulcsot (PSK)** tárolhatsz a WinVPN széfjében (a részletező nézetében a Kapcsolatok ablakban; a **Mentett titkok törlése** eltávolítja őket). A jelszót a WinVPN csatlakozáskor adja át, azzal a felhasználónévvel, amelyet a Windows a VPN-hez elmentett. A PSK: **A Windows a saját PSK-ját használja ehhez a VPN-hez, ha van neki; ha nincs, a WinVPN ezt tárolja el ott.** Ez az egyetlen változtatás, amelyet a WinVPN valaha a saját VPN-eden végez, és csak miután PSK-t mentettél hozzá.
- **Tárolt titkok nélkül** a WinVPN a Windows által a VPN-hez mentett felhasználónevet és jelszót használja; ha a Windowsnak nincs ilyen, a Windows saját bejelentkező ablaka nyílik meg.
- **Egyszer használatos kód:** egy L2TP rendszer VPN kérhet kódot, és a jelszó végére fűzheti (lásd [5.2](#52-többfaktoros-hitelesítés-mfa)).
- A rendszer VPN-ek a kapcsolataidhoz hasonlóan mappába tehetők, kitűzhetők és színezhetők.

### 3.6 SSTP

Létrehozás: **Új → SSTP**, vagy importálj egy `.sstp` fájlt. Űrlapja van: **Név**, **Szerver** (hosztnév vagy IP-cím, port nélkül), **Port** (alapból 443), **Felhasználónév** és **Jelszó**, a **Szervertanúsítvány** módja, **Minden forgalom a VPN-en keresztül** és **A szerver DNS-ének használata**.

- **Rendszer CA:** a Windows a szerver tanúsítványát a számítógép megbízható legfelső szintű hitelesítésszolgáltatói alapján ellenőrzi (a MacVPN-nel ellentétben, amely a Homebrew OpenSSL tárolóját használja). Nyilvános tanúsítvány azonnal működik.
- **Saját CA fájl** (**PEM fájl kiválasztása…**): a CA-ban a Windowsnak is meg kell bíznia, mert a Windows SSTP-kliense csak a számítógép tárolóját használja. Az űrlap alatti **A CA megbízhatóvá tétele a Windowsban…** ezt egyszer elvégzi, egy rendszergazda megerősítésével (lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)); utána az űrlapon ez áll: **A Windows megbízik benne**. Addig a csatlakozás ezzel bukik el: **A szerver hitelesítésszolgáltatójában (CA) a Windows nem bízik meg. Használd a szerkesztőben „A CA megbízhatóvá tétele a Windowsban…” lehetőséget.**
- A **Nincs ellenőrzés** Windowson nem választható (tiltva látszik): **A Windows mindig ellenőrzi az SSTP-szerver tanúsítványát. Válaszd a Rendszer CA vagy a Saját CA fájl lehetőséget.** A `cert=insecure` beállítású importált kapcsolat ezzel az okkal szürke.
- A Windows azt is ellenőrzi, hogy a szerver tanúsítványát nem vonták-e vissza: a szerver visszavonási listájának (CRL) elérhetőnek kell lennie.
- **A szerver DNS-ének használata** kikapcsolva Windowson a lehetőségekhez mérten működik: a WinVPN alacsony prioritást ad a VPN-adapternek, így előbb a saját hálózatod DNS-szerverei kapják a kérdést.
- `DOMAIN\user` helyett `user@domain` formát használj: a felhasználónévben nem lehet fordított perjel, szóköz és idézőjel. A jelszóban nem lehet idézőjel (`"`), fordított perjel (`\`) és vezérlőkarakter.
- A szervernek MS-CHAPv2-t kell elfogadnia.

A config (és a `.sstp` export) egyszerű `kulcs=érték` szöveg, jelszó nélkül, például `server=vpn.example.com`, `port=443`, `user=kovacs.janos@ceg.example`, `cert=system`, `route_all=yes`, `peer_dns=yes`.

### 3.7 Rendszergazdai lépések a natív VPN-ekhez

Néhány dolgot Windowson csak rendszergazda módosíthat. A WinVPN ezeket sosem végzi a háttérben (és sosem a WinVPN szolgáltatáson keresztül): mindegyik egy gomb, amely előbb megmutatja, mi fog történni, aztán egy rendszergazda megerősítését (UAC) kéri. Az elutasítás válasza: **Megszakítva**.

- **A CA megbízhatóvá tétele a Windowsban…** (SSTP **Saját CA fájl**-lal, IKEv2): előbb egy megerősítés megnevezi a CA-t (**Tulajdonos: …**, **Érvényes: … – …**, **SHA-256 ujjlenyomat: …**), és figyelmeztet: **A számítógép minden programja meg fog bízni az ettől a CA-tól származó szerver- és klienstanúsítványokban (az általa aláírt szoftverekben nem).** A **Megbízom benne** gombra csak a szervezeted VPN-CA-jánál kattints. Utána a WinVPN (a rendszergazda jóváhagyása után) felveszi a számítógép Megbízható legfelső szintű hitelesítésszolgáltatói közé, csak szerver- és klienshitelesítésre, kódaláírásra soha, és ellenőrzi (**A Windows mostantól megbízik a CA-ban.**). Ehhez a Program Files mappába telepített WinVPN kell. A nem CA- vagy lejárt tanúsítványt elutasítja. Későbbi eltávolítás: `certlm.msc` → Megbízható legfelső szintű hitelesítésszolgáltatók → Tanúsítványok → törlés.
- **L2TP engedélyezése NAT mögött…** (egy választ nem kapott L2TP/IPsec kapcsolat hibájában, 809-es Windows-hiba): a Windows `reg.exe` programjával beállítja az `AssumeUDPEncapsulationContextOnSendRule` értéket (2) a `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent` alatt, majd ezt írja: **Az L2TP/IPsec NAT mögött engedélyezve. Az érvényesítéshez indítsd újra a Windowst.** A gép minden L2TP/IPsec VPN-jére érvényes.
- **Számítógép-tanúsítvány az IKEv2-höz:** egy rendszergazda a Windows saját eszközével importálja (a tanúsítvány jelszavához a WinVPN sosem nyúl): `certlm.msc` → **Személyes** → **Tanúsítványok** → jobb kattintás → **Minden feladat** → **Importálás…**, válaszd ki a `.p12` / `.pfx` fájlt, add meg a jelszavát, a tároló maradjon **Személyes**, befejezés. A tanúsítvány kiadó CA-jának a **Megbízható legfelső szintű hitelesítésszolgáltatók** között is ott kell lennie.

### 3.8 Hol tárolja a WinVPN a natív VPN-eket

- A WinVPN az L2TP/IPsec, IKEv2 és SSTP kapcsolatai Windows VPN-bejegyzéseit a **saját telefonkönyvébe** írja (`%LOCALAPPDATA%\WinVPN\ras\WinVPN.pbk`), sosem a Windows telefonkönyveibe. Ezért nem jelennek meg a Gépház → VPN alatt, és csak a WinVPN-ben építhetők fel (popover, Kapcsolatok ablak, párosított appok).
- Minden bejegyzés neve `WinVPN-<a kapcsolat azonosítója>`. Az `ipconfig` egy élő kapcsolatot **PPP adapter WinVPN-…** néven mutat.
- Az L2TP-bejegyzés mentéskor, az IKEv2- és SSTP-bejegyzés minden csatlakozáskor íródik (az aktuális configból). Egy kapcsolat törlése törli a bejegyzését; a széf feloldása után a WinVPN azokat a bejegyzéseket is törli, amelyeknek már nincs kapcsolatuk.
- **Titkok:** a jelszót (az egyszer használatos kóddal) a WinVPN csak a tárcsázás pillanatában adja át a Windowsnak; a Windowsban sosem tárolódik. Az **előre megosztott kulcsnak** nincs ilyen mezője: a WinVPN minden csatlakozás előtt beírja a Windows titkosított VPN-hitelesítőadat-tárolójába, csak ehhez az egy bejegyzéshez (a széfből, így a módosított PSK azonnal érvényes), és a bejegyzés törlésekor eltávolítja. Egyik sem kerül soha a telefonkönyv-fájlba vagy naplóba.

### 3.9 Hibák mentéskor

A **Mentés** például ezeket a hibákat adhatja:

- `3. sor: Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort`
- `5. sor: Kockázatos direktíva, tudomásulvétel szükséges: user` (a beállítás a sárga **Kockázatos beállítások** panelen látszik)
- `7. sor: Külső fájl hivatkozás, inline blokk kell: ca`
- WireGuard: `4. sor: Tiltott kulcs: postup`; IKEv2: `2. sor: Tiltott: include`
- Argumentumok: `4. sor: Érvénytelen argumentum: dev`, `8. sor: Hibás argumentumszám: keepalive`
- OpenVPN: `12. sor: Túl hosszú sor`, `9. sor: Nem engedélyezett setenv: SystemRoot – töröld vagy tedd megjegyzésbe (#) a sort`

Javítás: lásd [7.7](#77-nem-engedélyezett-direktíva--tiltott-direktíva). Egy IKEv2- vagy SSTP-kapcsolat windowsos korlátja nem mentési hiba: a kapcsolat mentődik, és szürkén, az okkal együtt látszik (lásd [3.](#3-kapcsolatok-felvétele-típusonként)).

---

## 4. Import és export

**Import.** **Új → Import fájlból…** (több fájlt is kijelölhetsz), vagy húzz egy vagy több fájlt a Kapcsolatok ablakba. Minden fájl legfeljebb 1 MB-os, szabályos UTF-8 szövegfájl legyen. A típust a kiterjesztés és a tartalom alapján ismeri fel:

- `.ovpn`, vagy `client` / `dev tun` + `remote` sor → OpenVPN
- `[Interface]` + `PrivateKey` → WireGuard
- `connections {` → IKEv2 (strongSwan)
- `.sstp`, vagy `server=…` sor + `user=`, `cert=`, `route_all=` vagy `peer_dns=` sor → SSTP

Ha egy fájl nem ismerhető fel vagy nem importálható, a többi fájl attól még importálódik. A hibákat egy közös ablak sorolja fel. A `.mobileconfig` profil (a MacVPN L2TP- vagy Cisco IPsec-exportja) nem importálható: **A .mobileconfig profil nem importálható a WinVPN-be. Hozd létre a kapcsolatot az Új → L2TP menüponttal, vagy állíts vissza egy mentést, amelyben benne van.**

**Más fájlokra hivatkozó OpenVPN configok** (`ca ca.crt`, `tls-auth ta.key 1`, …): a WinVPN a hivatkozott fájlokat inline blokként beemeli a configba, és az import után felsorolja őket, például **Importálva, beemelt fájlok: ca.crt, ta.key**. Biztonsági okból a hivatkozott fájlt csak akkor olvassa be, ha:

- az `.ovpn` fájl mappájában (vagy annak almappájában) van. A `..\` útvonalakat, a mappán kívüli útvonalakat, a hálózati útvonalakat (`\\szerver\megosztás\…`) és a mappán kívülre mutató linkeket elutasítja: **A hivatkozott fájl a config mappáján kívül van**; a kettőspontot tartalmazó nevet (alternatív adatfolyamot, például `ca.crt:hidden`) hiányzó fájlként utasítja el;
- legfeljebb 1 MB;
- a tartalma megfelel a direktívának: `ca`, `cert`, `extra-certs` → PEM tanúsítvány; `key` → PEM privát kulcs; `tls-auth`, `tls-crypt`, `secret` → OpenVPN statikus kulcs; `tls-crypt-v2` → tls-crypt-v2 kliens kulcs; `dh` → DH paraméterek. Különben: **A(z) … direktíva fájlja (…) nem a várt formátumú**.

A OneDrive-mappában lévő, csak online elérhető fájlt a WinVPN olvasáskor letölti. A `pkcs12 client.p12` fájlt ugyanígy beemeli, base64-ként egy `<pkcs12>` blokkba. Az `auth-user-pass` mellett megadott felhasználónév/jelszó fájl (például `auth-user-pass auth.cfg`) sosem kerül a configba: ha a mappán belül van, legfeljebb 1 KB, és pontosan két sora van, a WinVPN megkérdezi: **Használod a(z) … fájlban lévő hitelesítő adatokat ehhez a kapcsolathoz?**; **Használat** esetén a kapcsolat **Felhasználónév** és **Jelszó** mezőjébe (a széfbe) teszi. Az `askpass pass.txt` fájlt ugyanígy a **Privát kulcs jelszava** mezőbe teszi.

**Az importált config ellenőrzése.** Az importált configot a WinVPN rögtön ugyanazokkal a szabályokkal ellenőrzi, mint a **Mentés**. Ha hibás, attól még importálódik, és a szerkesztője pirossal jelölt hibalistával nyílik meg. Ha kockázatos beállítást tartalmaz, az import üzenete jelzi, a szerkesztő pedig a sárga **Kockázatos beállítások** panelen mutatja. A Windows által nem támogatott beállítást tartalmazó IKEv2- vagy SSTP-config importálódik, és az okkal együtt szürkén látszik (lásd [3.3](#33-ikev2-strongswan), [3.6](#36-sstp)).

**Export.** A kapcsolat fejlécében az export ikon (**Exportálás… (jelszavak sosem kerülnek bele)**) az eredeti formátumban menti ki a configot: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, `.sstp`, L2TP és Cisco IPsec kapcsolatnál `.mobileconfig`.

- A jelszó, a PSK és a felhasználónév **nem** kerül az exportba. Az SSTP felhasználónév a config része, ezért benne van a `.sstp` exportban; a jelszó nincs.
- **Privát kulcsok:** ha a config része egy privát kulcs (OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<pkcs12>`, `<auth-user-pass>` vagy `<http-proxy-user-pass>` blokk, WireGuard `PrivateKey` / `PresharedKey`, strongSwan `secrets` szakasz), a WinVPN figyelmeztet (**A config privát kulcsokat vagy hitelesítő adatokat tartalmaz**), és három lehetőséget ad: **Exportálás kulcsok nélkül** (alapértelmezett), **Exportálás kulcsokkal**, vagy **Mégse**. Aki a kulcsokat birtokolja, a te nevedben csatlakozhat.
- Az exportált fájlt csak te (és a SYSTEM) olvashatod.
- **Mappa és közös hitelesítő adat.** Ha a kapcsolat mappában van, vagy közös hitelesítő adatot használ, a szöveges export egy megjegyzéssorral kezdődik, például `# macvpn-meta: {"folder":["Munka","Ügyfelek"],"credentialName":"Iroda AD"}`. Ebben csak ezek a nevek vannak, titok soha. Importáláskor a WinVPN létrehozza a hiányzó mappákat, és oda teszi a kapcsolatot. A `credentialName` sosem kapcsolódik csendben: a WinVPN előbb rákérdez, és megnevezi a szervert (lásd [13.4](#134-import-és-export)).
- Ezek az exportok visszaimportálhatók a WinVPN-be és a MacVPN-be. Az L2TP- vagy Cisco IPsec-kapcsolat `.mobileconfig` exportja macOS-profil: Macen dupla kattintásra ott telepíti a VPN-t; a Windows nem tudja használni, és windowsos exportformátum nincs. Egy L2TP-kapcsolatot teljes biztonsági mentéssel (lásd [14.](#14-biztonsági-mentés-és-visszaállítás)) vagy csapatkatalógussal vihetsz át másik számítógépre.

### 4.1 VPN-fájlok megnyitása a Fájlkezelőből

Kattints duplán egy `.ovpn` vagy `.sstp` fájlra a Fájlkezelőben: a WinVPN megnyitja a **Kapcsolatok** ablakot, és importálja a fájlt. Ez ugyanaz az import, mint az **Import fájlból…**: ugyanazok az ellenőrzések, ugyanazok a kérdések és ugyanaz az összesítő. Semmi nem csatlakozik. Ha a WinVPN nem fut, a dupla kattintás elindítja; ha fut, a futó WinVPN kapja meg a fájlt.

- **Mely fájlok nyílnak a WinVPN-ben.** A telepítő a WinVPN-t teszi alapértelmezett alkalmazássá a `.ovpn` és a `.sstp` fájlokhoz, valamint a `.macvpncatalog` fájlokhoz, amelyek a csapatkatalógus párbeszédablakát nyitják meg (lásd [16.1](#161-feliratkozás-egy-katalógusra)).
- **A `.conf` fájlokat nem veszi át**, mert ezt a kiterjesztést a WireGuard és sok más program is használja. WireGuard vagy strongSwan `.conf` fájlnál kattints rá jobb gombbal, és válaszd a **Társítás → WinVPN** lehetőséget.
- **Egy másik VPN-app nyitja meg a `.ovpn` fájlokat:** kattints jobb gombbal egy `.ovpn` fájlra → **Társítás** → **Másik alkalmazás választása**, válaszd a **WinVPN**-t, majd a **Mindig** gombot.
- **Nem a Fájlkezelőből nyílik:** az adminisztrátori kulcsfájl (`.macvpnadminkey`) és a biztonsági mentés (`.macvpnbackup`). Ezekhez a WinVPN saját gombjait használd. Ha mégis a WinVPN-nel nyitod meg, az összesítő ezt írja: **Ezt a fájlt a WinVPN saját paneljén kell megnyitni, nem a Fájlkezelőből.**
- **A letöltött fájlokra előbb rákérdez.** Az internetről letöltött fájlt a Windows megjelöli (a „Mark of the Web” jelöléssel). Az ilyen fájlt a WinVPN nem importálja azonnal: egyszer, az összesre együtt rákérdez – **Importálod a letöltött fájlt?** vagy **Importálod a(z) N letöltött fájlt?** –, felsorolja a fájlokat, és hozzáteszi: **Csak olyan fájlt importálj, amelyben megbízol.** Az **Importálás** importálja őket, a **Mégse** kihagyja őket. A nem letöltött fájlok mindkét esetben importálódnak. A WinVPN a jelölést csak olvassa, nem törli.
- **A széf zárolva van, vagy még nincs beállítva:** a WinVPN előbb a feloldó (vagy beállító) ablakot mutatja, és a széf megnyitása után importálja a fájlokat. Ha ehelyett bezárod az ablakot, semmi nem importálódik.
- A megnyitott fájl nem megbízható bemenet, pont úgy, mint egy ablakba húzott fájl: csak akkor importálódik, ha átmegy az ellenőrzéseken.

---

## 5. Csatlakozás

- **A popoverből:** kattints a kapcsolat kártyáján a kapcsolóra. Az állapotot a típusbuborék jelvénye és a név alatti sor mutatja:
  - **zöld:** kapcsolódva (mellette az IP és az eltelt idő); a kapcsoló is zöld. Alatta a kapcsolódás óta letöltött és feltöltött adat és az aktuális sebesség: **↓ 12,4 MB  ↑ 1,2 MB · ↓ 350 kB/s  ↑ 20,0 kB/s** (↓ letöltés, ↑ feltöltés; 1 kB = 1000 bájt, ezért a számok kicsit nagyobbak lehetnek a Fájlkezelő KB-jánál). Ugyanez a sor a Kapcsolatok ablakban is ott van a kapcsolat neve alatt, és egy rendszer VPN részleteiben is. Másodpercenként frissül, amíg a tálcamenü vagy az ablak nyitva van. Újracsatlakozáskor (automatikusan vagy az OpenVPN sajátjánál) az összeg megmarad; a kapcsolóval újra csatlakozva nulláról indul. Minden típusnál látszik; az L2TP/IPsec kapcsolatok és a rendszer VPN-ek az IP-címüket is mutatják.
  - **borostyánsárga, lüktet:** **Csatlakozás…** vagy **Bontás…** (a kapcsoló borostyánsárga), illetve **Hitelesítésre vár**: egyszer használatos kódra, böngészős bejelentkezésre vagy hiányzó hitelesítő adatokra (lásd [5.2](#52-többfaktoros-hitelesítés-mfa) és [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor))
  - **piros:** hiba (mellette a rövid ok)
  - **szürke:** nincs kapcsolat
  - **Használja: …** a kártyán: egy párosított app tartja fenn a kapcsolatot (lásd [5.4](#54-párosított-appok-vezérlő-api))
- **A Kapcsolatok ablakból:** **Csatlakozás** / **Bontás** gomb.
- **Melyik típus hogyan csatlakozik:** az OpenVPN és a WireGuard a WinVPN szolgáltatáson keresztül (lásd [1.3](#13-a-winvpn-szolgáltatás)); az L2TP/IPsec, az IKEv2 és az SSTP a Windows VPN-kliensével, amelyet a WinVPN a saját felhasználói fiókodban tárcsáz; a rendszer VPN-ek is (lásd [3.5](#35-rendszer-vpn-ek-a-saját-windows-vpn-jeid)).
- Egyszerre több kapcsolat is aktív lehet, bármilyen típusból.
- Ha egy típushoz hiányzik a motor, a kapcsolat kiszürkül, és a **Nincs telepítve: … – Rendszerállapot** felirat jelenik meg rajta (lásd [2.4](#24-hiányzó-vpn-motorok)).
- **Értesítések** jönnek, ha egy kapcsolat csatlakozott, megszakadt, újracsatlakozott vagy sikertelen, és ha kódra vagy bejelentkezésre vár („…: hitelesítés szükséges”; kattintásra előjön a kódbekérő ablak): lásd [2.3](#23-értesítések). Alvás vagy a hálózat elvesztése után a WinVPN magától is újra felépítheti a kapcsolatot: lásd [5.5](#55-automatikus-újracsatlakozás).

### 5.1 A kapcsolatok sorrendje

A popover és a **Kapcsolatok** ablak listája ugyanazt a sorrendet használja. A WinVPN-ben létrehozott kapcsolatok és a rendszer VPN-ek közös rangsorban vannak. Mappák esetén ugyanezek a szabályok érvényesek minden mappán belül, az almappák után (lásd [12.3](#123-sorrend-egy-mappán-belül)).

- **Elöl a kitűzött kapcsolatok**, a te sorrendedben. Kitűzéshez kattints jobb gombbal a kapcsolatra a **Kapcsolatok** ablakban, és válaszd a **Kitűzés** pontot; levenni a **Kitűzés megszüntetése** ponttal lehet. Ha egy kitűzött kapcsolatot ugyanannak a mappának egy másik kitűzött kapcsolatára húzol, a sorrendjük megváltozik.
- **Utánuk a többi, a leggyakrabban használt elöl.** Minden sikeres, a WinVPN-ből indított csatlakozás 1 pontot ér, és a pontok értéke 14 naponta a felére csökken. A WinVPN-en kívül (például a Gépházban) indított kapcsolatok nem számítanak. Az azonos pontszámú kapcsolatok (például az új, még pont nélküliek) név szerint követik egymást.
- A sorrend a széfben tárolódik. Az egyes kapcsolatok exportja nem viszi, a teljes biztonsági mentés igen.

### 5.2 Többfaktoros hitelesítés (MFA)

A WinVPN a MacVPN-nel azonosan kezeli az egyszer használatos kódokat (OTP, TOTP, token PIN) és a böngészős bejelentkezést (SAML / SSO, push jóváhagyás). A kód soha nem tárolódik, és nem kerül a naplóba.

**A kódbekérő ablak.** Ha kód kell, egy kis ablak nyílik meg a kapcsolat nevével, a szerver (vagy a config) kérdésével, egy **Kód** mezővel, **Mégse** és **Tovább** gombbal. A mező elrejti a beírt kódot, hacsak a szerver nem kéri a megjelenítését. Az ablak 2 perc után lejár, ilyenkor a csatlakozás **A hitelesítés nem fejeződött be időben** hibával ér véget. Amíg a WinVPN vár, a kapcsolat sorában **Hitelesítésre vár** áll, és az értesítési terület ikonja kulcs lesz. Az ablak nem veszi el a billentyűzetet attól az apptól, amelyikben éppen dolgozol: értesítés is jön („…: hitelesítés szükséges”); a kód beírásához kattints az értesítésre vagy az ablakra. A szervertől jövő szöveg **A VPN-szerver üzenete:** címkét kap. A megjelenés utáni kb. egy másodpercben az ablak nem fogad bevitelt, így egy véletlen leütés nem válaszol rá. Bontáskor az ablak bezárul, és a csatlakozás leáll.

**OpenVPN: automatikus.** Nincs mit beállítani:

- **Statikus challenge** (`static-challenge "…" 0|1` a configban): a WinVPN csatlakozás előtt bekéri a kódot a config szövegével, és a jelszóval együtt küldi a szervernek (SCRV1 formában, vagy egyszerűen a jelszó végére fűzve, ha a configban `concat` áll).
- **A szerver által küldött challenge** (dinamikus `CRV1` challenge vagy szöveges challenge): a kódbekérő ablak csatlakozás közben nyílik meg, a szerver szövegével.
- **Bejelentkezés a böngészőben** (`OPEN_URL`, `WEB_AUTH`: SAML, SSO, push): a WinVPN megmutatja a cím hosztját (egyszerű ASCII alakban, kisbetűvel) és a teljes címet, és rákérdez: **Megnyitás a böngészőben** (ez nem alapértelmezett gomb: kattints rá). Csak `https://` címet nyit meg, minden más címet figyelmen kívül hagy. A bejelentkezés (vagy a push jóváhagyása a telefonon) után a kapcsolat felépül. A WinVPN legfeljebb 5 percig vár (vagy a szerver rövidebb határidejéig).

**Minden típus: kód a jelszó végén.** Egyes szerverek a jelszó után beírt kódot várják (például `jelszó123456` vagy `jelszó,123456`). A kapcsolat beállításainál kapcsold be: **Egyszer használatos kód kérése csatlakozáskor, a jelszó végére fűzve**, és válaszd ki az **Elválasztó**t: nincs, `,` vagy `:`. OpenVPN, IKEv2, SSTP és L2TP kapcsolatnál érhető el, valamint L2TP rendszer VPN-eknél (a részletező nézetükben, a **Kapcsolatok** ablakban). Csatlakozáskor a WinVPN bekéri a kódot, és jelszó + elválasztó + kód formában küldi. Ha a WinVPN-ben nincs mentett jelszó, jelszóként csak a kód megy át. SSTP-nél a kóddal együtt sem lehet a jelszóban `"`, `\` vagy vezérlőkarakter. `static-challenge`-es OpenVPN confignál a beállítás nem érvényes, mert a statikus challenge már viszi a kódot.

**Hogyan működik (OpenVPN).** A WinVPN szolgáltatás az `openvpn.exe`-t a management interfészével indítja, a számítógép saját visszacsatolási (loopback) címén, és mielőtt elküldené a management jelszót, ellenőrzi, hogy valóban ez az `openvpn.exe` válaszol. Csak a szolgáltatás beszél vele, rögzített parancslistával. A szolgáltatás csak a kérdést, a `https` címet és az állapotot adja át az appnak (a saját csatornáján, csak a te felhasználói fiókodnak), a válaszodat pedig az OpenVPN-nek.

### 5.3 Hitelesítő adatok bekérése csatlakozáskor

Ha egy kapcsolathoz felhasználónév, jelszó, közös kulcs (PSK) vagy privát kulcs jelszó kell, de nincs elmentve a WinVPN-ben, a WinVPN csatlakozás előtt bekéri egy kis **Hitelesítő adatok szükségesek** ablakban. Ehhez semmit nem kell beállítani.

- **Mikor jelenik meg:**
  - **OpenVPN:** a configban `auth-user-pass` van fájl és beágyazott `<auth-user-pass>` blokk nélkül, és nincs elmentve a felhasználónév vagy a jelszó. Titkosított privát kulcs, amelynek a jelszava nincs elmentve.
  - **IKEv2:** EAP bejelentkezés (`auth = eap…` a `local` szakaszban), és nincs elmentve a felhasználónév vagy a jelszó.
  - **SSTP:** nincs elmentve a jelszó (a felhasználónév a kapcsolat beállításai között van).
  - **L2TP/IPsec:** nincs elmentve a fiók, a jelszó vagy a közös kulcs.
  - **WireGuard,** számítógép-tanúsítványos IKEv2 és a **rendszer VPN-ek** soha nem kérik a WinVPN ablakát: egy rendszer VPN-nél a Windows a saját mentett adatait használja, vagy a saját bejelentkező ablakát nyitja meg (lásd [3.5](#35-rendszer-vpn-ek-a-saját-windows-vpn-jeid)).
- **Az ablak** csak a hiányzó mezőket mutatja. Az elmentett felhasználónév ki van töltve. A **Mentés a széfbe** be van pipálva (**Titkosítva a WinVPN széfjében marad, a következő kapcsolódástól ezt használja**). Ha csak erre a csatlakozásra kell, vedd ki a pipát. Ha a kapcsolat olyan közös hitelesítő adatot használ, amelyhez nincs mentett jelszó, az ablak megnevezi (**A(z) Iroda AD jelszava — 4 kapcsolat használja**), és a **Mentés a széfbe** a közös hitelesítő adatba menti a jelszót, minden kapcsolat számára, amely használja.
- **Mentés csak a sikeres csatlakozás után.** Rossz jelszó soha nem kerül tárolásra.
- **Rossz felhasználónév vagy jelszó:** ha a szerver elutasítja a bejelentkezést (OpenVPN `AUTH_FAILED`, SSTP és EAP-s IKEv2: **Hitelesítési hiba (rossz felhasználónév vagy jelszó)** / **Hitelesítési hiba (EAP)**), az ablak **egyszer** újra megnyílik a **Sikertelen bejelentkezés — ellenőrizd a felhasználónevet és a jelszót** sorral, a felhasználónév kitöltve. A második hiba a szokásos hibával és értesítéssel ér véget. Az L2TP/IPsec nem kérdez újra (mint a MacVPN-ben); a hibaüzenete megmondja, hogy a bejelentkezés nem sikerült.
- **Mégse** (vagy Escape, vagy az ablak bezárása) hiba és értesítés nélkül leállítja a csatlakozást. Ha nyitott ablak mellett bontasz, az ablak bezárul. 2 perc után lejár, ez Mégsének számít.
- **Mint a kódbekérő,** nem veszi el a billentyűzetet a használt apptól: a gépeléshez kattints az ablakra vagy a „…: hitelesítő adatok szükségesek” értesítésre. Megjelenése után kb. egy másodpercig nem fogad bevitelt, és nincs alapértelmezett gombja: az Enter nem csinál semmit, a **Csatlakozás** gombra kell kattintani. Amíg nyitva van, a sor **Hitelesítésre vár** állapotú.
- **Ismert korlát:** a PKCS#12 csomagban (`<pkcs12>`) lévő privát kulcs jelszavát nem kéri be, mert a WinVPN nem tudja eldönteni, van-e ilyen. Mentsd el a kapcsolat szerkesztőjében (**Privát kulcs jelszava**).
- A beírt adat erre a csatlakozásra jut el a VPN-motorhoz. A WinVPN használat után törli a saját másolatait; a rendszer útközben készült másolatait (a webes nézet és az app belső üzenetküldése) a WinVPN nem tudja törölni. A beírt adat soha nem kerül a naplóba, és parancssorba sem. Egy vezérlő API kliens csak a `waiting_for_credentials` állapotot látja, és a `credentials_cancelled` hibát, ha megszakítod.

### 5.4 Párosított appok (vezérlő API)

A felhasználói fiókod egy másik programja, például a [RemoteDesktop](https://github.com/LovaszCC/RemoteDesktop) társalkalmazás, párosítás után fel- és lekapcsolhatja helyetted a WinVPN kapcsolatait. Alapból ki van kapcsolva.

1. Nyisd meg a **Kapcsolatok** ablakot (**Kapcsolatok kezelése…**), és az oldalsávban válaszd a **Párosított appok** pontot.
2. Kapcsold be: **Más appok vezérelhetik a VPN-eket**. Kikapcsolva egyetlen program sem érheti el így a WinVPN-t.
3. Indítsd el a párosítást a másik programban. A WinVPN megnyitja az **Engedélyezed, hogy egy app vezérelje a VPN-eket?** ablakot: **Név (a program saját megnevezése)** (a program maga választotta, így semmit nem bizonyít), a **Futtatható fájl** teljes útvonala, és a **Használható kapcsolatok**, kapcsolatonként egy jelölőnégyzettel, egyik sincs bejelölve. Ellenőrizd az útvonalat, jelöld be a kapcsolatokat, és kattints az **Engedélyezés** gombra. Az **Elutasítás**, az ablak bezárása vagy 2 perc válasz nélkül elutasítást jelent.

A párosított program csak az általad engedélyezett kapcsolatokat látja, és csak a fel- és lekapcsolásukat kérheti (ugyanazokkal a kód- és hitelesítőadat-ablakokkal, mint a kézi csatlakozás); configot, felhasználónevet és jelszót sosem lát.

Windowson a programok a felhasználói fiókod egy névvel ellátott csövén (named pipe) érik el a WinVPN-t (`\\.\pipe\WinVPN-control-<a felhasználód SID-je>`). A Windows csak a saját asztali munkamenetedben, a te nevedben futó programokat engedi csatlakozni: más felhasználót nem, a hálózatot nem, és a saját fiókodat sem egy távoli parancssorból (például SSH-ról). A WinVPN minden programot a felhasználói fiókja és a futtatható fájlja útvonala alapján azonosít. Fejlesztőknek: [vezérlő API, Windows](control-api.hu.md#11-windows-winvpn).

A **Párosított appok** alatt minden program látszik a futtatható fájl útvonalával, az **Utoljára használva** (vagy **Még nem használta**) és a **Párosítva:** idejével, és az **Engedélyezett kapcsolatok** listájával, amelyet bármikor módosíthatsz. A **Visszavonás** azonnal megszünteti a párosítást. Ha a programot áthelyezed vagy más útvonalra fordítod újra, **Megváltozott az útvonal** jelenik meg: vond vissza, és párosítsd újra. A **Tevékenység** a legutóbbi párosításokat, bejelentkezéseket és foglalásokat mutatja.

### 5.5 Automatikus újracsatlakozás

Ha egy kapcsolat azért bomlik, mert a gép alvó állapotba került vagy elment a hálózat, a WinVPN magától is újra felépítheti, pontosan a [MacVPN automatikus újracsatlakozásának](user-guide.hu.md#55-automatikus-újracsatlakozás) szabályaival, minden típusnál, amelyet maga csatlakoztat (a Windows VPN-kliens típusainál is; a rendszer VPN-eket sosem csatlakoztatja újra):

A WinVPN ebben a sorrendben ellenőriz:

1. **A VPN saját hálózatai közül egyik sem érhető el ott közvetlenül** (az útvonalai: WireGuard `AllowedIPs`, OpenVPN `route` sorok és küldött útvonalak, a „mindent a VPN-be” útvonalak nélkül; és a DNS-szerverei). Ez az első, így az irodai hálózat egy új router mögött is megakadályozza az újracsatlakozást. Az L2TP-nek, az IKEv2-nek és az SSTP-nek nincs ilyen listája, náluk csak a 2. szabály számít.
2. **Ugyanaz a hálózat**, mint amikor a kapcsolat felépült: a router címe és hardvercíme, és ahol a Windows megmondja, a Wi-Fi neve. A Windows 11 24H2-től a Wi-Fi nevét csak helymeghatározási engedéllyel rendelkező app látja; a WinVPN ezt nem kéri, így általában a router hardvercíme dönt. Ha a hálózat nem azonosítható, nincs újracsatlakozás (**A hálózatot nem sikerült azonosítani.**).

Példa: az „Office VPN” az irodai 10.20.30.0/24 hálózatot vezeti a VPN-be. Otthon felépítve alvás után otthon visszajön. Az irodában, ahol a gép a 10.20.30.0/24-en van, bontva marad (**Office VPN: nem csatlakozott újra** / **A VPN hálózata itt közvetlenül elérhető.**). Más hálózaton, ahol a VPN-ből semmi sem helyi (például egy kávézóban), az ok: **Másik hálózaton vagy.**


- Akkor indul, ha egy kapcsolat alvás előtt élt, és ébredés után nem él (vagy 3 percen belül megszakad), ha hálózat nélkül vagy egy hálózatváltás utáni egy percen belül szakad meg, és (a 2.0.3-tól) ha meglévő hálózat mellett magától szakad meg (leállt a motor, a szerver lezárta a munkamenetet vagy nem válaszol); legfeljebb 3 próbálkozás (azonnal, 10 és 30 másodperc múlva). Az újra és újra megszakadó vagy nem válaszoló kapcsolatot 10 percen belül legfeljebb háromszor csatlakoztatja azonnal újra.
- **Ha a gyors próbálkozások nem sikerültek** (a 2.0.3-tól): ugyanúgy, mint a [MacVPN-ben](user-guide.hu.md#55-automatikus-újracsatlakozás). A kapcsolatot, amelynek fenn kell lennie, 5 percenként, legfeljebb egy órán át újrapróbálja, csak hálózattal, sosem a VPN saját hálózatán, sosem elutasított bejelentkezés vagy tanúsítvány után; egy értesítés az elején, egy az óra végén; a sorában **Újrapróbálás 4 perc múlva** áll. A saját csatlakoztatásod vagy bontásod, vagy a kikapcsolt kapcsoló leállítja.
- **Sosem csatlakozik újra:** egy párosított app által indított kapcsolat (a **Kilépés, fussanak tovább** és egy újraindítás után sem: a WinVPN megjegyzi, amíg le nem bomlik vagy te nem csatlakoztatod), az általad bontott kapcsolat (a WinVPN-ből való kilépés vagy kijelentkezés miatt sem), az általad indított sikertelen csatlakozás, az elutasított bejelentkezés vagy tanúsítvány, a megszakított kódbekérő vagy hitelesítőadat-ablak. Zárolt széfnél nincs újracsatlakozás (**Az újracsatlakozáshoz oldd fel a széfet.**).
- **Alvást túlélő alagutak** (az OpenVPN `ping-restart`-ja, a WireGuard, és a Windows VPN-kliense, amely a megszakadt kapcsolatot maga hívja újra): ha a gép olyan hálózaton ébred, ahol a VPN hálózatai vagy DNS-szerverei közvetlenül elérhetők (az iroda), a WinVPN bontja az ilyen alagutat, és megírja, miért (**A VPN hálózata itt közvetlenül elérhető, ezért a kapcsolat bontva lett.**); minden más hálózaton (kávézó) él tovább. Ezután nem csatlakozik magától újra, amíg újra nem csatlakoztatod.
- **Ha a kapcsolat alól eltűnik a hálózat** (kikapcsolt Wi-Fi, kihúzott kábel): ugyanúgy, mint a [MacVPN-ben](user-guide.hu.md#55-automatikus-újracsatlakozás). Kb. 3 másodperccel azután, hogy az utolsó fizikai hálózat is eltűnt (a VPN-, TAP-, Wintun-, WireGuard- és telefonos adapterek nem számítanak hálózatnak), minden felépült vagy csatlakozó kapcsolat **Hálózatra vár…**, a tálcaikon a félig kitöltött pajzs (**WinVPN – Hálózatra vár…**). A legfeljebb 2 perces kiesést túlélő alagút újra csatlakozottnak látszik; a megszakadóra a fenti szabályok érvényesek. 2 perc hálózat nélkül után a WinVPN bontja (**2 percig nem volt hálózat.**), és bekapcsolt kapcsolóval újracsatlakoztatja, amikor visszajön a hálózat (**Újracsatlakozik, amikor visszajön a hálózat.**). A Windows VPN-kliense egy L2TP-, IKEv2- vagy SSTP-kapcsolatot ennél előbb maga is bonthat vagy újrahívhat.
- **Ha egy alagút nem válaszol** (a 2.0.3-tól): ugyanúgy, mint a [MacVPN-ben](user-guide.hu.md#55-automatikus-újracsatlakozás). Amíg a gépnek van hálózata, a WinVPN 30 másodpercenként megkérdezi a WinVPN Service-t minden WireGuard- és OpenVPN-kapcsolatról. A `PersistentKeepalive`-os WireGuard kb. 3½ perc sikeres kézfogás nélkül halott; enélkül akkor, ha a munkamenete lejárta után küldött valamit, és 1½ perccel később sincs kézfogás (a tétlen alagút sosem számít halottnak). A magától újrainduló OpenVPN sora **Újracsatlakozás…**, 2 perc után halott. A halott alagutat a WinVPN bontja, és bekapcsolt kapcsolóval újracsatlakoztatja (**Office VPN: nem válaszol** / **A VPN-szerver nem válaszol. A kapcsolat újracsatlakozik.**); kikapcsolt kapcsolóval, vagy ha egy párosított app indította, bontva marad, a sorában **Nem válaszol** áll. 10 percen belül 3 újracsatlakozás után a lassú próbálkozásokra vált (5 percenként, legfeljebb egy órán át). Az L2TP-t, az IKEv2-t és az SSTP-t nem kérdezi: a halott kapcsolatot a Windows VPN-kliense maga bontja. Ehhez a 2.0.3-as WinVPN Service kell: egy régebbi szolgáltatással nincs észlelés.
- **Ha hálózatot váltasz** (a 2.0.3-tól: Wi-Fi-ről másik Wi-Fi-re, Wi-Fi-ről kábelre, vagy a hálózat a **Hálózatra vár…** 2 percén belül másik hálózatként jön vissza): ugyanúgy, mint a [MacVPN-ben](user-guide.hu.md#55-automatikus-újracsatlakozás). A működő alagút marad; a WinVPN 2 percig közelről figyeli, és a halottat (a WireGuard 20 másodpercig küld, de semmit sem kap; az OpenVPN egy percig újra és újra újraindul), vagy a váltáskor megszakadót **az új hálózaton** csatlakoztatja újra. Ha a VPN hálózatai vagy DNS-szerverei ott közvetlenül elérhetők (az iroda), inkább bontja. Alvás után marad az „ugyanaz a hálózat” szabály.
- **A kapcsoló:** **Automatikus újracsatlakozás** a kapcsolat részleteinél a Kapcsolatok ablakban (alapból be); csak ezen a gépen tárolódik.
- **Modern Standby:** a Modern Standbyvel alvó gépeken a Windows nem mindig szól az appoknak az elalvásról; ilyenkor a WinVPN az ébredés utáni hálózat-visszatérésre hagyatkozik.

### 5.6 DNS kapcsolat közben

- **A WireGuard** a `DNS =` szervereit csak a saját adapterén állítja be; az adapter a beállításaival együtt megszűnik a kapcsolat végén, egy összeomláskor is. A hálózati beállításaid közül más nem változik.
- **Az OpenVPN** a szerver által küldött DNS-t a saját adapterén alkalmazza (TAP-Windows6-nál annak DHCP-jén át, DCO-nál egy beállítással, amelyet az OpenVPN bontáskor töröl). Az OpenVPN `dns` direktíváját (a Windows névfeloldási házirendjét) Windowson nem használja: az a szerver, amely csak így küld DNS-t, DCO-s kapcsolatnál nem ad DNS-t. Kérd meg a szerver rendszergazdáját, hogy `dhcp-option DNS`-t is küldjön.
- **L2TP/IPsec, IKEv2, SSTP és a rendszer VPN-ek:** a szerver DNS-ét maga a Windows alkalmazza a VPN-adapteren (az SSTP kikapcsolt **A szerver DNS-ének használata** beállításáról lásd [3.6](#36-sstp)).
- Így a régebbi MacVPN-verziókkal ellentétben egy összeomlás vagy újraindítás után semmit nem kell kézzel visszaállítani.

### 5.7 Kilépés, kijelentkezés és alvó állapot

- **Kilépéskor** (**Kilépés** a popoverben, valamint a Windows kijelentkezésekor, újraindításakor vagy leállításakor) a WinVPN előbb a Kapcsolatok ablak nem mentett változásaira kérdez rá (**Mentés**, **Elvetés** vagy **Mégse**). Utána, ha van aktív kapcsolat, megkérdezi: **Leállítás és kilépés**, **Kilépés, fussanak tovább** vagy **Mégse**. Kijelentkezéskor és leállításkor a Windows megvárja a válaszodat, és a kijelentkezést feltartó alkalmazások listájában ezt mutatja: **A WinVPN bezárása…**; a **Mégse** esetén a WinVPN fut tovább.
- **A kilépés után tovább futó kapcsolatokat** (az OpenVPN-t és a WireGuardot a WinVPN szolgáltatásban, a többit a Windows VPN-kliensében) a WinVPN következő indításakor újra kapcsolódottként mutatja.
- **A kijelentkezés bontja a kapcsolataidat:** az OpenVPN- és WireGuard-kapcsolatokat a WinVPN szolgáltatás, az L2TP/IPsec, IKEv2 és SSTP kapcsolatokat a Windows bontja, és a WinVPN gondoskodik róla, hogy így legyen (akkor is, ha egy rendszergazda úgy állította be a Windowst, hogy a VPN-kapcsolatok túléljék a kijelentkezést). A képernyő zárolása és a felhasználóváltás után megmaradnak.
- **Egy ablak bezárása** nem lépteti ki a WinVPN-t: tovább fut az értesítési területen.
- **Alvó állapot után** a WinVPN frissíti az állapotát, ellenőrzi a csapatkatalógusait (lásd [16.4](#164-frissítés-és-változások)), és újracsatlakozhat (lásd [5.5](#55-automatikus-újracsatlakozás)).

---

## 6. Debug mód és a napló

Ha egy kapcsolat nem jön létre, a debug mód lépésről lépésre megmutatja, mi történt.

**Indítás:**

- a popoverben **Alt + kattintás** a kapcsolón (**Alt+kattintás a kapcsolón: debug mód**), vagy
- a Kapcsolatok ablakban a **Csatlakozás debug módban** gomb.

Ilyenkor a **Napló** fül automatikusan megnyílik, és élőben követi az eseményeket. A debug mód csak erre az egy csatlakozásra érvényes.

Debug módban:

- **OpenVPN:** bőbeszédűbb kimenet (`--verb 5`): TLS handshake, a szerver által küldött beállítások, útvonalak, DNS.
- **WireGuard:** csatlakozás után a társ (peer) állapota (mint a MacVPN `wg show` kimenete: végpont, engedélyezett IP-k, utolsó handshake, fogadott és küldött bájtok; kulcs soha) a `▶ [WinVPN] WireGuard peer status (…)` sor alatt.
- **OpenVPN és WireGuard:** **diagnosztika** csatlakozás előtt és után (`▶ [WinVPN] diagnosztika (előtte)` / `(utána)`): a szerver nevének feloldása, az IPv4-útvonalak, a DNS és a hálózati interfészek.
- **L2TP/IPsec, IKEv2, SSTP:** a WinVPN által megírt Windows VPN-bejegyzés a **Windows VPN-bejegyzés (hibakereső mód):** sor alatt (típus, szerver, bejelentkezés, útvonalak, IKEv2-nél az IPsec-javaslat; jelszó és PSK soha), utána a tárcsázás minden lépése, mint mindig.

**Mi kerül a naplóba, típusonként:**

- **OpenVPN és WireGuard:** a kapcsolat WinVPN szolgáltatásbeli naplója (`C:\ProgramData\WinVPN\logs\<azonosító>.log`, csak a rendszergazdák és a rendszer olvashatja): az OpenVPN saját kimenete, a management lépései `[mgmt] …` előtaggal, a WinVPN saját megjegyzései `[WinVPN] …` előtaggal (például a TAP-Windows6-ra váltás), és a WireGuard lépései.
- **L2TP/IPsec, IKEv2 és SSTP:** a WinVPN saját tárcsázási naplója (`%LOCALAPPDATA%\WinVPN\logs\ras\<azonosító>.log`), debug mód nélkül is: **Kapcsolódás ide: vpn.example.com…**, **Hitelesítés…**, **Hitelesítve**, **Projekció (IP-beállítások)…**, **Csatlakozva, IPv4: 10.20.30.6**, hibánál pedig egy `✗` sor a WinVPN magyarázatával, és `Windows error <kód>: <a Windows saját szövege>` (a Windows szövege a Windows megjelenítési nyelvén van). A MacVPN-nel ellentétben ezeknek a típusoknak Windowson debug mód nélkül is van naplója.
- **A rendszer VPN-eknek** nincs naplója a WinVPN-ben (a Windows tárcsázza őket; a WinVPN a Windows által jelzett hibát mutatja).

**A napló sorai, színkóddal:**

| Előtag | Jelentés |
|---|---|
| `═══` | új csatlakozás kezdete (dátummal és idővel) |
| `▶ [WinVPN]`, `[WinVPN]`, `[mgmt]` | a WinVPN saját lépései (a szolgáltatás, a diagnosztikája, az OpenVPN management csatornája) |
| `✗` | hiba |
| egyéb | a motor (openvpn, wireguard-nt) saját kimenete vagy a Windows VPN-kliens tárcsázási lépései |

**A Napló fül** a kapcsolat naplójának utolsó 5000 sorát mutatja, és élőben követi, debug módon kívül is.

**Naplóméret.** Egy OpenVPN- vagy WireGuard-napló legfeljebb 8 MiB: ha megtelik, a régebbi rész, az `<azonosító>.log.1` lesz belőle, az új napló egy erről szóló sorral kezdődik (**A napló elérte a méretkorlátot; a korábbi része: …**), és a **Napló** fül elölről indul. A következő csatlakozás törli a régebbi részt. Az OpenVPN `--mute 20`-szal fut, így egy sokszor egymás után ismétlődő üzenet (például `Network is unreachable`, amíg nincs hálózat) csak 20-szor kerül a naplóba, utána egy számláló. Egy L2TP/IPsec-, IKEv2- vagy SSTP-napló minden csatlakozáskor újraindul, és legfeljebb 1 MiB, plusz egy 1 MiB-os régebbi rész.

**Napló műveletek:** szűrés (**Minden**, **Parancsok**, **Hibák**), **Keresés**, időszűrő, **Követés** (automatikus görgetés), **Másolás** (a szűrt sorokat másolja), **Mentés…** (a naplót `<név>-naplo.txt` néven menti, csak te olvashatod), **Napló törlése…**. Jelszó, PSK, egyszer használatos kód és privát kulcs nem kerül a naplóba, így a mentett napló is megosztható (például a rendszergazdával).

**Időszűrő.** A **Keresés** melletti menüvel csak egy időszak sorai látszanak: **Bármikor** (alapértelmezés), **Utolsó 5 perc**, **Utolsó 15 perc**, **Utolsó óra**, **Ma**, vagy **Egyéni időszak**, amely egy **Ettől** és egy **Eddig** mezőt ad (helyi idő; bármelyik üresen maradhat). A szűrőkkel és a kereséssel együtt működik, és a **Másolás** azt másolja, ami látszik. Egy sor ideje az, amellyel kezdődik (az OpenVPN `2026-10-28 14:03:05` formája, minden csatlakozás `═══ … ═══` fejléce); a saját idő nélküli sor (folytatósor, egy lépés vagy a Windows VPN-kliens eseménye) az előtte lévő sorhoz tartozik. Időszűrővel a nézet első időpontja előtti sorok nem látszanak.

**Napló törlése…** megerősítés után (**Törlöd a naplót: <név>? Ez nem vonható vissza.**) kiüríti a kapcsolat naplóját, a régebbi részével (`<AZONOSÍTÓ>.log.1`) együtt. Élő kapcsolatnál is működik: a napló az új sorokkal folytatódik, a **Napló** fül elölről indul. A kiürített napló első sora **Napló törölve: <idő>**, így aki később olvassa, látja, hová lettek a korábbi sorok. Az OpenVPN- és WireGuard-naplót a WinVPN Service üríti ki, csak a saját kapcsolataid naplóját, más felhasználóét soha; az L2TP/IPsec-, IKEv2- és SSTP-naplót (a saját mappádban) maga a WinVPN. Ha a szolgáltatás régebbi az alkalmazásnál, a WinVPN ezt jelzi (**A WinVPN Service régebbi, mint az alkalmazás, és nem tudja törölni a naplót. Frissítsd a WinVPN-t, majd próbáld újra.**). Ha még szükséged lehet rá, előbb mentsd el a naplót.

---

## 7. Hibaelhárítás a napló alapján

Először nézd meg a hibaüzenetet a popoverben vagy az értesítésben. Ha ez nem elég, csatlakozz debug módban, és keress a **Napló** fülön (a **Hibák** szűrő csak a hibasorokat mutatja). Az alábbi üzenetek a magyarok; ha a WinVPN nyelve angol, angolul jelennek meg.

### 7.1 `AUTH_FAILED` (OpenVPN)

Üzenet: **Hitelesítési hiba (AUTH_FAILED)**. A szerver elutasította a felhasználónevet vagy a jelszót.

- Ellenőrizd a **Felhasználónév** és **Jelszó** mezőket, majd nyomd meg a **Mentés** gombot.
- Lejárt vagy zárolt fiók esetén keresd a szolgáltatót.
- Ha a szerver egyszer használatos kódot kér, lásd [5.2](#52-többfaktoros-hitelesítés-mfa) és [7.11](#711-egyszer-használatos-kód-és-böngészős-bejelentkezés-mfa).

### 7.2 `TLS handshake failed` / `TLS Error` (OpenVPN)

A titkosított csatorna nem jött létre. Jellemző sor: `TLS Error: TLS key negotiation failed to occur within 60 seconds`.

- Rossz szervercím, port vagy protokoll (`proto udp` vagy `tcp`). Vesd össze a szolgáltató adataival.
- Tűzfal, vagy egy szállodai, céges hálózat blokkolja a portot. Próbáld másik hálózatról.
- Nem egyező `<tls-auth>` vagy `<tls-crypt>` kulcs vagy `key-direction`, vagy rossz `<ca>`. Importálj friss `.ovpn` fájlt a szolgáltatótól.

### 7.3 Időtúllépés

Üzenet: **Időtúllépés: 30 mp alatt nem épült fel a kapcsolat** (OpenVPN, WireGuard), **Időtúllépés** (L2TP/IPsec, IKEv2, SSTP: a WinVPN legfeljebb 150 másodpercig vár, utána bont). A kapcsolat nem jött létre időben, ezért a WinVPN leállította.

- Ellenőrizd az internetkapcsolatot, és hogy a szerver elérhető-e.
- Nézd meg a napló utolsó sorait. Gyakran ott a valódi ok (például TLS-hiba vagy elérhetetlen szerver).

### 7.4 Nincs WireGuard handshake

A WireGuard-kapcsolat zöldnek látszik (az adapter létezik), de nem megy forgalom.

- Rossz `Endpoint` (cím vagy port), vagy a hálózat blokkolja az UDP-t.
- A `[Peer]` `PublicKey` értéke nem a szerver kulcsa, vagy a te nyilvános kulcsod nincs felvéve a szerveren.
- Az `AllowedIPs` nem fedi le a célhálózatot.
- Bonts, javítsd a configot, és csatlakozz újra.
- **Nem hozható létre a WireGuard-adapter (…)** vagy **Nem állítható be a WireGuard-adapter: …**: a WinVPN szolgáltatás nem tudta beállítani az adaptert; a részletek a naplóban. Ha **A wireguard.dll nem egyezik a rögzített verzióval. Javítsd a WinVPN-t.** jelenik meg, javítsd a WinVPN-t a Telepített alkalmazások alatt.

### 7.5 OpenVPN-illesztőprogramok (DCO és TAP-Windows6)

- **Ehhez a kapcsolathoz a(z) TAP-Windows6 illesztőprogram kell. Javítsd az OpenVPN Communityt a Rendszerállapotban.** (vagy a DCO): az illesztőprogram nincs telepítve. Az OpenVPN sor **Javítás** gombja telepíti (lásd [1.4](#14-openvpn-community)). Az **Add hozzá a DCO és a TAP-Windows6 illesztőprogramot: Gépház → Alkalmazások → Telepített alkalmazások → OpenVPN → Módosítás.** üzenet azt jelenti, hogy a WinVPN maga nem tudta telepíteni őket (egy nem általa telepített OpenVPN-nél).
- `[WinVPN] DCO cannot run this connection (pushed options); retrying with TAP-Windows6` a naplóban: a szerver olyan beállítást küldött, amelyet a DCO nem tud (tömörítés, régebbi titkosító). A WinVPN egyszer újrapróbálta TAP-Windows6-tal; teendő nincs, de kérd meg a szerver rendszergazdáját, hogy kapcsolja ki a tömörítést.
- Egy második TAP-Windows6-os kapcsolat, amíg az első él, hibát ad: TAP-Windows6 adapter egy van. Bontsd az elsőt.
- **Az openvpn.exe-t nem a(z) OpenVPN Inc. írta alá.** / **Az openvpn.exe olyan mappában van, amelyet más felhasználók is módosíthatnak: …** / **Az OpenVPN Community … túl régi (2.6.0 vagy újabb kell).**: a telepített OpenVPN nem ment át a szolgáltatás ellenőrzésén. Használd a Rendszerállapot **Javítás** vagy **Frissítés** gombját, vagy telepítsd újra az OpenVPN Communityt a hivatalos telepítővel a `C:\Program Files` alá.

### 7.6 A Windows VPN-kliens hibái (L2TP, IKEv2, SSTP)

A WinVPN egy sikertelen tárcsázás Windows-hibakódját olyan mondattá alakítja, amely megmondja, mit tegyél; a naplóban a kód és a Windows saját szövege is ott van (`Windows error 809: …`). A gyakoriak:

| Windows-hiba | Üzenet | Teendő |
|---|---|---|
| 691 | **Hitelesítési hiba (rossz felhasználónév vagy jelszó)** | Ellenőrizd a felhasználónevet és a jelszót; SSTP-nél és IKEv2-nél a WinVPN még egyszer rákérdez (lásd [5.3](#53-hitelesítő-adatok-bekérése-csatlakozáskor)). |
| 13801 | **Hitelesítési hiba (EAP)** (EAP-s IKEv2); **A szerver nem fogadta el a számítógép-tanúsítványt.** (tanúsítványos IKEv2) | Ellenőrizd az EAP-felhasználónevet (`eap_id`) és a jelszót; tanúsítványnál kérdezd meg a rendszergazdát, milyen tanúsítványt vár a szerver. |
| 13806 | **Nem található számítógép-tanúsítvány az IKEv2-höz. Egy rendszergazdának kell importálnia (lásd a felhasználói útmutatót).** | Importáld a tanúsítványt (lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)). |
| 789 | **Az IPsec-egyeztetés a szerverrel nem sikerült. Ellenőrizd az előre megosztott kulcsot és a szerver IPsec-beállításait – vagy a szerver nem válaszolt (ellenőrizd a címet, és hogy az UDP 500/4500 eléri-e).** | Ellenőrizd a PSK-t, a címet, és hogy az UDP 500 és 4500 eléri-e a szervert (egy hallgató szerver kb. egy perc után végződik így). |
| 766 (L2TP) | **A Windows nem tárol előre megosztott kulcsot ehhez a kapcsolathoz. Mentsd el újra, és kapcsolódj újra.** | Nyisd meg a kapcsolatot, add meg a PSK-t, **Mentés**, csatlakozz újra. |
| 809 | **A szerver nem válaszolt a VPN-portokon. Lehet, hogy tűzfal blokkolja őket, vagy a szerver NAT mögött van: ezt a Windows L2TP/IPsec esetén csak az „L2TP engedélyezése NAT mögött…” után engedi (egy rendszergazda hagyja jóvá).** | L2TP/IPsec-nél: kattints a hibában az **L2TP engedélyezése NAT mögött…** gombra, egy rendszergazda erősítse meg, indítsd újra a Windowst (lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)). Egyébként ellenőrizd a tűzfalat. |
| 812 | **A szerver házirendje elutasította a kapcsolatot (például a hitelesítési mód miatt). Kérdezd a VPN-rendszergazdát.** | Kérdezd a VPN-rendszergazdát. |
| 13868 | **A szerver a WinVPN által kínált IPsec-javaslatok egyikét sem fogadta el (…).** | A szerver más algoritmusokat vár: a `proposals` / `esp_proposals` értéke olyan legyen, amelyet mindkét oldal ismer (lásd [3.3](#33-ikev2-strongswan)). |
| 868 | **A szerver neve nem oldható fel. Ellenőrizd a szerver címét és a hálózat DNS-beállítását.** | Ellenőrizd a szerver nevét. |
| 800, 815 | **A szerver nem válaszolt. Ellenőrizd a szerver címét és a hálózati kapcsolatot.** | Ellenőrizd a címet és a hálózatot. |
| 720, 734 | **A PPP-egyeztetés a szerverrel nem sikerült. Kérdezd meg a VPN-rendszergazdát, milyen hitelesítést és titkosítást vár a szerver.** | A szerver másféle bejelentkezést vár (a WinVPN MS-CHAPv2-t használ). |
| 619, 628 | **A szerver a kapcsolat felépülése előtt lezárta azt.**; IKEv2-nél: **A szerver nem válaszolt, vagy lezárta a kapcsolatot.** | Ellenőrizd a címet, hogy az UDP 500 és 4500 eléri-e a szervert, és a naplót. |
| 0x8007274C (SSTP) | **A szerver nem válaszolt a portján. Ellenőrizd a szerver címét és a hálózati kapcsolatot.** | Ellenőrizd a címet és a portot (443 vagy a beállított). |
| 633 | **A Windows még zárja az előző kapcsolatot. Próbáld újra egy kis idő múlva.** | Várj néhány másodpercet, és csatlakozz újra. |
| 756 | **Ez a kapcsolat már tárcsáz.** | Várd meg a futó próbálkozást. |
| 631 | **A kapcsolódás megszakítva.** | Te bontottál. |
| egyéb | **Windows-hiba: … (lásd a naplót)** | Keresd meg a kódot a naplóban; csatlakozz debug módban, és küldd el a naplót a rendszergazdának. |

Ezeknek a típusoknak egyéb üzenetei:

- **Ez a kapcsolat már kapcsolódik.**: várd meg a futó próbálkozást, vagy előbb bonts.
- **Mentsd el újra ezt a kapcsolatot: a Windows VPN-bejegyzése hiányzik vagy sérült.**: nyisd meg az L2TP-kapcsolatot, és kattints a **Mentés** gombra.
- **A WinVPN … mappája nem ennek a felhasználónak a saját mappája. Töröld, majd indítsd újra a WinVPN-t.**: a `%LOCALAPPDATA%\WinVPN` egyik mappája (`ras` vagy `logs`) másé, vagy link; töröld, és indítsd újra a WinVPN-t (újra létrehozza).
- **A(z) … Windows-szolgáltatás le van tiltva. Egy rendszergazdának Kézi indításra kell állítania (services.msc).**: lásd [1.5](#15-a-wireguard-és-a-windows-vpn-kliens).
- **Rendszer VPN:** **Ez a Windows VPN már nem létezik. Lehet, hogy törölték a Gépházban: Hálózat és internet → VPN.**; a Windows bejelentkező ablakának megszakítása után: **A kapcsolat nem jött létre.**

### 7.7 „Nem engedélyezett direktíva” / „Tiltott direktíva”

Ezeket a hibákat **Mentéskor** vagy csatlakozáskor kaphatod, például:

- `3. sor: Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort`
- `5. sor: Kockázatos direktíva, tudomásulvétel szükséges: user` (a beállítás a sárga **Kockázatos beállítások** panelen látszik)
- csatlakozáskor: `A kockázatos beállítások nincsenek tudomásul véve: user. Nyisd meg a kapcsolatot a WinVPN → Kapcsolatok alatt, és jelöld be a négyzetet a Kockázatos beállítások résznél.`
- `7. sor: Külső fájl hivatkozás, inline blokk kell: ca`
- WireGuard: `4. sor: Tiltott kulcs: postup`, `6. sor: Nem engedélyezett kulcs: …`
- IKEv2: `2. sor: Tiltott: include`, `9. sor: Tiltott kulcs: updown`, `6. sor: Csak fájlnév adható meg, útvonal nem: cacerts`
- Argumentumok: `4. sor: Érvénytelen argumentum: dev`, `8. sor: Hibás argumentumszám: keepalive`, WireGuard `3. sor: Érvénytelen érték: address`
- OpenVPN: `12. sor: Túl hosszú sor`, `9. sor: Nem engedélyezett setenv: SystemRoot – töröld vagy tedd megjegyzésbe (#) a sort`

A WinVPN szolgáltatás rendszerjogokkal futtatja az OpenVPN-t, ezért a WinVPN csak ismert, biztonságos beállításokat enged. Javítás:

- **Tiltott direktíva / kulcs** (például `up`, `down`, `script-security`, `PostUp`, Windowson a `cryptoapicert`, a `windows-driver` és a `win-sys`): ezek külső parancsot futtatnának, vagy a configot olyasmihez engednék, amihez csak a rendszer férhet hozzá. Töröld a sort, vagy tegyél elé `#` jelet. A DNS-t, az útvonalakat és az illesztőprogramot a WinVPN maga kezeli.
- **Tudomásulvételt igénylő kockázatos direktíva / nincsenek tudomásul véve:** olvasd el az indoklást a sárga panelen; ha kell a beállítás, jelöld be a **Tudomásul veszem a beállításokat és a biztonsági kockázatokat** négyzetet, és **Mentés**, különben tedd megjegyzésbe a sort.
- **Érvénytelen argumentum / érték, rossz számú argumentum:** a beállítás engedett, de az értéke nem a várt formájú. Az üzenet a beállítást nevezi meg, nem az értéket.
- **Külső fájlra hivatkozás:** egy tanúsítvány fájlra hivatkozik (`ca ca.crt`). Importáld újra a `.ovpn` fájlt a hivatkozott fájlokkal együtt, vagy másold a tartalmukat egy `<ca>…</ca>` blokkba.
- **Nem engedélyezett vezérlőkarakter**: a fájlban láthatatlan karakter van. Írd be újra a sort.
- **Túl hosszú sor**: a sor hosszabb 255 bájtnál. Egy beágyazott blokkban lévő tanúsítvány vagy kulcs sorai általában 64 karakteresek; exportáld újra a forrásából, vagy tördeld a sort. Egy más programnak készült configban hosszú megjegyzéssorok lehetnek: rövidítsd vagy töröld őket.
- **Nem engedélyezett setenv**: Windowson csak a [3.1](#31-openvpn) részben felsorolt `setenv` nevek engedettek. Töröld a sort, vagy kérdezd meg a szolgáltatót, kell-e a beállítás.

### 7.8 A WinVPN szolgáltatás és egyéb üzenetek

- **A WinVPN szolgáltatás nem érhető el.** / **A WinVPN szolgáltatás hiányzik, vagy egy másik WinVPN-verzióhoz tartozik. Javítsd a WinVPN-t: …**: az OpenVPN és a WireGuard nem csatlakozik. Egy rendszergazda a `sc.exe query WinVPN` paranccsal ellenőrizheti (`RUNNING` kell legyen), a `sc.exe start WinVPN` paranccsal elindíthatja, vagy javíthatja a WinVPN-t a Telepített alkalmazások alatt. Az L2TP/IPsec, az IKEv2, az SSTP és a rendszer VPN-ek tovább működnek.
- **A(z) C:\ProgramData\WinVPN mappa jogosultságai nem biztonságosak. Egy rendszergazdának törölnie kell, majd újra kell indítania a WinVPN szolgáltatást.**: lásd [1.3](#13-a-winvpn-szolgáltatás).
- **Az OpenVPN Communityt csak a Program Files mappába telepített WinVPN tudja telepíteni.**: fejlesztői buildet futtatsz; telepítsd a WinVPN-t az MSI-jével.
- **Az OpenVPN telepítőjét nem sikerült letölteni: …** / **Az OpenVPN telepítője hibával leállt (…).**: a telepítés nem fejeződött be; semmi nem változott. Próbáld később, vagy telepítsd az OpenVPN Communityt magad az openvpn.net oldalról.
- **Az OpenVPN interaktív szolgáltatását (Interactive Service) nem sikerült letiltani.**: az OpenVPN települt, de a második rendszergazdai kérdést elutasították; az OpenVPN így is működik.
- **A WinVPN frissítése bontja az aktív VPN-kapcsolatokat.**: frissítés előtt jelenik meg (lásd [8.](#8-frissítés)).
- **Ugyanarra a fájlra mutató `cert` és `key`** (kombinált PEM fájl: tanúsítvány és privát kulcs, akár titkosítva, Windows-sorvégekkel is): támogatott. A WinVPN csak a tanúsítványblokkokat teszi a `<cert>`, csak a kulcsot a `<key>` részbe, és csatlakozáskor bekéri a **Privát kulcs jelszava** mezőt.

### 7.9 SSTP és IKEv2: tanúsítványhibák

- **A szerver hitelesítésszolgáltatójában (CA) a Windows nem bízik meg. Használd a szerkesztőben „A CA megbízhatóvá tétele a Windowsban…” lehetőséget.**: **Saját CA fájl** módú SSTP, mielőtt a CA megbízható lett volna (lásd [3.6](#36-sstp), [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)).
- **A szerver tanúsítványát nem olyan hitelesítésszolgáltató (CA) adta ki, amelyben a Windows megbízik. Kérdezd a VPN-rendszergazdát.**: **Rendszer CA** módnál (vagy IKEv2-nél) a kiadó CA nincs a számítógép megbízható gyökerei között. Kérd el a CA-tanúsítványt, és tedd megbízhatóvá, vagy használd a **Saját CA fájl** módot.
- **A szerver tanúsítványa nem egyezik a szerver címével. Szervercímként a tanúsítványban szereplő nevet add meg.**: a tanúsítványban szereplő névvel csatlakozz, ne IP-címmel vagy más álnévvel (IKEv2: `remote_addrs`).
- **A Windows nem tudta ellenőrizni, hogy a szerver tanúsítványát visszavonták-e (a visszavonási szerver nem érhető el).**: a szerver visszavonási listája (CRL) nem érhető el a hálózatodról. Kérdezd a VPN-rendszergazdát.
- Lejárt tanúsítvány, vagy rosszul jár a számítógép órája.

### 7.10 Sikertelen bejelentkezés (L2TP, IKEv2, SSTP)

Üzenet: **Hitelesítési hiba (rossz felhasználónév vagy jelszó)** (691-es Windows-hiba) vagy **Hitelesítési hiba (EAP)** (IKEv2, 13801).

- Ellenőrizd a **Felhasználónév** és **Jelszó** mezőt, majd **Mentés**. Windows-tartományi fiókot `user@domain` formában írj (nem `DOMAIN\user`).
- A szervernek MS-CHAPv2-t (L2TP, SSTP) vagy EAP-MSCHAPv2-t (IKEv2) kell engednie. Ha csak tanúsítványos (EAP-TLS) vagy PAP bejelentkezést fogad el, a WinVPN nem tud hozzá csatlakozni.
- A jelszó végére fűzött kódnál ellenőrizd, milyen **Elválasztó**t vár a szolgáltató.

### 7.11 Egyszer használatos kód és böngészős bejelentkezés (MFA)

- **A hitelesítés nem fejeződött be időben**: 2 percen belül nem érkezett kód, vagy a böngészős bejelentkezés nem fejeződött be a határidőn belül (legfeljebb 5 perc). Csatlakozz újra, és válaszolj hamarabb.
- **A hitelesítés megszakítva**: a kódbekérő vagy a böngészős ablakban a **Mégse** gombra kattintottál, vagy bontottál.
- **Hitelesítési hiba**: a szerver elutasította a kódot vagy a jelszót. A kódok gyorsan lejárnak: használj frisset. A jelszó végére fűzött kódnál ellenőrizd, milyen **Elválasztó**t vár a szolgáltató.
- **Nem jelenik meg a böngészős ablak**: a WinVPN csak egyszerű ASCII hosztnevű `https://` címet nyit meg (nemzetközi név csak `xn--` alakban, az elérési út előtt nincs `%` és `@`). Ilyenkor a naplóban `web authentication URL dropped (only https with a plain ASCII host is accepted)` áll. Kérj ilyen bejelentkezési címet a szolgáltatótól.
- **Nem sikerült a kapcsolat az OpenVPN kezelőfelületével**: a WinVPN szolgáltatás nem érte el az OpenVPN management interfészét. Csatlakozz újra; ha ismétlődik, csatlakozz debug módban, és nézd meg a `[mgmt]` sorokat.
- **Nincs hitelesítésre váró kapcsolat**: a csatlakozás már véget ért (határidő vagy hiba), mielőtt a válasz megérkezett. Csatlakozz újra.
- A naplóban a `[mgmt]` sorok a szolgáltatás lépései (például `hold released`, `credentials sent`, `dynamic challenge received`). Soha nem tartalmazzák a kódot vagy a jelszót, a bejelentkezési címnek pedig csak a hosztja kerül a naplóba.

### 7.12 Az értesítések okai

Egy megszakadásról vagy sikertelen csatlakozásról szóló értesítés (lásd [2.3](#23-értesítések)) ezek egyikét adja okként. A WinVPN a kapcsolat naplójának utolsó illeszkedő sorából veszi; nyisd meg a **Napló** fület, és keress a középső oszlop szövegére.

| Ok | A mögötte álló naplósorok (példák) | Automatikus újracsatlakozás |
|---|---|---|
| **A szerver nem válaszol.** | `Inactivity timeout (--ping-restart)`, `Inactivity timeout (--ping-exit)` (OpenVPN), `peer not responding` | megpróbálja |
| **A szerver nem érhető el.** | `TLS key negotiation failed`, `Connection refused`, `Connection timed out`, `Windows error 800:`, `809:`, `815:`, `0x8007274C:` | megpróbálja |
| **A szerver nevét nem sikerült feloldani.** | `Cannot resolve host address`, `Windows error 868:` | megpróbálja |
| **A szerver elutasította a bejelentkezést.** | `AUTH_FAILED`, `Windows error 691:`, `Windows error 13801:` | nem próbálja |
| **Egy tanúsítványt nem fogadott el a kapcsolat.** | `VERIFY ERROR`, `certificate verify failed`, `Windows error 13806:`, `Windows error 0x800B0109:`, `0x80092013:`, `0x800B010F:` | nem próbálja |
| **Megszakadt a hálózati kapcsolat.** | `Network is unreachable`, `No route to host` | megpróbálja |

Minden más esetben **Kattints a naplóért.** áll ott (sikertelen csatlakozásnál **Részletek a WinVPN-ben**). Az ok csak útmutatás: a fenti szakaszok minden hibát részletesen leírnak.

---

## 8. Frissítés

A WinVPN a GitHub Releases oldalon keresi az új verziókat: induláskor, majd 24 óránként egyszer. Ez a telepített WinVPN-ben működik (fejlesztői buildben nem).

- Ha van újabb verzió, a popoverben megjelenik a **Frissítés elérhető: vX.Y.Z** sor. Kattintásra megnyílik a **Frissítés** ablak a változások listájával és a telepített verzióval. A **Később** bezárja; a **Kiadás megnyitása a GitHubon** a kiadás oldalát nyitja meg.
- A **Letöltés és telepítés** gomb:
  1. letölti a számítógép processzorához tartozó MSI-t (`WinVPN-X.Y.Z-x64.msi` vagy `-arm64.msi`), a hozzá tartozó `.sha256` fájlt és a `.sig` aláírást, ellenőrzi az SHA-256 ellenőrzőösszeget, majd azt, hogy az aláírást a fejlesztő offline kulcsa készítette, pontosan erre a verzióra és erre a telepítőfájlra. Ha az aláírás hiányzik vagy érvénytelen, **A frissítést nem a WinVPN fejlesztője írta alá** üzenettel leáll, és semmit nem telepít;
  2. a kilépéshez hasonlóan rákérdez a nem mentett változásokra és az aktív kapcsolatokra (**A WinVPN frissítése bontja az aktív VPN-kapcsolatokat.**: a telepítő újraindítja a WinVPN szolgáltatást);
  3. **rendszergazdai megerősítést** kér (mint az első telepítés; normál felhasználónak rendszergazdai jelszó kell), majd kilép; a Windows Installer frissíti a WinVPN-t és a WinVPN szolgáltatást, a WinVPN pedig magától újraindul.
  Az ablak minden lépést kijelez (**Letöltés…**, **Telepítés előkészítése…**, **Kilépés és újraindítás…**). Ha a kilépés előtt bármi hibára fut, a telepített verzió marad, és a WinVPN tovább fut. A rendszergazdai kérdés elutasítása megszakítja a frissítést.
- **Aláírt frissítések:** minden kiadást a fejlesztő egy offline tárolt Ed25519 kulccsal ír alá; a kulcs soha nincs a GitHubon. Az aláírás a telepítőfájlt is megnevezi, így egy másik termék vagy processzor aláírása sosem érvényes. A WinVPN csak aláírásfájllal rendelkező kiadást ajánl fel. A még alá nem írt újabb kiadást nem ajánlja fel; a **Frissítések keresése most** ilyenkor **A frissítés aláírásra vár** üzenetet ad.
- **Beállítások** a popoverben: **Frissítések keresése most** (ha nincs újabb: **A WinVPN naprakész**), **Frissítések automatikus keresése**, és **Csak a legalább 24 órája megjelent frissítések felajánlása** (alapból ki; időt hagy arra, hogy egy hibás kiadás kiderüljön és lekerüljön, mielőtt telepítenéd).
- **A VPN-motorok** (OpenVPN Community, wireguard-nt) külön frissülnek, WinVPN-kiadás nélkül (lásd [2.5](#25-az-openvpn-és-a-wireguard-frissítése)); a Windows VPN-kliensét a Windows Update frissíti.
- A telepítési naplók egy hétig a `%LOCALAPPDATA%\WinVPN\updates` mappában maradnak (`msiexec-<verzió>.log`). Ha egy frissítés nem sikerült, a WinVPN a következő indításkor egyszer jelzi, a napló útvonalával; a telepített verzió megmarad.

### 8.1 Frissítés az 1.5-ös előzetesről

Az 1.5.0-s WinVPN nem keresett frissítést, ezért a 2.0-t egyszer kézzel kell telepíteni: egy rendszergazda duplán kattint a 2.0-s MSI-re (lásd [1.1](#11-a-telepítő)). Ez helyben frissíti az előzetest (egy WinVPN a Telepített alkalmazások között), és felveszi a WinVPN szolgáltatást. A széfed, a kapcsolataid és a beállításaid megmaradnak. Utána:

1. Nyisd meg a **Rendszerállapot** ablakot: ha OpenVPN-t használsz, telepítsd az OpenVPN Communityt (lásd [1.4](#14-openvpn-community)).
2. Az L2TP/IPsec kapcsolataid a széf feloldásakor kapják meg a Windows VPN-bejegyzésüket; az IKEv2 és az SSTP az első csatlakozáskor. A szürke kapcsolatoknál nézd meg az okot (például Cisco IPsec, PSK-s IKEv2).
3. Mostantól a WinVPN magát frissíti (lásd [8.](#8-frissítés)).

---

## 9. Eltávolítás

A WinVPN-t a Windowsban távolíthatod el (Telepített alkalmazások). Mivel minden felhasználónak a saját fiókjában is vannak WinVPN-adatai és Windows VPN-bejegyzései, a **Rendszerállapot** előbb a saját fiókod rendbetételét kínálja.

### 9.1 WinVPN eltávolítása erről a fiókról

**Rendszerállapot** → **WinVPN eltávolítása erről a fiókról…** (a **A WinVPN-t a Windowsban távolíthatod el: …** megjegyzés alatt). A megerősítés felsorolja, mi törlődik:

- az **indítás bejelentkezéskor**;
- **a WinVPN Windows VPN-bejegyzései és a Windows által hozzájuk tárolt előre megosztott kulcsok** (minden `WinVPN-…` bejegyzés, azoké a kapcsolatoké is, amelyeket egy zárolt széf nem listázott);
- bejelölt **A felhasználói adatok törlése is (kapcsolatok, a széf és a kulcsa)** mellett: a kapcsolataid és jelszavaid (`%LOCALAPPDATA%\WinVPN`, a naplókkal és a beállításokkal) és a széfkulcs a Hitelesítőadat-kezelőben (`local.winvpn.vault`).

Az aktív kapcsolatok előbb bontódnak. **A saját Windows VPN-jeid megmaradnak** (a WinVPN sosem nyúl hozzájuk). Kattints az **Eltávolítás** gombra: a WinVPN ezt írja: **A WinVPN eltávolítva erről a fiókról**, és megnyílik a Gépház → Alkalmazások → **Telepített alkalmazások**. Utána:

1. Lépj ki a WinVPN-ből (**Kilépés** a popoverben).
2. A **Telepített alkalmazások** alatt keresd meg a **WinVPN**-t, és válaszd az **Eltávolítás** pontot (egy rendszergazda megerősíti). A program, a WinVPN szolgáltatás, a `wireguard.dll` és a Start menü bejegyzése törlődik.

Ha a gép más Windows-felhasználói is használták a WinVPN-t, mindegyikük a saját fiókjában futtassa a **WinVPN eltávolítása erről a fiókról…** lépést, mielőtt a programot eltávolítják.

Ha megtartod az adataidat (a négyzet nincs bejelölve), és később újra telepíted a WinVPN-t, a széf ugyanúgy megnyílik; az L2TP/IPsec kapcsolatokat egyszer nyisd meg, és kattints a **Mentés** gombra, hogy a Windows VPN-bejegyzésük újra elkészüljön.

### 9.2 Mi marad meg az eltávolítás után

- **Az OpenVPN Community**, a DCO és TAP-Windows6 illesztőprogramja és a TAP-adapterei: az OpenVPN-hez tartoznak. Ha már nincs rá szükséged, távolítsd el az **OpenVPN**-t a Telepített alkalmazások alatt. Ha a WinVPN telepítette, az interaktív szolgáltatása letiltva marad.
- **A `C:\ProgramData\WinVPN`**: az OpenVPN- és WireGuard-kapcsolatok maszkolt naplói, a `service.log` és a szolgáltatás által letöltött wireguard-nt. Egy rendszergazda törölheti a mappát.
- **Az adataid**, ha nem jelölted be **A felhasználói adatok törlése is** négyzetet: a `%LOCALAPPDATA%\WinVPN` és a `local.winvpn.vault` hitelesítő adat (Vezérlőpult → Felhasználói fiókok → Hitelesítőadat-kezelő → Windows hitelesítő adatai). A kettő kézi törlése ugyanazt teszi, mint a négyzet.
- **A biztonsági mentések**, amelyeket a **Teljes biztonsági mentés…** készített: ha már nincs rájuk szükséged, töröld őket magad.
- **A rendbetétel nélkül** (például ha előbb a programot távolították el): a WinVPN telefonkönyve a `%LOCALAPPDATA%\WinVPN\ras` mappában marad, a Windows által a bejegyzéseihez tárolt PSK-kkal együtt. Ezek semmit nem csinálnak (a Windows nem listázza és nem tárcsázza őket), de az eltávolításukhoz telepítsd újra a WinVPN-t, és futtasd a **WinVPN eltávolítása erről a fiókról…** lépést, vagy töröld a mappát; egy még élő VPN-kapcsolat a kijelentkezésig él. Eltávolítás előtt bonts.

---

## 10. Biztonsági megjegyzések

**Mit véd a WinVPN, és mit nem.** A WinVPN a kapcsolataidat és jelszavaikat egy titkosított széfben tartja (lásd [11.](#11-széf)), egy csak általad olvasható mappában. A Windows-fiókodban **már futó programok ellen nem** véd: egy ilyen program mindent elolvashat, amit te is.

- **Automatikus feloldás és a Hitelesítőadat-kezelő.** Bekapcsolt **Automatikus feloldás** mellett (ez az alapértelmezés) a széfkulcs a Windows Hitelesítőadat-kezelőjében van, `local.winvpn.vault` általános hitelesítő adatként. A Windows a Windows-fiókodhoz kötve titkosítja (DPAPI), és csak ezen a számítógépen tartja (sosem vándorol másik számítógépre).
  - *Véd:* a számítógép többi felhasználója ellen, és az ellen, aki a lemezt (vagy a `%LOCALAPPDATA%\WinVPN` egy másolatát) a Windows-jelszavad nélkül viszi el.
  - *Nem véd:* a te nevedben futó kártevő ellen. A Hitelesítőadat-kezelőben nincs alkalmazásonkénti hozzáférés-szabályozás: a Windows-fiókodban futó bármely program kiolvashatja a széfkulcsot, és vele a széfet. (macOS-en a Keychain csak a MacVPN saját kódaláírásának adja ki a kulcsot; a Windowsban nincs ilyen ellenőrzés.)
  - Ha ez neked nem elfogadható, kapcsold ki az **Automatikus feloldás** kapcsolót (lásd [11.2](#112-automatikus-feloldás)): a kulcs törlődik a Hitelesítőadat-kezelőből, és a WinVPN minden indításkor a mesterjelszót kéri.
- **Az adatmappád.** A `%LOCALAPPDATA%\WinVPN` mappa és minden fájlja olyan hozzáférési listát kap, amely csak a felhasználódat és a SYSTEM-et (magát az operációs rendszert, amelyet a mentő- és víruskereső programok használnak) engedi be; a Rendszergazdák csoport nincs benne, bár egy rendszergazda szándékosan átveheti a tulajdonjogot. A WinVPN elutasítja azt a széffájlt, amelynek a hozzáférési listája ennél bővebb.
- **A WinVPN szolgáltatás.** Csak a számítógép programjaitól fogad kérést, és az app, mielőtt bármit küldene, ellenőrzi, hogy a csatorna valóban a rendszeré (így egy program, amely előbb lefoglalta a nevet, sosem kap jelszót). Minden kérés ahhoz a Windows-felhasználóhoz kötődik, aki küldte: egy felhasználó sosem láthatja, bonthatja vagy olvashatja egy másik felhasználó kapcsolatait. Csak OpenVPN Inc. által aláírt, rendszergazdák által írható mappában lévő `openvpn.exe`-t és csak WireGuard LLC által aláírt `wireguard.dll`-t futtat; azok az OpenVPN-beállítások, amelyekkel egy config rendszerjogokkal futtathatna programot vagy olvashatna fájlt, tiltottak (lásd [3.1](#31-openvpn)). Tanúsítványt vagy Windows-beállítást egy felhasználó kedvéért sosem módosít.
- **Titok sosem kerül parancssorba vagy naplóba.** A jelszavak, PSK-k és egyszer használatos kódok egy privát fájlon vagy a management csatornán jutnak el az OpenVPN-hez, a WireGuard-kulcsok közvetlenül a meghajtóhoz, a Windows VPN-kliense pedig a jelszót csak tárcsázáskor kapja meg. Az egyetlen kivétel az L2TP/IPsec **előre megosztott kulcsa**, amelyet a Windows csak a saját titkosított VPN-hitelesítőadat-tárolójából tud venni: a WinVPN a saját bejegyzéséhez oda teszi (lásd [3.8](#38-hol-tárolja-a-winvpn-a-natív-vpn-eket)), és a bejegyzéssel együtt eltávolítja. Minden naplósor maszkolt.
- **A rendszergazdai lépéseket** (CA megbízhatóvá tétele, L2TP NAT mögött) a WinVPN mindig előbb megmutatja, és rendszergazdai megerősítést kérnek; egy megbízhatóvá tett CA-ban a gép minden programja megbízik, ezért csak a szervezeted VPN-CA-jával tedd (lásd [3.7](#37-rendszergazdai-lépések-a-natív-vpn-ekhez)).
- **A nyitott széf a memóriában.** Amíg a széf nyitva van, a kulcsa és a visszafejtett lapjai a WinVPN memóriájában vannak, és a WinVPN felszabadításkor törli ezt a memóriát. Azt, hogy ezek a lapok ne kerüljenek a lapozófájlba, a Windowson csak a lehetőségekhez mérten tudja biztosítani (a Windows egy programnak csak kevés memória zárolását engedi): ahogy a macOS swapjába, úgy a lapozófájlba is kikerülhet belőlük néhány. Hogy egy ellopott lemezen a lapozófájl is védve legyen, használj BitLockert (vagy más teljeslemez-titkosítást) a rendszermeghajtón, vagy titkosítsd a lapozófájlt (`fsutil behavior set EncryptPagingFile 1`, rendszergazdaként).
- **Aláíratlan telepítő.** Az MSI nincs Authenticode-dal aláírva (lásd [1.2](#12-smartscreen)). Csak a hivatalos helyről töltsd le. A WinVPN által telepített frissítéseket a fejlesztő offline Ed25519 aláírásával ellenőrzi, a telepítő nevéhez, verziójához és processzortípusához kötve (lásd [8.](#8-frissítés)).
- **A motorfrissítéseket** a kiadóik aláírása (OpenVPN Inc., WireGuard LLC) alapján fogadja el, és régebbi verziót sosem telepít (lásd [2.5](#25-az-openvpn-és-a-wireguard-frissítése)).
- **Letöltött fájlok.** A Windows által letöltöttként megjelölt fájlt a WinVPN csak egy kérdés után importálja (lásd [4.1](#41-vpn-fájlok-megnyitása-a-fájlkezelőből)).
- **Titkok a vágólapon.** A helyreállítási kulcsot, a csapatkulcsot és a feliratkozási kódot a WinVPN úgy másolja, hogy ne kerüljenek a Windows vágólap-előzményeibe (Win+V) és a felhőalapú vágólap-szinkronizálásba, és a vágólapfigyelő programokat is kéri, hogy hagyják ki őket. A WinVPN 60 másodperc után, a **Széf zárolása most** parancsnál és kilépéskor törli a vágólapot, hacsak közben mást nem másoltál.
- **Párosított appok.** Alapból kikapcsolva; a vezérlő csövet csak a saját asztali munkamenetedben futó programok érik el (lásd [5.4](#54-párosított-appok-vezérlő-api)). Részletek: [a vezérlő API leírása](control-api.hu.md#4-biztonsági-modell).
- **Mentések.** A **Teljes biztonsági mentés…** fájlja minden titkot tartalmaz, a mentés jelszavával titkosítva. Aki birtokolja a fájlt és a jelszavát, az összes VPN-hitelesítő adatodat elolvashatja: a kettőt tartsd külön. Lásd [14.](#14-biztonsági-mentés-és-visszaállítás)
- **Csapatkatalógusok.** Lásd [16.11](#1611-biztonsági-modell).
- **Külső licencek.** A WinVPN MIT-licences ([LICENSE](../LICENSE)). A `C:\Program Files\WinVPN\THIRD-PARTY-NOTICES.txt` felsorolja a mellékelt összetevők licenceit, köztük az SQLCipherét (BSD-típusú, © Zetetic LLC), az OpenSSL-ét és a wireguard-nt-ét.

---

## 11. Széf

A WinVPN egyetlen titkosított fájlban, a **széfben** tárolja a kapcsolataidat, a configjaikat, a felhasználóneveket, jelszavakat, PSK-kat és kulcsjelszavakat, a közös hitelesítő adatokat, a mappákat és színeket, a sorrendet és a kitűzéseket, a csapatkatalógusokat és a párosított appokat: `%LOCALAPPDATA%\WinVPN\vault.db`, mellette a kulcsfájlja, a `vault.keys`. A teljes adatbázis titkosított; a széfkulcs nélkül semmi sem olvasható ki belőle, még a kapcsolatok neve sem.

### 11.1 Mesterjelszó és helyreállítási kulcs

A **Széf beállítása** ablak az első indításkor nyílik meg (később, amíg nincs széf, a popover **Széf beállítása…** sorából).

1. **A széf beállítása.** Elmagyarázza a széfet. Új számítógépen itt a **Visszaállítás biztonsági mentésből…** is választható (lásd [14.3](#143-visszaállítás-új-számítógépen)). Kattints a **Tovább** gombra.
2. **Válassz mesterjelszót.** Legalább 10 karakter; egy hosszú kifejezést könnyebb megjegyezni és nehezebb kitalálni. A mező alatti jelzés értékeli (**Túl rövid**, **Gyenge – könnyű kitalálni**, **Közepes**, **Erős**); a gyenge jelszót elfogadja, de nem ajánlott. Írd be újra **A mesterjelszó még egyszer** mezőbe. Az **Automatikus feloldás** be van jelölve (lásd [11.2](#112-automatikus-feloldás)). Kattints a **Széf létrehozása** gombra.
3. **A helyreállítási kulcsod.** 24 betű és számjegy hat csoportban, például `7K2M-…-QX4T`. Ha elfelejted a mesterjelszót, csak ezzel a kulccsal juthatsz vissza a széfbe. Írd fel, vagy tárold egy jelszókezelőben: **csak most látható**. A **Másolás** kimásolja (lásd a vágólapról szóló megjegyzést a [10.](#10-biztonsági-megjegyzések) részben). Kattints az **Elmentettem** gombra.
4. **A helyreállítási kulcs ellenőrzése.** Írd be a kért csoportot (**Írd be a helyreállítási kulcs 3. csoportját, balról számolva.**), és kattints a **Megerősítés** gombra.
5. **A széf elkészült.** Kattints a **Kész** gombra.

Az ablaknak nincs alapértelmezett gombja: az Enter egy mezőben nem csinál semmit, kattints a gombokra. A helyreállítási kulcsban nem számít a kis- és nagybetű; az `O` `0`-nak, az `I` és az `L` `1`-nek számít, a kötőjelek és szóközök nem számítanak.

### 11.2 Automatikus feloldás

- **Bekapcsolva** (alapértelmezés): a széfkulcs a Windows Hitelesítőadat-kezelőjében van (`local.winvpn.vault`), így a WinVPN kérdés nélkül megnyílik. Hogy ez mi ellen véd, lásd a [10.](#10-biztonsági-megjegyzések) részben.
- **Kikapcsolva:** a WinVPN minden indításkor elkéri a mesterjelszót. Kikapcsoláshoz nyisd meg a popover **Beállítások** csoportját, kapcsold ki az **Automatikus feloldás** kapcsolót, és erősítsd meg a **Kikapcsolás** gombbal (**Kikapcsolod az automatikus feloldást?**). A hitelesítő adat törlődik a Hitelesítőadat-kezelőből.
- **Visszakapcsoláshoz** kapcsold be: **Az automatikus feloldás bekapcsolása** ablak elkéri a mesterjelszót; kattints a **Bekapcsolás** gombra.
- Ha a hitelesítő adat nem olvasható (például törölted a Hitelesítőadat-kezelőben), a WinVPN a mesterjelszót kéri.

### 11.3 Feloldás

**A WinVPN feloldása** ablak induláskor nyílik meg, ha a széf nem oldódik fel automatikusan, illetve a zárolt popover **Széf feloldása…** sorából. Add meg a **Mesterjelszó** mezőben, és kattints a **Feloldás** gombra.

Hibás jelszónál **Hibás jelszó vagy helyreállítási kulcs** jelenik meg. Minden további hibás próba után egyre többet kell várni (1, 2, 4, 8, 16, majd 30 másodperc; a gombon **Újrapróbálás 8 mp múlva** áll). Kizárás nincs. Ha elfelejtetted a jelszót, kattints a **Helyreállítási kulcs használata** gombra (lásd [11.8](#118-elfelejtett-mesterjelszó)).

### 11.4 Széf zárolása most

A popover alján lévő **Széf zárolása most** gomb azonnal zárolja a széfet. Akkor látszik, ha az **Automatikus feloldás** ki van kapcsolva, vagy ha a popover **Beállítások** csoportjában bekapcsolod a **„Széf zárolása most” megjelenítése** kapcsolót.

A zárolás bezárja a széfet, és törli a kulcsát a memóriából. A Hitelesítőadat-kezelőben lévő hitelesítő adatot **nem** törli: bekapcsolt **Automatikus feloldás** mellett a következő indítás ismét kérdés nélkül megnyílik. A Kapcsolatok ablak nem mentett változásai elvesznek, a mesterjelszó és a helyreállítási kulcs ablakai bezáródnak.

### 11.5 A zárolt popover

Amíg a széf zárolva van, a popoverben csak egy **Széf feloldása…** sor (**A WinVPN zárolva van**), az aktív kapcsolatok száma és a **Kilépés** látszik.

Zárolt széf mellett semmi sem működik, ami a széfet igényli: szerkesztés, import, export, a mappák (rejtve vannak, és nem módosíthatók: **A mappák nem módosíthatók, amíg a széf zárolva van**), a közös hitelesítő adatok, a csapatkatalógusok és a mentések. Ezek válasza: **A széf zárolva van. Oldd fel, és próbáld újra.** A párosított appok `locked` hibát kapnak.

### 11.6 A mesterjelszó módosítása

1. Popover → **Beállítások** → **Mesterjelszó módosítása…**.
2. Add meg a **Jelenlegi mesterjelszó** mezőt, majd kétszer az **Új mesterjelszó** mezőt.
3. Kattints a **Jelszó módosítása** gombra. **A mesterjelszó megváltozott**: mostantól az újat használd.

A helyreállítási kulcsod változatlan. A széf nem titkosítódik újra; csak a jelszóval becsomagolt kulcsa íródik újra. A hibás jelenlegi jelszót a feloldáshoz hasonlóan lassítja.

### 11.7 Új helyreállítási kulcs

Ha a helyreállítási kulcsodat valaki láthatta, vagy elvesztetted, de a mesterjelszót még tudod:

1. Popover → **Beállítások** → **Új helyreállítási kulcs…**.
2. Add meg a **Mesterjelszó** mezőt, és kattints az **Új kulcs készítése** gombra. Az új kulcs a régi helyébe lép: a régi azonnal érvényét veszti.
3. Mentsd el az új kulcsot (csak most látható), kattints az **Elmentettem** gombra, írd be a kért csoportot, és kattints a **Megerősítés** gombra.

### 11.8 Elfelejtett mesterjelszó

1. **A WinVPN feloldása** ablakban kattints a **Helyreállítási kulcs használata** gombra.
2. Írd be a **Helyreállítási kulcs** mezőt, majd kétszer az **Új mesterjelszó** mezőt.
3. Kattints a **Visszaállítás és feloldás** gombra.

A kapcsolataid változatlanok maradnak, és a helyreállítási kulcs továbbra is működik. **A mesterjelszó használata** visszavisz a jelszómezőhöz.

---

## 12. Mappák és színek

A mappák csoportosítják a kapcsolatokat a **Kapcsolatok** ablakban és a popoverben. Tetszőleges mélységig egymásba ágyazhatók.

### 12.1 Mappák

- **Létrehozás:** eszköztár **Új** (+) → **Új mappa**, vagy jobb kattintás egy mappára → **Új mappa** (almappa), vagy jobb kattintás egy kapcsolatra vagy üres területre → **Új mappa** (a legfelső szinten). Az új mappa neve „Új mappa”, és a névmezője nyitva van: írd be a nevet, és nyomj Entert.
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
- **A kapcsolatok** csak akkor változtatnak helyet, ha egy mappára ejted őket. Kivétel, ha egy kitűzött kapcsolatot ugyanannak a mappának egy másik kitűzött kapcsolatára ejtesz: ez a kitűzések sorrendjét változtatja meg.
- Húzás közben megjelenik egy **Legfelső szint** célterület: ide ejtve az elem minden mappából kikerül.
- Egy mappa nem ejthető önmagába vagy a saját almappájába: **Egy mappa nem helyezhető önmagába vagy a saját almappájába**.

### 12.5 Mappa törlése

A **Törlés…** megkérdezi: **Mi legyen a tartalmával?**

- Alapértelmezés: **A tartalma kerüljön a szülőmappába** (legfelső szintű mappánál **A tartalma kerüljön a legfelső szintre**). A kapcsolatok és az almappák megmaradnak.
- **A kapcsolatok is törlődjenek**: a mappa és almappái kapcsolatai a mentett jelszavaikkal együtt törlődnek. Előtte egy második megerősítés kérdez (**Törlöd a(z) 3 kapcsolatot?**, **Ez nem vonható vissza.**, **Kapcsolatok törlése**).

### 12.6 Mappák a popoverben

- A mappák nyitható-csukható sorok; a WinVPN megjegyzi, melyik van becsukva.
- A beágyazást behúzás jelzi, legfeljebb 3 szintig; a mélyebb mappák is működnek, de nem húzódnak be tovább.

### 12.7 Kapcsolatok keresése

A **Kapcsolatok** ablak oldalsávjának tetején lévő **Kapcsolatok keresése** mező (**Ctrl+F**) gépelés közben szűri a listát. A kis- és nagybetű meg az ékezet nem számít: az „arvizturo” megtalálja az „Árvíztűrő”-t. Keres a kapcsolat nevében, típusában, a szerverében (a beállításokból vagy a konfigurációból vett gépnév, például az OpenVPN első `remote` sora), a csapatkatalógusa nevében és a mappái nevében. A **↑** és **↓** a találatok között lép, az Enter megnyitja a kiemeltet, az Esc kiüríti a mezőt (a második Esc kilép belőle). Keresés közben a húzás nem működik. Ha nincs találat, a **Keresés törlése** visszahozza a teljes listát.

---

## 13. Közös hitelesítő adatok

A **közös hitelesítő adat** egy névvel ellátott felhasználónév és jelszó, amelyet több kapcsolat használ, például „Iroda AD”. Elég egyszer módosítani, és minden kapcsolat, amely használja, az újjal jelentkezik be. A jelszavak a széfben vannak, és sosem jelennek meg.

### 13.1 A Hitelesítő adatok rész

Nyisd meg a **Kapcsolatok** ablakot, és válaszd az oldalsáv **Hitelesítő adatok** pontját. Minden tételnél látszik a neve, a felhasználóneve (vagy **Nincs felhasználónév**), a **Jelszó mentve** vagy **Nincs mentett jelszó: kapcsolódáskor kérdezi**, és **3 kapcsolat használja**.

- **Hitelesítő adat hozzáadása…** → **Új közös hitelesítő adat**: **Név** (1–64 karakter), **Felhasználónév**, **Jelszó**. A jelszó nem kötelező.
- **Szerkesztés…**: a felhasználónév vagy a jelszó módosítása. A jelszómezőben **Mentve – írj be újat a cseréhez** áll, mint a szerkesztőkben.
- **Átnevezés…**: új név; a kapcsolódások megmaradnak.
- **Törlés**: a nem használt hitelesítő adat törlődik. Ha kapcsolatok használják, a WinVPN felsorolja őket, és megkérdezi: **Másolás minden kapcsolatba** (mindegyik saját felhasználónevet és jelszót kap belőle, majd a közös adat törlődik) vagy **Mégse**.

### 13.2 Létrehozás kapcsolatból

1. **Hitelesítő adatok** → **Létrehozás kapcsolatból…**.
2. Válaszd ki a **Kapcsolat** mezőt, adj **Név**-et, és kattints a **Tovább** gombra. A kapcsolat tárolt felhasználónevéből és jelszavából közös hitelesítő adat lesz, amelyet ezután használ. Az értékek nem jelennek meg.
3. Az **Összekapcsolod az azonos bejelentkezéseket?** lépés felsorolja a többi kapcsolatot, amelynek ugyanez a felhasználóneve és jelszava (a WinVPN belül hasonlítja össze, sosem mutatja). Jelöld be, melyek használják szintén, és kattints a **Létrehozás és összekapcsolás** gombra.

### 13.3 Használat egy kapcsolatban

A felhasználónevet és jelszót használó szerkesztőkben (OpenVPN `auth-user-pass`-szal, IKEv2 EAP-pal, SSTP, L2TP, Cisco IPsec) van egy **Jelszó forrása** választó:

- **Saját felhasználónév és jelszó** (alapértelmezés): a kapcsolat saját mezői.
- **Hitelesítő adat: Iroda AD**: a WinVPN megkérdezi: **Használod a(z) Iroda AD közös hitelesítő adatot?**, és jelzi, hogy a kapcsolathoz tárolt felhasználónév és jelszó törlődik. Kattints a **Használat** gombra. A kapcsolat saját mezői ezután rejtve vannak.

A többi titok (PSK, privát kulcs jelszava, egyszer használatos kód beállításai) kapcsolatonként marad. **A szerkesztő sosem módosítja a közös hitelesítő adatot**: egy kapcsolat mentése nem változtathatja meg azt, amit a többi kapcsolat használ. A közös hitelesítő adat csak a **Hitelesítő adatok** részben változik.

### 13.4 Import és export

- Az export csak a hitelesítő adat **nevét** írja ki (`credentialName` a `# macvpn-meta` sorban), a felhasználónevét és jelszavát sosem.
- Az import sosem kapcsol csendben hitelesítő adatot: az importált fájl maga választja a szerverét, és egy csendes kapcsolás oda küldené a közös jelszavadat. Ha van ilyen nevű hitelesítő adat, a WinVPN megkérdezi: **Használod a(z) „Iroda AD” közös hitelesítő adatot ehhez a(z) vpn.example.com szerverre csatlakozó kapcsolathoz?**, a fájlból kiolvasott szerverrel. A **Saját adatok használata** (a biztonságos választás) a kapcsolat saját felhasználónevét és jelszavát hagyja meg; a **Közös hitelesítő adat használata** gombot csak akkor válaszd, ha megbízol a fájlban.
- A párosított appok (vezérlő API) sosem látják a közös hitelesítő adatokat.

---

## 14. Biztonsági mentés és visszaállítás

A kapcsolatonkénti export (lásd [4.](#4-import-és-export)) sosem tartalmaz jelszót. A Windows újratelepítéséhez vagy egy másik számítógépre költözéshez **teljes biztonsági mentés** van: egyetlen titkosított fájl, benne minden. A WinVPN és a MacVPN ugyanazt a mentési formátumot használja, így Macről számítógépre is így költözhetsz.

### 14.1 Mi van a mentésben

- minden kapcsolat a configjával és a titkaival,
- a mappák, színek, a sorrend, a kitűzések és a használati rangsor,
- a közös hitelesítő adatok,
- az app beállításai, köztük az **Indítás bejelentkezéskor**, a **Más appok vezérelhetik a VPN-eket** és az **Automatikus feloldás**,
- a **csapatkatalógus-feliratkozásaid**, az **adminisztrátori aláírókulcsaid** és a **közzétételeid** a csapatkulcsaikkal. Maguk a katalógus kapcsolatai és mappái nincsenek a mentésben: visszaállítás után a következő frissítés visszahozza őket a forrásból.

Az aláírókulcsot tartalmazó mentéssel katalógust lehet aláírni a csapatodnak: úgy védd, mint magát az aláírókulcsot. Nincs benne: a **párosított appok** (ezen a számítógépen lévő programútvonalakhoz kötődnek: visszaállítás után párosítsd őket újra), a széfkulcs és a helyreállítási kulcs.

### 14.2 Teljes biztonsági mentés

1. Popover → **Beállítások** → **Teljes biztonsági mentés…** (vagy a Kapcsolatok ablakban **Új** (+) → **Teljes biztonsági mentés…**). Feloldott széf kell hozzá.
2. Olvasd el a figyelmeztetést: **Aki birtokolja ezt a fájlt és a jelszavát, az összes VPN-hitelesítő adatodat elolvashatja.**
3. Válassz egy **A mentés jelszava** jelszót (legalább 10 karakter), és ismételd meg. A WinVPN nem tárolja: nélküle a mentés nem nyitható meg.
   - Helyette **A mesterjelszavam használata…** gombbal a mesterjelszót is használhatod, a **Mesterjelszó használata** megerősítése után. Akkor viszont bárki, aki megtudja a mesterjelszavadat, ezt a fájlt is megnyithatja; egy külön mentési jelszó elválasztja a kettőt.
   - Írd be a **Mesterjelszó** mezőbe a mesterjelszót is. A WinVPN minden mentés előtt ellenőrzi, így egy felügyelet nélkül hagyott, feloldott számítógép nem elég ahhoz, hogy valaki minden jelszavadról másolatot vigyen.
4. Kattints a **Mentés…** gombra, és válaszd ki a helyét. A fájl neve `WinVPN-backup-<dátum>.macvpnbackup` (a `.macvpnbackup` a MacVPN és a WinVPN közös formátuma), csak te olvashatod.
5. A fájlt és a jelszavát tartsd külön, például a fájlt egy külső lemezen, a jelszót egy jelszókezelőben.

### 14.3 Visszaállítás új számítógépen

1. Telepítsd a WinVPN-t, és indítsd el.
2. A **Széf beállítása** ablakban kattints a **Visszaállítás biztonsági mentésből…** gombra. (Ehhez új, üres széf kell.) A MacVPN-nel készült mentés is használható.
3. **Fájl kiválasztása…**, add meg **A mentés jelszava** mezőt, és kattints a **Mentés megnyitása** gombra.
4. Válassz új mesterjelszót ehhez a számítógéphez, és mentsd el az új helyreállítási kulcsot, ahogy a [11.1](#111-mesterjelszó-és-helyreállítási-kulcs) leírja.
5. Minden egy lépésben visszaáll. Utána kövesd a [14.5](#145-visszaállítás-után) lépéseit.

### 14.4 Visszaállítás meglévő széfbe

1. Popover → **Beállítások** → **Visszaállítás biztonsági mentésből…**. Semmi sem változik, amíg jóvá nem hagyod, mit állítson vissza.
2. **Fájl kiválasztása…**, **A mentés jelszava**, **Mentés megnyitása**. Hibás jelszónál vagy sérült fájlnál egyetlen üzenet jön: **A mentés nem nyitható meg. Hibás a jelszó, vagy sérült a fájl.**
3. Az összesítő megmutatja, mikor készült, és hány **Kapcsolatok**, **Mappák** és **Közös hitelesítő adatok** tétel van benne. Elöl felsorolja azokat a kapcsolatokat, amelyeknél kockázatos OpenVPN-beállítások vannak jóváhagyva: csak saját készítésű mentést állíts vissza.
4. Válassz:
   - **Összefésülés**: hozzáadja, ami itt hiányzik. A már létező elemekre egyszer, mindegyikre érvényesen döntesz: **Felülírás a mentésben lévő példánnyal**, **Az itt lévő elem megtartása**, vagy **Mindkettő megtartása (a mentésből származó másolat neve „(backup)” végződést kap)**. Az összefésülés elveti a visszaállított kapcsolatok kockázatos beállításainak jóváhagyását, hacsak ugyanez a kapcsolat ugyanezzel a configgal már nincs itt.
   - **Minden cseréje**: előbb kiüríti a széfet. Egy megerősítés megmondja, hány kapcsolat, mappa és közös hitelesítő adat törlődik; **Ez nem vonható vissza.** Az **Előbb a jelenlegi állapot mentése…** gomb a folytatás előtt elmenti a mostani állapotot. A párosított appok maradnak. A csapatkatalógus-feliratkozások helyére a mentésben lévők kerülnek; azok az aláírókulcsok és közzétételek, amelyek nincsenek a mentésben, ezen a számítógépen maradnak.
5. **A mentés visszaállítva.**

Ha bármi hibára fut: **A visszaállítás nem sikerült. Semmi sem változott.**

### 14.5 Visszaállítás után

- **Beállítások.** **A mentés beállításai maguktól nem lépnek életbe.** Minden sor mutatja a mentés és ennek a számítógépnek az értékét (**Mentés: Be · Ez a számítógép: Ki**). Jelöld be azokat, amelyeket ezen a számítógépen használnál, és kattints **A kijelölt beállítások alkalmazása** gombra. A **Más appok vezérelhetik a VPN-eket** sosincs előre bejelölve: csak akkor jelöld be, ha ezen a számítógépen párosított appokat használsz, és párosítsd őket újra.
- **Natív kapcsolatok.** **A WinVPN megírta az L2TP kapcsolatok Windows VPN-bejegyzéseit. Az IKEv2 és SSTP kapcsolatok az első csatlakozáskor kapják meg a sajátjukat.** Minden visszaállított L2TP-kapcsolat **Kész** állapotú. Az a kapcsolat, amelyet a Windows nem tud futtatni (egy Macről jött Cisco IPsec kapcsolat, egy PSK-s IKEv2 config), visszaáll, és helyette az okával együtt látszik (lásd [3.4](#34-l2tpipsec-és-cisco-ipsec)).
- Egy MacVPN-mentésben rendszer VPN-ek tárolt titkai is lehetnek: ezek csak egy azonos azonosítójú Windows VPN-re érvényesek, ezért a Windows VPN-jeidhez add meg őket újra (lásd [3.5](#35-rendszer-vpn-ek-a-saját-windows-vpn-jeid)).

### 14.6 A mentés nem megbízható bemenet

Aki ismeri egy mentés jelszavát, készíthet is ilyet, ezért a WinVPN minden elemet a szerkesztőkkel azonos szabályokkal ellenőriz, mielőtt bármit írna. Az érvénytelen mentést egészében elutasítja (**Ez a mentés nem állítható vissza: olyan adatot tartalmaz, amelyet a WinVPN nem fogad el.**). Az újabb verzióval készült mentést elutasítja, és a WinVPN frissítését kéri. A visszaállítás sosem kapcsolja be magától a vezérlő API-t.

---

## 15. Gyakori kérdések a széfről

**Elfelejtettem a mesterjelszót.**
**A WinVPN feloldása** ablakban kattints a **Helyreállítási kulcs használata** gombra, és a helyreállítási kulccsal adj meg új mesterjelszót ([11.8](#118-elfelejtett-mesterjelszó)). Bekapcsolt **Automatikus feloldás** mellett a WinVPN jelszó nélkül is megnyílik, de a **Mesterjelszó módosítása…** és az **Új helyreállítási kulcs…** kéri: zárold a WinVPN-t (**Széf zárolása most**), majd állítsd vissza a jelszót a helyreállítási kulccsal.

**Elvesztettem a helyreállítási kulcsot.**
Ha a mesterjelszót még tudod, azonnal készíts újat: **Beállítások → Új helyreállítási kulcs…** ([11.7](#117-új-helyreállítási-kulcs)). Ha a mesterjelszót és a helyreállítási kulcsot is elvesztetted: bekapcsolt **Automatikus feloldás** mellett a WinVPN továbbra is megnyitja a széfet, de semmi nem működik, ami a mesterjelszót kéri (a módosítása, új helyreállítási kulcs, új mentés); exportáld most a szükséges kapcsolatokat. Kikapcsolt **Automatikus feloldás** mellett a széfet senki nem tudja megnyitni, a WinVPN sem.

**A WinVPN azt írja, hogy zárolva van.**
Kattints a popoverben a **Széf feloldása…** sorra, és add meg a mesterjelszót. Ha minden indításkor zárolva van, az **Automatikus feloldás** ki van kapcsolva, vagy a hitelesítő adata hiányzik a Hitelesítőadat-kezelőből: kapcsold be a **Beállítások** alatt ([11.2](#112-automatikus-feloldás)).

**„A széf sérült, és nem nyitható meg.”**
A `vault.db` vagy a `vault.keys` megváltozott vagy hiányos. Állítsd vissza egy mentésből ([14.](#14-biztonsági-mentés-és-visszaállítás)), vagy lépj ki a WinVPN-ből, és tedd vissza mindkét fájl egy másolatát (amely akkor készült, amikor a WinVPN nem futott).

**Hogyan törölhetek mindent?**
**Rendszerállapot → WinVPN eltávolítása erről a fiókról…**, bejelölt **A felhasználói adatok törlése is** négyzettel (lásd [9.](#9-eltávolítás)), utána töröld a `.macvpnbackup` fájljaidat.

---

## 16. Csapatkatalógusok

A **csapatkatalógus** VPN-kapcsolatokat oszt meg egy csapattal. A közzétevő (a rendszergazda) egyszer közzétesz egy kapcsolatkészletet, a mappáikkal, színeikkel és névvel ellátott bejelentkezési helyekkel együtt. A csapattagok WinVPN-je vagy MacVPN-je feliratkozik rá, és magától átveszi az új, a módosult és a törölt kapcsolatokat. Mindenki megtartja a saját felhasználónevét és jelszavát, valamint a saját kitűzéseit, sorrendjét és csukott mappáit.

- A katalógus egyetlen fájl, `<név>.macvpncatalog`. A rendszergazda **adminisztrátori aláírókulcsa** **aláírja**, a **csapatkulcs** pedig **titkosítja**. A WinVPN és a MacVPN ugyanazokat a katalógusokat olvassa és teszi közzé.
- A WinVPN semmit nem tölt fel. A rendszergazda a fájlt egy HTTPS-webszerverre, egy fájlmegosztásra vagy egy szinkronizált mappába teszi, és a tagok onnan olvassák.

Amit a tag a rendszergazdától kap: a **forrás** (egy `https://` cím vagy egy fájl útvonala), a **csapatkulcs** (`TEAM-`, utána 14 darab 4 karakteres csoport) és a **közzétevő ujjlenyomata** (8 darab 4 hexadecimális jegyből álló csoport). A **feliratkozási kód** (`macvpn-sub:…`) mindhármat egy sorban tartalmazza.

### 16.1 Feliratkozás egy katalógusra

1. Nyisd meg a **Kapcsolatok** ablakot, és az oldalsávban válaszd a **Csapatkatalógusok** részt. Kattints a **Csapatkatalógus hozzáadása…** gombra.
2. Illeszd be a rendszergazdától kapott **feliratkozási kódot**. Ez kitölti a forrást és az ujjlenyomatot; a csapatkulcsot ellenőrzi, és rejtve tartja. Feliratkozási kód nélkül töltsd ki magad a mezőket:
   - **Forrás:** egy `https://` cím, vagy **Fájl** és **Fájl kiválasztása…** egy hálózati megosztáson vagy szinkronizált mappában (OneDrive, Dropbox) lévő fájlhoz.
   - **Hozzáférési token** (nem kötelező, csak HTTPS-nél): ha a webszerver bearer tokent kér, itt add meg. Nem része a feliratkozási kódnak; kérdezd a rendszergazdát.
   - **Csapatkulcs:** `TEAM-XXXX-…`. A kis- és nagybetű, a kötőjel és a szóköz nem számít; az `O` `0`-nak, az `I` és az `L` `1`-nek számít. Az utolsó csoport ellenőrző csoport, így az elírás már beíráskor kiderül.
   - **A közzétevő ujjlenyomata:** 8 darab 4 karakteres csoport. Kötelező: a WinVPN nélküle sosem bízik meg az első letöltésben.
3. Kattints az **Ellenőrzés** gombra. A WinVPN beolvassa a katalógust, a megadott ujjlenyomattal ellenőrzi az aláírását, és a csapatkulccsal megnyitja. Az előnézet mutatja a katalógus nevét, verzióját és ujjlenyomatát, a kapcsolatok és mappák számát, a közös belépési adatok helyeit, és hogy hány kapcsolatban van kockázatos beállítás.
4. **Hasonlítsd össze az ujjlenyomatot** azzal, amit a rendszergazda egy másik csatornán, például telefonon mondott. Ha eltér, ne iratkozz fel.
5. Jelöld be **Az ujjlenyomat egyezik azzal, amit a rendszergazda küldött** négyzetet, és kattints a **Feliratkozás** gombra. A katalógus kapcsolatai azonnal megjelennek.

**A Fájlkezelőből.** Kattints duplán egy `.macvpncatalog` fájlra. A WinVPN megnyitja a **Csapatkatalógusok** részt a **Csapatkatalógus hozzáadása…** ablakkal: a forrás **Fájl**, és ez a fájl van kiválasztva. A csapatkulcsot és a közzétevő ujjlenyomatát ugyanúgy neked kell megadnod, az **Ellenőrzés** után összevetni az ujjlenyomatot és bejelölni a négyzetet: a fájl megnyitása önmagában semmire nem iratkoztat fel.

**HTTPS-forrás.** Csak `https://`, a Windows megbízható tanúsítványai alapján ellenőrizve, a Windows saját `curl.exe` programjával (a `System32` mappából), üres környezettel letöltve; átirányítás csak `https://` címre, legfeljebb 5; a hozzáférési token csak a feliratkozási cím saját hosztjára és portjára megy, és sosem kerül parancssorba. **Proxy nem támogatott:** a katalógus hosztjának közvetlenül elérhetőnek kell lennie. A fájlt nem módosító szerver „nem változott” választ ad.

**Fájlforrás.** Egy hálózati megosztáson (csatlakoztatott meghajtón vagy `\\szerver\megosztás\…` útvonalon) vagy szinkronizált mappában lévő útvonal. Maga a fájl nem lehet link, szabályos fájlnak kell lennie, legfeljebb 8 MB-osnak. Az el nem érhető megosztás, vagy egy éppen le nem tölthető felhőbeli fájl **nem elérhető** állapotot jelent, nem hibát. A fájlt azon az útvonalon válaszd ki, amelyet a tagok számítógépei használnak.

### 16.2 A katalógus kapcsolatai

- Minden katalógusnak saját, legfelső szintű mappája van a katalógus nevével és **Csapat** jelvénnyel. Benne vannak a közzétevő mappái és színei.
- **Csak olvasható:** a név, a config, a mappa és a közzétevő színe. A szerkesztő kiírja: **A(z) „Acme VPN” csapatkatalógus kezeli**.
- **Amit te állíthatsz:** kitűzés és sorrend, mappák csukása, egy kapcsolat saját színe, és a kockázatos beállítások jelölője. A felhasználóneved és a jelszavad a katalógus közös belépési adatának helyéből jön (lásd [16.3](#163-közös-belépési-adatok-helyei)). A **Másolat saját kapcsolatként…** önálló, szerkeszthető másolatot készít a legfelső szinten.
- A **párosított appok** a katalógus kapcsolatait ugyanúgy látják, mint a többit; kapcsolatonként engedélyezed őket.

### 16.3 Közös belépési adatok helyei

A **közös belépési adat helye** egy névvel ellátott bejelentkezés, például „Office AD”, amelyet a katalógus felhasználónév és jelszó nélkül használ. A katalógus első alkalmazásakor a WinVPN minden helyhez létrehoz egy üres **közös hitelesítő adatot** (lásd [13.](#13-közös-hitelesítő-adatok)) a hely nevével; a saját felhasználónevedet és jelszavadat a **Hitelesítő adatok** részben add meg. Ezek a széfedben maradnak: sosem jutnak el a rendszergazdához vagy a katalógusba.

### 16.4 Frissítés és változások

A WinVPN minden katalógust ellenőriz induláskor és a széf feloldásakor, 15 percenként, amikor a számítógép felébred alvó állapotból, és amikor a **Csapatkatalógusok** részben a **Frissítés most** gombra kattintasz. Ha egy forrás tartósan hibás, a WinVPN egyre ritkábban próbálkozik (legfeljebb óránként); az ébredés és a **Frissítés most** mindig azonnal próbálkozik.

Az új verzió egyetlen lépésben kerül alkalmazásra: vagy minden, vagy semmi. Egy értesítés felsorolja a változásokat, például: **A(z) „Acme VPN” csapatkatalógus frissült: 2 hozzáadva, 3 módosítva, 1 eltávolítva**. Ugyanaz a verzió újra elmentve semmit nem változtat.

### 16.5 Feliratkozás módosítása és leiratkozás

- A feliratkozás részleteiben a **Csapatkulcs cseréje…** (ha a rendszergazda lecserélte), a **Hozzáférési token cseréje…** és a **Forrás szerkesztése…** található. Ha az új forrás másik hoszton vagy porton van, vagy fájl, a tárolt hozzáférési token törlődik: a token sosem megy új címre.
- A **Leiratkozás…** megnevezi a katalógust, és hogy hány kapcsolatot töröl. A katalógus minden kapcsolata és mappája törlődik, és a párosított appok elveszítik hozzájuk a hozzáférést. A kitöltött közös belépési adatok helyei közönséges közös hitelesítő adatként megmaradnak.

### 16.6 Hibaelhárítás felhasználóknak

- **A katalógust más kulcs írta alá, mint amelynek az ujjlenyomatát megadtad.**: a fájlt nem az a kulcs írta alá, amelyet a rendszergazda adott. Ellenőrizd az ujjlenyomatot a rendszergazdával telefonon.
- **A csapatkatalógust más közzétevő írta alá, mint akiben megbízol.**: kérdezd meg a rendszergazdát; lehet, hogy az új ujjlenyomattal újra fel kell iratkoznod.
- **A(z) „Acme VPN” csapatkulcsa megváltozott. Kérd el a rendszergazdától az új kulcsot.**: kérd el az új kulcsot biztonságos csatornán, majd **Csapatkulcs cseréje…** és **Frissítés most**.
- **A(z) „Acme VPN” csapatkatalógus régebbi verziót kínált (v3 a v5 után), ezért nem lett alkalmazva.**: a visszaléptetés elleni védelem (lásd [16.11](#1611-biztonsági-modell)). Szólj a rendszergazdának; egy új verzió közzététele megoldja.
- **A csapatkatalógus nem olvasható: hozzáférés megtagadva (ellenőrizd a hozzáférési tokent)**: a HTTPS-szerver elutasította a kérést (HTTP 401 vagy 403). Add meg az aktuális tokent a **Hozzáférési token cseréje…** gombbal.
- **A csapatkatalógus forrása nem érhető el (…).**: a megosztás nem érhető el, vagy egy felhőbeli fájl éppen nem tölthető le. A WinVPN később újra megpróbálja; a **Frissítés most** gombra is kattinthatsz.

### 16.7 Rendszergazdáknak: az adminisztrátori aláírókulcs

A közzétételhez **adminisztrátori aláírókulcs** kell: egy Ed25519 aláírókulcs a széfedben. Az **ujjlenyomatát** veti össze a csapat feliratkozáskor.

1. **Kapcsolatok** ablak → **Közzététel** → **Adminisztrátori aláírókulcs létrehozása**. Az ujjlenyomat 8 csoportban jelenik meg; a **Másolás** kimásolja.
2. **Tartalék aláírókulcs létrehozása**, majd **Tartalék kulcs exportálása…**: válaszd ki a `.macvpnadminkey` fájl helyét, és adj meg (kétszer) egy legalább 10 karakteres jelszót. Jelöld be ezt: **A tartalék kulcs törlése erről a számítógépről az export után**. A fájlt offline tartsd, a jelszavát máshol.

A tartalék kulcsra váltáshoz azon a számítógépen, amelyről ezután közzéteszel, **Aláírókulcs importálása…** (ott a közzétételeidnek is meg kell lenniük: ugyanazt a széfet használd, vagy előbb állíts vissza egy teljes biztonsági mentést), majd **Váltás a tartalék kulcsra…**, tedd közzé minden katalógus új verzióját, és készíts új tartalék kulcsot.

### 16.8 Rendszergazdáknak: katalógus közzététele

A **Közzététel** → **Katalógus közzététele…** megnyitja a varázslót: **Kapcsolatok** (jelöld be a mappákat és a kapcsolatokat), **Áttekintés** (a katalógus tartalma; a **Csapattitkok** alatt csak azokat a titkokat jelöld be, amelyeket a csapatban mindenki ismerhet, a **Közös belépési adatok helyei** alatt pedig a névvel ellátott bejelentkezéseket, felhasználónév és jelszó nélkül), **Név és fájl** (a `<név>.macvpncatalog` mentési helye; **A WinVPN semmit nem tölt fel: a fájlt te tedd a webszerveredre vagy a megosztásra.**), végül **Kész**. Új katalógusnál a **csapatkulcs csak egyszer jelenik meg**: **Másold** ki, tartsd biztonságban, kattints az **Elmentettem** gombra, és írd be a kért csoportot. Utána **Feliratkozási kód másolása…**.

Mindig ugyanoda tedd közzé, hogy a tagok forrása érvényes maradjon. Fájlmegosztáson a fájlt egészében cseréld (a WinVPN így írja, ha közvetlenül oda mented). A fájlt a számítógép minden felhasználója olvashatja (megosztásra készül; alá van írva és titkosítva van).

### 16.9 Rendszergazdáknak: a csapatkulcs és a feliratkozási kód

- A **csapatkulcs** 256 véletlen bit, a katalógus első közzétételekor készül, és **csak egyszer jelenik meg**.
- A **Feliratkozási kód másolása…** kéri a **mesterjelszavadat** és azt a forrást, amelyet a csapat használni fog (az útvonalat úgy, ahogy a tagok számítógépein látszik). A `macvpn-sub:…` kódot megjelenítés nélkül a vágólapra teszi. A kód tartalmazza a csapatkulcsot: csak biztonságos csatornán küldd el. Az ujjlenyomatot külön mondd meg a tagoknak.
- A **Csapatkulcs cseréje…** (annak kizárására, aki elhagyta a csapatot) új csapatkulcsot készít, és a következő verzióként közzéteszi. **A csapatkulcs cseréje az egyetlen módja annak, hogy valakitől visszavond a hozzáférést egy olyan katalógushoz, amely már nála van.**

### 16.10 Az aláírókulcs cseréje és a kompromittálódás

A tartalék kulcsra váltás tervezett kulcscsere, **nem helyreállítás kompromittálódás után**. Ha az aláírókulcs kiszivároghatott: hozz létre új aláírókulcsot egy megbízható számítógépen, tedd közzé a kapcsolatokat új katalógusként, töröld a régi katalógusfájlt a megosztásról, és küldd el minden tagnak az új feliratkozási kódot és ujjlenyomatot megbízható csatornán. A régi katalógus csapattitkait is változtasd meg. Ha csak a csapatkulcs szivárgott ki, cseréld le.

### 16.11 Biztonsági modell

- **Aláírás (adminisztrátori aláírókulcs, Ed25519).** Minden katalógus alá van írva; a WinVPN az ujjlenyomattal rögzített közzétevői kulccsal ellenőrzi az aláírást, mielőtt bármit visszafejtene vagy használna. Véd a módosítás ellen bárkitől, akinek nincs meg az aláírókulcs, azoktól is, akik a megosztást írhatják; nem véd kiszivárgott aláírókulcs ellen, és az ellen, hogy a rendszergazda rossz dolgot tesz közzé.
- **Titkosítás (csapatkulcs, XChaCha20-Poly1305).** A tartalom a csapatkulccsal titkosított. Aki birtokolja a csapatkulcsot, a csere előtt távozott tagot is beleértve, mindent elolvashat a katalógusban, a bejelölt csapattitkokat is.
- **Visszaléptetés elleni védelem.** Minden feliratkozás megjegyzi a legutóbb alkalmazott verziót; alacsonyabb verziót figyelmeztetéssel elutasít.
- **Ellenőrzés, mint importnál.** A katalógus minden configja ugyanazokon a validátorokon megy át, mint egy import, és a kockázatos beállításokhoz minden tag saját jóváhagyása kell. A katalógus nem vihet felhasználói jelszót.
- **A titkaid.** A csapatkulcs a széfben van, és a teljes mentésben; sosem kerül naplóba. A feliratkozási kód és a csapatkulcs **Másolás** gombja a [10.](#10-biztonsági-megjegyzések) részben leírt védett vágólapot használja.
