# WinVPN – Hogyan csináld

[English version](winvpn-how-to.en.md)

Rövid, lépésenkénti útmutatók a WinVPN 2.0-hoz, Windows 10-en és 11-en. A részleteket a [WinVPN felhasználói útmutató](winvpn-user-guide.hu.md) írja le; a lenti linkek annak fejezeteire mutatnak. (MacVPN Macen: [MacVPN – Hogyan csináld](how-to.hu.md).)

## Tartalom

1. [A WinVPN telepítése MSI-ből](#1-a-winvpn-telepítése-msi-ből)
2. [A beállítás befejezése](#2-a-beállítás-befejezése)
3. [Kapcsolat felvétele](#3-kapcsolat-felvétele)
4. [Csatlakozás és bontás](#4-csatlakozás-és-bontás)
5. [Kód vagy bejelentkezés kérése (MFA)](#5-kód-vagy-bejelentkezés-kérése-mfa)
6. [Kapcsolatok kitűzése és sorrendje](#6-kapcsolatok-kitűzése-és-sorrendje)
7. [Napló megtekintése és mentése hibakereséshez](#7-napló-megtekintése-és-mentése-hibakereséshez)
8. [Export és mentés](#8-export-és-mentés)
9. [A WinVPN frissítése](#9-a-winvpn-frissítése)
10. [A WinVPN indítása bejelentkezéskor](#10-a-winvpn-indítása-bejelentkezéskor)
11. [A WinVPN eltávolítása](#11-a-winvpn-eltávolítása)
12. [Gyakori hibák](#12-gyakori-hibák)
13. [Frissítés az 1.5-ös előzetesről](#13-frissítés-az-15-ös-előzetesről)
14. [A széf beállítása, zárolása és feloldása](#14-a-széf-beállítása-zárolása-és-feloldása)
15. [Kapcsolatok mappákba rendezése](#15-kapcsolatok-mappákba-rendezése)
16. [Egy bejelentkezés több kapcsolathoz](#16-egy-bejelentkezés-több-kapcsolathoz)
17. [Teljes mentés és visszaállítás](#17-teljes-mentés-és-visszaállítás)
18. [Feliratkozás egy csapatkatalógusra](#18-feliratkozás-egy-csapatkatalógusra)
19. [Kapcsolatok megosztása a csapattal (katalógus közzététele)](#19-kapcsolatok-megosztása-a-csapattal-katalógus-közzététele)
20. [Egy csapattag hozzáférésének visszavonása (csapatkulcs cseréje)](#20-egy-csapattag-hozzáférésének-visszavonása-csapatkulcs-cseréje)
21. [Az aláírókulcs átvitele új számítógépre](#21-az-aláírókulcs-átvitele-új-számítógépre)
22. [A Windowsban beállított VPN használata](#22-a-windowsban-beállított-vpn-használata)
23. [Macről jött Cisco IPsec kapcsolat használata](#23-macről-jött-cisco-ipsec-kapcsolat-használata)
24. [Tesztelés a VPN-laborral (tesztelőknek)](#24-tesztelés-a-vpn-laborral-tesztelőknek)
25. [A megjelenés és a kapcsolatértesítések beállítása](#25-a-megjelenés-és-a-kapcsolatértesítések-beállítása)
26. [Automatikus újracsatlakozás alvás után](#26-automatikus-újracsatlakozás-alvás-után)
27. [Csatlakozás UniFi, pfSense vagy OPNsense VPN-hez](#27-csatlakozás-unifi-pfsense-vagy-opnsense-vpn-hez)

---

## 1. A WinVPN telepítése MSI-ből

Windows 10 vagy 11 kell, és egy rendszergazda a telepítéshez.

1. Töltsd le a `WinVPN-x.y.z-x64.msi` (a legtöbb számítógéphez) vagy a `WinVPN-x.y.z-arm64.msi` (ARM-gépekhez) fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Kattints rá duplán. A SmartScreen figyelmeztethet (**A Windows megvédte a számítógépet**): **További információ** → **Futtatás mindenképp**. Egy rendszergazda megerősíti a kérdést.
3. Indítsd el a **WinVPN**-t a Start menüből. Egy pajzs jelenik meg az értesítési területen, és megnyílik a **Széf beállítása** ablak: válassz mesterjelszót, és mentsd el a helyreállítási kulcsot ([14. pont](#14-a-széf-beállítása-zárolása-és-feloldása)).

A telepítő a **WinVPN szolgáltatást** is felveszi, amely az OpenVPN- és WireGuard-kapcsolatokat építi fel. Részletek: [útmutató, 1.](winvpn-user-guide.hu.md#1-telepítés)

## 2. A beállítás befejezése

A **Rendszerállapot** ablak magától megnyílik, ha valami hiányzik (később: popover → **Rendszerállapot**). Az, hogy az OpenVPN Community nincs telepítve, nem számít ide: nem kötelező.

1. A **WinVPN szolgáltatás** és a **WireGuard** sor a telepítés után rögtön zöld.
2. **OpenVPN Community** (csak ha OpenVPN-t használsz): **Telepítés**, egy rendszergazda megerősíti (Windows 11-en a winget egyszer, utána a WinVPN még egyszer kérdez). A kimenet a sor alatt látszik.
3. A **Windows VPN-kliens** (L2TP/IPsec, IKEv2, SSTP) a Windows része, zöld.
4. Ha a sorok zöldek, kész vagy.

Részletek: [útmutató, 2.](winvpn-user-guide.hu.md#2-első-indítás-és-a-rendszerállapot-ablak)

## 3. Kapcsolat felvétele

Popover → **Új kapcsolat / Import…** (vagy **Kapcsolatok kezelése…**). Ez a **Kapcsolatok** ablakot nyitja meg.

- **Fájlból:** **Új (+)** → **Import fájlból…**, vagy húzd a `.ovpn`, `.conf`, `.sstp` vagy strongSwan fájlt a listára. A `.ovpn` által hivatkozott fájlok (`ca.crt`, …) legyenek mellette. A Fájlkezelőben a `.ovpn` vagy `.sstp` fájlra duplán kattintva is importálódik.
- **Kézzel:** **Új (+)** → OpenVPN, WireGuard, IKEv2, SSTP vagy L2TP. Töltsd ki a sablont vagy az űrlapot, és kattints a **Mentés** gombra (Ctrl+S).
- **L2TP/IPsec:** szerver, fióknév, jelszó és PSK; a **Mentés** azonnal megírja a Windows VPN-bejegyzését, nincs mit jóváhagyni.
- **IKEv2:** EAP-MSCHAPv2-t (felhasználónév és jelszó) vagy számítógép-tanúsítványt használj; előre megosztott kulcsos IKEv2-t a Windows nem támogat. A szerkesztő alatti szürke sor mutatja, mit használ a Windows.
- **SSTP céges CA-val:** válaszd a **Saját CA fájl** módot, majd **A CA megbízhatóvá tétele a Windowsban…** (egy rendszergazda egyszer megerősíti).

A szürke kapcsolat megmondja, miért nem tudja a Windows futtatni. Az **Új** csak az itt használható típusokat kínálja (Cisco IPsec-et soha). Részletek: [útmutató, 3.](winvpn-user-guide.hu.md#3-kapcsolatok-felvétele-típusonként)

## 4. Csatlakozás és bontás

- **Popover:** kattints a kapcsolat kártyáján a kapcsolóra. Zöld = kapcsolódva, borostyán = csatlakozik vagy rád vár, piros = hiba.
- **Kapcsolatok ablak:** **Csatlakozás** / **Bontás**.
- Ha a WinVPN felhasználónevet, jelszót vagy PSK-t kér (**Hitelesítő adatok szükségesek**), add meg; a **Mentés a széfbe** megtartja a következő alkalomra.
- Ha élő kapcsolatokkal lépsz ki a WinVPN-ből, válaszd a **Leállítás és kilépés** vagy a **Kilépés, fussanak tovább** lehetőséget. A Windowsból való kijelentkezés mindig bontja a kapcsolataidat.

Részletek: [útmutató, 5.](winvpn-user-guide.hu.md#5-csatlakozás)

## 5. Kód vagy bejelentkezés kérése (MFA)

1. Ha a szerver kódot kér, egy kis ablak jelenik meg (és egy „…: hitelesítés szükséges” értesítés). Kattints rá, írd be a kódot, és kattints a **Tovább** gombra, 2 percen belül.
2. Böngészős bejelentkezésnél kattints a **Megnyitás a böngészőben** gombra, jelentkezz be vagy hagyd jóvá a push-t, és térj vissza; a WinVPN legfeljebb 5 percig vár.
3. Ha a szerver a jelszó után várja a kódot: a kapcsolat beállításainál kapcsold be az **Egyszer használatos kód kérése csatlakozáskor, a jelszó végére fűzve** lehetőséget, és válaszd ki az **Elválasztó**t.

Részletek: [útmutató, 5.2](winvpn-user-guide.hu.md#52-többfaktoros-hitelesítés-mfa).

## 6. Kapcsolatok kitűzése és sorrendje

Jobb kattintás egy kapcsolatra a **Kapcsolatok** ablakban → **Kitűzés**. Egy kitűzött kapcsolatot egy másik kitűzöttre húzva átrendezheted. A többit a használat sorolja. Részletek: [útmutató, 5.1](winvpn-user-guide.hu.md#51-a-kapcsolatok-sorrendje).

## 7. Napló megtekintése és mentése hibakereséshez

1. Alt+kattintás a kapcsolón a popoverben (vagy **Csatlakozás debug módban** a Kapcsolatok ablakban). A **Napló** fül megnyílik, és élőben követi.
2. Szűrj a **Hibák** gombbal, keress, majd **Mentés…** (`<név>-naplo.txt`). Jelszó, PSK és kód sosem kerül bele, így elküldheted a hálózati rendszergazdának.

Részletek: [útmutató, 6.](winvpn-user-guide.hu.md#6-debug-mód-és-a-napló) és [7.](winvpn-user-guide.hu.md#7-hibaelhárítás-a-napló-alapján)

## 8. Export és mentés

- **Egy kapcsolat:** az export ikon a fejlécében. Jelszó sosem kerül az exportba; privát kulcsoknál választhatsz: **Exportálás kulcsok nélkül** vagy **Exportálás kulcsokkal**. Egy L2TP-kapcsolat macOS-es `.mobileconfig` fájlként exportálódik.
- **Minden:** lásd a [17. pontot](#17-teljes-mentés-és-visszaállítás).

Részletek: [útmutató, 4.](winvpn-user-guide.hu.md#4-import-és-export)

## 9. A WinVPN frissítése

1. Ha a popoverben **Frissítés elérhető: vX.Y.Z** jelenik meg, kattints rá, olvasd el a változásokat, és kattints a **Letöltés és telepítés** gombra.
2. Válaszolj a kilépési kérdésekre, majd egy rendszergazda erősítse meg. A WinVPN frissül, és magától újraindul.
3. Az OpenVPN Community és a WireGuard külön frissül, új WinVPN nélkül: a WinVPN naponta ellenőrzi, és a **Rendszerállapot** a sorukon felkínálja a **Frissítés** gombot (**Frissítés elérhető: …**). Az OpenVPN frissítéséhez rendszergazda kell; a WireGuard-éhoz az, hogy ne legyen élő WireGuard-kapcsolat a számítógépen. A Windows VPN-kliensét a Windows Update frissíti.

Részletek: [útmutató, 8.](winvpn-user-guide.hu.md#8-frissítés) és [2.5](winvpn-user-guide.hu.md#25-az-openvpn-és-a-wireguard-frissítése).

## 10. A WinVPN indítása bejelentkezéskor

Popover → **Beállítások** → **Indítás bejelentkezéskor** (vagy a **Rendszerállapot** ablakban). Ha a Windows kikapcsolta a Gépház → Alkalmazások → Indítás alatt, a WinVPN az **Indítási alkalmazások beállításai…** gombot mutatja ehhez az oldalhoz. Részletek: [útmutató, 2.1](winvpn-user-guide.hu.md#21-indítás-bejelentkezéskor).

## 11. A WinVPN eltávolítása

1. **Rendszerállapot** → **WinVPN eltávolítása erről a fiókról…**. **A felhasználói adatok törlése is** négyzetet csak akkor jelöld be, ha a kapcsolataidat és a széfet is törölni akarod. Kattints az **Eltávolítás** gombra.
2. Lépj ki a WinVPN-ből. A **Gépház → Alkalmazások → Telepített alkalmazások** alatt (megnyílik) távolítsd el a **WinVPN**-t; egy rendszergazda megerősíti.
3. Az OpenVPN Community megmarad: ha már nem kell, ott azt is távolítsd el.

Részletek: [útmutató, 9.](winvpn-user-guide.hu.md#9-eltávolítás)

## 12. Gyakori hibák

**Egy kapcsolat szürke, rajta: „Nincs telepítve: OpenVPN Community – Rendszerállapot”.**
Kattints a sorban a **Rendszerállapot** linkre, majd a **Telepítés** gombra. Az OpenVPN Community nem kötelező, ezért a hiánya miatt a Rendszerállapot nem nyílik meg magától. [Bővebben](winvpn-user-guide.hu.md#24-hiányzó-vpn-motorok)

**Az OpenVPN és a WireGuard ezt írja: „A WinVPN szolgáltatás nem érhető el”.**
Egy rendszergazda elindítja a `sc.exe start WinVPN` paranccsal, vagy javítja a WinVPN-t a Telepített alkalmazások alatt. Az L2TP, az IKEv2 és az SSTP közben is működik. [Bővebben](winvpn-user-guide.hu.md#78-a-winvpn-szolgáltatás-és-egyéb-üzenetek)

**Az OpenVPN ezt írja: „Hitelesítési hiba (AUTH_FAILED)”.**
Ellenőrizd a **Felhasználónév** és **Jelszó** mezőt, és ments. Ha a szerver egyszer használatos kódot kér, lásd az [5. pontot](#5-kód-vagy-bejelentkezés-kérése-mfa). [Bővebben](winvpn-user-guide.hu.md#71-auth_failed-openvpn)

**Egy `cryptoapicert` vagy `windows-driver` sort tartalmazó OpenVPN config nem menthető.**
Ezek Windowson tiltottak: a tanúsítvány és a kulcs kerüljön a configba (vagy egy PKCS#12 fájlba); az illesztőprogramot a WinVPN maga választja. [Bővebben](winvpn-user-guide.hu.md#31-openvpn)

**L2TP/IPsec: „A szerver nem válaszolt a VPN-portokon … L2TP engedélyezése NAT mögött…”.**
A szerver NAT mögött van. Kattints az **L2TP engedélyezése NAT mögött…** gombra, egy rendszergazda erősítse meg, és indítsd újra a Windowst. [Bővebben](winvpn-user-guide.hu.md#37-rendszergazdai-lépések-a-natív-vpn-ekhez)

**Az IKEv2 szürke: „Windowson nem támogatott: local auth = psk”.**
A Windows IKEv2-kliense nem tud előre megosztott kulcsot használni. Kérj EAP-hozzáférést, vagy használd a PSK-t L2TP/IPsec-kel. [Bővebben](winvpn-user-guide.hu.md#33-ikev2-strongswan)

**IKEv2: „Nem található számítógép-tanúsítvány az IKEv2-höz”.**
Egy rendszergazda a `certlm.msc` eszközzel importálja a `.p12` fájlt a számítógép Személyes tárolójába. [Bővebben](winvpn-user-guide.hu.md#37-rendszergazdai-lépések-a-natív-vpn-ekhez)

**SSTP: „A szerver hitelesítésszolgáltatójában (CA) a Windows nem bízik meg”.**
Nyisd meg a kapcsolatot, és kattints **A CA megbízhatóvá tétele a Windowsban…** gombra (egy rendszergazda megerősíti). [Bővebben](winvpn-user-guide.hu.md#79-sstp-és-ikev2-tanúsítványhibák)

**A Macről jött Cisco IPsec kapcsolat szürke.**
A Windowsban nincs Cisco IPsec kliens. Lásd a [23. pontot](#23-macről-jött-cisco-ipsec-kapcsolat-használata).

**„Windows-hiba: … (lásd a naplót)”.**
Csatlakozz debug módban, és nézd meg a `Windows error` sort; az útmutató táblázata a gyakori kódokat magyarázza. [Bővebben](winvpn-user-guide.hu.md#76-a-windows-vpn-kliens-hibái-l2tp-ikev2-sstp)

**A WireGuard zöld, de nem megy forgalom.**
Általában rossz `Endpoint`, `PublicKey` vagy `AllowedIPs`, vagy a hálózat blokkolja az UDP-t. [Bővebben](winvpn-user-guide.hu.md#74-nincs-wireguard-handshake)

**Lejárt a kódbekérő ablak („A hitelesítés nem fejeződött be időben”).**
Csatlakozz újra, és 2 percen belül add meg a kódot (böngészős bejelentkezésnél 5 perc). [Bővebben](winvpn-user-guide.hu.md#711-egyszer-használatos-kód-és-böngészős-bejelentkezés-mfa)

**Elfelejtettem a mesterjelszót.**
**A WinVPN feloldása** ablakban kattints a **Helyreállítási kulcs használata** gombra, írd be a helyreállítási kulcsot és egy új mesterjelszót, majd **Visszaállítás és feloldás**. [Bővebben](winvpn-user-guide.hu.md#118-elfelejtett-mesterjelszó)

**A popover csak „Széf feloldása…” sort mutat.**
A széf zárolva van; a futó VPN-ek élnek. Kattints a **Széf feloldása…** sorra, és add meg a mesterjelszót. [Bővebben](winvpn-user-guide.hu.md#115-a-zárolt-popover)

**A mentés nem nyitható meg.**
A mentés jelszava hibás, vagy a fájl sérült; a WinVPN nem mondja meg, melyik. [Bővebben](winvpn-user-guide.hu.md#14-biztonsági-mentés-és-visszaállítás)

## 13. Frissítés az 1.5-ös előzetesről

1. Egy rendszergazda telepíti a 2.0-s MSI-t az előzetes fölé (dupla kattintás). A széfed és a kapcsolataid megmaradnak.
2. Nyisd meg a **Rendszerállapot** ablakot, és ha OpenVPN-t használsz, telepítsd az OpenVPN Communityt.
3. Az L2TP-kapcsolataid a széf feloldása után használhatók; a szürke kapcsolatoknál nézd meg az okot.

Részletek: [útmutató, 8.1](winvpn-user-guide.hu.md#81-frissítés-az-15-ös-előzetesről).

## 14. A széf beállítása, zárolása és feloldása

1. Első indításkor: **Tovább**, válassz mesterjelszót (kétszer), ha szeretnéd, hagyd bejelölve az **Automatikus feloldás** négyzetet, majd **Széf létrehozása**.
2. Mentsd el a helyreállítási kulcsot (csak most látható), **Elmentettem**, írd be a kért csoportot, **Megerősítés**, **Kész**.
3. Zárolás: **Széf zárolása most** a popoverben (kikapcsolt **Automatikus feloldás** mellett, vagy a **„Széf zárolása most” megjelenítése** beállítással látszik). Feloldás: **Széf feloldása…** és a mesterjelszó.

Részletek: [útmutató, 11.](winvpn-user-guide.hu.md#11-széf)

## 15. Kapcsolatok mappákba rendezése

**Új (+)** → **Új mappa**, írd be a nevet, Enter. Húzd a kapcsolatokat a mappára. Jobb kattintással: **Szín…**, **Átnevezés**, **Törlés…**. Részletek: [útmutató, 12.](winvpn-user-guide.hu.md#12-mappák-és-színek)

## 16. Egy bejelentkezés több kapcsolathoz

**Kapcsolatok** ablak → **Hitelesítő adatok** → **Hitelesítő adat hozzáadása…** (vagy **Létrehozás kapcsolatból…**). Minden szerkesztőben válaszd ki a **Jelszó forrása** alatt. Részletek: [útmutató, 13.](winvpn-user-guide.hu.md#13-közös-hitelesítő-adatok)

## 17. Teljes mentés és visszaállítás

1. Popover → **Beállítások** → **Teljes biztonsági mentés…**: mentési jelszó (kétszer) és a mesterjelszó, **Mentés…**, válaszd ki a helyét.
2. Új számítógépen (vagy a Windows újratelepítése után): a **Széf beállítása** ablakban **Visszaállítás biztonsági mentésből…**, válaszd ki a fájlt, add meg a jelszavát. MacVPN-mentés is jó.
3. Meglévő széfbe: **Beállítások** → **Visszaállítás biztonsági mentésből…**, majd **Összefésülés** vagy **Minden cseréje**.

Az L2TP-kapcsolatok azonnal megkapják a Windows VPN-bejegyzésüket. Részletek: [útmutató, 14.](winvpn-user-guide.hu.md#14-biztonsági-mentés-és-visszaállítás)

## 18. Feliratkozás egy csapatkatalógusra

1. **Kapcsolatok** ablak → **Csapatkatalógusok** → **Csapatkatalógus hozzáadása…**.
2. Illeszd be a feliratkozási kódot (vagy add meg a forrást: egy `https://` címet vagy egy fájlt, a csapatkulcsot és a közzétevő ujjlenyomatát; HTTPS-nél esetleg egy hozzáférési tokent).
3. **Ellenőrzés**, telefonon vesd össze az ujjlenyomatot a rendszergazdával, jelöld be a négyzetet, **Feliratkozás**.

Részletek: [útmutató, 16.1](winvpn-user-guide.hu.md#161-feliratkozás-egy-katalógusra).

## 19. Kapcsolatok megosztása a csapattal (katalógus közzététele)

1. **Közzététel** → **Adminisztrátori aláírókulcs létrehozása** (és egy tartalék aláírókulcs, offline tartott fájlba exportálva).
2. **Katalógus közzététele…**: jelöld be a kapcsolatokat, a csapattitkokat és a közös belépési adatok helyeit, mentsd a `<név>.macvpncatalog` fájlt, és mentsd el az egyszer megjelenő csapatkulcsot.
3. Tedd a fájlt a webszerveredre vagy a megosztásra, és minden tagnak küldd el biztonságos csatornán a **Feliratkozási kód másolása…** eredményét; az ujjlenyomatot külön mondd meg.

Részletek: [útmutató, 16.7](winvpn-user-guide.hu.md#167-rendszergazdáknak-az-adminisztrátori-aláírókulcs) és [16.8](winvpn-user-guide.hu.md#168-rendszergazdáknak-katalógus-közzététele).

## 20. Egy csapattag hozzáférésének visszavonása (csapatkulcs cseréje)

**Közzététel** → a katalógus → **Csapatkulcs cseréje…**, töltsd fel az új fájlt, és a maradó tagoknak küldd el az új kulcsot. Részletek: [útmutató, 16.9](winvpn-user-guide.hu.md#169-rendszergazdáknak-a-csapatkulcs-és-a-feliratkozási-kód).

## 21. Az aláírókulcs átvitele új számítógépre

1. Állíts vissza egy teljes mentést az új számítógépen (ez hozza a közzétételeidet).
2. **Közzététel** → **Aláírókulcs importálása…** a `.macvpnadminkey` fájllal és a jelszavával, majd **Váltás a tartalék kulcsra…**, ha kulcsot váltasz.
3. Tedd közzé minden katalógus új verzióját.

Részletek: [útmutató, 16.7](winvpn-user-guide.hu.md#167-rendszergazdáknak-az-adminisztrátori-aláírókulcs).

## 22. A Windowsban beállított VPN használata

1. Vedd fel a VPN-t a szokásos módon a **Gépház → Hálózat és internet → VPN** alatt. Másodperceken belül megjelenik a WinVPN-ben **Rendszer-VPN**-ként.
2. Csatlakoztasd a popoverből. A Windows saját mentett jelszavát használja, vagy a Windows bejelentkező ablaka nyílik meg.
3. Egy L2TP VPN-hez a jelszót és a PSK-t a WinVPN-ben is tárolhatod (a részleteinél a Kapcsolatok ablakban).

A WinVPN sosem módosítja és nem törli. Részletek: [útmutató, 3.5](winvpn-user-guide.hu.md#35-rendszer-vpn-ek-a-saját-windows-vpn-jeid).

## 23. Macről jött Cisco IPsec kapcsolat használata

A Windows nem tud Cisco IPsec (IKEv1 XAUTH-tal) kapcsolatot felépíteni.

1. Kérdezd meg a VPN-rendszergazdát, kínál-e a szerver L2TP/IPsec-et (ugyanazzal a PSK-val) vagy IKEv2-t.
2. L2TP/IPsec-hez: nyisd meg a Cisco kapcsolatot, és kattints az **L2TP/IPsec másolat készítése** gombra. A „<név> (L2TP)” másolatban ugyanaz a szerver, fiók, jelszó és PSK. Csatlakoztasd.
3. IKEv2-höz: hozz létre IKEv2-kapcsolatot a rendszergazdától kapott adatokkal.

A Cisco kapcsolat megmarad, és a Macen továbbra is működik. Részletek: [útmutató, 3.4](winvpn-user-guide.hu.md#34-l2tpipsec-és-cisco-ipsec).

## 24. Tesztelés a VPN-laborral (tesztelőknek)

A repóban van egy eldobható VPN-labor mindkét app teszteléséhez: `scripts/vpn-lab/` (a kézikönyve a [README](../scripts/vpn-lab/README.md), angolul). Minden szervertípust (OpenVPN, WireGuard, L2TP/IPsec, IKEv2 EAP-pal / PSK-val / tanúsítvánnyal, Cisco IPsec, SSTP) Dockerben futtat egy Macen vagy egy LAN-on lévő Linux gépen, generált hitelesítő adatokkal és egy labor-CA-val.

1. A laborgépen: `scripts/vpn-lab/up.sh --bind <a gép LAN-címe>`, majd `scripts/vpn-lab/check.sh --selftest` (minden sor `ok`).
2. Másold a teszt-számítógépre a `scripts/vpn-lab/.state/client/windows` (vagy `macos`) kliensprofiljait; a jelszavak, a PSK és a kódok a `scripts/vpn-lab/.state/client/CREDENTIALS.txt` fájlban vannak (ezt ne másolgasd).
3. Importáld a profilokat a WinVPN-be, csatlakozz, és nyisd meg a `http://10.99.0.10/` oldalt (a labor tesztoldala megmondja, melyik szerveren át jöttél). A labor a Docker NAT-ja mögött van, ezért a windowsos L2TP/IPsec-hez egyszer kell az **L2TP engedélyezése NAT mögött…**, az SSTP-hez és az IKEv2-höz pedig a labor-CA megbízhatóvá tétele (**A CA megbízhatóvá tétele a Windowsban…**).
4. Utána töröld a labor-CA-t és -tanúsítványt (`certlm.msc`), és állítsd le a labort: `scripts/vpn-lab/down.sh`.

## 25. A megjelenés és a kapcsolatértesítések beállítása

**Megjelenés:** popover → **Beállítások** → **Megjelenés**: **Rendszer szerint** (alapértelmezés, a Windows alkalmazásmódját követi), **Világos** vagy **Sötét**. Azonnal érvényes a popoverre és minden ablakra.

**Kapcsolatértesítések:** a WinVPN szól, ha egy kapcsolat csatlakozott, megszakadt, újracsatlakozott vagy sikertelen, rövid, közérthető okkal. Az értesítés csak a kapcsolatot nevezi meg; kattintásra a kapcsolat **Napló** füle nyílik meg. Kikapcsolás: popover → **Beállítások** → kapcsold ki a **Kapcsolatértesítések** kapcsolót. A kód- és a hitelesítőadat-kérések továbbra is értesítenek. A Windows saját kapcsolója: Gépház → Rendszer → Értesítések → **WinVPN**.

Részletek: [útmutató, 2.2](winvpn-user-guide.hu.md#22-megjelenés) és [2.3](winvpn-user-guide.hu.md#23-értesítések).

## 26. Automatikus újracsatlakozás alvás után

Ha egy kapcsolat azért szakadt meg, mert a számítógép aludt, vagy elveszett a hálózat, magától újra felépül, de csak ha mindkét feltétel teljesül:

1. **A VPN saját hálózatai és DNS-szerverei közül egyik sem érhető el közvetlenül** azon a hálózaton, amelyen vagy (például abban az irodában vagy, ahová a VPN vezet). Ezt ellenőrzi először.
2. **Ugyanazon a hálózaton vagy**, mint amikor a kapcsolat felépült (ugyanaz a router; azonosíthatatlan hálózaton a WinVPN nem csatlakozik újra).

A WinVPN legfeljebb háromszor próbálkozik, és megírja az eredményt (**…: újracsatlakozva**, **…: nem csatlakozott újra** az okkal, vagy **…: nem sikerült újracsatlakozni**). Az általad bontott kapcsolat (a WinVPN-ből való kilépéssel vagy kijelentkezéssel is) sosem csatlakozik újra. Az alvást túlélő alagutat bontja, ha az új hálózaton a VPN hálózata közvetlenül elérhető.

**Kikapcsolás egy kapcsolatnál:** **Kapcsolatok** ablak → a kapcsolat → kapcsold ki az **Automatikus újracsatlakozás** kapcsolót (a rendszer VPN-eknek nincs ilyen).

Részletek: [útmutató, 5.5](winvpn-user-guide.hu.md#55-automatikus-újracsatlakozás).

## 27. Csatlakozás UniFi, pfSense vagy OPNsense VPN-hez

Ezek az átjárók és tűzfalak olyan klienskonfigot adnak, amelyet a WinVPN változtatás nélkül importál. A konzolon a lépések ugyanazok, mint a MacVPN-nél: [MacVPN – Hogyan használd, 24.](how-to.hu.md#24-csatlakozás-unifi-pfsense-vagy-opnsense-vpn-hez) (a forrásokkal együtt). Ami Windowson más:

**Ubiquiti UniFi (UniFi OS átjárók)**

- **WireGuard** (ajánlott): **Settings → VPN → VPN Server → WireGuard → Add Client → Download**, majd **Új (+) → Import fájlból…** → a `.conf`. A QR-kód telefonra való; a WinVPN nem olvassa be. Ha az `AllowedIPs`-ben `0.0.0.0/0` van, minden forgalom a VPN-en megy; osztott alagúthoz cseréld az irodai hálózatokra. Ha a fájlban nincs `PersistentKeepalive`, írd a `[Peer]` alá: `PersistentKeepalive = 25`, így a WinVPN tétlen alagútnál is észreveszi, ha az nem válaszol.
- **OpenVPN:** előbb telepítsd az **OpenVPN Community**-t a **Rendszerállapot** ablakban. Importáld a UniFi által letöltött `.ovpn`-t, töltsd ki a **Felhasználónév** / **Jelszó** mezőt. A UniFi fájlja `cipher AES-256-CBC` sort tartalmaz (a régebbiek `comp-lzo`-t is), ezért a WinVPN a **TAP-Windows6** illesztőprogrammal futtatja; működik, de egyszerre csak egy TAP-Windows6 kapcsolat lehet fenn ([útmutató, 7.5](winvpn-user-guide.hu.md#75-openvpn-illesztőprogramok-dco-és-tap-windows6)). Ha egy leírás fájljában `user nobody` / `group nogroup` sor van, töröld őket.
- **L2TP/IPsec** (a USG / USG-Pro távoli felhasználós VPN-je): **Új → L2TP**, **Szerver**, **Fióknév**, **Jelszó** és **Közös kulcs (PSK)**; a WinVPN MS-CHAP v2-vel jelentkezik be, ahogy a Ubiquiti Windowsra kéri (ha a UniFi L2TP-szerver haladó beállításai között van **Require Strong Authentication**, kapcsold be). Ha az átjáró egy másik router mögött van, a Windowsnak egyszer kell az **L2TP engedélyezése NAT mögött…** (ez a Ubiquiti „módosítsd a registryt” lépése; rendszergazda hagyja jóvá, utána indítsd újra a Windowst). A UniFi nem küld útvonalakat: a **Minden forgalom a VPN-en keresztül** maradjon bekapcsolva, vagy vedd fel magad az útvonalakat.
- **A Teleport (WiFiman) nem támogatott:** a Ubiquiti felhőjén megy át, és nincs exportálható konfigurációja. Használd a WireGuard-szervert.

**pfSense és OPNsense**

- **OpenVPN:** pfSense: **VPN → OpenVPN → Client Export → Inline Configurations → Most Clients**; OPNsense: **VPN → OpenVPN → Client Export → File Only**. Mindkettő hiba nélkül importálható. A **Microsoft Certificate Storage** maradjon kikapcsolva: a `cryptoapicert` a WinVPN-ben tiltott (a szolgáltatás SYSTEM-ként fut, és a számítógép tanúsítványtárát érné el); az inline export a tanúsítványt a fájlba teszi. Az **Archive** export is működik, ha egy mappába bontod ki (a `.p12` jelszava a **Privát kulcs jelszava** mezőbe kerül).
- **Gyorsabb illesztőprogram:** a pfSense alapértelmezett **Fallback Data Encryption Algorithm** beállítása AES-256-CBC, és az OPNsense exportja is a szerver tartalék titkosítását viszi: CBC tartalékkal vagy tömörítéssel a WinVPN a TAP-Windows6-ot használja. Állítsd a szerveren a tartalékot **AES-256-GCM**-re (a tömörítést kapcsold ki), exportálj újra, és a WinVPN a gyorsabb DCO illesztőprogramot használja.
- **WireGuard:** a pfSense nem exportál klienskonfigot (a peer adataiból írd meg a `.conf`-ot, lásd a MacVPN-szakaszt); az OPNsense **VPN → WireGuard → Peer generator** oldala mutat egyet, amelyet kimásolhatsz. Az IPv6, a több `AllowedIPs` és a DNS keresési tartományok is működnek.
- **IPsec (mobil kliensek) – csak IKEv2, EAP-MSCHAPv2-vel vagy számítógép-tanúsítvánnyal.** A `swanctl.conf`-ot a MacVPN-szakasz szerint írd meg; a WinVPN lefordítja. A Windows egyetlen IKE- és ESP-kombinációt használ: a `proposals` / `esp_proposals` közül az elsőt, amelyet ismer (a Netgate leírása működik: az AES-256-GCM DH 16-tal kimarad, az AES-256 / SHA-256 / DH 14 lesz használva, ESP-re AES-256-GCM PFS 14-gyel). A tűzfal Phase 1 beállításában legyen legalább egy AES-256 / SHA-256 / DH 14 vagy AES-GCM / ECP-256 javaslat, mert a Windows mást nem kínál. A `remote_addrs` a szervertanúsítványban lévő név legyen, és a CA legyen megbízható (**A CA megbízhatóvá tétele a Windowsban…**).
- **Windowson nem megy:** az IKEv2 **előre megosztott kulccsal (PSK)** és az **EAP-TLS** (a Windows IKEv2-kliense itt EAP-MSCHAPv2-vel vagy a számítógép tanúsítványával jelentkezik be), valamint az IKEv1 **XAuth-os „Cisco-stílusú”** mobil beállítás (a Windowsnak nincs Cisco IPsec kliense). Kérj EAP-MSCHAPv2-t vagy számítógép-tanúsítványt, lásd [útmutató, 3.3](winvpn-user-guide.hu.md#33-ikev2-strongswan).
