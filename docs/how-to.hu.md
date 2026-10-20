# MacVPN – Hogyan használd

[English version](how-to.en.md)

Rövid, lépésenkénti leírások a MacVPN 1.3-hoz. A részletek a [felhasználói útmutatóban](user-guide.hu.md) vannak; a lenti hivatkozások annak fejezeteire mutatnak.

## Tartalom

1. [A MacVPN telepítése a DMG-ből](#1-a-macvpn-telepítése-a-dmg-ből)
2. [A beállítás befejezése](#2-a-beállítás-befejezése)
3. [Kapcsolat felvétele](#3-kapcsolat-felvétele)
4. [Csatlakozás és bontás](#4-csatlakozás-és-bontás)
5. [Kód vagy bejelentkezés kérése (MFA)](#5-kód-vagy-bejelentkezés-kérése-mfa)
6. [Kapcsolatok kitűzése és rendezése](#6-kapcsolatok-kitűzése-és-rendezése)
7. [Napló megtekintése és mentése hibakereséshez](#7-napló-megtekintése-és-mentése-hibakereséshez)
8. [Export és biztonsági mentés](#8-export-és-biztonsági-mentés)
9. [A MacVPN frissítése](#9-a-macvpn-frissítése)
10. [Indítás bejelentkezéskor](#10-indítás-bejelentkezéskor)
11. [A MacVPN eltávolítása](#11-a-macvpn-eltávolítása)
12. [Gyakori kérdések hibaelhárításhoz](#12-gyakori-kérdések-hibaelhárításhoz)
13. [Frissítés 1.1-ről 1.2-re](#13-frissítés-11-ről-12-re)
14. [A széf beállítása, zárolása és feloldása](#14-a-széf-beállítása-zárolása-és-feloldása)
15. [Kapcsolatok mappákba rendezése](#15-kapcsolatok-mappákba-rendezése)
16. [Egy bejelentkezés több kapcsolatnak](#16-egy-bejelentkezés-több-kapcsolatnak)
17. [Teljes biztonsági mentés és visszaállítás](#17-teljes-biztonsági-mentés-és-visszaállítás)
18. [Feliratkozás egy csapatkatalógusra](#18-feliratkozás-egy-csapatkatalógusra)
19. [Kapcsolatok megosztása a csapattal (katalógus közzététele)](#19-kapcsolatok-megosztása-a-csapattal-katalógus-közzététele)
20. [Egy csapattag hozzáférésének visszavonása (csapatkulcs cseréje)](#20-egy-csapattag-hozzáférésének-visszavonása-csapatkulcs-cseréje)
21. [Az aláírókulcs átvitele új Macre](#21-az-aláírókulcs-átvitele-új-macre)

---

## 1. A MacVPN telepítése a DMG-ből

macOS 14 vagy újabb és rendszergazdai fiók kell hozzá.

1. Töltsd le a legfrissebb `MacVPN-x.y.z.dmg` fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Nyisd meg a DMG-t, és húzd a **MacVPN**-t az **Applications** mappára. Dobd ki a DMG-t.
3. Nyisd meg először a MacVPN-t. Ad-hoc aláírású (nem Apple Developer ID-vel), ezért a Gatekeeper a sima dupla kattintást letiltja:
   - **macOS 14:** az Applications mappában kattints a Control billentyűvel (jobb gombbal) a **MacVPN**-re, válaszd a **Megnyitás** pontot, majd kattints a **Megnyitás** gombra.
   - **macOS 15 és újabb:** kattints duplán a MacVPN-re, zárd be a figyelmeztetést, majd a **Rendszerbeállítások → Adatvédelem és biztonság** alatt kattints a **Megnyitás mindenképp** gombra, add meg a jelszavadat, és kattints újra a **Megnyitás mindenképp** gombra.
4. A menüsorban megjelenik egy pajzs, és megnyílik a **Széf beállítása** ablak: válassz mesterjelszót, és mentsd el a helyreállítási kulcsot ([14. rész](#14-a-széf-beállítása-zárolása-és-feloldása)).

Részletek: [útmutató, 1.](user-guide.hu.md#1-telepítés)

## 2. A beállítás befejezése

Ha valami hiányzik, a **Rendszerállapot** ablak magától megnyílik (később: menü → **Rendszerállapot**). Az L2TP és a Cisco IPsec ezek nélkül is működik.

1. **Homebrew:** ha piros, kattints a **Telepítés…** gombra. Terminál nyílik a hivatalos telepítővel; kövesd, majd kattints az **Újraellenőrzés** gombra.
2. **VPN eszközök:** kattints a **Telepítés** gombra. A `brew install` kimenete az ablakban látszik. Az ablakot közben bezárhatod, a telepítés folytatódik.
3. **Jogosultság (root scriptek + sudoers):** kattints az **Engedélyezés** gombra, és add meg egyszer az admin jelszót (a MacVPN 1.2 a 8-as root réteget telepíti). Ez telepíti a `mvpn` root binárist és a sudoers szabályt, így később a csatlakozáshoz nem kell jelszó.
4. Ha mindhárom sor zöld, kész vagy.

Részletek: [útmutató, 2.](user-guide.hu.md#2-első-indítás-és-a-rendszerállapot-ablak)

## 3. Kapcsolat felvétele

Menü → **Új kapcsolat / Import…** (vagy **Kapcsolatok kezelése…**). Ez megnyitja a **Kapcsolatok** ablakot.

**Fájlok importálása:** kattints az **Új** (+) → **Import fájlból…** pontra, és jelölj ki egy vagy több fájlt, vagy húzd a fájlokat az ablakba. Utána jelöld ki az új kapcsolatot, töltsd ki a jelszómezőket, és kattints a **Mentés** gombra (⌘S).

**Kézi létrehozás:** kattints az **Új** (+) gombra, és válaszd ki a típust. Töltsd ki a sablont vagy az űrlapot, majd kattints a **Mentés** gombra.

| Típus | Import | Létrehozás | Mit kell kitölteni |
|---|---|---|---|
| OpenVPN | `.ovpn` fájl; a hivatkozott fájlok (`ca.crt`, `client.key`, `.p12`, …) legyenek ugyanabban a mappában | **Új → OpenVPN** | **Felhasználónév**, **Jelszó**; titkosított kulcsnál **Privát kulcs jelszava**. Ha az import megkérdezi: **Használod a(z) … fájlban lévő hitelesítő adatokat ehhez a kapcsolathoz?**, a **Használat** gombbal a fájlból veszi át őket. Ha sárga **Kockázatos beállítások** panel jelenik meg, olvasd el, és mentés előtt jelöld be: **Tudomásul veszem a beállításokat és a biztonsági kockázatokat**. |
| WireGuard | `.conf` fájl | **Új → WireGuard** (sablon) | Semmi más: a kulcsok a configban vannak. |
| IKEv2 (strongSwan) | `swanctl.conf` fájl | **Új → IKEv2** (sablon) | **Felhasználónév** (egyezzen az `eap_id`-val) és **Jelszó**, vagy **Pre-shared key (PSK)**. |
| SSTP | `.sstp` fájl | **Új → SSTP** (űrlap) | **Szerver**, **Port**, **Felhasználónév**, **Jelszó**, **Szervertanúsítvány**. |
| L2TP / Cisco IPsec | nem lehet (`.mobileconfig` nem importálható) | **Új → L2TP** vagy **Új → Cisco IPsec** (űrlap) | **Szerver**, **Fióknév**, **Jelszó**, **Pre-shared key (PSK)**, Ciscónál **Csoportnév (group name)**. Kattints a **Mentés és profil telepítése** gombra, majd hagyd jóvá a profilt a **Rendszerbeállítások → Általános → Eszközkezelés** alatt. |

**A macOS-ben már beállított VPN-ek** maguktól megjelennek a listában, **Rendszer-VPN** jelöléssel. Ezeket indíthatod és bonthatod. Ha egy L2TP vagy Cisco IPsec rendszer VPN a MacVPN-ből nem csatlakozik, add meg a részletező nézetében a **Közös kulcs (PSK)** értékét (és ha kell, a jelszót), majd kattints a **Mentés** gombra.

Részletek: [útmutató, 3.](user-guide.hu.md#3-kapcsolatok-felvétele-típusonként) és [4.](user-guide.hu.md#4-import-és-export)

## 4. Csatlakozás és bontás

1. Kattints a menüsorban a pajzsra.
2. Kattints a kapcsolat kártyáján a kapcsolóra. Csatlakozás közben a kapcsoló és a típusbuborék jelvénye borostyánsárga, a kártyán **Csatlakozás…** áll; ha felépült, zöldre váltanak, és a kártyán az IP-cím és az eltelt idő látszik.
3. Bontáshoz kattints újra a kapcsolóra.

A Kapcsolatok ablakban a **Csatlakozás** / **Bontás** gomb is használható. Egyszerre több kapcsolat is aktív lehet. A piros jelvény hibát jelez; a rövid ok a kártyán látszik, és értesítés is jön. A kártyán a **Használja: …** felirat azt jelenti, hogy egy párosított app tartja fenn a VPN-t ([útmutató, 5.4](user-guide.hu.md#54-párosított-appok-vezérlő-api)).

Ha aktív kapcsolattal lépsz ki, a MacVPN megkérdezi: **Leállítás és kilépés**, **Kilépés, fussanak tovább** vagy **Mégse**.

**Ha egy jelszó nincs elmentve,** a MacVPN csatlakozás előtt bekéri egy **Hitelesítő adatok szükségesek** ablakban (csak a hiányzó mezőket). Kattints az ablakra (nem veszi el a billentyűzetet a használt apptól), írd be az adatokat, és kattints a **Csatlakozás** gombra; az Enter nem csinál semmit. Bepipált **Mentés a széfbe** mellett az adatok a sikeres csatlakozás után a MacVPN titkosított széfjébe kerülnek. Ha a szerver elutasítja őket, az ablak egyszer újra kérdez. A **Mégse** hiba nélkül leállítja a csatlakozást.

**Csatlakozás a jelszó mentése nélkül:** a **Csatlakozás** előtt vedd ki a pipát a **Mentés a széfbe** elől a **Hitelesítő adatok szükségesek** ablakban. Az adatok csak erre a csatlakozásra érvényesek, a MacVPN legközelebb újra kérdez. Ha egy korábban elmentett jelszót akarsz újra bekéretni, nyisd meg a kapcsolatot a Kapcsolatok ablakban, és használd a **Mentett jelszó törlése** (vagy **Mentett titkok törlése**) gombot.

Részletek: [felhasználói kézikönyv, 5.3](user-guide.hu.md#53-hitelesítő-adatok-bekérése-csatlakozáskor).

## 5. Kód vagy bejelentkezés kérése (MFA)

- **Kódot kér a szerver** (OpenVPN challenge, vagy statikus challenge a configban): egy kis ablak nyílik **Kód** mezővel. Nem veszi el a billentyűzetet attól az apptól, amelyikben dolgozol: kattints az ablakra (vagy a „…: hitelesítés szükséges” értesítésre), írd be a kódot, és kattints a **Tovább** gombra. 2 perced van.
- **Bejelentkezés a böngészőben** (SAML, SSO, push): az ablak mutatja a címet. Ha te indítottad a kapcsolatot, és megbízol a címben, kattints a **Megnyitás a böngészőben** gombra, majd jelentkezz be, vagy hagyd jóvá a push értesítést a telefonodon. Legfeljebb 5 perced van.
- **Kód a jelszó végén** (egyes RADIUS / LDAP szerverek): nyisd meg a kapcsolatot a Kapcsolatok ablakban, jelöld be az **Egyszer használatos kód kérése csatlakozáskor, a jelszó végére fűzve** négyzetet, válaszd ki az **Elválasztó**t (**Nincs**, `,` vagy `:`), és ments. A MacVPN ezután minden csatlakozáskor bekéri a kódot. L2TP / Cisco IPsec rendszer VPN-nél is működik.

Amíg a MacVPN vár, a menüsor ikonja kulcs, a sorban **Hitelesítésre vár** áll. A **Mégse** leállítja a csatlakozást.

Részletek: [útmutató, 5.2](user-guide.hu.md#52-többfaktoros-hitelesítés-mfa)

## 6. Kapcsolatok kitűzése és rendezése

1. Nyisd meg a **Kapcsolatok** ablakot (menü → **Kapcsolatok kezelése…**).
2. Kattints jobb gombbal egy kapcsolatra, és válaszd a **Kitűzés** pontot. A **Kitűzött** részbe kerül, a menüben is.
3. A kitűzött kapcsolatokat húzással rendezheted.
4. Levenni jobb klikk → **Kitűzés megszüntetése** ponttal lehet.

A többi kapcsolat a használat szerint rendeződik: minden sikeres, MacVPN-ből indított csatlakozás számít, és a pontszám 14 naponta a felére csökken. Részletek: [útmutató, 5.1](user-guide.hu.md#51-a-kapcsolatok-sorrendje)

## 7. Napló megtekintése és mentése hibakereséshez

1. Csatlakozz debug módban: **Option+kattintás** a menü kapcsolóján, vagy a Kapcsolatok ablakban a **Csatlakozás debug módban** gomb. Megnyílik a **Napló** fül, és élőben követi a csatlakozást.
2. A szűrővel (**Minden**, **Parancsok**, **Hibák**) és a **Keresés** mezővel keresd meg a hibát. Vesd össze az üzenetet a [hibaelhárítási fejezettel](user-guide.hu.md#7-hibaelhárítás-a-napló-alapján).
3. Ha a naplót el akarod küldeni a hálózati rendszergazdának, kattints a **Mentés…** (vagy a **Másolás**) gombra. Jelszó, PSK és kulcs soha nincs a naplóban. Az SSTP debug napló tartalmazza az MS-CHAPv2 cserét, ezt csak a rendszergazdával oszd meg.

Az L2TP-nek és a Cisco IPsec-nek csak debug módban van naplója.

## 8. Export és biztonsági mentés

1. A Kapcsolatok ablakban jelöld ki a kapcsolatot, és kattints az export ikonra (**Exportálás… (jelszavak sosem kerülnek bele)**).
2. Ha a config privát kulcsokat vagy hitelesítő adatokat tartalmaz, válaszd az **Exportálás kulcsok nélkül** (biztonságosabb) vagy az **Exportálás kulcsokkal** (csak ha a címzettnek kellenek) lehetőséget.
3. Válaszd ki a mentés helyét. A fájlt csak te olvashatod.

Az export soha nem tartalmaz jelszót és PSK-t. A kapcsolat mappáját és közös hitelesítő adatának nevét viszi, így importáláskor a kapcsolat visszakerül a mappájába. A `.ovpn`, a WireGuard `.conf`, a `.swanctl.conf` és a `.sstp` fájl visszaimportálható; az L2TP / Cisco `.mobileconfig` exportot egy másik Macen a Finderben dupla kattintással telepítheted.

**Ha mindent a jelszavakkal együtt mentenél,** a **Teljes biztonsági mentés…** funkciót használd ([17. rész](#17-teljes-biztonsági-mentés-és-visszaállítás)). Az adataid a `~/Library/Application Support/MacVPN` mappában lévő titkosított széfben vannak; a mappa másolása a széfet is viszi, de a megnyitásához a mesterjelszó vagy a helyreállítási kulcs kell.

## 9. A MacVPN frissítése

1. Ha új verzió jelent meg, a menüben megjelenik a **Frissítés elérhető: vX.Y.Z** sor. (Vagy válaszd a **Frissítések keresése most** pontot.)
2. Kattints rá, olvasd el a változásokat, majd kattints a **Letöltés és telepítés** gombra.
3. Válaszolj a nem mentett változásokra és az aktív kapcsolatokra vonatkozó kérdésekre. A MacVPN ellenőrzi az aláírást, lecseréli magát, és újraindul.
4. Ha a macOS megkérdezi, hogy a MacVPN használhatja-e a Keychain-elemét (a széfkulcsot, frissítésenként legfeljebb egyszer), kattints a **Mindig engedélyez** gombra, de csak akkor, ha a kérdés a `/Applications/MacVPN.app` MacVPN-t nevezi meg.
5. Ha a **Rendszerállapot** ablak **Frissítés szükséges** felirattal nyílik meg, kattints az **Engedélyezés** gombra, és add meg az admin jelszót.

1.1-ről frissítesz? Kövesd a [13. részt](#13-frissítés-11-ről-12-re). 0.x verzióról frissítesz? Előbb olvasd el: [Frissítés 0.x verzióról](user-guide.hu.md#81-frissítés-0x-verzióról). Részletek: [útmutató, 8.](user-guide.hu.md#8-frissítés)

## 10. Indítás bejelentkezéskor

1. Ellenőrizd, hogy a MacVPN az Applications mappából fut.
2. Nyisd meg a menüt, és jelöld be az **Indítás bejelentkezéskor** négyzetet (a Rendszerállapot ablakban is megvan).
3. Ha egy megjegyzés jóváhagyást kér, kattints a **Bejelentkezési elemek beállításai…** gombra, és ott kapcsold be a MacVPN-t.

Ha a megjegyzés **Bejelentkezési LaunchAgenttel bekapcsolva (a következő bejelentkezéstől érvényes).**, akkor a következő bejelentkezéstől indul. Kikapcsoláshoz töröld a jelölést. Részletek: [útmutató, 2.1](user-guide.hu.md#21-indítás-bejelentkezéskor)

## 11. A MacVPN eltávolítása

1. Nyisd meg a **Rendszerállapot** ablakot, és kattints a **MacVPN eltávolítása…** gombra.
2. Ha az adataidat is törölni szeretnéd, jelöld be **A felhasználói adatok törlése is** négyzetet: a széf minden kapcsolattal és jelszóval, a Keychainben lévő széfkulcs és a régi MacVPN 1.1 Keychain-bejegyzések is törlődnek. Az általad készített mentésfájlok megmaradnak.
3. Kattints az **Eltávolítás** gombra, és add meg az admin jelszót. Előtte az aktív kapcsolatok bontódnak.
4. Kattints a **Kilépés** gombra, majd húzd a `MacVPN.app`-ot a Kukába.
5. Ha akarod, töröld a Homebrew csomagokat (`brew uninstall openvpn wireguard-tools strongswan sstp-client`) és az L2TP / Cisco profilokat a **Rendszerbeállítások → Általános → Eszközkezelés** alatt.

Részletek: [útmutató, 9.](user-guide.hu.md#9-eltávolítás)

## 12. Gyakori kérdések hibaelhárításhoz

**Egy kapcsolat szürke, és „Hiányzó eszköz” áll rajta.**
Hiányzik egy Homebrew eszköz ehhez a típushoz, vagy a root réteg nincs telepítve, illetve elavult. Nyisd meg a **Rendszerállapot** ablakot, telepítsd, ami piros, és ha a jogosultság sor kéri, kattints az **Engedélyezés** gombra.

**A menüben „Az állapot nem kérdezhető le: …” áll.**
A root réteg vagy a sudoers szabály hiányzik vagy elavult. Nyisd meg a **Rendszerállapot** ablakot, és kattints az **Engedélyezés** gombra.

**OpenVPN: „Hitelesítési hiba (AUTH_FAILED)”.**
Ellenőrizd a **Felhasználónév** és **Jelszó** mezőt, és ments. Ha a szerver egyszer használatos kódot kér, lásd az [5. pontot](#5-kód-vagy-bejelentkezés-kérése-mfa). [Bővebben](user-guide.hu.md#71-auth_failed-openvpn)

**A kapcsolat 30 másodperc után időtúllépéssel leáll.**
Ellenőrizd a hálózatot és a szervercímet, majd csatlakozz debug módban, és olvasd el a napló utolsó sorait. [Bővebben](user-guide.hu.md#73-időtúllépés)

**A mentés „Tiltott direktíva” vagy „Kockázatos direktíva, tudomásulvétel szükséges” hibát ad.**
A tiltott sorokat (például `up`, `down`, `script-security 2`) törölni kell, vagy megjegyzésbe tenni. A kockázatosakhoz a **Kockázatos beállítások** alatti négyzetet kell bejelölni. [Bővebben](user-guide.hu.md#77-nem-engedélyezett-direktíva--tiltott-direktíva)

**A WireGuard zöld, de nincs forgalom.**
Általában rossz az `Endpoint`, a `PublicKey` vagy az `AllowedIPs`, vagy a hálózat blokkolja az UDP-t. [Bővebben](user-guide.hu.md#74-nincs-wireguard-handshake)

**L2TP / Cisco: „A profil nincs telepítve”.**
Hagyd jóvá a profilt a **Rendszerbeállítások → Általános → Eszközkezelés** alatt, minden módosítás után újra. [Bővebben](user-guide.hu.md#76-a-profil-nincs-jóváhagyva-l2tp--cisco)

**Egy L2TP rendszer VPN a Rendszerbeállításokból működik, a MacVPN-ből nem.**
Add meg a **Közös kulcs (PSK)** értékét a MacVPN → Kapcsolatok → a VPN alatt, és ments. [Bővebben](user-guide.hu.md#35-rendszer-vpn-ek-közös-kulcs-l2tp--cisco-esetén)

**SSTP: „Szervertanúsítvány-hiba”.**
Céges CA esetén válaszd a **Saját CA fájl** módot, és töltsd be a CA-t PEM formátumban; IP-cím helyett a hosztnevet használd. [Bővebben](user-guide.hu.md#79-sstp-tanúsítványhiba)

**A kódbekérő lejárt („A hitelesítés nem fejeződött be időben”).**
Csatlakozz újra, és 2 percen belül add meg a kódot (böngészős bejelentkezésnél 5 percen belül). [Bővebben](user-guide.hu.md#711-egyszer-használatos-kód-és-böngészős-bejelentkezés-mfa)

**Frissítés után a macOS Keychain-hozzáférést kér.**
Bekapcsolt **Automatikus feloldás** mellett ez frissítésenként egyszer várható (a széfkulcs miatt), mert a MacVPN ad-hoc aláírású; kikapcsolva a frissítés semmit sem kérdez. Csak akkor engedélyezd, ha a kérdés a `/Applications/MacVPN.app` MacVPN-t nevezi meg.

**„A telepítés megszakítva: a(z) /usr/local/libexec nem a root tulajdona…” az Engedélyezés után.**
Javítsd a mappa tulajdonosát a Terminálban az üzenet szerint, majd kattints újra az **Engedélyezés** gombra. [Bővebben](user-guide.hu.md#78-egyéb)

**A frissítés szerint az app helye nem írható.**
Helyezd a MacVPN-t az Applications mappába, és próbáld újra, vagy telepítsd kézzel az új DMG-t.

**Elfelejtettem a mesterjelszót.**
**A MacVPN feloldása** ablakban kattints a **Helyreállítási kulcs használata** gombra, írd be a helyreállítási kulcsot és egy új mesterjelszót, majd **Visszaállítás és feloldás**. [Bővebben](user-guide.hu.md#118-elfelejtett-mesterjelszó)

**Elvesztettem a helyreállítási kulcsot.**
Amíg a mesterjelszót tudod: menü → **Beállítások** → **Új helyreállítási kulcs…**. Ha mindkettő elveszett, bekapcsolt **Automatikus feloldás** mellett a széf még megnyílik (exportáld, amire szükséged van); nélküle senki sem nyithatja meg. A mesterjelszóval készült mentéshez az akkori mesterjelszó kell; a helyreállítási kulcs sosem nyit meg mentést. Állíts vissza egy olyan mentést, amelyet meg tudsz nyitni, vagy állítsd be újra a MacVPN-t. [Bővebben](user-guide.hu.md#15-gyakori-kérdések-a-széfről)

**A menüben csak a „Széf feloldása…” látszik.**
A széf zárolva van; a futó VPN-ek fennmaradtak. Kattints a **Széf feloldása…** sorra, és add meg a mesterjelszót. [Bővebben](user-guide.hu.md#115-a-zárolt-menü)

**Az 1.1-ről való frissítéskor „Az átköltöztetés nem fejeződött be”.**
Semmi sem törlődött, a MacVPN írásvédetten fut az 1.1-es adataidból. Kattints a menü sávjára, és hozd létre újra a széfet egy új mesterjelszóval. [Bővebben](user-guide.hu.md#82-frissítés-11-ről)

**Az 1.2-re frissítés után a macOS sokszor kért Keychain-hozzáférést.**
Ez egyszer várható: az átköltöztetés alatt régi mentett jelszavanként egy kérdés. Mindig a **Mindig engedélyez** gombot válaszd. A későbbi frissítések legfeljebb egyszer kérdeznek, és csak bekapcsolt **Automatikus feloldás** mellett. [Bővebben](user-guide.hu.md#15-gyakori-kérdések-a-széfről)

**Egy mappa nem törölhető.**
Van benne aktív kapcsolat. Előbb bontsd. [Bővebben](user-guide.hu.md#125-mappa-törlése)

**Egy kapcsolat jelszómezője nem módosítható.**
Közös hitelesítő adatot használ. A **Hitelesítő adatok** részben módosíthatod. [Bővebben](user-guide.hu.md#133-használat-egy-kapcsolatban)

**A mentés nem nyitható meg.**
Hibás a mentés jelszava, vagy sérült a fájl; a MacVPN nem árulja el, melyik. [Bővebben](user-guide.hu.md#14-biztonsági-mentés-és-visszaállítás)

## 13. Frissítés 1.1-ről 1.2-re

1. Lépj ki a MacVPN 1.1-ből, és másold le az adatait: `cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.1`. A jelszavaid legyenek kéznél (például jelszókezelőben). Indítsd újra a MacVPN-t.
2. Menü → **Frissítések keresése most** → **Letöltés és telepítés**.
3. A **Széf beállítása** ablakban nézd meg, hány Keychain kérdést jelez előre, kattints a **Tovább** gombra, válassz mesterjelszót (legalább 10 karakter), és kattints a **Széf létrehozása** gombra.
4. Mentsd el a helyreállítási kulcsot (csak egyszer látható), kattints az **Elmentettem** gombra, írd be a kért csoportot, és kattints a **Megerősítés** gombra.
5. **Az adatok átköltöztetése a széfbe…** alatt minden olyan Keychain kérdésre, amely a `/Applications/MacVPN.app` MacVPN-t nevezi meg, a **Mindig engedélyez** gombbal válaszolj.
6. Ellenőrizd az eredményt (**Az adataid a széfben vannak**), kattints a **Tovább**, majd a **Kész** gombra.
7. A **Rendszerállapot** ablakban a **Frissítés szükséges (7 → 8)** sornál kattints az **Engedélyezés** gombra, és add meg az admin jelszót.
8. Csatlakozz egyszer minden kapcsolattal.

Ha az átköltöztetés nem sikerül, semmi sem törlődik: kattints a menü sávjára, és próbáld újra. Részletek: [útmutató, 8.2](user-guide.hu.md#82-frissítés-11-ről)

## 14. A széf beállítása, zárolása és feloldása

**Zárolás most:** kattints a menü alján a **Széf zárolása most** gombra. Ha nem látod, a **Beállítások** alatt kapcsold be a **„Széf zárolása most” megjelenítése** kapcsolót (kikapcsolt **Automatikus feloldás** mellett mindig látszik). A futó VPN-ek fennmaradnak.

**Feloldás:** kattints a menüben a **Széf feloldása…** sorra, írd be a mesterjelszót, és kattints a **Feloldás** gombra.

**Jelszókérés minden indításkor:** **Beállítások** → kapcsold ki az **Automatikus feloldás** kapcsolót → **Kikapcsolás**. Visszakapcsoláshoz kapcsold be, és add meg a mesterjelszót.

**A mesterjelszó módosítása:** **Beállítások** → **Mesterjelszó módosítása…** → a jelenlegi jelszó, kétszer az új → **Jelszó módosítása**. A helyreállítási kulcs nem változik.

**Új helyreállítási kulcs:** **Beállítások** → **Új helyreállítási kulcs…** → mesterjelszó → **Új kulcs készítése**, mentsd el, **Elmentettem**, írd be a csoportot, **Megerősítés**. A régi kulcs érvényét veszti.

**Elfelejtett mesterjelszó visszaállítása:** **A MacVPN feloldása** ablakban **Helyreállítási kulcs használata** → a helyreállítási kulcs és kétszer az új jelszó → **Visszaállítás és feloldás**.

Részletek: [útmutató, 11.](user-guide.hu.md#11-széf)

## 15. Kapcsolatok mappákba rendezése

1. Nyisd meg a **Kapcsolatok** ablakot. Kattints az **Új** (+) → **Új mappa** pontra, írj be egy nevet (legfeljebb 64 karakter), és nyomj Entert.
2. Húzd a kapcsolatokat a mappára. Egy mappát egy másik mappára húzva beágyazod, mappák közé húzva átrendezed. A **Legfelső szint** területre ejtve az elem minden mappából kikerül.
3. Jobb klikk egy mappán: **Átnevezés**, **Szín…**, **Áthelyezés a legfelső szintre**, **Törlés…**; jobb klikk egy kapcsolaton: **Szín…** (vagy **A mappa színe**) és **Kitűzés**.
4. Mappa törléséhez válaszd a **Törlés…** pontot. Alapból a tartalma egy szinttel feljebb kerül; **A kapcsolatok is törlődjenek** választásnál a törlés előtt újra rákérdez.

A menüben egy mappára kattintva nyitod és csukod; a jelvénye mutatja, hány kapcsolat aktív benne. Részletek: [útmutató, 12.](user-guide.hu.md#12-mappák-és-színek)

## 16. Egy bejelentkezés több kapcsolatnak

**Nulláról:**
1. **Kapcsolatok** ablak → az oldalsávban **Hitelesítő adatok** → **Hitelesítő adat hozzáadása…**.
2. Add meg a **Név**, a **Felhasználónév** és (ha akarod) a **Jelszó** mezőt, és ments.
3. Nyisd meg mindegyik kapcsolatot, amely használja, a **Jelszó forrása** legyen **Hitelesítő adat: <név>**, erősítsd meg a **Használat** gombbal, és ments.

**Egy olyan kapcsolatból, amelynek már van felhasználóneve és jelszava:**
1. **Hitelesítő adatok** → **Létrehozás kapcsolatból…**, válaszd ki a kapcsolatot és egy nevet, kattints a **Tovább** gombra.
2. Jelöld be a többi, azonos bejelentkezésű kapcsolatot, és kattints a **Létrehozás és összekapcsolás** gombra.

**Jelszócsere mindegyiknél:** **Hitelesítő adatok** → a tétel → **Szerkesztés…**, írd be az új jelszót, ments.

**A közös használat megszüntetése:** töröld a hitelesítő adatot, és válaszd a **Másolás minden kapcsolatba** gombot.

Ha olyan fájlt importálsz, amely közös hitelesítő adatot nevez meg, a MacVPN a kapcsolás előtt rákérdez, és megmutatja a szervert; válaszd a **Saját adatok használata** gombot, hacsak nem bízol a fájlban. Részletek: [útmutató, 13.](user-guide.hu.md#13-közös-hitelesítő-adatok)

## 17. Teljes biztonsági mentés és visszaállítás

**Mentés:**
1. Menü → **Beállítások** → **Teljes biztonsági mentés…**.
2. Írj be kétszer egy mentési jelszót (legalább 10 karakter). (Vagy **A mesterjelszavam használata…**, ami a fájlt a mesterjelszavadhoz köti.)
3. Kattints a **Mentés…** gombra, és válaszd ki a `MacVPN-backup-<dátum>.macvpnbackup` helyét.
4. A fájlt és a jelszavát tartsd külön helyen.

**Visszaállítás új Macen:**
1. Telepítsd és indítsd el a MacVPN-t. A **Széf beállítása** ablakban kattints a **Visszaállítás biztonsági mentésből…** gombra.
2. **Fájl kiválasztása…**, írd be a mentés jelszavát, **Mentés megnyitása**.
3. Válassz új mesterjelszót, és mentsd el az új helyreállítási kulcsot.
4. Jelöld be a kívánt beállításokat, majd **A kijelölt beállítások alkalmazása**. Az L2TP / Cisco profilokat a **… natív profil újratelepítése** gombbal telepítsd újra, és hagyd jóvá a Rendszerbeállításokban. A párosított appokat párosítsd újra.

**Visszaállítás a jelenlegi széfbe:** menü → **Beállítások** → **Visszaállítás biztonsági mentésből…**, nyisd meg a fájlt, nézd át az összesítőt, majd válaszd az **Összefésülés** (hozzáadja, ami hiányzik; a már meglévő elemekről te döntesz) vagy a **Minden cseréje…** lehetőséget (törli, ami nincs a mentésben; előtte az **Előbb a jelenlegi állapot mentése…** gombbal menthetsz).

Részletek: [útmutató, 14.](user-guide.hu.md#14-biztonsági-mentés-és-visszaállítás)

## 18. Feliratkozás egy csapatkatalógusra

Amit a rendszergazdától kapsz: egy feliratkozási kódot (`macvpn-sub:…`), vagy a forrást, a csapatkulcsot és a közzétevő ujjlenyomatát; egyes webszervereknél hozzáférési tokent is.

1. **Kapcsolatok** ablak → az oldalsávban **Csapatkatalógusok** → **Csapatkatalógus hozzáadása…**.
2. Illeszd be a feliratkozási kódot (egy sorban). Vagy add meg a **Forrás** (egy `https://` cím, vagy **Fájl kiválasztása…** egy megosztáson, illetve iCloud Drive-, OneDrive- vagy Dropbox-mappában), a **Csapatkulcs** és **A közzétevő ujjlenyomata** mezőt.
3. Ha a webszerver kéri, add meg a **Hozzáférési token** mezőt.
4. Kattints az **Ellenőrzés** gombra. Vesd össze az előnézetben látható ujjlenyomatot azzal, amit a rendszergazda telefonon vagy személyesen mondott. Ha eltér, állj meg.
5. Kattints a **Feliratkozás** gombra. A kapcsolatok a katalógus nevét viselő, **Csapat** jelvényes mappában jelennek meg.
6. Csatlakozz. Az első alkalommal a MacVPN minden közös belépési adat helyéhez (például **Office AD**) bekéri a saját felhasználónevedet és jelszavadat; jelöld be a **Mentés a széfbe** négyzetet.

A MacVPN induláskor, 15 percenként és ébredéskor frissíti a katalógust; a **Frissítés most** azonnal ellenőriz. Kilépéshez válaszd ki a katalógust, és kattints a **Leiratkozás…** gombra (a fennálló kapcsolatokat előbb bontja). Ha egy kapcsolatot magadnak megtartanál, előbb használd a **Másolat saját kapcsolatként…** pontot. Részletek: [útmutató, 16.](user-guide.hu.md#16-csapatkatalógusok)

## 19. Kapcsolatok megosztása a csapattal (katalógus közzététele)

**Egyszer:**
1. **Kapcsolatok** ablak → **Közzététel** → **Adminisztrátori aláírókulcs létrehozása**. Jegyezd fel az ujjlenyomatot.
2. **Tartalék aláírókulcs létrehozása** → **Tartalék kulcs exportálása…**, egy legalább 10 karakteres jelszó, és jelöld be: **A tartalék kulcs törlése erről a Macről az export után**. A fájlt offline tartsd, a jelszavát máshol.

**Közzététel:**
1. **Közzététel** → **Katalógus közzététele…**.
2. Jelöld be a megosztandó mappákat és kapcsolatokat.
3. Csak azokat a csapattitkokat jelöld be, amelyeket mindenki ismerhet (például egy közös PSK-t). A többit hagyd üresen.
4. A közös belépési adatok helyeit hagyd bejelölve: így a tagok a saját felhasználónevüket és jelszavukat adják meg.
5. Javítsd, amit az áttekintés elutasítottként listáz. WireGuard privát kulcsnál jelöld be, hogy mindenki ugyanazt a kulcsot használja, vagy hagyd ki a kapcsolatot.
6. Nevezd el a katalógust, és mentsd el a `<név>.macvpncatalog` fájlt.
7. Másold ki a **csapatkulcsot** (csak most látszik), tartsd biztonságban, kattints az **Elmentettem** gombra, és írd be a kért csoportot.
8. Tedd a fájlt oda, ahonnan a csapat olvassa:
   - **Webszerver:** töltsd fel úgy, hogy `https://`-en, a macOS által elfogadott tanúsítvánnyal legyen elérhető (ha kell, bearer token mögött).
   - **Fájlmegosztás:** másold arra az SMB- vagy NFS-megosztásra, amelyet a csapat csatol.
   - **Szinkronizált mappa:** mentsd egy megosztott iCloud Drive-, OneDrive- vagy Dropbox-mappába.
9. **Feliratkozási kód másolása…**: add meg a mesterjelszavadat, és azt a címet vagy útvonalat, amelyet a csapat használni fog. A kódot biztonságos csatornán küldd el (ne sima e-mailben), az ujjlenyomatot pedig külön, szóban mondd meg.

**Új verzió:** szerkeszd a kapcsolatokat a szokásos módon, majd a **Közzététel** részben **Új verzió közzététele**, és mentsd ugyanoda (webszervernél töltsd fel újra). A tagok 15 percen belül megkapják, a **Frissítés most** gombbal azonnal. Részletek: [útmutató, 16.8](user-guide.hu.md#168-rendszergazdáknak-katalógus-közzététele)

## 20. Egy csapattag hozzáférésének visszavonása (csapatkulcs cseréje)

1. **Kapcsolatok** ablak → **Közzététel** → a katalógus → **Csapatkulcs cseréje…**. Olvasd el a magyarázatot, és erősítsd meg.
2. Erősítsd meg a fájl helyét a mentési ablakban. Az új verzió azonnal oda kerül (webszervernél töltsd fel újra).
3. Másold ki az **új csapatkulcsot** (csak most látszik), kattints az **Elmentettem** gombra, és írd be a kért csoportot.
4. Küldd el a maradó tagoknak az új kulcsot (vagy egy új kódot a **Feliratkozási kód másolása…** ponttal) biztonságos csatornán. Náluk megjelenik: **A(z) „…” csapatkulcsa megváltozott**, és a **Csapatkatalógusok** részben a **Csapatkulcs cseréje…** gombbal adják meg.
5. Változtasd meg a katalógusban lévő csapattitkokat (például a szerveren a PSK-t), és tiltsd le a távozó fiókját a VPN-szerveren.

Aki távozott, megtartja, amit már letöltött, de egyetlen újabb verziót sem tud megnyitni. Részletek: [útmutató, 16.9](user-guide.hu.md#169-rendszergazdáknak-a-csapatkulcs-és-a-feliratkozási-kód)

## 21. Az aláírókulcs átvitele új Macre

A közzétételeid (minden katalógus azonosítója, verziója és csapatkulcsa) a széfben vannak, az aláírókulcs mellett. Együtt vidd át őket, teljes biztonsági mentéssel.

1. A régi Macen: **Beállítások** → **Teljes biztonsági mentés…** ([17.](#17-teljes-biztonsági-mentés-és-visszaállítás)).
2. Az új Macen: telepítsd a MacVPN 1.3-at vagy újabbat, és állítsd vissza a mentést (**Visszaállítás biztonsági mentésből…** a **Széf beállítása** ablakban).
3. **Kapcsolatok** ablak → **Közzététel**: ellenőrizd, hogy az aláírókulcs ujjlenyomata a régi, és minden közzététel megvan.
4. Tedd közzé minden katalógus következő verzióját ugyanoda. A tagok semmit nem vesznek észre.
5. A mentésfájlt töröld, ha már nem kell, vagy őrizd olyan biztonságosan, mint az aláírókulcsot. A régi Macen a **MacVPN eltávolítása…** gombbal távolítsd el, bejelölve: **A felhasználói adatok törlése is (kapcsolatok, a széf és a kulcsa)**.

**Ha közben a régi kulcsot is lecserélnéd** (például a régi Mac másé lesz): a 2. lépés után **Aláírókulcs importálása…** a `.macvpnadminkey` fájllal, majd **Váltás a tartalék kulcsra…**, tedd közzé a katalógusokat, és hozz létre, majd exportálj egy új tartalék kulcsot. Akik a tartalék kulcs létrehozása óta frissítettek, automatikusan követik; a többieknek újra fel kell iratkozniuk.

**Teljes biztonsági mentés nélkül** (elveszett a régi Mac): a tartalék kulcs fájlja önmagában nem tartalmazza a közzétételeket, így a következő közzététel új katalógust hoz létre. Tedd közzé a kapcsolatokat új katalógusként, és küldd el minden tagnak az új feliratkozási kódot; ők leiratkoznak a régiről. Ha az elveszett Mac széfje nyitva lehetett, kezeld kiszivárgottként az aláírókulcsot: lásd [útmutató, 16.10](user-guide.hu.md#1610-az-aláírókulcs-cseréje-és-a-kompromittálódás).
