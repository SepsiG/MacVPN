# MacVPN – Hogyan használd

[English version](how-to.en.md)

Rövid, lépésenkénti leírások a MacVPN 1.1-hez. A részletek a [felhasználói útmutatóban](user-guide.hu.md) vannak; a lenti hivatkozások annak fejezeteire mutatnak.

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

---

## 1. A MacVPN telepítése a DMG-ből

macOS 14 vagy újabb és rendszergazdai fiók kell hozzá.

1. Töltsd le a legfrissebb `MacVPN-x.y.z.dmg` fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Nyisd meg a DMG-t, és húzd a **MacVPN**-t az **Applications** mappára. Dobd ki a DMG-t.
3. Nyisd meg először a MacVPN-t. Ad-hoc aláírású (nem Apple Developer ID-vel), ezért a Gatekeeper a sima dupla kattintást letiltja:
   - **macOS 14:** az Applications mappában kattints a Control billentyűvel (jobb gombbal) a **MacVPN**-re, válaszd a **Megnyitás** pontot, majd kattints a **Megnyitás** gombra.
   - **macOS 15 és újabb:** kattints duplán a MacVPN-re, zárd be a figyelmeztetést, majd a **Rendszerbeállítások → Adatvédelem és biztonság** alatt kattints a **Megnyitás mindenképp** gombra, add meg a jelszavadat, és kattints újra a **Megnyitás mindenképp** gombra.
4. A menüsorban megjelenik egy pajzs. A MacVPN-nek nincs Dock ikonja.

Részletek: [útmutató, 1.](user-guide.hu.md#1-telepítés)

## 2. A beállítás befejezése

Ha valami hiányzik, a **Rendszerállapot** ablak magától megnyílik (később: menü → **Rendszerállapot**). Az L2TP és a Cisco IPsec ezek nélkül is működik.

1. **Homebrew:** ha piros, kattints a **Telepítés…** gombra. Terminál nyílik a hivatalos telepítővel; kövesd, majd kattints az **Újraellenőrzés** gombra.
2. **VPN eszközök:** kattints a **Telepítés** gombra. A `brew install` kimenete az ablakban látszik. Az ablakot közben bezárhatod, a telepítés folytatódik.
3. **Jogosultság (root scriptek + sudoers):** kattints az **Engedélyezés** gombra, és add meg egyszer az admin jelszót. Ez telepíti a `mvpn` root binárist és a sudoers szabályt, így később a csatlakozáshoz nem kell jelszó.
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

**Ha egy jelszó nincs elmentve,** a MacVPN csatlakozás előtt bekéri egy **Hitelesítő adatok szükségesek** ablakban (csak a hiányzó mezőket). Kattints az ablakra (nem veszi el a billentyűzetet a használt apptól), írd be az adatokat, és kattints a **Csatlakozás** gombra; az Enter nem csinál semmit. Bepipált **Mentés** mellett az adatok a sikeres csatlakozás után a macOS Keychainbe kerülnek. Ha a szerver elutasítja őket, az ablak egyszer újra kérdez. A **Mégse** hiba nélkül leállítja a csatlakozást.

**Csatlakozás a jelszó mentése nélkül:** a **Csatlakozás** előtt vedd ki a pipát a **Mentés** elől a **Hitelesítő adatok szükségesek** ablakban. Az adatok csak erre a csatlakozásra érvényesek, a MacVPN legközelebb újra kérdez. Ha egy korábban elmentett jelszót akarsz újra bekéretni, nyisd meg a kapcsolatot a Kapcsolatok ablakban, és használd a **Mentett jelszó törlése** (vagy **Mentett titkok törlése**) gombot.

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

Az export soha nem tartalmaz jelszót és PSK-t. Biztonsági mentéshez exportáld az összes kapcsolatot, a jelszavakat pedig tartsd biztonságos helyen (például jelszókezelőben). A `.ovpn`, a WireGuard `.conf`, a `.swanctl.conf` és a `.sstp` fájl visszaimportálható; az L2TP / Cisco `.mobileconfig` exportot egy másik Macen a Finderben dupla kattintással telepítheted.

A kapcsolataid a `~/Library/Application Support/MacVPN` mappában vannak, a jelszavaik a Keychainben. A mappa másolása önmagában nem viszi a jelszavakat.

## 9. A MacVPN frissítése

1. Ha új verzió jelent meg, a menüben megjelenik a **Frissítés elérhető: vX.Y.Z** sor. (Vagy válaszd a **Frissítések keresése most** pontot.)
2. Kattints rá, olvasd el a változásokat, majd kattints a **Letöltés és telepítés** gombra.
3. Válaszolj a nem mentett változásokra és az aktív kapcsolatokra vonatkozó kérdésekre. A MacVPN ellenőrzi az aláírást, lecseréli magát, és újraindul.
4. Ha a macOS megkérdezi, hogy a MacVPN használhatja-e a Keychain-elemeit, kattints a **Mindig engedélyezés** gombra, de csak akkor, ha a kérdés a `/Applications/MacVPN.app` MacVPN-t nevezi meg.
5. Ha a **Rendszerállapot** ablak **Frissítés szükséges** felirattal nyílik meg, kattints az **Engedélyezés** gombra, és add meg az admin jelszót.

0.x verzióról frissítesz? Előbb olvasd el: [Frissítés 0.x verzióról](user-guide.hu.md#81-frissítés-0x-verzióról). Részletek: [útmutató, 8.](user-guide.hu.md#8-frissítés)

## 10. Indítás bejelentkezéskor

1. Ellenőrizd, hogy a MacVPN az Applications mappából fut.
2. Nyisd meg a menüt, és jelöld be az **Indítás bejelentkezéskor** négyzetet (a Rendszerállapot ablakban is megvan).
3. Ha egy megjegyzés jóváhagyást kér, kattints a **Bejelentkezési elemek beállításai…** gombra, és ott kapcsold be a MacVPN-t.

Ha a megjegyzés **Bejelentkezési LaunchAgenttel bekapcsolva (a következő bejelentkezéstől érvényes).**, akkor a következő bejelentkezéstől indul. Kikapcsoláshoz töröld a jelölést. Részletek: [útmutató, 2.1](user-guide.hu.md#21-indítás-bejelentkezéskor)

## 11. A MacVPN eltávolítása

1. Nyisd meg a **Rendszerállapot** ablakot, és kattints a **MacVPN eltávolítása…** gombra.
2. Ha a kapcsolataidat és a jelszavaikat is törölni szeretnéd, jelöld be: **A felhasználói adatok törlése is (kapcsolatok és Keychain jelszavak)**.
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
Ez frissítésenként egyszer várható, mert a MacVPN ad-hoc aláírású. Csak akkor engedélyezd, ha a kérdés a `/Applications/MacVPN.app` MacVPN-t nevezi meg.

**„A telepítés megszakítva: a(z) /usr/local/libexec nem a root tulajdona…” az Engedélyezés után.**
Javítsd a mappa tulajdonosát a Terminálban az üzenet szerint, majd kattints újra az **Engedélyezés** gombra. [Bővebben](user-guide.hu.md#78-egyéb)

**A frissítés szerint az app helye nem írható.**
Helyezd a MacVPN-t az Applications mappába, és próbáld újra, vagy telepítsd kézzel az új DMG-t.
