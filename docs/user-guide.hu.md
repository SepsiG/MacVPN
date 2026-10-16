# MacVPN – felhasználói útmutató

[English version](user-guide.en.md)

A MacVPN egy menüsor-alkalmazás macOS-re (14 vagy újabb). Egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), L2TP/IPsec és Cisco IPsec kapcsolatokat. Itt importálhatod és szerkesztheted a configokat, a jelszavak a Keychainben vannak, és minden kapcsolatnak van élő naplója.

> **Nyelv:** a MacVPN a macOS nyelvi beállítását követi (Rendszerbeállítások → Általános → Nyelv és régió, illetve az appra beállított nyelv). Magyarul és angolul érhető el; ha a preferált nyelvek között egyik sincs, angolul jelenik meg. Ez az útmutató a magyar feliratokat használja, az [angol útmutató](user-guide.en.md) az angolokat.

## Tartalom

1. [Telepítés](#1-telepítés)
2. [Első indítás és a Rendszerállapot ablak](#2-első-indítás-és-a-rendszerállapot-ablak)
3. [Kapcsolatok felvétele típusonként](#3-kapcsolatok-felvétele-típusonként)
4. [Import és export](#4-import-és-export)
5. [Csatlakozás](#5-csatlakozás)
6. [Debug mód és a napló](#6-debug-mód-és-a-napló)
7. [Hibaelhárítás a napló alapján](#7-hibaelhárítás-a-napló-alapján)
8. [Frissítés](#8-frissítés)
9. [Eltávolítás](#9-eltávolítás)
10. [Biztonsági megjegyzések](#10-biztonsági-megjegyzések)

---

## 1. Telepítés

### 1.1 A DMG letöltése

1. Töltsd le a legfrissebb `MacVPN-x.y.z.dmg` fájlt a [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról.
2. Nyisd meg a DMG-t, és húzd a **MacVPN** ikont az **Applications** mappára.
3. Dobd ki (Eject) a DMG-t a Finderben.

### 1.2 Az első indítás engedélyezése (Gatekeeper)

Az app nincs Apple Developer ID-vel aláírva, ezért az első indításkor a macOS letiltja („nem nyitható meg, mert az Apple nem tudja ellenőrizni…”). Engedélyezése:

1. Indítsd el egyszer a MacVPN-t az Applications mappából. Zárd be a figyelmeztetést (**Kész** vagy **OK**).
2. Nyisd meg: **Rendszerbeállítások → Adatvédelem és biztonság**.
3. Görgess le a **Biztonság** részhez. Ott ezt látod: „A(z) MacVPN blokkolva lett…”. Kattints a **Megnyitás mindenképp** gombra.
4. Add meg a jelszavadat, majd a megjelenő ablakban kattints újra a **Megnyitás mindenképp** gombra.

Ezt csak egyszer kell megtenni. A későbbi frissítések az appon belül települnek (lásd [8. fejezet](#8-frissítés)).

### 1.3 Homebrew és a VPN-eszközök

Az OpenVPN, WireGuard és IKEv2 kapcsolatokhoz a MacVPN a [Homebrew](https://brew.sh) csomagkezelőből telepített eszközöket használja: `openvpn`, `wireguard-tools`, `strongswan`, `bash`. Ezeket a Rendszerállapot ablakból telepítheted (lásd a következő fejezetet). Ha már van Homebrew-d, Terminálban is megteheted:

```
brew install openvpn wireguard-tools strongswan bash
```

Az L2TP és a Cisco IPsec kapcsolatok a macOS beépített VPN-jét használják, ezekhez nem kell Homebrew.

---

## 2. Első indítás és a Rendszerállapot ablak

Indítás után a MacVPN a menüsorban egy pajzs ikonként jelenik meg. Dokk ikonja nincs.

- **szürke pajzs:** nincs aktív kapcsolat
- **pajzs pipával:** van aktív kapcsolat
- **pajzs felkiáltójellel:** hiba (sikertelen csatlakozás, vagy az állapot nem kérdezhető le)

Ha valami hiányzik, első indításkor automatikusan megnyílik a **Rendszerállapot** ablak. Később a menüből is elérhető (**Rendszerállapot**). Három ellenőrzést mutat, mindegyik zöld vagy piros:

1. **Homebrew.** Ha hiányzik, a **Telepítés…** gomb Terminált nyit a hivatalos telepítővel. A telepítő a rendszergazdai jelszavadat kéri. Ha végzett, térj vissza, és nyomd meg az **Újraellenőrzés** gombot.
2. **VPN eszközök.** A hiányzó eszközök listája mellett a **Telepítés** gomb lefuttatja a `brew install` parancsot. A kimenet élőben látszik az ablakban. A telepítés akkor is folytatódik, ha közben bezárod az ablakot.
3. **Jogosultság (root scriptek + sudoers).** Az **Engedélyezés** gomb egyszer kéri az admin jelszót. Telepíti a `/usr/local/libexec/macvpn` scripteket és a `/etc/sudoers.d/macvpn` szabályt. Ezután a csatlakozás és a bontás jelszó nélkül működik. Ha egy app-frissítés újabb root scripteket hoz, itt a **Frissítés szükséges** felirat jelenik meg. Ilyenkor nyomd meg újra az **Engedélyezés** gombot.

Ha mindhárom zöld, kész a telepítés. Az L2TP és a Cisco IPsec ezek nélkül is működik.

---

## 3. Kapcsolatok felvétele típusonként

Kapcsolatot a **Kapcsolatok** ablakban veszel fel. Megnyitása: menü → **Kapcsolatok kezelése…** vagy **Új kapcsolat / Import…**.

- Bal oldalt a lista. A **Saját kapcsolatok** a MacVPN-ben létrehozottak. A **Rendszer VPN-ek** a macOS-ben máshonnan beállított VPN-ek. Ezeket csak indítani és bontani lehet. L2TP és Cisco IPsec rendszer VPN-nél a közös kulcsot (PSK) is eltárolhatod a MacVPN-ben (lásd [3.5](#35-rendszer-vpn-ek-közös-kulcs-l2tp--cisco-esetén)).
- Az eszköztár **Új** (+) menüjéből választhatsz típust (OpenVPN, WireGuard, IKEv2, L2TP, Cisco IPsec), vagy **Import fájlból…**.
- Jobb oldalt a kijelölt kapcsolat két füle: **Beállítások** és **Napló**.

A szöveges típusoknál (OpenVPN, WireGuard, IKEv2) monospace szerkesztő van. A **Mentés** (⌘S) előbb ellenőrzi a configot. Ha hibát talál, a hibás sorok pirosan, sorszámmal jelennek meg (például `3. sor: Nem engedélyezett direktíva: up`), és a mentés nem történik meg. A jelszavak külön mezőkben vannak (**Hitelesítés (Keychainben tárolva)**), ezek a macOS Keychainbe kerülnek, nem a configba.

Ha nem mentett változással váltasz kapcsolatot vagy zárod be az ablakot, az app rákérdez: **Mentés**, **Elvetés** vagy **Mégse**.

### 3.1 OpenVPN

A legegyszerűbb, ha a szolgáltatótól kapott `.ovpn` fájlt importálod (**Új → Import fájlból…**, vagy húzd a fájlt a listára).

- Ha a `.ovpn` külső fájlokra hivatkozik (például `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), az import a `.ovpn` mellől beolvassa és beágyazza őket (`<ca>…</ca>` blokkokba). Ezért importálás előtt a fájlok legyenek a `.ovpn` mellett. Ha egy fájl hiányzik, az import hibát jelez.
- Ha a szerver felhasználónevet és jelszót kér (`auth-user-pass` sor), töltsd ki a **Felhasználónév** és **Jelszó** mezőket.
- Biztonsági okból néhány direktíva nem engedett, például `up`, `down`, `script-security`, `plugin` és `log` (külső scriptet futtatnának, vagy a MacVPN saját beállításait írnák felül). A DNS-t a MacVPN maga állítja be. Részletek a [7.7 fejezetben](#77-nem-engedélyezett-direktíva--tiltott-direktíva).

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

### 3.4 L2TP/IPsec és Cisco IPsec

Ezek a macOS beépített VPN-jét használják. A beállítás űrlapon történik (**Új → L2TP** vagy **Új → Cisco IPsec**):

- **Név**, **Szerver**, **Fióknév**, **Jelszó**, **Pre-shared key (PSK)**
- Cisco esetén a **Csoportnév (group name)** is
- **Minden forgalom a VPN-en keresztül**: ha be van kapcsolva, minden forgalom a VPN-en megy

**Profil jóváhagyása:** a **Mentés és profil telepítése** gomb egy konfigurációs profilt készít és nyit meg. A macOS ezt nem telepíti magától:

1. Nyisd meg: **Rendszerbeállítások → Általános → Eszközkezelés** (régebbi macOS-en: **Profilok**).
2. Kattints duplán a MacVPN profilra, majd a **Telepítés…** gombra, és add meg a jelszavadat.

Minden módosítás után újra jóvá kell hagyni a profilt. Kapcsolat törlésekor a MacVPN megnyitja a Profilok panelt, ahol a profilt neked kell eltávolítanod.

Csatlakozáskor a MacVPN a mentett PSK-t és jelszót közvetlenül átadja a macOS-nek, így a kapcsolat nem azon múlik, hogy a macOS megtalálja-e őket a Rendszer kulcskarikában.

### 3.5 Rendszer VPN-ek: közös kulcs L2TP / Cisco esetén

A Rendszerbeállításokban felvett VPN (például **Office L2TP**) a **Rendszer VPN-ek** alatt jelenik meg. A MacVPN nem módosítja a beállításait. Előfordul, hogy a macOS nem tudja kiolvasni egy ilyen VPN közös kulcsát, ha másik alkalmazás indítja: a kapcsolat nem jön létre, és a macOS „a szerver nem érhető el” jellegű üzenetet mutathat, holott a Rendszerbeállításokból indítva működik.

L2TP és Cisco IPsec rendszer VPN-nél a részletező nézetben két mező van:

- **Közös kulcs (PSK)**
- **Jelszó (nem kötelező, ha nincs elmentve a macOS-ben)**

Kattints a **Mentés** gombra. A MacVPN kulcskarikájában tárolódnak (nem a VPN saját beállításaiban), és minden MacVPN-ből indított csatlakozáskor átadja őket a macOS-nek. A **Mentett titkok törlése** gomb törli őket. Üresen hagyott mező szintén törlődik.

Ha itt mentetlen módosítással váltasz vagy zárod be az ablakot, az app ugyanúgy rákérdez (**Mentés / Elvetés / Mégse**), mint a többi kapcsolatnál.

---

## 4. Import és export

**Import.** **Új → Import fájlból…**, vagy húzz egy vagy több fájlt a Kapcsolatok ablakba. A típust a kiterjesztés és a tartalom alapján ismeri fel:

- `.ovpn`, vagy `client` / `dev tun` + `remote` sor → OpenVPN
- `[Interface]` + `PrivateKey` → WireGuard
- `connections {` → IKEv2 (strongSwan)

Ha egy fájl nem ismerhető fel vagy hibás, a többi fájl attól még importálódik. A hibákat egy közös ablak sorolja fel.

**Export.** A kapcsolat fejlécében az export ikon (**Exportálás… (jelszavak nélkül)**) az eredeti formátumban menti ki a configot: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, natív kapcsolatnál `.mobileconfig`.

- A jelszó, a PSK és a felhasználónév **nem** kerül az exportba. A natív profilban ezek üresen maradnak.
- **Figyelem, WireGuard:** a `PrivateKey` a config része, ezért **benne van** az exportban. Az app erre figyelmeztet. Az ilyen fájlt csak megbízható helyre mentsd vagy add át.
- Az exportált fájl `600`-as jogosultsággal jön létre (csak te olvashatod).
- A `.ovpn`, a WireGuard `.conf` és a `.swanctl.conf` export visszaimportálható a MacVPN-be.
- A `.mobileconfig` export (L2TP, Cisco IPSec) a MacVPN-be **nem** importálható. Másik Macen dupla kattintással nyisd meg a Finderben: a macOS profilként telepíti, utána a **Rendszerbeállítások → Általános → Eszközkezelés** (Profilok) alatt hagyd jóvá. Ha `.mobileconfig` fájlt próbálsz importálni a MacVPN-be, az app is ezt írja ki.

---

## 5. Csatlakozás

- **Menüből:** kattints a kapcsolat melletti kapcsolóra. Az állapotjelző:
  - **zöld pont:** kapcsolódva (mellette az IP és az eltelt idő)
  - **forgó jel:** csatlakozás vagy bontás folyamatban
  - **piros pont:** hiba (mellette a rövid ok)
  - **üres kör:** nincs kapcsolat
- **A Kapcsolatok ablakból:** **Csatlakozás** / **Bontás** gomb.
- Egyszerre több kapcsolat is aktív lehet.
- Ha egy típushoz hiányzik eszköz, a kapcsolat kiszürkül, és a **Hiányzó eszköz** felirat jelenik meg rajta. Ilyenkor nézd meg a **Rendszerállapot** ablakot.
- Sikertelen csatlakozásnál macOS értesítés jelenik meg („…: sikertelen csatlakozás”). Kattintásra a kapcsolat **Napló** füle nyílik meg. Ha egy élő kapcsolat váratlanul megszakad, arról is értesítés jön. Automatikus újracsatlakozás nincs.
- **Kilépéskor**, ha van aktív kapcsolat, az app megkérdezi: **Leállítás és kilépés**, **Kilépés, fussanak tovább** vagy **Mégse**. A tovább futó kapcsolatokat a MacVPN következő indításkor felismeri.

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
- **L2TP / Cisco:** a macOS VPN-folyamatainak naplója (legfeljebb 60 mp-ig, vagy amíg a kapcsolat létre nem jön). Ezeknél debug mód nélkül nincs napló.
- **Diagnosztika** csatlakozás előtt és után: a szerver nevének feloldása, a route tábla, a DNS állapot és az interfészek.

**A napló sorai, színkóddal:**

| Előtag | Jelentés |
|---|---|
| `═══` | új csatlakozás vagy bontás kezdete (dátummal) |
| `▶ [mvpn]` | a MacVPN saját lépései (config másolása, ellenőrzés, talált eszközök) |
| `$ …` | lefuttatott parancs (a jelszavak `***`-gal maszkolva) |
| `✗` | hiba |
| egyéb | az eszköz (openvpn, wg-quick, charon) saját kimenete |

**Napló műveletek:** szűrés (**Minden**, **Parancsok**, **Hibák**), **Keresés**, **Követés** (automatikus görgetés), **Másolás**, **Mentés…**. Jelszó, PSK és privát kulcs nem kerül a naplóba, így a mentett napló is megosztható (például a rendszergazdával).

---

## 7. Hibaelhárítás a napló alapján

Először nézd meg a hibaüzenetet a menüben vagy az értesítésben. Ha ez nem elég, csatlakozz debug módban, és keress a **Napló** fülön (a **Hibák** szűrő csak a hibasorokat mutatja).

### 7.1 `AUTH_FAILED` (OpenVPN)

Üzenet: **Hitelesítési hiba (AUTH_FAILED)**. A szerver elutasította a felhasználónevet vagy a jelszót.

- Ellenőrizd a **Felhasználónév** és **Jelszó** mezőket, majd nyomd meg a **Mentés** gombot.
- Lejárt vagy zárolt fiók esetén keresd a szolgáltatót.
- Ha a szerver egyszer használatos kódot (OTP) kér, a MacVPN ezt jelenleg nem támogatja.

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
- `5. sor: Nem engedélyezett direktíva: xyz – töröld vagy tedd megjegyzésbe (#) a sort`
- `Külső fájl hivatkozás, inline blokk kell: ca`
- WireGuard: `Tiltott kulcs: postup`, `Nem engedélyezett kulcs: …`
- IKEv2: `Tiltott: include`, `Tiltott kulcs: updown`

A MacVPN rootként indítja a VPN-eszközöket, ezért csak ismert, biztonságos beállításokat enged. Javítás:

- **Tiltott direktíva / kulcs** (például `up`, `down`, `script-security`, `PostUp`): ezek külső parancsot futtatnának. Töröld a sort, vagy tegyél elé `#` jelet. A DNS-t és a route-okat a MacVPN kezeli, ezekre a scriptekre nincs szükség.
- **Nem engedélyezett direktíva:** ritka vagy ismeretlen beállítás. Ha nem nélkülözhetetlen, tedd megjegyzésbe. Ha szükséges, jelezd egy GitHub issue-ban.
- **Külső fájl hivatkozás:** a tanúsítvány fájlra hivatkozik (`ca ca.crt`). Importáld újra a `.ovpn` fájlt úgy, hogy a hivatkozott fájlok mellette legyenek, vagy másold be a tartalmukat egy `<ca>…</ca>` blokkba.
- **Nem engedélyezett vezérlőkarakter:** a fájlban láthatatlan karakter van (például Windowsból másolt szöveg). Írd be újra a sort.

### 7.8 Egyéb

- **„Az állapot nem kérdezhető le…”** figyelmeztetés a menüben: a root scriptek vagy a sudoers szabály hiányzik vagy elavult. Nyisd meg a **Rendszerállapot** ablakot, és nyomd meg az **Engedélyezés** gombot.
- **„Az openvpn nem található (brew install openvpn)”** és hasonló üzenetek: telepítsd a hiányzó eszközt a **Rendszerállapot** ablakból.

---

## 8. Frissítés

A MacVPN a GitHub Releases oldalon keresi az új verziókat: induláskor, majd 24 óránként.

- Ha van újabb verzió, a menüben megjelenik a **Frissítés elérhető: vX.Y.Z** sor. Kattintásra egy ablak mutatja a változások listáját.
- A **Letöltés és telepítés** gomb:
  1. letölti a DMG-t és a hozzá tartozó `.sha256` fájlt, és ellenőrzi az SHA-256 ellenőrzőösszeget;
  2. csatolja a DMG-t, és ellenőrzi, hogy a benne lévő app a MacVPN (`local.macvpn`) és a verziója egyezik a kiadáséval;
  3. a kilépéshez hasonlóan rákérdez a nem mentett változásokra és az aktív kapcsolatokra;
  4. kilép, kicseréli az appot ott, ahonnan fut (általában `/Applications/MacVPN.app`), majd újraindítja.
- Kézi ellenőrzés: menü → **Frissítések keresése most**.
- Az automatikus ellenőrzés kikapcsolható: menü → **Frissítések automatikus keresése** jelölőnégyzet.
- Ha a frissítés új root scripteket hoz, a **Rendszerállapot** ablakban **Frissítés szükséges** jelenik meg. Az **Engedélyezés** gombbal egy admin jelszóval frissíted őket.
- Ha az app helye nem írható (például közvetlenül a Letöltések mappából vagy a DMG-ről fut), a telepítés hibát jelez. Húzd az appot az Applications mappába, vagy frissíts kézzel: töltsd le az új DMG-t, és írd felül vele az appot.
- A frissítés naplója: `~/Library/Caches/MacVPN/update.log`.

---

## 9. Eltávolítás

1. Nyisd meg a **Rendszerállapot** ablakot, és kattints a **MacVPN eltávolítása…** gombra.
2. A megerősítő ablak felsorolja, mi törlődik:
   - `/usr/local/libexec/macvpn` (root scriptek)
   - `/etc/sudoers.d/macvpn` (sudoers szabály)
   - `/var/run/macvpn` (futási adatok)
   - `/var/log/macvpn` (kapcsolatnaplók)
3. Ha a **A felhasználói adatok törlése is** jelölőnégyzetet bejelölöd, a kapcsolataid (`~/Library/Application Support/MacVPN`) és a Keychainben tárolt jelszavaik is törlődnek, a rendszer VPN-ekhez mentett közös kulcsokkal együtt.
4. Kattints az **Eltávolítás** gombra, és add meg az admin jelszót. Előtte a MacVPN bontja az aktív kapcsolatokat.
   Ha egy kapcsolat nem bontható, az eltávolítás megszakad („Egy kapcsolat nem bontható, az eltávolítás megszakítva”), és semmi nem törlődik. Bontsd a kapcsolatot (vagy indítsd újra a gépet), majd próbáld újra.
5. A végén egy **A MacVPN eltávolítva** című ablak jelenik meg, ezzel a szöveggel:
   > Az app most áthúzható a Kukába. A Homebrew csomagok megmaradtak (brew uninstall openvpn wireguard-tools strongswan).

   Ha volt L2TP vagy Cisco kapcsolatod, egy második bekezdés is megjelenik:
   > Az L2TP / Cisco profilokat a Rendszerbeállítások → Általános → Eszközkezelés alatt távolíthatod el.

   A **Kilépés** után húzd a `MacVPN.app`-ot a Kukába.

A Homebrew csomagokat a MacVPN nem törli, mert más programok is használhatják őket. Ha már nincs rájuk szükséged:

```
brew uninstall openvpn wireguard-tools strongswan
```

Az L2TP és Cisco profilokat a **Rendszerbeállítások → Általános → Eszközkezelés** alatt távolíthatod el.

---

## 10. Biztonsági megjegyzések

- **Aláíratlan app.** A MacVPN nincs Apple Developer ID-vel aláírva és notarizálva, ezért kell az első indításkor a „Megnyitás mindenképp” lépés. Csak a hivatalos [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról töltsd le.
- **Jelszavak.** A jelszavak, a PSK és a felhasználónév a macOS Keychainben vannak. A naplóban maszkolva (`***`) jelennek meg, és az export sem tartalmazza őket. Kivétel a WireGuard `PrivateKey`, amely a config része. Jelszavas OpenVPN kapcsolat alatt a felhasználónév és a jelszó egy csak root által olvasható fájlban is megvan (`/var/run/macvpn/<id>/auth`, `600`-as jogosultság egy `700`-as könyvtárban), hogy az OpenVPN újracsatlakozáskor újra be tudjon lépni. Bontáskor a fájl törlődik.
- **Sudoers és Homebrew (ismert korlát).** A csatlakozáshoz a MacVPN egy sudoers szabállyal, jelszó nélkül futtatja rootként a `/usr/local/libexec/macvpn/mvpn` scriptet, ez pedig a Homebrew eszközeit (`openvpn`, `wg-quick`, `charon`). A Homebrew könyvtára (`/opt/homebrew`) a felhasználó által írható. Egy, a felhasználói fiókodban futó kártevő kicserélheti ezeket a programokat, és így rootjogot szerezhet. A configok szűrése a véletlen vagy importált veszélyes beállítások ellen véd, a fiókodon belül futó kártevő ellen nem. Egyfelhasználós, általad adminisztrált gépen ez elfogadható kockázat. Ha nem az, ne engedélyezd a root réteget, és csak L2TP / Cisco kapcsolatot használj.
- **A frissítés hitelessége (korlát).** Developer ID és aláírt frissítési feed nélkül a letöltés hitelességét a HTTPS és az ugyanabból a GitHub-kiadásból származó SHA-256 ellenőrzőösszeg adja. Ez véd a sérült vagy menet közben módosított letöltés ellen. Ha viszont valaki átveszi a GitHub-fiókot vagy a repót, rosszindulatú kiadást tehet közzé, és ezt az updater nem tudja kiszűrni. Ha ezt a kockázatot nem vállalod, kapcsold ki a **Frissítések automatikus keresése** opciót, és frissíts kézzel, miután meggyőződtél a kiadás hitelességéről.
