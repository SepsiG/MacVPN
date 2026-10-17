# MacVPN – felhasználói útmutató

[English version](user-guide.en.md)

A MacVPN egy menüsor-alkalmazás macOS-re (14 vagy újabb). Egy helyen kezeli az OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec és Cisco IPsec kapcsolatokat. Itt importálhatod és szerkesztheted a configokat, a jelszavak a Keychainben vannak, és minden kapcsolatnak van élő naplója.

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

Az OpenVPN, WireGuard, IKEv2 és SSTP kapcsolatokhoz a MacVPN a [Homebrew](https://brew.sh) csomagkezelőből telepített eszközöket használja: `openvpn`, `wireguard-tools`, `strongswan`, `sstp-client`, `bash`. Ezeket a Rendszerállapot ablakból telepítheted (lásd a következő fejezetet). Ha már van Homebrew-d, Terminálban is megteheted:

```
brew install openvpn wireguard-tools strongswan sstp-client bash
```

Az L2TP és a Cisco IPsec kapcsolatok a macOS beépített VPN-jét használják, ezekhez nem kell Homebrew.

---

## 2. Első indítás és a Rendszerállapot ablak

Indítás után a MacVPN a menüsorban egy pajzs ikonként jelenik meg. Dokk ikonja nincs.

- **szürke pajzs:** nincs aktív kapcsolat
- **pajzs pipával:** van aktív kapcsolat
- **pajzs felkiáltójellel:** hiba (sikertelen csatlakozás, vagy az állapot nem kérdezhető le)

Ha valami hiányzik, első indításkor automatikusan megnyílik a **Rendszerállapot** ablak. Később a menüből is elérhető (**Rendszerállapot**). Három ellenőrzést mutat, mindegyik zöld vagy piros:

1. **Homebrew.** Ha hiányzik, a **Telepítés…** gomb Terminált nyit a hivatalos telepítővel. A telepítő a rendszergazdai jelszavadat kéri. Ha a telepítő nem tölthető le, a Terminál ablak ezt kiírja, és semmit nem futtat. Ha végzett, térj vissza, és nyomd meg az **Újraellenőrzés** gombot.
2. **VPN eszközök.** A hiányzó eszközök listája mellett a **Telepítés** gomb lefuttatja a `brew install` parancsot. A kimenet élőben látszik az ablakban. A telepítés akkor is folytatódik, ha közben bezárod az ablakot.
3. **Jogosultság (root scriptek + sudoers).** Az **Engedélyezés** gomb egyszer kéri az admin jelszót. Telepíti a `/usr/local/libexec/macvpn` scripteket és a `/etc/sudoers.d/macvpn` szabályt. Ezután a csatlakozás és a bontás jelszó nélkül működik. Ha egy app-frissítés újabb root scripteket hoz, itt a **Frissítés szükséges** felirat jelenik meg. Ilyenkor nyomd meg újra az **Engedélyezés** gombot.

Ha mindhárom zöld, kész a telepítés. Az L2TP és a Cisco IPsec ezek nélkül is működik.

### 2.1 Indítás bejelentkezéskor

A MacVPN alapból nem indul el magától. Ha minden bejelentkezéskor el szeretnéd indítani, jelöld be az **Indítás bejelentkezéskor** négyzetet a menüben (a **Frissítések automatikus keresése** alatt) vagy a **Rendszerállapot** ablakban. Kikapcsolni a jelölés törlésével lehet. A négyzet azt mutatja, amit a macOS jelez, így a **Rendszerbeállítások → Általános → Bejelentkezési elemek** alatt végzett változásokat is követi.

- Ha a macOS jóváhagyást kér, megjegyzés jelenik meg: „Engedélyezd a MacVPN-t a Rendszerbeállítások → Általános → Bejelentkezési elemek alatt.” A **Bejelentkezési elemek beállításai…** gomb megnyitja ezt az oldalt. Ott kapcsold be a MacVPN-t.
- A négyzet nem kattintható, ha a MacVPN nem az Alkalmazások mappából (`/Applications` vagy `~/Applications`) fut, például közvetlenül a DMG-ről vagy a Letöltések mappából. Húzd az appot az Alkalmazások mappába, onnan nyisd meg, és próbáld újra.

---

## 3. Kapcsolatok felvétele típusonként

Kapcsolatot a **Kapcsolatok** ablakban veszel fel. Megnyitása: menü → **Kapcsolatok kezelése…** vagy **Új kapcsolat / Import…**.

- Bal oldalt a lista. A **Saját kapcsolatok** a MacVPN-ben létrehozottak. A **Rendszer VPN-ek** a macOS-ben máshonnan beállított VPN-ek. Ezeket csak indítani és bontani lehet. L2TP és Cisco IPsec rendszer VPN-nél a közös kulcsot (PSK) is eltárolhatod a MacVPN-ben (lásd [3.5](#35-rendszer-vpn-ek-közös-kulcs-l2tp--cisco-esetén)).
- Az eszköztár **Új** (+) menüjéből választhatsz típust (OpenVPN, WireGuard, IKEv2, SSTP, L2TP, Cisco IPsec), vagy **Import fájlból…**.
- Jobb oldalt a kijelölt kapcsolat két füle: **Beállítások** és **Napló**.

A szöveges típusoknál (OpenVPN, WireGuard, IKEv2) monospace szerkesztő van. A **Mentés** (⌘S) előbb ellenőrzi a configot. Ha hibát talál, a hibás sorok pirosan, sorszámmal jelennek meg (például `3. sor: Nem engedélyezett direktíva: up`), és a mentés nem történik meg. A jelszavak külön mezőkben vannak (**Hitelesítés (Keychainben tárolva)**), ezek a macOS Keychainbe kerülnek, nem a configba.

Az SSTP-nek szöveges szerkesztő helyett űrlapja van (lásd [3.6](#36-sstp)).

Ha nem mentett változással váltasz kapcsolatot vagy zárod be az ablakot, az app rákérdez: **Mentés**, **Elvetés** vagy **Mégse**.

### 3.1 OpenVPN

A legegyszerűbb, ha a szolgáltatótól kapott `.ovpn` fájlt importálod (**Új → Import fájlból…**, vagy húzd a fájlt a listára).

- Ha a `.ovpn` külső fájlokra hivatkozik (például `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), az import a `.ovpn` mellől beolvassa és beágyazza őket (`<ca>…</ca>` blokkokba). Ezért importálás előtt a fájlok legyenek a `.ovpn` mellett. Ha egy fájl hiányzik, az import hibát jelez.
- Ha a szerver felhasználónevet és jelszót kér (`auth-user-pass` sor), töltsd ki a **Felhasználónév** és **Jelszó** mezőket.
- Biztonsági okból néhány direktíva nem engedett, például `up`, `down`, `script-security`, `plugin` és `log` (külső scriptet futtatnának, vagy a MacVPN saját beállításait írnák felül). A DNS-t a MacVPN maga állítja be. Részletek a [7.7 fejezetben](#77-nem-engedélyezett-direktíva--tiltott-direktíva).
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

**A macOS szolgáltatás azonosítása.** A profil telepítése után a MacVPN megjegyzi a macOS VPN szolgáltatás azonosítóját (azonos nevű és szervercímű szolgáltatás), és onnantól ezzel csatlakozik, bont és kérdezi le az állapotot. Egy véletlenül azonos nevű másik VPN így a **Rendszer VPN-ek** között jelenik meg. Ha a MacVPN nem tudja eldönteni, hogy több azonos nevű szolgáltatás közül melyik az övé, nem csatlakozik (és nem adja át a jelszót), hanem ezt írja ki: **Több „<név>” nevű VPN szolgáltatás van…**. Nevezd át vagy töröld a másikat a **Rendszerbeállítások → Hálózat** alatt.

A **fióknév** a kapcsolat beállításfájljában (`meta.json`) nyíltan tárolódik: nem titok. A jelszó és a PSK a Keychainben van.

### 3.5 Rendszer VPN-ek: közös kulcs L2TP / Cisco esetén

A Rendszerbeállításokban felvett VPN (például **Office L2TP**) a **Rendszer VPN-ek** alatt jelenik meg. A MacVPN nem módosítja a beállításait. Előfordul, hogy a macOS nem tudja kiolvasni egy ilyen VPN közös kulcsát, ha másik alkalmazás indítja: a kapcsolat nem jön létre, és a macOS „a szerver nem érhető el” jellegű üzenetet mutathat, holott a Rendszerbeállításokból indítva működik.

L2TP és Cisco IPsec rendszer VPN-nél a részletező nézetben két mező van:

- **Közös kulcs (PSK)**
- **Jelszó (nem kötelező, ha nincs elmentve a macOS-ben)**

Kattints a **Mentés** gombra. A MacVPN kulcskarikájában tárolódnak (nem a VPN saját beállításaiban), és minden MacVPN-ből indított csatlakozáskor átadja őket a macOS-nek. A **Mentett titkok törlése** gomb törli őket. Üresen hagyott mező szintén törlődik.

Ha itt mentetlen módosítással váltasz vagy zárod be az ablakot, az app ugyanúgy rákérdez (**Mentés / Elvetés / Mégse**), mint a többi kapcsolatnál.

### 3.6 SSTP

Az SSTP (Secure Socket Tunneling Protocol, a Microsoft HTTPS fölötti VPN-je, 443-as port) a root rétegen fut, a Homebrew `sstp-client` csomag (`sstpc`) és a macOS beépített `pppd`-je segítségével. Az `sstp-client` csomagot a **Rendszerállapot** ablakból telepítheted (vagy `brew install sstp-client`).

Létrehozás: **Új → SSTP**, vagy importálj egy `.sstp` fájlt. Szöveges szerkesztő helyett űrlapja van:

- **Név**, **Szerver** (hosztnév vagy IPv4/IPv6 cím, port nélkül), **Port** (alapból 443). IPv6 címre csatlakozást valódi szerverrel még nem teszteltünk; inkább a hosztnevet add meg.
- **Felhasználónév** és **Jelszó**. A jelszó a Keychainbe kerül. `DOMAIN\user` helyett `user@domain` formát használj: a felhasználónévben nem lehet fordított perjel, szóköz és idézőjel. **Az SSTP jelszóban nem lehet idézőjel (`"`), fordított perjel (`\`) és vezérlőkarakter**: az `sstpc` a jelszót escape nélkül adja át a `pppd`-nek, így ezek a karakterek a `pppd` beállításait módosíthatnák. Az űrlap ilyenkor hibát jelez, és nem ment; szükség esetén változtasd meg a jelszót a szerveren.
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

**Import.** **Új → Import fájlból…**, vagy húzz egy vagy több fájlt a Kapcsolatok ablakba. A típust a kiterjesztés és a tartalom alapján ismeri fel:

- `.ovpn`, vagy `client` / `dev tun` + `remote` sor → OpenVPN
- `[Interface]` + `PrivateKey` → WireGuard
- `connections {` → IKEv2 (strongSwan)
- `.sstp`, vagy `server=…` sor + `user=` / `cert=` sor → SSTP

Ha egy fájl nem ismerhető fel vagy nem importálható, a többi fájl attól még importálódik. A hibákat egy közös ablak sorolja fel.

**Más fájlokra hivatkozó OpenVPN configok** (`ca ca.crt`, `tls-auth ta.key 1`, …): a MacVPN a hivatkozott fájlokat inline blokként beemeli a configba, és az import után felsorolja őket, például **Importálva, beemelt fájlok: ca.crt, ta.key**. Biztonsági okból a hivatkozott fájlt csak akkor olvassa be, ha:

- az `.ovpn` fájl mappájában (vagy annak almappájában) van. A `../` útvonalakat, a mappán kívülre mutató abszolút útvonalakat és symlinkeket elutasítja: **A hivatkozott fájl a config mappáján kívül van**;
- legfeljebb 1 MB;
- a tartalma megfelel a direktívának: `ca`, `cert`, `extra-certs` → PEM tanúsítvány; `key` → PEM privát kulcs (`-----BEGIN … PRIVATE KEY-----`); `tls-auth`, `tls-crypt`, `secret` → OpenVPN statikus kulcs (`-----BEGIN OpenVPN Static key V1-----`); `tls-crypt-v2` → tls-crypt-v2 kliens kulcs; `dh` → DH paraméterek. Különben: **A(z) … direktíva fájlja (…) nem a várt formátumú**.

`pkcs12` fájl nem importálható, előbb alakítsd PEM-re. Az `auth-user-pass` mellett megadott felhasználónév/jelszó fájlt a MacVPN sosem olvassa be: a hitelesítő adatokat a MacVPN-ben add meg.

**Az importált config ellenőrzése.** Az importált configot a MacVPN rögtön ugyanazokkal a szabályokkal ellenőrzi, mint a **Mentés**. Ha hibás, attól még importálódik, és a szerkesztője pirossal jelölt hibalistával nyílik meg, így javíthatod és mentheted.

**Export.** A kapcsolat fejlécében az export ikon (**Exportálás… (jelszavak sosem kerülnek bele)**) az eredeti formátumban menti ki a configot: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, `.sstp`, natív kapcsolatnál `.mobileconfig`.

- A jelszó, a PSK és a felhasználónév **nem** kerül az exportba. A natív profilban ezek üresen maradnak. Az SSTP felhasználónév a config része, ezért benne van a `.sstp` exportban; a jelszó nincs.
- **Privát kulcsok:** a config részét képező kulcsok viszont belekerülhetnek. Ha a configban OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>` vagy `<pkcs12>` blokk, WireGuard `PrivateKey` / `PresharedKey`, vagy strongSwan `secrets` szakasz van, a MacVPN figyelmeztet (**A config privát kulcsokat tartalmaz**), és három lehetőséget ad: **Exportálás kulcsok nélkül** (alapértelmezett: az OpenVPN kulcsblokkok és a strongSwan `secrets` szakasz kimarad, a WireGuard kulcsok üresen maradnak), **Exportálás kulcsokkal**, vagy **Mégse**. Aki a kulcsokat birtokolja, a te nevedben csatlakozhat: csak akkor exportáld őket, ha a címzettnek szüksége van rájuk, és a fájlt megbízható helyen tartsd.
- Az exportált fájl `600`-as jogosultsággal jön létre (csak te olvashatod).
- A `.ovpn`, a WireGuard `.conf`, a `.swanctl.conf` és a `.sstp` export visszaimportálható a MacVPN-be.
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
- Sikertelen csatlakozásnál macOS értesítés jelenik meg („…: sikertelen csatlakozás”, **Részletek a MacVPN-ben** szöveggel). Maga a hibaüzenet nem kerül az értesítésbe, mert az a lezárt képernyőn is látszhat; a teljes ok a MacVPN-ben látszik. Kattintásra a kapcsolat **Napló** füle nyílik meg. Ha egy élő kapcsolat váratlanul megszakad, arról is értesítés jön. Automatikus újracsatlakozás nincs.
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
- IKEv2: `Tiltott: include`, `Tiltott kulcs: updown`, `Csak fájlnév adható meg, útvonal nem: cacerts`
- Argumentumok: `4. sor: Érvénytelen argumentum: dev`, `8. sor: Hibás argumentumszám: keepalive`, WireGuard: `3. sor: Érvénytelen érték: address`

A MacVPN rootként indítja a VPN-eszközöket, ezért csak ismert, biztonságos beállításokat enged. Javítás:

- **Tiltott direktíva / kulcs** (például `up`, `down`, `script-security`, `PostUp`): ezek külső parancsot futtatnának. Töröld a sort, vagy tegyél elé `#` jelet. A DNS-t és a route-okat a MacVPN kezeli, ezekre a scriptekre nincs szükség.
- **Nem engedélyezett direktíva:** ritka vagy ismeretlen beállítás. Ha nem nélkülözhetetlen, tedd megjegyzésbe. Ha szükséges, jelezd egy GitHub issue-ban.
- **Érvénytelen argumentum / érték, hibás argumentumszám:** a beállítás engedett, de az értéke nem a várt formájú (például eszközútvonal a `dev` után, szám helyett szó). Az üzenet a beállítás nevét mondja meg, az értéket nem. Vesd össze a sort a szolgáltató eredeti configjával.
- **Külső fájl hivatkozás:** a tanúsítvány fájlra hivatkozik (`ca ca.crt`). Importáld újra a `.ovpn` fájlt úgy, hogy a hivatkozott fájlok mellette legyenek, vagy másold be a tartalmukat egy `<ca>…</ca>` blokkba.
- **Nem engedélyezett vezérlőkarakter:** a fájlban láthatatlan karakter van (például Windowsból másolt szöveg). Írd be újra a sort.

### 7.8 Egyéb

- **„A telepítés megszakítva: a(z) /usr/local/libexec nem a root tulajdona, vagy más felhasználó is írhatja…”** (vagy ugyanez a `/usr/local`-ra) az **Engedélyezés** gomb után: a root scriptek egyik szülőmappája a felhasználódé, vagy más is írhatja. Így bármi, ami ennek a felhasználónak a nevében fut, kicserélhetné a MacVPN root scriptjeit, ezért a MacVPN nem telepít oda, és a mappát magától nem módosítja. Javítsd a Terminálban, majd nyomd meg újra az **Engedélyezés** gombot:
  ```
  sudo chown root:wheel /usr/local/libexec && sudo chmod go-w /usr/local/libexec
  ```
  (az üzenetben megnevezett mappával). Intel Macen a `/usr/local/libexec` a Homebrew-é lehet; a változtatás után a Homebrew `sudo` nélkül nem tud oda írni, ami egyes csomagokat érinthet.
- **„Az állapot nem kérdezhető le…”** figyelmeztetés a menüben: a root scriptek vagy a sudoers szabály hiányzik vagy elavult. Nyisd meg a **Rendszerállapot** ablakot, és nyomd meg az **Engedélyezés** gombot.
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
- **Opcionális késleltetés:** a **Csak a legalább 24 órája megjelent frissítések felajánlása** jelölőnégyzettel (alapból ki van kapcsolva) a MacVPN egy új kiadást csak akkor ajánl fel, ha az már 24 órája nyilvános (a GitHub-kiadás közzétételi ideje alapján). Így marad idő arra, hogy egy hibás vagy rosszindulatú kiadás kiderüljön és lekerüljön, mielőtt telepítenéd. A **Frissítések keresése most** ilyenkor jelzi, ha van újabb verzió, de még nincs felajánlva.
- **Keychain kérdés frissítés után:** mivel a MacVPN ad-hoc aláírású (nincs Developer ID-je), a macOS minden új verziót új programnak tekint, és minden frissítés után egyszer rákérdezhet, hogy a MacVPN hozzáférhet-e a saját Keychain-elemeihez. A **Mindig engedélyezés** (*Always Allow*) gombot csak akkor válaszd, ha a kérdés a MacVPN sajátja: a MacVPN nevét és útvonalát mutatja (általában `/Applications/MacVPN.app`). Ha más programot nevez meg, utasítsd el (*Deny*).
- Ha a frissítés új root scripteket hoz, a **Rendszerállapot** ablakban **Frissítés szükséges** jelenik meg. Az **Engedélyezés** gombbal egy admin jelszóval frissíted őket.
- Ha az app helye nem írható (például közvetlenül a Letöltések mappából vagy a DMG-ről fut), a telepítés hibát jelez. Húzd az appot az Applications mappába, vagy frissíts kézzel: töltsd le az új DMG-t, és írd felül vele az appot.
- A frissítés naplója: `~/Library/Caches/MacVPN/update.log`. Ha az előző frissítés megszakadt (mert a MacVPN 30 másodpercen belül nem lépett ki) vagy hibával leállt, a MacVPN a következő indításkor egyszer jelzi; a telepített verzió megmarad. Induláskor a MacVPN egy megszakadt frissítés maradványait is törli (rejtett `.MacVPN.app.update-…` és `.MacVPN.app.old-…` mappák az app mellett).

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
   > Az app most áthúzható a Kukába. A Homebrew csomagok megmaradtak (brew uninstall openvpn wireguard-tools strongswan sstp-client).

   Ha volt L2TP vagy Cisco kapcsolatod, egy második bekezdés is megjelenik:
   > Az L2TP / Cisco profilokat a Rendszerbeállítások → Általános → Eszközkezelés alatt távolíthatod el.

   Ha az **Indítás bejelentkezéskor** be volt kapcsolva, a MacVPN eltávolítja magát a bejelentkezési elemek közül. Ha ez nem sikerül, az ablak jelzi, és a **Rendszerbeállítások → Általános → Bejelentkezési elemek** alatt távolíthatod el.

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

- **Aláíratlan app.** A MacVPN nincs Apple Developer ID-vel aláírva és notarizálva, ezért kell az első indításkor a „Megnyitás mindenképp” lépés. Csak a hivatalos [Releases](https://github.com/SepsiG/MacVPN/releases) oldalról töltsd le.
- **Jelszavak.** A jelszavak és a PSK a macOS Keychainben vannak (`local.macvpn.secrets` szolgáltatás; a régebbi verziók `macvpn` alatti bejegyzéseit a MacVPN induláskor automatikusan áthelyezi). A szöveges típusok felhasználóneve is a Keychainben van; az L2TP / Cisco kapcsolatok fiókneve nyíltan a kapcsolat `meta.json` fájljában, mert nem titok. A jelszavak és a PSK a naplóban maszkolva (`***`) jelennek meg, és az export sem tartalmazza őket. A config részét képező kulcsok (WireGuard `PrivateKey`, OpenVPN `<key>` és hasonlók) csak az **Exportálás kulcsokkal** választásával kerülnek az exportba. Az L2TP / Cisco profil tartalmazza a PSK-t (a jelszót nem), és telepítés után törlődik a lemezről. Felhasználónévben, jelszóban és PSK-ban nem lehet sortörés vagy vezérlőkarakter (a MacVPN nem menti el). A mentett napló `600`-as jogosultsággal jön létre. Jelszavas OpenVPN kapcsolat alatt a felhasználónév és a jelszó egy csak root által olvasható fájlban is megvan (`/var/run/macvpn/<id>/auth`, `600`-as jogosultság egy `700`-as könyvtárban), hogy az OpenVPN újracsatlakozáskor újra be tudjon lépni. Bontáskor a fájl törlődik.
- **A root réteg sértetlensége.** A telepítő a root scripteket egy csak root által elérhető átmeneti mappába másolja, és csak akkor telepíti őket, ha a SHA-256-juk egyezik azzal, amit az app közvetlenül az admin jelszó kérése előtt kiszámolt. A `/usr/local/libexec/macvpn` mappát a root tulajdonába adja, és mások számára írhatatlanná teszi. Ha a `/usr/local` vagy a `/usr/local/libexec` nem a root tulajdona, vagy más is írhatja, nem módosítja őket, hanem útmutatással megáll (lásd [7.8](#78-egyéb)). A sudoers szabály tiszta környezettel indítja a `mvpn`-t (a munkameneted `LANG`, `LC_*` és más változói nélkül).
- **Sudoers és Homebrew (ismert korlát).** A csatlakozáshoz a MacVPN egy sudoers szabállyal, jelszó nélkül futtatja rootként a `/usr/local/libexec/macvpn/mvpn` scriptet, ez pedig a Homebrew eszközeit (`openvpn`, `wg-quick`, `charon`, `sstpc`). A Homebrew könyvtára (`/opt/homebrew`) a felhasználó által írható. Egy, a felhasználói fiókodban futó kártevő kicserélheti ezeket a programokat, és így rootjogot szerezhet. A configok szűrése a véletlen vagy importált veszélyes beállítások ellen véd, a fiókodon belül futó kártevő ellen nem. Egyfelhasználós, általad adminisztrált gépen ez elfogadható kockázat. Ha nem az, ne engedélyezd a root réteget, és csak L2TP / Cisco kapcsolatot használj.
- **SSTP jelszó a parancssorban (ismert korlát).** A Homebrew `sstpc` az SSTP crypto binding kulcsait maga számolja a jelszóból, ezért csak akkor indul el, ha a jelszót a parancssorában kapja (`--password`). A MacVPN ott adja át, a naplóba soha nem írja (`***`). Az `sstpc` a saját parancssorát a beolvasás után azonnal kicsillagozza, de ebben az első pillanatban a gép más felhasználói a `ps` paranccsal láthatják a jelszót. Egyfelhasználós gépen ez elfogadható kockázat. Ha nálad nem az, ne használj SSTP-t.
- **A frissítés hitelessége (korlát).** Developer ID és aláírt frissítési feed nélkül a letöltés hitelességét a HTTPS és az ugyanabból a GitHub-kiadásból származó SHA-256 ellenőrzőösszeg adja. Ez véd a sérült vagy menet közben módosított letöltés ellen. Ha viszont valaki átveszi a GitHub-fiókot vagy a repót, rosszindulatú kiadást tehet közzé, és ezt az updater nem tudja kiszűrni. Ha ezt a kockázatot nem vállalod, kapcsold ki a **Frissítések automatikus keresése** opciót, és frissíts kézzel, miután meggyőződtél a kiadás hitelességéről.
- **Hogyan szűkíti ezt a kockázatot az updater.**
  - A legfrissebb kiadást a repó rögzített numerikus azonosítójával kéri le a GitHubtól (`MacVPNUpdateRepoID` az app `Info.plist`-jében), nem a nevével. Ha a repót átneveznék vagy törölnék, és valaki a régi néven újat hozna létre, az app onnan nem frissülne. Az azonosító nélkül az app egyáltalán nem keres frissítést.
  - A DMG-t és a `.sha256` fájlt csak a `https://github.com/SepsiG/MacVPN/releases/download/<tag>/<fájlnév>` címről fogadja el, pontosan a kiadás tagjével; átirányítás csak a GitHub saját letöltési hostjaira vezethet.
  - A kiadásokat egy megerősített GitHub Actions workflow készíti: commitra rögzített actionök, csak olvasási jogú build, a tagelt commitnak a `main` ágon kell lennie, a közzétételt pedig egy külön job végzi, amely nem futtat kódot a repóból.
  - Az opcionális 24 órás késleltetés (lásd [8.](#8-frissítés)) időt ad egy hibás kiadás észlelésére és visszavonására.
  - Az app ad-hoc aláírású; a macOS minden frissítés után egyszer kérheti a Keychain-hozzáférést a MacVPN elemeihez (lásd [8.](#8-frissítés)). Csak a MacVPN saját kérdésénél engedélyezd.
