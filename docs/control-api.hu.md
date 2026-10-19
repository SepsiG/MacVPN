# MacVPN – Helyi vezérlő API

[English version](control-api.md)

Ez az útmutató fejlesztőknek szól, akik azt szeretnék, hogy egy másik program ugyanazon a Macen fel- és lekapcsolhassa a MacVPN kapcsolatait. A legtöbb felhasználónak nincs rá szüksége; minden mást a [felhasználói útmutató](user-guide.hu.md) ír le.

## Tartalom

1. [Mit tud](#1-mit-tud)
2. [Bekapcsolás](#2-bekapcsolás)
3. [Párosítás](#3-párosítás)
4. [Biztonsági modell](#4-biztonsági-modell)
5. [Protokoll](#5-protokoll)
6. [Hibakódok](#6-hibakódok)
7. [Foglalási szabályok](#7-foglalási-szabályok)
8. [Kompatibilitás a későbbi verziókkal](#8-kompatibilitás-a-későbbi-verziókkal)
9. [Hogyan illeszd be egy Rust appba](#9-hogyan-illeszd-be-egy-rust-appba)
10. [Hibaelhárítás](#10-hibaelhárítás)

---

## 1. Mit tud

Amíg a MacVPN fut, ugyanannak a macOS-felhasználónak egy programja (például egy Remote Desktop app):

- listázhatja azokat a VPN-kapcsolatokat, amelyeket a felhasználó engedélyezett neki,
- felkapcsolhatja valamelyiket,
- és újra lekapcsolhatja.

A VPN csak addig marad fent, amíg a programnak szüksége van rá. A program **foglalást** (lease) tart a kapcsolaton, amíg a MacVPN-nel nyitott socket-kapcsolata nyitva van. Ha a program bezárja a socketet, kilép vagy összeomlik, a foglalás véget ér, és ha másnak nem kell a VPN, a MacVPN lebontja.

Az API-n keresztül egy program **nem**:

- olvashat vagy módosíthat configot, felhasználónevet, jelszót vagy más titkot,
- hozhat létre, importálhat vagy törölhet kapcsolatot,
- válaszolhat MFA-kérdésre (a MacVPN a saját ablakaiban kérdezi meg a felhasználót, pontosan úgy, mint kézi csatlakozáskor),
- csatlakozhat másik felhasználói fiókból vagy a hálózatról.

Az átvitel Unix domain socketen történik, az üzenetek soronként egy JSON-objektumot tartalmaznak. Rust példakliens: [`examples/macvpn-control-client`](../examples/macvpn-control-client/) (angolul).

## 2. Bekapcsolás

1. A MacVPN menüjében válaszd a **Kapcsolatok kezelése…** pontot.
2. A Kapcsolatok ablak oldalsávjában válaszd a **Párosított appok** részt.
3. Kapcsold be: **Más appok vezérelhetik a VPN-eket**. Alapból ki van kapcsolva.

A MacVPN ezután itt figyel:

```
~/Library/Application Support/MacVPN/control/macvpn.sock
```

Amíg a beállítás ki van kapcsolva, a socket fájl nem létezik. A beállítás kikapcsolása minden kliens kapcsolatát bontja, a hitelesített klienseknek előtte egy [`closing` eseményt](#510-a-closing-esemény) küldve; a foglalások a [7. szakasz](#7-foglalási-szabályok) szerint érnek véget.

Ha a socketet nem lehet létrehozni, az ok a kapcsoló alatt jelenik meg, például: **Más appok nem vezérelhetik a VPN-eket: a(z) … mappa nem használható (…).** vagy **A MacVPN egy másik példánya már engedi, hogy más appok vezéreljék a VPN-eket.**

## 3. Párosítás

Egy programot egyszer párosítani kell, mielőtt bármit csinálhatna.

1. A program csatlakozik a sockethez, és elküldi: `{"id":1,"op":"pair","name":"Remote Desktop"}`.
2. A MacVPN megnyitja az **Engedélyezed, hogy egy app vezérelje a VPN-eket?** ablakot. Az ablak nem veszi el a fókuszt, a gombjai 1 másodpercig zárolva vannak, és egyik gomb sem alapértelmezett. Ezt mutatja:
   - **Név (a program saját megnevezése)**: a program által küldött név. Ezt a program választotta, tehát semmit sem bizonyít.
   - **Futtatható fájl**: a program futtatható fájljának útvonala, amelyet a MacVPN az operációs rendszertől kérdez le. Ez az az azonosító, amelyhez a MacVPN a párosítást köti.
   - **Használható kapcsolatok**: minden kapcsolathoz egy jelölőnégyzet, alapból egyik sincs bejelölve.
3. A felhasználó az **Engedélyezés** vagy az **Elutasítás** gombra kattint.
   - **Engedélyezés**: a MacVPN egyszer elküldi a tokent, `{"id":1,"ok":true,"token":"…","client_id":"…"}`, és bontja a kapcsolatot.
   - **Elutasítás**, vagy ha 2 percig nincs válasz: `{"id":1,"ok":false,"error":"denied"}`, és a kapcsolat bomlik. 3 elutasítás után a MacVPN 10 percig minden párosítást `denied` válasszal utasít el.

A token 32 véletlen bájt, base64url kódolással, kitöltés nélkül (43 karakter). A MacVPN csak az SHA-256 hash-ét tárolja. **A programnak a saját Keychain-elemében kell tárolnia a tokent**, soha nem sima fájlban vagy naplóban (lásd [9.2](#92-a-token-tárolása-a-keychainben)).

Egyszerre csak egy párosítási ablak lehet nyitva; egy közben érkező újabb `pair` választ `busy` kap.

A **Párosított appok** rész minden párosított programot felsorol: a nevét és a futtatható fájl útvonalát, az **Utoljára használva** (vagy **Még nem használta**) és a **Párosítva** időpontot, valamint az **Engedélyezett kapcsolatok** listáját, amely bármikor módosítható. A **Visszavonás** megszünteti a párosítást, és azonnal bontja a program nyitott kapcsolatait; azokat a VPN-eket, amelyeket csak ő épített fel, a MacVPN lebontja. Az alul lévő **Tevékenység** lista a legutóbbi párosításokat, bejelentkezéseket és foglalásokat mutatja.

## 4. Biztonsági modell

**Ki csatlakozhat.**

- A socket egy privát mappában van (`control/`, `0700` jogosultság), maga a socket `0600`. Ha ez a mappa szimbolikus link, vagy nem a felhasználó a tulajdonosa, a MacVPN nem indítja el a szolgáltatást.
- A MacVPN minden kapcsolatnál lekérdezi a kerneltől a másik fél felhasználói azonosítóját. Más felhasználó folyamatát azonnal bontja.
- Egy kapcsolatnak 5 másodpercen belül el kell küldenie a `pair` vagy a `hello` kérést, és másodpercenként legfeljebb 20 kérést küldhet. Egyszerre legfeljebb 8 kliens kapcsolódhat.

**Hitelesítés.** Minden kapcsolat ezzel kezdődik: `{"op":"hello","token":"…"}`. A MacVPN csak akkor fogadja el, ha:

- a token hash-e egy párosított programéval egyezik (állandó idejű összehasonlítással),
- a párosítást nem vonták vissza, és
- a másik fél futtatható fájljának útvonala pontosan az, amelyhez a párosítás kötve van.

Különben a válasz egy általános `unauthorized`, 1 másodperc késleltetéssel, és a kapcsolat bomlik.

**Mit kap egy párosított program.** Csak az engedélyezett kapcsolatait, csak fel- és lekapcsolást, és csak állapotneveket. Configot, felhasználónevet, jelszót, IP-címet vagy nyers eszközkimenetet nem. A hiba oka egy rövid, lokalizált szöveg, ugyanaz, mint a MacVPN saját értesítésében.

**Naplózás.** A párosítási kérések és eredményeik, a sikertelen bejelentkezések, minden `up` és `down` a program nevével és útvonalával, valamint minden foglalás vége a **Tevékenység** listába és a MacVPN debug kimenetébe kerül. Token soha nem kerül naplóba. A menü és a Kapcsolatok ablak a foglalt kapcsolat mellett ezt mutatja: **Használja: …**.

### Vállalt korlátok

A felhasználó nevében már futó kártevőt ezek az ellenőrzések nem állítják meg teljesen. Egy ilyen kártevő:

- lecserélheti a párosított program futtatható fájlját a rögzített útvonalon, ha azt a felhasználó írhatja, vagy
- elindíthatja vagy vezérelheti magát a párosított programot.

Amit ezzel nyer, korlátozott: csak az engedélyezett kapcsolatokat, csak fel- és lekapcsolást, és semmilyen titkot. Minden művelet látszik a menüben és a Tevékenység listában. Ez megfelel a MacVPN meglévő fenyegetési modelljének, amelyben a Homebrew VPN-eszközei is a felhasználó által írhatók (lásd [Biztonsági megjegyzések](user-guide.hu.md#10-biztonsági-megjegyzések)).

További ismert korlátok:

- A párosítás egy **útvonalhoz** kötődik, nem kódaláíráshoz: a MacVPN és a tipikus kliensek ad-hoc aláírásúak, így nincs stabil aláírói azonosító, amit ellenőrizni lehetne. Az ugyanott újrafordított bináris továbbra is működik; egy másik útvonalon lévő bináris új párosítást igényel.
- A párosítási ablakban látható nevet a program maga adja meg. A programot a futtatható fájl útvonala alapján ítéld meg.
- A kliens futás közben a memóriájában tartja a tokent.

## 5. Protokoll

### 5.1 Formátum

- Soronként egy JSON-objektum, UTF-8 kódolással, `\n` végződéssel (a `\r\n` is elfogadott). Egy kérés sora legfeljebb 4096 bájt lehet.
- Minden kérésben van egy `op` és egy, a kliens által választott `id`: előjel nélküli egész szám. A MacVPN a válaszban visszaküldi az `id`-t. A `pair` és a `hello` elhagyhatja; ekkor a válaszukban sincs `id`.
- A válaszban `"ok":true` vagy `"ok":false` áll. A sikertelen válaszban van egy `error` kód, és lehet egy `message` is.
- Az **események** kéretlen sorok, `event` kulccsal és `id` nélkül. Bármikor érkezhetnek, egy kérés és a válasza között is.
- A kéréseket a MacVPN szigorúan ellenőrzi: ismeretlen mező, ismétlődő kulcs vagy rossz típus `bad_request`, ismeretlen `op` pedig `unsupported`. A válaszok és az események a későbbi verziókban új mezőket kaphatnak; amit nem ismersz, hagyd figyelmen kívül.
- A kapcsolatazonosítók UUID alakúak (`8-4-4-4-12` hexadecimális számjegy), és **kis- és nagybetű-érzékenyek**: pontosan úgy küldd vissza őket, ahogy a `list` adta.
- Egyszerre egy kérést küldj, és várd meg a válaszát. Ez a legegyszerűbb helyes kliens; a példakliens is így működik.

### 5.2 `pair`

```json
{"id":1,"op":"pair","name":"Remote Desktop"}
```

`name`: tisztítás után 1–64 karakter (a vezérlőkarakterekből szóköz lesz, a szöveg elejéről és végéről a szóközök lekerülnek). Az ablakot a [3. szakasz](#3-párosítás) írja le.

```json
{"id":1,"ok":true,"token":"Q2hhbmdlTWUtVGhpcy1Jcy1Ob3QtQS1SZWFsLVRva2Vu","client_id":"0D6A3C2E-9F1B-4C7A-8E25-6B1F0A9D4C33"}
{"id":1,"ok":false,"error":"denied"}
{"id":1,"ok":false,"error":"busy"}
```

A MacVPN a válasz után mindenképp bontja a kapcsolatot. Csatlakozz újra, és küldd el a `hello` kérést.

### 5.3 `hello`

```json
{"id":1,"op":"hello","token":"Q2hhbmdlTWUtVGhpcy1Jcy1Ob3QtQS1SZWFsLVRva2Vu"}
```

```json
{"id":1,"ok":true,"api":1}
{"id":1,"ok":false,"error":"unauthorized"}
```

Az `api` a protokoll verziója, jelenleg `1`. Az `unauthorized` (1 másodperc késleltetéssel) után a kapcsolat bomlik. Ha a token nem 43 base64url karakter, a válasz pontosan ugyanez az `unauthorized`, ugyanazzal a késleltetéssel, így a válaszból nem derül ki, mi volt a hiba. Csak a szerkezetileg hibás `hello` (nem szöveg vagy hiányzó `token`, ismeretlen mező) kap `bad_request` választ, azonnal, és a kapcsolat nyitva marad.

Ha a sikeres `hello` előtt a `pair` és a `hello` kivételével bármilyen kérés érkezik, a válasz `unauthorized`, és a kapcsolat bomlik. Utána egy újabb `pair` vagy `hello` `bad_request`.

### 5.4 `list`

```json
{"id":2,"op":"list"}
```

```json
{"id":2,"ok":true,"connections":[
  {"id":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","name":"Office","kind":"openvpn","state":"disconnected"},
  {"id":"38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4","name":"Office L2TP","kind":"system","state":"connected"}
]}
```

(Itt több sorban látszik; a valóságban egy sor.)

Csak azok a kapcsolatok, amelyeket ez a program használhat, a MacVPN sorrendjében. A `kind` értéke `openvpn`, `wireguard`, `strongswan`, `sstp`, `l2tp`, `cisco`, vagy `system` egy, a MacVPN-en kívül, a macOS-ben beállított VPN-nél. A `state` az [5.8](#58-állapotok) egyik állapota.

### 5.5 `up`

```json
{"id":3,"op":"up","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01"}
```

Foglalást vesz fel erre a socketre, és ha a kapcsolat le van kapcsolva, elindítja, pontosan úgy, mint egy kézi csatlakozás: ugyanazokkal az MFA-ablakokkal, ugyanazzal a Keychainnel, ugyanazokkal az ellenőrzésekkel. Amíg felépül, a kliens eseményeket kap, majd egyetlen végső választ:

```json
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"connecting"}
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"waiting_for_mfa"}
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"connecting"}
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"connected"}
{"id":3,"ok":true,"state":"connected"}
```

vagy például:

```json
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"failed","reason":"Időtúllépés a csatlakozáskor"}
{"id":3,"ok":false,"error":"failed","message":"Időtúllépés a csatlakozáskor"}
```

- **Már fent van:** a `{"id":3,"ok":true,"state":"connected"}` válasz azonnal megjön, események nélkül.
- **Egy másik program már éppen felkapcsolja:** ez a socket csatlakozik ehhez a felépüléshez. Először egy eseményt kap az aktuális állapottal, utána ugyanazokat az eseményeket és a választ.
- A **`waiting_for_mfa`** azt jelenti, hogy a MacVPN kódot vagy bejelentkezést kér a felhasználótól. Szólj a felhasználónak, hogy nézzen rá a MacVPN-re. Ez percekig is tarthat, ezért ne tegyél rövid időkorlátot a válaszra.
- A **`waiting_for_credentials`** azt jelenti, hogy a MacVPN egy el nem mentett felhasználónevet, jelszót, közös kulcsot vagy kulcsjelszót kér a felhasználótól. Ugyanaz érvényes: szólj a felhasználónak, hogy nézzen rá a MacVPN-re, és számolj percekkel. A programod soha nem látja, amit a felhasználó beír. Ha a felhasználó megszakítja (vagy a 2 perces ablak lejár), az `up` `credentials_cancelled` hibával ér véget.
- Ha az `up` sikertelen, a foglalás vele együtt véget ér. Egy későbbi `up` új csatlakozást indít.
- A MacVPN ebben a sorrendben ellenőriz: a párosítás még létezik (`unauthorized`, a kapcsolat bomlik), a kapcsolat engedélyezett (`not_allowed`), még létezik (`unknown_connection`), a szolgáltatás nem áll le éppen (`disabled` / `app_quitting`), a kapcsolat nem vált állapotot foglalás nélkül (`busy`), ez a socket nem vár már ugyanennek a kapcsolatnak az `up` válaszára (`busy`), és csak ha ennek az `up` kérésnek kell elindítania a kapcsolatot: a kapcsolathoz szükséges telepítés teljes (`setup_required`).
- **A telepítés ellenőrzése a kapcsolattól függ.** Az a kapcsolat, amelyet a MacVPN a root segédjén keresztül futtat (OpenVPN, WireGuard, IKEv2, SSTP), Homebrew-t, naprakész root segédet és a típusához tartozó VPN-eszközt igényel. A rendszer VPN és a natív L2TP vagy Cisco IPsec kapcsolat a macOS-en keresztül indul, ezek egyikét sem igényli. A már fent lévő, vagy egy másik foglalás miatt éppen felépülő kapcsolathoz a socket telepítés-ellenőrzés nélkül csatlakozik: az `up` válasza `connected`, akkor is, ha a telepítés nem teljes.

### 5.6 `down`

```json
{"id":4,"op":"down","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01"}
```

```json
{"id":4,"ok":true}
```

Megszünteti ennek a socketnek a foglalását. Ha ez volt az utolsó foglalás egy olyan kapcsolaton, amelyet a foglalások miatt indított el, a MacVPN lebontja, és a válasz a bontás **után** érkezik (előtte `disconnecting` / `disconnected` eseményeket is kaphatsz). Ha ezen a socketen ugyanerre a kapcsolatra egy `up` még válaszra vár, az előbb `failed` választ kap. A `down` mindig sikeres: egy foglalás nélküli, vagy a program számára nem engedélyezett kapcsolathoz egyszerűen nem nyúl.

A `down` küldése nem kötelező: a socket bezárása az összes foglalását megszünteti.

### 5.7 `status`

```json
{"id":5,"op":"status"}
```

```json
{"id":5,"ok":true}
```

Feliratkoztatja ezt a socketet az összes engedélyezett kapcsolat állapot-eseményeire, amíg nyitva marad. A válasz nem tartalmaz állapotokat: az aktuálisakat a `list` adja. `status` nélkül egy socket csak azoknak a kapcsolatoknak az eseményeit kapja, amelyeket foglal, vagy amelyekre vár. Ha a felhasználó lebont egy foglalt kapcsolatot, vagy az megszakad, a socket a lekapcsolódásig továbbra is megkapja az eseményeit.

```json
{"event":"state","connection":"38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4","state":"disconnected"}
```

Esemény csak állapotváltozáskor érkezik; ugyanaz az állapot nem ismétlődik.

### 5.8 Állapotok

| Állapot | Jelentés |
|---|---|
| `disconnected` | Lekapcsolva. |
| `connecting` | Felépül. |
| `waiting_for_mfa` | A MacVPN arra vár, hogy a felhasználó beírjon egy kódot vagy bejelentkezzen. |
| `waiting_for_credentials` | A MacVPN arra vár, hogy a felhasználó megadjon egy hiányzó felhasználónevet, jelszót, közös kulcsot vagy kulcsjelszót (1.1.0-tól). |
| `connected` | Fent van. |
| `disconnecting` | Bomlik. |
| `failed` | Hiba után lekapcsolva. Az eseményben van egy `reason`: rövid, lokalizált szöveg a felhasználónak. |

Minden más állapotot „folyamatban” állapotként kezelj (lásd [8. szakasz](#8-kompatibilitás-a-későbbi-verziókkal)).

### 5.9 Korlátok

| Korlát | Mi történik |
|---|---|
| Egyszerre 8 kliens | A 9. kapcsolat azonnal bomlik, válasz nélkül. |
| 4096 bájtnál hosszabb sor | `{"ok":false,"error":"bad_request"}` `id` nélkül, majd a kapcsolat bomlik. |
| Nincs `pair` vagy `hello` a csatlakozás után 5 másodpercen belül | A kapcsolat válasz nélkül bomlik. |
| Másodpercenként 20-nál több kérés (legfeljebb 20-as löketekben) | A kapcsolat válasz nélkül bomlik. |
| Egy socketen 16-nál több válaszra váró `up` | `busy`. |
| A kliens nem olvassa a válaszait és az eseményeit (64 sor gyűlt össze, vagy egy írás 5 másodpercig blokkol) | A kapcsolat bomlik. |

### 5.10 A `closing` esemény

```json
{"event":"closing","reason":"disabled"}
```

Ha a felhasználó kikapcsolja a **Más appok vezérelhetik a VPN-eket** beállítást (`"reason":"disabled"`), vagy a MacVPN kilép (`"reason":"app_quitting"`), minden hitelesített socket utolsó sorként ezt az eseményt kapja, a válaszra váró `up` kérései válaszai után, majd a kapcsolat bomlik. Így a foglalást tartó program puszta fájlvége helyett megtudja, miért ér véget a socketje. A foglalások a [7. szakasz](#7-foglalási-szabályok) szerint érnek véget.

Az esemény előre kompatibilis: az a kliens, amely nem ismeri, figyelmen kívül hagyja, mint bármely ismeretlen eseménytípust, és egyszerűen fájlvéget lát. A későbbi verziók más okokat is küldhetnek. Visszavonáskor, korlát túllépésekor és hitelesítetlen socketnél a kapcsolat esemény nélkül bomlik.

## 6. Hibakódok

A hibakódok általánosak, soha nem tartalmaznak nyers eszközkimenetet.

| Kód | Mikor | Mit tegyél |
|---|---|---|
| `unauthorized` | `hello` rossz, rossz alakú vagy visszavont tokennel, vagy más futtatható fájl útvonalról, mint a párosításkor. Kérés a `hello` előtt. Kérés azután, hogy a programot visszavonták. A kapcsolat bomlik. | Párosíts újra (lásd [10. szakasz](#10-hibaelhárítás)). |
| `not_allowed` | A kapcsolat nincs a program engedélyezett kapcsolatai között, vagy az azonosítója nem pontosan az, amit a `list` adott. | Kérd meg a felhasználót, hogy engedélyezze a **Párosított appok** alatt. |
| `unknown_connection` | A kapcsolatot törölték a MacVPN-ben. | Hívd meg újra a `list` kérést. |
| `busy` | A kapcsolat foglalás nélkül vált állapotot (valaki más csatlakoztatja vagy bontja), egy foglalás bontása még fut, ez a socket már vár ugyanennek a kapcsolatnak az `up` válaszára, vagy túl sok `up` vár. `pair` esetén: már nyitva van egy párosítási ablak. | Rövid várakozás után próbáld újra. |
| `setup_required` | Az `up` kérésnek a MacVPN root segédje által futtatott kapcsolatot kell elindítania, és hiányzik vagy elavult a Homebrew vagy a root segéd, vagy hiányzik a kapcsolat típusához tartozó VPN-eszköz. Rendszer VPN-nél, natív L2TP / Cisco IPsec kapcsolatnál és már fent lévő kapcsolatnál soha. | Kérd meg a felhasználót, hogy fejezze be a telepítést a MacVPN **Rendszerállapot** ablakában. |
| `mfa_cancelled` | A felhasználó megszakította a kód- vagy bejelentkezési ablakot. | Magától ne próbálkozz újra. |
| `mfa_timeout` | A kód- vagy bejelentkezési ablak lejárt. | Hagyd, hogy a felhasználó újrapróbálja. |
| `credentials_cancelled` | A felhasználó megszakította a hitelesítő adatokat kérő ablakot, vagy az 2 perc után lejárt (1.1.0-tól). | Magától ne próbálkozz újra. |
| `locked` | A MacVPN széfje zárolva van (1.2.0-tól): a `pair`, `hello`, `list`, `up` és `status` kérést elutasítja, amíg a felhasználó fel nem oldja a MacVPN-ben. A `down` továbbra is működik, a meglévő munkamenet és a bérletei megmaradnak. `pair` vagy `hello` után a kapcsolat bezárul. | Kérd meg a felhasználót, hogy oldja fel a MacVPN-t, aztán próbáld újra. |
| `failed` | Minden egyéb hiba. A `message`, ha van, rövid, lokalizált ok a felhasználónak. Akkor is ez jön, ha a felhasználó felépülés közben lebontotta a kapcsolatot a MacVPN-ben, vagy ha a saját `down` kérésed szakította meg az `up`-ot. | Mutasd meg az üzenetet. |
| `app_quitting` | A MacVPN kilép. A kapcsolat ezután bomlik (a [`closing` esemény](#510-a-closing-esemény) `reason` értéke is lehet). | Csatlakozz újra, ha a MacVPN ismét fut. |
| `disabled` | A felhasználó kikapcsolta: **Más appok vezérelhetik a VPN-eket**. A kapcsolat ezután bomlik (a [`closing` esemény](#510-a-closing-esemény) `reason` értéke is lehet). | — |
| `unsupported` | Ismeretlen `op`. | — |
| `bad_request` | Hibás kérés: nem JSON, ismeretlen mező, ismétlődő kulcs, rossz típus, rossz kapcsolatazonosító, rossz név, túl hosszú sor. (A rossz alakú token `unauthorized`.) | Javítsd a klienst. |
| `denied` | Csak `pair` esetén: a felhasználó az **Elutasítás** gombra kattintott, az ablak lejárt, a párosítás 3 elutasítás után szünetel, vagy a MacVPN nem tudta kiolvasni a program futtatható fájljának útvonalát. | — |

Minden más kódot `failed` kódként kezelj (lásd [8. szakasz](#8-kompatibilitás-a-későbbi-verziókkal)).

## 7. Foglalási szabályok

- Egy kapcsolatot többen is foglalhatnak. Minden socket, amely sikeres `up` kérést küldött, egy foglalást tart, akkor is, ha ugyanannak a programnak a socketjei.
- **Az utolsó foglalás vége lebontja a VPN-t.** Ha az utolsó foglaló `down` kérést küld, bezárja a socketet, kilép vagy összeomlik, vagy visszavonják, a MacVPN lebontja azt a kapcsolatot, amelyet a foglalások miatt indított el.
- **A korábban is futó kapcsolat fent marad.** Ha a kapcsolat foglalás nélkül már fent volt (a felhasználó vagy más indította), az `up` csak `connected` választ ad, és semmilyen foglalás vége nem bontja le.
- **A felhasználó dönt.** Ha a felhasználó a MacVPN-ben bont egy foglalt kapcsolatot, azonnal véget ér rajta minden foglalás. A foglalók megkapják a `disconnecting` és a `disconnected` eseményt (a válaszra váró `up` pedig `failed` választ), és a MacVPN magától nem kapcsolódik újra. A socket ezutáni bezárása már nem változtat semmin.
- **A megszakadás is véget vet a foglalásnak.** Ha a VPN hibára fut vagy megszakad, a foglalók megkapják a `failed` (vagy `disconnected`) eseményt, és a foglalások véget érnek. Az újracsatlakozás a program dolga: küldjön újra `up` kérést.
- **Alvás és ébredés.** A socketek nyitva maradnak. Ha közben a VPN megszakad, az előző szabály érvényes.
- **A beállítás kikapcsolása.** A válaszra váró `up` kérések `disabled` választ kapnak, minden hitelesített socket megkapja a `closing` eseményt `"reason":"disabled"` értékkel, minden socket bezárul, és a foglalások a szokásos módon érnek véget: azok a kapcsolatok, amelyeket csak a foglalások tartottak fent, lebomlanak.
- **Kilépés a MacVPN-ből.** A kilépési kérdés megnevezi a kapcsolatokat foglaló programokat: **Más appok is használják a MacVPN-en keresztül: …. A kilépés megszakítja a munkamenetüket.** A válaszra váró `up` kérések `app_quitting` választ kapnak, minden hitelesített socket megkapja a `closing` eseményt `"reason":"app_quitting"` értékkel, és minden socket bezárul. A foglalások bontás **nélkül** érnek véget: a kilépési kérdés dönt. A **Leállítás és kilépés** a szokásos módon minden kapcsolatot bont, a **Kilépés, fussanak tovább** pedig fent hagyja őket, foglalás nélkül (a MacVPN a következő indításkor korábban is futó kapcsolatként találja meg őket).
- A menü és a Kapcsolatok ablak a foglalt kapcsolat mellett ezt mutatja: **Használja: …**.

## 8. Kompatibilitás a későbbi verziókkal

A későbbi MacVPN verziók új állapotokat és hibakódokat vezetnek be az `api` megváltoztatása nélkül. Ilyen kiegészítés a `waiting_for_credentials` állapot és a `credentials_cancelled` hiba; ezek az 1-es API-val egy kiadásban jelennek meg (1.1.0). Ilyen a `locked` hiba is (1.2.0). Minden kliensnek ezeket a szabályokat kell követnie:

- **Az ismeretlen állapot „folyamatban” állapotot jelent.** Várj tovább az `up` végső válaszára, és tartsd meg a foglalást.
- **Az ismeretlen hibakód `failed` hibát jelent.** Mutasd meg a `message` szövegét, ha van, és naplózd a kódot.
- A válaszok és az események **ismeretlen mezőit**, valamint az ismeretlen `event` típusokat hagyd figyelmen kívül. A [`closing` eseményt](#510-a-closing-esemény) nem ismerő régebbi kliens figyelmen kívül hagyja, és továbbra is működik: fájlvéget lát.
- Ne küldj olyan mezőt, amelyet ez a dokumentum nem ír le: a kéréseket a MacVPN szigorúan ellenőrzi.

A példakliens mindezt megvalósítja: a `State::Other` „folyamatban” állapot, az `ErrorCode::from_wire` pedig az ismeretlen kódokat `Failed` kódra képezi le.

## 9. Hogyan illeszd be egy Rust appba

### 9.1 Másold át a klienst

Másold be az [`examples/macvpn-control-client/src/lib.rs`](../examples/macvpn-control-client/src/lib.rs) fájlt az appodba, például `src/macvpn.rs` néven, és vedd fel a `serde_json` függőséget. Tartalma:

- `Client`: egy socket. `Client::pair`, `Client::open` (csatlakozás + `hello`), `list`, `up(id, on_event)`, `down`, `status`, `next_event`, `closer`, és `closing_reason` (a `closing` esemény oka, miután a socket bezárult).
- `Lease`: egy távoli munkamenet foglalása egy VPN-en.
- `State`, `ErrorCode`, `Error`: beépítve a kompatibilitási szabályokkal.

### 9.2 A token tárolása a Keychainben

A tokent általános jelszóként (generic password) tárold az appod saját Keychain-elemében, egy saját szolgáltatásnév alatt.

A [`security-framework`](https://crates.io/crates/security-framework) crate-tel:

```rust
use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};

const SERVICE: &str = "com.example.remote-desktop.macvpn";
const ACCOUNT: &str = "control-token";

fn store_token(token: &str) -> Result<(), security_framework::base::Error> {
    set_generic_password(SERVICE, ACCOUNT, token.as_bytes())
}

fn load_token() -> Option<String> {
    let bytes = get_generic_password(SERVICE, ACCOUNT).ok()?;
    String::from_utf8(bytes).ok()
}

fn forget_token() {
    let _ = delete_generic_password(SERVICE, ACCOUNT);
}
```

Külön crate nélkül, a `security` paranccsal. Ennek interaktív módja (`security -i`) a szabványos bemenetről olvassa a parancsot, így a token soha nem jelenik meg olyan parancssorban, amelyet más folyamatok láthatnak:

```rust
use std::io::Write;
use std::process::{Command, Stdio};

const SERVICE: &str = "com.example.remote-desktop.macvpn";
const ACCOUNT: &str = "control-token";

fn store_token(token: &str) -> std::io::Result<bool> {
    // A token base64url (A–Z, a–z, 0–9, '-', '_'), nem kell idézőjelezni.
    let mut child = Command::new("/usr/bin/security").arg("-i").stdin(Stdio::piped()).stdout(Stdio::null()).spawn()?;
    let command = format!("add-generic-password -U -s {SERVICE} -a {ACCOUNT} -w {token}\n");
    child.stdin.take().expect("piped").write_all(command.as_bytes())?; // eldobva: vége a bemenetnek
    // A `security -i` kilépési kódja nem jelzi a sikertelen parancsot: olvasd vissza az elemet.
    Ok(child.wait()?.success() && load_token().as_deref() == Some(token))
}

fn load_token() -> Option<String> {
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
```

Terminálból: `security add-generic-password -U -s com.example.remote-desktop.macvpn -a control-token -w` (ha a `-w` az utolsó, a `security` bekéri az értéket).

### 9.3 Párosítás magából az appból

A MacVPN a párosító folyamat futtatható fájljának útvonalát rögzíti. Ezért az app saját magát párosítja, például a beállításaiban egy **Párosítás a MacVPN-nel** gombbal:

```rust
use macvpn::{Client, ErrorCode, default_socket_path};

fn pair_with_macvpn() -> Result<(), Box<dyn std::error::Error>> {
    // Addig blokkol, amíg a felhasználó nem válaszol a MacVPN ablakában (legfeljebb kb. 2 perc): ne a UI szálon fusson.
    let pairing = match Client::pair(&default_socket_path()?, "Remote Desktop") {
        Err(e) if e.code() == Some(ErrorCode::Denied) => return Err("A MacVPN nem engedélyezte a párosítást".into()),
        other => other?,
    };
    store_token(&pairing.token)?; // a token többé nem jelenik meg
    Ok(())
}
```

Ha a socket nem létezik (`Error::Io`, `NotFound` vagy `ConnectionRefused` hibával), kérd meg a felhasználót, hogy a MacVPN-ben kapcsolja be ezt: **Más appok vezérelhetik a VPN-eket**. Ha később a `hello` válasza `unauthorized`, töröld a tokent, és ajánld fel az újrapárosítást.

### 9.4 A socket élettartama a távoli munkamenethez kötve

**Távoli munkamenetenként egy socketet** nyiss, a munkamenet elején vedd fel a foglalást, és a végén zárd be a socketet. Ne tarts egy hosszú életű socketet az egész appnak: a foglalás, és vele a VPN, túlélné a munkamenetet.

```rust
use macvpn::{Lease, State, default_socket_path};

fn run_session(connection_id: &str, host: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Some(token) = load_token() else { return Err("előbb párosítsd a MacVPN-nel".into()) };
    // Csatlakozik, 5 másodpercen belül elküldi a hello-t, majd az up-ot, és megvárja a "connected" állapotot.
    let mut vpn = Lease::acquire(&default_socket_path()?, &token, connection_id, |event| match event.state {
        State::WaitingForMfa => show_status("Hagyd jóvá a bejelentkezést a MacVPN-ben"),
        State::WaitingForCredentials => show_status("Add meg a VPN jelszavát a MacVPN-ben"),
        ref state if state.is_in_progress() => show_status("A VPN csatlakozik…"),
        _ => {}
    })?;

    // A munkamenet alatt figyeld a VPN-t: külön szálon, vagy az eseményhurkodban.
    let closer = vpn.closer()?;
    let watcher = std::thread::spawn(move || {
        while let Ok(Some(change)) = vpn.next_change() {
            if change.state.is_down() {
                // A felhasználó a MacVPN-ben bontotta, vagy megszakadt. A foglalás véget ért.
                notify_user("A VPN lekapcsolódott");
                break;
            }
        }
        // Itt a `vpn` eldobódik: a socket bezárul.
    });

    let result = remote_desktop_session(host); // maga a munkamenet

    closer.close(); // vége a munkamenetnek: a socket bezárul, a foglalás véget ér
    let _ = watcher.join();
    Ok(result?)
}
```

A garanciát maga a socket adja: ha az appod összeomlik vagy leállítják, a kernel bezárja a socketet, és a MacVPN megszünteti a foglalást. Ha két munkamenetnek ugyanaz a VPN kell, mindkettő a saját `Lease` értékét tartja; a VPN addig marad fent, amíg mindkettő véget nem ér.

A kapcsolat kiválasztása: hívd meg a `list` kérést (például az appod kapcsolatbeállításaiban), hagyd, hogy a felhasználó válasszon, és az `id`-t pontosan úgy tárold, ahogy megkaptad. A `name` változhat, az `id` nem.

## 10. Hibaelhárítás

- **A socket nem létezik** (`No such file or directory` vagy `Connection refused`). Ki van kapcsolva a **Más appok vezérelhetik a VPN-eket** beállítás, vagy nem fut a MacVPN. Kapcsold be a Kapcsolatok ablakban → **Párosított appok**. Ha a kapcsoló alatt üzenet látszik, az megnevezi az okot.
- **`unauthorized` újrafordítás vagy áthelyezés után.** A párosítás a futtatható fájl útvonalához kötődik. Egy másik mappában készült build (például `target/debug` a telepített `/Applications/…` helyett) vagy egy áthelyezett app nem egyezik vele. A Párosított appok listája ilyenkor ezt mutatja: **Megváltozott az útvonal**, az új útvonallal. Vond vissza a régi bejegyzést, és párosíts újra az új helyről.
- **`unauthorized`, pedig korábban működött.** A programot visszavonták a **Párosított appok** alatt, vagy rosszul tárolódott a token. Párosíts újra.
- **`busy`.** A kapcsolatot éppen valaki más csatlakoztatja vagy bontja (a felhasználó, a MacVPN, vagy egy éppen véget ért foglalás). Várj egy kicsit, és próbáld újra. `pair` esetén: már nyitva van egy párosítási ablak. Ha a saját `down` kérésed vagy egy bezárt socket után közvetlenül kapod `up`-ra, a bontás még fut.
- **`setup_required`.** A MacVPN telepítése nem teljes: hiányzik vagy elavult a Homebrew, a root segéd vagy a kapcsolat típusához tartozó VPN-eszköz. Nyisd meg a MacVPN **Rendszerállapot** ablakát, és fejezd be a telepítést. A MacVPN ezt csak akkor ellenőrzi, ha az `up` kérésnek a root segéd által futtatott kapcsolatot kell elindítania; rendszer VPN, natív L2TP / Cisco IPsec kapcsolat és már fent lévő kapcsolat soha nem kapja.
- **`not_allowed`.** Jelöld be a kapcsolatot az **Engedélyezett kapcsolatok** között a **Párosított appok** alatt. Ellenőrizd, hogy az azonosítót pontosan úgy küldöd-e, ahogy a `list` adta (az azonosítók kis- és nagybetű-érzékenyek).
- **A kapcsolat rögtön a csatlakozás után bomlik.** Küldd el a `hello` (vagy a `pair`) kérést 5 másodpercen belül, maradj másodpercenként 20 kérés alatt, és folyamatosan olvasd a socketet: azt a klienst, amelynél felgyűlnek a válaszok és az események, a MacVPN lecsatlakoztatja.
- **Azonnali `denied`, ablak nélkül.** 3 elutasítás után a párosítás 10 percig szünetel.
- **A VPN a munkamenet után is fent marad.** Már az első foglalás előtt is fent volt (korábban is futó kapcsolat), vagy egy másik socket még foglalja. Nézd meg a **Használja: …** feliratot.
