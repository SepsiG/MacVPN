import Foundation

/// The two UI languages. English is the source language and the fallback.
public enum AppLanguage: String, CaseIterable, Sendable {
    case en, hu

    /// The first preferred language that is Hungarian or English; anything else (or nothing) means English.
    /// This mirrors how Foundation picks between the app's `en` and `hu` localizations.
    public static func resolve(preferred: [String]) -> AppLanguage {
        for language in preferred {
            let code = language.lowercased()
            if code == "hu" || code.hasPrefix("hu-") || code.hasPrefix("hu_") { return .hu }
            if code == "en" || code.hasPrefix("en-") || code.hasPrefix("en_") { return .en }
        }
        return .en
    }

    /// Fixed language for processes that get it on the command line (`mvpn-validate --lang`) and for tests.
    nonisolated(unsafe) public static var override: AppLanguage?

    public static var current: AppLanguage { override ?? resolve(preferred: Locale.preferredLanguages) }

    /// `--lang` value: `hu` gives Hungarian, anything else English.
    public init(argument: String) {
        self = argument == "hu" ? .hu : .en
    }
}

/// MacVPNCore texts. An embedded table instead of a resource bundle, because the same code runs as root in
/// `mvpn-validate` (`/usr/local/libexec/macvpn`), where no `MacVPN_MacVPNCore.bundle` exists. The key is the
/// English text (also the `en` value); `hungarian` holds the translations. `String(format:)` specifiers.
public enum L10n {
    public static func tr(_ key: String, _ args: CVarArg..., language: AppLanguage = .current) -> String {
        let format = language == .hu ? (hungarian[key] ?? key) : key
        return args.isEmpty ? format : String(format: format, locale: nil, arguments: args)
    }

    public static let hungarian: [String: String] = [
        // Validators (also printed by mvpn-validate as root)
        "Control character not allowed": "Nem engedélyezett vezérlőkarakter",
        "Invalid closing tag": "Hibás záró tag",
        "Inline block not allowed: %@": "Nem engedélyezett inline blokk: %@",
        "Unclosed inline block: %@": "Lezáratlan inline blokk: %@",
        "Missing remote directive": "Hiányzik a remote direktíva",
        "Invalid directive": "Érvénytelen direktíva",
        "setenv: missing argument": "setenv: hiányzó argumentum",
        "setenv opt: missing directive": "setenv opt: hiányzó direktíva",
        "setenv not allowed: %@": "Nem engedélyezett setenv: %@",
        "setenv not allowed": "Nem engedélyezett setenv",
        " – delete the line or comment it out (#)": " – töröld vagy tedd megjegyzésbe (#) a sort",
        "Forbidden directive: %@": "Tiltott direktíva: %@",
        "Directive not allowed: %@": "Nem engedélyezett direktíva: %@",
        "External file reference, use an inline block: %@": "Külső fájl hivatkozás, inline blokk kell: %@",
        "Unknown section": "Ismeretlen szakasz",
        "Invalid line": "Érvénytelen sor",
        "Key not allowed": "Nem engedélyezett kulcs",
        "Key not allowed: %@": "Nem engedélyezett kulcs: %@",
        "Forbidden key: %@": "Tiltott kulcs: %@",
        "Exactly one [Interface] section is required": "Pontosan egy [Interface] szakasz kell",
        "Missing PrivateKey": "Hiányzik a PrivateKey",
        "At least one [Peer] with a PublicKey is required": "Legalább egy [Peer] kell PublicKey-jel",
        "Character not allowed: \\": "Nem engedélyezett karakter: \\",
        "Unbalanced quote (multi-line strings are not allowed)": "Páratlan idézőjel (többsoros string nem engedélyezett)",
        "Forbidden: include": "Tiltott: include",
        "Missing connections block": "Hiányzik a connections blokk",
        "Missing children block": "Hiányzik a children blokk",
        "Invalid argument: %@": "Érvénytelen argumentum: %@",
        "Wrong number of arguments: %@": "Hibás argumentumszám: %@",
        "Directive not allowed in a <connection> block: %@": "Nem engedélyezett direktíva <connection> blokkban: %@",
        "Invalid value: %@": "Érvénytelen érték: %@",
        "Section not allowed: %@": "Nem engedélyezett szakasz: %@",
        "Section not allowed": "Nem engedélyezett szakasz",
        "Only a file name is allowed, no path: %@": "Csak fájlnév adható meg, útvonal nem: %@",
        "Forbidden: file: URI": "Tiltott: file: URI",
        "Unexpected closing brace": "Váratlan záró kapcsos zárójel",
        "Unclosed section": "Lezáratlan szakasz",
        "Line %ld: %@": "%ld. sor: %@",
        "Invalid line in the CA certificate block": "Érvénytelen sor a CA tanúsítvány blokkban",
        "Only one <ca> block is allowed": "Csak egy <ca> blokk lehet",
        "Duplicate key: %@": "Ismétlődő kulcs: %@",
        "Missing key: %@": "Hiányzó kulcs: %@",
        "cert=ca requires a <ca> block with a PEM certificate": "A cert=ca mellé PEM tanúsítványt tartalmazó <ca> blokk kell",
        "Invalid server: use a host name or an IPv4/IPv6 address, without a port":
            "Érvénytelen szerver: hosztnév vagy IPv4/IPv6 cím kell, port nélkül",
        "Invalid port: 1–65535": "Érvénytelen port: 1–65535",
        "The SSTP password must not contain quotation marks, backslashes or control characters":
            "Az SSTP jelszóban nem lehet idézőjel, fordított perjel és vezérlőkarakter",
        "Invalid user name: letters, digits and . _ @ + - only (use user@domain instead of DOMAIN\\user)":
            "Érvénytelen felhasználónév: csak betű, számjegy és . _ @ + - lehet (DOMAIN\\user helyett user@domain)",
        "Invalid value for %@: allowed: %@": "Érvénytelen érték (%@), megengedett: %@",

        // mvpn-validate
        "Cannot read the file: %@": "A fájl nem olvasható: %@",
        "Usage: mvpn-validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> <file> | --swan-names <file> | --sstp-params <file> | --sstp-ca <file>":
            "Használat: mvpn-validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> <fájl> | --swan-names <fájl> | --sstp-params <fájl> | --sstp-ca <fájl>",
        "Unknown type: %@": "Ismeretlen típus: %@",

        // Connections, root and native backends
        "The connection dropped": "A kapcsolat megszakadt",
        "mvpn error (exit code: %d)": "mvpn hiba (kilépési kód: %d)",
        "scutil error (exit code: %d)": "scutil hiba (kilépési kód: %d)",
        "The command was stopped after a timeout: %@": "A parancs időtúllépés miatt megszakadt: %@",
        "The connection could not be established – for details, connect in debug mode":
            "A kapcsolat nem jött létre – részletek: debug csatlakozás",
        "Cannot query the status: %@": "Az állapot nem kérdezhető le: %@",
        "Timed out": "Időtúllépés",
        "The profile is not installed: %@": "A profil nincs telepítve: %@",
        "More than one VPN service is named “%@”. MacVPN does not pass the password until it is clear which one is its own: rename or remove the other one in System Settings → Network.":
            "Több „%@” nevű VPN szolgáltatás van. A MacVPN nem adja át a jelszót, amíg nem egyértelmű, melyik az övé: nevezd át vagy töröld a másikat a Rendszerbeállítások → Hálózat alatt.",
        "The server address of the VPN service named “%@” does not match this connection’s server. MacVPN does not pass the password or the PSK to it: reinstall the profile in MacVPN → Connections, or remove the other service in System Settings → Network.":
            "A(z) „%@” nevű VPN szolgáltatás szervercíme nem egyezik a kapcsolat szerverével. A MacVPN nem adja át neki a jelszót és a PSK-t: telepítsd újra a profilt a MacVPN → Kapcsolatok alatt, vagy töröld a másik szolgáltatást a Rendszerbeállítások → Hálózat alatt.",
        "Cannot open the VPN service: %@": "A VPN szolgáltatás nem nyitható meg: %@",
        "Cannot start the VPN service: %@": "A VPN szolgáltatás nem indítható: %@",
        "Cannot stop the VPN service: %@": "A VPN szolgáltatás nem állítható le: %@",
        "The connection did not come up.": "A kapcsolat nem jött létre.",
        "The connection did not come up. If this is an L2TP/IPsec VPN, enter its shared secret (PSK) in MacVPN → Connections → %@.":
            "A kapcsolat nem jött létre. Ha ez egy L2TP/IPsec VPN, add meg a közös kulcsát (PSK) itt: MacVPN → Kapcsolatok → %@.",

        "The user name, password and PSK must not contain line breaks or control characters":
            "A felhasználónév, a jelszó és a PSK nem tartalmazhat sortörést vagy vezérlőkaraktert",

        // Log filter
        "All": "Minden",
        "Commands": "Parancsok",
        "Errors": "Hibák",

        // Import, export, storage
        "Referenced file not found: %@": "A hivatkozott fájl nem található: %@",
        "The referenced file is outside the config's folder: %@": "A hivatkozott fájl a config mappáján kívül van: %@",
        "The referenced file is larger than 1 MB: %@": "A hivatkozott fájl nagyobb 1 MB-nál: %@",
        "The file for the %@ directive (%@) does not have the expected format": "A(z) %@ direktíva fájlja (%@) nem a várt formátumú",
        "Directive not supported for import: %@": "Nem támogatott direktíva importnál: %@",
        "Cannot detect the config type": "Nem ismerhető fel a config típusa",
        "A .mobileconfig profile cannot be imported into MacVPN. Double-click it in Finder: macOS installs it as a profile, then approve it in System Settings → General → Device Management (Profiles).":
            "A .mobileconfig profil nem importálható a MacVPN-be. Kattints rá duplán a Finderben: a macOS profilként telepíti, utána a Rendszerbeállítások → Általános → Eszközkezelés (Profilok) alatt hagyd jóvá.",
        "Cannot write: %@": "Nem írható: %@",
        "Cannot set the permissions: %@": "Nem állítható be a jogosultság: %@",
        "Cannot delete: %@": "Nem törölhető: %@",
        "Not a directory: %@": "Nem könyvtár: %@",
        "A profile can only be generated for L2TP and Cisco IPsec connections":
            "Csak L2TP és Cisco IPsec kapcsolathoz generálható profil",
        "Cisco IPsec requires a group name": "Cisco IPsec-hez csoportnév szükséges",

        // Root installer and uninstaller
        "Invalid user name: %@": "Érvénytelen felhasználónév: %@",
        "Cannot create a temporary directory": "Nem hozható létre ideiglenes könyvtár",
        "Cannot set the permissions of the temporary directory": "Nem állítható be az ideiglenes könyvtár jogosultsága",
        "Cannot write the installer script": "Nem írható a telepítő script",
        "Cannot set the permissions of the script": "Nem állítható be a script jogosultsága",
        "Installation cancelled": "A telepítés megszakítva",
        "Installation error": "Telepítési hiba",
        "Unsafe directory, installation cancelled:": "Nem biztonságos könyvtár, a telepítés megszakítva:",
        "Installation cancelled: %@ is not owned by root or is writable by other users, so anything running as that user could replace the MacVPN root scripts. Fix it in Terminal, then try again: sudo chown root:wheel %@ && sudo chmod go-w %@ (on Intel Macs this may affect Homebrew).":
            "A telepítés megszakítva: a(z) %@ nem a root tulajdona, vagy más felhasználó is írhatja, így bármi, ami ennek a felhasználónak a nevében fut, kicserélhetné a MacVPN root scriptjeit. Javítsd a Terminálban, majd próbáld újra: sudo chown root:wheel %@ && sudo chmod go-w %@ (Intel Macen ez érintheti a Homebrew-t).",
        "Integrity check failed, installation cancelled:": "A sértetlenség-ellenőrzés sikertelen, a telepítés megszakítva:",
        "Uninstall cancelled": "Az eltávolítás megszakítva",
        "Uninstall error": "Eltávolítási hiba",
        "Could not disconnect:": "Nem bontható kapcsolat:",
        "A connection could not be disconnected, uninstall cancelled.\n\n%@":
            "Egy kapcsolat nem bontható, az eltávolítás megszakítva.\n\n%@",

        // Updates
        "Invalid update source: %@": "Érvénytelen frissítési forrás: %@",
        "No release available (HTTP 404)": "Nincs elérhető kiadás (HTTP 404)",
        "GitHub is temporarily limiting requests (HTTP 403). Try again later.":
            "A GitHub átmenetileg korlátozza a lekérdezéseket (HTTP 403). Próbáld később.",
        "The server returned an error (HTTP %ld)": "A szerver hibát adott (HTTP %ld)",
        "Unexpected response from GitHub": "Értelmezhetetlen válasz a GitHubtól",
        "Missing from the release: %@": "A kiadásból hiányzik: %@",
        "Download address not allowed: %@": "Nem megengedett letöltési cím: %@",
        "Invalid checksum file (.sha256)": "Hibás ellenőrzőösszeg-fájl (.sha256)",
        "The checksum (SHA-256) of the downloaded file does not match. Update cancelled.":
            "A letöltött fájl ellenőrzőösszege (SHA-256) nem egyezik. A frissítés megszakítva.",
        "The update is not signed by the MacVPN maintainer": "A frissítést nem a MacVPN fejlesztője írta alá",
        "Cannot mount the disk image: %@": "A lemezkép nem csatolható: %@",
        "The app on the disk image is not accepted: %@": "A lemezképen lévő alkalmazás nem fogadható el: %@",
        "The app's location is not writable: %@. Drag the app to the Applications folder, or update manually from the DMG.":
            "Az alkalmazás helye nem írható: %@. Húzd az appot az Alkalmazások mappába, vagy frissíts kézzel a DMG-ből.",
        "Cannot start the installer helper script: %@": "A telepítő segédscript nem indítható: %@",
        "unexpected hdiutil output": "értelmezhetetlen hdiutil kimenet",
        "no mount point": "nincs csatolási pont",
        "the mounted disk image is not the downloaded and verified file":
            "a csatolt lemezkép nem a letöltött és ellenőrzött fájl",
        "signature verification failed: %@": "az aláírás ellenőrzése sikertelen: %@",
        "%@ not found": "%@ nem található",
        "cannot read Info.plist": "az Info.plist nem olvasható",
        "bundle identifier %@, expected: %@": "a bundle azonosító %@, várt: %@",
        "version %@, expected: %@": "a verzió %@, várt: %@",
        "link pointing outside the bundle: %@": "a bundle-ön kívülre mutató link: %@",
        "exit code: %d": "kilépési kód: %d",
        // Launch at login
        "Approve MacVPN in System Settings → General → Login Items.":
            "Engedélyezd a MacVPN-t a Rendszerbeállítások → Általános → Bejelentkezési elemek alatt.",
        "Enabled via a login LaunchAgent (applies at next login).":
            "Bejelentkezési LaunchAgenttel bekapcsolva (a következő bejelentkezéstől érvényes).",
        "Refusing to write %@: it is a symbolic link or not a regular file.":
            "A(z) %@ nem írható: szimbolikus link vagy nem szabályos fájl.",
        "Could not write %@: %@":
            "A(z) %@ nem írható: %@",
        "Could not remove %@: %@":
            "A(z) %@ nem törölhető: %@",
        "Launch at login is available only when MacVPN runs from the Applications folder. Drag the app there first.":
            "Az indítás bejelentkezéskor csak akkor érhető el, ha a MacVPN az Alkalmazások mappából fut. Előbb húzd oda az appot.",
        "macOS is running MacVPN from a temporary location. Move the app to the Applications folder and open it from there.":
            "A macOS egy ideiglenes helyről futtatja a MacVPN-t. Helyezd az appot az Alkalmazások mappába, és onnan nyisd meg.",
    ]
}
