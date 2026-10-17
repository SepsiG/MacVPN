import Foundation
import MacVPNCore

// Root oldali validátor a `mvpn` scripthez. Ugyanazt a kódot futtatja, mint az app.
//   mvpn-validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> <fájl> → hibák soronként stdout-ra; exit 1, ha van hiba
//   mvpn-validate [--lang en|hu] --swan-names <fájl>                    → connection és child név két sorban; exit 1, ha nincs
//   mvpn-validate [--lang en|hu] --sstp-params <fájl>                   → validált SSTP paraméterek soronként (server, port,
//                                                                         user, cert, route_all, peer_dns); exit 1, ha hibás
//   mvpn-validate [--lang en|hu] --sstp-ca <fájl>                       → a validált config <ca> PEM blokkja; exit 1, ha nincs
// A nyelvet a `--lang` adja (a `sudo` nem viszi át a felhasználó locale-ját); hiányzó vagy ismeretlen érték: angol.
// Az üzenetek a MacVPNCore beágyazott táblájából jönnek (`L10n`), resource bundle nem kell.

var args = Array(CommandLine.arguments.dropFirst())
AppLanguage.override = .en
if let i = args.firstIndex(of: "--lang") {
    AppLanguage.override = i + 1 < args.count ? AppLanguage(argument: args[i + 1]) : .en
    args.removeSubrange(i..<min(i + 2, args.count))
}

func readFile(_ path: String) -> String {
    guard let data = FileManager.default.contents(atPath: path) else {
        print(L10n.tr("Cannot read the file: %@", path))
        exit(2)
    }
    return String(decoding: data, as: UTF8.self)
}

guard args.count == 2 else {
    print(L10n.tr("Usage: mvpn-validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> <file> | --swan-names <file> | --sstp-params <file> | --sstp-ca <file>"))
    exit(2)
}

if args[0] == "--swan-names" {
    guard let names = StrongSwanValidator.names(in: readFile(args[1])) else { exit(1) }
    print(names.connection)
    print(names.child)
    exit(0)
}

if args[0] == "--sstp-params" {
    guard let params = SSTPValidator.parameters(in: readFile(args[1])) else { exit(1) }
    params.forEach { print($0) }
    exit(0)
}

if args[0] == "--sstp-ca" {
    guard let pem = SSTPValidator.caPEM(in: readFile(args[1])) else { exit(1) }
    print(pem)
    exit(0)
}

guard let kind = VPNKind(rawValue: args[0]), let validator = Validators.validator(for: kind) else {
    print(L10n.tr("Unknown type: %@", args[0]))
    exit(2)
}
let issues = validator.validate(readFile(args[1]))
issues.forEach { print($0.display) }
exit(issues.isEmpty ? 0 : 1)
