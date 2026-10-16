import Foundation

public enum ConfigImportError: LocalizedError, Equatable {
    case missingFile(String)
    case unsupported(String)
    case unknownType
    /// Natív (L2TP / Cisco) export: a Finderből, a macOS Profilokon át kell telepíteni, nem a MacVPN-be importálni.
    case nativeProfile

    public var errorDescription: String? {
        switch self {
        case .missingFile(let f): return L10n.tr("Referenced file not found: %@", f)
        case .unsupported(let d): return L10n.tr("Directive not supported for import: %@", d)
        case .unknownType: return L10n.tr("Cannot detect the config type")
        case .nativeProfile: return L10n.tr("A .mobileconfig profile cannot be imported into MacVPN. Double-click it in Finder: macOS installs it as a profile, then approve it in System Settings → General → Device Management (Profiles).")
        }
    }
}

public enum ConfigImporter {
    /// Mint a `detectKind`, de hibával jelzi, miért nem importálható a fájl.
    public static func kind(fileName: String, content: String) throws -> VPNKind {
        if (fileName as NSString).pathExtension.lowercased() == "mobileconfig" { throw ConfigImportError.nativeProfile }
        guard let kind = detectKind(fileName: fileName, content: content) else { throw ConfigImportError.unknownType }
        return kind
    }

    public static func detectKind(fileName: String, content: String) -> VPNKind? {
        let ext = (fileName as NSString).pathExtension.lowercased()
        if ext == "ovpn" { return .openvpn }
        let lower = content.lowercased()
        if lower.contains("[interface]"), lower.contains("privatekey") { return .wireguard }
        if content.range(of: "(?m)^\\s*connections\\s*\\{", options: .regularExpression) != nil { return .strongswan }
        if content.range(of: "(?m)^\\s*remote\\s+\\S+", options: .regularExpression) != nil,
           content.range(of: "(?m)^\\s*(client|dev\\s+tun)", options: .regularExpression) != nil { return .openvpn }
        return nil
    }

    static let inlineable: Set<String> = ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs", "dh"]

    /// A külső fájlra hivatkozó OpenVPN direktívákat inline blokká alakítja.
    public static func inlineOpenVPNFiles(_ content: String, baseDirectory: URL) throws -> String {
        var out: [String] = []
        for raw in content.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: CharacterSet.whitespaces.union(CharacterSet(charactersIn: "\r")))
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let first = tokens.first?.lowercased(), tokens.count >= 2, tokens[1] != "[inline]" else {
                out.append(raw)
                continue
            }
            if first == "auth-user-pass" {
                out.append("auth-user-pass")
                continue
            }
            if first == "pkcs12" { throw ConfigImportError.unsupported("pkcs12") }
            guard inlineable.contains(first) else {
                out.append(raw)
                continue
            }
            let path = tokens[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            let url = path.hasPrefix("/") ? URL(fileURLWithPath: path) : baseDirectory.appendingPathComponent(path)
            guard let data = try? String(contentsOf: url, encoding: .utf8) else {
                throw ConfigImportError.missingFile(path)
            }
            out.append("<\(first)>")
            out.append(data.hasSuffix("\n") ? String(data.dropLast()) : data)
            out.append("</\(first)>")
            if first == "tls-auth", tokens.count >= 3 { out.append("key-direction \(tokens[2])") }
        }
        return out.joined(separator: "\n")
    }

    public static func template(for kind: VPNKind) -> String {
        switch kind {
        case .openvpn:
            return """
            client
            dev tun
            proto udp
            remote vpn.example.com 1194
            nobind
            persist-key
            persist-tun
            remote-cert-tls server
            auth-user-pass
            <ca>
            </ca>

            """
        case .wireguard:
            return """
            [Interface]
            PrivateKey =
            Address = 10.0.0.2/32
            DNS = 1.1.1.1

            [Peer]
            PublicKey =
            AllowedIPs = 0.0.0.0/0
            Endpoint = vpn.example.com:51820

            """
        case .strongswan:
            return """
            connections {
              myvpn {
                remote_addrs = vpn.example.com
                vips = 0.0.0.0
                local {
                  auth = eap-mschapv2
                  eap_id = felhasznalo
                }
                remote {
                  auth = pubkey
                  id = vpn.example.com
                }
                children {
                  myvpn {
                    remote_ts = 0.0.0.0/0
                  }
                }
              }
            }

            """
        case .l2tp, .cisco:
            return ""
        }
    }
}
