import Foundation

public enum VPNKind: String, Codable, CaseIterable, Sendable {
    case openvpn, wireguard, strongswan, sstp, l2tp, cisco

    public var displayName: String {
        switch self {
        case .openvpn: return "OpenVPN"
        case .wireguard: return "WireGuard"
        case .strongswan: return "IKEv2"
        case .sstp: return "SSTP"
        case .l2tp: return "L2TP"
        case .cisco: return "Cisco IPsec"
        }
    }

    /// Natív macOS VPN (scutil + mobileconfig), nem a root rétegen fut.
    public var isNative: Bool { self == .l2tp || self == .cisco }
}

public struct NativeSettings: Codable, Hashable, Sendable {
    public var server: String
    public var account: String
    /// Cisco IPsec csoportnév (LocalIdentifier). L2TP-nél üres.
    public var groupName: String
    public var sendAllTraffic: Bool

    public init(server: String = "", account: String = "", groupName: String = "", sendAllTraffic: Bool = true) {
        self.server = server
        self.account = account
        self.groupName = groupName
        self.sendAllTraffic = sendAllTraffic
    }
}

public struct Connection: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var kind: VPNKind
    public var createdAt: Date
    /// Natív kapcsolatnál a scutil-ban megjelenő szolgáltatás neve.
    public var nativeServiceName: String?
    /// Natív kapcsolatnál a telepített szolgáltatás scutil azonosítója, amint megjelent (név és szervercím alapján
    /// kötve). Ettől kezdve az indítás / leállítás / állapot ezt használja, nem a nevet.
    public var nativeServiceID: String?
    /// Natív beállítások. A fióknév nem titok (a `meta.json`-ban nyíltan áll); a jelszó és a PSK a Keychainben van.
    public var native: NativeSettings?
    /// OpenVPN: a felhasználó által tudomásul vett kockázatos (RISKY) direktívák nevei, rendezve. Pontosan a mentéskori
    /// kockázatos halmaz; egy újonnan bekerülő kockázatos direktíva új tudomásulvételt igényel. A `mvpn up` ezt adja át
    /// `--accept-risky`-ként. Hiányzó mező (régebbi `meta.json`): üres.
    public var acknowledgedRiskyDirectives: [String]

    public init(id: UUID = UUID(), name: String, kind: VPNKind, createdAt: Date = Date(),
                nativeServiceName: String? = nil, native: NativeSettings? = nil,
                acknowledgedRiskyDirectives: [String] = []) {
        self.id = id
        self.name = name
        self.kind = kind
        self.createdAt = createdAt
        self.nativeServiceName = nativeServiceName
        self.native = native
        self.acknowledgedRiskyDirectives = acknowledgedRiskyDirectives
    }

    enum CodingKeys: String, CodingKey {
        case id, name, kind, createdAt, nativeServiceName, nativeServiceID, native, acknowledgedRiskyDirectives
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        kind = try c.decode(VPNKind.self, forKey: .kind)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        nativeServiceName = try c.decodeIfPresent(String.self, forKey: .nativeServiceName)
        nativeServiceID = try c.decodeIfPresent(String.self, forKey: .nativeServiceID)
        native = try c.decodeIfPresent(NativeSettings.self, forKey: .native)
        acknowledgedRiskyDirectives = try c.decodeIfPresent([String].self, forKey: .acknowledgedRiskyDirectives) ?? []
    }
}

public enum ConnectionState: Equatable, Sendable {
    case disconnected
    case connecting
    case connected(ip: String?, since: Date?)
    case disconnecting
    case failed(String)

    public var isActive: Bool {
        switch self {
        case .connecting, .connected, .disconnecting: return true
        case .disconnected, .failed: return false
        }
    }

    public var isConnected: Bool {
        if case .connected = self { return true }
        return false
    }
}

/// `line == 0`: az egész fájlra vonatkozó hiba.
public struct ValidationIssue: Equatable, Sendable {
    public let line: Int
    public let message: String

    public init(line: Int, message: String) {
        self.line = line
        self.message = message
    }

    public var display: String { line == 0 ? message : L10n.tr("Line %ld: %@", line, message) }
}

public struct Secrets: Equatable, Sendable {
    public var username: String?
    public var password: String?
    public var psk: String?
    /// OpenVPN: a privát kulcs (titkosított PEM `<key>` vagy PKCS#12) jelszava. A `mvpn` `--askpass` fájlként adja át.
    public var keyPassword: String?

    public init(username: String? = nil, password: String? = nil, psk: String? = nil, keyPassword: String? = nil) {
        self.username = username
        self.password = password
        self.psk = psk
        self.keyPassword = keyPassword
    }

    /// Mentéskor ellenőrzött szabály minden típusra: nincs sortörés és vezérlőkarakter (C0, DEL, C1,
    /// U+2028/U+2029). nil: rendben, egyébként a hibaüzenet. (Az SSTP jelszóra ennél szigorúbb szabály is vonatkozik.)
    public var inputError: String? {
        let bad = [username, password, psk, keyPassword].contains { value in
            (value ?? "").unicodeScalars.contains {
                $0.value < 0x20 || (0x7F...0x9F).contains($0.value) || $0.value == 0x2028 || $0.value == 0x2029
            }
        }
        return bad ? L10n.tr("The user name, password and PSK must not contain line breaks or control characters") : nil
    }

    /// A `mvpn up` stdin formátuma: `kulcs=érték` soronként. A sortörések levágása csak védőháló: mentéskor az
    /// `inputError` már elutasítja őket.
    public var stdinPayload: String {
        var out = ""
        for (key, value) in [("username", username), ("password", password), ("psk", psk), ("keypass", keyPassword)] {
            guard let v = value?.replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: ""), !v.isEmpty else { continue }
            out += "\(key)=\(v)\n"
        }
        return out
    }
}
