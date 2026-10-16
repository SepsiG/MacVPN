import Foundation

public enum MobileconfigGenerator {
    public struct NotNativeError: LocalizedError {
        public var errorDescription: String? { L10n.tr("A profile can only be generated for L2TP and Cisco IPsec connections") }
    }

    public struct ValidationError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// A fix PayloadIdentifier miatt az újratelepítés felülírja a korábbi profilt.
    public static func generate(connection: Connection, password: String, psk: String) throws -> Data {
        guard connection.kind.isNative else { throw NotNativeError() }
        let s = connection.native ?? NativeSettings()
        let identifier = "macvpn.\(connection.id.uuidString)"

        var vpn: [String: Any] = [
            "PayloadType": "com.apple.vpn.managed",
            "PayloadIdentifier": identifier + ".vpn",
            "PayloadUUID": innerUUID(for: connection.id),
            "PayloadVersion": 1,
            "PayloadDisplayName": connection.name,
            "UserDefinedName": connection.name,
            "IPv4": ["OverridePrimary": s.sendAllTraffic ? 1 : 0],
        ]

        switch connection.kind {
        case .l2tp:
            vpn["VPNType"] = "L2TP"
            var ppp: [String: Any] = ["CommRemoteAddress": s.server, "AuthName": s.account]
            if !password.isEmpty { ppp["AuthPassword"] = password }
            vpn["PPP"] = ppp
            vpn["IPSec"] = [
                "AuthenticationMethod": "SharedSecret",
                "SharedSecret": Data(psk.utf8),
            ]
        case .cisco:
            vpn["VPNType"] = "IPSec"
            guard !s.groupName.isEmpty else {
                throw ValidationError(message: L10n.tr("Cisco IPsec requires a group name"))
            }
            var ipsec: [String: Any] = [
                "RemoteAddress": s.server,
                "AuthenticationMethod": "SharedSecret",
                "SharedSecret": Data(psk.utf8),
                "LocalIdentifier": s.groupName,
                "LocalIdentifierType": "KeyID",
                "XAuthEnabled": 1,
                "XAuthName": s.account,
                "PromptForVPNPIN": false,
            ]
            if !password.isEmpty { ipsec["XAuthPassword"] = password }
            vpn["IPSec"] = ipsec
        default:
            throw NotNativeError()
        }

        let root: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadIdentifier": identifier,
            "PayloadUUID": connection.id.uuidString,
            "PayloadVersion": 1,
            "PayloadDisplayName": "MacVPN – \(connection.name)",
            "PayloadContent": [vpn],
        ]
        return try PropertyListSerialization.data(fromPropertyList: root, format: .xml, options: 0)
    }

    /// Determinisztikus, a kapcsolat azonosítójából származtatott belső PayloadUUID.
    static func innerUUID(for id: UUID) -> String {
        var bytes = id.uuid
        bytes.0 ^= 0xFF
        bytes.15 ^= 0xA5
        return UUID(uuid: bytes).uuidString
    }
}
