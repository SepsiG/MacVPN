import XCTest
@testable import MacVPNCore

final class ModelsTests: XCTestCase {
    func testKindDisplayNamesAndNativeFlag() {
        XCTAssertEqual(VPNKind.openvpn.displayName, "OpenVPN")
        XCTAssertEqual(VPNKind.wireguard.displayName, "WireGuard")
        XCTAssertEqual(VPNKind.strongswan.displayName, "IKEv2")
        XCTAssertEqual(VPNKind.l2tp.displayName, "L2TP")
        XCTAssertEqual(VPNKind.cisco.displayName, "Cisco IPsec")
        XCTAssertTrue(VPNKind.l2tp.isNative)
        XCTAssertTrue(VPNKind.cisco.isNative)
        XCTAssertFalse(VPNKind.openvpn.isNative)
        XCTAssertEqual(VPNKind.strongswan.rawValue, "strongswan")
    }

    func testConnectionCodableRoundTrip() throws {
        let c = Connection(name: "Iroda", kind: .cisco,
                           native: NativeSettings(server: "vpn.example.com", account: "bob", groupName: "staff", sendAllTraffic: false))
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        let back = try dec.decode(Connection.self, from: enc.encode(c))
        XCTAssertEqual(back.id, c.id)
        XCTAssertEqual(back.native?.groupName, "staff")
        XCTAssertEqual(back.kind, .cisco)
    }

    func testConnectionStateActive() {
        XCTAssertTrue(ConnectionState.connecting.isActive)
        XCTAssertTrue(ConnectionState.connected(ip: nil, since: nil).isActive)
        XCTAssertTrue(ConnectionState.disconnecting.isActive)
        XCTAssertFalse(ConnectionState.disconnected.isActive)
        XCTAssertFalse(ConnectionState.failed("x").isActive)
    }

    func testSecretsStdinPayloadSkipsEmptyAndStripsNewlines() {
        let s = Secrets(username: "bob", password: "p\nw", psk: "")
        XCTAssertEqual(s.stdinPayload, "username=bob\npassword=pw\n")
        XCTAssertEqual(Secrets().stdinPayload, "")
    }
}
