import XCTest
@testable import MacVPNCore

final class MobileconfigGeneratorTests: XCTestCase {
    // Magyar üzeneteket ellenőriz: a nyelv rögzítve, nem a gép locale-ja dönt.
    override func setUp() { super.setUp(); AppLanguage.override = .hu }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    func payload(_ data: Data) throws -> [String: Any] {
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        XCTAssertEqual(root["PayloadType"] as? String, "Configuration")
        return (root["PayloadContent"] as! [[String: Any]])[0]
    }

    func testL2TP() throws {
        let c = Connection(name: "Office L2TP", kind: .l2tp,
                           native: NativeSettings(server: "vpn.ice.hu", account: "bob", sendAllTraffic: true))
        let data = try MobileconfigGenerator.generate(connection: c, psk: "k")
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        XCTAssertEqual(root["PayloadIdentifier"] as? String, "macvpn.\(c.id.uuidString)")
        let p = try payload(data)
        XCTAssertEqual(p["PayloadType"] as? String, "com.apple.vpn.managed")
        XCTAssertEqual(p["VPNType"] as? String, "L2TP")
        XCTAssertEqual(p["UserDefinedName"] as? String, "Office L2TP")
        let ppp = p["PPP"] as! [String: Any]
        XCTAssertEqual(ppp["CommRemoteAddress"] as? String, "vpn.ice.hu")
        XCTAssertEqual(ppp["AuthName"] as? String, "bob")
        XCTAssertNil(ppp["AuthPassword"], "the password is passed in-process when connecting, never written to the profile")
        let ipsec = p["IPSec"] as! [String: Any]
        XCTAssertEqual(ipsec["SharedSecret"] as? Data, Data("k".utf8))
        XCTAssertEqual((p["IPv4"] as! [String: Any])["OverridePrimary"] as? Int, 1)
    }

    func testCisco() throws {
        let c = Connection(name: "Partner", kind: .cisco,
                           native: NativeSettings(server: "1.2.3.4", account: "bob", groupName: "staff", sendAllTraffic: false))
        let p = try payload(try MobileconfigGenerator.generate(connection: c, psk: "k"))
        XCTAssertEqual(p["VPNType"] as? String, "IPSec")
        let ipsec = p["IPSec"] as! [String: Any]
        XCTAssertEqual(ipsec["RemoteAddress"] as? String, "1.2.3.4")
        XCTAssertEqual(ipsec["XAuthName"] as? String, "bob")
        XCTAssertNil(ipsec["XAuthPassword"], "the password is passed in-process when connecting, never written to the profile")
        XCTAssertEqual(ipsec["SharedSecret"] as? Data, Data("k".utf8))
        XCTAssertEqual(ipsec["LocalIdentifier"] as? String, "staff")
        XCTAssertEqual(ipsec["XAuthEnabled"] as? Int, 1)
        XCTAssertNil(p["PPP"])
    }

    func testRejectsNonNative() {
        XCTAssertThrowsError(try MobileconfigGenerator.generate(connection: Connection(name: "x", kind: .openvpn), psk: ""))
    }

    /// Sehol a profilban (semmilyen szinten) nincs jelszó kulcs.
    func testNoPasswordKeyAnywhere() throws {
        for c in [Connection(name: "A", kind: .l2tp, native: NativeSettings(server: "s", account: "u")),
                  Connection(name: "B", kind: .cisco, native: NativeSettings(server: "s", account: "u", groupName: "g"))] {
            let xml = String(decoding: try MobileconfigGenerator.generate(connection: c, psk: "k"), as: UTF8.self)
            XCTAssertFalse(xml.contains("Password"), xml)
        }
    }

    func testPasswordIsNeverInTheProfile() throws {
        let l2tp = Connection(name: "A", kind: .l2tp, native: NativeSettings(server: "s", account: "u"))
        let p1 = try payload(try MobileconfigGenerator.generate(connection: l2tp, psk: "k"))
        XCTAssertNil((p1["PPP"] as! [String: Any])["AuthPassword"])
        let cisco = Connection(name: "B", kind: .cisco, native: NativeSettings(server: "s", account: "u", groupName: "g"))
        let p2 = try payload(try MobileconfigGenerator.generate(connection: cisco, psk: "k"))
        XCTAssertNil((p2["IPSec"] as! [String: Any])["XAuthPassword"])
    }

    func testCiscoRequiresGroupName() {
        let c = Connection(name: "B", kind: .cisco, native: NativeSettings(server: "s", account: "u", groupName: ""))
        XCTAssertThrowsError(try MobileconfigGenerator.generate(connection: c, psk: "k")) {
            XCTAssertEqual($0.localizedDescription, "Cisco IPsec-hez csoportnév szükséges")
        }
    }

    func testInnerPayloadUUIDIsDeterministic() throws {
        let c = Connection(name: "A", kind: .l2tp, native: NativeSettings(server: "s", account: "u"))
        let a = try payload(try MobileconfigGenerator.generate(connection: c, psk: "k"))
        let b = try payload(try MobileconfigGenerator.generate(connection: c, psk: "k"))
        XCTAssertEqual(a["PayloadUUID"] as? String, b["PayloadUUID"] as? String)
        XCTAssertNotEqual(a["PayloadUUID"] as? String, c.id.uuidString)
    }
}
