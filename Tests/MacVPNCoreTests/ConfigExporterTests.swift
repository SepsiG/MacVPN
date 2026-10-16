import XCTest
@testable import MacVPNCore

final class ConfigExporterTests: XCTestCase {
    var base: URL!
    var store: ConnectionStore!

    override func setUpWithError() throws {
        base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = ConnectionStore(baseURL: base)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: base) }

    func testFileNames() {
        XCTAssertEqual(ConfigExporter.fileName(for: Connection(name: "Iroda/VPN", kind: .openvpn)), "Iroda-VPN.ovpn")
        XCTAssertEqual(ConfigExporter.fileName(for: Connection(name: "Home", kind: .wireguard)), "Home.conf")
        XCTAssertEqual(ConfigExporter.fileName(for: Connection(name: "P", kind: .strongswan)), "P.swanctl.conf")
        XCTAssertEqual(ConfigExporter.fileName(for: Connection(name: "Ice", kind: .l2tp)), "Ice.mobileconfig")
    }

    func testTextExportIsConfigAsIs() throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        XCTAssertEqual(try ConfigExporter.export(c, store: store), Data("remote x\n".utf8))
    }

    func testNativeExportHasNoSecrets() throws {
        let c = Connection(name: "Ice", kind: .l2tp, native: NativeSettings(server: "s", account: "bob"))
        let data = try ConfigExporter.export(c, store: store)
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        let p = (root["PayloadContent"] as! [[String: Any]])[0]
        // A generátor az üres jelszót kihagyja (a macOS így rákérdez csatlakozáskor).
        XCTAssertNil((p["PPP"] as! [String: Any])["AuthPassword"])
        XCTAssertEqual((p["PPP"] as! [String: Any])["AuthName"] as? String, "")
        XCTAssertEqual((p["IPSec"] as! [String: Any])["SharedSecret"] as? Data, Data())
    }

    func testCiscoExportHasNoSecrets() throws {
        let c = Connection(name: "Cis", kind: .cisco, native: NativeSettings(server: "s", account: "bob", groupName: "g"))
        let data = try ConfigExporter.export(c, store: store)
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        let ipsec = (root["PayloadContent"] as! [[String: Any]])[0]["IPSec"] as! [String: Any]
        XCTAssertNil(ipsec["XAuthPassword"])
        XCTAssertEqual(ipsec["XAuthName"] as? String, "")
        XCTAssertEqual(ipsec["LocalIdentifier"] as? String, "g")
        XCTAssertEqual(ipsec["SharedSecret"] as? Data, Data())
    }

    func testRoundTripThroughImporterDetection() throws {
        let c = Connection(name: "WG", kind: .wireguard)
        let conf = "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n"
        try store.save(c, config: conf)
        let data = try ConfigExporter.export(c, store: store)
        XCTAssertEqual(ConfigImporter.detectKind(fileName: ConfigExporter.fileName(for: c),
                                                 content: String(decoding: data, as: UTF8.self)), .wireguard)
    }

    func testWarnsForWireGuardPrivateKey() {
        XCTAssertNotNil(ConfigExporter.warning(for: .wireguard))
        XCTAssertNil(ConfigExporter.warning(for: .openvpn))
    }

    private func mode(_ url: URL) throws -> Int {
        (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as! NSNumber).intValue & 0o777
    }

    func testWriteCreatesPrivateFile() throws {
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        let url = base.appendingPathComponent("x.conf")
        try ConfigExporter.write(Data("secret".utf8), to: url)
        XCTAssertEqual(try Data(contentsOf: url), Data("secret".utf8))
        XCTAssertEqual(try mode(url), 0o600)
    }

    func testWriteReplacesExistingWorldReadableFile() throws {
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        let url = base.appendingPathComponent("x.conf")
        try Data("old content that is longer".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        try ConfigExporter.write(Data("new".utf8), to: url)
        XCTAssertEqual(try Data(contentsOf: url), Data("new".utf8))
        XCTAssertEqual(try mode(url), 0o600)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: base.path)
        XCTAssertEqual(leftovers, ["x.conf"])
    }
}
