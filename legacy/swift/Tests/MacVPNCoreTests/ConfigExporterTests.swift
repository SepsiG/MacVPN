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

    static let ovpn = """
    client
    remote a 1194
    <ca>
    -----BEGIN CERTIFICATE-----
    MIIB
    -----END CERTIFICATE-----
    </ca>
    <cert>
    -----BEGIN CERTIFICATE-----
    MIIC
    -----END CERTIFICATE-----
    </cert>
    <key>
    -----BEGIN PRIVATE KEY-----
    SECRET1
    -----END PRIVATE KEY-----
    </key>
    <TLS-AUTH>
    SECRET2
    </TLS-AUTH>
    key-direction 1
    <tls-crypt>
    SECRET3
    </tls-crypt>
    <tls-crypt-v2>
    SECRET4
    </tls-crypt-v2>
    <secret>
    SECRET5
    </secret>
    <pkcs12>
    SECRET6
    </pkcs12>
    verb 3

    """

    func testOpenVPNSecretsAreDetectedAndStripped() {
        XCTAssertEqual(ConfigExporter.secretMaterial(in: Self.ovpn, kind: .openvpn),
                       ["<key>", "<tls-auth>", "<tls-crypt>", "<tls-crypt-v2>", "<secret>", "<pkcs12>"])
        let stripped = ConfigExporter.stripSecrets(Self.ovpn, kind: .openvpn)
        XCTAssertFalse(stripped.contains("SECRET"))
        XCTAssertTrue(stripped.contains("<ca>\n-----BEGIN CERTIFICATE-----\nMIIB"))
        XCTAssertTrue(stripped.contains("<cert>"))
        XCTAssertTrue(stripped.hasSuffix("key-direction 1\nverb 3\n"))
        XCTAssertEqual(ConfigExporter.secretMaterial(in: stripped, kind: .openvpn), [])
        XCTAssertEqual(ConfigExporter.secretMaterial(in: "client\nremote a 1\n<ca>\nx\n</ca>\n", kind: .openvpn), [])
    }

    /// Inline credentials (`<auth-user-pass>`, `<http-proxy-user-pass>`, also inside `<connection>`) are flagged and stripped.
    func testOpenVPNInlineCredentialsAreDetectedAndStripped() {
        let conf = """
        client
        remote vpn.example.com 1194
        auth-user-pass
        <auth-user-pass>
        bob
        CredPass1
        </auth-user-pass>
        <connection>
        remote alt.example.com 443 tcp
        http-proxy proxy.example.com 8080 [inline]
        <http-proxy-user-pass>
        proxyuser
        ProxyPass2
        </http-proxy-user-pass>
        </connection>
        <ca>
        CA
        </ca>
        verb 3

        """
        XCTAssertEqual(ConfigExporter.secretMaterial(in: conf, kind: .openvpn),
                       ["<auth-user-pass>", "<http-proxy-user-pass>"])
        let stripped = ConfigExporter.stripSecrets(conf, kind: .openvpn)
        XCTAssertFalse(stripped.contains("CredPass1"))
        XCTAssertFalse(stripped.contains("ProxyPass2"))
        XCTAssertFalse(stripped.contains("proxyuser"))
        XCTAssertFalse(stripped.contains("\nbob\n"))
        XCTAssertTrue(stripped.contains("<connection>\nremote alt.example.com 443 tcp\nhttp-proxy proxy.example.com 8080 [inline]\n</connection>"))
        XCTAssertTrue(stripped.contains("<ca>\nCA\n</ca>"))
        XCTAssertEqual(ConfigExporter.secretMaterial(in: stripped, kind: .openvpn), [])
        // The plain directive alone (credentials from the Keychain) is not secret material.
        XCTAssertEqual(ConfigExporter.secretMaterial(in: "remote a 1\nauth-user-pass\n", kind: .openvpn), [])
    }

    func testOpenVPNUnclosedSecretBlockIsStrippedToTheEnd() {
        let stripped = ConfigExporter.stripSecrets("remote a 1\n<key>\nSECRET\n", kind: .openvpn)
        XCTAssertEqual(stripped, "remote a 1\n")
    }

    func testWireGuardKeysAreBlanked() {
        let conf = "[Interface]\nprivatekey = abc=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = pub=\nPresharedKey=psk=\n"
        XCTAssertEqual(ConfigExporter.secretMaterial(in: conf, kind: .wireguard), ["PrivateKey", "PresharedKey"])
        let stripped = ConfigExporter.stripSecrets(conf, kind: .wireguard)
        XCTAssertEqual(stripped, "[Interface]\nPrivateKey =\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = pub=\nPresharedKey =\n")
        XCTAssertEqual(ConfigExporter.secretMaterial(in: stripped, kind: .wireguard), [])
        XCTAssertEqual(ConfigImporter.detectKind(fileName: "x.conf", content: stripped), .wireguard)
    }

    func testStrongSwanSecretsSectionIsStripped() {
        let conf = "connections {\n  a {\n    children { a { } }\n  }\n}\nsecrets {\n  eap-1 {\n    id = bob\n    secret = \"p{w}\"\n  }\n}\npools { }\n"
        XCTAssertEqual(ConfigExporter.secretMaterial(in: conf, kind: .strongswan), ["secrets"])
        let stripped = ConfigExporter.stripSecrets(conf, kind: .strongswan)
        XCTAssertEqual(stripped, "connections {\n  a {\n    children { a { } }\n  }\n}\npools { }\n")
        XCTAssertEqual(ConfigExporter.secretMaterial(in: "connections {\n}\n", kind: .strongswan), [])
    }

    func testOtherKindsHaveNoSecretMaterial() {
        XCTAssertEqual(ConfigExporter.secretMaterial(in: "server=x\n", kind: .sstp), [])
        XCTAssertEqual(ConfigExporter.stripSecrets("server=x\n", kind: .sstp), "server=x\n")
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
