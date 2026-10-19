import XCTest
@testable import MacVPNCore

/// OpenVPN 2.7.8 lefedettség (rögzített `--help` opciólista) és a MikroTik RouterOS által exportált / a MikroTik wiki
/// szerinti kliens configok súrlódásmentes importja.
final class OpenVPN27CoverageTests: XCTestCase {
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    static let fixtures = LocalizationTests.projectRoot.appendingPathComponent("Tests/Fixtures")

    static func helpOptions() throws -> [String] {
        let url = fixtures.appendingPathComponent("openvpn/openvpn-2.7.8-help-options.txt")
        return try String(contentsOf: url, encoding: .utf8).components(separatedBy: "\n")
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }

    static func hasExplicitTier(_ name: String) -> Bool {
        name == "setenv" || OpenVPNValidator.argumentSpecs[name] != nil || OpenVPNValidator.riskyReasons[name] != nil
            || OpenVPNValidator.forbidden.contains(name)
    }

    func testEveryOpenVPN278OptionIsClassifiedAndDocumented() throws {
        let options = try Self.helpOptions()
        XCTAssertEqual(options.count, 234)
        let doc = try String(contentsOf: LocalizationTests.projectRoot.appendingPathComponent("docs/openvpn-directives.md"), encoding: .utf8)
        for name in options {
            XCTAssertTrue(Self.hasExplicitTier(name), "no explicit tier: \(name)")
            XCTAssertTrue(doc.contains("`\(name)`"), "not in docs/openvpn-directives.md: \(name)")
        }
    }

    private func ok(_ line: String, file: StaticString = #filePath, l: UInt = #line) {
        XCTAssertEqual(OpenVPNValidator().validate("client\nremote a 1194\n" + line + "\n"), [], line, file: file, line: l)
    }

    private func bad(_ line: String, file: StaticString = #filePath, l: UInt = #line) {
        XCTAssertEqual(OpenVPNValidator().validate("client\nremote a 1194\n" + line + "\n").map(\.line), [3], line, file: file, line: l)
    }

    func testDnsDirectiveForms() {
        for line in ["dns search-domains corp.example lab.example", "dns server 0 address 10.0.0.53",
                     "dns server 1 address 10.0.0.53:5353 [fd00::53]:53 fd00::54", "dns server -5 address 1.1.1.1",
                     "dns server 1 resolve-domains corp.example", "dns server 1 dnssec optional",
                     "dns server 1 transport DoT", "dns server 1 transport DoH", "dns server 1 sni dns.example"] { ok(line) }
        for line in ["dns", "dns server", "dns server 1 address /etc/x", "dns resolver 1", "dns server 1 address `x`"] { bad(line) }
        XCTAssertEqual(OpenVPNValidator.tier(of: "dns-updown"), .forbidden)
        XCTAssertEqual(OpenVPNValidator.tier(of: "tls-export-cert"), .forbidden)
    }

    func testArgumentsOpenVPN27Accepts() {
        let lines = ["data-ciphers AES-256-GCM:AES-128-GCM:?CHACHA20-POLY1305:aes-256-cbc", "tls-groups X25519:secp256r1:X448",
                     "tls-cert-profile legacy", "tls-cert-profile preferred", "tls-cert-profile suiteb", "tls-cert-profile insecure",
                     "verify-x509-name \"CN=vpn\" subject", "verify-x509-name vpn.example name",
                     "verify-x509-name vpn name-prefix", "remote a 1194 tcp-client", "remote a 1194 udp6",
                     "proto tcp-client", "proto udp4", "proto udp6", "proto tcp4-client", "proto tcp6-client",
                     "redirect-gateway def1 bypass-dhcp ipv6 !ipv4", "redirect-gateway local autolocal block-local bypass-dns",
                     "dhcp-option DNS 10.0.0.1", "dhcp-option DNS6 fd00::1", "dhcp-option DOMAIN corp.example",
                     "dhcp-option DOMAIN-SEARCH a.example", "dhcp-option ADAPTER_DOMAIN_SUFFIX a.example",
                     "dhcp-option NTP 10.0.0.2", "dhcp-option WINS 10.0.0.3", "dhcp-option NBS 10.0.0.4",
                     "dhcp-option NBT 2", "dhcp-option NBDD 10.0.0.5", "dhcp-option DISABLE-NBT",
                     "dhcp-option PROXY_HTTP proxy.example 8080", "dhcp-option PROXY_AUTO_CONFIG_URL http://wpad.example/proxy.pac",
                     "dhcp-option PROXY_BYPASS a.example b.example", "route 10.0.0.0 255.0.0.0 net_gateway",
                     "route 10.0.0.0 255.0.0.0 vpn_gateway 50", "route remote_host 255.255.255.255 net_gateway",
                     "route 10.1.0.0 255.255.0.0 10.8.0.1 default", "auth sha1", "auth SHA256", "auth sha512",
                     "cipher BF-CBC", "cipher bf-cbc", "cipher AES-128-CBC", "cipher aes-128-cbc", "cipher AES-256-GCM",
                     "ifconfig-ipv6 fd00::2/64", "ifconfig-ipv6 fd00::2/64 fd00::1", "route-ipv6-gateway fd00::1",
                     "force-tls-key-material-export", "push-peer-info", "disable-dco", "ncp-disable", "comp-lzo",
                     "comp-lzo no", "comp-lzo adaptive", "tls-cipher DEFAULT:@SECLEVEL=0", "compress stub-v2"]
        for line in lines { ok(line) }
        XCTAssertEqual(OpenVPNValidator.tier(of: "client-nat"), .risky)
    }

    func testScriptSecurityLevels() {
        ok("script-security 0")
        ok("script-security 1")
        for line in ["script-security 2", "script-security 3", "script-security", "script-security 1 x"] { bad(line) }
        XCTAssertEqual(OpenVPNValidator().validate("client\nremote a\nscript-security 2\n", acknowledgedRisky: ["script-security"]).issues.map(\.line), [3])
    }
}

final class MikroTikImportTests: XCTestCase {
    var root: URL!
    var dir: URL!

    override func setUpWithError() throws {
        AppLanguage.override = .en
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        dir = root.appendingPathComponent("router")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        AppLanguage.override = nil
        try? FileManager.default.removeItem(at: root)
    }

    static func fixture(_ name: String) throws -> String {
        try String(contentsOf: OpenVPN27CoverageTests.fixtures.appendingPathComponent("mikrotik/\(name)"), encoding: .utf8)
    }

    func testRouterOSExportsAreSafeWithoutAcknowledgement() throws {
        for name in ["routeros-v7-export-udp.ovpn", "routeros-v7-export-tcp.ovpn", "routeros-v7-export-tls-crypt.ovpn",
                     "routeros-wiki-extras.ovpn", "routeros-v6-imported.ovpn"] {
            let text = try Self.fixture(name)
            let result = OpenVPNValidator().validate(text, acknowledgedRisky: [])
            XCTAssertEqual(result.issues, [], name)
            XCTAssertEqual(result.risky, [], name)
            XCTAssertEqual(OpenVPNValidator().validate(text), [], name)
            let prepared = try ConfigImporter.prepare(fileName: name, content: text, baseDirectory: dir)
            XCTAssertEqual(prepared.issues, [], name)
            XCTAssertEqual(prepared.risky, [], name)
            XCTAssertEqual(prepared.config, text, name)
        }
        XCTAssertTrue(ConfigImporter.containsEncryptedKey(try Self.fixture("routeros-v7-export-udp.ovpn")))
        XCTAssertTrue(ConfigImporter.containsEncryptedKey(try Self.fixture("routeros-v6-imported.ovpn")))
    }

    @discardableResult
    private func openssl(_ args: [String]) throws -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = args
        p.currentDirectoryURL = dir
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    private func put(_ name: String, _ text: String) throws {
        try text.write(to: dir.appendingPathComponent(name), atomically: true, encoding: .utf8)
    }

    /// Valódi CA + kliens tanúsítvány és a MikroTik exporthoz hasonlóan jelszóval titkosított kulcs, mindkét formában.
    private func makeRouterFiles(legacyKey: Bool) throws {
        XCTAssertEqual(try openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
                                    "-subj", "/CN=router-ca", "-days", "1"]), 0)
        XCTAssertEqual(try openssl(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "plain.key", "-out", "client.csr",
                                    "-subj", "/CN=client1"]), 0)
        XCTAssertEqual(try openssl(["x509", "-req", "-in", "client.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                                    "-out", "client.crt", "-days", "1"]), 0)
        if legacyKey {
            XCTAssertEqual(try openssl(["rsa", "-in", "plain.key", "-aes256", "-passout", "pass:exportpass", "-out", "client.key"]), 0)
        } else {
            XCTAssertEqual(try openssl(["pkcs8", "-topk8", "-in", "plain.key", "-v2", "aes-256-cbc", "-passout", "pass:exportpass",
                                        "-out", "client.key"]), 0)
        }
    }

    private func importV6(legacyKey: Bool) throws -> ConfigImporter.PreparedImport {
        try makeRouterFiles(legacyKey: legacyKey)
        try put("auth.cfg", "vpnuser\nS3cret pass\n")
        return try ConfigImporter.prepare(fileName: "router.ovpn", content: try Self.fixture("routeros-v6-wiki.ovpn"), baseDirectory: dir)
    }

    func testRouterOSv6WikiWithFilesImportsCleanly() throws {
        for legacy in [false, true] {
            let prepared = try importV6(legacyKey: legacy)
            XCTAssertEqual(prepared.issues, [], "legacy: \(legacy)")
            XCTAssertEqual(prepared.risky, [], "legacy: \(legacy)")
            XCTAssertEqual(prepared.inlinedFiles, ["ca.crt", "client.crt", "client.key"])
            XCTAssertTrue(prepared.hasEncryptedKey)
            XCTAssertTrue(prepared.config.contains(legacy ? "Proc-Type: 4,ENCRYPTED" : "-----BEGIN ENCRYPTED PRIVATE KEY-----"))
            XCTAssertEqual(prepared.credentials.username, "vpnuser")
            XCTAssertEqual(prepared.credentials.password, "S3cret pass")
            XCTAssertEqual(prepared.credentials.credentialsFile, "auth.cfg")
            XCTAssertEqual(prepared.credentials.unreadFiles, [])
            XCTAssertFalse(prepared.config.contains("S3cret"))
            XCTAssertFalse(prepared.config.contains("auth.cfg"))
            XCTAssertTrue(prepared.config.contains("\nauth-user-pass\n"))
            XCTAssertEqual(OpenVPNValidator().validate(prepared.config), [])
        }
    }

    func testCredentialsFileRules() throws {
        let base = "client\nremote a 1194\nauth-user-pass "
        func creds(_ file: String) throws -> ConfigImporter.ImportedCredentials {
            try ConfigImporter.prepare(fileName: "x.ovpn", content: base + file + "\n", baseDirectory: dir).credentials
        }
        try put("crlf.txt", "user\r\npass\r\n")
        XCTAssertEqual(try creds("crlf.txt").password, "pass")
        try put("three.txt", "a\nb\nc\n")
        try put("one.txt", "a\n")
        try put("big.txt", "u\n" + String(repeating: "p", count: 2000) + "\n")
        try put("ctrl.txt", "u\u{01}\np\n")
        for name in ["three.txt", "one.txt", "big.txt", "ctrl.txt", "missing.txt", "../outside.txt", "/etc/hosts"] {
            let c = try creds(name)
            XCTAssertNil(c.username, name)
            XCTAssertEqual(c.unreadFiles, [name], name)
        }
        let outside = root.appendingPathComponent("outside.txt")
        try "u\np\n".write(to: outside, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("link.txt"), withDestinationURL: outside)
        XCTAssertEqual(try creds("link.txt").unreadFiles, ["link.txt"])
    }

    func testAskpassFileGoesToKeychainField() throws {
        try put("pass.txt", "exportpass\n")
        let prepared = try ConfigImporter.prepare(fileName: "x.ovpn", content: "client\nremote a 1194\naskpass pass.txt\n",
                                                  baseDirectory: dir)
        XCTAssertEqual(prepared.credentials.keyPassword, "exportpass")
        XCTAssertEqual(prepared.credentials.keyPasswordFile, "pass.txt")
        XCTAssertTrue(prepared.config.contains("\naskpass\n"))
        XCTAssertFalse(prepared.config.contains("pass.txt"))
        XCTAssertEqual(prepared.issues, [])
    }
}
