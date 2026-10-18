import XCTest
@testable import MacVPNCore

/// A háromszintű OpenVPN direktíva-besorolás (SAFE / RISKY / FORBIDDEN), a tudomásulvétel és a hozzá tartozó
/// modell-, kliens- és import-változások.
final class OpenVPNTierTests: XCTestCase {
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    private let base = "client\ndev tun\nremote vpn.example.com 1194\n"

    private func check(_ body: String, ack: Set<String> = []) -> OpenVPNValidation {
        OpenVPNValidator().validate(base + body + "\n", acknowledgedRisky: ack)
    }

    // MARK: A felhasználó példái

    func testUserExamplesImportWithoutFriction() {
        XCTAssertEqual(OpenVPNValidator().validate(base + "setenv CONFIG_VERSION \"2.0.4\"\n"), [])
        XCTAssertEqual(OpenVPNValidator().validate(base + "remap-usr1 SIGTERM\nremap-usr1 SIGHUP\n"), [])
        let r = check("user nobody\ngroup nogroup\nuser\ngroup")
        XCTAssertEqual(r.issues, [])
        XCTAssertEqual(r.unacknowledged, ["group", "user"])
        XCTAssertEqual(r.risky.map(\.line), [4, 5, 6, 7])
        XCTAssertEqual(r.allIssues.map(\.line), [4, 5, 6, 7])
        XCTAssertEqual(r.allIssues.first?.message, "Risky directive, acknowledgement required: user")
        XCTAssertEqual(check("user nobody\ngroup nogroup", ack: ["user", "group"]).allIssues, [])
    }

    func testRemapUsr1RejectsOtherSignals() {
        XCTAssertEqual(check("remap-usr1 SIGKILL").issues.map(\.line), [4])
    }

    // MARK: Táblázat

    func testTiersAreDisjoint() {
        let safe = Set(OpenVPNValidator.argumentSpecs.keys)
        let risky = Set(OpenVPNValidator.riskyReasons.keys)
        XCTAssertTrue(safe.isDisjoint(with: risky), "\(safe.intersection(risky))")
        XCTAssertTrue(safe.isDisjoint(with: OpenVPNValidator.forbidden), "\(safe.intersection(OpenVPNValidator.forbidden))")
        XCTAssertTrue(risky.isDisjoint(with: OpenVPNValidator.forbidden), "\(risky.intersection(OpenVPNValidator.forbidden))")
        for d in safe { XCTAssertEqual(OpenVPNValidator.tier(of: d), .safe, d) }
        for d in risky { XCTAssertEqual(OpenVPNValidator.tier(of: d), .risky, d) }
        for d in OpenVPNValidator.forbidden { XCTAssertEqual(OpenVPNValidator.tier(of: d), .forbidden, d) }
        XCTAssertEqual(OpenVPNValidator.tier(of: "setenv"), .safe)
        XCTAssertEqual(OpenVPNValidator.tier(of: "some-future-option"), .risky)
    }

    func testNotableDecisions() {
        for d in ["chroot", "echo", "pkcs11-id", "syslog", "capath", "genkey", "dns-updown", "iproute", "script-security"] {
            XCTAssertEqual(OpenVPNValidator.tier(of: d), .forbidden, d)
        }
        for d in ["user", "group", "route-noexec", "ifconfig-noexec", "win-sys", "service", "mode", "allow-recursive-routing"] {
            XCTAssertEqual(OpenVPNValidator.tier(of: d), .risky, d)
        }
        for d in ["askpass", "pkcs12", "dns", "machine-readable-output", "register-dns", "block-outside-dns", "disable-dco"] {
            XCTAssertEqual(OpenVPNValidator.tier(of: d), .safe, d)
        }
    }

    /// A `docs/openvpn-directives.md` táblázata minden táblabeli direktívát megnevez.
    func testDocumentationListsEveryDirective() throws {
        let url = LocalizationTests.repoRoot.appendingPathComponent("docs/openvpn-directives.md")
        let doc = try String(contentsOf: url, encoding: .utf8)
        var names = Set(OpenVPNValidator.argumentSpecs.keys)
        names.formUnion(OpenVPNValidator.riskyReasons.keys)
        names.formUnion(OpenVPNValidator.forbidden)
        for name in names { XCTAssertTrue(doc.contains("`\(name)`"), name) }
        for reason in Set(OpenVPNValidator.riskyReasons.values) { XCTAssertTrue(doc.contains(reason), reason) }
    }

    func testEveryReasonIsTranslated() {
        let reasons = Set(OpenVPNValidator.riskyReasons.values).union([OpenVPNValidator.reasonUnknown])
        for key in reasons { XCTAssertNotNil(L10n.hungarian[key], key) }
    }

    func testForbiddenStaysForbiddenEvenWhenAcknowledged() {
        for d in OpenVPNValidator.forbidden {
            let r = check("\(d) x", ack: [d])
            XCTAssertEqual(r.issues.map(\.line), [4], d)
            XCTAssertTrue(r.issues.first?.message.hasPrefix("Forbidden directive: \(d)") == true, d)
        }
    }

    func testUnknownNamesThatLookLikeHooksOrFilesAreForbidden() {
        for d in ["foo-verify", "pre-up", "client-script", "state-dir", "cache-file", "pool-persist", "management-new", "pkcs11-x"] {
            XCTAssertEqual(OpenVPNValidator.tier(of: d), .forbidden, d)
            XCTAssertEqual(check("\(d) x", ack: [d]).issues.map(\.line), [4], d)
        }
    }

    // MARK: RISKY / ismeretlen argumentumok

    func testUnknownDirectiveIsRiskyWithHarmlessArguments() {
        let r = check("future-option 3 abc \"quoted text\" 10.0.0.0/24")
        XCTAssertEqual(r.issues, [])
        XCTAssertEqual(r.risky, [RiskyFinding(directive: "future-option", line: 4, reasonKey: OpenVPNValidator.reasonUnknown)])
        XCTAssertEqual(check("future-option 3", ack: ["future-option"]).allIssues, [])
    }

    func testRiskyArgumentsCannotSmuggleFiles() {
        let bad = ["/etc/master.passwd", "../x", "a/../b", "etc/master.passwd", "file:x", "FILE:/x", "-x", "--up", "~/x",
                   "a$b", "a`b`", "a;b", "a|b", "a&b", "\"a<b\"", "\"a>b\""]
        for arg in bad {
            let r = check("future-option \(arg)", ack: ["future-option"])
            XCTAssertEqual(r.issues.map(\.line), [4], arg)
            XCTAssertEqual(r.risky, [], arg)
            XCTAssertEqual(check("user \(arg)", ack: ["user"]).issues.map(\.line), [4], arg)
        }
    }

    func testRiskyIsNotAllowedInConnectionBlock() {
        let r = OpenVPNValidator().validate("client\n<connection>\nremote a 1\nuser nobody\n</connection>\n", acknowledgedRisky: ["user"])
        XCTAssertEqual(r.issues.map(\.line), [4])
    }

    func testAcknowledgementIsPerName() {
        let r = check("user nobody\ngroup nogroup\nfuture-option 1", ack: ["user"])
        XCTAssertEqual(r.unacknowledged, ["future-option", "group"])
        XCTAssertEqual(r.riskyNames, ["future-option", "group", "user"])
        XCTAssertEqual(r.allIssues.map(\.line), [5, 6])
    }

    func testAllIssuesKeepsWholeFileIssuesLast() {
        let r = OpenVPNValidator().validate("client\nuser nobody\nup /x\n", acknowledgedRisky: [])
        XCTAssertEqual(r.allIssues.map(\.line), [2, 3, 0])
    }

    // MARK: setenv

    func testSetenvAcceptsAnyShellName() {
        for line in ["setenv CONFIG_VERSION \"2.0.4\"", "setenv foo bar", "setenv _X 1", "setenv UV_ID abc", "setenv PUSH_PEER_INFO",
                     "setenv FORWARD_COMPATIBLE 1", "setenv opt remap-usr1 SIGTERM"] {
            XCTAssertEqual(OpenVPNValidator().validate(base + line + "\n"), [], line)
        }
    }

    func testSetenvDenylist() {
        let exact = ["BASH_ENV", "ENV", "PATH", "IFS", "SHELLOPTS", "BASHOPTS", "PS4", "CDPATH", "GLOBIGNORE", "HOME", "TMPDIR",
                     "OPENSSL_CONF", "TZDIR", "LANG", "NLSPATH", "path", "script_type", "dev", "ifconfig_local"]
        let prefixed = ["BASH_FUNC_x%%", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "MALLOC_CHECK_", "PYTHONPATH", "PERL5LIB",
                        "RUBYOPT", "SSL_CERT_FILE", "SSL_CERT_DIR", "LC_ALL", "LC_CTYPE", "MallocStackLogging",
                        "NSObjCMessageLoggingEnabled", "CFFIXED_USER_HOME", "OBJC_DEBUG", "foreign_option_1"]
        for name in exact + prefixed {
            let issues = OpenVPNValidator().validate(base + "setenv \(name) x\n")
            XCTAssertEqual(issues.map(\.line), [4], name)
        }
        XCTAssertFalse(OpenVPNValidator.isDeniedSetenvName("CONFIG_VERSION"))
        XCTAssertFalse(OpenVPNValidator.isDeniedSetenvName("NAME"))
    }

    func testSetenvShapeAndRecursion() {
        XCTAssertEqual(OpenVPNValidator().validate(base + "setenv 1X a\n").map(\.line), [4])
        XCTAssertEqual(OpenVPNValidator().validate(base + "setenv A b c\n").map(\.line), [4])
        let r = check("setenv opt user nobody")
        XCTAssertEqual(r.issues, [])
        XCTAssertEqual(r.unacknowledged, ["user"])
        XCTAssertEqual(check("setenv opt chroot /x", ack: ["chroot"]).issues.map(\.line), [4])
    }

    // MARK: Új SAFE direktívák

    func testExpandedSafeDirectives() {
        let lines = ["machine-readable-output", "mute 10", "connect-timeout 10", "explicit-exit-notify 2", "persist-local-ip",
                     "route-nopull", "pull-filter ignore \"route-ipv6\"", "allow-pull-fqdn", "push-peer-info", "auth-nocache",
                     "auth-retry nointeract", "tls-cert-profile preferred", "ignore-unknown-option block-outside-dns",
                     "data-ciphers AES-256-GCM", "verify-x509-name vpn name", "remote-cert-tls server", "sndbuf 0",
                     "mssfix 1400", "fragment 1300", "mtu-disc yes", "tun-mtu 1500", "keepalive 10 60", "inactive 0",
                     "server-poll-timeout 4", "hand-window 70", "tran-window 3600", "reneg-sec 0", "key-direction 1",
                     "dhcp-option DNS 10.0.0.1", "block-outside-dns", "register-dns", "redirect-gateway def1",
                     "route 10.0.0.0 255.0.0.0", "ifconfig-nowarn", "route-delay 2", "route-metric 5", "float", "nobind",
                     "resolv-retry infinite", "connect-retry 2 30", "proto-force udp", "mark 1", "bind-dev utun3",
                     "disable-dco", "compress lz4-v2", "comp-lzo no", "allow-compression no", "tls-version-min 1.2",
                     "tls-groups X25519", "ecdh-curve secp384r1", "cipher AES-256-CBC", "auth SHA256", "peer-fingerprint [inline]",
                     "verify-hash AB:CD SHA256", "x509-username-field CN", "x509-track +CN", "auth-token-user dXNlcg==",
                     "http-proxy p 8080", "http-proxy-option AGENT \"Mozilla 5\"", "socks-proxy p 1080", "askpass",
                     "dns server 1 address 10.0.0.53", "dns search-domains corp.example", "nice -5", "mlock",
                     "remap-usr1 SIGHUP", "local 0.0.0.0", "socket-flags TCP_NODELAY", "keying-material-exporter EXPORTER-x 32"]
        for line in lines {
            XCTAssertEqual(OpenVPNValidator().validate(base + line + "\n"), [], line)
        }
    }

    func testAskpassWithFileIsRejected() {
        XCTAssertEqual(OpenVPNValidator().validate(base + "askpass pass.txt\n").map(\.line), [4])
        XCTAssertEqual(OpenVPNValidator().validate(base + "askpass /etc/master.passwd\n").map(\.line), [4])
    }

    // MARK: Valós szolgáltatói profilok

    func testRealisticProviderProfiles() {
        let nordStyle = """
        client
        dev tun
        proto udp
        remote 1.2.3.4 1194
        resolv-retry infinite
        remote-random
        nobind
        tun-mtu 1500
        tun-mtu-extra 32
        mssfix 1450
        persist-key
        persist-tun
        ping 15
        ping-restart 0
        ping-timer-rem
        reneg-sec 0
        comp-lzo no
        verify-x509-name CN=us1234.nordvpn.com
        remote-cert-tls server
        auth-user-pass
        verb 3
        pull
        fast-io
        cipher AES-256-CBC
        auth SHA512
        <ca>
        X
        </ca>
        key-direction 1
        <tls-auth>
        X
        </tls-auth>
        """
        let protonStyle = """
        client
        dev tun
        proto udp
        remote a.protonvpn.net 80
        remote a.protonvpn.net 51820
        server-poll-timeout 20
        remote-random
        resolv-retry infinite
        nobind
        cipher AES-256-GCM
        setenv CLIENT_CERT 0
        tun-mtu 1500
        mssfix 0
        persist-key
        persist-tun
        reneg-sec 0
        remote-cert-tls server
        auth-user-pass
        script-security 2
        """
        let piaStyle = """
        client
        dev tun
        proto udp
        remote x.privacy.network 1198
        resolv-retry infinite
        nobind
        persist-key
        persist-tun
        cipher aes-128-cbc
        auth sha1
        tls-client
        remote-cert-tls server
        auth-user-pass
        compress
        verb 1
        reneg-sec 0
        disable-occ
        user nobody
        group nogroup
        setenv CONFIG_VERSION "2.0.4"
        remap-usr1 SIGTERM
        """
        let accessServer = """
        setenv FORWARD_COMPATIBLE 1
        client
        server-poll-timeout 4
        nobind
        remote vpn.example.com 1194 udp
        remote vpn.example.com 443 tcp
        dev tun
        dev-type tun
        remote-cert-tls server
        tls-version-min 1.2
        reneg-sec 604800
        tun-mtu 1420
        verb 3
        push-peer-info
        setenv UV_ID abc123
        setenv UV_PLAT_REL 2.0
        static-challenge "Enter Authenticator Code" 1
        auth-user-pass
        <ca>
        X
        </ca>
        <tls-crypt-v2>
        X
        </tls-crypt-v2>
        """
        XCTAssertEqual(OpenVPNValidator().validate(nordStyle), [])
        XCTAssertEqual(OpenVPNValidator().validate(accessServer), [])
        // A ProtonVPN-profil `script-security 2` sora továbbra is tiltott (a MacVPN maga adja meg).
        XCTAssertEqual(OpenVPNValidator().validate(protonStyle).map(\.line), [19])
        let pia = OpenVPNValidator().validate(piaStyle, acknowledgedRisky: [])
        XCTAssertEqual(pia.issues, [])
        XCTAssertEqual(pia.unacknowledged, ["group", "user"])
        XCTAssertEqual(OpenVPNValidator().validate(piaStyle, acknowledgedRisky: ["user", "group"]).allIssues, [])
    }

    // MARK: Modell, kliens

    func testConnectionDecodesWithoutAcknowledgements() throws {
        let json = """
        {"id":"11111111-2222-3333-4444-555555555555","name":"x","kind":"openvpn","createdAt":0}
        """
        let c = try JSONDecoder().decode(Connection.self, from: Data(json.utf8))
        XCTAssertEqual(c.acknowledgedRiskyDirectives, [])
        var d = c
        d.acknowledgedRiskyDirectives = ["group", "user"]
        let back = try JSONDecoder().decode(Connection.self, from: JSONEncoder().encode(d))
        XCTAssertEqual(back, d)
    }

    func testKeyPasswordSecret() {
        let s = Secrets(username: "u", password: "p", keyPassword: "k")
        XCTAssertEqual(s.stdinPayload, "username=u\npassword=p\nkeypass=k\n")
        XCTAssertNotNil(Secrets(keyPassword: "a\nb").inputError)
        XCTAssertNotNil(Secrets(keyPassword: "a\u{7F}b").inputError)
        XCTAssertNil(Secrets(keyPassword: "ok pass").inputError)
        let store = KeychainSecretStore(service: "t", legacyService: "t-legacy", backend: InMemoryKeychain())
        let id = UUID()
        store.set("kp", for: id, field: .keyPassword)
        XCTAssertEqual(store.secrets(for: id).keyPassword, "kp")
        XCTAssertTrue(KeychainSecretStore.isOurAccount("\(id.uuidString).keypass"))
        store.deleteAll(for: id)
        XCTAssertNil(store.get(id, field: .keyPassword))
    }

    func testUpPassesAcceptRiskyBeforeLang() async throws {
        let id = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let mock = MockCommandRunner()
        try await MvpnClient(runner: mock, language: .hu).up(kind: .openvpn, id: id, secrets: Secrets(keyPassword: "k"),
                                                             debug: false, acceptRisky: ["user", "group", "user", "Bad;x"])
        XCTAssertEqual(mock.calls.first?.commandLine,
                       "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up openvpn \(id.uuidString) --accept-risky group,user --lang hu")
        XCTAssertEqual(mock.calls.first?.stdin, "keypass=k\n")
        let wg = MockCommandRunner()
        try await MvpnClient(runner: wg, language: .en).up(kind: .wireguard, id: id, secrets: Secrets(), debug: true, acceptRisky: ["user"])
        XCTAssertEqual(wg.calls.first?.commandLine, "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard \(id.uuidString) --debug --lang en")
    }

    func testConnectRefusesUnacknowledgedRisk() {
        var c = Connection(name: "x", kind: .openvpn)
        let config = base + "user nobody\n"
        XCTAssertEqual(ConnectionManager.unacknowledgedRiskReason(c, config: config),
                       "Risky settings are not acknowledged: user. Open the connection in MacVPN → Connections and tick the checkbox under Risky settings.")
        c.acknowledgedRiskyDirectives = ["user"]
        XCTAssertNil(ConnectionManager.unacknowledgedRiskReason(c, config: config))
        XCTAssertNotNil(ConnectionManager.unacknowledgedRiskReason(c, config: config + "group nogroup\n"))
        XCTAssertNil(ConnectionManager.unacknowledgedRiskReason(c, config: nil))
    }
}

/// PKCS#12 import és titkosított PEM kulcs.
final class PKCS12ImportTests: XCTestCase {
    var root: URL!
    var dir: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        dir = root.appendingPathComponent("vpn")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

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

    /// Valódi PKCS#12 a teszt saját kulcsával és tanúsítványával (`/usr/bin/openssl pkcs12 -export`).
    private func makeP12(_ name: String, password: String) throws -> Data {
        XCTAssertEqual(try openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem",
                                    "-subj", "/CN=macvpn-test", "-days", "1"]), 0)
        XCTAssertEqual(try openssl(["pkcs12", "-export", "-in", "c.pem", "-inkey", "k.pem", "-out", name,
                                    "-passout", "pass:\(password)"]), 0)
        return try Data(contentsOf: dir.appendingPathComponent(name))
    }

    private func check(_ p12: Data, _ name: String) throws {
        XCTAssertTrue(ConfigImporter.isPKCS12(p12))
        let input = "client\ndev tun\nremote a 1194\npkcs12 \(name)\n"
        let prepared = try ConfigImporter.prepare(fileName: "x.ovpn", content: input, baseDirectory: dir)
        XCTAssertEqual(prepared.inlinedFiles, [name])
        XCTAssertEqual(prepared.issues, [])
        XCTAssertEqual(prepared.risky, [])
        let lines = prepared.config.components(separatedBy: "\n")
        let start = try XCTUnwrap(lines.firstIndex(of: "<pkcs12>"))
        let end = try XCTUnwrap(lines.firstIndex(of: "</pkcs12>"))
        let body = Array(lines[(start + 1)..<end])
        XCTAssertTrue(body.allSatisfy { $0.count <= 64 && !$0.isEmpty })
        XCTAssertTrue(body.dropLast().allSatisfy { $0.count == 64 })
        XCTAssertEqual(Data(base64Encoded: body.joined()), p12)
        XCTAssertFalse(prepared.config.contains("pkcs12 \(name)"))
        // Export: a <pkcs12> kulcsanyag, levágható.
        XCTAssertEqual(ConfigExporter.secretMaterial(in: prepared.config, kind: .openvpn), ["<pkcs12>"])
        XCTAssertFalse(ConfigExporter.stripSecrets(prepared.config, kind: .openvpn).contains("pkcs12"))
    }

    func testImportsPKCS12WithoutPassword() throws {
        try check(try makeP12("nopass.p12", password: ""), "nopass.p12")
    }

    func testImportsPKCS12WithPassword() throws {
        try check(try makeP12("client.p12", password: "s3cret"), "client.p12")
    }

    func testRejectsNonPKCS12AndEscapes() throws {
        try "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n".write(to: dir.appendingPathComponent("fake.p12"),
                                                                                 atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try ConfigImporter.prepare(fileName: "x.ovpn", content: "remote a\npkcs12 fake.p12\n", baseDirectory: dir)) {
            XCTAssertEqual($0 as? ConfigImportError, .wrongFormat(directive: "pkcs12", file: "fake.p12"))
        }
        XCTAssertThrowsError(try ConfigImporter.prepare(fileName: "x.ovpn", content: "remote a\npkcs12 ../out.p12\n", baseDirectory: dir)) {
            XCTAssertEqual($0 as? ConfigImportError, .outsideBaseDirectory("../out.p12"))
        }
        XCTAssertThrowsError(try ConfigImporter.prepare(fileName: "x.ovpn", content: "remote a\npkcs12 missing.p12\n", baseDirectory: dir)) {
            XCTAssertEqual($0 as? ConfigImportError, .missingFile("missing.p12"))
        }
        XCTAssertFalse(ConfigImporter.isPKCS12(Data([0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x02] + [UInt8](repeating: 0, count: 40))))
        XCTAssertFalse(ConfigImporter.isPKCS12(Data([0x31, 0x82])))
    }

    func testEncryptedPEMKeysAreInlined() throws {
        XCTAssertEqual(try openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "c.pem",
                                    "-subj", "/CN=macvpn-test", "-days", "1"]), 0)
        XCTAssertEqual(try openssl(["rsa", "-in", "k.pem", "-aes256", "-passout", "pass:x", "-out", "legacy.key"]), 0)
        XCTAssertEqual(try openssl(["pkcs8", "-topk8", "-in", "k.pem", "-passout", "pass:x", "-out", "pkcs8.key"]), 0)
        for name in ["legacy.key", "pkcs8.key"] {
            let prepared = try ConfigImporter.prepare(fileName: "x.ovpn", content: "remote a\nkey \(name)\n", baseDirectory: dir)
            XCTAssertEqual(prepared.inlinedFiles, [name], name)
            XCTAssertTrue(prepared.config.contains("ENCRYPTED"), name)
            XCTAssertEqual(prepared.issues, [], name)
        }
    }
}
