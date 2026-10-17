import XCTest
import CryptoKit
@testable import MacVPNCore

/// Az offline Ed25519 kiadás-aláírás ellenőrzése. Minden aláírás eldobható kulccsal készül, a valódi
/// kiadási kulcsokat a tesztek nem használják.
final class UpdateSignatureTests: XCTestCase {
    let primary = Curve25519.Signing.PrivateKey()
    let backup = Curve25519.Signing.PrivateKey()
    let digest = String(repeating: "0123456789abcdef", count: 4)

    var keys: [Curve25519.Signing.PublicKey] { [primary.publicKey, backup.publicKey] }

    func sign(_ key: Curve25519.Signing.PrivateKey, version: String = "0.2.2", digest: String? = nil) throws -> String {
        let message = try XCTUnwrap(UpdateSignature.message(version: version, sha256Hex: digest ?? self.digest))
        return try key.signature(for: message).base64EncodedString() + "\n"
    }

    func verify(_ sig: String, version: String = "0.2.2", digest: String? = nil) -> Bool {
        UpdateSignature.verify(version: version, sha256Hex: digest ?? self.digest, signatureBase64: sig, publicKeys: keys)
    }

    func testMessageFormatIsExact() throws {
        let message = try XCTUnwrap(UpdateSignature.message(version: "0.2.2", sha256Hex: digest))
        XCTAssertEqual(message, Data("macvpn-update-v1\n0.2.2\n\(digest)\n".utf8))
        XCTAssertNil(UpdateSignature.message(version: "v0.2.2", sha256Hex: digest))
        XCTAssertNil(UpdateSignature.message(version: "0.2", sha256Hex: digest))
        XCTAssertNil(UpdateSignature.message(version: "0.2.2\n", sha256Hex: digest))
        XCTAssertNil(UpdateSignature.message(version: "0.2.2", sha256Hex: digest.uppercased()))
        XCTAssertNil(UpdateSignature.message(version: "0.2.2", sha256Hex: String(digest.dropLast())))
        XCTAssertNil(UpdateSignature.message(version: "0.2.2", sha256Hex: String(digest.dropLast()) + "g"))
    }

    func testValid() throws {
        XCTAssertTrue(verify(try sign(primary)))
        // Záró újsor nélkül is (a fájl formátuma egy sor + újsor, de a sor maga a lényeg).
        XCTAssertTrue(verify(try sign(primary).trimmingCharacters(in: .newlines)))
    }

    func testBackupKeyAlsoWorks() throws {
        XCTAssertTrue(verify(try sign(backup)))
        XCTAssertTrue(UpdateSignature.verify(version: "0.2.2", sha256Hex: digest, signatureBase64: try sign(backup),
                                             publicKeys: [backup.publicKey]))
    }

    func testWrongVersion() throws {
        XCTAssertFalse(verify(try sign(primary, version: "0.2.1")))
        XCTAssertFalse(verify(try sign(primary), version: "0.2.3"))
        XCTAssertFalse(verify(try sign(primary), version: "v0.2.2"))
    }

    func testWrongHash() throws {
        let other = String(repeating: "f", count: 64)
        XCTAssertFalse(verify(try sign(primary, digest: other)))
        XCTAssertFalse(verify(try sign(primary), digest: other))
        XCTAssertFalse(verify(try sign(primary), digest: digest.uppercased()))
        XCTAssertFalse(verify(try sign(primary), digest: ""))
    }

    func testWrongKey() throws {
        XCTAssertFalse(verify(try sign(Curve25519.Signing.PrivateKey())))
        XCTAssertFalse(UpdateSignature.verify(version: "0.2.2", sha256Hex: digest, signatureBase64: try sign(primary),
                                              publicKeys: [backup.publicKey]))
        XCTAssertFalse(UpdateSignature.verify(version: "0.2.2", sha256Hex: digest, signatureBase64: try sign(primary), publicKeys: []))
        // A beágyazott (valódi) kulcsok az eldobható kulcs aláírását nem fogadják el.
        XCTAssertFalse(UpdateSignature.verify(version: "0.2.2", sha256Hex: digest, signatureBase64: try sign(primary)))
    }

    func testMalformedBase64() throws {
        let good = try sign(primary).trimmingCharacters(in: .newlines)
        for bad in ["", "\n", "not base64!", String(good.dropLast(4)), good + "AAAA", "====",
                    Data(repeating: 1, count: 63).base64EncodedString(), Data(repeating: 1, count: 65).base64EncodedString(),
                    String(good.prefix(44)) + "\n" + String(good.dropFirst(44)), String(good.prefix(44)) + " " + String(good.dropFirst(44)),
                    good + "\n" + good] {
            XCTAssertFalse(verify(bad), bad)
        }
    }

    func testOversizeInput() throws {
        let good = try sign(primary)
        XCTAssertTrue(verify(good + String(repeating: "\n", count: UpdateSignature.maxSignatureFileSize - good.utf8.count)))
        XCTAssertFalse(verify(good + String(repeating: "\n", count: UpdateSignature.maxSignatureFileSize - good.utf8.count + 1)))
        XCTAssertFalse(verify(String(repeating: "A", count: 1 << 20)))
        XCTAssertEqual(UpdateSignature.maxSignatureFileSize, 1024)
    }

    /// Az elsődleges és a tartalék nyilvános kulcs érvényes, 32 bájtos, és különböző.
    func testEmbeddedPublicKeysDecodeTo32Bytes() throws {
        for b64 in [UpdateSignature.primaryPublicKeyBase64, UpdateSignature.backupPublicKeyBase64] {
            let raw = try XCTUnwrap(Data(base64Encoded: b64), b64)
            XCTAssertEqual(raw.count, 32, b64)
            XCTAssertNoThrow(try Curve25519.Signing.PublicKey(rawRepresentation: raw))
        }
        XCTAssertEqual(UpdateSignature.primaryPublicKeyBase64, "KfHXY5gQkjMA3e8bx8rIuPQ4x3zCuSJoMo3PYcMgbFk=")
        XCTAssertEqual(UpdateSignature.backupPublicKeyBase64, "QUFfsn9koh06k4EX9lNPognIvQ84/Ox6lgZhShvVrmI=")
        XCTAssertEqual(UpdateSignature.trustedKeys.map { $0.rawRepresentation.base64EncodedString() },
                       [UpdateSignature.primaryPublicKeyBase64, UpdateSignature.backupPublicKeyBase64])
    }

    // MARK: OpenSSL interop és a sign-release.sh

    static var repoRoot: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    /// OpenSSL 3 (Homebrew); nil, ha nincs (ilyenkor a teszt kimarad).
    static var openssl: String? {
        let path = "/opt/homebrew/opt/openssl@3/bin/openssl"
        guard FileManager.default.isExecutableFile(atPath: path),
              let out = try? run(path, ["version"]), out.status == 0, out.stdout.hasPrefix("OpenSSL 3.") else { return nil }
        return path
    }

    @discardableResult
    static func run(_ tool: String, _ args: [String], env: [String: String]? = nil) throws -> (status: Int32, stdout: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        if let env { p.environment = ProcessInfo.processInfo.environment.merging(env) { $1 } }
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("macvpn-sig-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    /// Eldobható OpenSSL Ed25519 kulcs: (PEM útvonal, CryptoKit nyilvános kulcs).
    func opensslKey(_ openssl: String, in dir: URL) throws -> (pem: URL, publicKey: Curve25519.Signing.PublicKey) {
        let pem = dir.appendingPathComponent("throwaway.pem")
        let der = dir.appendingPathComponent("throwaway.pub.der")
        XCTAssertEqual(try Self.run(openssl, ["genpkey", "-algorithm", "ed25519", "-out", pem.path]).status, 0)
        XCTAssertEqual(try Self.run(openssl, ["pkey", "-in", pem.path, "-pubout", "-outform", "DER", "-out", der.path]).status, 0)
        let spki = try Data(contentsOf: der)
        XCTAssertEqual(spki.count, 44)
        return (pem, try Curve25519.Signing.PublicKey(rawRepresentation: spki.suffix(32)))
    }

    /// Az OpenSSL `pkeyutl -sign -rawin` (tiszta Ed25519) aláírását a CryptoKit elfogadja.
    func testOpenSSLRawinSignatureVerifiesInCryptoKit() throws {
        guard let openssl = Self.openssl else { throw XCTSkip("OpenSSL 3 not installed") }
        let dir = try tempDir()
        let key = try opensslKey(openssl, in: dir)
        let message = dir.appendingPathComponent("message")
        let sig = dir.appendingPathComponent("sig.bin")
        try XCTUnwrap(UpdateSignature.message(version: "0.2.2", sha256Hex: digest)).write(to: message)
        XCTAssertEqual(try Self.run(openssl, ["pkeyutl", "-sign", "-rawin", "-inkey", key.pem.path,
                                              "-in", message.path, "-out", sig.path]).status, 0)
        let b64 = try Data(contentsOf: sig).base64EncodedString() + "\n"
        XCTAssertTrue(UpdateSignature.verify(version: "0.2.2", sha256Hex: digest, signatureBase64: b64, publicKeys: [key.publicKey]))
        XCTAssertFalse(UpdateSignature.verify(version: "0.2.3", sha256Hex: digest, signatureBase64: b64, publicKeys: [key.publicKey]))
        XCTAssertFalse(UpdateSignature.verify(version: "0.2.2", sha256Hex: digest, signatureBase64: b64))
    }

    /// `scripts/sign-release.sh --dry-run` eldobható kulccsal: az aláírása a CryptoKit szerint is érvényes a helyben
    /// számolt hash-re (a script és az app ugyanazt az üzenetet építi). Hálózat és Keychain nélkül.
    func testSignReleaseDryRunMatchesApp() throws {
        guard let openssl = Self.openssl else { throw XCTSkip("OpenSSL 3 not installed") }
        let dir = try tempDir()
        let key = try opensslKey(openssl, in: dir)
        let dmg = dir.appendingPathComponent("MacVPN-0.2.2.dmg")
        try Data((0..<5000).map { UInt8($0 % 251) }).write(to: dmg)
        let script = Self.repoRoot.appendingPathComponent("scripts/sign-release.sh").path
        let out = try Self.run("/bin/bash", [script, "--dry-run", "--dmg", dmg.path, "--backup-key", key.pem.path, "v0.2.2"],
                               env: ["HTTPS_PROXY": "http://127.0.0.1:9", "GIT_TERMINAL_PROMPT": "0"])
        XCTAssertEqual(out.status, 0, out.stdout)
        let line = try XCTUnwrap(out.stdout.split(separator: "\n").first { $0.hasPrefix("signature: ") })
        let sig = String(line.dropFirst("signature: ".count)) + "\n"
        let localHash = try UpdateInstaller.sha256(of: dmg)
        XCTAssertTrue(out.stdout.contains(localHash))
        XCTAssertTrue(UpdateSignature.verify(version: "0.2.2", sha256Hex: localHash, signatureBase64: sig, publicKeys: [key.publicKey]))
        XCTAssertFalse(UpdateSignature.verify(version: "0.2.2", sha256Hex: localHash, signatureBase64: sig))
        XCTAssertTrue(out.stdout.contains("not an embedded key"))
    }

    /// A script a Swift forrásból olvassa a beágyazott kulcsokat: ugyanazt kapja, mint az app.
    func testSignReleaseUsesTheEmbeddedKeys() throws {
        let script = Self.repoRoot.appendingPathComponent("scripts/sign-release.sh").path
        let out = try Self.run("/bin/bash", [script, "--print-public-keys"])
        XCTAssertEqual(out.status, 0)
        XCTAssertEqual(out.stdout, "primary \(UpdateSignature.primaryPublicKeyBase64)\nbackup \(UpdateSignature.backupPublicKeyBase64)\n")
    }
}
