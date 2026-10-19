import Foundation
import CryptoKit

/// A kiadások offline Ed25519 aláírása.
///
/// A karbantartó a GitHubtól független, offline kulccsal írja alá minden kiadás DMG-jének SHA-256-ját
/// (`scripts/sign-release.sh`); az aláírás a `MacVPN-<verzió>.dmg.sig` asset. Az app csak akkor telepít, ha az
/// aláírás a beágyazott nyilvános kulcsok valamelyikével érvényes, így egy feltört GitHub fiók (vagy CI) sem tud
/// frissítést kiadni.
///
/// Az aláírt üzenet bájtra pontosan: `"macvpn-update-v1\n" + verzió + "\n" + sha256hex_kisbetűs + "\n"`, a verzió
/// `v` nélkül (pl. `0.2.2`). Tiszta Ed25519 (OpenSSL 3: `pkeyutl -sign -rawin`). A `.sig` egyetlen sor: a 64 bájtos
/// aláírás base64-ben, záró újsorral.
public enum UpdateSignature {
    /// Az elsődleges kulcs (a karbantartó login Keychainjében). Nyers 32 bájt, base64.
    /// A `scripts/sign-release.sh` ugyanezt a két értéket a Swift forrásból olvassa ki.
    public static let primaryPublicKeyBase64 = "KfHXY5gQkjMA3e8bx8rIuPQ4x3zCuSJoMo3PYcMgbFk="
    /// A tartalék kulcs (offline, jelszókezelőben); az elsődleges elvesztése vagy kompromittálódása esetére.
    public static let backupPublicKeyBase64 = "QUFfsn9koh06k4EX9lNPognIvQ84/Ox6lgZhShvVrmI="

    /// A `.sig` asset legnagyobb mérete (a valódi: 88 karakter + újsor).
    public static let maxSignatureFileSize = 1024
    static let domain = "macvpn-update-v1"

    /// A beágyazott, megbízható kulcsok (elsődleges, tartalék).
    public static var trustedKeys: [Curve25519.Signing.PublicKey] {
        [primaryPublicKeyBase64, backupPublicKeyBase64].compactMap { b64 in
            Data(base64Encoded: b64).flatMap { try? Curve25519.Signing.PublicKey(rawRepresentation: $0) }
        }
    }

    /// Az aláírt üzenet. Nil, ha a verzió nem `X.Y.Z`, vagy a hash nem 64 kisbetűs hex karakter.
    public static func message(version: String, sha256Hex: String) -> Data? {
        guard version.range(of: "^[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}$", options: .regularExpression) != nil,
              sha256Hex.utf8.count == 64,
              sha256Hex.utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }) else { return nil }
        return Data("\(domain)\n\(version)\n\(sha256Hex)\n".utf8)
    }

    /// Igaz, ha a `signatureBase64` (a `.sig` tartalma) a `version` és `sha256Hex` üzenetre érvényes Ed25519 aláírás
    /// a `publicKeys` bármelyikével. Tiszta függvény: nincs hálózat, nincs fájl. A hash a helyben számolt SHA-256.
    public static func verify(version: String, sha256Hex: String, signatureBase64: String,
                              publicKeys: [Curve25519.Signing.PublicKey] = trustedKeys) -> Bool {
        guard signatureBase64.utf8.count <= maxSignatureFileSize,
              let message = message(version: version, sha256Hex: sha256Hex) else { return false }
        // Egy sor; a záró újsor (és szóköz) megengedett, belső szóköz vagy több sor nem.
        let trimmed = signatureBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains(where: { $0.isWhitespace || $0.isNewline }),
              let signature = Data(base64Encoded: trimmed), signature.count == 64 else { return false }
        return publicKeys.contains { $0.isValidSignature(signature, for: message) }
    }
}
