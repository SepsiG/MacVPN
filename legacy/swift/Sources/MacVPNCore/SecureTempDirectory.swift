import Foundation

/// Biztonságos `mkdtemp(3)` és a hozzá tartozó törlés.
///
/// A `mkdtemp(&array)` visszatérési pointere az inout-to-pointer konverzió miatt csak a hívás alatt érvényes;
/// optimalizált buildben utána felszabadított memóriára mutathat, ebből üres vagy szemét útvonal lesz.
/// Ezért az elkészült útvonalat magából a bufferből olvassuk ki, és ellenőrizzük, hogy valóban a kért
/// szülőkönyvtárban, a kért előtaggal jött létre. A törlés csak ilyen, általunk létrehozott könyvtárat érinthet.
public enum SecureTempDirectory {
    public struct CreationError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    static let randomLength = 8

    /// Friss 0700-as könyvtár: `<parent>/<prefix>XXXXXXXX`.
    public static func make(prefix: String, in parent: URL) throws -> URL {
        let parentPath = parent.standardizedFileURL.path
        guard parentPath.hasPrefix("/"), !prefix.isEmpty, !prefix.contains("/") else {
            throw CreationError(message: L10n.tr("Cannot create a temporary directory"))
        }
        let template = (parentPath as NSString).appendingPathComponent(prefix + String(repeating: "X", count: randomLength))
        var buffer = Array(template.utf8CString)
        let ok = buffer.withUnsafeMutableBufferPointer { mkdtemp($0.baseAddress!) != nil }
        guard ok else {
            let reason = String(cString: strerror(errno))
            throw CreationError(message: L10n.tr("Cannot create a temporary directory") + " (\(template): \(reason))")
        }
        let path = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        guard isOwnedPath(path, prefix: prefix, parentPath: parentPath) else {
            throw CreationError(message: L10n.tr("Cannot create a temporary directory") + " (\(template))")
        }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    /// Abszolút útvonal, közvetlenül a szülőben, `<prefix>` + pontosan 8 véletlen karakter nevű.
    static func isOwnedPath(_ path: String, prefix: String, parentPath: String? = nil) -> Bool {
        guard path.hasPrefix("/"), path != "/" else { return false }
        let ns = path as NSString
        let name = ns.lastPathComponent
        guard name.hasPrefix(prefix), name.count == prefix.count + randomLength,
              !name.contains("/"), name != ".", name != ".." else { return false }
        if let parentPath, ns.deletingLastPathComponent != parentPath { return false }
        return true
    }

    /// Csak a saját, `make`-kel létrehozott könyvtárat törli: abszolút útvonal, előtaggal kezdődő név,
    /// valódi könyvtár (nem symlink). Minden más esetben nem csinál semmit.
    public static func removeIfOwned(_ dir: URL, prefix: String) {
        let path = dir.standardizedFileURL.path
        guard isOwnedPath(path, prefix: prefix) else { return }
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return }
        try? FileManager.default.removeItem(atPath: path)
    }
}
