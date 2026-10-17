import Foundation
import os

/// `<base>/<UUID>/meta.json`, `config`. (A natív profil nem itt van: lásd `NativeProfileStaging`.)
/// A `mvpn` root script ugyanebből az útvonalból olvas: ~/Library/Application Support/MacVPN/connections/<UUID>/config
public final class ConnectionStore {
    public let baseURL: URL

    /// `~/Library/Application Support/MacVPN` (a felhasználói adatok gyökere).
    public static var applicationSupportDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MacVPN", isDirectory: true)
    }

    public static var defaultBaseURL: URL {
        applicationSupportDirectory.appendingPathComponent("connections", isDirectory: true)
    }

    public struct RemovalError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// A felhasználói adatok törlése (eltávolításkor). Csak `MacVPN` nevű, valódi (nem symlink) könyvtárat töröl.
    public static func removeApplicationSupportDirectory(_ url: URL = applicationSupportDirectory) throws {
        guard url.lastPathComponent == "MacVPN" else { throw RemovalError(message: L10n.tr("Cannot delete: %@", url.path)) }
        var st = stat()
        guard lstat(url.path, &st) == 0 else { return }
        guard (st.st_mode & S_IFMT) == S_IFDIR else { throw RemovalError(message: L10n.tr("Not a directory: %@", url.path)) }
        try FileManager.default.removeItem(at: url)
    }

    private let fm = FileManager.default
    private static let log = Logger(subsystem: "local.macvpn", category: "store")
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    public init(baseURL: URL = ConnectionStore.defaultBaseURL) {
        self.baseURL = baseURL
    }

    public func directory(for id: UUID) -> URL { baseURL.appendingPathComponent(id.uuidString, isDirectory: true) }
    public func configURL(for id: UUID) -> URL { directory(for: id).appendingPathComponent("config") }
    /// A régebbi verziók ide írták a natív profilt (benne a jelszóval és a PSK-val); induláskor törlendő.
    public static let legacyProfileName = "profile.mobileconfig"
    func metaURL(for id: UUID) -> URL { directory(for: id).appendingPathComponent("meta.json") }

    public func list() throws -> [Connection] {
        guard fm.fileExists(atPath: baseURL.path) else { return [] }
        let dirs = try fm.contentsOfDirectory(at: baseURL, includingPropertiesForKeys: nil)
        return dirs.compactMap { dir in
            let meta = dir.appendingPathComponent("meta.json")
            guard let data = try? Data(contentsOf: meta) else { return nil }
            do {
                return try decoder.decode(Connection.self, from: data)
            } catch {
                Self.log.error("Invalid meta.json (\(dir.lastPathComponent, privacy: .public)): \(error.localizedDescription, privacy: .public)")
                return nil
            }
        }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// `config == nil`: a meglévő config fájl változatlan marad.
    public func save(_ connection: Connection, config: String?) throws {
        let dir = directory(for: connection.id)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        try writePrivate(try encoder.encode(connection), to: metaURL(for: connection.id))
        if let config {
            try writePrivate(Data(config.utf8), to: configURL(for: connection.id))
        }
    }

    /// Migráció: a kapcsolat-könyvtárakban maradt régi `profile.mobileconfig` fájlok törlése. A törölt fájlok száma.
    @discardableResult
    public func removeLegacyProfiles() -> Int {
        guard let dirs = try? fm.contentsOfDirectory(at: baseURL, includingPropertiesForKeys: nil) else { return 0 }
        var removed = 0
        for dir in dirs {
            let url = dir.appendingPathComponent(Self.legacyProfileName)
            var st = stat()
            // Symlinket is törlünk (magát a linket), a célját nem.
            guard lstat(url.path, &st) == 0 else { continue }
            if unlink(url.path) == 0 { removed += 1 }
        }
        return removed
    }

    public func loadConfig(_ id: UUID) throws -> String {
        try String(contentsOf: configURL(for: id), encoding: .utf8)
    }

    public func delete(_ id: UUID) throws {
        try fm.removeItem(at: directory(for: id))
    }

    /// Temp fájl 0600-zal létrehozva (O_EXCL), fsync, majd rename és a könyvtár fsync-je: soha nincs tágabb jogú
    /// állapot, és áramszünet után sem marad üres / csonka meta.json vagy config.
    private func writePrivate(_ data: Data, to url: URL) throws {
        let dir = url.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".tmp-\(UUID().uuidString)")
        let fd = open(tmp.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: tmp.path]) }
        do {
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            try handle.write(contentsOf: data)
            guard fsync(fd) == 0 else { throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: tmp.path]) }
            try handle.close()
            guard rename(tmp.path, url.path) == 0 else {
                throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
            }
        } catch {
            try? fm.removeItem(at: tmp)
            throw error
        }
        // A rename tartóssága; ha a könyvtár nem nyitható meg, az írás attól még sikeres.
        let dirFD = open(dir.path, O_RDONLY | O_DIRECTORY)
        if dirFD >= 0 {
            _ = fsync(dirFD)
            close(dirFD)
        }
    }
}
