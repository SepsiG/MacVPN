import Foundation

/// Indítás bejelentkezéskor kódaláírás nélkül: per-user LaunchAgent (`~/Library/LaunchAgents/local.macvpn.launcher.plist`).
/// Az ad-hoc aláírt (Developer ID nélküli) MacVPN-nél az `SMAppService.mainApp` gyakran `.notFound`-ot ad, vagy a
/// `register()` hibát dob; ilyenkor ezt használjuk. A `ProgramArguments` `/usr/bin/open -b local.macvpn`: a bundle
/// azonosító alapján indít, így nincs benne útvonal, és az app áthelyezése után is működik. Nem hívunk
/// `launchctl bootstrap`-et: a launchd a következő bejelentkezéskor veszi fel az agentet.
public struct LaunchAgentLoginItem: Sendable {
    public static let defaultLabel = "local.macvpn.launcher"
    public static let defaultBundleIdentifier = "local.macvpn"

    public let directory: URL
    public let label: String
    public let bundleIdentifier: String

    /// - Parameter directory: a LaunchAgents könyvtár; a tesztek ideiglenes könyvtárat adnak át.
    public init(directory: URL = LaunchAgentLoginItem.defaultDirectory,
                label: String = LaunchAgentLoginItem.defaultLabel,
                bundleIdentifier: String = LaunchAgentLoginItem.defaultBundleIdentifier) {
        self.directory = directory
        self.label = label
        self.bundleIdentifier = bundleIdentifier
    }

    public static var defaultDirectory: URL {
        URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
    }

    public var plistURL: URL { directory.appendingPathComponent("\(label).plist") }

    public var programArguments: [String] { ["/usr/bin/open", "-b", bundleIdentifier] }

    /// A kiírt property list tartalma.
    public var plistContents: [String: Any] {
        [
            "Label": label,
            "ProgramArguments": programArguments,
            "RunAtLoad": true,
            "LimitLoadToSessionType": "Aqua",
        ]
    }

    public func plistData() throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: plistContents, format: .xml, options: 0)
    }

    // MARK: Állapot

    /// Be van kapcsolva: a plist szabályos fájl (nem symlink), és a `Label` és a `ProgramArguments` a várt.
    public var isInstalled: Bool {
        guard let plist = readOwnPlist() else { return false }
        return plist["Label"] as? String == label && plist["ProgramArguments"] as? [String] == programArguments
    }

    /// A plist beolvasása O_NOFOLLOW-val; nil, ha nincs, symlink, nem szabályos fájl vagy nem property list.
    private func readOwnPlist() -> [String: Any]? {
        guard isRegularFile(plistURL.path) else { return nil }
        let fd = open(plistURL.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard let data = try? handle.read(upToCount: 1 << 16) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    private func isRegularFile(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG
    }

    private func exists(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0
    }

    // MARK: Írás, törlés

    /// Kiírja a plistet atomikusan (temp fájl O_EXCL | O_NOFOLLOW, 0644, fsync, rename). Symlinket vagy nem
    /// szabályos fájlt nem ír felül. A LaunchAgents könyvtárat létrehozza, ha hiányzik.
    public func install() throws {
        let path = plistURL.path
        if exists(path), !isRegularFile(path) { throw LaunchAgentError.notRegularFile(path) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        let data = try plistData()
        let tmp = directory.appendingPathComponent(".\(label).plist.tmp-\(UUID().uuidString)")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o644)
        guard fd >= 0 else { throw LaunchAgentError.writeFailed(path, errno) }
        do {
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            // Az umask ne szűkítse/bővítse: a LaunchAgentek szokásos módja 0644.
            guard fchmod(fd, 0o644) == 0 else { throw LaunchAgentError.writeFailed(path, errno) }
            try handle.write(contentsOf: data)
            guard fsync(fd) == 0 else { throw LaunchAgentError.writeFailed(path, errno) }
            try handle.close()
            // Közben symlinkre cserélték? A rename magát a linket cserélné, de inkább megtagadjuk.
            if exists(path), !isRegularFile(path) { throw LaunchAgentError.notRegularFile(path) }
            guard rename(tmp.path, path) == 0 else { throw LaunchAgentError.writeFailed(path, errno) }
        } catch {
            unlink(tmp.path)
            throw error
        }
    }

    /// Törli a plistet, de csak ha szabályos fájl a mi `Label`-ünkkel (más tartalmú / idegen fájlt nem bánt).
    /// True, ha törölt.
    @discardableResult
    public func remove() throws -> Bool {
        guard let plist = readOwnPlist(), plist["Label"] as? String == label else { return false }
        guard unlink(plistURL.path) == 0 else {
            if errno == ENOENT { return false }
            throw LaunchAgentError.removeFailed(plistURL.path, errno)
        }
        return true
    }
}

public enum LaunchAgentError: LocalizedError, Equatable {
    case notRegularFile(String)
    case writeFailed(String, Int32)
    case removeFailed(String, Int32)

    public var errorDescription: String? {
        switch self {
        case .notRegularFile(let path):
            return L10n.tr("Refusing to write %@: it is a symbolic link or not a regular file.", path)
        case .writeFailed(let path, let code):
            return L10n.tr("Could not write %@: %@", path, String(cString: strerror(code)))
        case .removeFailed(let path, let code):
            return L10n.tr("Could not remove %@: %@", path, String(cString: strerror(code)))
        }
    }
}

/// `LoginItemService` két réteggel: előbb az `SMAppService` (`primary`), ha az nem megy (hibát dob, vagy a
/// regisztráció után is `.notFound`), akkor a per-user LaunchAgent.
@MainActor
public final class FallbackLoginItemService: LoginItemService {
    private let primary: LoginItemService
    public let launchAgent: LaunchAgentLoginItem

    public init(primary: LoginItemService, launchAgent: LaunchAgentLoginItem = LaunchAgentLoginItem()) {
        self.primary = primary
        self.launchAgent = launchAgent
    }

    /// Az `SMAppService` `.enabled` / `.requiresApproval` állapota az erősebb; különben ha a LaunchAgent megvan,
    /// `.enabledViaLaunchAgent`; egyébként az `SMAppService` állapota (`.notRegistered` / `.notFound`).
    public var status: LoginItemStatus {
        let primaryStatus = primary.status
        switch primaryStatus {
        case .enabled, .requiresApproval, .enabledViaLaunchAgent:
            return primaryStatus
        case .notRegistered, .notFound:
            return launchAgent.isInstalled ? .enabledViaLaunchAgent : primaryStatus
        }
    }

    public func register() throws {
        do {
            try primary.register()
            switch primary.status {
            case .enabled, .requiresApproval, .enabledViaLaunchAgent:
                // Sikerült a rendes úton: egy korábbi tartalék agent ne indítson még egyszer.
                _ = try? launchAgent.remove()
                return
            case .notRegistered, .notFound:
                break
            }
        } catch {
            // Ad-hoc aláírt build: az SMAppService hibát dob, jön a tartalék.
        }
        try launchAgent.install()
    }

    /// Mindkettőt eltávolítja. Az `SMAppService` hibáját elnyeli, hacsak utána is regisztrálva maradt
    /// (különben a kapcsoló hiba nélkül bekapcsolva maradna).
    public func unregister() throws {
        var primaryError: Error?
        do { try primary.unregister() } catch { primaryError = error }
        try launchAgent.remove()
        if let primaryError {
            switch primary.status {
            case .enabled, .requiresApproval: throw primaryError
            default: break
            }
        }
    }

    public func openSystemSettingsLoginItems() { primary.openSystemSettingsLoginItems() }
}
