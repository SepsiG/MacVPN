import Foundation

/// The generated L2TP / Cisco profile is written to a fresh private temp directory (never into the connection store),
/// opened from there, and deleted once the service shows up in `scutil --nc list`, or at the latest on the next launch.
/// The password is never in the profile (it is passed in-process when connecting); the PSK is, because without it
/// the system service would not work from System Settings.
public enum NativeProfileStaging {
    /// Prefix of the staging directories (`mkdtemp`), also what the launch sweep looks for.
    public static let prefix = "macvpn-profile."

    /// The per-user temp directory (`$TMPDIR`, itself 0700 and owned by the user).
    public static var defaultParent: URL { FileManager.default.temporaryDirectory }

    public struct StagingError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// `mkdtemp` 0700 directory in `parent`, with the profile created 0600 (O_EXCL, no symlink follow).
    public static func stage(_ data: Data, fileName: String, in parent: URL) throws -> URL {
        guard !fileName.isEmpty, !fileName.contains("/"), fileName != ".", fileName != ".." else {
            throw StagingError(message: L10n.tr("Cannot write: %@", fileName))
        }
        var template = Array(parent.appendingPathComponent(prefix + "XXXXXXXX").path.utf8CString)
        guard let created = mkdtemp(&template) else {
            throw StagingError(message: L10n.tr("Cannot create a temporary directory"))
        }
        let dir = URL(fileURLWithPath: String(cString: created), isDirectory: true)
        let file = dir.appendingPathComponent(fileName)
        let fd = open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            try? FileManager.default.removeItem(at: dir)
            throw StagingError(message: L10n.tr("Cannot write: %@", file.path))
        }
        do {
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            try handle.write(contentsOf: data)
            try handle.close()
        } catch {
            try? FileManager.default.removeItem(at: dir)
            throw error
        }
        return file
    }

    /// Deletes the staging directory of `profile`. Anything not inside a staging directory is left alone.
    public static func remove(_ profile: URL) {
        let dir = profile.deletingLastPathComponent()
        guard dir.lastPathComponent.hasPrefix(prefix), isRealDirectory(dir.path) else { return }
        try? FileManager.default.removeItem(at: dir)
    }

    /// Launch sweep: deletes every leftover staging directory in `parent` (real directories only, not symlinks).
    @discardableResult
    public static func sweep(in parent: URL) -> Int {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: parent.path) else { return 0 }
        var removed = 0
        for name in names where name.hasPrefix(prefix) {
            let url = parent.appendingPathComponent(name)
            guard isRealDirectory(url.path) else { continue }
            if (try? FileManager.default.removeItem(at: url)) != nil { removed += 1 }
        }
        return removed
    }

    static func isRealDirectory(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR
    }
}

/// The staged profiles waiting for their service to appear. Not thread-safe: used from the main actor.
public final class StagedProfiles {
    /// A re-saved profile whose service already existed: the service being listed says nothing about whether the new
    /// profile was installed. macOS keeps an opened profile in System Settings for a few minutes, so the file is
    /// deleted only after this much time (or on the next launch).
    public static let regeneratedGrace: TimeInterval = 600

    struct Entry {
        let profile: URL
        let stagedAt: Date
        let serviceExisted: Bool
    }

    private var entries: [UUID: Entry] = [:]
    private let clock: () -> Date

    public init(clock: @escaping () -> Date = Date.init) {
        self.clock = clock
    }

    public var pendingIDs: Set<UUID> { Set(entries.keys) }

    /// A previous staged profile of the same connection is deleted.
    public func track(_ id: UUID, profile: URL, serviceExisted: Bool) {
        if let old = entries[id], old.profile != profile { NativeProfileStaging.remove(old.profile) }
        entries[id] = Entry(profile: profile, stagedAt: clock(), serviceExisted: serviceExisted)
    }

    /// Called after each successful `scutil --nc list` with the connections whose service is listed.
    public func servicesSeen(_ ids: Set<UUID>) {
        let now = clock()
        for (id, entry) in entries where ids.contains(id) {
            if entry.serviceExisted, now.timeIntervalSince(entry.stagedAt) < Self.regeneratedGrace { continue }
            NativeProfileStaging.remove(entry.profile)
            entries[id] = nil
        }
    }

    public func removeAll() {
        for entry in entries.values { NativeProfileStaging.remove(entry.profile) }
        entries = [:]
    }
}
