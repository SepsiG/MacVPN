import Foundation
import CryptoKit

/// Frissítés letöltése, ellenőrzése, csatolása és a cserét végző segédscript előkészítése.
///
/// Folyamat: DMG + `.sha256` letöltése a cache-be → SHA-256 ellenőrzés (CryptoKit) → `hdiutil attach -readonly`
/// → a csatolt app bundle ID-je és verziója → segédscript egy friss 0700-as könyvtárban. A script megvárja az
/// app kilépését, `ditto`-val a cél mellé másol, átnevezéssel cserél, leveszi a quarantine-t, leválasztja a DMG-t,
/// újraindítja az appot és törli magát. Jogosultságot nem emel: nem írható célhelynél hibát ad.
/// Egy ellenőrzött letöltés: a DMG a saját 0700-as könyvtárában, és a hash-e.
public struct VerifiedDownload: Equatable, Sendable {
    public let dmg: URL
    public let directory: URL
    public let sha256: String
}

public struct UpdateInstaller: Sendable {
    public static let bundleIdentifier = "local.macvpn"
    public static let appName = "MacVPN.app"
    static let maxChecksumFileSize = 4096

    let http: HTTPClient
    let runner: CommandRunner
    public let cacheDirectory: URL

    public static var defaultCacheDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Caches/MacVPN", isDirectory: true)
    }

    public init(http: HTTPClient, runner: CommandRunner, cacheDirectory: URL = UpdateInstaller.defaultCacheDirectory) {
        self.http = http
        self.runner = runner
        self.cacheDirectory = cacheDirectory
    }

    // MARK: Letöltés + ellenőrzés

    /// A `.sha256` fájl: `<64 hex>  <fájlnév>` (a `shasum` kimenete; `*` bináris jelzés megengedett).
    public static func parseChecksum(_ text: String, expectedName: String) throws -> String {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        for line in lines {
            let parts = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" })
            guard parts.count == 2 else { continue }
            let hash = parts[0].lowercased()
            var name = parts[1].trimmingCharacters(in: .whitespaces)
            if name.hasPrefix("*") { name.removeFirst() }
            if name == expectedName, hash.count == 64, hash.allSatisfy({ $0.isHexDigit && $0.isASCII }) { return hash }
        }
        throw UpdateError.invalidChecksumFile
    }

    /// SHA-256 hex, darabolva olvasva (a DMG nagy lehet).
    public static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Letölti a DMG-t a cache alatti friss, 0700-as (mkdtemp) könyvtárba, és ellenőrzi az SHA-256-ot.
    /// Eltérésnél (vagy bármely hibánál) a könyvtárat törli; eltérésnél `checksumMismatch`.
    public func downloadVerified(_ release: Release) async throws -> VerifiedDownload {
        guard UpdateURLPolicy.isAllowedDownload(release.dmg.url) else { throw UpdateError.untrustedURL(release.dmg.url.absoluteString) }
        guard UpdateURLPolicy.isAllowedDownload(release.checksum.url) else {
            throw UpdateError.untrustedURL(release.checksum.url.absoluteString)
        }
        // A név a release-ből jön, de csak a várt alakot fogadjuk el (útvonal-elem nem lehet benne).
        guard release.dmg.name.range(of: "^MacVPN-[0-9A-Za-z.]+\\.dmg$", options: .regularExpression) != nil else {
            throw UpdateError.missingAsset(release.dmg.name)
        }
        let sumResponse = try await http.get(release.checksum.url)
        guard sumResponse.status == 200 else { throw UpdateError.http(sumResponse.status) }
        guard sumResponse.data.count <= Self.maxChecksumFileSize,
              let text = String(data: sumResponse.data, encoding: .utf8) else { throw UpdateError.invalidChecksumFile }
        let expected = try Self.parseChecksum(text, expectedName: release.dmg.name)

        try prepareCacheDirectory()
        let directory = try RootInstaller.makePrivateTempDirectory(prefix: "download", in: cacheDirectory)
        do {
            let (tmp, status) = try await http.download(release.dmg.url)
            defer { try? FileManager.default.removeItem(at: tmp) }
            guard status == 200 else { throw UpdateError.http(status) }
            let dest = directory.appendingPathComponent(release.dmg.name)
            try FileManager.default.moveItem(at: tmp, to: dest)
            guard try Self.sha256(of: dest) == expected else { throw UpdateError.checksumMismatch }
            return VerifiedDownload(dmg: dest, directory: directory, sha256: expected)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    private func prepareCacheDirectory() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: cacheDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: cacheDirectory.path, isDirectory: &isDir), isDir.boolValue,
              (try? fm.destinationOfSymbolicLink(atPath: cacheDirectory.path)) == nil else {
            throw UpdateError.notWritable(cacheDirectory.path)
        }
        _ = chmod(cacheDirectory.path, 0o700)
    }

    // MARK: Csatolás

    /// `hdiutil attach -plist` kimenetéből az első csatolási pont (a `/Volumes` alatt).
    public static func parseMountPoint(_ plist: Data) throws -> String {
        guard let root = try? PropertyListSerialization.propertyList(from: plist, format: nil) as? [String: Any],
              let entities = root["system-entities"] as? [[String: Any]] else {
            throw UpdateError.mountFailed(L10n.tr("unexpected hdiutil output"))
        }
        for e in entities {
            if let mp = e["mount-point"] as? String, mp.hasPrefix("/Volumes/"), !mp.contains("/../") { return mp }
        }
        throw UpdateError.mountFailed(L10n.tr("no mount point"))
    }

    /// `hdiutil info -plist`: melyik lemezkép van a megadott csatolási ponton.
    public static func imagePath(forMountPoint mountPoint: String, infoPlist: Data) -> String? {
        guard let root = try? PropertyListSerialization.propertyList(from: infoPlist, format: nil) as? [String: Any],
              let images = root["images"] as? [[String: Any]] else { return nil }
        for image in images {
            let entities = image["system-entities"] as? [[String: Any]] ?? []
            if entities.contains(where: { $0["mount-point"] as? String == mountPoint }) { return image["image-path"] as? String }
        }
        return nil
    }

    /// Közvetlenül csatolás előtt újra hash-el (TOCTOU), csatol, majd ellenőrzi, hogy a csatolt kép a hash-elt fájl.
    public func mount(_ download: VerifiedDownload) async throws -> String {
        guard try Self.sha256(of: download.dmg) == download.sha256 else { throw UpdateError.checksumMismatch }
        let result = try await runner.run("/usr/bin/hdiutil",
                                          ["attach", "-nobrowse", "-readonly", "-noautoopen", "-plist", download.dmg.path], stdin: nil)
        guard result.exitCode == 0 else {
            throw UpdateError.mountFailed(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let mountPoint = try Self.parseMountPoint(Data(Self.xmlPart(result.stdout).utf8))
        let info = try? await runner.run("/usr/bin/hdiutil", ["info", "-plist"], stdin: nil)
        let image = info.flatMap { Self.imagePath(forMountPoint: mountPoint, infoPlist: Data(Self.xmlPart($0.stdout).utf8)) }
        guard let image, Self.samePath(image, download.dmg.path) else {
            await detach(mountPoint)
            throw UpdateError.mountFailed(L10n.tr("the mounted disk image is not the downloaded and verified file"))
        }
        return mountPoint
    }

    /// A plist előtt a hdiutil írhat egyéb sort; a `<?xml` kezdettől olvasunk.
    static func xmlPart(_ out: String) -> String {
        out.range(of: "<?xml").map { String(out[$0.lowerBound...]) } ?? out
    }

    static func samePath(_ a: String, _ b: String) -> Bool {
        URL(fileURLWithPath: a).resolvingSymlinksInPath().standardizedFileURL.path
            == URL(fileURLWithPath: b).resolvingSymlinksInPath().standardizedFileURL.path
    }

    public func detach(_ mountPoint: String) async {
        _ = try? await runner.run("/usr/bin/hdiutil", ["detach", mountPoint, "-quiet"], stdin: nil)
    }

    /// A csatolt app teljes ellenőrzése: `verifyBundle`, majd `codesign --verify --strict`. Az app ad-hoc aláírású,
    /// így ez az épséget (a lezárt erőforrásokat) ellenőrzi, nem a kiadó személyét.
    public func verifyApp(at app: URL, expectedVersion: String) async throws {
        try Self.verifyBundle(at: app, expectedVersion: expectedVersion)
        let result = try await runner.run("/usr/bin/codesign", ["--verify", "--strict", app.path], stdin: nil)
        guard result.exitCode == 0 else {
            let msg = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw UpdateError.invalidApp(L10n.tr("signature verification failed: %@", msg))
        }
    }

    /// Valódi könyvtár (nem symlink), bundle ID, verzió, és a `Contents` alatti symlinkek nem mutatnak a bundle-ön kívülre.
    public static func verifyBundle(at app: URL, expectedVersion: String) throws {
        var st = stat()
        guard lstat(app.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else {
            throw UpdateError.invalidApp(L10n.tr("%@ not found", appName))
        }
        let plistURL = app.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plistURL),
              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw UpdateError.invalidApp(L10n.tr("cannot read Info.plist"))
        }
        let bundleID = info["CFBundleIdentifier"] as? String
        guard bundleID == bundleIdentifier else {
            throw UpdateError.invalidApp(L10n.tr("bundle identifier %@, expected: %@", bundleID ?? "-", bundleIdentifier))
        }
        let version = info["CFBundleShortVersionString"] as? String
        guard version == expectedVersion else {
            throw UpdateError.invalidApp(L10n.tr("version %@, expected: %@", version ?? "-", expectedVersion))
        }
        try checkSymlinks(in: app)
    }

    static func checkSymlinks(in app: URL) throws {
        let fm = FileManager.default
        let bundle = app.resolvingSymlinksInPath().standardizedFileURL.path
        let contents = app.appendingPathComponent("Contents")
        guard let walker = fm.enumerator(at: contents, includingPropertiesForKeys: [.isSymbolicLinkKey]) else { return }
        for case let url as URL in walker {
            guard (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true else { continue }
            let target = url.resolvingSymlinksInPath().standardizedFileURL.path
            guard target.hasPrefix(bundle + "/") else {
                throw UpdateError.invalidApp(L10n.tr("link pointing outside the bundle: %@", url.path))
            }
        }
    }

    // MARK: Célhely

    /// A futó app helye (pl. `/Applications/MacVPN.app`, de bárhol lehet). Nem írható helynél hiba.
    public static func checkInstallTarget(_ bundleURL: URL) throws -> URL {
        let target = bundleURL.resolvingSymlinksInPath().standardizedFileURL
        guard target.pathExtension == "app" else { throw UpdateError.notWritable(target.path) }
        let fm = FileManager.default
        let parent = target.deletingLastPathComponent().path
        guard fm.isWritableFile(atPath: parent), fm.isWritableFile(atPath: target.path),
              !target.path.contains("/AppTranslocation/") else {
            throw UpdateError.notWritable(target.path)
        }
        return target
    }

    // MARK: Segédscript

    static func quote(_ s: String) -> String { RootInstaller.shellQuote(s) }

    /// A cserét végző bash script. Minden útvonal egyszeres idézőjelben, escape-elve.
    public static func helperScript(pid: Int32, sourceApp: String, targetApp: String, mountPoint: String,
                                    scriptDirectory: String, downloadDirectory: String, logFile: String,
                                    token: String = UUID().uuidString) -> String {
        let target = URL(fileURLWithPath: targetApp)
        let parent = target.deletingLastPathComponent().path
        let base = target.lastPathComponent
        let staged = (parent as NSString).appendingPathComponent(".\(base).update-\(token)")
        let old = (parent as NSString).appendingPathComponent(".\(base).old-\(token)")
        return """
        #!/bin/bash
        # MacVPN update helper (generated by the app). Waits for the app to quit, replaces it, relaunches it.
        # Its log (update.log) is a diagnostic file and stays English.
        set -u
        trap '' HUP
        export PATH='/usr/bin:/bin:/usr/sbin:/sbin'
        APP_PID=\(pid)
        SRC=\(quote(sourceApp))
        DEST=\(quote(targetApp))
        STAGED=\(quote(staged))
        OLD=\(quote(old))
        MOUNT=\(quote(mountPoint))
        SELF_DIR=\(quote(scriptDirectory))
        DOWNLOAD_DIR=\(quote(downloadDirectory))
        LOG=\(quote(logFile))
        exec >>"$LOG" 2>&1
        echo "=== $(date '+%Y-%m-%d %H:%M:%S') update: $SRC -> $DEST ==="

        finish() {
          /usr/bin/hdiutil detach "$MOUNT" -quiet || /usr/bin/hdiutil detach "$MOUNT" -force -quiet || true
          /bin/rm -rf "$DOWNLOAD_DIR"
          /bin/rm -rf "$SELF_DIR"
        }

        # A régi app visszaállítása (ha a cél szabad). Sikertelenség naplózva; ilyenkor nem indítunk semmit.
        restore() {
          if [ -e "$OLD" ]; then
            if [ ! -e "$DEST" ] && /bin/mv "$OLD" "$DEST"; then
              echo "old app restored"
            else
              echo "restore failed: the old app was left here: $OLD"
              return 1
            fi
          fi
          return 0
        }

        # Az app kilépésére várunk (legfeljebb 30 mp).
        waited=0
        while /bin/kill -0 "$APP_PID" 2>/dev/null; do
          if [ "$waited" -ge 60 ]; then
            echo "the app did not quit within 30 s, update cancelled"
            finish
            exit 1
          fi
          /bin/sleep 0.5
          waited=$((waited + 1))
        done

        /bin/rm -rf "$STAGED"
        if ! /usr/bin/ditto "$SRC" "$STAGED"; then
          echo "copy (ditto) failed"
          /bin/rm -rf "$STAGED"
          finish
          /usr/bin/open "$DEST"
          exit 1
        fi
        if [ -e "$DEST" ] && ! /bin/mv "$DEST" "$OLD"; then
          echo "cannot rename the old app"
          /bin/rm -rf "$STAGED"
          finish
          /usr/bin/open "$DEST"
          exit 1
        fi
        if [ -e "$DEST" ]; then
          echo "the target still exists after the rename, update cancelled"
          /bin/rm -rf "$STAGED"
          restore
          finish
          exit 1
        fi
        if ! /bin/mv "$STAGED" "$DEST"; then
          echo "cannot move the new app into place, restoring"
          /bin/rm -rf "$STAGED"
          restore && /usr/bin/open "$DEST"
          finish
          exit 1
        fi
        /bin/rm -rf "$OLD"
        /usr/bin/xattr -dr com.apple.quarantine "$DEST" || true
        finish
        /usr/bin/open "$DEST"
        echo "done"

        """
    }

    /// Friss 0700-as könyvtár, benne a script (O_EXCL, O_NOFOLLOW, 0700). A könyvtárat a script törli.
    public static func writeHelper(_ makeScript: (_ directory: URL) -> String) throws -> URL {
        let dir = try RootInstaller.makePrivateTempDirectory(prefix: "macvpn-update")
        do {
            return try RootInstaller.writeScript(makeScript(dir), in: dir, name: "update.sh")
        } catch {
            try? FileManager.default.removeItem(at: dir)
            throw error
        }
    }

    /// Kettős fork: a külső bash a scriptet `nohup` alatt háttérbe teszi, `disown`-olja, és azonnal kilép.
    /// A script útvonala külön argumentum (`$1`), nem kerül a parancssor szövegébe.
    public static func helperLaunchArguments(script: URL) -> [String] {
        ["-c", "/usr/bin/nohup /bin/bash \"$1\" >/dev/null 2>&1 </dev/null & disown", "macvpn-update", script.path]
    }

    /// Leválasztva indítja a scriptet (az app kilépése után is fut, nem az app gyereke marad).
    public static func launchHelper(_ script: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = helperLaunchArguments(script: script)
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { throw UpdateError.helperFailed(error.localizedDescription) }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw UpdateError.helperFailed(L10n.tr("exit code: %d", process.terminationStatus)) }
    }
}
