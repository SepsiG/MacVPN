import Foundation

public enum RootInstaller {
    public struct InstallError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    public static func installScript(sourceDir: URL, user: String) throws -> String {
        guard user.range(of: "^[A-Za-z_][A-Za-z0-9_.-]*$", options: .regularExpression) != nil else {
            throw InstallError(message: L10n.tr("Invalid user name: %@", user))
        }
        let src = { (name: String) in shellQuote(sourceDir.appendingPathComponent(name).path) }
        let dir = MvpnClient.installDir
        return """
        #!/bin/bash
        set -euo pipefail
        install -d -o root -g wheel -m 755 \(dir)
        install -o root -g wheel -m 755 \(src("mvpn")) \(dir)/mvpn
        install -o root -g wheel -m 755 \(src("ovpn-dns")) \(dir)/ovpn-dns
        install -o root -g wheel -m 755 \(src("mvpn-validate")) \(dir)/mvpn-validate
        install -o root -g wheel -m 644 \(src("VERSION")) \(dir)/VERSION
        install -d -o root -g wheel -m 755 \(MvpnClient.logDir)
        install -d -o root -g wheel -m 700 /var/run/macvpn
        TMP=$(mktemp)
        printf '%s\\n' '\(user) ALL=(root) NOPASSWD: \(dir)/mvpn' > "$TMP"
        visudo -c -f "$TMP"
        install -o root -g wheel -m 440 "$TMP" /etc/sudoers.d/macvpn
        rm -f "$TMP"

        """
    }

    public static func appleScript(scriptPath: String) -> String {
        let escaped = scriptPath.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        return "do shell script \"/bin/bash \" & quoted form of \"\(escaped)\" with administrator privileges"
    }

    /// Friss, csak a felhasználó által elérhető (0700) könyvtár, `mkdtemp(3)`-mal (atomikus, kiszámíthatatlan név).
    static func makePrivateTempDirectory(prefix: String = "macvpn-install",
                                         in base: URL = FileManager.default.temporaryDirectory) throws -> URL {
        let template = base.appendingPathComponent("\(prefix).XXXXXX").path
        var buffer = Array(template.utf8CString)
        guard let result = mkdtemp(&buffer) else {
            throw InstallError(message: L10n.tr("Cannot create a temporary directory"))
        }
        let path = String(cString: result)
        guard chmod(path, 0o700) == 0 else {
            try? FileManager.default.removeItem(atPath: path)
            throw InstallError(message: L10n.tr("Cannot set the permissions of the temporary directory"))
        }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    /// A telepítő scriptet 0700-as jogosultsággal, kizárólagos létrehozással (O_EXCL, symlinket nem követ) írja ki.
    static func writeScript(_ script: String, in dir: URL, name: String = "install.sh") throws -> URL {
        let url = dir.appendingPathComponent(name)
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o700)
        guard fd >= 0 else { throw InstallError(message: L10n.tr("Cannot write the installer script")) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: Data(script.utf8))
        try handle.close()
        guard chmod(url.path, 0o700) == 0 else { throw InstallError(message: L10n.tr("Cannot set the permissions of the script")) }
        return url
    }

    /// Egy admin jelszó-bekéréssel telepíti a root scripteket és a sudoers szabályt.
    public static func install(sourceDir: URL, user: String = NSUserName(), runner: CommandRunner) async throws {
        try await runPrivileged(installScript(sourceDir: sourceDir, user: user), runner: runner,
                                cancelled: L10n.tr("Installation cancelled"), failure: L10n.tr("Installation error"))
    }

    /// Az eltávolító script. Előbb minden futó kapcsolatot bont (`/var/run/macvpn/<uuid>/kind` alapján, az uuid és
    /// a típus ellenőrzése után), majd törli a root réteget. A felhasználó a naplófájl tulajdonosa miatt kell
    /// (`mvpn` a `SUDO_USER`-ből olvassa; az osascript admin futás ezt nem állítja be).
    public static func uninstallScript(user: String) throws -> String {
        guard user.range(of: "^[A-Za-z_][A-Za-z0-9_.-]*$", options: .regularExpression) != nil else {
            throw InstallError(message: L10n.tr("Invalid user name: %@", user))
        }
        let dir = MvpnClient.installDir
        return """
        #!/bin/bash
        set -uo pipefail
        MVPN=\(shellQuote(MvpnClient.executable))
        RUN_BASE=/var/run/macvpn
        FAILED=""
        if [ -x "$MVPN" ] && [ -d "$RUN_BASE" ] && [ ! -L "$RUN_BASE" ]; then
          for d in "$RUN_BASE"/*/; do
            d="${d%/}"
            [ -L "$d" ] && continue
            id=$(/usr/bin/basename "$d")
            [[ "$id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || continue
            [ -f "$d/kind" ] && [ ! -L "$d/kind" ] || continue
            kind=$(/usr/bin/head -c 32 "$d/kind")
            case "$kind" in openvpn|wireguard|strongswan) ;; *) continue ;; esac
            if ! SUDO_USER=\(shellQuote(user)) "$MVPN" down "$kind" "$id" --lang \(AppLanguage.current.rawValue) </dev/null; then
              FAILED="$FAILED $id"
            fi
          done
        fi
        # Ha bármelyik kapcsolat nem bontható, a root réteg marad (a mvpn kell a későbbi bontáshoz).
        if [ -n "$FAILED" ]; then
          echo \(shellQuote(disconnectFailureMarker))"$FAILED" >&2
          exit 1
        fi
        /bin/rm -f /etc/sudoers.d/macvpn
        /bin/rm -rf \(dir) /var/run/macvpn \(MvpnClient.logDir)

        """
    }

    /// Az eltávolító script ezzel a (lokalizált) előtaggal jelzi a nem bontható kapcsolatokat a stderr-en.
    static var disconnectFailureMarker: String { L10n.tr("Could not disconnect:") }

    /// Egy admin jelszó-bekéréssel bontja a futó kapcsolatokat és eltávolítja a root réteget.
    public static func uninstall(user: String = NSUserName(), runner: CommandRunner) async throws {
        let failure = L10n.tr("Uninstall error")
        do {
            try await runPrivileged(uninstallScript(user: user), runner: runner,
                                    cancelled: L10n.tr("Uninstall cancelled"), failure: failure)
        } catch let error as InstallError where error.message.contains(disconnectFailureMarker) {
            let detail = error.message.replacingOccurrences(of: failure + ": ", with: "")
            throw InstallError(message: L10n.tr("A connection could not be disconnected, uninstall cancelled.\n\n%@", detail))
        }
    }

    /// A scriptet friss 0700-as könyvtárba írja, egy `osascript … with administrator privileges` hívással futtatja,
    /// majd a könyvtárat törli.
    static func runPrivileged(_ script: String, runner: CommandRunner, cancelled: String, failure: String) async throws {
        let dir = try makePrivateTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = try writeScript(script, in: dir)
        let result = try await runner.run("/usr/bin/osascript", ["-e", appleScript(scriptPath: url.path)], stdin: nil)
        guard result.exitCode == 0 else {
            let msg = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw InstallError(message: msg.contains("-128") ? cancelled : "\(failure): \(msg)")
        }
    }
}
