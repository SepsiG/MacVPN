import CryptoKit
import Foundation

public enum RootInstaller {
    public struct InstallError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    /// A telepítendő root fájlok (a bundle `Resources/root` mappájából).
    public static let rootFiles = ["mvpn", "ovpn-dns", "mvpn-validate", "VERSION"]

    /// A root fájlok SHA-256-ja (kisbetűs hex), közvetlenül a telepítő script előállítása előtt számolva.
    public static func fileHashes(in sourceDir: URL) throws -> [String: String] {
        var hashes: [String: String] = [:]
        for name in rootFiles {
            let path = sourceDir.appendingPathComponent(name).path
            guard let data = FileManager.default.contents(atPath: path) else {
                throw InstallError(message: L10n.tr("Cannot read the file: %@", path))
            }
            hashes[name] = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        return hashes
    }

    /// A sudoers fájl sorai. A `mvpn`-re vonatkozó Defaults: tiszta környezet (`env_reset`), a felhasználói változók
    /// (LANG, LC_* stb.) közül semmi nem marad meg (`!env_keep`), és env_reset nélkül is törlődnének (`env_delete`).
    public static func sudoersLines(user: String) -> [String] {
        let mvpn = MvpnClient.executable
        return [
            "\(user) ALL=(root) NOPASSWD: \(mvpn)",
            "Defaults!\(mvpn) env_reset, !env_keep",
            "Defaults!\(mvpn) env_delete += \"LANG LANGUAGE LC_* CHARSET\"",
        ]
    }

    /// A telepítő script (rootként fut, `osascript … with administrator privileges`).
    /// 1. `/usr/local`, `/usr/local/libexec`, `/usr/local/libexec/macvpn`: symlink vagy nem könyvtár → megszakítás; hiányzó →
    ///    root tulajdonnal létrejön. Ha a két szülő nem root tulajdonú vagy group/world írható → megszakítás kézi javítási
    ///    útmutatóval (nem írjuk át: Intel Macen a Homebrew-é lehet); a saját `macvpn` könyvtárat `chown root:wheel` + `chmod go-w` javítja.
    /// 2. A forrásfájlok egy root tulajdonú átmeneti könyvtárba másolódnak, és csak akkor települnek (onnan), ha a SHA-256-juk
    ///    egyezik a `hashes`-ben átadottal (az app közvetlenül a script írása előtt számolja). Így a felhasználó által írható
    ///    forrás a script megírása és a root futás között nem cserélhető ki észrevétlenül.
    /// 3. sudoers: `visudo -c -f` ellenőrzés után a helyére kerül.
    public static func installScript(sourceDir: URL, user: String, hashes: [String: String]) throws -> String {
        guard user.range(of: "^[A-Za-z_][A-Za-z0-9_.-]*$", options: .regularExpression) != nil else {
            throw InstallError(message: L10n.tr("Invalid user name: %@", user))
        }
        var stageLines: [String] = []
        for name in rootFiles {
            guard let hash = hashes[name], hash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw InstallError(message: L10n.tr("Integrity check failed, installation cancelled:") + " " + name)
            }
            stageLines.append("stage \(shellQuote(sourceDir.appendingPathComponent(name).path)) \(name) \(hash)")
        }
        let dir = MvpnClient.installDir
        // A szülőkönyvtárakat nem írjuk át (Intel Macen a /usr/local/libexec lehet a Homebrew-é): ha nem root tulajdonúak
        // vagy group/world írhatók, a telepítés megszakad, kézi javítási útmutatóval. Csak a saját könyvtárunkat javítjuk.
        let parentChecks = ["/usr/local", "/usr/local/libexec"].map { d in
            "check_dir \(d) \(shellQuote(L10n.tr("Installation cancelled: %@ is not owned by root or is writable by other users, so anything running as that user could replace the MacVPN root scripts. Fix it in Terminal, then try again: sudo chown root:wheel %@ && sudo chmod go-w %@ (on Intel Macs this may affect Homebrew).", d, d, d)))"
        }.joined(separator: "\n")
        let sudoers = sudoersLines(user: user).map(shellQuote).joined(separator: " ")
        return """
        #!/bin/bash
        set -euo pipefail
        export PATH=/usr/bin:/bin:/usr/sbin:/sbin
        export LC_ALL=C
        DIR=\(dir)
        TMP=""
        STAGE=""
        trap 'rm -rf "$STAGE" "$TMP"' EXIT
        unsafe_dir() { [ "$(stat -f %u "$1")" != 0 ] || [ $(( 0$(stat -f %Lp "$1") & 022 )) != 0 ]; }
        check_dir() { # <könyvtár> <üzenet, ha nem root tulajdonú vagy group/world írható szülő>
          if [ -L "$1" ] || { [ -e "$1" ] && [ ! -d "$1" ]; }; then
            echo \(shellQuote(L10n.tr("Unsafe directory, installation cancelled:"))) "$1" >&2
            exit 1
          fi
          if [ ! -d "$1" ]; then
            install -d -o root -g wheel -m 755 "$1"
          elif unsafe_dir "$1"; then
            if [ -z "$2" ]; then
              chown root:wheel "$1"
              chmod go-w "$1"
            else
              echo "$2" >&2
              exit 1
            fi
          fi
        }
        \(parentChecks)
        check_dir "$DIR" ""
        STAGE=$(mktemp -d /var/run/macvpn-install.XXXXXX)
        stage() {
          cp -- "$1" "$STAGE/$2"
          if [ "$(shasum -a 256 "$STAGE/$2" | awk '{print $1}')" != "$3" ]; then
            echo \(shellQuote(L10n.tr("Integrity check failed, installation cancelled:"))) "$2" >&2
            exit 1
          fi
        }
        \(stageLines.joined(separator: "\n"))
        install -o root -g wheel -m 755 "$STAGE/mvpn" "$DIR/mvpn"
        install -o root -g wheel -m 755 "$STAGE/ovpn-dns" "$DIR/ovpn-dns"
        install -o root -g wheel -m 755 "$STAGE/mvpn-validate" "$DIR/mvpn-validate"
        install -o root -g wheel -m 644 "$STAGE/VERSION" "$DIR/VERSION"
        install -d -o root -g wheel -m 755 \(MvpnClient.logDir)
        install -d -o root -g wheel -m 700 /var/run/macvpn
        TMP=$(mktemp)
        printf '%s\\n' \(sudoers) > "$TMP"
        visudo -c -f "$TMP"
        install -o root -g wheel -m 440 "$TMP" /etc/sudoers.d/macvpn

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
        // A mkdtemp visszatérési pointere csak a hívás alatt érvényes (inout-to-pointer),
        // ezért az elkészült útvonalat magából a bufferből olvassuk ki.
        let ok = buffer.withUnsafeMutableBufferPointer { mkdtemp($0.baseAddress!) != nil }
        guard ok else {
            let reason = String(cString: strerror(errno))
            throw InstallError(message: L10n.tr("Cannot create a temporary directory") + " (\(template): \(reason))")
        }
        let path = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        guard chmod(path, 0o700) == 0 else {
            let reason = String(cString: strerror(errno))
            try? FileManager.default.removeItem(atPath: path)
            throw InstallError(message: L10n.tr("Cannot set the permissions of the temporary directory") + " (\(path): \(reason))")
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
        let hashes = try fileHashes(in: sourceDir)
        try await runPrivileged(installScript(sourceDir: sourceDir, user: user, hashes: hashes), runner: runner,
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
        PPP_OPTIONS=/etc/ppp/options
        PPP_MARKER=\(dir)/.created-ppp-options
        FAILED=""
        if [ -x "$MVPN" ] && [ -d "$RUN_BASE" ] && [ ! -L "$RUN_BASE" ]; then
          for d in "$RUN_BASE"/*/; do
            d="${d%/}"
            [ -L "$d" ] && continue
            id=$(/usr/bin/basename "$d")
            [[ "$id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || continue
            [ -f "$d/kind" ] && [ ! -L "$d/kind" ] || continue
            kind=$(/usr/bin/head -c 32 "$d/kind")
            case "$kind" in openvpn|wireguard|strongswan|sstp) ;; *) continue ;; esac
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
        # A /etc/ppp/options-t csak akkor töröljük, ha a mvpn hozta létre (jelölő), és azóta is üres.
        if [ -f "$PPP_MARKER" ] && [ ! -L "$PPP_MARKER" ] && [ -f "$PPP_OPTIONS" ] && [ ! -L "$PPP_OPTIONS" ] && [ ! -s "$PPP_OPTIONS" ]; then
          /bin/rm -f "$PPP_OPTIONS"
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
