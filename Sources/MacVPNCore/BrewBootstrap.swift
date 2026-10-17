import Foundation

/// Environment for `brew install`: only what Homebrew needs, so nothing from the app's environment (for example a
/// `HOMEBREW_*` override pointing at another tap or remote, or `DYLD_*` / `RUBYOPT`) reaches it.
public enum BrewEnvironment {
    static let passed = ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG"]

    public static func make(from environment: [String: String], brewPrefix: String) -> [String: String] {
        var env: [String: String] = [:]
        for key in passed { if let value = environment[key] { env[key] = value } }
        env["PATH"] = "\(brewPrefix)/bin:\(brewPrefix)/sbin:/usr/bin:/bin:/usr/sbin:/sbin"
        env["HOMEBREW_NO_ENV_HINTS"] = "1"
        return env
    }
}

/// The Terminal `.command` script that runs the official Homebrew installer.
public enum BrewBootstrap {
    public static let installerURL = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
    static let directoryPrefix = "macvpn-brew."

    static func quote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    /// The installer is downloaded first; if `curl` fails the script stops with `failed` instead of running an empty
    /// or partial script. The script deletes its own directory when it exits.
    public static func script(start: String, done: String, failed: String, cleanupDirectory: String) -> String {
        """
        #!/bin/bash
        trap \(quote("rm -rf -- " + quote(cleanupDirectory))) EXIT
        echo \(quote(start))
        s=$(/usr/bin/curl -fsSL \(installerURL)) || { echo \(quote(failed)); exit 1; }
        /bin/bash -c "$s"
        echo; echo \(quote(done))

        """
    }

    public struct WriteError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// Writes the script (built from its directory's path) into a fresh `mkdtemp` 0700 directory in `parent`,
    /// created with O_EXCL | O_NOFOLLOW and mode 0700. Every error is thrown.
    public static func write(script: (_ directory: String) -> String, in parent: URL) throws -> URL {
        var template = Array(parent.appendingPathComponent(directoryPrefix + "XXXXXXXX").path.utf8CString)
        guard let created = mkdtemp(&template) else {
            throw WriteError(message: L10n.tr("Cannot create a temporary directory"))
        }
        let dir = URL(fileURLWithPath: String(cString: created), isDirectory: true)
        let url = dir.appendingPathComponent("install-homebrew.command")
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o700)
        guard fd >= 0 else {
            try? FileManager.default.removeItem(at: dir)
            throw WriteError(message: L10n.tr("Cannot write: %@", url.path))
        }
        do {
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            try handle.write(contentsOf: Data(script(dir.path).utf8))
            try handle.close()
            // A umask szűkíthette: legyen pontosan 0700 (futtatható a Terminálnak).
            guard chmod(url.path, 0o700) == 0 else { throw WriteError(message: L10n.tr("Cannot set the permissions: %@", url.path)) }
        } catch {
            try? FileManager.default.removeItem(at: dir)
            throw error
        }
        return url
    }
}
