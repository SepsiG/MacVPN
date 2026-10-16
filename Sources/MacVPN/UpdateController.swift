import SwiftUI
import AppKit
import MacVPNCore

/// Frissítés-ellenőrzés (induláskor és 24 óránként) és a telepítés lépései.
/// Ki van kapcsolva, ha az `Info.plist`-ben nincs `MacVPNUpdateRepo` (pl. `swift run`).
@MainActor
final class UpdateController: ObservableObject {
    static let autoCheckKey = "autoCheckUpdates"
    static let lastCheckKey = "lastUpdateCheck"
    static let checkInterval: TimeInterval = 24 * 60 * 60

    let repo: String?
    let currentVersion: String
    private let http: HTTPClient
    private let runner: CommandRunner
    private var schedulerTask: Task<Void, Never>?

    @Published private(set) var available: Release?
    @Published private(set) var checking = false
    @Published private(set) var lastError: String?
    /// Telepítés közben az aktuális lépés (nil = nem fut).
    @Published private(set) var installStage: String?
    @Published var installError: String?
    @Published var autoCheck: Bool {
        didSet { UserDefaults.standard.set(autoCheck, forKey: Self.autoCheckKey) }
    }

    var enabled: Bool { repo != nil }

    init(runner: CommandRunner, http: HTTPClient = URLSessionHTTPClient()) {
        let info = Bundle.main.infoDictionary
        repo = Bundle.main.bundleIdentifier != nil ? UpdateChecker.repo(fromInfo: info) : nil
        currentVersion = info?["CFBundleShortVersionString"] as? String ?? "0.0.0"
        self.http = http
        self.runner = runner
        UserDefaults.standard.register(defaults: [Self.autoCheckKey: true])
        autoCheck = UserDefaults.standard.bool(forKey: Self.autoCheckKey)
    }

    /// Induláskor egyszer; óránként ébred, és ha az utolsó ellenőrzés óta 24 óra eltelt, ellenőriz.
    func startScheduler() {
        guard enabled, schedulerTask == nil else { return }
        schedulerTask = Task { [weak self] in
            var first = true
            while !Task.isCancelled {
                guard let self else { return }
                if self.autoCheck {
                    let last = UserDefaults.standard.object(forKey: Self.lastCheckKey) as? Date ?? .distantPast
                    if first || Date().timeIntervalSince(last) >= Self.checkInterval {
                        _ = await self.check()
                    }
                }
                first = false
                try? await Task.sleep(for: .seconds(3600))
            }
        }
    }

    /// True, ha van újabb verzió. A hibát a `lastError` őrzi.
    @discardableResult
    func check() async -> Bool {
        guard let repo, !checking else { return available != nil }
        checking = true
        defer { checking = false }
        do {
            let release = try await UpdateChecker(repo: repo, http: http).latestRelease()
            UserDefaults.standard.set(Date(), forKey: Self.lastCheckKey)
            lastError = nil
            available = release.isNewer(than: currentVersion) ? release : nil
        } catch {
            lastError = error.localizedDescription
        }
        return available != nil
    }

    /// „Frissítések keresése most": ha nincs újabb, ezt (vagy a hibát) egy ablakban jelzi.
    func checkNow() async -> Bool {
        let found = await check()
        guard !found else { return true }
        let alert = NSAlert()
        if let lastError {
            alert.messageText = String(localized: "The update check failed")
            alert.informativeText = lastError
            alert.alertStyle = .warning
        } else {
            alert.messageText = String(localized: "MacVPN is up to date")
            alert.informativeText = String(localized: "The installed version (\(currentVersion)) is the latest.")
        }
        alert.addButton(withTitle: String(localized: "OK"))
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        return false
    }

    /// Letöltés → SHA-256 → csatolás → app ellenőrzés → segédscript → kilépés (a kilépési kérdések után).
    func install(confirmQuit: () async -> Bool, terminate: () -> Void) async {
        guard let release = available, installStage == nil else { return }
        installError = nil
        let installer = UpdateInstaller(http: http, runner: runner)
        var mountPoint: String?
        var helperDir: URL?
        var download: VerifiedDownload?
        do {
            installStage = String(localized: "Checking the install location…")
            let target = try UpdateInstaller.checkInstallTarget(Bundle.main.bundleURL)
            installStage = String(localized: "Downloading…")
            let verified = try await installer.downloadVerified(release)
            download = verified
            installStage = String(localized: "Mounting the disk image…")
            let mp = try await installer.mount(verified)
            mountPoint = mp
            installStage = String(localized: "Verifying the app…")
            let source = URL(fileURLWithPath: mp).appendingPathComponent(UpdateInstaller.appName)
            try await installer.verifyApp(at: source, expectedVersion: release.version)
            installStage = String(localized: "Preparing the installation…")
            let log = installer.cacheDirectory.appendingPathComponent("update.log").path
            let script = try UpdateInstaller.writeHelper { dir in
                UpdateInstaller.helperScript(pid: ProcessInfo.processInfo.processIdentifier, sourceApp: source.path,
                                             targetApp: target.path, mountPoint: mp, scriptDirectory: dir.path,
                                             downloadDirectory: verified.directory.path, logFile: log)
            }
            helperDir = script.deletingLastPathComponent()
            installStage = String(localized: "Quitting and restarting…")
            guard await confirmQuit() else {
                try? FileManager.default.removeItem(at: script.deletingLastPathComponent())
                await installer.detach(mp)
                try? FileManager.default.removeItem(at: verified.directory)
                installStage = nil
                return
            }
            try UpdateInstaller.launchHelper(script)
            terminate()
        } catch {
            if let helperDir { try? FileManager.default.removeItem(at: helperDir) }
            if let mountPoint { await installer.detach(mountPoint) }
            if let download { try? FileManager.default.removeItem(at: download.directory) }
            installError = error.localizedDescription
            installStage = nil
        }
    }
}
