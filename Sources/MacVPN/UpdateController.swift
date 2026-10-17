import SwiftUI
import AppKit
import MacVPNCore

/// Frissítés-ellenőrzés (induláskor és 24 óránként) és a telepítés lépései.
/// Ki van kapcsolva, ha az `Info.plist`-ben nincs érvényes `MacVPNUpdateRepoID` és `MacVPNUpdateRepo` (pl. `swift run`).
@MainActor
final class UpdateController: ObservableObject {
    static let autoCheckKey = "autoCheckUpdates"
    static let delayKey = "delayUpdates24h"
    static let lastCheckKey = "lastUpdateCheck"
    static let noticedHelperRunKey = "noticedUpdateHelperRun"
    static let checkInterval: TimeInterval = 24 * 60 * 60

    /// A Súgó linkjeihez és az asset útvonalak ellenőrzéséhez (`MacVPNUpdateRepo`).
    let repo: String?
    /// A lekérdezéshez (`MacVPNUpdateRepoID`). Nélküle nincs frissítés.
    let repoID: Int64?
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
    /// Opcionális: csak a legalább 24 órája közzétett kiadást ajánlja fel (alapból ki).
    @Published var delayUpdates: Bool {
        didSet {
            UserDefaults.standard.set(delayUpdates, forKey: Self.delayKey)
            if let release = available ?? deferred { apply(release) }
        }
    }
    /// Újabb kiadás, amely a késleltetés miatt még nincs felajánlva.
    @Published private(set) var deferred: Release?

    var enabled: Bool { repo != nil && repoID != nil }

    init(runner: CommandRunner, http: HTTPClient = URLSessionHTTPClient()) {
        let info = Bundle.main.infoDictionary
        let isApp = Bundle.main.bundleIdentifier != nil
        let source = isApp ? UpdateChecker.source(fromInfo: info) : nil
        repo = isApp ? UpdateChecker.repo(fromInfo: info) : nil
        repoID = source?.id
        currentVersion = info?["CFBundleShortVersionString"] as? String ?? "0.0.0"
        self.http = http
        self.runner = runner
        UserDefaults.standard.register(defaults: [Self.autoCheckKey: true, Self.delayKey: false])
        autoCheck = UserDefaults.standard.bool(forKey: Self.autoCheckKey)
        delayUpdates = UserDefaults.standard.bool(forKey: Self.delayKey)
    }

    private func apply(_ release: Release) {
        switch UpdateChecker.offer(release, currentVersion: currentVersion, delayed: delayUpdates) {
        case .offer: available = release; deferred = nil
        case .tooRecent: available = nil; deferred = release
        case .upToDate: available = nil; deferred = nil
        }
    }

    /// Induláskor egyszer: egy megszakadt csere maradványainak törlése és az előző frissítés hibájának jelzése,
    /// majd az ütemező: óránként ébred, és ha az utolsó ellenőrzés óta 24 óra eltelt, ellenőriz.
    func startScheduler() {
        launchHousekeeping()
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
        guard let repo, let repoID, !checking else { return available != nil }
        checking = true
        defer { checking = false }
        do {
            let release = try await UpdateChecker(repoID: repoID, repo: repo, http: http).latestRelease()
            UserDefaults.standard.set(Date(), forKey: Self.lastCheckKey)
            lastError = nil
            apply(release)
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
        } else if let deferred {
            alert.messageText = String(localized: "MacVPN is up to date")
            alert.informativeText = String(localized: "Version \(deferred.version) was published less than 24 hours ago. It will be offered later, as \"Only Offer Updates Published at Least 24 Hours Ago\" is on.")
        } else {
            alert.messageText = String(localized: "MacVPN is up to date")
            alert.informativeText = String(localized: "The installed version (\(currentVersion)) is the latest.")
        }
        alert.addButton(withTitle: String(localized: "OK"))
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        return false
    }

    private var housekeepingDone = false

    /// Csak valódi app bundle-ből (nem `swift run`), egyszer.
    private func launchHousekeeping() {
        guard !housekeepingDone, Bundle.main.bundleIdentifier != nil else { return }
        housekeepingDone = true
        UpdateInstaller.sweepLeftovers(nextTo: Bundle.main.bundleURL.resolvingSymlinksInPath())
        guard let notice = previousUpdateNotice() else { return }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            let alert = NSAlert()
            alert.messageText = String(localized: "The previous update did not complete")
            alert.informativeText = notice
            alert.alertStyle = .warning
            alert.addButton(withTitle: String(localized: "OK"))
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }

    /// Az előző frissítés kimenetele a segédscript naplójából; egy futásról csak egyszer (és csak 14 napon belül) szól.
    private func previousUpdateNotice() -> String? {
        let log = UpdateInstaller.defaultCacheDirectory.appendingPathComponent("update.log")
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: log.path),
              let modified = attrs[.modificationDate] as? Date, Date().timeIntervalSince(modified) < 14 * 24 * 3600,
              (attrs[.size] as? Int ?? 0) < 1 << 20,
              let text = try? String(contentsOf: log, encoding: .utf8),
              let last = UpdateInstaller.lastHelperOutcome(log: text),
              UserDefaults.standard.string(forKey: Self.noticedHelperRunKey) != last.run else { return nil }
        let path = log.path.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
        switch last.outcome {
        case .succeeded, .unknown:
            return nil
        case .timedOut:
            UserDefaults.standard.set(last.run, forKey: Self.noticedHelperRunKey)
            return String(localized: "The update was cancelled because MacVPN did not quit within 30 seconds. The installed version was not changed; you can try again from the menu.")
        case .failed(let line):
            UserDefaults.standard.set(last.run, forKey: Self.noticedHelperRunKey)
            return String(localized: "The update stopped with an error (\(line)). The installed version was kept. Details: \(path)")
        }
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
