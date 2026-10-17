import SwiftUI
import AppKit
import Combine
import UserNotifications
import MacVPNCore

@MainActor
final class AppModel: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    let manager: ConnectionManager
    let store: ConnectionStore
    let secrets: SecretStore
    let runner: CommandRunner
    @Published var setup = SetupReport.unknown
    /// Csak olvasásra; váltani a `select(_:)`-tel kell (nem mentett változások védelme).
    @Published private(set) var selectedID: String?
    /// Egyszer használatos kérés: ennek a kapcsolatnak a részletező nézete a Napló fülre vált, majd törli.
    @Published var logTabRequest: UUID?
    /// Egyszer használatos kérés: a Beállítások fülre vált (pl. sikertelen mentés után).
    @Published var settingsTabRequest: UUID?
    /// Nem mentett változás miatt függőben lévő művelet (a kezelő ablak kérdez rá).
    @Published var pendingAction: PendingAction?
    @Published private(set) var dirtyIDs: Set<UUID> = []
    /// Mentés-kezelők: nil = sikerült, egyébként a hiba szövege.
    private var saveHandlers: [UUID: () -> String?] = [:]
    /// A Homebrew telepítő az ablak bezárását is túléli.
    let brew = BrewInstaller()
    /// Frissítés-ellenőrzés és telepítés (GitHub Releases).
    let updates: UpdateController
    /// Indítás bejelentkezéskor (SMAppService.mainApp). Alapból ki, csak a kapcsolóra regisztrál.
    let loginItem: LoginItemController
    @Published var nativeLogs: [UUID: NativeLogCollector] = [:]
    /// A megnyitott, még nem telepített natív profilok (ideiglenes fájlok).
    let stagedProfiles = StagedProfiles()
    @Published var installError: String?

    /// Aktív (vagy folyamatban lévő) kapcsolat mellett 3 mp, egyébként 30 mp.
    static let activePollInterval: TimeInterval = 3
    static let idlePollInterval: TimeInterval = 30
    /// Natív debug naplógyűjtés felső korlátja.
    static let nativeLogMaxSeconds: TimeInterval = 60

    private var cancellables = Set<AnyCancellable>()
    private var pollTask: Task<Void, Never>?
    private var startTask: Task<Void, Never>?

    override init() {
        let store = ConnectionStore()
        let secrets = KeychainSecretStore()
        // Egyszeri áthelyezés a régi "macvpn" szolgáltatásból (idempotens, megszakítás után is biztonságos).
        secrets.migrateLegacyItems()
        let runner = ProcessCommandRunner()
        // `mvpn up` hosszabb, a gyakori status / scutil lekérdezések rövidebb időkorláttal futnak.
        let quickRunner = ProcessCommandRunner(timeout: RunnerTimeouts.quick)
        let mvpn = MvpnClient(runner: runner, upRunner: ProcessCommandRunner(timeout: RunnerTimeouts.up),
                              statusRunner: quickRunner)
        self.store = store
        self.secrets = secrets
        self.runner = runner
        self.updates = UpdateController(runner: runner)
        self.loginItem = LoginItemController(service: SMAppServiceLoginItem())
        self.manager = ConnectionManager(store: store, secrets: secrets,
                                         mvpn: mvpn, native: NativeVPNController(runner: quickRunner, driver: SystemConfigurationDriver()))
        super.init()
        manager.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &cancellables)
        brew.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &cancellables)
        updates.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &cancellables)
        loginItem.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &cancellables)
        // A telepítés végén akkor is újraellenőriz, ha a Rendszerállapot ablak közben bezárult.
        brew.$finishedCount.dropFirst().sink { [weak self] _ in
            Task { await self?.checkSetup() }
        }.store(in: &cancellables)
        manager.onEvent = { [weak self] event in self?.notify(event) }
        manager.onNativeServicesSeen = { [weak self] ids in self?.stagedProfiles.servicesSeen(ids) }
        // Az előző futásból maradt ideiglenes profilok, és a régi verziók által a kapcsolat-könyvtárba írt
        // profile.mobileconfig (benne jelszó és PSK) törlése.
        NativeProfileStaging.sweep(in: NativeProfileStaging.defaultParent)
        store.removeLegacyProfiles()
        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didWakeNotification)
            .sink { [weak self] _ in Task { await self?.manager.refresh() } }
            .store(in: &cancellables)
        Task { await self.start() }
    }

    // MARK: Indulás, polling

    /// Idempotens: többszöri hívás ugyanazt az indulást várja meg.
    func start() async {
        if startTask == nil { startTask = Task { await performStart() } }
        await startTask?.value
    }

    private func performStart() async {
        manager.reload()
        await checkSetup()
        if Bundle.main.bundleIdentifier != nil {
            let center = UNUserNotificationCenter.current()
            center.delegate = self
            _ = try? await center.requestAuthorization(options: [.alert, .sound])
        }
        updates.startScheduler()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.manager.refresh()
                // Másodpercenként újraszámolja az intervallumot: egy új csatlakozás (`.connecting` is aktív)
                // azonnal a gyors ütemre vált, nem kell kivárni a 30 mp-et.
                let started = Date()
                while !Task.isCancelled {
                    let interval = self.manager.hasActive ? Self.activePollInterval : Self.idlePollInterval
                    if Date().timeIntervalSince(started) >= interval { break }
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        }
    }

    var menuBarSymbol: String {
        if manager.hasFailure || manager.statusError != nil { return "exclamationmark.shield.fill" }
        if manager.hasActive { return "checkmark.shield.fill" }
        return "shield"
    }

    // MARK: Setup

    func checkSetup() async {
        setup = await SetupChecker(runner: runner, bundledRootDir: RootResources.directory).check()
    }

    func installRoot() async {
        installError = nil
        guard let dir = RootResources.directory else {
            installError = String(localized: "The root scripts were not found in the app")
            return
        }
        do { try await RootInstaller.install(sourceDir: dir, runner: runner) } catch {
            installError = error.localizedDescription
        }
        await checkSetup()
    }

    /// A Homebrew hivatalos telepítője a Terminálban. A script friss, privát ideiglenes könyvtárba kerül (O_EXCL),
    /// és leáll, ha a letöltés nem sikerül. Hiba esetén riasztás.
    func openBrewInstallInTerminal() {
        let start = String(localized: "Installing Homebrew (with the official installer)…")
        let done = String(localized: "Done. Go back to MacVPN and click Check Again.")
        let failed = String(localized: "Could not download the Homebrew installer. Check the internet connection, then try again.")
        do {
            let url = try BrewBootstrap.write(script: { dir in
                BrewBootstrap.script(start: start, done: done, failed: failed, cleanupDirectory: dir)
            }, in: FileManager.default.temporaryDirectory)
            NSWorkspace.shared.open(url)
        } catch {
            let alert = NSAlert()
            alert.messageText = String(localized: "Could not start the Homebrew installer")
            alert.informativeText = error.localizedDescription
            alert.alertStyle = .warning
            alert.addButton(withTitle: String(localized: "OK"))
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }

    // MARK: Indítás bejelentkezéskor

    /// A kapcsoló: regisztrál / leiratkozik, hiba esetén riasztásban mutatja a rendszer üzenetét.
    func setLaunchAtLogin(_ on: Bool) {
        do {
            try loginItem.setEnabled(on)
        } catch {
            let alert = NSAlert()
            alert.messageText = on ? String(localized: "Could not turn on launch at login")
                                   : String(localized: "Could not turn off launch at login")
            alert.informativeText = error.localizedDescription
            alert.alertStyle = .warning
            alert.addButton(withTitle: String(localized: "OK"))
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }

    // MARK: Súgó, eltávolítás

    /// A nyelvnek megfelelő felhasználói útmutató a GitHubon.
    func openUserGuide() {
        NSWorkspace.shared.open(UserGuide.url(repo: updates.repo ?? UpdateChecker.repo(fromInfo: Bundle.main.infoDictionary),
                                              preferredLanguages: Locale.preferredLanguages))
    }

    /// Megerősítés után bontja a kapcsolatokat, egy admin jelszóval eltávolítja a root réteget, és kérésre a
    /// felhasználói adatokat is törli. A végén jelzi, hogy a Homebrew csomagok megmaradtak.
    func uninstall() async {
        let alert = NSAlert()
        alert.messageText = String(localized: "Uninstall MacVPN")
        alert.informativeText = String(localized: """
        After you enter an admin password, these are deleted:
        • /usr/local/libexec/macvpn (root scripts)
        • /etc/sudoers.d/macvpn (sudoers rule)
        • /var/run/macvpn (runtime data)
        • /var/log/macvpn (connection logs)

        Active connections are disconnected first. Homebrew packages are kept.
        """)
        alert.alertStyle = .warning
        let checkbox = NSButton(checkboxWithTitle: String(localized: "Also delete user data (connections and Keychain passwords)"),
                                target: nil, action: nil)
        checkbox.toolTip = String(localized: "~/Library/Application Support/MacVPN and the MacVPN Keychain items")
        alert.accessoryView = checkbox
        alert.addButton(withTitle: String(localized: "Uninstall"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let removeUserData = checkbox.state == .on

        // A root kapcsolatokat az eltávolító script bontja; a natív (scutil) kapcsolatokat csak a sikeres admin lépés után.
        do {
            try await RootInstaller.uninstall(runner: runner)
        } catch {
            let fail = NSAlert()
            fail.messageText = String(localized: "Uninstall failed")
            fail.informativeText = error.localizedDescription
            fail.alertStyle = .warning
            fail.runModal()
            await checkSetup()
            return
        }
        for c in manager.connections where c.kind.isNative && manager.state(for: c.id.uuidString).isActive {
            await manager.disconnect(c)
        }
        pollTask?.cancel()
        let hadNative = manager.connections.contains { $0.kind.isNative }
        // Ne maradjon árva bejelentkezési elem.
        var loginItemLeft = false
        do { try loginItem.unregisterIfRegistered() } catch { loginItemLeft = true }
        if removeUserData {
            for c in manager.connections { secrets.deleteAll(for: c.id) }
            secrets.removeAll()
            discardUnsaved()
            let fm = FileManager.default
            try? ConnectionStore.removeApplicationSupportDirectory()
            try? fm.removeItem(at: UpdateInstaller.defaultCacheDirectory)
            if let id = Bundle.main.bundleIdentifier { UserDefaults.standard.removePersistentDomain(forName: id) }
        }
        let done = NSAlert()
        done.messageText = String(localized: "MacVPN has been uninstalled")
        var info = String(localized: "You can now drag the app to the Trash. The Homebrew packages were kept (brew uninstall openvpn wireguard-tools strongswan sstp-client).")
        if hadNative {
            info += "\n\n" + String(localized: "You can remove the L2TP / Cisco profiles in System Settings → General → Device Management.")
        }
        if loginItemLeft {
            info += "\n\n" + String(localized: "MacVPN could not be removed from the login items. You can remove it in System Settings → General → Login Items.")
        }
        done.informativeText = info
        done.addButton(withTitle: String(localized: "Quit MacVPN"))
        NSApp.activate(ignoringOtherApps: true)
        done.runModal()
        // A root réteg már nincs meg: csak a nem mentett változásokra kérdezünk rá.
        if confirmUnsaved() { terminateConfirmed() }
    }

    // MARK: Kijelölés, nem mentett változások

    enum PendingAction: Equatable {
        case select(String?)
        case closeWindow
    }

    var hasUnsavedChanges: Bool { !dirtyIDs.isEmpty }

    /// Kijelölés váltása. Nem mentett változásnál előbb rákérdez (`pendingAction`).
    func select(_ id: String?) {
        guard id != selectedID else { return }
        if hasUnsavedChanges {
            pendingAction = .select(id)
        } else {
            selectedID = id
        }
    }

    /// A szerkesztők jelentik a piszkos állapotot; `save` true-t ad, ha a mentés sikerült.
    func setUnsaved(_ id: UUID, dirty: Bool, save: (() -> String?)? = nil) {
        if dirty {
            dirtyIDs.insert(id)
            if let save { saveHandlers[id] = save }
        } else {
            dirtyIDs.remove(id)
            saveHandlers[id] = nil
        }
    }

    /// Minden nem mentett szerkesztő mentése. False, ha valamelyik nem menthető (pl. validációs hiba):
    /// ilyenkor a hibát megmutatja, és a hibás kapcsolat Beállítások fülére vált.
    func saveAllUnsaved() -> Bool {
        var failures: [(id: UUID, message: String)] = []
        for (id, save) in saveHandlers where dirtyIDs.contains(id) {
            if let message = save() { failures.append((id, message)) } else { setUnsaved(id, dirty: false) }
        }
        guard let first = failures.first else { return true }
        var names = Dictionary(uniqueKeysWithValues: manager.connections.map { ($0.id, $0.name) })
        for s in manager.systemServices { if let id = s.secretID { names[id] = s.name } }
        let alert = NSAlert()
        alert.messageText = String(localized: "Saving failed")
        alert.informativeText = failures.map { "\(names[$0.id] ?? $0.id.uuidString): \($0.message)" }
            .joined(separator: "\n\n")
        alert.alertStyle = .warning
        alert.addButton(withTitle: String(localized: "OK"))
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        // A hibás kapcsolat űrlapja látsszon (a dirty-ellenőrzést szándékosan megkerüli: ugyanazt a szerkesztést mutatja).
        pendingAction = nil
        logTabRequest = nil
        settingsTabRequest = first.id
        selectedID = first.id.uuidString
        openManageWindow?()
        return false
    }

    func discardUnsaved() {
        dirtyIDs = []
        saveHandlers = [:]
    }

    /// A függő kijelölés végrehajtása (Mentés vagy Elvetés után). Bezárást a nézet hajt végre.
    func resolvePendingSelection() {
        if case .select(let id)? = pendingAction { selectedID = id }
        pendingAction = nil
    }

    func cancelPendingAction() {
        pendingAction = nil
        logTabRequest = nil
    }

    // MARK: Kapcsolás

    func toggle(_ c: Connection, debug: Bool) {
        if manager.state(for: c.id.uuidString).isActive {
            Task { await manager.disconnect(c); nativeLogs[c.id]?.stop() }
        } else {
            connect(c, debug: debug)
        }
    }

    func connect(_ c: Connection, debug: Bool) {
        var collector: NativeLogCollector?
        if debug {
            logTabRequest = c.id
            select(c.id.uuidString)
            openManageWindow?()
            if c.kind.isNative {
                let existing = nativeLogs[c.id] ?? NativeLogCollector()
                nativeLogs[c.id] = existing
                existing.start()
                collector = existing
            }
        }
        let generation = collector?.generation
        Task {
            await manager.connect(c, debug: debug)
            guard let collector, let generation else { return }
            await stopWhenSettled(collector, generation: generation, key: c.id.uuidString)
        }
    }

    /// Natív debug: a gyűjtés leáll, ha a kapcsolat `connected` vagy `failed` lett, vagy 60 mp után.
    /// Az állapotot a manager (a polling `refresh`-ei) dönti el, itt csak figyeljük.
    private func stopWhenSettled(_ collector: NativeLogCollector, generation: Int, key: String) async {
        let deadline = Date().addingTimeInterval(Self.nativeLogMaxSeconds)
        while Date() < deadline, collector.generation == generation {
            switch manager.state(for: key) {
            case .connected, .failed, .disconnected:
                collector.stop()
                return
            case .connecting, .disconnecting:
                try? await Task.sleep(for: .milliseconds(500))
            }
        }
        if collector.generation == generation { collector.stop() }
    }

    func toggleSystem(_ s: SystemVPNService) {
        Task {
            if manager.state(for: s.id).isActive { await manager.disconnectSystem(s) } else { await manager.connectSystem(s) }
        }
    }

    // MARK: Létrehozás, import, mentés, törlés

    func createNew(kind: VPNKind) {
        let c = Connection(name: String(localized: "New \(kind.displayName)"), kind: kind,
                           native: kind.isNative ? NativeSettings() : nil)
        try? store.save(c, config: kind.isNative ? nil : ConfigImporter.template(for: kind))
        manager.reload()
        select(c.id.uuidString)
    }

    /// Egy import eredménye: hibák (nem importált fájlok) és tájékoztatás (beemelt fájlok, validációs hibák).
    struct ImportReport: Equatable {
        var errors: [String] = []
        var notes: [String] = []

        var isEmpty: Bool { errors.isEmpty && notes.isEmpty }
        var message: String { (errors + notes).joined(separator: "\n") }

        mutating func merge(_ other: ImportReport) {
            errors += other.errors
            notes += other.notes
        }
    }

    /// Az importált kapcsolat validációs hibái: a szerkesztő az első betöltéskor megjeleníti (egyszer használatos).
    private var importIssues: [UUID: [ValidationIssue]] = [:]

    func takeImportIssues(_ id: UUID) -> [ValidationIssue] {
        importIssues.removeValue(forKey: id) ?? []
    }

    /// A configot validációs hiba esetén is menti (a szerkesztőben javítható), és rögtön meg is nyitja.
    private func importFile(_ url: URL) -> ImportReport {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let file = url.lastPathComponent
        guard let content = try? String(contentsOf: url, encoding: .utf8) else {
            return ImportReport(errors: ["\(file): \(String(localized: "Cannot read the file"))"])
        }
        do {
            let prepared = try ConfigImporter.prepare(fileName: file, content: content,
                                                      baseDirectory: url.deletingLastPathComponent())
            let c = Connection(name: url.deletingPathExtension().lastPathComponent, kind: prepared.kind)
            try store.save(c, config: prepared.config)
            if !prepared.issues.isEmpty { importIssues[c.id] = prepared.issues }
            manager.reload()
            select(c.id.uuidString)
            var report = ImportReport()
            if !prepared.inlinedFiles.isEmpty {
                let list = prepared.inlinedFiles.joined(separator: ", ")
                report.notes.append("\(file): \(String(localized: "Imported, inlined: \(list)"))")
            }
            if !prepared.issues.isEmpty {
                report.notes.append("\(file): \(String(localized: "Imported, but the config has problems. Fix them in the editor (red list)."))")
            }
            return report
        } catch {
            return ImportReport(errors: ["\(file): \(error.localizedDescription)"])
        }
    }

    func importFiles(_ urls: [URL]) -> ImportReport {
        var report = ImportReport()
        for url in urls { report.merge(importFile(url)) }
        return report
    }

    /// Export. Ha a config privát / statikus kulcsot vagy inline hitelesítő adatot tartalmaz, rákérdez: kulcsok nélkül
    /// (alapértelmezett), kulcsokkal, vagy mégse. A Keychainben tárolt jelszó és PSK sosem kerül bele. A mentési panel
    /// szövege a ténylegesen kiírt adatból dől el: ha abban kulcsanyag maradt, kimondja, hogy benne van.
    func export(_ c: Connection) {
        var data: Data
        do { data = try ConfigExporter.export(c, store: store) } catch {
            NSAlert(error: error).runModal()
            return
        }
        let text = String(decoding: data, as: UTF8.self)
        let material = ConfigExporter.secretMaterial(in: text, kind: c.kind)
        if !material.isEmpty {
            let alert = NSAlert()
            alert.messageText = String(localized: "The config contains private keys or credentials")
            let list = material.joined(separator: ", ")
            alert.informativeText = String(localized: "It contains: \(list). Anyone who has these keys can connect as you. Export them only if the recipient needs them, and keep the file in a trusted place.")
            alert.alertStyle = .warning
            alert.addButton(withTitle: String(localized: "Export Without Keys"))
            alert.addButton(withTitle: String(localized: "Export With Keys"))
            alert.addButton(withTitle: String(localized: "Cancel"))
            switch alert.runModal() {
            case .alertFirstButtonReturn: data = Data(ConfigExporter.stripSecrets(text, kind: c.kind).utf8)
            case .alertSecondButtonReturn: break
            default: return
            }
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = ConfigExporter.fileName(for: c)
        let included = ConfigExporter.secretMaterial(in: String(decoding: data, as: UTF8.self), kind: c.kind)
        if included.isEmpty {
            panel.message = String(localized: "Passwords and the PSK are not included in the export.")
        } else {
            let list = included.joined(separator: ", ")
            panel.message = String(localized: "The export INCLUDES the private keys and credentials from the config (\(list)). Passwords and the PSK stored in the Keychain are not included.")
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try ConfigExporter.write(data, to: url)
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    /// Hibák listája; üres = mentve.
    func saveText(_ c: Connection, name: String, config: String, secrets newSecrets: Secrets) -> [ValidationIssue] {
        var issues = Validators.validator(for: c.kind)?.validate(config) ?? []
        if let error = newSecrets.inputError { issues.append(ValidationIssue(line: 0, message: error)) }
        guard issues.isEmpty else { return issues }
        var updated = c
        updated.name = name
        do { try store.save(updated, config: config) } catch {
            return [ValidationIssue(line: 0, message: error.localizedDescription)]
        }
        storeSecrets(newSecrets, for: c.id)
        manager.reload()
        return []
    }

    /// Az SSTP űrlap mentése: a config szerializálva és validálva, a jelszó a Keychainbe. Hibák listája; üres = mentve.
    func saveSSTP(_ c: Connection, name: String, config: SSTPConfig, password: String) -> [ValidationIssue] {
        guard SSTPConfig.isAcceptablePassword(password) else {
            return [ValidationIssue(line: 0, message: SSTPConfig.passwordRuleMessage)]
        }
        return saveText(c, name: name, config: config.serialized(), secrets: Secrets(password: password))
    }

    /// Natív mentés: a profil (jelszó nélkül, PSK-val) egy friss, privát ideiglenes könyvtárba kerül, onnan nyílik meg,
    /// és törlődik, amint a szolgáltatás megjelenik a `scutil --nc list`-ben (legkésőbb a következő induláskor).
    func saveNative(_ c: Connection, name: String, settings: NativeSettings, password: String, psk: String) -> String? {
        guard !settings.server.isEmpty, !settings.account.isEmpty else { return String(localized: "Server and account name are required") }
        if let error = Secrets(username: settings.account, password: password, psk: psk).inputError { return error }
        var updated = c
        updated.name = name
        updated.native = settings
        updated.nativeServiceName = name
        let serviceExisted = manager.installedNativeIDs.contains(c.id)
        do {
            let data = try MobileconfigGenerator.generate(connection: updated, psk: psk)
            try store.save(updated, config: nil)
            storeSecrets(Secrets(username: settings.account, password: password, psk: psk), for: c.id)
            manager.reload()
            let profile = try NativeProfileStaging.stage(data, fileName: ConfigExporter.fileName(for: updated),
                                                         in: NativeProfileStaging.defaultParent)
            stagedProfiles.track(c.id, profile: profile, serviceExisted: serviceExisted)
            NSWorkspace.shared.open(profile)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func storeSecrets(_ s: Secrets, for id: UUID) {
        secrets.set(s.username ?? "", for: id, field: .username)
        secrets.set(s.password ?? "", for: id, field: .password)
        secrets.set(s.psk ?? "", for: id, field: .psk)
    }

    /// A rendszer VPN-hez a MacVPN kulcskarikájában tárolt PSK / jelszó (csak L2TP / Cisco IPsec, UUID azonosítóval).
    /// Üres mező törli a bejegyzést. nil: mentve; egyébként a hiba (vezérlőkarakter, más típus, nem UUID azonosító).
    func saveSystemSecrets(_ s: SystemVPNService, psk: String, password: String) -> String? {
        guard s.supportsStoredSecrets, let id = s.secretID else { return String(localized: "The editor is no longer available") }
        if let error = Secrets(password: password, psk: psk).inputError { return error }
        secrets.set(psk, for: id, field: .psk)
        secrets.set(password, for: id, field: .password)
        return nil
    }

    func forgetSystemSecrets(_ s: SystemVPNService) {
        guard let id = s.secretID else { return }
        secrets.deleteAll(for: id)
        setUnsaved(id, dirty: false)
    }

    func delete(_ c: Connection) {
        Task {
            if manager.state(for: c.id.uuidString).isActive { await manager.disconnect(c) }
            nativeLogs[c.id]?.stop()
            nativeLogs[c.id] = nil
            setUnsaved(c.id, dirty: false)
            try? store.delete(c.id)
            secrets.deleteAll(for: c.id)
            manager.reload()
            if selectedID == c.id.uuidString { selectedID = nil }
            if c.kind.isNative,
               let url = URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension") {
                NSWorkspace.shared.open(url)
            }
            await manager.refresh()
        }
    }

    // MARK: Értesítések

    private func notify(_ event: ConnectionEvent) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        let id: String
        switch event {
        case .failed(let cid, let name, _):
            id = cid
            content.title = String(localized: "\(name): connection failed")
            // A hiba szövege (szerver, felhasználónév, rendszerüzenet) nem kerül a lezárt képernyőn is látható
            // értesítésbe: a teljes ok az appban látszik.
            content.body = String(localized: "Open MacVPN for details")
        case .dropped(let cid, let name):
            id = cid
            content.title = String(localized: "\(name): the connection dropped")
            content.body = String(localized: "Click to see the log.")
        }
        content.userInfo = ["connectionID": id]
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let id = response.notification.request.content.userInfo["connectionID"] as? String
        Task { @MainActor in
            if let id, let uuid = UUID(uuidString: id), self.manager.connections.contains(where: { $0.id == uuid }) {
                self.logTabRequest = uuid
            }
            self.select(id)
            self.openManageWindow?()
            completionHandler()
        }
    }

    /// Előtérben is jelenjen meg az értesítés.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    /// A SwiftUI `openWindow` akciót a nézet adja át (Task 22).
    var openManageWindow: (() -> Void)?

    // MARK: Kilépés

    /// A kilépést már megerősítették: az `applicationShouldTerminate` nem kérdez újra.
    private(set) var quitConfirmed = false

    func quit() {
        Task { if await confirmQuit() { terminateConfirmed() } }
    }

    /// Kilépés a kérdések után (menü Kilépés, frissítés, eltávolítás).
    func terminateConfirmed() {
        quitConfirmed = true
        NSApp.terminate(nil)
    }

    /// A kilépés előtti kérdések (nem mentett változások, aktív kapcsolatok). True: mehet a kilépés
    /// (a választott kapcsolatok addigra le vannak bontva). A frissítés telepítése is ezt használja.
    func confirmQuit() async -> Bool {
        guard confirmUnsaved() else { return false }
        return await confirmActiveConnections()
    }

    /// Nem mentett változásnál Mentés / Elvetés / Mégse. True: mehet tovább.
    func confirmUnsaved() -> Bool {
        if hasUnsavedChanges {
            let alert = NSAlert()
            alert.messageText = String(localized: "Unsaved Changes")
            alert.informativeText = String(localized: "The edited settings have not been saved yet.")
            alert.addButton(withTitle: String(localized: "Save"))
            alert.addButton(withTitle: String(localized: "Discard"))
            alert.addButton(withTitle: String(localized: "Cancel"))
            NSApp.activate(ignoringOtherApps: true)
            switch alert.runModal() {
            case .alertFirstButtonReturn:
                guard saveAllUnsaved() else { return false }
            case .alertSecondButtonReturn:
                discardUnsaved()
            default:
                return false
            }
        }
        return true
    }

    /// Aktív kapcsolatnál: leállítás / futhatnak tovább / Mégse. True: mehet a kilépés.
    private func confirmActiveConnections() async -> Bool {
        guard manager.hasActive else { return true }
        let alert = NSAlert()
        alert.messageText = String(localized: "There are active VPN connections")
        alert.informativeText = String(localized: "Disconnect them before quitting?")
        alert.addButton(withTitle: String(localized: "Disconnect and Quit"))
        alert.addButton(withTitle: String(localized: "Quit, Keep Them Running"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            await manager.disconnectAll()
            // A nem az app által kezelt rendszer VPN-eket is bontja, ha aktívak.
            for s in manager.systemServices where manager.state(for: s.id).isActive {
                await manager.disconnectSystem(s)
            }
            return true
        case .alertSecondButtonReturn:
            return true
        default:
            return false
        }
    }
}
