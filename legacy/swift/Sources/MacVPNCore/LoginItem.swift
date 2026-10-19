import Foundation
import Combine

/// Indítás bejelentkezéskor (login item). A tényleges állapot mindig a rendszertől jön (`SMAppService.mainApp.status`),
/// nem egy mentett kapcsolóból. A ServiceManagement-es megvalósítás az appban van (`SMAppServiceLoginItem`), itt csak a
/// protokoll, az állapot → UI leképezés és a hibakezelés, hogy mock szolgáltatással tesztelhető legyen.

/// `SMAppService.Status` megfelelője.
public enum LoginItemStatus: Equatable, Sendable {
    case enabled
    case notRegistered
    case requiresApproval
    case notFound
    /// Az `SMAppService` nem regisztrált (ad-hoc aláírt buildnél tipikusan `.notFound`), de a saját per-user
    /// LaunchAgentünk (`~/Library/LaunchAgents/local.macvpn.launcher.plist`) a várt tartalommal megvan.
    case enabledViaLaunchAgent
}

/// A rendszer login item szolgáltatása (élesben `SMAppService.mainApp`).
@MainActor
public protocol LoginItemService: AnyObject {
    var status: LoginItemStatus { get }
    func register() throws
    func unregister() throws
    func openSystemSettingsLoginItems()
}

/// Honnan fut az app. DMG-ről, letöltés mappából vagy App Translocation alól a regisztráció törékeny
/// (a rendszer egy ideiglenes útvonalat jegyezne meg), ezért csak az Applications mappákból engedjük.
public enum LoginItemLocation: Equatable, Sendable {
    case applications
    case notInApplications
    case translocated

    /// Tiszta függvény: `/Applications` vagy `~/Applications` (almappa is) alatt futó `.app` rendben van.
    /// Az összehasonlítás kis-nagybetű független (az APFS alapból az). A symlinkeket a hívó oldja fel.
    public static func check(bundlePath: String, homeDirectory: String) -> LoginItemLocation {
        let path = (bundlePath as NSString).standardizingPath
        if path.contains("/AppTranslocation/") { return .translocated }
        guard (path as NSString).pathExtension.lowercased() == "app" else { return .notInApplications }
        let home = (homeDirectory as NSString).standardizingPath
        var roots = ["/Applications"]
        if home.hasPrefix("/"), home != "/" { roots.append((home as NSString).appendingPathComponent("Applications")) }
        let lowered = path.lowercased()
        return roots.contains { lowered.hasPrefix($0.lowercased() + "/") } ? .applications : .notInApplications
    }

    /// Az éppen futó app helye (symlinkek feloldva).
    public static func current(bundleURL: URL = Bundle.main.bundleURL,
                               homeDirectory: String = NSHomeDirectory()) -> LoginItemLocation {
        check(bundlePath: bundleURL.resolvingSymlinksInPath().path, homeDirectory: homeDirectory)
    }
}

/// A kapcsoló alatti megjegyzés.
public enum LoginItemNote: Equatable, Sendable {
    case requiresApproval
    /// A bekapcsolás a LaunchAgent tartalékkal történt (a következő bejelentkezéstől érvényes).
    case launchAgent
    case notInApplications
    case translocated

    public var message: String {
        switch self {
        case .requiresApproval:
            return L10n.tr("Approve MacVPN in System Settings → General → Login Items.")
        case .launchAgent:
            return L10n.tr("Enabled via a login LaunchAgent (applies at next login).")
        case .notInApplications:
            return L10n.tr("Launch at login is available only when MacVPN runs from the Applications folder. Drag the app there first.")
        case .translocated:
            return L10n.tr("macOS is running MacVPN from a temporary location. Move the app to the Applications folder and open it from there.")
        }
    }
}

/// Amit a UI mutat: a kapcsoló állása, kattintható-e, a megjegyzés és a „Bejelentkezési elemek" gomb.
public struct LoginItemState: Equatable, Sendable {
    public var isOn: Bool
    public var canToggle: Bool
    public var note: LoginItemNote?
    public var showsOpenSettings: Bool

    public init(isOn: Bool, canToggle: Bool, note: LoginItemNote?, showsOpenSettings: Bool) {
        self.isOn = isOn
        self.canToggle = canToggle
        self.note = note
        self.showsOpenSettings = showsOpenSettings
    }

    /// - `.enabled` → be; `.notRegistered` → ki.
    /// - `.requiresApproval` → be (regisztrálva van, csak jóváhagyásra vár; kikapcsolva visszavonható) + megjegyzés és gomb.
    /// - `.notFound` → ugyanaz, mint `.notRegistered`: ad-hoc aláírt (Developer ID nélküli) buildnél az
    ///   `SMAppService.mainApp` akkor is ezt adja, ha az app a helyén van. A bekapcsolás ilyenkor a LaunchAgent
    ///   tartalékra esik vissza (`FallbackLoginItemService`); megjegyzés csak egy tényleges hibánál (riasztás).
    /// - `.enabledViaLaunchAgent` → be, halvány megjegyzéssel (a következő bejelentkezéstől érvényes).
    /// - Rossz helyről futva bekapcsolni nem lehet; ha már regisztrálva van, kikapcsolni igen (ne ragadjon be).
    public static func make(status: LoginItemStatus, location: LoginItemLocation) -> LoginItemState {
        let locationNote: LoginItemNote? = switch location {
        case .applications: nil
        case .notInApplications: .notInApplications
        case .translocated: .translocated
        }
        switch status {
        case .enabled:
            return LoginItemState(isOn: true, canToggle: true, note: locationNote, showsOpenSettings: false)
        case .requiresApproval:
            return LoginItemState(isOn: true, canToggle: true, note: .requiresApproval, showsOpenSettings: true)
        case .enabledViaLaunchAgent:
            return LoginItemState(isOn: true, canToggle: true, note: locationNote ?? .launchAgent, showsOpenSettings: false)
        case .notRegistered, .notFound:
            return LoginItemState(isOn: false, canToggle: locationNote == nil, note: locationNote, showsOpenSettings: false)
        }
    }
}

/// A login item állapota és műveletei. Új felhasználónál alapból KI: az app sosem regisztrál magától, csak a kapcsolóra.
@MainActor
public final class LoginItemController: ObservableObject {
    /// Új telepítésnél az alapértelmezés: nincs indítás bejelentkezéskor (nincs automatikus regisztráció).
    public static let defaultEnabled = false

    @Published public private(set) var status: LoginItemStatus
    @Published public private(set) var location: LoginItemLocation
    private let service: LoginItemService
    private let locate: () -> LoginItemLocation

    public init(service: LoginItemService, locate: @escaping () -> LoginItemLocation = { LoginItemLocation.current() }) {
        self.service = service
        self.locate = locate
        status = service.status
        location = locate()
    }

    public var state: LoginItemState { .make(status: status, location: location) }

    /// Újraolvassa a rendszer állapotát (menü megnyitásakor, a Rendszerállapot ablaknál, váltás után).
    public func refresh() {
        let newStatus = service.status
        let newLocation = locate()
        if newStatus != status { status = newStatus }
        if newLocation != location { location = newLocation }
    }

    /// A kapcsoló: be → `register()`, ki → `unregister()`. A hibát továbbdobja (a UI riasztásban mutatja);
    /// az állapotot mindenképp újraolvassa. Ha a kapcsoló nem kattintható, nem csinál semmit.
    public func setEnabled(_ on: Bool) throws {
        defer { refresh() }
        let current = state
        guard on != current.isOn else { return }
        if on {
            guard current.canToggle else { return }
            try service.register()
        } else {
            try service.unregister()
        }
    }

    /// Eltávolításkor: ha regisztrálva van (be, jóváhagyásra vár vagy LaunchAgenttel), leiratkozik, hogy ne maradjon árva login item.
    /// True, ha volt mit eltávolítani.
    @discardableResult
    public func unregisterIfRegistered() throws -> Bool {
        defer { refresh() }
        switch service.status {
        case .enabled, .requiresApproval, .enabledViaLaunchAgent:
            try service.unregister()
            return true
        case .notRegistered, .notFound:
            return false
        }
    }

    public func openSystemSettings() {
        service.openSystemSettingsLoginItems()
    }
}
