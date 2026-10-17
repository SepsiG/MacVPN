import XCTest
@testable import MacVPNCore

@MainActor
final class MockLoginItemService: LoginItemService {
    var status: LoginItemStatus
    var calls: [String] = []
    var registerError: Error?
    var unregisterError: Error?
    /// Sikeres register után ez lesz az állapot (pl. `.requiresApproval`).
    var statusAfterRegister: LoginItemStatus = .enabled

    init(status: LoginItemStatus) { self.status = status }

    func register() throws {
        calls.append("register")
        if let registerError { throw registerError }
        status = statusAfterRegister
    }

    func unregister() throws {
        calls.append("unregister")
        if let unregisterError { throw unregisterError }
        status = .notRegistered
    }

    func openSystemSettingsLoginItems() { calls.append("openSettings") }
}

struct LoginItemTestError: LocalizedError {
    var errorDescription: String? { "Operation not permitted" }
}

@MainActor
final class LoginItemTests: XCTestCase {
    override func tearDown() async throws {
        AppLanguage.override = nil
    }

    func makeController(_ service: MockLoginItemService,
                        location: LoginItemLocation = .applications) -> LoginItemController {
        LoginItemController(service: service, locate: { location })
    }

    // MARK: Állapot → UI

    func testStateMappingFromApplications() {
        XCTAssertEqual(LoginItemState.make(status: .enabled, location: .applications),
                       LoginItemState(isOn: true, canToggle: true, note: nil, showsOpenSettings: false))
        XCTAssertEqual(LoginItemState.make(status: .notRegistered, location: .applications),
                       LoginItemState(isOn: false, canToggle: true, note: nil, showsOpenSettings: false))
        XCTAssertEqual(LoginItemState.make(status: .requiresApproval, location: .applications),
                       LoginItemState(isOn: true, canToggle: true, note: .requiresApproval, showsOpenSettings: true))
        XCTAssertEqual(LoginItemState.make(status: .notFound, location: .applications),
                       LoginItemState(isOn: false, canToggle: false, note: .notFound, showsOpenSettings: false))
    }

    func testBadLocationDisablesTurningOnButAllowsTurningOff() {
        XCTAssertEqual(LoginItemState.make(status: .notRegistered, location: .notInApplications),
                       LoginItemState(isOn: false, canToggle: false, note: .notInApplications, showsOpenSettings: false))
        XCTAssertEqual(LoginItemState.make(status: .notRegistered, location: .translocated),
                       LoginItemState(isOn: false, canToggle: false, note: .translocated, showsOpenSettings: false))
        XCTAssertEqual(LoginItemState.make(status: .notFound, location: .translocated),
                       LoginItemState(isOn: false, canToggle: false, note: .translocated, showsOpenSettings: false))
        // Már regisztrálva (pl. az app azóta máshonnan fut): kikapcsolható marad.
        XCTAssertEqual(LoginItemState.make(status: .enabled, location: .notInApplications),
                       LoginItemState(isOn: true, canToggle: true, note: .notInApplications, showsOpenSettings: false))
    }

    func testControllerReadsStatusFromService() {
        let service = MockLoginItemService(status: .notRegistered)
        let controller = makeController(service)
        XCTAssertFalse(controller.state.isOn)
        service.status = .enabled  // pl. a Rendszerbeállításokban kapcsolták be
        XCTAssertFalse(controller.state.isOn)
        controller.refresh()
        XCTAssertTrue(controller.state.isOn)
        service.status = .requiresApproval
        controller.refresh()
        XCTAssertEqual(controller.state.note, .requiresApproval)
    }

    // MARK: Alapértelmezés

    func testDefaultIsOffAndNothingIsRegisteredAutomatically() {
        XCTAssertFalse(LoginItemController.defaultEnabled)
        let service = MockLoginItemService(status: .notRegistered)
        let controller = makeController(service)
        controller.refresh()
        XCTAssertEqual(service.calls, [])
        XCTAssertFalse(controller.state.isOn)
    }

    // MARK: Kapcsoló

    func testToggleCallsRegisterAndUnregister() throws {
        let service = MockLoginItemService(status: .notRegistered)
        let controller = makeController(service)
        try controller.setEnabled(true)
        XCTAssertEqual(service.calls, ["register"])
        XCTAssertEqual(controller.status, .enabled)
        try controller.setEnabled(false)
        XCTAssertEqual(service.calls, ["register", "unregister"])
        XCTAssertEqual(controller.status, .notRegistered)
    }

    func testToggleToCurrentValueIsNoOp() throws {
        let service = MockLoginItemService(status: .enabled)
        let controller = makeController(service)
        try controller.setEnabled(true)
        XCTAssertEqual(service.calls, [])
    }

    func testRegisterNeedingApprovalShowsNote() throws {
        let service = MockLoginItemService(status: .notRegistered)
        service.statusAfterRegister = .requiresApproval
        let controller = makeController(service)
        try controller.setEnabled(true)
        XCTAssertEqual(controller.state.note, .requiresApproval)
        XCTAssertTrue(controller.state.showsOpenSettings)
        controller.openSystemSettings()
        XCTAssertEqual(service.calls, ["register", "openSettings"])
    }

    func testDisabledToggleDoesNotRegister() throws {
        let service = MockLoginItemService(status: .notRegistered)
        try makeController(service, location: .translocated).setEnabled(true)
        let notFound = MockLoginItemService(status: .notFound)
        try makeController(notFound).setEnabled(true)
        XCTAssertEqual(service.calls, [])
        XCTAssertEqual(notFound.calls, [])
    }

    func testRegisterErrorSurfacesAndStateIsReread() {
        let service = MockLoginItemService(status: .notRegistered)
        service.registerError = LoginItemTestError()
        let controller = makeController(service)
        XCTAssertThrowsError(try controller.setEnabled(true)) { error in
            XCTAssertEqual(error.localizedDescription, "Operation not permitted")
        }
        XCTAssertFalse(controller.state.isOn)
    }

    func testUnregisterErrorSurfaces() {
        let service = MockLoginItemService(status: .enabled)
        service.unregisterError = LoginItemTestError()
        let controller = makeController(service)
        XCTAssertThrowsError(try controller.setEnabled(false))
        XCTAssertTrue(controller.state.isOn)
    }

    // MARK: Eltávolítás

    func testUninstallUnregistersWhenRegistered() throws {
        for status in [LoginItemStatus.enabled, .requiresApproval] {
            let service = MockLoginItemService(status: status)
            let controller = makeController(service)
            XCTAssertTrue(try controller.unregisterIfRegistered())
            XCTAssertEqual(service.calls, ["unregister"])
            XCTAssertEqual(controller.status, .notRegistered)
        }
    }

    func testUninstallSkipsWhenNotRegistered() throws {
        for status in [LoginItemStatus.notRegistered, .notFound] {
            let service = MockLoginItemService(status: status)
            XCTAssertFalse(try makeController(service).unregisterIfRegistered())
            XCTAssertEqual(service.calls, [])
        }
    }

    func testUninstallUnregisterErrorSurfaces() {
        let service = MockLoginItemService(status: .enabled)
        service.unregisterError = LoginItemTestError()
        XCTAssertThrowsError(try makeController(service).unregisterIfRegistered())
    }

    // MARK: Hely

    func testLocationCheck() {
        let home = "/Users/anna"
        func check(_ path: String) -> LoginItemLocation { LoginItemLocation.check(bundlePath: path, homeDirectory: home) }
        XCTAssertEqual(check("/Applications/MacVPN.app"), .applications)
        XCTAssertEqual(check("/Applications/Utilities/MacVPN.app"), .applications)
        XCTAssertEqual(check("/applications/MacVPN.app"), .applications)
        XCTAssertEqual(check("/Users/anna/Applications/MacVPN.app"), .applications)
        XCTAssertEqual(check("/Users/anna/Applications/../Applications/MacVPN.app"), .applications)
        XCTAssertEqual(check("/Volumes/MacVPN/MacVPN.app"), .notInApplications)
        XCTAssertEqual(check("/Users/anna/Downloads/MacVPN.app"), .notInApplications)
        XCTAssertEqual(check("/Users/bob/Applications/MacVPN.app"), .notInApplications)
        XCTAssertEqual(check("/ApplicationsOld/MacVPN.app"), .notInApplications)
        XCTAssertEqual(check("/Applications/../tmp/MacVPN.app"), .notInApplications)
        XCTAssertEqual(check("/Applications"), .notInApplications)
        XCTAssertEqual(check("/Users/anna/dev/macvpn/.build/debug"), .notInApplications)
        XCTAssertEqual(check("/private/var/folders/x/T/AppTranslocation/1234-ABCD/d/MacVPN.app"), .translocated)
        XCTAssertEqual(LoginItemLocation.check(bundlePath: "/Users/anna/Applications/MacVPN.app", homeDirectory: ""),
                       .notInApplications)
    }

    // MARK: Szövegek

    func testNotesAreLocalized() {
        let notes: [LoginItemNote] = [.requiresApproval, .notFound, .notInApplications, .translocated]
        AppLanguage.override = .en
        let english = notes.map(\.message)
        XCTAssertEqual(english[0], "Approve MacVPN in System Settings → General → Login Items.")
        AppLanguage.override = .hu
        for (note, en) in zip(notes, english) {
            XCTAssertEqual(note.message, L10n.hungarian[en], "nincs magyar fordítás: \(en)")
        }
        XCTAssertEqual(LoginItemNote.requiresApproval.message,
                       "Engedélyezd a MacVPN-t a Rendszerbeállítások → Általános → Bejelentkezési elemek alatt.")
    }
}
