import XCTest
@testable import MacVPNCore

/// A LaunchAgent tartalék tesztjei. Mindig ideiglenes könyvtárral: a valódi `~/Library/LaunchAgents`-hez és a
/// valódi login itemhez nem nyúlnak.
@MainActor
final class LaunchAgentLoginItemTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("macvpn-launchagent-\(UUID().uuidString)/LaunchAgents", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir.deletingLastPathComponent())
        AppLanguage.override = nil
    }

    var agent: LaunchAgentLoginItem { LaunchAgentLoginItem(directory: dir) }

    func readPlist() throws -> [String: Any] {
        let data = try Data(contentsOf: agent.plistURL)
        return try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    func writePlist(_ dict: [String: Any]) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: agent.plistURL)
    }

    func makeService(_ primary: MockLoginItemService) -> FallbackLoginItemService {
        FallbackLoginItemService(primary: primary, launchAgent: agent)
    }

    // MARK: Plist

    func testDefaults() {
        XCTAssertEqual(LaunchAgentLoginItem.defaultLabel, "local.macvpn.launcher")
        XCTAssertEqual(LaunchAgentLoginItem.defaultBundleIdentifier, "local.macvpn")
        XCTAssertTrue(LaunchAgentLoginItem.defaultDirectory.path.hasSuffix("/Library/LaunchAgents"))
        XCTAssertEqual(agent.plistURL.lastPathComponent, "local.macvpn.launcher.plist")
    }

    func testInstallWritesExpectedPlistWithMode0644() throws {
        XCTAssertFalse(agent.isInstalled)
        try agent.install()
        let plist = try readPlist()
        XCTAssertEqual(plist["Label"] as? String, "local.macvpn.launcher")
        XCTAssertEqual(plist["ProgramArguments"] as? [String], ["/usr/bin/open", "-b", "local.macvpn"])
        XCTAssertEqual(plist["RunAtLoad"] as? Bool, true)
        XCTAssertEqual(plist["LimitLoadToSessionType"] as? String, "Aqua")
        let attrs = try FileManager.default.attributesOfItem(atPath: agent.plistURL.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o644)
        XCTAssertEqual(attrs[.type] as? FileAttributeType, .typeRegular)
        XCTAssertTrue(agent.isInstalled)
        // Nem marad temp fájl.
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["local.macvpn.launcher.plist"])
        // Újraírás (felülírás) is működik.
        try agent.install()
        XCTAssertTrue(agent.isInstalled)
    }

    func testInstallRefusesSymlink() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let target = dir.deletingLastPathComponent().appendingPathComponent("target.plist")
        try Data("keep".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: agent.plistURL, withDestinationURL: target)
        XCTAssertThrowsError(try agent.install()) { error in
            XCTAssertEqual(error as? LaunchAgentError, .notRegularFile(agent.plistURL.path))
        }
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "keep")
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: agent.plistURL.path), target.path)
        XCTAssertFalse(agent.isInstalled)
    }

    func testSymlinkToValidPlistIsNotInstalledAndNotRemoved() throws {
        let real = LaunchAgentLoginItem(directory: dir.deletingLastPathComponent(), label: "local.macvpn.launcher")
        try real.install()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: agent.plistURL, withDestinationURL: real.plistURL)
        XCTAssertFalse(agent.isInstalled)
        XCTAssertFalse(try agent.remove())
        XCTAssertTrue(real.isInstalled)
    }

    func testStatusDetectionChecksLabelAndArguments() throws {
        XCTAssertFalse(agent.isInstalled)
        try writePlist(["Label": "local.macvpn.launcher", "ProgramArguments": ["/usr/bin/open", "-b", "local.macvpn"]])
        XCTAssertTrue(agent.isInstalled)
        try writePlist(["Label": "local.macvpn.launcher", "ProgramArguments": ["/tmp/evil"]])
        XCTAssertFalse(agent.isInstalled)
        try writePlist(["Label": "com.example.other", "ProgramArguments": ["/usr/bin/open", "-b", "local.macvpn"]])
        XCTAssertFalse(agent.isInstalled)
        try Data("not a plist".utf8).write(to: agent.plistURL)
        XCTAssertFalse(agent.isInstalled)
    }

    func testRemoveDeletesOnlyOurLabel() throws {
        XCTAssertFalse(try agent.remove())  // nincs mit törölni
        try writePlist(["Label": "com.example.other", "ProgramArguments": ["/bin/true"]])
        XCTAssertFalse(try agent.remove())
        XCTAssertTrue(FileManager.default.fileExists(atPath: agent.plistURL.path))
        // A mi címkénk, régi argumentumokkal: töröljük.
        try writePlist(["Label": "local.macvpn.launcher", "ProgramArguments": ["/old/path"]])
        XCTAssertTrue(try agent.remove())
        XCTAssertFalse(FileManager.default.fileExists(atPath: agent.plistURL.path))
    }

    // MARK: Összetett szolgáltatás

    func testRegisterFallsBackWhenSMAppServiceThrows() throws {
        let primary = MockLoginItemService(status: .notFound)
        primary.registerError = LoginItemTestError()
        let service = makeService(primary)
        XCTAssertEqual(service.status, .notFound)
        try service.register()
        XCTAssertEqual(primary.calls, ["register"])
        XCTAssertTrue(agent.isInstalled)
        XCTAssertEqual(service.status, .enabledViaLaunchAgent)
    }

    func testRegisterFallsBackWhenStatusStaysNotFound() throws {
        let primary = MockLoginItemService(status: .notFound)
        primary.statusAfterRegister = .notFound
        let service = makeService(primary)
        try service.register()
        XCTAssertTrue(agent.isInstalled)
        XCTAssertEqual(service.status, .enabledViaLaunchAgent)
    }

    func testRegisterViaSMAppServiceDoesNotWritePlistAndRemovesStaleOne() throws {
        let primary = MockLoginItemService(status: .notRegistered)
        let service = makeService(primary)
        try service.register()
        XCTAssertEqual(service.status, .enabled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: agent.plistURL.path))

        try agent.install()
        let approval = MockLoginItemService(status: .notRegistered)
        approval.statusAfterRegister = .requiresApproval
        try makeService(approval).register()
        XCTAssertFalse(agent.isInstalled)
    }

    func testRegisterFallbackErrorSurfaces() throws {
        let primary = MockLoginItemService(status: .notFound)
        primary.registerError = LoginItemTestError()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: agent.plistURL.path, withDestinationPath: "/dev/null")
        let controller = LoginItemController(service: makeService(primary), locate: { .applications })
        XCTAssertThrowsError(try controller.setEnabled(true))
        XCTAssertFalse(controller.state.isOn)
    }

    func testStatusFromPlist() throws {
        let primary = MockLoginItemService(status: .notRegistered)
        let service = makeService(primary)
        XCTAssertEqual(service.status, .notRegistered)
        try agent.install()
        XCTAssertEqual(service.status, .enabledViaLaunchAgent)
        primary.status = .requiresApproval  // az SMAppService állapota az erősebb (jóváhagyás gombja kell)
        XCTAssertEqual(service.status, .requiresApproval)
    }

    func testUnregisterRemovesBothAndIgnoresSMAppServiceError() throws {
        let primary = MockLoginItemService(status: .notFound)
        primary.unregisterError = LoginItemTestError()
        let service = makeService(primary)
        try agent.install()
        try service.unregister()
        XCTAssertEqual(primary.calls, ["unregister"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: agent.plistURL.path))
        XCTAssertEqual(service.status, .notFound)
    }

    func testUnregisterSurfacesErrorWhenSMAppServiceStaysEnabled() {
        let primary = MockLoginItemService(status: .enabled)
        primary.unregisterError = LoginItemTestError()
        XCTAssertThrowsError(try makeService(primary).unregister())
    }

    func testUnregisterLeavesForeignPlistAlone() throws {
        let primary = MockLoginItemService(status: .notRegistered)
        try writePlist(["Label": "com.example.other", "ProgramArguments": ["/bin/true"]])
        try makeService(primary).unregister()
        XCTAssertTrue(FileManager.default.fileExists(atPath: agent.plistURL.path))
    }

    func testToggleOnAndOffThroughController() throws {
        let primary = MockLoginItemService(status: .notFound)
        primary.statusAfterRegister = .notFound
        let controller = LoginItemController(service: makeService(primary), locate: { .applications })
        XCTAssertEqual(controller.state, LoginItemState(isOn: false, canToggle: true, note: nil, showsOpenSettings: false))
        try controller.setEnabled(true)
        XCTAssertEqual(controller.state, LoginItemState(isOn: true, canToggle: true, note: .launchAgent, showsOpenSettings: false))
        try controller.setEnabled(false)
        XCTAssertFalse(agent.isInstalled)
        XCTAssertFalse(controller.state.isOn)
    }

    func testUninstallRemovesPlist() throws {
        let primary = MockLoginItemService(status: .notFound)
        let controller = LoginItemController(service: makeService(primary), locate: { .applications })
        try agent.install()
        controller.refresh()
        XCTAssertTrue(try controller.unregisterIfRegistered())
        XCTAssertFalse(FileManager.default.fileExists(atPath: agent.plistURL.path))
        XCTAssertEqual(controller.status, .notRegistered)
    }

    func testErrorMessagesAreLocalized() {
        let error = LaunchAgentError.notRegularFile("/x.plist")
        AppLanguage.override = .en
        XCTAssertEqual(error.localizedDescription, "Refusing to write /x.plist: it is a symbolic link or not a regular file.")
        AppLanguage.override = .hu
        XCTAssertEqual(error.localizedDescription, "A(z) /x.plist nem írható: szimbolikus link vagy nem szabályos fájl.")
        for key in ["Could not write %@: %@", "Could not remove %@: %@",
                    "Enabled via a login LaunchAgent (applies at next login)."] {
            XCTAssertNotNil(L10n.hungarian[key], key)
        }
    }
}
