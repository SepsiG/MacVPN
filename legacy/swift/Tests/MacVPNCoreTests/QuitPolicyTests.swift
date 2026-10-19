import XCTest
@testable import MacVPNCore

final class QuitPolicyTests: XCTestCase {
    func testAlreadyConfirmedTerminatesWithoutAsking() {
        XCTAssertEqual(QuitPolicy.decide(alreadyConfirmed: true, hasUnsavedChanges: true, hasActiveConnections: true), .terminateNow)
    }

    func testNothingToAskTerminatesNow() {
        XCTAssertEqual(QuitPolicy.decide(alreadyConfirmed: false, hasUnsavedChanges: false, hasActiveConnections: false), .terminateNow)
    }

    func testUnsavedChangesAsk() {
        XCTAssertEqual(QuitPolicy.decide(alreadyConfirmed: false, hasUnsavedChanges: true, hasActiveConnections: false), .ask)
    }

    func testActiveConnectionsAsk() {
        XCTAssertEqual(QuitPolicy.decide(alreadyConfirmed: false, hasUnsavedChanges: false, hasActiveConnections: true), .ask)
    }
}
