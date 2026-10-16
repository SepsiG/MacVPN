import XCTest
@testable import MacVPNCore

final class SecretStoreTests: XCTestCase {
    func exercise(_ store: SecretStore) {
        let id = UUID()
        defer { store.deleteAll(for: id) }
        store.set("bob", for: id, field: .username)
        store.set("s3cret", for: id, field: .password)
        store.set("s3cret2", for: id, field: .password)
        XCTAssertEqual(store.get(id, field: .username), "bob")
        XCTAssertEqual(store.secrets(for: id), Secrets(username: "bob", password: "s3cret2", psk: nil))
        store.set("", for: id, field: .username)
        XCTAssertNil(store.get(id, field: .username))
        store.deleteAll(for: id)
        XCTAssertNil(store.get(id, field: .password))

        let a = UUID(), b = UUID()
        store.set("x", for: a, field: .password)
        store.set("y", for: b, field: .psk)
        store.removeAll()
        XCTAssertNil(store.get(a, field: .password))
        XCTAssertNil(store.get(b, field: .psk))
    }

    func testInMemory() { exercise(InMemorySecretStore()) }

    /// A GitHub runnereken a kulcskarika zárolva lehet: CI alatt kihagyjuk.
    func testKeychain() throws {
        try XCTSkipIf(ProcessInfo.processInfo.environment["CI"] != nil, "CI: a kulcskarika nem érhető el megbízhatóan")
        exercise(KeychainSecretStore(service: "macvpn.tests"))
    }
}
