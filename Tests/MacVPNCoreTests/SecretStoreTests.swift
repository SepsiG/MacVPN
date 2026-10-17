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

    func testKeychainStoreOverInMemoryBackend() {
        exercise(KeychainSecretStore(backend: InMemoryKeychain()))
    }

    func testDefaultServiceIsReverseDNS() {
        XCTAssertEqual(KeychainSecretStore.defaultService, "local.macvpn.secrets")
        XCTAssertEqual(KeychainSecretStore.legacyService, "macvpn")
        let backend = InMemoryKeychain()
        let id = UUID()
        KeychainSecretStore(backend: backend).set("pw", for: id, field: .password)
        XCTAssertEqual(backend.read(service: "local.macvpn.secrets", account: "\(id.uuidString).password"), Data("pw".utf8))
    }

    func testMigrationMovesLegacyItemsAndIsIdempotent() {
        let backend = InMemoryKeychain()
        let a = UUID(), b = UUID()
        backend.write(Data("old-pw".utf8), service: "macvpn", account: "\(a.uuidString).password")
        backend.write(Data("old-psk".utf8), service: "macvpn", account: "\(b.uuidString).psk")
        backend.write(Data("x".utf8), service: "macvpn", account: "not-ours")
        let store = KeychainSecretStore(backend: backend)
        XCTAssertEqual(store.migrateLegacyItems(), 2)
        XCTAssertEqual(store.get(a, field: .password), "old-pw")
        XCTAssertEqual(store.get(b, field: .psk), "old-psk")
        XCTAssertEqual(backend.accounts(service: "macvpn"), ["not-ours"])
        XCTAssertEqual(store.migrateLegacyItems(), 0)
        XCTAssertEqual(store.get(a, field: .password), "old-pw")
    }

    /// Megszakadt migráció (az új már megvan, a régi még nem törlődött): az új érték nyer, a régi törlődik.
    func testInterruptedMigrationKeepsTheNewValue() {
        let backend = InMemoryKeychain()
        let a = UUID()
        backend.write(Data("stale".utf8), service: "macvpn", account: "\(a.uuidString).password")
        backend.write(Data("current".utf8), service: "local.macvpn.secrets", account: "\(a.uuidString).password")
        let store = KeychainSecretStore(backend: backend)
        XCTAssertEqual(store.migrateLegacyItems(), 1)
        XCTAssertEqual(store.get(a, field: .password), "current")
        XCTAssertEqual(backend.accounts(service: "macvpn"), [])
    }

    func testFailedWriteKeepsTheLegacyItem() {
        let backend = InMemoryKeychain()
        let a = UUID()
        backend.write(Data("pw".utf8), service: "macvpn", account: "\(a.uuidString).password")
        backend.failWrites = true
        let store = KeychainSecretStore(backend: backend)
        XCTAssertEqual(store.migrateLegacyItems(), 0)
        XCTAssertEqual(backend.read(service: "macvpn", account: "\(a.uuidString).password"), Data("pw".utf8))
        backend.failWrites = false
        XCTAssertEqual(store.migrateLegacyItems(), 1)
        XCTAssertEqual(store.get(a, field: .password), "pw")
    }

    func testRemoveAllDeletesNewServiceAndOurLegacyLeftoversOnly() {
        let backend = InMemoryKeychain()
        let a = UUID(), b = UUID()
        backend.write(Data("1".utf8), service: "local.macvpn.secrets", account: "\(a.uuidString).password")
        backend.write(Data("2".utf8), service: "local.macvpn.secrets", account: "anything")
        backend.write(Data("3".utf8), service: "macvpn", account: "\(b.uuidString).psk")
        backend.write(Data("4".utf8), service: "macvpn", account: "someone-else")
        backend.write(Data("5".utf8), service: "macvpn", account: "\(b.uuidString).other")
        backend.write(Data("6".utf8), service: "other", account: "\(a.uuidString).password")
        KeychainSecretStore(backend: backend).removeAll()
        XCTAssertEqual(backend.accounts(service: "local.macvpn.secrets"), [])
        XCTAssertEqual(backend.accounts(service: "macvpn").sorted(), ["\(b.uuidString).other", "someone-else"])
        XCTAssertEqual(backend.accounts(service: "other").count, 1)
    }

    func testOurAccountPattern() {
        let id = UUID().uuidString
        XCTAssertTrue(KeychainSecretStore.isOurAccount("\(id).username"))
        XCTAssertTrue(KeychainSecretStore.isOurAccount("\(id.lowercased()).psk"))
        XCTAssertFalse(KeychainSecretStore.isOurAccount("\(id).token"))
        XCTAssertFalse(KeychainSecretStore.isOurAccount("x\(id).psk"))
        XCTAssertFalse(KeychainSecretStore.isOurAccount(id))
    }

    /// A GitHub runnereken a kulcskarika zárolva lehet: CI alatt kihagyjuk.
    func testKeychain() throws {
        try XCTSkipIf(ProcessInfo.processInfo.environment["CI"] != nil, "CI: a kulcskarika nem érhető el megbízhatóan")
        exercise(KeychainSecretStore(service: "local.macvpn.tests", legacyService: "macvpn.tests.legacy"))
    }

    func testKeychainMigration() throws {
        try XCTSkipIf(ProcessInfo.processInfo.environment["CI"] != nil, "CI: a kulcskarika nem érhető el megbízhatóan")
        let system = SystemKeychain()
        let store = KeychainSecretStore(service: "local.macvpn.tests.new", legacyService: "macvpn.tests.old", backend: system)
        defer { store.removeAll() }
        let id = UUID()
        system.write(Data("pw".utf8), service: "macvpn.tests.old", account: "\(id.uuidString).password")
        XCTAssertEqual(store.migrateLegacyItems(), 1)
        XCTAssertEqual(store.get(id, field: .password), "pw")
        XCTAssertNil(system.read(service: "macvpn.tests.old", account: "\(id.uuidString).password"))
        XCTAssertEqual(store.migrateLegacyItems(), 0)
    }
}
