import Foundation
import Security
import os

public enum SecretField: String, CaseIterable, Sendable {
    case username, password, psk
}

public protocol SecretStore: AnyObject {
    func get(_ id: UUID, field: SecretField) -> String?
    /// Üres érték törli a mezőt.
    func set(_ value: String, for id: UUID, field: SecretField)
    func deleteAll(for id: UUID)
    /// Az összes MacVPN bejegyzés törlése (eltávolításkor; a már törölt kapcsolatok maradékát is).
    func removeAll()
}

public extension SecretStore {
    func secrets(for id: UUID) -> Secrets {
        Secrets(username: get(id, field: .username), password: get(id, field: .password), psk: get(id, field: .psk))
    }
}

/// Raw generic-password access, behind a protocol so the store logic (and the service migration) is testable
/// without the real keychain.
public protocol KeychainBackend: AnyObject {
    func read(service: String, account: String) -> Data?
    /// Creates or updates the item. False on error.
    @discardableResult func write(_ data: Data, service: String, account: String) -> Bool
    func delete(service: String, account: String)
    /// Every account name stored under `service`.
    func accounts(service: String) -> [String]
}

public final class SystemKeychain: KeychainBackend {
    private static let log = Logger(subsystem: "local.macvpn", category: "keychain")

    public init() {}

    private func query(_ service: String, _ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    public func read(service: String, account: String) -> Data? {
        var q = query(service, account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            if status != errSecItemNotFound && status != errSecSuccess {
                Self.log.error("SecItemCopyMatching error: \(status)")
            }
            return nil
        }
        return data
    }

    @discardableResult
    public func write(_ data: Data, service: String, account: String) -> Bool {
        let q = query(service, account)
        let updateStatus = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecSuccess { return true }
        guard updateStatus == errSecItemNotFound else {
            Self.log.error("SecItemUpdate error: \(updateStatus)")
            return false
        }
        var add = q
        add[kSecValueData as String] = data
        let field = account.split(separator: ".").last.map(String.init) ?? ""
        add[kSecAttrLabel as String] = "MacVPN: \(field)"
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus != errSecSuccess { Self.log.error("SecItemAdd error: \(addStatus)") }
        return addStatus == errSecSuccess
    }

    /// A régi (fájl alapú) kulcskarikán egy hívás néha csak egyet töröl, ezért ismételjük (felső korláttal).
    public func delete(service: String, account: String) {
        for _ in 0..<100 {
            let status = SecItemDelete(query(service, account) as CFDictionary)
            if status == errSecItemNotFound { return }
            if status != errSecSuccess {
                Self.log.error("SecItemDelete error: \(status)")
                return
            }
        }
    }

    public func accounts(service: String) -> [String] {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecReturnAttributes as String: true,
                                kSecMatchLimit as String: kSecMatchLimitAll]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &items)
        guard status == errSecSuccess, let list = items as? [[String: Any]] else {
            if status != errSecItemNotFound && status != errSecSuccess {
                Self.log.error("SecItemCopyMatching (list) error: \(status)")
            }
            return []
        }
        return list.compactMap { $0[kSecAttrAccount as String] as? String }
    }
}

/// In-memory `KeychainBackend` for tests.
public final class InMemoryKeychain: KeychainBackend {
    private var items: [String: [String: Data]] = [:]
    /// Simulates a failing keychain write.
    public var failWrites = false

    public init() {}

    public func read(service: String, account: String) -> Data? { items[service]?[account] }

    @discardableResult
    public func write(_ data: Data, service: String, account: String) -> Bool {
        guard !failWrites else { return false }
        items[service, default: [:]][account] = data
        return true
    }

    public func delete(service: String, account: String) { items[service]?[account] = nil }

    public func accounts(service: String) -> [String] { (items[service] ?? [:]).keys.sorted() }
}

/// Generic passwords: service `local.macvpn.secrets`, account `<UUID>.<field>`. Earlier versions used the service
/// `macvpn`; `migrateLegacyItems()` moves those over.
public final class KeychainSecretStore: SecretStore {
    public static let defaultService = "local.macvpn.secrets"
    public static let legacyService = "macvpn"

    let service: String
    let legacyService: String
    let backend: KeychainBackend

    public init(service: String = KeychainSecretStore.defaultService,
                legacyService: String = KeychainSecretStore.legacyService,
                backend: KeychainBackend = SystemKeychain()) {
        self.service = service
        self.legacyService = legacyService
        self.backend = backend
    }

    private func account(_ id: UUID, _ field: SecretField) -> String { "\(id.uuidString).\(field.rawValue)" }

    /// `<UUID>.<username|password|psk>`: the account names MacVPN writes.
    public static func isOurAccount(_ account: String) -> Bool {
        guard let dot = account.lastIndex(of: ".") else { return false }
        return UUID(uuidString: String(account[..<dot])) != nil
            && SecretField(rawValue: String(account[account.index(after: dot)...])) != nil
    }

    public func get(_ id: UUID, field: SecretField) -> String? {
        backend.read(service: service, account: account(id, field)).flatMap { String(data: $0, encoding: .utf8) }
    }

    public func set(_ value: String, for id: UUID, field: SecretField) {
        if value.isEmpty {
            backend.delete(service: service, account: account(id, field))
        } else {
            backend.write(Data(value.utf8), service: service, account: account(id, field))
        }
    }

    public func deleteAll(for id: UUID) {
        for field in SecretField.allCases { backend.delete(service: service, account: account(id, field)) }
    }

    /// The new service's items, plus any of our items left under the legacy service. Others' items are not touched.
    public func removeAll() {
        for account in backend.accounts(service: service) { backend.delete(service: service, account: account) }
        for account in backend.accounts(service: legacyService) where Self.isOurAccount(account) {
            backend.delete(service: legacyService, account: account)
        }
    }

    /// One-time move from the legacy service: read, write the new item, read it back, then delete the old one.
    /// Idempotent and safe to interrupt: an existing new item is never overwritten (it is newer), and the old item
    /// is deleted only once the new one holds the value. Returns the number of legacy items removed.
    @discardableResult
    public func migrateLegacyItems() -> Int {
        var moved = 0
        for account in backend.accounts(service: legacyService) where Self.isOurAccount(account) {
            if backend.read(service: service, account: account) == nil {
                guard let data = backend.read(service: legacyService, account: account),
                      backend.write(data, service: service, account: account),
                      backend.read(service: service, account: account) == data else { continue }
            }
            backend.delete(service: legacyService, account: account)
            moved += 1
        }
        return moved
    }
}

public final class InMemorySecretStore: SecretStore {
    private var values: [String: String] = [:]

    public init() {}

    public func get(_ id: UUID, field: SecretField) -> String? { values["\(id).\(field)"] }

    public func set(_ value: String, for id: UUID, field: SecretField) {
        values["\(id).\(field)"] = value.isEmpty ? nil : value
    }

    public func deleteAll(for id: UUID) {
        for field in SecretField.allCases { values["\(id).\(field)"] = nil }
    }

    public func removeAll() { values.removeAll() }
}
