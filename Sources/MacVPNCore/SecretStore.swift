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

public final class KeychainSecretStore: SecretStore {
    let service: String

    public init(service: String = "macvpn") {
        self.service = service
    }

    private func query(_ id: UUID, _ field: SecretField) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "\(id.uuidString).\(field.rawValue)"]
    }

    private static let log = Logger(subsystem: "local.macvpn", category: "keychain")

    public func get(_ id: UUID, field: SecretField) -> String? {
        var q = query(id, field)
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
        return String(data: data, encoding: .utf8)
    }

    public func set(_ value: String, for id: UUID, field: SecretField) {
        let q = query(id, field)
        guard !value.isEmpty else {
            let status = SecItemDelete(q as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound { Self.log.error("SecItemDelete error: \(status)") }
            return
        }
        let data = Data(value.utf8)
        let updateStatus = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            Self.log.error("SecItemUpdate error: \(updateStatus)")
            return
        }
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "MacVPN: \(field.rawValue)"
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus != errSecSuccess { Self.log.error("SecItemAdd error: \(addStatus)") }
    }

    public func deleteAll(for id: UUID) {
        for field in SecretField.allCases { SecItemDelete(query(id, field) as CFDictionary) }
    }

    /// A szolgáltatás összes bejegyzése. A régi (fájl alapú) kulcskarikán egy hívás néha csak egyet töröl,
    /// ezért ismételjük, amíg talál (felső korláttal).
    public func removeAll() {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        for _ in 0..<1000 {
            let status = SecItemDelete(q as CFDictionary)
            if status == errSecItemNotFound { return }
            if status != errSecSuccess {
                Self.log.error("SecItemDelete error: \(status)")
                return
            }
        }
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
