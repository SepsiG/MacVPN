import Foundation
import Combine

public enum ConnectionEvent: Equatable, Sendable {
    case failed(connectionID: String, name: String, reason: String)
    case dropped(connectionID: String, name: String)
}

@MainActor
public final class ConnectionManager: ObservableObject {
    @Published public private(set) var connections: [Connection] = []
    /// Csak azok a rendszer VPN-ek, amelyeket nem az app kezel.
    @Published public private(set) var systemServices: [SystemVPNService] = []
    @Published public private(set) var states: [String: ConnectionState] = [:]
    /// Több egymás utáni sikertelen állapotlekérdezés után kitöltődik.
    @Published public private(set) var statusError: String?

    public var onEvent: ((ConnectionEvent) -> Void)?
    /// Tesztekhez injektálható óra.
    public var now: () -> Date = Date.init

    public let store: ConnectionStore
    public let secrets: SecretStore
    let mvpn: MvpnClient
    let native: NativeVPNController

    private enum Op {
        case connecting
        case disconnecting
        case awaitingNative(started: Date, sawConnecting: Bool, serviceID: String)
    }

    static let nativeGrace: TimeInterval = 5
    static let nativeTimeout: TimeInterval = 45
    static let statusErrorThreshold = 3
    static var nativeFailureReason: String { L10n.tr("The connection could not be established – for details, connect in debug mode") }

    private var ops: [String: Op] = [:]
    /// A felhasználó utoljára bontást kért (új connect törli): a késve sikerülő up-ot le kell bontani.
    private var wantDown: Set<String> = []
    private var queuedEvents: [ConnectionEvent] = []
    /// Monoton számláló: minden művelet-változás és refresh-indítás kap egyet.
    private var epoch = 0
    private var lastApplied = 0
    private var keyEpoch: [String: Int] = [:]
    private var failureStreak = 0

    public init(store: ConnectionStore, secrets: SecretStore, mvpn: MvpnClient, native: NativeVPNController) {
        self.store = store
        self.secrets = secrets
        self.mvpn = mvpn
        self.native = native
    }

    public func reload() {
        if let list = try? store.list() { connections = list }
    }

    public func state(for key: String) -> ConnectionState { states[key] ?? .disconnected }

    public var hasActive: Bool { states.values.contains { $0.isActive } }

    public var hasFailure: Bool {
        states.values.contains { if case .failed = $0 { return true } else { return false } }
    }

    // MARK: - Műveletek nyilvántartása

    private func setOp(_ key: String, _ op: Op?) {
        ops[key] = op
        epoch += 1
        keyEpoch[key] = epoch
    }

    /// Egy késve befejeződő up/start után: a bontást kérő felhasználó állapota `disconnected`.
    private func settleAfterTeardown(_ key: String) {
        if wantDown.contains(key), ops[key] == nil { states[key] = .disconnected }
    }

    /// Drop-észlelés és ragadós hiba. `nativeLike`: a drop után `disconnected`, nem `failed`.
    private func resolve(key: String, name: String, previous: ConnectionState?,
                         current: ConnectionState, nativeLike: Bool) -> ConnectionState {
        if previous?.isConnected == true {
            switch current {
            case .failed, .disconnected:
                queuedEvents.append(.dropped(connectionID: key, name: name))
                return nativeLike ? .disconnected : .failed(L10n.tr("The connection dropped"))
            default: break
            }
        }
        if case .failed? = previous {
            switch current {
            case .failed, .disconnected: return previous!
            default: break
            }
        }
        return current
    }

    // MARK: - Refresh

    public func refresh() async {
        epoch += 1
        let start = epoch
        var failure: String?
        let root: [RootStatus]?
        if connections.contains(where: { !$0.kind.isNative }) {
            do { root = try await mvpn.status() } catch { root = nil; failure = error.localizedDescription }
        } else {
            root = []   // nincs root-os kapcsolat: nem kérdezünk (sudo), és nem hiba
        }
        let services: [SystemVPNService]?
        do { services = try await native.list() } catch { services = nil; failure = failure ?? error.localizedDescription }

        guard start >= lastApplied else { return }   // egy újabb refresh már érvényesült
        lastApplied = start

        if let failure {
            failureStreak += 1
            if failureStreak >= Self.statusErrorThreshold {
                statusError = L10n.tr("Cannot query the status: %@", failure)
            }
        } else {
            failureStreak = 0
            statusError = nil
        }

        func stale(_ key: String) -> Bool { (keyEpoch[key] ?? 0) > start }

        var next: [String: ConnectionState] = [:]
        var managedNativeNames = Set<String>()
        var toStop: [String] = []

        for c in connections {
            let key = c.id.uuidString
            let name = c.nativeServiceName ?? c.name
            if c.kind.isNative { managedNativeNames.insert(name) }
            let previous = states[key]
            if stale(key) {
                if let previous { next[key] = previous }
                continue
            }
            switch ops[key] {
            case .connecting?: next[key] = .connecting; continue
            case .disconnecting?: next[key] = .disconnecting; continue
            default: break
            }

            var current: ConnectionState
            if c.kind.isNative {
                if case .awaitingNative(let started, _, let sid)? = ops[key], services == nil,
                   now().timeIntervalSince(started) > Self.nativeTimeout {
                    toStop.append(sid)
                    next[key] = failNative(key, c.name, reason: L10n.tr("Timed out"))
                    continue
                }
                guard let services else { next[key] = previous ?? .disconnected; continue }
                let service = services.first { $0.name == name }
                if case .awaitingNative(let started, let saw, let sid)? = ops[key] {
                    let elapsed = now().timeIntervalSince(started)
                    switch service?.connectionState {
                    case .connected?:
                        setOp(key, nil)
                        current = service!.connectionState
                    case .connecting?:
                        ops[key] = .awaitingNative(started: started, sawConnecting: true, serviceID: sid)
                        if elapsed > Self.nativeTimeout {
                            toStop.append(sid)
                            next[key] = failNative(key, c.name, reason: L10n.tr("Timed out"))
                        } else {
                            next[key] = .connecting
                        }
                        continue
                    default:
                        if saw || elapsed > Self.nativeGrace {
                            next[key] = failNative(key, c.name, reason: Self.nativeFailureReason)
                        } else {
                            next[key] = .connecting
                        }
                        continue
                    }
                } else {
                    current = service?.connectionState ?? .disconnected
                }
            } else {
                guard let root else { next[key] = previous ?? .disconnected; continue }
                current = root.first(where: { $0.id == c.id })?.connectionState ?? .disconnected
            }
            next[key] = resolve(key: key, name: c.name, previous: previous, current: current, nativeLike: c.kind.isNative)
        }

        if let services {
            let unmanaged = services.filter { !managedNativeNames.contains($0.name) }
            for s in unmanaged {
                let previous = states[s.id]
                if stale(s.id) {
                    if let previous { next[s.id] = previous }
                    continue
                }
                switch ops[s.id] {
                case .connecting?: next[s.id] = .connecting; continue
                case .disconnecting?: next[s.id] = .disconnecting; continue
                default: break
                }
                next[s.id] = resolve(key: s.id, name: s.name, previous: previous,
                                     current: s.connectionState, nativeLike: true)
            }
            systemServices = unmanaged
        } else {
            for s in systemServices { if let st = states[s.id] { next[s.id] = st } }
        }
        states = next
        let events = queuedEvents
        queuedEvents = []
        for event in events { onEvent?(event) }
        for id in toStop { try? await native.stop(serviceID: id) }
    }

    private func failNative(_ key: String, _ name: String, reason: String) -> ConnectionState {
        setOp(key, nil)
        queuedEvents.append(.failed(connectionID: key, name: name, reason: reason))
        return .failed(reason)
    }

    // MARK: - Csatlakozás / bontás

    public func connect(_ c: Connection, debug: Bool) async {
        let key = c.id.uuidString
        wantDown.remove(key)
        setOp(key, .connecting)
        states[key] = .connecting
        // Token: csak az a hívás írhatja a kulcsot, amelynek a művelete még a legfrissebb.
        var token = keyEpoch[key]
        do {
            if c.kind.isNative {
                let name = c.nativeServiceName ?? c.name
                guard let service = try await native.list().first(where: { $0.name == name }) else {
                    throw MvpnError.failed(L10n.tr("The profile is not installed: %@", name))
                }
                try await native.start(serviceID: service.id)
                guard keyEpoch[key] == token else {
                    if wantDown.contains(key) {
                        try? await native.stop(serviceID: service.id)
                        settleAfterTeardown(key)
                    }
                    return
                }
                // A tényleges eredményt a refresh dönti el (lásd awaitingNative).
                setOp(key, .awaitingNative(started: now(), sawConnecting: false, serviceID: service.id))
                token = keyEpoch[key]
                states[key] = .connecting
            } else {
                try await mvpn.up(kind: c.kind, id: c.id, secrets: secrets.secrets(for: c.id), debug: debug)
                guard keyEpoch[key] == token else {
                    // Közben a felhasználó bontott: a sikeres tunnelt le kell bontani. Újabb connect érintetlen marad.
                    if wantDown.contains(key) {
                        try? await mvpn.down(kind: c.kind, id: c.id)
                        settleAfterTeardown(key)
                    }
                    return
                }
                states[key] = .connecting
                setOp(key, nil)
                await refresh()
            }
        } catch {
            guard keyEpoch[key] == token else { return }
            let reason = error.localizedDescription
            states[key] = .failed(reason)
            setOp(key, nil)
            onEvent?(.failed(connectionID: key, name: c.name, reason: reason))
        }
    }

    public func disconnect(_ c: Connection) async {
        let key = c.id.uuidString
        wantDown.insert(key)
        setOp(key, .disconnecting)
        let token = keyEpoch[key]
        states[key] = .disconnecting
        do {
            if c.kind.isNative {
                let name = c.nativeServiceName ?? c.name
                if let service = try await native.list().first(where: { $0.name == name }) {
                    try await native.stop(serviceID: service.id)
                }
            } else {
                try await mvpn.down(kind: c.kind, id: c.id)
            }
        } catch {
            if keyEpoch[key] == token {
                onEvent?(.failed(connectionID: key, name: c.name, reason: error.localizedDescription))
            }
        }
        if keyEpoch[key] == token {
            states[key] = .disconnected
            setOp(key, nil)
        }
        await refresh()
    }

    public func connectSystem(_ s: SystemVPNService) async {
        setOp(s.id, .connecting)
        states[s.id] = .connecting
        do { try await native.start(serviceID: s.id) } catch {
            states[s.id] = .failed(error.localizedDescription)
            setOp(s.id, nil)
            onEvent?(.failed(connectionID: s.id, name: s.name, reason: error.localizedDescription))
            return
        }
        states[s.id] = .connecting
        setOp(s.id, nil)
        await refresh()
    }

    public func disconnectSystem(_ s: SystemVPNService) async {
        setOp(s.id, .disconnecting)
        states[s.id] = .disconnecting
        try? await native.stop(serviceID: s.id)
        states[s.id] = .disconnected
        setOp(s.id, nil)
        await refresh()
    }

    /// Aktív managed kapcsolatok bontása (kilépéskor).
    public func disconnectAll() async {
        for c in connections where state(for: c.id.uuidString).isActive {
            await disconnect(c)
        }
    }
}
