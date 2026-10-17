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
    /// Minden sikeres `scutil --nc list` után: azok a managed natív kapcsolatok, amelyek szolgáltatása listázva van.
    public var onNativeServicesSeen: ((Set<UUID>) -> Void)?
    /// Az utolsó sikeres listázás szerint telepített managed natív kapcsolatok.
    public private(set) var installedNativeIDs: Set<UUID> = []
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
    static func serverMismatchReason(_ name: String) -> String {
        L10n.tr("The server address of the VPN service named “%@” does not match this connection’s server. MacVPN does not pass the password or the PSK to it: reinstall the profile in MacVPN → Connections, or remove the other service in System Settings → Network.", name)
    }
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
    /// `scutil --nc show` eredménye szolgáltatásonként (a kötéshez). A `reload` üríti.
    private var remoteAddresses: [String: String?] = [:]

    public init(store: ConnectionStore, secrets: SecretStore, mvpn: MvpnClient, native: NativeVPNController) {
        self.store = store
        self.secrets = secrets
        self.mvpn = mvpn
        self.native = native
    }

    public func reload() {
        if let list = try? store.list() { connections = list }
        remoteAddresses = [:]
    }

    /// A kapcsolat legfrissebb (kötött azonosítójú) példánya.
    private func current(_ c: Connection) -> Connection { connections.first { $0.id == c.id } ?? c }

    // MARK: - Natív szolgáltatás egyeztetése

    enum NativeMatch: Equatable {
        case service(SystemVPNService)
        case none
        /// Nincs kötött azonosító, és több azonos nevű szolgáltatás van.
        case ambiguous([SystemVPNService])
    }

    /// Kötött azonosítónál csak az számít (eltűnt: `.none`); különben a név, egyértelmű egyezéssel.
    static func match(_ c: Connection, in services: [SystemVPNService]) -> NativeMatch {
        if let id = c.nativeServiceID {
            return services.first { $0.id == id }.map(NativeMatch.service) ?? .none
        }
        let name = c.nativeServiceName ?? c.name
        let named = services.filter { $0.name == name }
        switch named.count {
        case 0: return .none
        case 1: return .service(named[0])
        default: return .ambiguous(named)
        }
    }

    /// A managed natív kapcsolatokhoz tartozó szolgáltatás-azonosítók (ezek nem jelennek meg rendszer VPN-ként).
    /// Kötetlen kapcsolatnál az összes azonos nevű.
    static func managedServiceIDs(_ connections: [Connection], in services: [SystemVPNService]) -> Set<String> {
        var ids = Set<String>()
        for c in connections where c.kind.isNative {
            switch match(c, in: services) {
            case .service(let s): ids.insert(s.id)
            case .ambiguous(let all): ids.formUnion(all.map(\.id))
            case .none: break
            }
        }
        return ids
    }

    /// Kötés: a kötött, de eltűnt azonosító törlődik; a kötetlen kapcsolat az első olyan azonos nevű szolgáltatáshoz
    /// kötődik, amelynek a szervercíme is egyezik (és még nincs más kapcsolathoz kötve). A `meta.json`-ba menti.
    private func bindNativeServices(_ services: [SystemVPNService]) async {
        let listed = Set(services.map(\.id))
        remoteAddresses = remoteAddresses.filter { listed.contains($0.key) }
        for c in connections where c.kind.isNative {
            var updated = c
            if let id = c.nativeServiceID {
                guard !listed.contains(id) else { continue }
                updated.nativeServiceID = nil
            }
            if updated.nativeServiceID == nil, let server = c.native?.server, !server.isEmpty {
                let taken = Set(connections.compactMap(\.nativeServiceID))
                let name = c.nativeServiceName ?? c.name
                for s in services where s.name == name && !taken.contains(s.id) {
                    let address: String?
                    if let cached = remoteAddresses[s.id] { address = cached } else {
                        address = await native.remoteAddress(serviceID: s.id)
                        remoteAddresses[s.id] = address
                    }
                    if address?.lowercased() == server.lowercased() {
                        updated.nativeServiceID = s.id
                        break
                    }
                }
            }
            guard updated.nativeServiceID != c.nativeServiceID,
                  let index = connections.firstIndex(where: { $0.id == c.id }) else { continue }
            connections[index] = updated
            try? store.save(updated, config: nil)
        }
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
        if let services { await bindNativeServices(services) }

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
        var toStop: [String] = []

        for c in connections {
            let key = c.id.uuidString
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
                let service: SystemVPNService?
                switch Self.match(c, in: services) {
                case .service(let s): service = s
                case .ambiguous(let all): service = all.first
                case .none: service = nil
                }
                if let pending = evaluateAwaiting(key: key, name: c.name, service: service,
                                                  failureReason: { Self.nativeFailureReason }, toStop: &toStop) {
                    next[key] = pending
                    continue
                }
                current = service?.connectionState ?? .disconnected
            } else {
                guard let root else { next[key] = previous ?? .disconnected; continue }
                current = root.first(where: { $0.id == c.id })?.connectionState ?? .disconnected
            }
            next[key] = resolve(key: key, name: c.name, previous: previous, current: current, nativeLike: c.kind.isNative)
        }

        if let services {
            let managed = Self.managedServiceIDs(connections, in: services)
            installedNativeIDs = Set(connections.filter {
                guard $0.kind.isNative else { return false }
                if case .none = Self.match($0, in: services) { return false }
                return true
            }.map(\.id))
            let unmanaged = services.filter { !managed.contains($0.id) }
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
                if let pending = evaluateAwaiting(key: s.id, name: s.name, service: s,
                                                  failureReason: { self.systemFailureReason(s) }, toStop: &toStop) {
                    next[s.id] = pending
                    continue
                }
                next[s.id] = resolve(key: s.id, name: s.name, previous: previous,
                                     current: s.connectionState, nativeLike: true)
            }
            systemServices = unmanaged
        } else {
            for s in systemServices {
                if !stale(s.id), case .awaitingNative(let started, _, let sid)? = ops[s.id],
                   now().timeIntervalSince(started) > Self.nativeTimeout {
                    toStop.append(sid)
                    next[s.id] = failNative(s.id, s.name, reason: L10n.tr("Timed out"))
                } else if let st = states[s.id] {
                    next[s.id] = st
                }
            }
        }
        states = next
        let events = queuedEvents
        queuedEvents = []
        for event in events { onEvent?(event) }
        if services != nil { onNativeServicesSeen?(installedNativeIDs) }
        for id in toStop { try? await native.stop(serviceID: id) }
    }

    /// A függő natív indítás (`awaitingNative`) kiértékelése a friss scutil állapot alapján.
    /// nil: nincs függő indítás, vagy épp csatlakozott – a hívó a szolgáltatás állapotát használja.
    private func evaluateAwaiting(key: String, name: String, service: SystemVPNService?,
                                  failureReason: () -> String, toStop: inout [String]) -> ConnectionState? {
        guard case .awaitingNative(let started, let saw, let sid)? = ops[key] else { return nil }
        let elapsed = now().timeIntervalSince(started)
        switch service?.connectionState {
        case .connected?:
            setOp(key, nil)
            return nil
        case .connecting?:
            ops[key] = .awaitingNative(started: started, sawConnecting: true, serviceID: sid)
            if elapsed > Self.nativeTimeout {
                toStop.append(sid)
                return failNative(key, name, reason: L10n.tr("Timed out"))
            }
            return .connecting
        default:
            if saw || elapsed > Self.nativeGrace { return failNative(key, name, reason: failureReason()) }
            return .connecting
        }
    }

    /// Rendszer VPN hibája: PSK nélkül (L2TP / Cisco) arra utal, hogy a MacVPN-ben megadható.
    func systemFailureReason(_ s: SystemVPNService) -> String {
        if s.supportsStoredSecrets, let id = s.secretID, (secrets.get(id, field: .psk) ?? "").isEmpty {
            return L10n.tr("The connection did not come up. If this is an L2TP/IPsec VPN, enter its shared secret (PSK) in MacVPN → Connections → %@.", s.name)
        }
        return L10n.tr("The connection did not come up.")
    }

    /// A rendszer VPN-hez a MacVPN kulcskarikájában tárolt PSK/jelszó (csak L2TP / Cisco IPsec).
    public func systemSecrets(for s: SystemVPNService) -> Secrets {
        guard s.supportsStoredSecrets, let id = s.secretID else { return Secrets() }
        return Secrets(password: secrets.get(id, field: .password), psk: secrets.get(id, field: .psk))
    }

    private func failNative(_ key: String, _ name: String, reason: String) -> ConnectionState {
        setOp(key, nil)
        queuedEvents.append(.failed(connectionID: key, name: name, reason: reason))
        return .failed(reason)
    }

    // MARK: - Csatlakozás / bontás

    public func connect(_ c: Connection, debug: Bool) async {
        let c = current(c)
        let key = c.id.uuidString
        wantDown.remove(key)
        setOp(key, .connecting)
        states[key] = .connecting
        // Token: csak az a hívás írhatja a kulcsot, amelynek a művelete még a legfrissebb.
        var token = keyEpoch[key]
        do {
            if c.kind.isNative {
                let name = c.nativeServiceName ?? c.name
                let service: SystemVPNService
                switch Self.match(c, in: try await native.list()) {
                case .service(let s):
                    // Kötetlen kapcsolat csak név szerint egyezett: a titkot csak akkor kaphatja, ha a szolgáltatás
                    // szervercíme (`scutil --nc show`, frissen lekérve) a kapcsolat szervere. Különben titok nélkül sem indul.
                    if c.nativeServiceID == nil {
                        let address = await native.remoteAddress(serviceID: s.id)
                        remoteAddresses[s.id] = address
                        guard let server = c.native?.server, !server.isEmpty,
                              address?.lowercased() == server.lowercased() else {
                            throw MvpnError.failed(Self.serverMismatchReason(name))
                        }
                    }
                    service = s
                case .none: throw MvpnError.failed(L10n.tr("The profile is not installed: %@", name))
                case .ambiguous:
                    // Nem tudni, melyik a miénk: a jelszót / PSK-t nem adjuk át egy esetleg idegen szolgáltatásnak.
                    throw MvpnError.failed(L10n.tr("More than one VPN service is named “%@”. MacVPN does not pass the password until it is clear which one is its own: rename or remove the other one in System Settings → Network.", name))
                }
                try await native.start(serviceID: service.id, kind: NativeKind(kind: c.kind),
                                       secrets: secrets.secrets(for: c.id))
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
        let c = current(c)
        let key = c.id.uuidString
        wantDown.insert(key)
        setOp(key, .disconnecting)
        let token = keyEpoch[key]
        states[key] = .disconnecting
        do {
            if c.kind.isNative {
                switch Self.match(c, in: try await native.list()) {
                case .service(let s): try await native.stop(serviceID: s.id)
                case .ambiguous(let all):
                    // Bontásnál nincs titok: az összes aktív azonos nevűt leállítjuk.
                    for s in all where s.connectionState.isActive { try await native.stop(serviceID: s.id) }
                case .none: break
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
        let key = s.id
        wantDown.remove(key)
        setOp(key, .connecting)
        states[key] = .connecting
        let token = keyEpoch[key]
        do {
            try await native.start(serviceID: s.id, kind: NativeKind(typeLabel: s.typeLabel), secrets: systemSecrets(for: s))
            guard keyEpoch[key] == token else {
                if wantDown.contains(key) {
                    try? await native.stop(serviceID: s.id)
                    settleAfterTeardown(key)
                }
                return
            }
            // Mint a managed natívnál: a tényleges eredményt a refresh dönti el, így a hiba nem csendes "bontva".
            setOp(key, .awaitingNative(started: now(), sawConnecting: false, serviceID: s.id))
            states[key] = .connecting
        } catch {
            guard keyEpoch[key] == token else { return }
            let reason = error.localizedDescription
            states[key] = .failed(reason)
            setOp(key, nil)
            onEvent?(.failed(connectionID: key, name: s.name, reason: reason))
        }
    }

    public func disconnectSystem(_ s: SystemVPNService) async {
        wantDown.insert(s.id)
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
