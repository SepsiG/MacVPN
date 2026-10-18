import Foundation

/// A kapcsolatok sorrendje (spec 10e): a kitűzöttek felül, a felhasználó sorrendjében; alattuk a többi a
/// használat szerint (sikeres csatlakozásonként 1 pont, 14 napos felezési idővel csökkenve), egyenlőségnél név
/// szerint. A kulcs a managed kapcsolat UUID-ja (`uuidString`) vagy a rendszer-VPN scutil szolgáltatás-ID-ja:
/// ugyanaz a kulcs, mint a `ConnectionManager.states`-ben. Tiszta érték: az órát a hívó adja.
public struct ConnectionRanking: Codable, Equatable, Sendable {
    public struct UsageStats: Codable, Equatable, Sendable {
        /// A pontszám a `lastUpdated` időpontban.
        public var score: Double
        public var lastUpdated: Date

        public init(score: Double, lastUpdated: Date) {
            self.score = score
            self.lastUpdated = lastUpdated
        }
    }

    public static let halfLife: TimeInterval = 14 * 24 * 60 * 60

    /// Kitűzött kulcsok, a megjelenítés sorrendjében.
    public private(set) var pinned: [String]
    public private(set) var usage: [String: UsageStats]

    public init(pinned: [String] = [], usage: [String: UsageStats] = [:]) {
        self.pinned = pinned
        self.usage = usage
    }

    /// `score` csökkentve `from`-tól `to`-ig. Visszafelé járó óránál (`to < from`) nem nő.
    public static func decayed(_ score: Double, from: Date, to: Date) -> Double {
        let elapsed = max(0, to.timeIntervalSince(from))
        return score * pow(0.5, elapsed / halfLife)
    }

    public func score(id: String, at now: Date) -> Double {
        guard let stats = usage[id] else { return 0 }
        return Self.decayed(stats.score, from: stats.lastUpdated, to: now)
    }

    /// Sikeres csatlakozás: a pontszám `now`-ra csökkentve, majd +1.
    public mutating func recordSuccess(id: String, at now: Date) {
        usage[id] = UsageStats(score: score(id: id, at: now) + 1, lastUpdated: max(now, usage[id]?.lastUpdated ?? now))
    }

    public func isPinned(_ id: String) -> Bool { pinned.contains(id) }

    /// A kitűzöttek végére kerül; már kitűzöttnél nincs változás.
    public mutating func pin(_ id: String) {
        if !pinned.contains(id) { pinned.append(id) }
    }

    public mutating func unpin(_ id: String) {
        pinned.removeAll { $0 == id }
    }

    /// Húzás a látható kitűzött listában (a SwiftUI `onMove` paraméterei). A `visible` a kitűzött kulcsok
    /// jelenleg látható sorrendje; a nem látható (pl. épp nem listázott rendszer-VPN) kitűzöttek a végén maradnak.
    public mutating func movePinned(visible: [String], fromOffsets source: IndexSet, toOffset destination: Int) {
        var moved = visible
        let items = source.sorted().compactMap { $0 < moved.count ? moved[$0] : nil }
        let insertAt = destination - source.filter { $0 < destination }.count
        for index in source.sorted(by: >) where index < moved.count { moved.remove(at: index) }
        moved.insert(contentsOf: items, at: max(0, min(insertAt, moved.count)))
        let rest = pinned.filter { !moved.contains($0) }
        pinned = moved.filter { pinned.contains($0) } + rest
    }

    /// A nem létező kapcsolatok bejegyzéseinek törlése. true: változott.
    @discardableResult
    public mutating func prune(keeping ids: Set<String>) -> Bool {
        let before = self
        pinned.removeAll { !ids.contains($0) }
        usage = usage.filter { ids.contains($0.key) }
        return before != self
    }

    /// A sorrend: a `pinned` szerinti kitűzöttek elöl, utánuk a többi csökkenő pontszám, majd név szerint
    /// (kis- és nagybetűtől függetlenül, a nyelv szabályai szerint), végül kulcs szerint (stabil).
    public static func order(ids: [String], pinned: [String], now: Date,
                             score: (String) -> Double, name: (String) -> String) -> [String] {
        let present = Set(ids)
        var seen = Set<String>()
        let top = pinned.filter { present.contains($0) && seen.insert($0).inserted }
        let rest = ids.filter { !seen.contains($0) }
        let scores = Dictionary(rest.map { ($0, score($0)) }, uniquingKeysWith: { a, _ in a })
        let sorted = rest.sorted { a, b in
            let sa = scores[a] ?? 0, sb = scores[b] ?? 0
            if sa != sb { return sa > sb }
            switch name(a).localizedCaseInsensitiveCompare(name(b)) {
            case .orderedAscending: return true
            case .orderedDescending: return false
            case .orderedSame: return a < b
            }
        }
        return top + sorted
    }

    /// `order(ids:pinned:now:score:name:)` a tárolt kitűzésekkel és pontszámokkal.
    public func order(ids: [String], now: Date, name: (String) -> String) -> [String] {
        Self.order(ids: ids, pinned: pinned, now: now, score: { score(id: $0, at: now) }, name: name)
    }
}

/// `~/Library/Application Support/MacVPN/connection-order.json` (0600, atomi írás). Nem titkos, nem exportált.
public final class ConnectionRankingStore {
    public let url: URL

    public static var defaultURL: URL {
        ConnectionStore.applicationSupportDirectory.appendingPathComponent("connection-order.json")
    }

    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    public init(url: URL = ConnectionRankingStore.defaultURL) {
        self.url = url
    }

    /// Hiányzó vagy hibás fájl: üres sorrend (nincs mit megőrizni belőle).
    public func load() -> ConnectionRanking {
        guard let data = try? Data(contentsOf: url),
              let ranking = try? decoder.decode(ConnectionRanking.self, from: data) else { return ConnectionRanking() }
        return ranking
    }

    public func save(_ ranking: ConnectionRanking) throws {
        let dir = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        try ConnectionStore.writePrivate(try encoder.encode(ranking), to: url)
    }
}
