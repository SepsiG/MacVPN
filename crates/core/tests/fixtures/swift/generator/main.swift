// Writes the Swift-side compatibility fixtures for the Rust core (crates/core/tests/compat_swift.rs).
// Built together with legacy/swift/Sources/MacVPNCore/*.swift by generate.sh; it uses the real ConnectionStore,
// ConnectionRankingStore and SystemOTPStore, so the files are byte-for-byte what MacVPN 0.4.0 writes.
// Usage: gen <fixtures dir> <scratch dir>
import Foundation

let args = CommandLine.arguments
let out = URL(fileURLWithPath: args[1], isDirectory: true)
let scratch = URL(fileURLWithPath: args[2], isDirectory: true)
let fm = FileManager.default
try? fm.removeItem(at: scratch)
try fm.createDirectory(at: scratch, withIntermediateDirectories: true)

func write(_ text: String, _ path: String) throws {
    let url = out.appendingPathComponent(path)
    try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data(text.utf8).write(to: url)
}

func copy(_ from: URL, _ path: String) throws {
    let url = out.appendingPathComponent(path)
    try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? fm.removeItem(at: url)
    try fm.copyItem(at: from, to: url)
}

func date(_ s: String) -> Date { ISO8601DateFormatter().date(from: s)! }
func uuid(_ s: String) -> UUID { UUID(uuidString: s)! }

// MARK: meta.json, as ConnectionStore.save writes it

let created = date("2026-10-16T17:55:00Z")
var samples: [(String, Connection)] = []
samples.append(("openvpn-minimal", Connection(id: uuid("11111111-2222-3333-4444-555555555555"), name: "Iroda", kind: .openvpn,
                                              createdAt: created)))
samples.append(("openvpn-full", Connection(id: uuid("0A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9"), name: "Office VPN", kind: .openvpn,
                                           createdAt: Date(timeIntervalSince1970: 1_792_173_300.75),
                                           acknowledgedRiskyDirectives: ["group", "user"],
                                           otp: OTPSetting(enabled: true, separator: .colon))))
samples.append(("wireguard", Connection(id: uuid("22222222-3333-4444-5555-666666666666"), name: "WG", kind: .wireguard,
                                        createdAt: date("2000-02-29T23:59:59Z"))))
samples.append(("strongswan", Connection(id: uuid("33333333-4444-5555-6666-777777777777"), name: "IKEv2 – Iroda", kind: .strongswan,
                                         createdAt: date("1970-01-01T00:00:00Z"), otp: OTPSetting(enabled: true, separator: .none))))
samples.append(("sstp", Connection(id: uuid("44444444-5555-6666-7777-888888888888"), name: "SSTP", kind: .sstp,
                                   createdAt: date("2099-12-31T23:59:59Z"), otp: OTPSetting(enabled: false, separator: .comma))))
var l2tp = Connection(id: uuid("55555555-6666-7777-8888-999999999999"), name: "Office L2TP", kind: .l2tp, createdAt: created,
                      nativeServiceName: "MacVPN Office L2TP",
                      native: NativeSettings(server: "vpn.example.com", account: "bob", groupName: "", sendAllTraffic: true))
l2tp.nativeServiceID = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4"
samples.append(("l2tp", l2tp))
samples.append(("cisco", Connection(id: uuid("66666666-7777-8888-9999-AAAAAAAAAAAA"), name: "Cisco", kind: .cisco, createdAt: created,
                                    nativeServiceName: "MacVPN Cisco",
                                    native: NativeSettings(server: "10.0.0.1", account: "alice", groupName: "staff", sendAllTraffic: false))))
samples.append(("special-chars", Connection(id: uuid("77777777-8888-9999-AAAA-BBBBBBBBBBBB"),
                                            name: "a/b \"q\" \\ \t\n\r\u{1}\u{8}\u{C}\u{1F}\u{7F} é 🇭🇺 \u{2028} <&> ' ~",
                                            kind: .openvpn, createdAt: created, acknowledgedRiskyDirectives: ["future-option"])))

let metaStore = ConnectionStore(baseURL: scratch.appendingPathComponent("meta"))
for (name, c) in samples {
    try metaStore.save(c, config: nil)
    try copy(metaStore.directory(for: c.id).appendingPathComponent("meta.json"), "meta/\(name).json")
}

// MARK: Decoding: hand-written inputs → what Swift loads and writes back (or INVALID)

let inputs = out.appendingPathComponent("inputs/meta")
for file in try fm.contentsOfDirectory(atPath: inputs.path).sorted() where file.hasSuffix(".json") {
    let store = ConnectionStore(baseURL: scratch.appendingPathComponent("decode-\(file)"))
    let dir = store.baseURL.appendingPathComponent(UUID().uuidString)
    try fm.createDirectory(at: dir, withIntermediateDirectories: true)
    try fm.copyItem(at: inputs.appendingPathComponent(file), to: dir.appendingPathComponent("meta.json"))
    let loaded = try store.list()
    if let c = loaded.first {
        let back = ConnectionStore(baseURL: scratch.appendingPathComponent("reencode-\(file)"))
        try back.save(c, config: nil)
        try copy(back.directory(for: c.id).appendingPathComponent("meta.json"), "decoded/meta/\(file)")
    } else {
        try write("INVALID\n", "decoded/meta/\(file)")
    }
}

// MARK: list() order (localizedCaseInsensitiveCompare under the process locale; generate.sh pins en_US)

let names = ["b", "A", "éjszakai", "Ember", "alpha", "Zulu", "zulu2", "10", "9", "Árvíztűrő", "arvizturo", "Office", "office",
             "Cs", "Cz", "ß", "ss", "Ö", "Oz", "x-y", "x_y", "x y", "xy"]
let orderStore = ConnectionStore(baseURL: scratch.appendingPathComponent("order"))
for (i, n) in names.enumerated() {
    let id = uuid(String(format: "00000000-0000-0000-0000-%012d", i))
    try orderStore.save(Connection(id: id, name: n, kind: .wireguard, createdAt: created), config: nil)
}
try write(try orderStore.list().map(\.name).joined(separator: "\n") + "\n", "list-order-\(Locale.current.identifier).txt")

// MARK: connection-order.json

let t0 = Date(timeIntervalSince1970: 1_800_000_000)
let day: TimeInterval = 24 * 60 * 60
var ranking = ConnectionRanking()
ranking.recordSuccess(id: "11111111-2222-3333-4444-555555555555", at: t0)
ranking.recordSuccess(id: "11111111-2222-3333-4444-555555555555", at: t0 + 3 * day)
ranking.recordSuccess(id: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4", at: t0 + 0.5)
ranking.pin("22222222-3333-4444-5555-666666666666")
ranking.pin("11111111-2222-3333-4444-555555555555")
let rankingStore = ConnectionRankingStore(url: scratch.appendingPathComponent("ranking/MacVPN/connection-order.json"))
try rankingStore.save(ranking)
try copy(rankingStore.url, "connection-order/recorded.json")
let numbers = ConnectionRanking(pinned: [], usage: [
    "a": .init(score: 1.5e-7, lastUpdated: t0), "b": .init(score: 1e16, lastUpdated: t0), "c": .init(score: 123.456, lastUpdated: t0),
    "d": .init(score: 0.0001, lastUpdated: t0), "e": .init(score: 1e15, lastUpdated: t0), "f": .init(score: 0, lastUpdated: t0),
    "g": .init(score: 2.5e-308, lastUpdated: t0), "h": .init(score: 1.7976931348623157e308, lastUpdated: t0),
    "i": .init(score: 0.1 + 0.2, lastUpdated: t0), "j": .init(score: 12345678.9, lastUpdated: t0),
    "k": .init(score: 5e-324, lastUpdated: t0), "l": .init(score: 9007199254740993, lastUpdated: t0),
])
try rankingStore.save(numbers)
try copy(rankingStore.url, "connection-order/numbers.json")
try rankingStore.save(ConnectionRanking())
try copy(rankingStore.url, "connection-order/empty.json")

let rankingInputs = out.appendingPathComponent("inputs/connection-order")
for file in try fm.contentsOfDirectory(atPath: rankingInputs.path).sorted() where file.hasSuffix(".json") {
    let loaded = ConnectionRankingStore(url: rankingInputs.appendingPathComponent(file)).load()
    let back = ConnectionRankingStore(url: scratch.appendingPathComponent("ranking-\(file)/connection-order.json"))
    try back.save(loaded)
    try copy(back.url, "decoded/connection-order/\(file)")
}

// MARK: system-otp.json

let otpStore = SystemOTPStore(url: scratch.appendingPathComponent("otp/system-otp.json"))
try otpStore.save(["38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4": OTPSetting(enabled: true, separator: .comma),
                   "DISABLED-IS-DROPPED": OTPSetting(enabled: false, separator: .colon),
                   "0F9E8D7C-6B5A-4938-2716-05F4E3D2C1B0": OTPSetting(enabled: true, separator: .none),
                   "A1": OTPSetting(enabled: true, separator: .colon)])
try copy(otpStore.url, "system-otp/saved.json")
try otpStore.save([:])
try copy(otpStore.url, "system-otp/empty.json")

let otpInputs = out.appendingPathComponent("inputs/system-otp")
for file in try fm.contentsOfDirectory(atPath: otpInputs.path).sorted() where file.hasSuffix(".json") {
    let loaded = SystemOTPStore(url: otpInputs.appendingPathComponent(file)).load()
    let back = SystemOTPStore(url: scratch.appendingPathComponent("otp-\(file)/system-otp.json"))
    try back.save(loaded)
    try copy(back.url, "decoded/system-otp/\(file)")
}
// MARK: .mobileconfig, as MobileconfigGenerator.generate writes it

for (file, kind, psk) in [("cisco.mobileconfig", VPNKind.cisco, String(repeating: "k", count: 100)),
                          ("l2tp.mobileconfig", VPNKind.l2tp, ""), ("l2tp-psk.mobileconfig", VPNKind.l2tp, "secret psk")] {
    let c = Connection(id: uuid("55555555-6666-7777-8888-999999999999"), name: "Office <L2TP> & \"q\" 'a' é \u{1}", kind: kind,
                       createdAt: created, native: NativeSettings(server: "vpn.example.com", account: "bob", groupName: "staff",
                                                                  sendAllTraffic: kind == .l2tp))
    let url = out.appendingPathComponent("mobileconfig/\(file)")
    try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try MobileconfigGenerator.generate(connection: c, psk: psk).write(to: url)
}
print("ok")
