import XCTest
@testable import MacVPNCore

final class LogTests: XCTestCase {
    func testClassify() {
        XCTAssertEqual(LogLine("═══ 2026-10-16 up openvpn ═══").kind, .header)
        XCTAssertEqual(LogLine("▶ [mvpn] config másolása").kind, .step)
        XCTAssertEqual(LogLine("$ /opt/homebrew/sbin/openvpn --config x").kind, .command)
        XCTAssertEqual(LogLine("[#] ifconfig utun5 inet 10.0.0.2").kind, .command)
        XCTAssertEqual(LogLine("✗ időtúllépés").kind, .error)
        XCTAssertEqual(LogLine("2026-10-16 AUTH_FAILED").kind, .error)
        XCTAssertEqual(LogLine("TLS: Initial packet").kind, .output)
    }

    func testFilter() {
        let lines = ["$ a", "out", "✗ bad", "▶ [mvpn] x"].map(LogLine.init)
        XCTAssertEqual(lines.filter { $0.matches(.commands) }.map(\.text), ["$ a", "▶ [mvpn] x"])
        XCTAssertEqual(lines.filter { $0.matches(.errors) }.map(\.text), ["✗ bad"])
        XCTAssertEqual(lines.filter { $0.matches(.all) }.count, 4)
    }

    func testTailerReturnsOnlyCompleteNewLines() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".log")
        defer { try? FileManager.default.removeItem(at: url) }
        let tailer = LogTailer(url: url)
        XCTAssertEqual(tailer.readNew(), [])
        try "egy\nket".write(to: url, atomically: false, encoding: .utf8)
        XCTAssertEqual(tailer.readNew(), ["egy"])
        let h = try FileHandle(forWritingTo: url)
        h.seekToEndOfFile(); h.write(Data("tő\nhárom\n".utf8)); try h.close()
        XCTAssertEqual(tailer.readNew(), ["kettő", "három"])
        XCTAssertEqual(tailer.readNew(), [])
        try "új\n".write(to: url, atomically: false, encoding: .utf8)  // csonkolás
        XCTAssertEqual(tailer.readNew(), ["új"])
    }

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".log")
    }

    func testFirstReadIsBoundedToLast256KB() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let line = String(repeating: "x", count: 99) + "\n"   // 100 bajt
        try String(repeating: line, count: 10_000).write(to: url, atomically: false, encoding: .utf8)
        let lines = LogTailer(url: url).readNew()
        XCTAssertLessThanOrEqual(lines.count, 256 * 1024 / 100)
        XCTAssertGreaterThan(lines.count, 256 * 1024 / 100 - 3)
        XCTAssertTrue(lines.allSatisfy { $0.count == 99 }, "a részleges első sort el kell dobni")
    }

    func testInodeReplacementResets() throws {
        let url = tempURL()
        let other = tempURL()
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(at: other) }
        try "a\nb\n".write(to: url, atomically: false, encoding: .utf8)
        let tailer = LogTailer(url: url)
        XCTAssertEqual(tailer.readNew(), ["a", "b"])
        try "c\nd\ne\nf\n".write(to: other, atomically: false, encoding: .utf8)
        XCTAssertEqual(rename(other.path, url.path), 0)
        XCTAssertEqual(tailer.readNew(), ["c", "d", "e", "f"])
    }

    func testOverlongLineWithoutNewlineIsFlushed() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try String(repeating: "y", count: 100_000).write(to: url, atomically: false, encoding: .utf8)
        let lines = LogTailer(url: url).readNew()
        XCTAssertEqual(lines.count, 1)
        XCTAssertEqual(lines.first?.count, 100_000)
    }

    func testPartialFlushNeverSplitsMultibyteCharacter() throws {
        let url = tempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        var data = Data(repeating: UInt8(ascii: "a"), count: 70_000)
        data.append(0xC3)                                  // az "é" első bájtja
        try data.write(to: url)
        let tailer = LogTailer(url: url)
        let first = tailer.readNew()
        XCTAssertEqual(first, [String(repeating: "a", count: 70_000)])
        let h = try FileHandle(forWritingTo: url)
        h.seekToEndOfFile(); h.write(Data([0xA9, 0x0A])); try h.close()
        XCTAssertEqual(tailer.readNew(), ["é"])
    }

    func testInodeReplacementReappliesWindow() throws {
        let url = tempURL()
        let other = tempURL()
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(at: other) }
        try "a\n".write(to: url, atomically: false, encoding: .utf8)
        let tailer = LogTailer(url: url)
        _ = tailer.readNew()
        let line = String(repeating: "x", count: 99) + "\n"
        try String(repeating: line, count: 10_000).write(to: other, atomically: false, encoding: .utf8)
        XCTAssertEqual(rename(other.path, url.path), 0)
        XCTAssertLessThanOrEqual(tailer.readNew().count, 256 * 1024 / 100)
    }
}
