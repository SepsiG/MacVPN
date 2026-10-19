import Foundation

/// Offsetből olvassa a fájl új, teljes sorait. Csonkoláskor vagy fájlcserekor (inode) elölről kezdi.
/// Az első olvasás csak az utolsó 256 KB-ot nézi, hívásonként legfeljebb 1 MB-ot olvas,
/// és a lezáratlan sort 64 KB felett sorként kiadja.
public final class LogTailer {
    static let initialWindow: UInt64 = 256 * 1024
    static let maxReadBytes = 1024 * 1024
    static let maxPartialBytes = 64 * 1024

    public let url: URL
    private var offset: UInt64 = 0
    private var partial = Data()
    private var started = false
    private var inode: UInt64?
    /// Ablak közepéről indulva az első (csonka) sort el kell dobni.
    private var discardLeading = false

    public init(url: URL) {
        self.url = url
    }

    public func readNew() -> [String] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        var st = stat()
        let ino: UInt64? = fstat(handle.fileDescriptor, &st) == 0 ? UInt64(st.st_ino) : nil
        if let inode, let ino, inode != ino {
            offset = 0
            partial = Data()
            discardLeading = false
            started = false      // az új fájlra is a 256 KB-os ablak vonatkozik
        }
        inode = ino
        let size = (try? handle.seekToEnd()) ?? 0
        if !started {
            started = true
            if size > Self.initialWindow {
                offset = size - Self.initialWindow
                discardLeading = true
            }
        }
        if size < offset {
            offset = 0
            partial = Data()
            discardLeading = false
        }
        guard size > offset else { return [] }
        try? handle.seek(toOffset: offset)
        var data = (try? handle.read(upToCount: Self.maxReadBytes)) ?? Data()
        offset += UInt64(data.count)
        if discardLeading {
            guard let nl = data.firstIndex(of: UInt8(ascii: "\n")) else { return [] }
            data = Data(data[(nl + 1)...])
            discardLeading = false
        }
        partial.append(data)
        var lines: [String] = []
        if let lastNewline = partial.lastIndex(of: UInt8(ascii: "\n")) {
            let complete = partial[partial.startIndex..<lastNewline]
            partial = Data(partial[(lastNewline + 1)...])
            lines = String(decoding: complete, as: UTF8.self).components(separatedBy: "\n")
        }
        if partial.count > Self.maxPartialBytes {
            let cut = Self.completeUTF8Prefix(partial)
            lines.append(String(decoding: partial[partial.startIndex..<(partial.startIndex + cut)], as: UTF8.self))
            partial = Data(partial[(partial.startIndex + cut)...])
        }
        return lines
    }

    /// A hossz, amelyig nem vágunk félbe többbájtos UTF-8 karaktert.
    static func completeUTF8Prefix(_ d: Data) -> Int {
        var i = d.count - 1
        var back = 0
        while i >= 0, back < 3, (d[d.startIndex + i] & 0xC0) == 0x80 { i -= 1; back += 1 }
        guard i >= 0 else { return d.count }
        let lead = d[d.startIndex + i]
        let need = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1
        return d.count - i < need ? i : d.count
    }
}
