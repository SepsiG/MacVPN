// A menüsor-ikonok (template PNG-k) előállítása a Tauri apphoz: ugyanazok az SF Symbolok, mint a Swift app
// `menuBarSymbol`-ja (shield / checkmark.shield.fill / exclamationmark.shield.fill / key.fill), fekete-átlátszó
// template képként, 36×36 px-en (18 pt @2x). A rendszer színezi őket a menüsor megjelenése szerint. A csatlakozás
// folyamatban állapot (shield.lefthalf.filled: félig kitöltött pajzs, az üres és a pipás között) a Tauri app saját
// ikonja (2026-10-28); Windowson ugyanezt a PNG-t színezi át az app (G-7).
// Használat: swift scripts/make-tray-icons.swift app/src-tauri/icons/tray
import AppKit

let outDir = CommandLine.arguments.dropFirst().first ?? "app/src-tauri/icons/tray"
let pixels = 36
let icons: [(file: String, symbol: String)] = [
    ("idle", "shield"),
    ("connecting", "shield.lefthalf.filled"),
    ("active", "checkmark.shield.fill"),
    ("failure", "exclamationmark.shield.fill"),
    ("auth", "key.fill"),
]

try FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)
for icon in icons {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: pixels, height: pixels)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    // Monokróm (template) megjelenítés: a pipa / felkiáltójel kivágás marad, nem fekete.
    let config = NSImage.SymbolConfiguration(pointSize: 27, weight: .medium)
    guard let symbol = NSImage(systemSymbolName: icon.symbol, accessibilityDescription: nil)?
        .withSymbolConfiguration(config) else { fatalError("nincs ilyen szimbólum: \(icon.symbol)") }
    let s = symbol.size
    let scale = min(1, CGFloat(pixels - 2) / max(s.width, s.height))
    let w = s.width * scale, h = s.height * scale
    symbol.draw(in: NSRect(x: (CGFloat(pixels) - w) / 2, y: (CGFloat(pixels) - h) / 2, width: w, height: h),
                from: .zero, operation: .sourceOver, fraction: 1)
    NSGraphicsContext.restoreGraphicsState()
    guard let png = rep.representation(using: .png, properties: [:]) else { fatalError("PNG hiba") }
    let path = "\(outDir)/\(icon.file).png"
    try png.write(to: URL(fileURLWithPath: path))
    print("Kész: \(path)")
}
