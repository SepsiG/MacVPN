// Az app ikonjának (Resources/AppIcon.icns) előállítása.
// Használat: swift scripts/make-icon.swift  (utána: scripts/make-icon.sh készíti az .icns-t)
import AppKit

let size: CGFloat = 1024
let out = CommandLine.arguments.dropFirst().first ?? "AppIcon-1024.png"

// Fix 1024×1024 pixeles bitmap (Retina-skálázás nélkül).
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                           bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let ctx = NSGraphicsContext.current!.cgContext

// macOS ikonrács: 824×824-es lekerekített négyzet, 100 px margóval, finom árnyékkal.
let inset: CGFloat = 100
let rect = CGRect(x: inset, y: inset, width: size - 2 * inset, height: size - 2 * inset)
let path = CGPath(roundedRect: rect, cornerWidth: 185, cornerHeight: 185, transform: nil)

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: NSColor.black.withAlphaComponent(0.35).cgColor)
ctx.addPath(path)
ctx.setFillColor(NSColor.black.cgColor)
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(path)
ctx.clip()
let colors = [NSColor(srgbRed: 0.07, green: 0.32, blue: 0.85, alpha: 1).cgColor,
              NSColor(srgbRed: 0.05, green: 0.70, blue: 0.78, alpha: 1).cgColor] as CFArray
let gradient = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: colors, locations: [0, 1])!
ctx.drawLinearGradient(gradient, start: CGPoint(x: rect.minX, y: rect.maxY), end: CGPoint(x: rect.maxX, y: rect.minY), options: [])
// Felső fényfolt a mélységért.
let highlight = [NSColor.white.withAlphaComponent(0.22).cgColor, NSColor.white.withAlphaComponent(0).cgColor] as CFArray
let hl = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: highlight, locations: [0, 1])!
ctx.drawLinearGradient(hl, start: CGPoint(x: 0, y: rect.maxY), end: CGPoint(x: 0, y: rect.midY), options: [])
ctx.restoreGState()

// Fehér pajzs + lakat szimbólum középen.
let config = NSImage.SymbolConfiguration(pointSize: 470, weight: .semibold)
    // Rétegek: lakat (kék, a háttérhez illő), pajzs (fehér).
    .applying(NSImage.SymbolConfiguration(paletteColors: [NSColor(srgbRed: 0.07, green: 0.40, blue: 0.85, alpha: 1), .white]))
if let symbol = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil)?
    .withSymbolConfiguration(config) {
    let s = symbol.size
    let origin = NSPoint(x: (size - s.width) / 2, y: (size - s.height) / 2 - 6)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -6), blur: 16, color: NSColor.black.withAlphaComponent(0.25).cgColor)
    symbol.draw(at: origin, from: .zero, operation: .sourceOver, fraction: 1)
    ctx.restoreGState()
}
NSGraphicsContext.restoreGraphicsState()

guard let png = rep.representation(using: .png, properties: [:]) else { fatalError("PNG hiba") }
try! png.write(to: URL(fileURLWithPath: out))
print("Kész: \(out)")
