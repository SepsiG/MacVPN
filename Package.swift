// swift-tools-version:5.10
import PackageDescription

// Lokalizáció: angol forrásnyelv, magyar fordítás.
// - MacVPN: String Catalog (Sources/MacVPN/Resources/Localizable.xcstrings). Nem SwiftPM resource (exclude): a
//   build-dmg.sh `xcstringstool compile`-lal közvetlenül a MacVPN.app/Contents/Resources/<nyelv>.lproj-ba fordítja,
//   így a SwiftUI `Text("…")` és a `String(localized:)` az alapértelmezett Bundle.main-ből oldja fel. Nincs
//   MacVPN_MacVPN.bundle és Bundle.module, ami a kézzel összerakott .app-ban hiányozhatna.
// - MacVPNCore: beágyazott táblázat (L10n.swift), mert a root oldali mvpn-validate resource bundle nélkül fut.
let package = Package(
    name: "MacVPN",
    defaultLocalization: "en",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "MacVPNCore"),
        .executableTarget(name: "MacVPN", dependencies: ["MacVPNCore"], exclude: ["Resources"]),
        .executableTarget(name: "mvpn-validate", dependencies: ["MacVPNCore"]),
        .testTarget(name: "MacVPNCoreTests", dependencies: ["MacVPNCore"]),
    ]
)
