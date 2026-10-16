import SwiftUI
import AppKit

/// Az ablak bezárása előtt megkérdezi a `shouldClose`-t. A SwiftUI saját ablak-delegate-jét megtartja:
/// minden más üzenetet annak továbbít.
struct WindowCloseGuard: NSViewRepresentable {
    let shouldClose: () -> Bool

    func makeCoordinator() -> Proxy { Proxy() }

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { install(on: view, proxy: context.coordinator) }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        context.coordinator.shouldClose = shouldClose
        install(on: nsView, proxy: context.coordinator)
    }

    /// Eltávolításkor visszaadja az eredeti delegate-et, ha még a proxy van beállítva.
    static func dismantleNSView(_ nsView: NSView, coordinator: Proxy) {
        if let window = coordinator.window, window.delegate === coordinator {
            window.delegate = coordinator.original
        }
        coordinator.window = nil
    }

    private func install(on view: NSView, proxy: Proxy) {
        proxy.shouldClose = shouldClose
        guard let window = view.window, window.delegate !== proxy else { return }
        proxy.original = window.delegate
        proxy.window = window
        window.delegate = proxy
    }

    final class Proxy: NSObject, NSWindowDelegate {
        weak var original: NSWindowDelegate?
        weak var window: NSWindow?
        var shouldClose: () -> Bool = { true }

        func windowShouldClose(_ sender: NSWindow) -> Bool {
            guard shouldClose() else { return false }
            return original?.windowShouldClose?(sender) ?? true
        }

        override func responds(to aSelector: Selector!) -> Bool {
            super.responds(to: aSelector) || (original?.responds(to: aSelector) ?? false)
        }

        override func forwardingTarget(for aSelector: Selector!) -> Any? {
            if let original, original.responds(to: aSelector) { return original }
            return super.forwardingTarget(for: aSelector)
        }
    }
}
