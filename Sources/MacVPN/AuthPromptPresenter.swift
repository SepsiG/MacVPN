import SwiftUI
import AppKit
import MacVPNCore

/// MFA kérések (spec 10f): kódbekérő ablak (a challenge szövege, kódmező, Mégse; 2 perc után lejár) és a webes
/// hitelesítés megerősítése (a hoszt látszik; csak „Megnyitás a böngészőben” után nyílik meg a https URL).
/// Kapcsolatonként legfeljebb egy nyitott kérés. A kód csak a visszaadott eredményben él: nem tárolódik, nem naplózódik.
/// Az ablak nem lopja el a fókuszt: az app nem aktiválódik, a panel nem lesz kulcsablak, amíg a felhasználó rá nem kattint
/// (vagy az értesítésre), így egy másik appba gépelt szöveg nem kerül a kódmezőbe. Nincs alapértelmezett gomb, és a
/// megjelenés utáni első másodpercben a panel nem fogad bevitelt.
@MainActor
final class AuthPromptPresenter {
    private final class Entry {
        let panel: NSPanel
        var continuation: CheckedContinuation<AuthPromptResult, Never>?
        /// Lejáratkor `timedOut` (az ablak láthatóságától függetlenül).
        var timeout: Task<Void, Never>?

        init(panel: NSPanel) { self.panel = panel }
    }

    private var entries: [String: Entry] = [:]
    /// Megjelenéskor (nem aktiváló módon) hívódik: értesítés a felhasználónak.
    var onShow: ((AuthPrompt) -> Void)?
    /// Bezáráskor (bármi okból).
    var onClose: ((String) -> Void)?

    /// A kapcsolat nyitott kérése előtérbe és fókuszba (pl. az értesítésre kattintva).
    func focus(_ key: String) {
        guard let entry = entries[key] else { return }
        NSApp.activate(ignoringOtherApps: true)
        entry.panel.makeKeyAndOrderFront(nil)
    }

    var hasOpenPrompt: Bool { !entries.isEmpty }

    func present(_ prompt: AuthPrompt) async -> AuthPromptResult {
        dismiss(prompt.connectionID)
        let key = prompt.connectionID
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<AuthPromptResult, Never>) in
                let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 420, height: 220),
                                    styleMask: [.titled, .closable], backing: .buffered, defer: false)
                let entry = Entry(panel: panel)
                entry.continuation = continuation
                entries[key] = entry
                let view = AuthPromptView(prompt: prompt) { [weak self] result in
                    self?.finish(key, result)
                }
                panel.contentViewController = NSHostingController(rootView: view)
                panel.title = prompt.connectionName
                panel.isReleasedWhenClosed = false
                panel.level = .floating
                panel.hidesOnDeactivate = false
                panel.delegate = PanelCloseDelegate.shared
                PanelCloseDelegate.shared.onClose[ObjectIdentifier(panel)] = { [weak self] in self?.finish(key, .cancelled) }
                let end = prompt.deadline.end
                entry.timeout = Task { @MainActor [weak self] in
                    let wait = end.timeIntervalSinceNow
                    if wait > 0 { try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000)) }
                    guard !Task.isCancelled else { return }
                    self?.finish(key, .timedOut)
                }
                panel.center()
                // Nem aktiváló megjelenítés: látszik, de nem kulcsablak (a billentyűleütések a jelenlegi appnál maradnak).
                panel.orderFrontRegardless()
                onShow?(prompt)
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.finish(key, .cancelled) }
        }
    }

    /// A kapcsolat nyitott kérésének bezárása (megszakítottként).
    func dismiss(_ key: String) {
        finish(key, .cancelled)
    }

    private func finish(_ key: String, _ result: AuthPromptResult) {
        guard let entry = entries.removeValue(forKey: key) else { return }
        entry.timeout?.cancel()
        PanelCloseDelegate.shared.onClose[ObjectIdentifier(entry.panel)] = nil
        entry.panel.orderOut(nil)
        entry.panel.close()
        entry.continuation?.resume(returning: result)
        entry.continuation = nil
        onClose?(key)
    }
}

/// Az ablak bezáró gombja: megszakítás.
@MainActor
private final class PanelCloseDelegate: NSObject, NSWindowDelegate {
    static let shared = PanelCloseDelegate()
    var onClose: [ObjectIdentifier: () -> Void] = [:]

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        onClose.removeValue(forKey: ObjectIdentifier(window))?()
    }
}

struct AuthPromptView: View {
    let prompt: AuthPrompt
    let done: (AuthPromptResult) -> Void
    @State private var code = ""
    @State private var finished = false
    /// A megjelenés utáni első másodpercben nincs bevitel (egy véletlen leütés ne válaszoljon).
    @State private var armed = false

    static let armDelay: UInt64 = 1_000_000_000

    private var codeIsValid: Bool { MFA.isValidCode(code) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            switch prompt.kind {
            case .code(let text, let echo, let fromServer):
                Label("One-time code", systemImage: "key.fill").font(.headline)
                if fromServer {
                    Text("The VPN server says:").font(.caption).foregroundStyle(.secondary)
                }
                Text(verbatim: text).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                Group {
                    if echo {
                        TextField("Code", text: $code)
                    } else {
                        SecureField("Code", text: $code)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .disabled(!armed)
                .onSubmit(submit)
                countdown
                HStack {
                    Spacer()
                    Button("Cancel", role: .cancel) { finish(.cancelled) }.keyboardShortcut(.cancelAction)
                    Button("Continue", action: submit).disabled(!codeIsValid || !armed)
                }
            case .webAuth(let url):
                Label("Sign in in the browser", systemImage: "globe").font(.headline)
                Text("The VPN server asks you to sign in on a web page. Open it only if you started this connection and you trust this address:")
                    .fixedSize(horizontal: false, vertical: true)
                // A hoszt és a teljes cím ASCII-ként (a punycode nincs dekódolva), hogy a hasonló alakú címek ne tévesszenek meg.
                Text(verbatim: WebAuthURL.displayHost(url)).font(.system(.body, design: .monospaced)).bold().textSelection(.enabled)
                Text(verbatim: url.absoluteString).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    .lineLimit(3).truncationMode(.middle).textSelection(.enabled)
                countdown
                HStack {
                    Spacer()
                    Button("Cancel", role: .cancel) { finish(.cancelled) }.keyboardShortcut(.cancelAction)
                    // Nem alapértelmezett gomb: csak kifejezett kattintásra nyílik meg.
                    Button("Open in Browser") {
                        guard armed else { return }
                        NSWorkspace.shared.open(url)
                        finish(.openedURL)
                    }
                    .disabled(!armed)
                }
            }
        }
        .padding(20)
        .frame(width: 420)
        .task {
            try? await Task.sleep(nanoseconds: Self.armDelay)
            armed = true
        }
    }

    /// Hátralévő idő; lejáratkor a kérés `timedOut`-tal zárul.
    private var countdown: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = prompt.deadline.remaining(at: context.date)
            Text("Expires in \(Self.format(left))")
                .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                .onChange(of: left) { _, value in if value == 0 { finish(.timedOut) } }
        }
    }

    static func format(_ seconds: Int) -> String { String(format: "%d:%02d", seconds / 60, seconds % 60) }

    private func submit() {
        guard armed, codeIsValid else { return }
        finish(.code(code))
    }

    private func finish(_ result: AuthPromptResult) {
        guard !finished else { return }
        finished = true
        code = ""
        done(result)
    }
}

/// „Kód a jelszó végén” beállítás (minden szerkesztőben ugyanaz).
struct OTPSettingFields: View {
    @Binding var setting: OTPSetting

    var body: some View {
        Toggle("Ask for a one-time code at connect and append it to the password", isOn: $setting.enabled)
        if setting.enabled {
            Picker("Separator", selection: $setting.separator) {
                Text("None").tag(OTPSeparator.none)
                Text(verbatim: ",").tag(OTPSeparator.comma)
                Text(verbatim: ":").tag(OTPSeparator.colon)
            }
            Text("The code is never stored. If no password is saved here, the code alone is sent as the password.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }
}
