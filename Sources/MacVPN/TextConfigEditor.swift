import SwiftUI
import MacVPNCore

/// A szöveges szerkesztő állapota. Objektumban él, hogy a modell „Mentés" gombja (nem mentett változások
/// párbeszéd) is el tudja menteni.
@MainActor
final class TextConfigDraft: ObservableObject {
    struct Fields: Equatable {
        var name = ""
        var text = ""
        var username = ""
        var password = ""
        var psk = ""
        var keyPassword = ""
        /// A tudomásul vett kockázatos direktívák (OpenVPN). A négyzet akkor bejelölt, ha minden jelenlegi kockázatos
        /// direktíva benne van; bejelöléskor pontosan a jelenlegi halmaz lesz.
        var acknowledged: Set<String> = []
        /// MFA: „kód a jelszó végén” (spec 10f).
        var otp = OTPSetting()
    }

    @Published var fields = Fields() {
        didSet {
            if fields.text != oldValue.text { updateRisky() }
            reportDirty()
        }
    }
    @Published private(set) var issues: [ValidationIssue] = []
    /// A config kockázatos (RISKY) direktívái, élőben (OpenVPN).
    @Published private(set) var risky: [RiskyFinding] = []
    @Published private(set) var savedAt: Date?
    private var original = Fields()
    private var connection: Connection?
    private weak var model: AppModel?

    var isDirty: Bool { connection != nil && fields != original }

    var riskyNames: Set<String> { Set(risky.map(\.directive)) }

    /// „Tudomásul veszem…” négyzet.
    var acknowledgesRisk: Bool {
        get { !risky.isEmpty && riskyNames.isSubset(of: fields.acknowledged) }
        set { fields.acknowledged = newValue ? riskyNames : [] }
    }

    private func updateRisky() {
        guard connection?.kind == .openvpn else { return }
        risky = OpenVPNValidator().validate(fields.text, acknowledgedRisky: []).risky
    }

    /// Csak az első megjelenéskor tölt: egy újabb `onAppear` nem írja felül a szerkesztést.
    func load(_ connection: Connection, model: AppModel) {
        guard self.connection == nil else { return }
        self.model = model
        let s = model.secrets.secrets(for: connection.id)
        let loaded = Fields(name: connection.name,
                            text: (try? model.store.loadConfig(connection.id)) ?? "",
                            username: s.username ?? "", password: s.password ?? "", psk: s.psk ?? "",
                            keyPassword: s.keyPassword ?? "",
                            acknowledged: Set(connection.acknowledgedRiskyDirectives), otp: connection.otp)
        original = loaded
        self.connection = connection
        fields = loaded
        updateRisky()
        issues = model.takeImportIssues(connection.id)
    }

    @discardableResult
    func save() -> Bool {
        guard let connection, let model else { return false }
        let acknowledged = acknowledgesRisk ? riskyNames : []
        issues = model.saveText(connection, name: fields.name, config: fields.text,
                                secrets: Secrets(username: fields.username, password: fields.password, psk: fields.psk,
                                                 keyPassword: connection.kind == .openvpn ? fields.keyPassword : ""),
                                acknowledgedRisky: acknowledged, otp: fields.otp)
        let ok = issues.isEmpty
        if ok {
            fields.acknowledged = acknowledged
            original = fields
        }
        savedAt = ok ? Date() : nil
        reportDirty()
        return ok
    }

    /// nil = mentve; egyébként a validációs hibák szövege.
    func saveReportingError() -> String? {
        save() ? nil : issues.map(\.display).joined(separator: "\n")
    }

    func detach() {
        if let connection { model?.setUnsaved(connection.id, dirty: false) }
    }

    private func reportDirty() {
        guard let connection, let model else { return }
        model.setUnsaved(connection.id, dirty: isDirty, save: { [weak self] in self?.saveReportingError() ?? String(localized: "The editor is no longer available") })
    }
}

struct TextConfigEditor: View {
    let connection: Connection
    /// Látható-e (a ⌘S csak ekkor él).
    var isActive = true
    @EnvironmentObject var model: AppModel
    @StateObject private var draft = TextConfigDraft()

    private var showsUser: Bool { connection.kind == .openvpn || connection.kind == .strongswan }
    private var showsPSK: Bool { connection.kind == .strongswan }
    private var showsKeyPassword: Bool { connection.kind == .openvpn }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("Name", text: $draft.fields.name).textFieldStyle(.roundedBorder)
            TextEditor(text: $draft.fields.text)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .border(draft.issues.isEmpty ? Color.secondary.opacity(0.3) : Color.red)
            if !draft.issues.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(draft.issues.enumerated()), id: \.offset) { _, issue in
                        Label(issue.display, systemImage: "xmark.octagon.fill").foregroundStyle(.red).font(.callout)
                    }
                }
            }
            if !draft.risky.isEmpty { RiskyPanel(findings: draft.risky, acknowledged: $draft.acknowledgesRisk) }
            if showsUser || showsPSK {
                GroupBox("Authentication (stored in the Keychain)") {
                    VStack {
                        if showsUser {
                            TextField("Username", text: $draft.fields.username)
                            SecureField("Password", text: $draft.fields.password)
                        }
                        if showsKeyPassword { SecureField("Private key password", text: $draft.fields.keyPassword) }
                        if showsPSK { SecureField("Pre-shared key (PSK)", text: $draft.fields.psk) }
                    }
                    .textFieldStyle(.roundedBorder)
                }
                GroupBox("One-time code (MFA)") {
                    VStack(alignment: .leading, spacing: 6) {
                        if connection.kind == .openvpn, MFA.staticChallenge(in: draft.fields.text) != nil {
                            Label("This config uses static-challenge: MacVPN asks for the code when connecting and sends it with the password (SCRV1).",
                                  systemImage: "info.circle")
                                .font(.callout)
                        } else {
                            OTPSettingFields(setting: $draft.fields.otp)
                        }
                        if connection.kind == .openvpn {
                            Text("Codes and web sign-in requested by the server during the connection (challenge/response, SAML, push) are asked for automatically.")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            HStack {
                if draft.isDirty {
                    Text("Unsaved changes").foregroundStyle(.orange)
                } else if let savedAt = draft.savedAt {
                    Text("Saved: \(savedAt.formatted(date: .omitted, time: .standard))").foregroundStyle(.secondary)
                }
                Spacer()
                if isActive {
                    Button("Save") { draft.save() }.keyboardShortcut("s").buttonStyle(.borderedProminent)
                } else {
                    Button("Save") { draft.save() }.buttonStyle(.borderedProminent)
                }
            }
        }
        .padding()
        .onAppear { draft.load(connection, model: model) }
        .onDisappear { draft.detach() }
    }
}

/// Sárga „Kockázatos beállítások” panel: soronként a direktíva és a rövid indoklás, alatta a tudomásulvétel négyzete.
struct RiskyPanel: View {
    let findings: [RiskyFinding]
    @Binding var acknowledged: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Risky settings", systemImage: "exclamationmark.triangle.fill")
                .font(.headline).foregroundStyle(.orange)
            ForEach(Array(findings.enumerated()), id: \.offset) { _, f in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(verbatim: "\(f.line).").foregroundStyle(.secondary).monospacedDigit()
                    Text(verbatim: f.directive).font(.system(.callout, design: .monospaced)).bold()
                    Text(verbatim: f.reason).font(.callout).foregroundStyle(.secondary)
                }
            }
            Toggle("I acknowledge these settings and the security risks", isOn: $acknowledged)
                .toggleStyle(.checkbox)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.yellow.opacity(0.15), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.yellow.opacity(0.6)))
    }
}
