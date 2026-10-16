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
    }

    @Published var fields = Fields() { didSet { reportDirty() } }
    @Published private(set) var issues: [ValidationIssue] = []
    @Published private(set) var savedAt: Date?
    private var original = Fields()
    private var connection: Connection?
    private weak var model: AppModel?

    var isDirty: Bool { connection != nil && fields != original }

    /// Csak az első megjelenéskor tölt: egy újabb `onAppear` nem írja felül a szerkesztést.
    func load(_ connection: Connection, model: AppModel) {
        guard self.connection == nil else { return }
        self.model = model
        let s = model.secrets.secrets(for: connection.id)
        let loaded = Fields(name: connection.name,
                            text: (try? model.store.loadConfig(connection.id)) ?? "",
                            username: s.username ?? "", password: s.password ?? "", psk: s.psk ?? "")
        original = loaded
        self.connection = connection
        fields = loaded
    }

    @discardableResult
    func save() -> Bool {
        guard let connection, let model else { return false }
        issues = model.saveText(connection, name: fields.name, config: fields.text,
                                secrets: Secrets(username: fields.username, password: fields.password, psk: fields.psk))
        let ok = issues.isEmpty
        if ok { original = fields }
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
            if showsUser || showsPSK {
                GroupBox("Authentication (stored in the Keychain)") {
                    VStack {
                        if showsUser {
                            TextField("Username", text: $draft.fields.username)
                            SecureField("Password", text: $draft.fields.password)
                        }
                        if showsPSK { SecureField("Pre-shared key (PSK)", text: $draft.fields.psk) }
                    }
                    .textFieldStyle(.roundedBorder)
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
