import SwiftUI
import UniformTypeIdentifiers
import MacVPNCore

/// Az SSTP űrlap állapota (lásd `TextConfigDraft`, `NativeConfigDraft`): piszkos-követés és a nem mentett
/// változások nyilvántartása (`AppModel.setUnsaved`). A config `SSTPConfig`-ként él, mentéskor szerializálva
/// és a `SSTPValidator`-ral ellenőrizve kerül a `config` fájlba; a jelszó a Keychainbe.
@MainActor
final class SSTPConfigDraft: ObservableObject {
    struct Fields: Equatable {
        var name = ""
        var config = SSTPConfig()
        var password = ""
    }

    @Published var fields = Fields() { didSet { reportDirty() } }
    @Published private(set) var issues: [String] = []
    @Published private(set) var savedAt: Date?
    @Published var importError: String?
    private var original = Fields()
    private var connection: Connection?
    private weak var model: AppModel?

    var isDirty: Bool { connection != nil && fields != original }

    /// Csak az első megjelenéskor tölt: egy újabb `onAppear` nem írja felül a szerkesztést.
    func load(_ connection: Connection, model: AppModel) {
        guard self.connection == nil else { return }
        self.model = model
        let text = (try? model.store.loadConfig(connection.id)) ?? ""
        let loaded = Fields(name: connection.name, config: SSTPConfig.parse(text),
                            password: model.secrets.secrets(for: connection.id).password ?? "")
        original = loaded
        self.connection = connection
        fields = loaded
        issues = model.takeImportIssues(connection.id).map(\.display)
    }

    @discardableResult
    func save() -> Bool {
        guard let connection, let model else { return false }
        issues = model.saveSSTP(connection, name: fields.name, config: fields.config, password: fields.password)
            .map(\.message)
        let ok = issues.isEmpty
        if ok { original = fields }
        savedAt = ok ? Date() : nil
        reportDirty()
        return ok
    }

    /// nil = mentve; egyébként a hibák szövege.
    func saveReportingError() -> String? {
        save() ? nil : issues.joined(separator: "\n")
    }

    /// A kiválasztott fájlból a PEM tanúsítvány(ok) a configba.
    func importCA(from url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8),
              let pem = SSTPConfig.extractCertificates(from: text) else {
            importError = String(localized: "The file contains no PEM certificate (-----BEGIN CERTIFICATE-----). Convert a binary (DER) .cer file to PEM first.")
            return
        }
        importError = nil
        fields.config.caPEM = pem
    }

    func detach() {
        if let connection { model?.setUnsaved(connection.id, dirty: false) }
    }

    private func reportDirty() {
        guard let connection, let model else { return }
        model.setUnsaved(connection.id, dirty: isDirty, save: { [weak self] in self?.saveReportingError() ?? String(localized: "The editor is no longer available") })
    }
}

struct SSTPConfigForm: View {
    let connection: Connection
    /// Látható-e (a ⌘S csak ekkor él).
    var isActive = true
    @EnvironmentObject var model: AppModel
    @StateObject private var draft = SSTPConfigDraft()
    @State private var showCAImporter = false

    private var certCount: Int { SSTPConfig.certificateCount(in: draft.fields.config.caPEM) }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $draft.fields.name)
                TextField("Server", text: $draft.fields.config.server, prompt: Text(verbatim: "vpn.example.com"))
                TextField("Port", value: $draft.fields.config.port, format: .number.grouping(.never))
                TextField("Username", text: $draft.fields.config.user)
                SecureField("Password", text: $draft.fields.password)
                if !SSTPConfig.isAcceptablePassword(draft.fields.password) {
                    Label(SSTPConfig.passwordRuleMessage, systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red).font(.callout)
                }
            } footer: {
                Text("The password is stored in the Keychain. Use user@domain instead of DOMAIN\\user.")
                    .font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Section {
                Picker("Server certificate", selection: $draft.fields.config.cert) {
                    Text("System CA").tag(SSTPConfig.CertMode.system)
                    Text("Custom CA file").tag(SSTPConfig.CertMode.ca)
                    Text("No verification").tag(SSTPConfig.CertMode.insecure)
                }
                switch draft.fields.config.cert {
                case .system:
                    Text("Uses the CA certificates of Homebrew's OpenSSL, not the macOS Keychain. For a company CA, choose a custom CA file.")
                        .font(.callout).foregroundStyle(.secondary)
                case .ca:
                    HStack {
                        if certCount > 0 {
                            Label("Certificates loaded: \(certCount)", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                        } else {
                            Label("No CA certificate loaded", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                        Spacer()
                        Button("Choose PEM File…") { showCAImporter = true }
                    }
                    if let error = draft.importError { Text(error).foregroundStyle(.red).font(.callout) }
                case .insecure:
                    Label("The server's certificate is not verified. Anyone between you and the server can impersonate it and capture your login. Use this only for testing.",
                          systemImage: "exclamationmark.octagon.fill")
                        .foregroundStyle(.red)
                        .font(.callout)
                }
            }
            Section {
                Toggle("Send all traffic over VPN", isOn: $draft.fields.config.routeAll)
                Toggle("Use the server's DNS", isOn: $draft.fields.config.peerDNS)
            }
            Section {
                ForEach(Array(draft.issues.enumerated()), id: \.offset) { _, issue in
                    Label(issue, systemImage: "xmark.octagon.fill").foregroundStyle(.red).font(.callout)
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
        }
        .formStyle(.grouped)
        .fileImporter(isPresented: $showCAImporter,
                      allowedContentTypes: [.x509Certificate, .plainText, .data, .item]) { result in
            if case .success(let url) = result { draft.importCA(from: url) }
        }
        .onAppear { draft.load(connection, model: model) }
        .onDisappear { draft.detach() }
    }
}
