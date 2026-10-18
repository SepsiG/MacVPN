import SwiftUI
import MacVPNCore

/// A natív űrlap állapota (lásd `TextConfigDraft`).
@MainActor
final class NativeConfigDraft: ObservableObject {
    struct Fields: Equatable {
        var name = ""
        var settings = NativeSettings()
        var password = ""
        var psk = ""
        var otp = OTPSetting()
    }

    @Published var fields = Fields() { didSet { reportDirty() } }
    @Published private(set) var error: String?
    @Published private(set) var saved = false
    private var original = Fields()
    private var connection: Connection?
    private weak var model: AppModel?

    var isDirty: Bool { connection != nil && fields != original }

    func load(_ connection: Connection, model: AppModel) {
        guard self.connection == nil else { return }
        self.model = model
        let s = model.secrets.secrets(for: connection.id)
        let loaded = Fields(name: connection.name, settings: connection.native ?? NativeSettings(),
                            password: s.password ?? "", psk: s.psk ?? "", otp: connection.otp)
        original = loaded
        self.connection = connection
        fields = loaded
    }

    @discardableResult
    func save() -> Bool {
        guard let connection, let model else { return false }
        var withoutOTP = fields
        withoutOTP.otp = original.otp
        if withoutOTP == original {
            // Csak a kód-beállítás változott: nem kell új profil (és jóváhagyás).
            error = model.saveOTP(connection, otp: fields.otp)
        } else {
            error = model.saveNative(connection, name: fields.name, settings: fields.settings,
                                     password: fields.password, psk: fields.psk, otp: fields.otp)
        }
        saved = error == nil
        if saved { original = fields }
        reportDirty()
        return saved
    }

    /// nil = mentve; egyébként a hiba szövege.
    func saveReportingError() -> String? {
        save() ? nil : (error ?? String(localized: "Unknown error"))
    }

    func detach() {
        if let connection { model?.setUnsaved(connection.id, dirty: false) }
    }

    private func reportDirty() {
        guard let connection, let model else { return }
        model.setUnsaved(connection.id, dirty: isDirty, save: { [weak self] in self?.saveReportingError() ?? String(localized: "The editor is no longer available") })
    }
}

struct NativeConfigForm: View {
    let connection: Connection
    @EnvironmentObject var model: AppModel
    @StateObject private var draft = NativeConfigDraft()

    var body: some View {
        Form {
            TextField("Name", text: $draft.fields.name)
            TextField("Server", text: $draft.fields.settings.server)
            TextField("Account name", text: $draft.fields.settings.account)
            SecureField("Password", text: $draft.fields.password)
            SecureField("Pre-shared key (PSK)", text: $draft.fields.psk)
            if connection.kind == .cisco {
                TextField("Group name", text: $draft.fields.settings.groupName)
            }
            Toggle("Send all traffic over VPN", isOn: $draft.fields.settings.sendAllTraffic)
            Section("One-time code (MFA)") {
                OTPSettingFields(setting: $draft.fields.otp)
            }
            Section {
                Text("Saving creates and opens a configuration profile. Approve it in System Settings → General → Device Management (Profiles). After each change it has to be approved again. The password is not in the profile: MacVPN passes it when connecting (from System Settings, macOS asks for it).")
                    .font(.callout).foregroundStyle(.secondary)
                if let error = draft.error { Text(error).foregroundStyle(.red) }
                if draft.isDirty {
                    Text("Unsaved changes").foregroundStyle(.orange)
                } else if draft.saved {
                    Text("Profile opened, approve it in System Settings.").foregroundStyle(.green)
                }
                HStack {
                    Spacer()
                    Button("Save and Install Profile") { draft.save() }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { draft.load(connection, model: model) }
        .onDisappear { draft.detach() }
    }
}
