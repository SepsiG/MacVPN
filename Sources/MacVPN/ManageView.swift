import SwiftUI
import UniformTypeIdentifiers
import MacVPNCore

struct ManageView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var manager: ConnectionManager
    @State private var showImporter = false
    @State private var importReport: AppModel.ImportReport?
    @State private var confirmUnsaved = false
    @Environment(\.dismissWindow) private var dismissWindow

    private var selection: Binding<String?> {
        Binding(get: { model.selectedID }, set: { model.select($0) })
    }

    var body: some View {
        NavigationSplitView {
            // Egy rangsor (spec 10e): a kitűzöttek húzással rendezhetők, a többi a használat szerint.
            List(selection: selection) {
                let pinned = manager.pinnedItems
                if !pinned.isEmpty {
                    Section("Pinned") {
                        ForEach(pinned) { item in row(item) }
                            .onMove { manager.movePinned(fromOffsets: $0, toOffset: $1) }
                    }
                }
                Section("Connections") {
                    ForEach(manager.unpinnedItems) { item in row(item) }
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 250)
            .toolbar {
                Menu {
                    ForEach(VPNKind.allCases, id: \.self) { kind in
                        Button(kind.displayName) { model.createNew(kind: kind) }
                    }
                    Divider()
                    Button("Import from File…") { showImporter = true }
                } label: {
                    Label("New", systemImage: "plus")
                }
            }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [.data, .plainText, .item],
                          allowsMultipleSelection: true) { result in
                if case .success(let urls) = result {
                    let report = model.importFiles(urls)
                    importReport = report.isEmpty ? nil : report
                }
            }
            .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                guard !providers.isEmpty else { return false }
                importReport = nil
                for provider in providers {
                    _ = provider.loadObject(ofClass: URL.self) { url, _ in
                        guard let url else { return }
                        Task { @MainActor in
                            // Fájlonként érkezik: az üzenetek gyűlnek, nem írják felül egymást.
                            let report = model.importFiles([url])
                            guard !report.isEmpty else { return }
                            var merged = importReport ?? AppModel.ImportReport()
                            merged.merge(report)
                            importReport = merged
                        }
                    }
                }
                return true
            }
        } detail: {
            VStack(spacing: 0) {
                if let error = manager.statusError {
                    StatusErrorBanner(message: error)
                }
                detail
            }
            // Legyen elég széles a részletező, különben a tördelt szövegek a minimális szélességnél
            // hatalmas minimális ablakmagasságot kényszerítenek ki.
            .navigationSplitViewColumnWidth(min: 480, ideal: 650)
        }
        .frame(minWidth: 720, minHeight: 420)
        .background(WindowCloseGuard {
            guard model.hasUnsavedChanges else { return true }
            model.pendingAction = .closeWindow
            return false
        })
        .onChange(of: model.pendingAction) { _, new in confirmUnsaved = new != nil }
        .confirmationDialog("Unsaved Changes", isPresented: $confirmUnsaved, titleVisibility: .visible) {
            Button("Save") {
                if model.saveAllUnsaved() { proceedPending() } else { model.cancelPendingAction() }
            }
            Button("Discard", role: .destructive) {
                model.discardUnsaved()
                proceedPending()
            }
            Button("Cancel", role: .cancel) { model.cancelPendingAction() }
        } message: {
            Text("The edited settings have not been saved yet.")
        }
        .alert((importReport?.errors.isEmpty ?? true) ? "Import" : "Import Error",
               isPresented: Binding(get: { importReport != nil }, set: { if !$0 { importReport = nil } })) {
            Button("OK") { importReport = nil }
        } message: {
            Text(importReport?.message ?? "")
        }
    }

    private func row(_ item: ConnectionItem) -> some View {
        let pinned = manager.isPinned(item.id)
        return Group {
            switch item {
            case .managed(let c):
                ConnectionLabel(name: c.name, type: c.kind.displayName, state: manager.state(for: item.id), pinned: pinned)
            case .system(let s):
                ConnectionLabel(name: s.name, type: String(localized: "\(s.typeLabel) · System VPN"),
                                state: manager.state(for: item.id), pinned: pinned)
            }
        }
        .tag(item.id)
        .contextMenu {
            if pinned {
                Button("Unpin") { manager.unpin(item.id) }
            } else {
                Button("Pin to Top") { manager.pin(item.id) }
            }
        }
    }

    private func proceedPending() {
        switch model.pendingAction {
        case .closeWindow?:
            model.pendingAction = nil
            dismissWindow(id: "manage")
        case .select?:
            model.resolvePendingSelection()
        case nil:
            break
        }
    }

    @ViewBuilder private var detail: some View {
        if let id = model.selectedID, let c = manager.connections.first(where: { $0.id.uuidString == id }) {
            ConnectionDetailView(connection: c).id(id)
        } else if let id = model.selectedID, let s = manager.systemServices.first(where: { $0.id == id }) {
            SystemServiceDetail(service: s).id(id)
        } else {
            ContentUnavailableView("Select a Connection", systemImage: "network",
                                   description: Text("Or drop an .ovpn / .conf / .sstp file here."))
        }
    }
}

/// A `ConnectionManager.statusError` figyelmeztetése (pl. a sudo/mvpn nem érhető el).
struct StatusErrorBanner: View {
    let message: String
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text(message).font(.callout).lineLimit(3).frame(maxWidth: .infinity, alignment: .leading)
            Button("System Status") {
                openWindow(id: "setup")
                NSApp.activate(ignoringOtherApps: true)
            }
        }
        .padding(10)
        .background(Color.orange.opacity(0.12))
    }
}

struct ConnectionLabel: View {
    let name: String
    let type: String
    let state: ConnectionState
    var pinned = false

    var body: some View {
        HStack {
            StatusDot(state: state)
            VStack(alignment: .leading) {
                HStack(spacing: 4) {
                    Text(name)
                    if pinned { PinBadge() }
                }
                Text(type).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct ConnectionDetailView: View {
    let connection: Connection
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var manager: ConnectionManager
    @State private var tab = 0
    @State private var confirmDelete = false

    var state: ConnectionState { manager.state(for: connection.id.uuidString) }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                StatusDot(state: state)
                VStack(alignment: .leading) {
                    Text(connection.name).font(.title3.bold())
                    Text(connection.kind.displayName).foregroundStyle(.secondary)
                }
                Spacer()
                Button(state.isActive ? "Disconnect" : "Connect") { model.toggle(connection, debug: false) }
                    .disabled(!model.setup.isAvailable(connection.kind) || state == .disconnecting)
                Button("Connect in Debug Mode") { model.connect(connection, debug: true) }
                    .disabled(state.isActive || !model.setup.isAvailable(connection.kind))
                Button { model.export(connection) } label: { Image(systemName: "square.and.arrow.up") }
                    .help("Export… (passwords are never included)")
                Button(role: .destructive) { confirmDelete = true } label: { Image(systemName: "trash") }
                    .help("Delete")
            }
            .padding()
            if case .failed(let reason) = state {
                Label(reason, systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
            } else if case .awaitingAuth = state {
                Label("Waiting for authentication", systemImage: "key.fill")
                    .foregroundStyle(.orange)
                    .font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
            }
            Picker("", selection: $tab) {
                Text("Settings").tag(0)
                Text("Log").tag(1)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal)
            Divider().padding(.top, 8)
            // Mindkét fül mountolva marad: fülváltás (vagy kényszerített Napló-váltás) nem dobja el a szerkesztést.
            ZStack {
                Group {
                    if connection.kind.isNative {
                        NativeConfigForm(connection: connection)
                    } else if connection.kind == .sstp {
                        SSTPConfigForm(connection: connection, isActive: tab == 0)
                    } else {
                        TextConfigEditor(connection: connection, isActive: tab == 0)
                    }
                }
                .opacity(tab == 0 ? 1 : 0)
                .allowsHitTesting(tab == 0)
                .accessibilityHidden(tab != 0)
                LogView(connection: connection)
                    .opacity(tab == 1 ? 1 : 0)
                    .allowsHitTesting(tab == 1)
                    .accessibilityHidden(tab != 1)
            }
        }
        .onAppear(perform: consumeLogTabRequest)
        .onChange(of: model.logTabRequest) { _, _ in consumeLogTabRequest() }
        .onChange(of: model.settingsTabRequest) { _, _ in consumeLogTabRequest() }
        .confirmationDialog("Delete \(connection.name)?", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { model.delete(connection) }
        } message: {
            Text(connection.kind.isNative
                 ? "You have to remove the installed profile yourself in the Profiles pane that opens."
                 : "The config and the saved passwords will be deleted.")
        }
    }
}

extension ConnectionDetailView {
    /// Egyszer használatos: csak a megcélzott kapcsolat vált a Napló fülre, és törli a kérést.
    /// A Beállítások-kérés (sikertelen mentés) elsőbbséget élvez.
    func consumeLogTabRequest() {
        if model.settingsTabRequest == connection.id {
            tab = 0
            model.settingsTabRequest = nil
        } else if model.logTabRequest == connection.id {
            tab = 1
            model.logTabRequest = nil
        }
    }
}

/// A rendszer VPN PSK / jelszó űrlapjának állapota (lásd `NativeConfigDraft`).
@MainActor
final class SystemSecretsDraft: ObservableObject {
    struct Fields: Equatable {
        var psk = ""
        var password = ""
        var otp = OTPSetting()
    }

    @Published var fields = Fields() { didSet { reportDirty() } }
    @Published private(set) var saved = false
    @Published private(set) var error: String?
    private var original = Fields()
    private var service: SystemVPNService?
    private weak var model: AppModel?

    var isDirty: Bool { service != nil && fields != original }
    var hasStored: Bool { original != Fields() }

    func load(_ service: SystemVPNService, model: AppModel) {
        guard self.service == nil, service.supportsStoredSecrets else { return }
        self.model = model
        let s = model.manager.systemSecrets(for: service)
        let loaded = Fields(psk: s.psk ?? "", password: s.password ?? "",
                            otp: model.manager.systemOTPSetting(for: service.id))
        original = loaded
        self.service = service
        fields = loaded
    }

    @discardableResult
    func save() -> Bool {
        guard let service, let model else { return false }
        error = model.saveSystemSecrets(service, psk: fields.psk, password: fields.password, otp: fields.otp)
        guard error == nil else {
            saved = false
            return false
        }
        original = fields
        saved = true
        reportDirty()
        return true
    }

    func forget() {
        guard let service, let model else { return }
        model.forgetSystemSecrets(service)
        error = nil
        original = Fields()
        saved = false
        fields = Fields()
    }

    func detach() {
        if let id = service?.secretID { model?.setUnsaved(id, dirty: false) }
    }

    private func reportDirty() {
        guard let id = service?.secretID, let model else { return }
        model.setUnsaved(id, dirty: isDirty, save: { [weak self] in
            guard let self else { return String(localized: "The editor is no longer available") }
            return self.save() ? nil : (self.error ?? String(localized: "The editor is no longer available"))
        })
    }
}

struct SystemServiceDetail: View {
    let service: SystemVPNService
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var manager: ConnectionManager
    @StateObject private var draft = SystemSecretsDraft()

    var state: ConnectionState { manager.state(for: service.id) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 12) {
                Text(service.name).font(.title3.bold())
                Text("\(service.typeLabel) · system VPN (not created by MacVPN)").foregroundStyle(.secondary)
                Text("This connection can only be connected and disconnected here. Its settings are in System Settings or in its own app.")
                Button(state.isActive ? "Disconnect" : "Connect") { model.toggleSystem(service) }
                    .disabled(state == .disconnecting)
                if case .failed(let reason) = state {
                    Label(reason, systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding([.horizontal, .top])
            if service.supportsStoredSecrets {
                Form {
                    Section {
                        SecureField("Shared secret (PSK)", text: $draft.fields.psk)
                        SecureField("Password (optional, if not saved in macOS)", text: $draft.fields.password)
                    } footer: {
                        Text("Stored in the MacVPN keychain and passed to macOS when connecting. Needed when macOS cannot read the shared secret on its own (\"incorrect user shared secret\").")
                            .font(.callout).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Section("One-time code (MFA)") {
                        OTPSettingFields(setting: $draft.fields.otp)
                    }
                    Section {
                        if let error = draft.error { Text(error).foregroundStyle(.red) }
                        if draft.isDirty {
                            Text("Unsaved changes").foregroundStyle(.orange)
                        } else if draft.saved {
                            Text("Saved").foregroundStyle(.green)
                        }
                        HStack {
                            Button("Forget saved secrets", role: .destructive) { draft.forget() }
                                .disabled(!draft.hasStored && !draft.isDirty)
                            Spacer()
                            Button("Save") { draft.save() }
                                .buttonStyle(.borderedProminent)
                                .disabled(!draft.isDirty)
                        }
                    }
                }
                .formStyle(.grouped)
            } else {
                Spacer()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { draft.load(service, model: model) }
        .onDisappear { draft.detach() }
    }
}
