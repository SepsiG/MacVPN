import SwiftUI
import UniformTypeIdentifiers
import MacVPNCore

struct ManageView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var manager: ConnectionManager
    @State private var showImporter = false
    @State private var importError: String?
    @State private var confirmUnsaved = false
    @Environment(\.dismissWindow) private var dismissWindow

    private var selection: Binding<String?> {
        Binding(get: { model.selectedID }, set: { model.select($0) })
    }

    var body: some View {
        NavigationSplitView {
            List(selection: selection) {
                Section("My Connections") {
                    ForEach(manager.connections) { c in
                        ConnectionLabel(name: c.name, type: c.kind.displayName, state: manager.state(for: c.id.uuidString))
                            .tag(c.id.uuidString)
                    }
                }
                if !manager.systemServices.isEmpty {
                    Section("System VPNs") {
                        ForEach(manager.systemServices) { s in
                            ConnectionLabel(name: s.name, type: s.typeLabel, state: manager.state(for: s.id)).tag(s.id)
                        }
                    }
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
                if case .success(let urls) = result { importError = model.importFiles(urls) }
            }
            .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                guard !providers.isEmpty else { return false }
                importError = nil
                for provider in providers {
                    _ = provider.loadObject(ofClass: URL.self) { url, _ in
                        guard let url else { return }
                        Task { @MainActor in
                            // Fájlonként érkezik: a hibák gyűlnek, nem írják felül egymást.
                            if let error = model.importFiles([url]) {
                                importError = [importError, error].compactMap { $0 }.joined(separator: "\n")
                            }
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
        }
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
        .alert("Import Error", isPresented: Binding(get: { importError != nil }, set: { if !$0 { importError = nil } })) {
            Button("OK") { importError = nil }
        } message: {
            Text(importError ?? "")
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
            SystemServiceDetail(service: s)
        } else {
            ContentUnavailableView("Select a Connection", systemImage: "network",
                                   description: Text("Or drop an .ovpn / .conf file here."))
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

    var body: some View {
        HStack {
            StatusDot(state: state)
            VStack(alignment: .leading) {
                Text(name)
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
                    .help("Export… (without passwords)")
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

struct SystemServiceDetail: View {
    let service: SystemVPNService
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var manager: ConnectionManager

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(service.name).font(.title3.bold())
            Text("\(service.typeLabel) · system VPN (not created by MacVPN)").foregroundStyle(.secondary)
            Text("This connection can only be connected and disconnected here. Its settings are in System Settings or in its own app.")
                .fixedSize(horizontal: false, vertical: true)
            Button(manager.state(for: service.id).isActive ? "Disconnect" : "Connect") { model.toggleSystem(service) }
                .disabled(manager.state(for: service.id) == .disconnecting)
            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
