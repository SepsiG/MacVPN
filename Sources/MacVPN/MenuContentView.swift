import SwiftUI
import AppKit
import MacVPNCore

struct MenuContentView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var manager: ConnectionManager
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let error = manager.statusError {
                Button { open("setup") } label: {
                    Label {
                        Text(error).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                    }
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 8).padding(.vertical, 4)
                }
                .buttonStyle(.plain)
                .help("Open System Status")
                Divider().padding(.vertical, 2)
            }
            if manager.connections.isEmpty && manager.systemServices.isEmpty {
                Text("No connections yet").foregroundStyle(.secondary).padding(8)
            }
            // Egy lista: kitűzöttek, majd használat szerint (spec 10e).
            ForEach(manager.orderedItems) { item in
                switch item {
                case .managed(let c):
                    MenuRow(name: c.name, type: c.kind.displayName,
                            state: manager.state(for: item.id),
                            available: model.setup.isAvailable(c.kind),
                            pinned: manager.isPinned(item.id)) { debug in
                        model.toggle(c, debug: debug)
                    }
                case .system(let s):
                    MenuRow(name: s.name, type: s.typeLabel, state: manager.state(for: item.id), available: true,
                            pinned: manager.isPinned(item.id)) { _ in
                        model.toggleSystem(s)
                    }
                }
            }
            Divider().padding(.vertical, 4)
            if let release = model.updates.available {
                MenuButton(title: "Update available: \(release.tag)", symbol: "arrow.down.circle.fill") { open("update") }
                    .foregroundStyle(Color.accentColor)
            }
            MenuButton(title: "New Connection / Import…", symbol: "plus") { open("manage") }
            MenuButton(title: "Manage Connections…", symbol: "gearshape") { open("manage") }
            MenuButton(title: "System Status",
                       symbol: model.setup.isComplete ? "checkmark.circle" : "exclamationmark.triangle") { open("setup") }
            MenuButton(title: "Help", symbol: "questionmark.circle") { model.openUserGuide() }
            if model.updates.enabled {
                MenuButton(title: model.updates.checking ? "Checking for Updates…" : "Check for Updates Now",
                           symbol: "arrow.triangle.2.circlepath") {
                    Task { if await model.updates.checkNow() { open("update") } }
                }
                .disabled(model.updates.checking)
                Toggle("Check for Updates Automatically", isOn: Binding(
                    get: { model.updates.autoCheck }, set: { model.updates.autoCheck = $0 }))
                    .toggleStyle(.checkbox)
                    .font(.callout)
                    .padding(.horizontal, 8).padding(.vertical, 2)
                Toggle("Only Offer Updates Published at Least 24 Hours Ago", isOn: Binding(
                    get: { model.updates.delayUpdates }, set: { model.updates.delayUpdates = $0 }))
                    .toggleStyle(.checkbox)
                    .font(.callout)
                    .padding(.horizontal, 8).padding(.vertical, 2)
            }
            LaunchAtLoginToggle(compact: true)
            MenuButton(title: "Quit MacVPN", symbol: "power") { model.quit() }
            Text("Option-click a switch: debug mode").font(.caption2).foregroundStyle(.tertiary).padding(.horizontal, 8)
        }
        .padding(8)
        .frame(width: 330)
        .task { await manager.refresh() }
        .onAppear { model.loginItem.refresh() }
    }

    private func open(_ id: String) {
        openWindow(id: id)
        NSApp.activate(ignoringOtherApps: true)
    }
}

struct MenuRow: View {
    let name: String
    let type: String
    let state: ConnectionState
    let available: Bool
    let pinned: Bool
    /// Paraméter: debug mód (Option lenyomva).
    let action: (Bool) -> Void

    var body: some View {
        HStack(spacing: 8) {
            StatusDot(state: state)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(name).fontWeight(.medium)
                    if pinned { PinBadge() }
                }
                subtitle.font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: Binding(
                get: { state.isActive },
                set: { _ in action(NSEvent.modifierFlags.contains(.option)) }))
                .toggleStyle(.switch)
                .controlSize(.mini)
                .labelsHidden()
                .disabled(!available || state == .disconnecting)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .opacity(available ? 1 : 0.5)
    }

    @ViewBuilder private var subtitle: some View {
        switch state {
        case .connected(let ip, let since):
            HStack(spacing: 4) {
                Text([type, ip].compactMap { $0 }.joined(separator: " · "))
                if let since { Text(verbatim: "·"); Text(since, style: .relative) }
            }
        case .failed(let reason):
            Text(verbatim: "\(type) · \(reason)").lineLimit(1)
        case .awaitingAuth:
            Text("\(type) · Waiting for authentication").lineLimit(1)
        default:
            Text(available ? type : String(localized: "\(type) · Missing tool"))
        }
    }
}

struct StatusDot: View {
    let state: ConnectionState

    var body: some View {
        switch state {
        case .connecting, .disconnecting:
            ProgressView().controlSize(.mini).frame(width: 10, height: 10)
        case .connected:
            Circle().fill(.green).frame(width: 10, height: 10)
        case .failed:
            Circle().fill(.red).frame(width: 10, height: 10)
        case .awaitingAuth:
            Image(systemName: "key.fill").font(.system(size: 9)).foregroundStyle(.orange).frame(width: 10, height: 10)
                .accessibilityLabel(Text("Waiting for authentication"))
        case .disconnected:
            Circle().strokeBorder(.secondary, lineWidth: 1.5).frame(width: 10, height: 10)
        }
    }
}

struct MenuButton: View {
    let title: LocalizedStringKey
    let symbol: String
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol).frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(hover ? Color.accentColor.opacity(0.15) : .clear, in: RoundedRectangle(cornerRadius: 5))
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

/// Kitűzött kapcsolat jele (menü és Kapcsolatok ablak).
struct PinBadge: View {
    var body: some View {
        Image(systemName: "pin.fill")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .rotationEffect(.degrees(45))
            .accessibilityLabel(Text("Pinned"))
    }
}
