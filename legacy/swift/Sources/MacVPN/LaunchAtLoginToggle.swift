import SwiftUI
import MacVPNCore

/// „Indítás bejelentkezéskor" jelölőnégyzet a rendszer állapotából, alatta a megjegyzéssel és szükség esetén a
/// Bejelentkezési elemek beállítás gombjával. A menüben és a Rendszerállapot ablakban is ez jelenik meg.
struct LaunchAtLoginToggle: View {
    @EnvironmentObject var model: AppModel
    /// A menüben kisebb betűk és behúzás (a „Frissítések automatikus keresése" mintájára).
    var compact = false

    var body: some View {
        let state = model.loginItem.state
        VStack(alignment: .leading, spacing: 2) {
            Toggle("Launch at Login", isOn: Binding(
                get: { model.loginItem.state.isOn }, set: { model.setLaunchAtLogin($0) }))
                .toggleStyle(.checkbox)
                .font(compact ? .callout : .body)
                .disabled(!state.canToggle)
            if let note = state.note {
                Text(note.message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, 20)
            }
            if state.showsOpenSettings {
                Button("Open Login Items Settings…") { model.loginItem.openSystemSettings() }
                    .controlSize(.small)
                    .padding(.leading, 20)
            }
        }
        .padding(.horizontal, compact ? 8 : 0)
        .padding(.vertical, compact ? 2 : 0)
    }
}
