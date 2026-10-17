import SwiftUI
import MacVPNCore

struct SetupView: View {
    @EnvironmentObject var model: AppModel
    @State private var installingRoot = false
    @State private var uninstalling = false

    /// Az `AppModel` birtokolja (túléli az ablak bezárását); a változásait a modell továbbítja.
    private var brew: BrewInstaller { model.brew }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("System Status").font(.title2.bold())
            Text("MacVPN uses the VPN tools from Homebrew (openvpn, wireguard-tools, strongswan, sstp-client, bash). You can install the missing ones here.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let error = model.manager.statusError {
                Label {
                    Text(error).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                .font(.callout)
            }

            CheckRow(ok: model.setup.brewPrefix != nil, title: "Homebrew",
                     detail: model.setup.brewPrefix
                        ?? String(localized: "Not installed. The installer runs in Terminal and asks for an administrator password.")) {
                Button("Install…") { model.openBrewInstallInTerminal() }
            }

            CheckRow(ok: model.setup.missingTools.isEmpty, title: "VPN tools",
                     detail: model.setup.missingTools.isEmpty
                        ? String(localized: "All tools are installed")
                        : String(localized: "Missing: \(model.setup.missingTools.joined(separator: ", "))")) {
                Button(brew.running ? "Installing…" : "Install") {
                    if let prefix = model.setup.brewPrefix { brew.install(brewPrefix: prefix) }
                }
                .disabled(brew.running || model.setup.brewPrefix == nil)
            }
            if !brew.output.isEmpty {
                ScrollView {
                    Text(brew.output)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(height: 160)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
            }

            CheckRow(ok: model.setup.rootOK, title: "Permissions (root scripts + sudoers)",
                     detail: rootDetail) {
                Button(installingRoot ? "Installing…" : "Authorize") {
                    installingRoot = true
                    Task { await model.installRoot(); installingRoot = false }
                }
                .disabled(installingRoot)
            }
            if let err = model.installError { Text(err).foregroundStyle(.red) }

            HStack {
                Text("L2TP and Cisco IPsec work without these.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Check Again") { Task { await model.checkSetup() } }
            }

            Divider()
            LaunchAtLoginToggle()

            Divider()
            HStack {
                Text("Removes the root scripts, the sudoers rule and the logs; optionally your connections too.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Uninstall MacVPN…", role: .destructive) {
                    uninstalling = true
                    Task { await model.uninstall(); uninstalling = false }
                }
                .disabled(uninstalling || installingRoot)
            }
        }
        .padding(20)
        .frame(width: 560)
        .task {
            model.loginItem.refresh()
            await model.checkSetup()
        }
    }

    private var rootDetail: String {
        let s = model.setup
        if s.rootOK { return String(localized: "Installed (version \(s.installedRootVersion ?? "?"))") }
        if let installed = s.installedRootVersion, installed != s.bundledRootVersion {
            let bundled = s.bundledRootVersion ?? "?"
            return String(localized: "Update required (\(installed) → \(bundled)). Asks for the admin password once.")
        }
        return String(localized: "Asks for the admin password once: installs the scripts in /usr/local/libexec/macvpn and the /etc/sudoers.d/macvpn rule.")
    }
}

struct CheckRow<Action: View>: View {
    let ok: Bool
    let title: LocalizedStringKey
    let detail: String
    @ViewBuilder let action: () -> Action

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(ok ? .green : .red)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).fontWeight(.semibold)
                Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if !ok { action() }
        }
    }
}
