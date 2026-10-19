import SwiftUI
import MacVPNCore

/// „Frissítés elérhető" ablak: release notes és „Letöltés és telepítés".
struct UpdateView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var updates: UpdateController
    @Environment(\.dismissWindow) private var dismissWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let release = updates.available {
                Text("Update available: \(release.tag)").font(.title2.bold())
                Text("Installed version: \(updates.currentVersion)").foregroundStyle(.secondary)
                ScrollView {
                    Text(notes(release.notes))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(minHeight: 160, maxHeight: 320)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                Text("The SHA-256 checksum of the downloaded disk image is checked against the release's .sha256 file. The app restarts after the installation.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let error = updates.installError {
                    Text(error).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    if let stage = updates.installStage {
                        ProgressView().controlSize(.small)
                        Text(stage).foregroundStyle(.secondary)
                    } else if let page = release.pageURL {
                        Link("Open the Release on GitHub", destination: page)
                    }
                    Spacer()
                    Button("Later") { dismissWindow(id: "update") }
                        .disabled(updates.installStage != nil)
                    Button("Download and Install") {
                        Task { await updates.install(confirmQuit: { await model.confirmQuit() }, terminate: { model.terminateConfirmed() }) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(updates.installStage != nil)
                }
            } else {
                Text("No update available").font(.title2.bold())
                Text("The installed version (\(updates.currentVersion)) is the latest.").foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Close") { dismissWindow(id: "update") }
                }
            }
        }
        .padding(20)
        .frame(width: 520)
    }

    private func notes(_ markdown: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: markdown, options: options)) ?? AttributedString(markdown)
    }
}
