import SwiftUI
import AppKit
import Combine
import MacVPNCore

@MainActor
final class LogViewModel: ObservableObject {
    @Published private(set) var lines: [LogLine] = []
    /// Minden változásnál nő; a sorszám 5000-nél megáll, ezért a követés erre figyel.
    @Published private(set) var revision = 0
    private var tailer: LogTailer?
    private var timer: Timer?
    private var cancellable: AnyCancellable?
    static let maxLines = 5000

    func start(connection: Connection, collector: NativeLogCollector?) {
        stop()
        lines = []
        if connection.kind.isNative {
            guard let collector else {
                lines = [LogLine("▶ [mvpn] \(String(localized: "Native connections only have a log when connected in debug mode."))")]
                return
            }
            cancellable = collector.$lines.sink { [weak self] raw in
                self?.lines = raw.suffix(Self.maxLines).map(LogLine.init)
                self?.revision += 1
            }
            return
        }
        let tailer = LogTailer(url: MvpnClient.logURL(for: connection.id))
        self.tailer = tailer
        append(tailer.readNew())
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.append(self?.tailer?.readNew() ?? []) }
        }
    }

    private func append(_ new: [String]) {
        guard !new.isEmpty else { return }
        lines.append(contentsOf: new.map(LogLine.init))
        if lines.count > Self.maxLines { lines.removeFirst(lines.count - Self.maxLines) }
        revision += 1
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        tailer = nil
        cancellable = nil
    }
}

struct LogView: View {
    let connection: Connection
    @EnvironmentObject var model: AppModel
    @StateObject private var vm = LogViewModel()
    @State private var filter: LogFilter = .all
    @State private var search = ""
    @State private var follow = true

    private var visible: [LogLine] {
        vm.lines.filter { $0.matches(filter) && (search.isEmpty || $0.text.localizedCaseInsensitiveContains(search)) }
    }

    var body: some View {
        let visible = self.visible
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $filter) {
                    ForEach(LogFilter.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 240)
                TextField("Search", text: $search).textFieldStyle(.roundedBorder)
                Toggle("Follow", isOn: $follow).toggleStyle(.checkbox)
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(visible.map(\.text).joined(separator: "\n"), forType: .string)
                }
                Button("Save…") { saveToFile() }
            }
            .padding(8)
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(visible.enumerated()), id: \.offset) { index, line in
                            Text(line.text)
                                .font(.system(size: 11, weight: line.kind == .header ? .bold : .regular, design: .monospaced))
                                .foregroundStyle(color(line.kind))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(index)
                        }
                    }
                    .padding(8)
                }
                .background(Color(nsColor: .textBackgroundColor))
                .onChange(of: vm.revision) { _, _ in
                    let count = self.visible.count
                    if follow, count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
                }
            }
        }
        .onAppear { vm.start(connection: connection, collector: model.nativeLogs[connection.id]) }
        .onChange(of: model.nativeLogs[connection.id] != nil) { _, _ in
            vm.start(connection: connection, collector: model.nativeLogs[connection.id])
        }
        .onDisappear { vm.stop() }
    }

    private func color(_ kind: LogLine.Kind) -> Color {
        switch kind {
        case .header: return .primary
        case .step: return .blue
        case .command: return .purple
        case .error: return .red
        case .output: return .secondary
        }
    }

    private func saveToFile() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = String(localized: "\(connection.name)-log.txt")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // 0600, O_NOFOLLOW (mint az export): a napló szervercímeket és felhasználóneveket tartalmazhat.
        do {
            try ConfigExporter.write(Data(vm.lines.map(\.text).joined(separator: "\n").utf8), to: url)
        } catch {
            let alert = NSAlert()
            alert.messageText = String(localized: "Could not save the log")
            alert.informativeText = error.localizedDescription
            alert.alertStyle = .warning
            alert.addButton(withTitle: String(localized: "OK"))
            alert.runModal()
        }
    }
}
