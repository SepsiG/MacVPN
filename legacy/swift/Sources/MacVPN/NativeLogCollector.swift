import Foundation

/// Natív (L2TP/Cisco) debug csatlakozáskor a rendszernaplót gyűjti, legfeljebb 60 mp-ig.
@MainActor
final class NativeLogCollector: ObservableObject {
    @Published private(set) var lines: [String] = []
    private var process: Process?
    /// Minden indítás új generáció: egy korábbi indítás 60 mp-es időzítője nem állíthatja le az újat.
    private(set) var generation = 0

    static let maxDuration: Duration = .seconds(60)
    static let predicate = #"process IN {"racoon","pppd","neagent","nesessionmanager"} OR subsystem == "com.apple.networkextension""#

    func start() {
        stop()
        generation += 1
        let current = generation
        lines = ["═══ \(Date().formatted(date: .numeric, time: .standard)) \(String(localized: "native debug")) ═══",
                 "$ log stream --style compact --predicate '\(Self.predicate)'"]
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        p.arguments = ["stream", "--style", "compact", "--predicate", Self.predicate]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil   // EOF: különben üresen pörögne
                return
            }
            let text = String(decoding: data, as: UTF8.self)
            Task { @MainActor [weak self] in
                guard let self, self.generation == current else { return }
                self.lines.append(contentsOf: text.split(separator: "\n").map(String.init))
            }
        }
        p.terminationHandler = { [weak self] _ in
            pipe.fileHandleForReading.readabilityHandler = nil
            Task { @MainActor [weak self] in
                // Saját stop() után (új generáció) nem jelezzük; csak a váratlan leállást.
                guard let self, self.generation == current else { return }
                self.process = nil
                self.generation += 1
                self.lines.append("▶ [mvpn] \(String(localized: "log stream stopped"))")
            }
        }
        do {
            try p.run()
            process = p
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: Self.maxDuration)
                guard let self, self.generation == current else { return }
                self.stop()
            }
        } catch {
            pipe.fileHandleForReading.readabilityHandler = nil
            lines.append("✗ \(String(localized: "log stream did not start: \(error.localizedDescription)"))")
        }
    }

    func stop() {
        guard let p = process else { return }
        generation += 1   // a még úton lévő kimenet-darabok már nem kerülnek be
        (p.standardOutput as? Pipe)?.fileHandleForReading.readabilityHandler = nil
        if p.isRunning { p.terminate() }
        process = nil
        lines.append("▶ [mvpn] \(String(localized: "log collection stopped"))")
    }
}
