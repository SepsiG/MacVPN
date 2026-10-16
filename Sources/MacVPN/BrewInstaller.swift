import Foundation
import MacVPNCore

/// `brew install …` futtatása user jogon, élő kimenettel. Az `AppModel` birtokolja, így az ablak bezárását is túléli.
///
/// Sorrend: a kimenetet egyetlen háttérszál olvassa EOF-ig, és a darabokat sorban a main queue-ra adja.
/// A záró sor csak akkor kerül be, ha az olvasás véget ért ÉS a folyamat kilépett, így mindig az utolsó,
/// és semmi nem vész el.
@MainActor
final class BrewInstaller: ObservableObject {
    @Published private(set) var output = ""
    @Published private(set) var running = false
    @Published private(set) var finishedCount = 0

    func install(brewPrefix: String) {
        guard !running else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: brewPrefix + "/bin/brew")
        p.arguments = ["install"] + SetupChecker.brewPackages
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "\(brewPrefix)/bin:\(brewPrefix)/sbin:/usr/bin:/bin:/usr/sbin:/sbin"
        env["HOMEBREW_NO_ENV_HINTS"] = "1"
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        let done = DispatchGroup()
        done.enter()   // folyamat kilépett
        p.terminationHandler = { _ in done.leave() }

        output = "$ brew install \(SetupChecker.brewPackages.joined(separator: " "))\n"
        running = true
        do { try p.run() } catch {
            running = false
            output += "✗ \(error.localizedDescription)\n"
            return
        }
        // A szülő példányát le kell zárni, különben az olvasó sosem kap EOF-ot.
        try? pipe.fileHandleForWriting.close()

        let reader = pipe.fileHandleForReading
        done.enter()   // olvasás EOF-ig
        DispatchQueue.global(qos: .utility).async { [weak self] in
            while true {
                let data = reader.availableData
                if data.isEmpty { break }
                let text = String(decoding: data, as: UTF8.self)
                DispatchQueue.main.async {
                    MainActor.assumeIsolated { self?.output += text }
                }
            }
            done.leave()
        }
        done.notify(queue: .main) { [weak self] in
            MainActor.assumeIsolated {
                let status = p.terminationStatus
                guard let self else { return }
                self.running = false
                self.output += status == 0 ? "\n✓ \(String(localized: "Done."))\n" : "\n✗ \(String(localized: "brew error (\(status))"))\n"
                self.finishedCount += 1
            }
        }
    }
}
