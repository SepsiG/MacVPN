import Foundation

public struct CommandResult: Equatable, Sendable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String

    public init(exitCode: Int32 = 0, stdout: String = "", stderr: String = "") {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public protocol CommandRunner: Sendable {
    func run(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult
}

public enum CommandError: LocalizedError, Equatable {
    case timedOut(String)

    public var errorDescription: String? {
        switch self {
        case .timedOut(let executable): return L10n.tr("The command was stopped after a timeout: %@", executable)
        }
    }
}

/// A futtatások időkorlátjai (mp).
public enum RunnerTimeouts {
    /// Alapértelmezés: telepítés, frissítés, `mvpn down` (ez is várhat a zárra), rendszerállapot.
    public static let standard: TimeInterval = 90
    /// `mvpn up`: legrosszabb esetben 45 mp zárvárakozás + a korábbi futás bontása + 30 mp kapcsolódás + pillanatképek.
    public static let up: TimeInterval = 150
    /// Gyakori, gyors lekérdezések: `mvpn status`, `scutil --nc …`.
    public static let quick: TimeInterval = 20
}

public struct ProcessCommandRunner: CommandRunner {
    let timeout: TimeInterval

    public init(timeout: TimeInterval = RunnerTimeouts.standard) {
        self.timeout = timeout
    }

    public func run(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult {
        let job = ProcessJob(executable: executable, arguments: arguments, stdin: stdin, timeout: timeout)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                job.start(continuation)
            }
        } onCancel: {
            job.cancel()
        }
    }
}

/// Egyetlen futtatás állapota. Nem blokkolja a cooperative poolt: a kimenetet
/// readabilityHandler gyűjti, a lezárást terminationHandler jelzi.
private final class ProcessJob: @unchecked Sendable {
    private let executable: String
    private let arguments: [String]
    private let stdin: String?
    private let timeout: TimeInterval

    private let lock = NSLock()
    private let process = Process()
    private let outPipe = Pipe(), errPipe = Pipe(), inPipe = Pipe()
    private var outData = Data(), errData = Data()
    private var continuation: CheckedContinuation<CommandResult, Error>?
    private var started = false
    private var finished = false
    private var timedOut = false
    private var cancelled = false

    init(executable: String, arguments: [String], stdin: String?, timeout: TimeInterval) {
        self.executable = executable
        self.arguments = arguments
        self.stdin = stdin
        self.timeout = timeout
    }

    func start(_ continuation: CheckedContinuation<CommandResult, Error>) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()

        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = outPipe
        process.standardError = errPipe
        process.standardInput = inPipe
        for pipe in [outPipe, errPipe] {
            _ = fcntl(pipe.fileHandleForReading.fileDescriptor, F_SETFL, O_NONBLOCK)
        }
        outPipe.fileHandleForReading.readabilityHandler = { [weak self] _ in self?.drain(stdout: true) }
        errPipe.fileHandleForReading.readabilityHandler = { [weak self] _ in self?.drain(stdout: false) }
        process.terminationHandler = { [weak self] _ in self?.finish() }

        do {
            try process.run()
        } catch {
            fail(error)
            return
        }

        lock.lock()
        started = true
        let alreadyCancelled = cancelled
        lock.unlock()

        // A szülő oldali, gyerekhez tartozó végek zárása, hogy a stdin EPIPE-ot kapjon.
        try? inPipe.fileHandleForReading.close()
        try? outPipe.fileHandleForWriting.close()
        try? errPipe.fileHandleForWriting.close()

        writeStdin()

        if alreadyCancelled { terminate() }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.timeoutFired()
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let running = started && !finished
        lock.unlock()
        if running { terminate() }
    }

    private func writeStdin() {
        let handle = inPipe.fileHandleForWriting
        _ = fcntl(handle.fileDescriptor, F_SETNOSIGPIPE, 1)
        let payload = stdin.map { Data($0.utf8) }
        DispatchQueue.global().async {
            if let payload, !payload.isEmpty {
                do { try handle.write(contentsOf: payload) } catch { /* EPIPE: a gyerek nem olvas, rendben */ }
            }
            try? handle.close()
        }
    }

    private func timeoutFired() {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        timedOut = true
        lock.unlock()
        terminate()
    }

    /// SIGTERM, majd 2 mp után SIGKILL.
    private func terminate() {
        guard process.isRunning else { return }
        process.terminate()
        let pid = process.processIdentifier
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let done = self.finished
            self.lock.unlock()
            if !done { kill(pid, SIGKILL) }
        }
    }

    /// Nem blokkoló olvasás; hívás előtt a lock NINCS megfogva.
    private func drain(stdout: Bool) {
        lock.lock()
        defer { lock.unlock() }
        drainLocked(stdout: stdout)
    }

    private func drainLocked(stdout: Bool) {
        guard !finished else { return }
        let pipe = stdout ? outPipe : errPipe
        let fd = pipe.fileHandleForReading.fileDescriptor
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n > 0 {
                if stdout { outData.append(contentsOf: buffer[0..<n]) } else { errData.append(contentsOf: buffer[0..<n]) }
            } else {
                if n == 0 { pipe.fileHandleForReading.readabilityHandler = nil }  // EOF
                return  // 0 vagy EAGAIN/hiba
            }
        }
    }

    private func finish() {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        drainLocked(stdout: true)
        drainLocked(stdout: false)
        finished = true
        outPipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil
        try? outPipe.fileHandleForReading.close()
        try? errPipe.fileHandleForReading.close()
        let cont = continuation
        continuation = nil
        let result = CommandResult(exitCode: process.terminationStatus,
                                   stdout: String(decoding: outData, as: UTF8.self),
                                   stderr: String(decoding: errData, as: UTF8.self))
        let error: Error? = timedOut ? CommandError.timedOut(executable) : (cancelled ? CancellationError() : nil)
        lock.unlock()
        if let error { cont?.resume(throwing: error) } else { cont?.resume(returning: result) }
    }

    private func fail(_ error: Error) {
        lock.lock()
        finished = true
        outPipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil
        let cont = continuation
        continuation = nil
        lock.unlock()
        for h in [outPipe.fileHandleForReading, outPipe.fileHandleForWriting, errPipe.fileHandleForReading,
                  errPipe.fileHandleForWriting, inPipe.fileHandleForReading, inPipe.fileHandleForWriting] {
            try? h.close()
        }
        cont?.resume(throwing: error)
    }
}
