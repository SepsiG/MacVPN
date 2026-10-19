import Darwin
import Foundation
import MacVPNCore

// mvpn-mgmt: root oldali közvetítő az OpenVPN management interfésze és a MacVPN app között (spec 10f).
// Telepítve: /usr/local/libexec/macvpn/mvpn-mgmt (root:wheel 755). Csak a `mvpn up openvpn` indítja (run_direct --bg):
//
//   mvpn-mgmt --id <uuid> --run <futási könyvtár> --ui <állapot-könyvtár> --uid <n> --gid <n> [--max-wait <mp>]
//
// - A management socket (`<run>/mgmt.sock`) a root tulajdonú 0700-as futási könyvtárban van; egyetlen kliense ez a folyamat.
// - Bemenet a mvpn-től: `<run>/mgmt-creds` (root 0600: username=, password=, packed=), beolvasás után azonnal törölve.
// - Válaszok az apptól: `<run>/mgmt-resp` (a `mvpn respond` írja, root 0600), beolvasás után törölve, újra validálva.
// - Kimenet a felhasználónak: `<ui>/<id>.json` (a felhasználóé, 0600, atomikus, symlink-biztos): csak a challenge
//   szövege, az echo jelző, a https URL, az állapot és a határidő. Titok soha.
// - Kimenet a mvpn-nek: `<run>/mgmt-status` (root 0600): `wait <unix idő>` | `ok` | `failed` | `cancelled` | `timeout`.
// - Egy hitelesítési körben (az első várakozástól a CONNECTED-ig) összesen legfeljebb --max-wait mp-et vár (a mvpn
//   MFA_MAX-a, alapból 420): az ismétlődő OPEN_URL / WEB_AUTH / CR_TEXT ezt nem nyújtja. Utána leállítja az openvpn-t
//   (felépülés utáni újrahitelesítésnél is, amikor nincs figyelő app).
// - A hitelesítő adatokat a kapcsolat idejére a root folyamat memóriájában tartja (újracsatlakozás, auth-nocache); a
//   beolvasott nyers fájltartalmat a feldolgozás után nullázza.
// - A management felé csak a `ManagementCommand` parancsai mennek: `state on`, `hold release`, `username "Auth"`,
//   `password "Auth"`, `cr-response`. Nincs általános továbbítás.
// - A naplóba (stdout → a kapcsolat naplója) csak eseménytípusok és a webes URL hosztja kerül, titok soha.
// - Kilép, amikor az openvpn bezárja a socketet (kilépett), vagy a futási könyvtár eltűnik.

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

func log(_ s: String) { print("[mgmt] " + s) }
func fail(_ s: String) -> Never {
    log(s)
    exit(1)
}

// MARK: - Argumentumok

var args: [String: String] = [:]
var it = CommandLine.arguments.dropFirst().makeIterator()
while let key = it.next() {
    guard ["--id", "--run", "--ui", "--uid", "--gid", "--max-wait"].contains(key), let value = it.next() else { fail("usage error") }
    args[key] = value
}
guard let idArg = args["--id"], let id = UUID(uuidString: idArg),
      let run = args["--run"], let uiDir = args["--ui"],
      let uid = args["--uid"].flatMap({ uid_t($0) }), let gid = args["--gid"].flatMap({ gid_t($0) }) else { fail("usage error") }
for path in [run, uiDir] where !path.hasPrefix("/") || path.contains("/../") || path.hasSuffix("/..") || path.utf8.count > 200 {
    fail("invalid path")
}
let isRoot = geteuid() == 0
/// Egy hitelesítési kör összesített várakozási korlátja (mp).
let maxWait = TimeInterval(args["--max-wait"].flatMap { Int($0) }.map { min(max($0, 1), 3600) } ?? 420)

let sockPath = run + "/mgmt.sock"
let credsPath = run + "/mgmt-creds"
let respPath = run + "/mgmt-resp"
let uiName = id.uuidString + ".json"

// MARK: - Fájlok

/// Biztonságos könyvtár: valódi könyvtár (nem symlink); rootként root tulajdonú és nem írható másnak.
func trustedDirectory(_ path: String, privateMode: Bool) -> Bool {
    var st = stat()
    guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { return false }
    if isRoot {
        guard st.st_uid == 0, st.st_mode & 0o022 == 0 else { return false }
        if privateMode, st.st_mode & 0o077 != 0 { return false }
    }
    return true
}

/// Saját tulajdonú, szabályos, egyetlen linkű fájl beolvasása (symlinket nem követ), legfeljebb `max` bájt.
func readPrivateFile(_ path: String, max: Int, remove: Bool) -> Data? {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { return nil }
    defer {
        close(fd)
        if remove { unlink(path) }
    }
    var st = stat()
    guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_nlink == 1,
          st.st_size >= 0, Int(st.st_size) <= max else { return nil }
    var data = Data(count: Int(st.st_size))
    let n = data.withUnsafeMutableBytes { read(fd, $0.baseAddress, Int(st.st_size)) }
    guard n == Int(st.st_size) else { return nil }
    return data
}

var tempCounter = 0

/// Atomikus írás: új, kizárólagos (O_EXCL, O_NOFOLLOW) ideiglenes fájl ugyanabban a könyvtárban, 0600, opcionálisan
/// a felhasználó tulajdonába adva, majd `rename`. A `rename` egy esetleges symlinket maga cserél le, nem követi.
func writeAtomic(dir: String, name: String, data: Data, owner: (uid_t, gid_t)?) -> Bool {
    tempCounter += 1
    let tmp = "\(dir)/.\(name).\(getpid()).\(tempCounter)"
    let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { return false }
    var ok = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) } == data.count
    if ok, let owner, isRoot { ok = fchown(fd, owner.0, owner.1) == 0 }
    if ok { ok = fchmod(fd, 0o600) == 0 }
    close(fd)
    if ok { ok = rename(tmp, "\(dir)/\(name)") == 0 }
    if !ok { unlink(tmp) }
    return ok
}

var seq = 0

func publish(_ state: AuthUIState.State, method: AuthUIState.Method? = nil, text: String? = nil, echo: Bool? = nil,
             url: URL? = nil, deadline: Date? = nil) {
    guard trustedDirectory(uiDir, privateMode: false) else {
        log("state directory is not safe, state not written")
        return
    }
    seq += 1
    let s = AuthUIState(seq: seq, state: state, method: method, text: text, echo: echo, url: url?.absoluteString,
                        deadline: deadline.map { $0.timeIntervalSince1970.rounded() })
    if !writeAtomic(dir: uiDir, name: uiName, data: s.encoded(), owner: (uid, gid)) { log("cannot write the state file") }
}

func clearUI() {
    guard trustedDirectory(uiDir, privateMode: false) else { return }
    unlink("\(uiDir)/\(uiName)")
}

func status(_ line: String) {
    guard trustedDirectory(run, privateMode: true) else { return }
    _ = writeAtomic(dir: run, name: "mgmt-status", data: Data((line + "\n").utf8), owner: nil)
}

// MARK: - Az openvpn folyamat

/// A folyamat indítási útvonala (KERN_PROCARGS2), mint a `ps -o comm`.
func execPath(_ pid: pid_t) -> String? {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
    var buf = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return nil }
    let path = buf[4..<size].prefix { $0 != 0 }
    return String(decoding: path, as: UTF8.self)
}

/// Végleges hiba vagy megszakítás: az openvpn leállítása (SIGTERM), hogy ne próbálkozzon újra (auth-retry interact).
/// Csak a `<run>/pid`-ben álló, ténylegesen `openvpn` nevű folyamatot (pid-újrahasznosítás ellen).
func stopOpenVPN() {
    guard let data = readPrivateFile(run + "/pid", max: 32, remove: false),
          let text = String(data: data, encoding: .utf8),
          let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1,
          let path = execPath(pid), (path as NSString).lastPathComponent == "openvpn" else { return }
    kill(pid, SIGTERM)
}

// MARK: - Bemenet a mvpn-től

guard trustedDirectory(run, privateMode: true) else { fail("the run directory is not safe") }
var credsData = readPrivateFile(credsPath, max: 4096, remove: true)
let creds = credsData.flatMap(ManagementCredentials.parse)
if let n = credsData?.count { credsData?.resetBytes(in: 0..<n) }
credsData = nil
unlink(credsPath)

// MARK: - Csatlakozás

func connectSocket() -> Int32? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(sockPath.utf8)
    guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
        close(fd)
        return nil
    }
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        for (i, b) in bytes.enumerated() { raw[i] = b }
    }
    let ok = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    if ok != 0 {
        close(fd)
        return nil
    }
    return fd
}

var sock: Int32 = -1
let connectDeadline = Date().addingTimeInterval(60)
while Date() < connectDeadline {
    guard trustedDirectory(run, privateMode: true) else { exit(0) }
    if let fd = connectSocket() {
        sock = fd
        break
    }
    usleep(250_000)
}
guard sock >= 0 else { fail("the management socket did not appear") }
log("connected")

func send(_ command: ManagementCommand) -> Bool {
    guard let line = command.line else { return false }
    let data = Array((line + "\n").utf8)
    var off = 0
    while off < data.count {
        let n = data[off...].withUnsafeBytes { write(sock, $0.baseAddress, $0.count) }
        if n <= 0 { return false }
        off += n
    }
    return true
}

// MARK: - Állapotgép

var pendingCRV1: CRV1Challenge?
var crv1Response: String?
var needAuthWaiting = false
var pendingStatic: ManagementStaticRequest?
var crTextPending = false
var awaitingUser = false       // a felhasználó válaszára vagy a webes hitelesítésre várunk
var deadline: Date?
var pendingTimeout: TimeInterval = MFA.webAuthTimeout
var finished = false
/// Az aktuális hitelesítési kör első várakozásának kezdete (a CONNECTED törli).
var roundStart: Date?

/// Határidő a felhasználónak / a szervernek, de legfeljebb a kör kezdete + `maxWait`.
func waitFor(_ seconds: TimeInterval) -> Date {
    let now = Date()
    let start = roundStart ?? now
    roundStart = start
    let d = min(now.addingTimeInterval(seconds), start.addingTimeInterval(maxWait))
    deadline = d
    status("wait \(Int(d.timeIntervalSince1970.rounded(.up)))")
    return d
}

func finish(_ reason: String, cancelled: Bool = false, timedOut: Bool = false) {
    guard !finished else { return }
    finished = true
    awaitingUser = false
    log(reason)
    status(cancelled ? "cancelled" : timedOut ? "timeout" : "failed")
    publish(cancelled ? .cancelled : .failed)
    stopOpenVPN()
}

func sendCredentials(username: String, password: String) {
    guard send(.username(username)), send(.password(password)) else {
        finish("credentials cannot be sent (empty user name, control character, or longer than 255 bytes)")
        return
    }
    log("credentials sent")
}

func sendCRV1() {
    guard let c = pendingCRV1, let response = crv1Response else { return }
    pendingCRV1 = nil
    crv1Response = nil
    needAuthWaiting = false
    sendCredentials(username: c.username, password: c.password(response: response))
}

func handle(_ event: ManagementEvent) {
    guard !finished else { return }
    switch event {
    case .hold:
        if send(.holdRelease) { log("hold released") }
    case .needAuth(nil):
        if pendingCRV1 != nil {
            if crv1Response != nil { sendCRV1() } else { needAuthWaiting = true }
        } else if let creds, !creds.username.isEmpty {
            sendCredentials(username: creds.username, password: creds.password)
        } else {
            finish("the server asks for a user name and password, but none is stored")
        }
    case .needAuth(let sc?):
        guard let creds, !creds.username.isEmpty else {
            finish("the server asks for a user name and password, but none is stored")
            return
        }
        if creds.packed {
            sendCredentials(username: creds.username, password: creds.password)
        } else {
            pendingStatic = sc
            awaitingUser = true
            let d = waitFor(MFA.codePromptTimeout)
            publish(.challenge, method: .static, text: sc.text, echo: sc.echo, deadline: d)
            log("static challenge received")
        }
    case .needOther:
        finish("OpenVPN asks for a password that MacVPN does not provide here")
    case .dynamicChallenge(let c):
        pendingCRV1 = c
        crv1Response = nil
        if c.responseRequired {
            awaitingUser = true
            let d = waitFor(MFA.codePromptTimeout)
            publish(.challenge, method: .crv1, text: c.text, echo: c.echo, deadline: d)
            log("dynamic challenge received")
        } else {
            crv1Response = ""
            log("dynamic challenge received (no response required)")
        }
    case .authFailed:
        finish("authentication failed")
    case .authRetry:
        // Lejárt auth-token vagy átmeneti hiba: az OpenVPN újrapróbál, a következő Need 'Auth'-ra újra a tárolt adatok mennek.
        log("authentication will be retried (session expired or temporary failure)")
    case .webAuth(let url?):
        awaitingUser = true
        let d = waitFor(pendingTimeout)
        publish(.webauth, method: .webauth, url: url, deadline: d)
        // Csak a validált, ASCII (punycode-ot nem dekódoló) hoszt kerül a naplóba.
        log("web authentication requested: \(WebAuthURL.displayHost(url))")
    case .webAuth(nil):
        awaitingUser = true
        let d = waitFor(pendingTimeout)
        publish(.pending, deadline: d)
        log("web authentication URL dropped (only https with a plain ASCII host is accepted)")
    case .crText(let echo, let text):
        crTextPending = true
        awaitingUser = true
        let d = waitFor(MFA.codePromptTimeout)
        publish(.challenge, method: .crtext, text: text, echo: echo, deadline: d)
        log("challenge received (CR_TEXT)")
    case .authPending(let timeout):
        pendingTimeout = min(TimeInterval(timeout ?? Int(MFA.webAuthTimeout)), MFA.webAuthTimeout)
        if !awaitingUser {
            awaitingUser = true
            let d = waitFor(pendingTimeout)
            publish(.pending, deadline: d)
        }
        log("authentication pending")
    case .connected:
        awaitingUser = false
        deadline = nil
        roundStart = nil
        status("ok")
        clearUI()
        log("authenticated")
    case .fatal:
        finish("OpenVPN reported a fatal error")
    case .ignored:
        break
    }
}

func handle(_ r: ManagementResponse) {
    guard !finished else { return }
    switch r.kind {
    case .cancel:
        finish("cancelled by the user", cancelled: true)
    case .webauthAck:
        log("web authentication opened in the browser")
    case .crv1:
        if crTextPending {
            crTextPending = false
            awaitingUser = false
            guard send(.crResponse(r.response)) else {
                finish("the response cannot be sent (too long)")
                return
            }
            publish(.pending, deadline: deadline)
            log("response sent (CR_TEXT)")
        } else if pendingCRV1 != nil {
            crv1Response = r.response
            awaitingUser = false
            publish(.pending, deadline: deadline)
            log("response received (CRV1)")
            if needAuthWaiting { sendCRV1() }
        } else {
            log("response ignored: no challenge is pending")
        }
    case .static:
        guard let sc = pendingStatic, let creds else {
            log("response ignored: no static challenge is pending")
            return
        }
        pendingStatic = nil
        awaitingUser = false
        let password = sc.concat ? creds.password + r.response : MFA.scrv1(password: creds.password, code: r.response)
        publish(.pending, deadline: deadline)
        sendCredentials(username: creds.username, password: password)
    }
}

// MARK: - Fő ciklus

_ = send(.stateOn)
var buffer = [UInt8]()
var skipping = false
var chunk = [UInt8](repeating: 0, count: 4096)
mainLoop: while true {
    var pfd = pollfd(fd: sock, events: Int16(POLLIN), revents: 0)
    let ready = poll(&pfd, 1, 250)
    if ready > 0 {
        let n = read(sock, &chunk, chunk.count)
        if n <= 0 { break mainLoop }
        for b in chunk[0..<n] {
            if b == 0x0A {
                if !skipping {
                    if buffer.last == 0x0D { buffer.removeLast() }
                    handle(ManagementParser.parse(String(decoding: buffer, as: UTF8.self)))
                }
                buffer.removeAll(keepingCapacity: true)
                skipping = false
            } else if !skipping {
                buffer.append(b)
                // Túl hosszú sor: eldobjuk a következő sorvégig.
                if buffer.count > ManagementParser.maxLineBytes {
                    buffer.removeAll(keepingCapacity: true)
                    skipping = true
                }
            }
        }
    } else if ready < 0, errno != EINTR {
        break mainLoop
    }
    if !trustedDirectory(run, privateMode: true) { break mainLoop }
    if var data = readPrivateFile(respPath, max: ManagementResponse.maxFileBytes, remove: true) {
        let parsed = ManagementResponse.parse(data)
        data.resetBytes(in: 0..<data.count)
        if let r = parsed { handle(r) } else { log("invalid response ignored") }
    }
    if awaitingUser, let d = deadline, Date() > d {
        finish("timed out waiting for authentication", timedOut: true)
    }
}
close(sock)
log("management connection closed")
exit(0)
