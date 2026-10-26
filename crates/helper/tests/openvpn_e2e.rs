//! OpenVPN end to end through the installed WinVPN Service: a local `openvpn.exe` server on loopback (TAP-Windows6,
//! started by this test as an administrator) with a throwaway PKI made by Git's `openssl.exe`, and a client config
//! sent to `\\.\pipe\WinVPN` like the app does. CI's windows-admin job runs it after installing OpenVPN Community
//! (`scripts/ci-install-openvpn.sh`) and the fresh MSI; the maintainer can run it in an elevated Git Bash. Ignored
//! everywhere (`scripts/ignored-everywhere.txt`): it needs the installed service, OpenVPN Community and an
//! administrator (the server's adapter).
#![cfg(windows)]

use macvpn_core::service_proto::{self as proto, LogSlice, PIPE_NAME};
use macvpn_winsys::pipe::{self, ServerTrust};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const OPENSSL: &str = r"C:\Program Files\Git\usr\bin\openssl.exe";
const REG: &str = r"C:\Windows\System32\reg.exe";

/// The two tests share the machine's adapters: one at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new(OPENSSL).current_dir(dir).args(args).output().unwrap();
    assert!(out.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// A throwaway CA, server and client (prime256v1, valid 1 day), in the test's own folder; nothing committed.
fn pki(dir: &Path) {
    for name in ["ca", "server", "client"] {
        openssl(dir, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", &format!("{name}.key")]);
    }
    openssl(
        dir,
        &["req", "-new", "-x509", "-days", "1", "-key", "ca.key", "-subj", "/CN=WinVPN test CA", "-out", "ca.crt"],
    );
    for name in ["server", "client"] {
        let (key, csr, crt) = (format!("{name}.key"), format!("{name}.csr"), format!("{name}.crt"));
        openssl(dir, &["req", "-new", "-key", &key, "-subj", &format!("/CN={name}"), "-out", &csr]);
        openssl(
            dir,
            &[
                "x509",
                "-req",
                "-days",
                "1",
                "-in",
                &csr,
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &crt,
            ],
        );
    }
}

/// `openvpn.exe` of the installed OpenVPN Community (the path the service trusts, `HKLM\SOFTWARE\OpenVPN`).
fn openvpn_exe() -> PathBuf {
    let out =
        Command::new(REG).args(["query", r"HKLM\SOFTWARE\OpenVPN", "/v", "exe_path", "/reg:64"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("exe_path")).expect("OpenVPN Community is installed");
    PathBuf::from(line.split("REG_SZ").nth(1).expect("exe_path is a REG_SZ").trim())
}

/// TAP-Windows6 adapters made for the test with OpenVPN's `tapctl.exe` (the installer may have made none or one;
/// the TAP-Windows6 test needs one for the server and one for the client), deleted when dropped.
struct TapAdapters {
    tapctl: PathBuf,
    guids: Vec<String>,
}

impl TapAdapters {
    fn create(count: usize) -> TapAdapters {
        let tapctl = openvpn_exe().with_file_name("tapctl.exe");
        let mut made = TapAdapters { tapctl, guids: Vec::new() };
        for _ in 0..count {
            let name = format!("WinVPN-e2e-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            let out = Command::new(&made.tapctl)
                .args(["create", "--hwid", r"root\tap0901", "--name", &name])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let guid = text.split_whitespace().find(|w| w.starts_with('{') && w.ends_with('}'));
            match guid {
                Some(g) if out.status.success() => made.guids.push(g.to_owned()),
                _ => panic!("tapctl create: {text}{}", String::from_utf8_lossy(&out.stderr)),
            }
        }
        made
    }
}

impl Drop for TapAdapters {
    fn drop(&mut self) {
        for guid in &self.guids {
            let _ = Command::new(&self.tapctl).args(["delete", guid]).output();
        }
    }
}

/// The test server: `openvpn.exe` on TAP-Windows6 (`--disable-dco`), its output kept for the failure messages.
struct Server {
    child: Child,
    output: Arc<Mutex<String>>,
}

impl Server {
    fn start(dir: &Path, port: u16, ciphers: &str) -> Server {
        let port = port.to_string();
        let mut child = Command::new(openvpn_exe())
            .current_dir(dir)
            .args([
                "--dev",
                "tun",
                "--disable-dco",
                "--proto",
                "udp4",
                "--port",
                &port,
                "--server",
                "10.201.0.0",
                "255.255.255.0",
                "--topology",
                "subnet",
                "--ca",
                "ca.crt",
                "--cert",
                "server.crt",
                "--key",
                "server.key",
                "--dh",
                "none",
                "--data-ciphers",
                ciphers,
                "--verb",
                "3",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let output = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = mpsc::channel();
        let (stdout, kept) = (child.stdout.take().unwrap(), output.clone());
        // Keeps draining the server's output for as long as it runs.
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let up = line.contains("Initialization Sequence Completed");
                let mut k = kept.lock().unwrap_or_else(|e| e.into_inner());
                k.push_str(&line);
                k.push('\n');
                if up {
                    let _ = tx.send(());
                }
            }
        });
        let server = Server { child, output };
        if rx.recv_timeout(Duration::from_secs(60)).is_err() {
            panic!("the test server did not start:\n{}", server.output());
        }
        server
    }

    fn output(&self) -> String {
        self.output.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn call(args: &[&str], body: &[u8], timeout: Duration) -> proto::Response {
    let mut s = pipe::connect_with(PIPE_NAME, Duration::from_secs(5), ServerTrust::LocalSystem).unwrap();
    s.set_read_timeout(Some(timeout)).unwrap();
    proto::write_request(&mut s, args, body).unwrap();
    proto::read_response(&mut s).unwrap()
}

fn status() -> String {
    String::from_utf8(call(&["status"], b"", Duration::from_secs(20)).stdout).unwrap()
}

/// Brings `extra` (client directives) up through the service against a fresh server on `port`, checks status and
/// the connection log, takes it down; returns the log.
fn connect_through_the_service(id: &str, port: u16, server_ciphers: &str, extra: &str, tap_adapters: usize) -> String {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("winvpn-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    pki(&dir);
    let _adapters = TapAdapters::create(tap_adapters);
    let server = Server::start(&dir, port, server_ciphers);
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    let config = format!(
        "client\ndev tun\nproto udp4\nremote 127.0.0.1 {port}\nnobind\n{extra}verb 3\n<ca>\n{}</ca>\n<cert>\n{}</cert>\n<key>\n{}</key>\n",
        read("ca.crt"),
        read("client.crt"),
        read("client.key")
    );
    // The root layer 8 frame: no auth-user-pass, so no secret lines.
    let body = format!("config {}\n{config}", config.len());
    let r = call(&["up", "openvpn", id, "--lang", "en"], body.as_bytes(), Duration::from_secs(120));
    let log = || {
        let slice = call(&["log", id, "0"], b"", Duration::from_secs(20));
        String::from_utf8_lossy(&LogSlice::parse(&slice.stdout).expect("a log slice").data).into_owned()
    };
    assert_eq!(
        r.code,
        0,
        "up: {}\n--- connection log ---\n{}\n--- server ---\n{}",
        String::from_utf8_lossy(&r.stderr),
        log(),
        server.output()
    );
    let st = status();
    assert!(st.contains(id) && st.contains("\"connected\"") && st.contains("10.201.0."), "{st}");
    let text = log();
    assert!(text.contains("Initialization Sequence Completed"), "{text}");
    assert!(!text.contains("PRIVATE KEY"), "the config's key never reaches the log: {text}");
    let down = call(&["down", "openvpn", id], b"", Duration::from_secs(30));
    assert_eq!(down.code, 0, "down: {}", String::from_utf8_lossy(&down.stderr));
    let st = status();
    assert!(!st.contains(id), "{st}");
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    text
}

/// An AEAD-only config: `choose_driver` picks DCO (no driver option in the argv).
#[test]
#[ignore = "admin: needs the installed WinVPN Service and OpenVPN Community (CI windows-admin)"]
fn admin_an_openvpn_connection_comes_up_through_the_service() {
    let log = connect_through_the_service(
        "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F1",
        11940,
        "AES-256-GCM",
        "data-ciphers AES-256-GCM\n",
        1,
    );
    assert!(!log.contains("retrying with TAP-Windows6"), "{log}");
}

/// A non-AEAD cipher: `choose_driver` picks TAP-Windows6 (`--disable-dco`); OpenVPN's log names the TAP adapter.
#[test]
#[ignore = "admin: needs the installed WinVPN Service and OpenVPN Community (CI windows-admin)"]
fn admin_a_tap_windows6_connection_comes_up_through_the_service() {
    let log = connect_through_the_service(
        "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F2",
        11941,
        "AES-256-GCM:AES-256-CBC",
        "cipher AES-256-CBC\ndata-ciphers AES-256-CBC\n",
        2,
    );
    assert!(log.to_ascii_lowercase().contains("tap-windows"), "{log}");
}
