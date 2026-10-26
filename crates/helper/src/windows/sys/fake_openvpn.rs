//! A stand-in for `openvpn.exe` in the tests (debug builds only: `sys/mod.rs` compiles this module only with
//! `debug_assertions`, and the console's `--fake-openvpn` is the only thing that runs it). The OpenVPN engine
//! starts `mvpn.exe` itself with the real argv (`--config …`); this speaks OpenVPN's management protocol on the
//! loopback port with the password from `mgmt.pw`, and prints OpenVPN-like lines. The scenario is a comment line of
//! the config: `# winvpn-fake: ok|userpass|crv1|authfail|dco|exit|hang`.
//!
//! What it prints for the tests to check: its environment's variable names, the driver it was given, and the
//! stored password it received (`userpass` only: the connection log must show it masked).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const CONNECTED: &str = ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,,\r\n";
const NEED_AUTH: &str = ">PASSWORD:Need 'Auth' username/password\r\n";

fn say(line: &str) {
    println!("{line}");
}

fn quoted<'a>(line: &'a str, command: &str) -> Option<&'a str> {
    line.strip_prefix(command)?.strip_prefix(" \"Auth\" \"")?.strip_suffix('"')
}

fn forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

pub fn main(args: &[String]) -> i32 {
    let (mut config, mut port, mut pw_file, mut tap) = (None, None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => config = it.next().cloned(),
            "--management" => {
                let _host = it.next();
                port = it.next().and_then(|p| p.parse::<u16>().ok());
                pw_file = it.next().cloned();
            }
            "--disable-dco" => tap = true,
            _ => {}
        }
    }
    let (Some(config), Some(port), Some(pw_file)) = (config, port, pw_file) else { return 2 };
    let text = std::fs::read_to_string(&config).unwrap_or_default();
    let scenario =
        text.lines().find_map(|l| l.strip_prefix("# winvpn-fake: ")).map(str::trim).unwrap_or("ok").to_string();
    let mut names: Vec<String> = std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
    names.sort();
    say(&format!("fake openvpn: env {}", names.join(",")));
    say(&format!("fake openvpn: driver {}", if tap { "tap-windows6" } else { "ovpn-dco" }));
    if scenario == "exit" {
        say("2026-10-22 10:00:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194");
        return 1;
    }
    let password = std::fs::read_to_string(&pw_file).unwrap_or_default();
    let password = password.lines().next().unwrap_or_default().to_string();
    let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) else {
        say("2026-10-22 10:00:00 MANAGEMENT: Socket bind failed on local address");
        return 1;
    };
    say(&format!("2026-10-22 10:00:00 MANAGEMENT: TCP Socket listening on [AF_INET]127.0.0.1:{port}"));
    let Ok((stream, _)) = listener.accept() else { return 1 };
    serve(stream, &password, &scenario, tap);
    forever()
}

/// The management session; returns when the client goes away (OpenVPN would keep running).
fn serve(mut s: TcpStream, password: &str, scenario: &str, tap: bool) {
    let Ok(reader) = s.try_clone() else { return };
    let mut lines = BufReader::new(reader).lines();
    let _ = s.write_all(b"ENTER PASSWORD:");
    match lines.next() {
        Some(Ok(l)) if l.trim_end() == password => {}
        _ => {
            let _ = s.write_all(b"ERROR: bad password\r\n");
            return;
        }
    }
    let _ = s.write_all(
        b"SUCCESS: password is correct\r\n>INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n\
          >HOLD:Waiting for hold release:0\r\n",
    );
    let connected = |s: &mut TcpStream| {
        say("2026-10-22 10:00:01 Initialization Sequence Completed");
        let _ = s.write_all(CONNECTED.as_bytes());
    };
    for line in lines {
        let Ok(line) = line else { return };
        let line = line.trim_end();
        if line == "state on" {
            let _ = s.write_all(b"SUCCESS: real-time state notification set to ON\r\n");
        } else if line == "signal SIGTERM" {
            let _ = s.write_all(b"SUCCESS: signal SIGTERM thrown\r\n");
            say("2026-10-22 10:00:02 SIGTERM[hard,] received, process exiting");
            std::process::exit(0);
        } else if line == "hold release" {
            let _ = s.write_all(b"SUCCESS: hold release succeeded\r\n");
            match scenario {
                "dco" if !tap => say(
                    "2026-10-22 10:00:01 OPTIONS ERROR: pushed options are incompatible with data channel offload. Use --disable-dco to connect to this server",
                ),
                "userpass" => {
                    let _ = s.write_all(NEED_AUTH.as_bytes());
                }
                "crv1" => {
                    let _ = s.write_all(
                        b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:fakestate:Ym9i:Enter the code']\r\n",
                    );
                    let _ = s.write_all(NEED_AUTH.as_bytes());
                }
                "authfail" => say("2026-10-22 10:00:01 AUTH: Received control message: AUTH_FAILED"),
                "hang" => {}
                _ => connected(&mut s),
            }
        } else if quoted(line, "username").is_some() {
            let _ = s.write_all(b"SUCCESS: 'Auth' username entered, but not yet verified\r\n");
        } else if let Some(pw) = quoted(line, "password") {
            let _ = s.write_all(b"SUCCESS: 'Auth' password entered, but not yet verified\r\n");
            match scenario {
                "crv1" if pw != "CRV1::fakestate::123456" => {
                    say("2026-10-22 10:00:01 AUTH: Received control message: AUTH_FAILED")
                }
                _ => {
                    // Only the stored password (the connection's secret, which the log masks); OpenVPN itself never
                    // prints it.
                    if scenario == "userpass" {
                        say(&format!("fake openvpn: password received {pw}"));
                    }
                    connected(&mut s);
                }
            }
        }
    }
}
