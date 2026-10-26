//! `macvpn-control-client`: a small command line client of MacVPN's control API, built on the reusable
//! [`Client`] in `lib.rs`.
//!
//! ```text
//! macvpn-control-client pair <name>             ask MacVPN to pair; prints the token once
//! macvpn-control-client list                    the connections this client may use
//! macvpn-control-client hold <connection-id>    bring one up and hold it until Ctrl-C or end of input
//! ```
//!
//! The token never goes on the command line (other users' `ps` could see it): `list` and `hold` read it from
//! the `MACVPN_TOKEN` environment variable or, if that is not set, from the first line of standard input.
//! `MACVPN_SOCKET` overrides the socket path (for example for a sandboxed development build of MacVPN). On Windows
//! the default is WinVPN's named pipe for this user (`\\.\pipe\WinVPN-control-<SID>`), and `MACVPN_SOCKET` takes a
//! pipe name.
//!
//! Remember that a pairing is pinned to the executable that asked for it: a token printed by `pair` works
//! for this binary at this path only.

#[cfg(windows)]
use macvpn_control_client::default_endpoint;
#[cfg(not(windows))]
use macvpn_control_client::default_socket_path;
use macvpn_control_client::{Client, Error, ErrorCode, StateEvent};
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const USAGE: &str = "usage:
  macvpn-control-client pair <name>
  macvpn-control-client list
  macvpn-control-client hold <connection-id>

The token for list and hold comes from MACVPN_TOKEN or the first line of standard input.
MACVPN_SOCKET overrides the socket path (on Windows: the pipe name).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["pair", name] => pair(name),
        ["list"] => list(),
        ["hold", connection] => hold(connection),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            if let Some(hint) = e.code().and_then(hint) {
                eprintln!("{hint}");
            }
            ExitCode::FAILURE
        }
    }
}

/// What the user can do about an error.
fn hint(code: ErrorCode) -> Option<&'static str> {
    Some(match code {
        ErrorCode::Unauthorized => {
            "The token is wrong or revoked, or this binary is not the one that was paired (a rebuild in another \
             folder counts). Pair again."
        }
        ErrorCode::Denied => {
            "The pairing was declined or timed out (after 3 rejections pairing pauses for 10 minutes)."
        }
        ErrorCode::NotAllowed => "Allow the connection for this app in MacVPN: Connections window → Paired apps.",
        ErrorCode::SetupRequired => "Finish the setup in MacVPN's System Status window.",
        ErrorCode::Busy => "The connection is changing state, or a pairing window is already open. Try again.",
        ErrorCode::CredentialsCancelled => "The password prompt in MacVPN was cancelled or timed out.",
        _ => return None,
    })
}

/// `MACVPN_SOCKET`, else MacVPN's socket (macOS) or WinVPN's named pipe for this user (Windows).
fn socket() -> Result<PathBuf, Error> {
    match std::env::var_os("MACVPN_SOCKET") {
        Some(path) if !path.is_empty() => Ok(PathBuf::from(path)),
        _ => Ok(default_endpoint()?),
    }
}

#[cfg(not(windows))]
fn default_endpoint() -> std::io::Result<PathBuf> {
    default_socket_path()
}

/// The token from `MACVPN_TOKEN`, else the first line of standard input.
fn token() -> Result<String, Error> {
    if let Ok(token) = std::env::var("MACVPN_TOKEN")
        && !token.trim().is_empty()
    {
        return Ok(token.trim().to_string());
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprintln!("Token (or set MACVPN_TOKEN):");
    }
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let token = line.trim().to_string();
    if token.is_empty() {
        return Err(Error::Io(io::Error::new(io::ErrorKind::InvalidInput, "no token in MACVPN_TOKEN or on stdin")));
    }
    Ok(token)
}

fn pair(name: &str) -> Result<ExitCode, Error> {
    eprintln!("Waiting for you to answer the pairing window in MacVPN…");
    let pairing = Client::pair(&socket()?, name)?;
    // The token goes to stdout alone, so it can be piped straight into a Keychain item; it is not shown again.
    println!("{}", pairing.token);
    eprintln!("Paired (client id {}). This token is shown only once: store it in the Keychain.", pairing.client_id);
    Ok(ExitCode::SUCCESS)
}

fn list() -> Result<ExitCode, Error> {
    let token = token()?;
    let mut client = Client::open(&socket()?, &token)?;
    for c in client.list()? {
        println!("{}\t{}\t{}\t{}", c.id, c.state.as_str(), c.kind, c.name);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_event(event: &StateEvent) {
    match &event.reason {
        Some(reason) => println!("{} {} ({reason})", event.connection, event.state.as_str()),
        None => println!("{} {}", event.connection, event.state.as_str()),
    }
}

fn hold(connection: &str) -> Result<ExitCode, Error> {
    let token = token()?;
    // `open` sends `hello` at once: MacVPN closes a connection that has not authenticated within 5 seconds.
    let mut client = Client::open(&socket()?, &token)?;
    client.up(connection, print_event)?;
    println!("{connection} connected; holding it until Ctrl-C or end of input (Ctrl-D)");

    // The lease lasts exactly as long as this socket. When standard input ends, close the socket from a second
    // thread; that unblocks `next_event` below. Ctrl-C needs no handler: the process ends, the kernel closes
    // the socket, and MacVPN ends the lease the same way (as it would after a crash).
    let released = Arc::new(AtomicBool::new(false));
    let closer = client.closer()?;
    let flag = released.clone();
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut io::sink());
        flag.store(true, Ordering::SeqCst);
        closer.close();
    });

    while let Some(event) = client.next_event()? {
        print_event(&event);
        // `disconnected` / `failed` of the held connection: the user disconnected it in MacVPN, or it dropped.
        // Either way the lease has ended. MacVPN never reconnects a connection it started for leases; one the
        // user started may come back through "Reconnect Automatically", but without this lease.
        if event.connection == connection && event.state.is_down() {
            eprintln!("The VPN went down; the lease has ended.");
            return Ok(ExitCode::FAILURE);
        }
        // Any other state, known or not, is "in progress": keep holding.
    }
    if released.load(Ordering::SeqCst) {
        eprintln!("Released.");
        Ok(ExitCode::SUCCESS)
    } else {
        // MacVPN says why in a `closing` event before it closes; without one, this app was most likely revoked.
        match client.closing_reason() {
            Some("disabled") => {
                eprintln!("\"Allow other apps to control VPNs\" was turned off in MacVPN; the lease has ended.")
            }
            Some("app_quitting") => eprintln!("MacVPN is quitting; the lease has ended."),
            Some(other) => eprintln!("MacVPN closed the connection ({other}); the lease has ended."),
            None => eprintln!("MacVPN closed the connection; the lease has ended."),
        }
        Ok(ExitCode::FAILURE)
    }
}
