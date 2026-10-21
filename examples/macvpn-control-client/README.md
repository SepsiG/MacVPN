# macvpn-control-client

A minimal Rust client for MacVPN's local control API. It needs only `std` and `serde_json`, and it is written to be copied into another app (the first user is a Remote Desktop app). The protocol, the security model and the error codes are described in [`docs/control-api.md`](../../docs/control-api.md) ([magyarul](../../docs/control-api.hu.md)).

- [`src/lib.rs`](src/lib.rs): the reusable part. Copy this file.
  - `Client`: one socket connection. It has `pair`, `open` (connect + `hello`), `list`, `up` with an event callback, `down`, `status`, `next_event`, `closer` to end the connection from another thread, and `closing_reason` (why MacVPN closed it: `disabled` or `app_quitting`).
  - `Lease`: one remote session's hold on one VPN. The VPN stays up while the `Lease` lives.
  - `State`, `ErrorCode`: an unknown state counts as "in progress", an unknown error code as `failed`.
- [`src/main.rs`](src/main.rs): a small command line tool built on it, for trying the API out.

The transport is a Unix domain socket (macOS). The crate compiles for Windows too, but there `Client::connect` returns `io::ErrorKind::Unsupported`: the named pipe client comes with WinVPN.

## Before you start

In MacVPN, open the Connections window (**Manage Connections…** in the menu), select **Paired apps** in the sidebar, and turn on **Allow other apps to control VPNs**. While the setting is off, the socket does not exist.

## The command line tool

```sh
cargo build -p macvpn-control-client
BIN=target/debug/macvpn-control-client

# 1. Pair. MacVPN shows a window with the name, this binary's path and the connections to allow.
#    The token is printed once, on stdout.
$BIN pair "My test client"

# 2. List the allowed connections: id, state, kind, name (tab-separated).
MACVPN_TOKEN=… $BIN list

# 3. Bring one up and hold it. The events are printed. Ctrl-C or Ctrl-D ends the hold,
#    and MacVPN brings the VPN down (if no one else holds it and it was not up before).
MACVPN_TOKEN=… $BIN hold 6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01
```

- The token is never taken from the command line, where other users could see it with `ps`. It comes from `MACVPN_TOKEN` or, if that is not set, from the first line of standard input. With `hold`, the rest of standard input stays open: `hold` ends when it reaches its end.
- `MACVPN_SOCKET` overrides the socket path, for example `target/sandbox-home/Library/Application Support/MacVPN/control/macvpn.sock` for a sandboxed development build of MacVPN.
- The pairing is pinned to **the executable that paired**: a token printed by this tool works only for this binary at this path (`target/debug` and `target/release` are different paths). Your app has to pair itself, with `Client::pair` from its own binary.
- `hold` exits with status 1 when the held VPN goes down (the user disconnected it in MacVPN, or it dropped) or when MacVPN closes the socket (it prints why: the setting was turned off, or MacVPN is quitting). MacVPN never reconnects on its own.

To keep the token in the Keychain while you try things out:

```sh
# Store it. With -w last, security prompts for the value, so it does not go into argv.
security add-generic-password -U -s com.example.my-test-client.macvpn -a control-token -w
# Read it back for a run.
MACVPN_TOKEN="$(security find-generic-password -s com.example.my-test-client.macvpn -a control-token -w)" $BIN list
```

## In your app

```rust
use macvpn_control_client::{Client, Lease, default_socket_path};

// Once, from the app itself (the path of the running binary is what MacVPN pins):
let pairing = Client::pair(&default_socket_path()?, "Remote Desktop")?;
keychain_store(&pairing.token); // see docs/control-api.md, "Storing the token"

// Per remote session:
let vpn = Lease::acquire(&default_socket_path()?, &keychain_load()?, &connection_id, |event| {
    show_status(&event.connection, event.state.as_str()); // "waiting_for_mfa": tell the user to look at MacVPN
})?;
run_remote_session();
drop(vpn); // or vpn.release()? to wait until MacVPN has disconnected
```

The full integration how-to, with the Keychain code and the session lifetime pattern, is in [`docs/control-api.md`](../../docs/control-api.md#9-how-to-integrate-a-rust-app).

## Tests

`crates/app-core/tests/control_example_client.rs` runs this `Client` and `Lease` against the real control server with a fake VPN host: pair, hello, list, up, drop, disconnect, and the error paths.
