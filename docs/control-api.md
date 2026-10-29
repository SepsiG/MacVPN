# MacVPN – Local control API

[Magyar változat](control-api.hu.md)

This guide is for developers who want another program on the same Mac to bring MacVPN connections up and down. Most MacVPN users never need it. The [User guide](user-guide.en.md) covers everything else. WinVPN, the Windows version, offers the same API over a named pipe: see [11](#11-windows-winvpn).

The API was built for [RemoteDesktop](https://github.com/LovaszCC/RemoteDesktop), a companion app that manages RDP, SSH, web admin and MikroTik connections and brings up the VPN each one needs. It is a working example of a paired app.

## Contents

1. [What it does](#1-what-it-does)
2. [Turning it on](#2-turning-it-on)
3. [Pairing](#3-pairing)
4. [Security model](#4-security-model)
5. [Protocol](#5-protocol)
6. [Error codes](#6-error-codes)
7. [Lease rules](#7-lease-rules)
8. [Forward compatibility](#8-forward-compatibility)
9. [How to integrate a Rust app](#9-how-to-integrate-a-rust-app)
10. [Troubleshooting](#10-troubleshooting)
11. [Windows (WinVPN)](#11-windows-winvpn)

---

## 1. What it does

While MacVPN runs, a program of the same macOS user (for example a Remote Desktop app) can:

- list the VPN connections the user allowed it to use,
- bring one of them up,
- bring it down again.

The VPN stays up only while the program needs it. The program holds a **lease** on the connection for as long as its socket connection to MacVPN stays open. When the program closes the socket, quits or crashes, the lease ends, and MacVPN brings the VPN down if no one else needs it.

The API does **not** let a program:

- read or change configs, user names, passwords or other secrets,
- create, import or delete connections,
- answer MFA prompts (MacVPN asks the user in its own windows, exactly as for a manual connect),
- connect from another user account or from the network.

The transport is a Unix domain socket. Messages are newline-delimited JSON. An example client in Rust is in [`examples/macvpn-control-client`](../examples/macvpn-control-client/).

## 2. Turning it on

1. In the MacVPN menu, choose **Manage Connections…**.
2. In the Connections window, select **Paired apps** in the sidebar.
3. Turn on **Allow other apps to control VPNs**. It is off by default.

MacVPN then listens on:

```
~/Library/Application Support/MacVPN/control/macvpn.sock
```

While the setting is off, the socket file does not exist. Turning the setting off closes every client connection, after a [`closing` event](#510-the-closing-event) to each authenticated one; the leases end as described in [section 7](#7-lease-rules).

If the socket cannot be set up, the reason is shown under the switch, for example **Other apps cannot control VPNs: the folder … cannot be used (…).** or **Another copy of MacVPN already lets other apps control VPNs.**

## 3. Pairing

A program must be paired once before it can do anything.

1. The program connects to the socket and sends `{"id":1,"op":"pair","name":"Remote Desktop"}`.
2. MacVPN shows the **Allow an App to Control VPNs?** window. The window does not steal focus, its buttons are locked for 1 second, and neither button is the default. It shows:
   - **Name (self-reported)**: the name the program sent. The program chose it, so it proves nothing.
   - **Executable**: the path of the program's executable, read by MacVPN from the operating system. This is the identity MacVPN pins.
   - **Connections it may use**: a checkbox for each connection, none ticked.
3. The user clicks **Allow** or **Deny**.
   - **Allow**: MacVPN sends the token once, `{"id":1,"ok":true,"token":"…","client_id":"…"}`, and closes the connection.
   - **Deny**, or no answer within 2 minutes: `{"id":1,"ok":false,"error":"denied"}`, and the connection closes. After 3 rejections, every pairing is refused with `denied` for 10 minutes.

The token is 32 random bytes, base64url-encoded without padding (43 characters). MacVPN keeps only its SHA-256 hash. **The program must store the token in its own Keychain item**, never in a plain file or a log (see [9.2](#92-storing-the-token-in-the-keychain)).

Only one pairing window can be open at a time; another `pair` meanwhile gets `busy`.

The **Paired apps** section lists every paired program with its name and executable path, **Last used** (or **Never used**), **Paired:**, and its **Allowed connections**, which you can change at any time. **Revoke** unpairs the program and closes its open connections at once. Connections that only it brought up are disconnected. The **Activity** list at the bottom shows the recent pairings, logins and leases.

## 4. Security model

**Who can connect.**

- The socket is in a private folder (`control/`, mode `0700`) and has mode `0600`. MacVPN refuses to serve if that folder is a symlink or is not owned by the user.
- On every connection, MacVPN asks the kernel for the peer's user id. A process of another user is disconnected at once.
- A connection must send `pair` or `hello` within 5 seconds, and it may send at most 20 requests per second. At most 8 clients can be connected at the same time.

**Authentication.** Every connection starts with `{"op":"hello","token":"…"}`. MacVPN accepts it only if:

- the token's hash matches a paired program (compared in constant time),
- that pairing has not been revoked, and
- the peer's executable path is exactly the path pinned at pairing.

Otherwise the reply is a generic `unauthorized`, sent after a 1-second delay, and the connection is closed.

**What a paired program gets.** Only the connections in its allowlist, only up and down, and only state names. No configs, user names, passwords, IP addresses or raw tool output. A failure reason is a short localized text, the same as in MacVPN's own notification.

**Audit.** Pairing requests and their results, failed logins, every `up` and `down` with the program's name and path, and every lease end are recorded in the **Activity** list and in MacVPN's debug output. Tokens are never logged. The menu and the Connections window show **Held by …** next to a leased connection.

### Accepted limitations

Malware that already runs as your user is not fully stopped by these checks. It could:

- replace the paired program's executable at its pinned path, if that path is writable by your user, or
- start or drive the paired program itself.

What it would gain is limited: only the allowlisted connections, only up and down, and no secrets. Every action shows up in the menu and in the Activity list. This matches MacVPN's existing threat model, in which the Homebrew VPN tools are writable by the user as well (see [Security notes](user-guide.en.md#10-security-notes)).

Other known limits:

- The pairing pins a **path**, not a code signature: MacVPN and typical clients are ad-hoc signed, so there is no stable signing identity to check. A rebuilt binary at the same path keeps working; a binary at another path needs a new pairing.
- The name in the pairing window is self-reported. Judge the program by its executable path.
- The client holds the token in its memory while it runs.

## 5. Protocol

### 5.1 Framing

- One JSON object per line, UTF-8, ending in `\n` (`\r\n` is accepted). A request line may be at most 4096 bytes.
- Every request has an `op` and an `id` that the client chooses: an unsigned integer. MacVPN echoes the `id` in the reply. `pair` and `hello` may leave it out; their reply then has no `id` either.
- Replies have `"ok":true` or `"ok":false`. A failed reply has an `error` code and may have a `message`.
- **Events** are unsolicited lines with an `event` key and no `id`. They can arrive at any time, also between a request and its reply.
- Requests are parsed strictly: an unknown field, a repeated key or a wrong type is `bad_request`, and an unknown `op` is `unsupported`. Replies and events may get new fields in later versions; ignore what you do not know.
- Connection ids are UUID-shaped (`8-4-4-4-12` hex digits). They are **case-sensitive**: send them back exactly as `list` returned them.
- Send one request at a time and wait for its reply. That is the simplest correct client; the example client does this.

### 5.2 `pair`

```json
{"id":1,"op":"pair","name":"Remote Desktop"}
```

`name`: 1 to 64 characters after cleanup (control characters become spaces, the text is trimmed). See [section 3](#3-pairing) for the window.

```json
{"id":1,"ok":true,"token":"Q2hhbmdlTWUtVGhpcy1Jcy1Ob3QtQS1SZWFsLVRva2Vu","client_id":"0D6A3C2E-9F1B-4C7A-8E25-6B1F0A9D4C33"}
{"id":1,"ok":false,"error":"denied"}
{"id":1,"ok":false,"error":"busy"}
```

MacVPN closes the connection after the reply, whatever it is. Connect again and send `hello`.

### 5.3 `hello`

```json
{"id":1,"op":"hello","token":"Q2hhbmdlTWUtVGhpcy1Jcy1Ob3QtQS1SZWFsLVRva2Vu"}
```

```json
{"id":1,"ok":true,"api":1}
{"id":1,"ok":false,"error":"unauthorized"}
```

`api` is the protocol version, currently `1`. After `unauthorized` (sent after a 1-second delay) the connection is closed. A token that is not 43 base64url characters gets exactly the same `unauthorized`, after the same delay, so the reply never tells which part was wrong. Only a structurally invalid `hello` (a `token` that is not a string, a missing `token`, an unknown field) is `bad_request`, at once, and the connection stays open.

Any request other than `pair` or `hello` before a successful `hello` gets `unauthorized`, and the connection is closed. A second `pair` or `hello` after it is `bad_request`.

### 5.4 `list`

```json
{"id":2,"op":"list"}
```

```json
{"id":2,"ok":true,"connections":[
  {"id":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","name":"Office","kind":"openvpn","state":"disconnected"},
  {"id":"38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4","name":"Office L2TP","kind":"system","state":"connected"}
]}
```

(Shown on several lines here; on the wire it is one line.)

Only the connections this program may use, in MacVPN's order. `kind` is `openvpn`, `wireguard`, `strongswan`, `sstp`, `l2tp`, `cisco`, or `system` for a VPN set up in macOS outside MacVPN. `state` is one of the states in [5.8](#58-states).

**Team catalog connections** (MacVPN 1.3) appear like any other connection, with the `kind` of their VPN type. Their `id` is derived from the catalog and the item, so it stays the same across catalog versions and on every Mac, and two catalogs never share an id. When a connection is removed from its catalog, or the user unsubscribes from the catalog, MacVPN removes its id from every paired app's allowed connections; subscribing again later never grants access silently. A connection that is up when it is removed stays listed until it goes down.

### 5.5 `up`

```json
{"id":3,"op":"up","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01"}
```

Takes a lease for this socket and starts the connection if it is down, the same way as a manual connect: same MFA prompts, same secrets from the vault, same checks. While it comes up, the client gets events, then one final reply:

```json
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"connecting"}
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"waiting_for_mfa"}
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"connecting"}
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"connected"}
{"id":3,"ok":true,"state":"connected"}
```

or, for example:

```json
{"event":"state","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01","state":"failed","reason":"Timed out: the connection was not established within 30 s"}
{"id":3,"ok":false,"error":"failed","message":"Timed out: the connection was not established within 30 s"}
```

- **Already connected:** the reply `{"id":3,"ok":true,"state":"connected"}` comes at once, without events.
- **Another program is already bringing it up:** this socket joins that connect. It first gets an event with the current state, then the same events and reply.
- **`waiting_for_mfa`** means MacVPN shows a code or sign-in prompt to the user. Tell your user to look at MacVPN. This can take minutes, so do not put a short timeout on the reply.
- **`waiting_for_credentials`** means MacVPN asks the user for a user name, password, shared secret or key password that is not saved. The same applies: tell your user to look at MacVPN, and allow minutes. Your program never sees what the user types. If the user cancels (or lets the 2-minute prompt expire), the `up` ends with `credentials_cancelled`.
- If the `up` fails, the lease ends with it. A later `up` starts a new connect.
- MacVPN checks, in this order: the pairing still exists (`unauthorized`, connection closed), the connection is allowed (`not_allowed`), it still exists (`unknown_connection`), the server is not stopping (`disabled` / `app_quitting`), the connection is not changing state without a lease (`busy`), this socket does not already wait for an `up` of it (`busy`), and, only when this `up` has to start the connection, the setup that this connection needs is complete (`setup_required`).
- **The setup check depends on the connection.** A connection that MacVPN runs through its root helper (OpenVPN, WireGuard, IKEv2, SSTP) needs Homebrew, a current root helper and its type's VPN tool (the same check that greys the connection in the menu with "Not installed: … – System Status"). A system VPN and a native L2TP or Cisco IPsec connection start through macOS and need none of them. A connection that is already up, or already coming up for another lease, is joined without any setup check: `up` replies `connected` even while the setup is incomplete.

### 5.6 `down`

```json
{"id":4,"op":"down","connection":"6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01"}
```

```json
{"id":4,"ok":true}
```

Ends this socket's lease. If it was the last lease of a connection that was started for the leases, MacVPN disconnects it, and the reply comes **after** the disconnect (you may see `disconnecting` / `disconnected` events before it). A pending `up` of the same connection on this socket is answered with `failed` first. `down` always succeeds: a connection without a lease, or one this program may not use, is simply not touched.

You do not have to send `down`: closing the socket ends every lease of that socket.

### 5.7 `status`

```json
{"id":5,"op":"status"}
```

```json
{"id":5,"ok":true}
```

Subscribes this socket to the state events of every allowed connection, for as long as it stays open. The reply carries no states: use `list` for the current ones. Without `status`, a socket gets events only for the connections it holds or waits for. After the user disconnects a held connection, or it drops, the socket still gets that connection's events until it is down.

```json
{"event":"state","connection":"38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4","state":"disconnected"}
```

An event is sent only when the state changes; the same state is not repeated.

### 5.8 States

| State | Meaning |
|---|---|
| `disconnected` | Down. |
| `connecting` | Coming up. |
| `waiting_for_mfa` | MacVPN waits for the user to enter a code or sign in. |
| `waiting_for_credentials` | MacVPN waits for the user to enter a missing user name, password, shared secret or key password (from 1.1.0). |
| `connected` | Up. |
| `disconnecting` | Going down. |
| `failed` | Down after an error. The event has a `reason`: a short localized text for the user. |

Treat any other state as "in progress" (see [section 8](#8-forward-compatibility)).

### 5.9 Limits

| Limit | What happens |
|---|---|
| 8 clients at the same time | The 9th connection is closed at once, without a reply. |
| A line longer than 4096 bytes | `{"ok":false,"error":"bad_request"}` without an `id`, then the connection is closed. |
| No `pair` or `hello` within 5 seconds of connecting | The connection is closed without a reply. |
| More than 20 requests per second (bursts of 20) | The connection is closed without a reply. |
| More than 16 `up`s waiting for their reply on one socket | `busy`. |
| A client that does not read its replies and events (64 lines queued, or a write blocked for 5 seconds) | The connection is closed. |

### 5.10 The `closing` event

```json
{"event":"closing","reason":"disabled"}
```

When the user turns **Allow other apps to control VPNs** off (`"reason":"disabled"`) or MacVPN quits (`"reason":"app_quitting"`), every authenticated socket gets this event as its last line, after the replies to its pending `up`s, and then the connection is closed. It tells a program holding a lease why its socket ends, instead of a bare end of file. The leases end as described in [section 7](#7-lease-rules).

The event is forward-compatible: a client that does not know it ignores it, like any unknown event type, and simply sees the end of file. Later versions may send other reasons. A revoke, a limit and an unauthenticated socket close without it.

## 6. Error codes

Error codes are generic. They never contain raw tool output.

| Code | When | What to do |
|---|---|---|
| `unauthorized` | `hello` with a wrong, malformed or revoked token, or from another executable path than the paired one. A request before `hello`. A request after the program was revoked. The connection is closed. | Pair again (see [section 10](#10-troubleshooting)). |
| `not_allowed` | The connection is not in this program's allowlist, or its id is not exactly as `list` returned it. | Ask the user to allow it under **Paired apps**. |
| `unknown_connection` | The connection was deleted in MacVPN. | Call `list` again. |
| `busy` | The connection is changing state without a lease (someone else is connecting or disconnecting it), a lease's disconnect is still running, this socket already waits for an `up` of it, or too many `up`s are waiting. For `pair`: another pairing window is open. | Retry after a short wait. |
| `setup_required` | `up` has to start a connection run by MacVPN's root helper, and Homebrew or the root helper is missing or out of date, or the VPN tool of this connection's type is missing. Never for a system VPN, a native L2TP / Cisco IPsec connection, or a connection that is already up. | Ask the user to complete MacVPN's **System Status** window. |
| `mfa_cancelled` | The user cancelled the code or sign-in prompt. | Do not retry on your own. |
| `mfa_timeout` | The code or sign-in prompt timed out. | Let the user retry. |
| `credentials_cancelled` | The user cancelled the credential prompt, or it expired after 2 minutes (from 1.1.0). | Do not retry on your own. |
| `locked` | MacVPN's vault is locked (from 1.2.0): `pair`, `hello`, `list`, `up` and `status` are refused until the user unlocks it in MacVPN. `down` still works, and an existing session and its leases are kept. After `pair` or `hello` the connection is closed. | Tell the user to unlock MacVPN, then try again. |
| `failed` | Any other failure. `message`, if present, is a short localized reason for the user. Also: the user disconnected the connection in MacVPN while it was coming up, or your own `down` cancelled the `up`. On WinVPN also a connection Windows cannot run, or a missing WinVPN Service (see [11.1](#111-the-pipe)). | Show the message. |
| `app_quitting` | MacVPN is quitting. The connection closes next (also the `reason` of the [`closing` event](#510-the-closing-event)). | Reconnect after MacVPN runs again. |
| `disabled` | The user turned **Allow other apps to control VPNs** off. The connection closes next (also the `reason` of the [`closing` event](#510-the-closing-event)). | — |
| `unsupported` | Unknown `op`. | — |
| `bad_request` | A malformed request: not JSON, an unknown field, a repeated key, a wrong type, a bad connection id, a bad name, an over-long line. (A malformed token is `unauthorized`.) | Fix the client. |
| `denied` | `pair` only: the user clicked **Deny**, the window timed out, pairing is paused after 3 rejections, or MacVPN could not read the program's executable path. | — |

Treat any other code as `failed` (see [section 8](#8-forward-compatibility)).

## 7. Lease rules

- A connection can have several lease holders. Every socket that sent a successful `up` holds one, even sockets of the same program.
- **The last lease ends, the VPN goes down.** When the last holder sends `down`, closes the socket, quits or crashes, or is revoked, MacVPN disconnects a connection that it started for the leases.
- **A pre-existing connection stays up.** If the connection was already up without a lease (the user or another path started it), `up` only reports `connected`, and no lease end ever brings it down.
- **The user wins.** If the user disconnects a leased connection in MacVPN, every lease on it ends at once. The holders get the `disconnecting` and `disconnected` events (a pending `up` gets `failed`), and MacVPN does not reconnect on its own. Closing the socket afterwards changes nothing.
- **A drop ends the leases too.** If the VPN fails or drops, the holders get the `failed` (or `disconnected`) event, and the leases end. Reconnecting is up to the program: send `up` again. MacVPN's **Reconnect Automatically** (from 2.0) never brings back a connection that it started for leases: it stays down until a program sends `up` again or the user connects it. A pre-existing connection (one the user started) may be reconnected after sleep or a network loss if **Reconnect Automatically** is on for it; your lease has ended all the same, so send `up` again if the session still needs the VPN.
- **Sleep and wake.** Sockets stay open, and the leases survive the sleep. If the VPN drops meanwhile, the rule above applies: the leases end, and a connection started for them is not reconnected, whether or not the program still runs after the wake.
- **Turning the setting off.** Pending `up`s get `disabled`, every authenticated socket gets the `closing` event with `"reason":"disabled"`, every socket is closed, and the leases end as usual: connections that only the leases kept up are disconnected.
- **Quitting MacVPN.** The quit question names the programs holding connections: **Used by other apps through MacVPN: …. Quitting ends their sessions.** Pending `up`s get `app_quitting`, every authenticated socket gets the `closing` event with `"reason":"app_quitting"`, and every socket is closed. The leases end **without** a disconnect: the quit question decides. **Disconnect and Quit** disconnects every connection as usual, and **Quit, Keep Them Running** leaves them up, without leases (MacVPN finds them again on its next launch, as connections that were already up).
- The menu and the Connections window show **Held by …** next to a leased connection.

## 8. Forward compatibility

Later MacVPN versions add states and error codes without changing `api`. The state `waiting_for_credentials` and the error `credentials_cancelled` are such additions; they ship in the same release as API 1 (1.1.0). The error `locked` is another one (1.2.0). Every client must follow these rules:

- **An unknown state means "in progress".** Keep waiting for the final reply of `up`, and keep holding the lease.
- **An unknown error code means `failed`.** Show the `message` if there is one, and log the code.
- **Unknown fields** in replies and events, and unknown `event` types, are ignored. A client written before the [`closing` event](#510-the-closing-event) ignores it and still works: it sees the end of file.
- Do not send fields that this document does not describe: requests are parsed strictly.

The example client implements all of this: `State::Other` is "in progress" and `ErrorCode::from_wire` maps unknown codes to `Failed`.

## 9. How to integrate a Rust app

### 9.1 Copy the client

Copy [`examples/macvpn-control-client/src/lib.rs`](../examples/macvpn-control-client/src/lib.rs) into your app, for example as `src/macvpn.rs`, and add `serde_json` to your dependencies. It has:

- `Client`: one socket. `Client::pair`, `Client::open` (connect + `hello`), `list`, `up(id, on_event)`, `down`, `status`, `next_event`, `closer`, and `closing_reason` (the reason of the `closing` event, once the socket has closed).
- `Lease`: one remote session's hold on one VPN.
- `State`, `ErrorCode`, `Error`: with the forward-compatibility rules built in.

### 9.2 Storing the token in the Keychain

Store the token as a generic password in your app's own Keychain item, under a service name of your own.

With the [`security-framework`](https://crates.io/crates/security-framework) crate:

```rust
use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};

const SERVICE: &str = "com.example.remote-desktop.macvpn";
const ACCOUNT: &str = "control-token";

fn store_token(token: &str) -> Result<(), security_framework::base::Error> {
    set_generic_password(SERVICE, ACCOUNT, token.as_bytes())
}

fn load_token() -> Option<String> {
    let bytes = get_generic_password(SERVICE, ACCOUNT).ok()?;
    String::from_utf8(bytes).ok()
}

fn forget_token() {
    let _ = delete_generic_password(SERVICE, ACCOUNT);
}
```

Without an extra crate, with the `security` tool. Its interactive mode (`security -i`) reads the command from standard input, so the token never appears in a command line that other processes could see:

```rust
use std::io::Write;
use std::process::{Command, Stdio};

const SERVICE: &str = "com.example.remote-desktop.macvpn";
const ACCOUNT: &str = "control-token";

fn store_token(token: &str) -> std::io::Result<bool> {
    // A token is base64url (A–Z, a–z, 0–9, '-', '_'), so it needs no quoting.
    let mut child = Command::new("/usr/bin/security").arg("-i").stdin(Stdio::piped()).stdout(Stdio::null()).spawn()?;
    let command = format!("add-generic-password -U -s {SERVICE} -a {ACCOUNT} -w {token}\n");
    child.stdin.take().expect("piped").write_all(command.as_bytes())?; // dropped: end of input
    // `security -i` does not report a failed command in its exit status: read the item back.
    Ok(child.wait()?.success() && load_token().as_deref() == Some(token))
}

fn load_token() -> Option<String> {
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
```

From a terminal: `security add-generic-password -U -s com.example.remote-desktop.macvpn -a control-token -w` (with `-w` last, `security` prompts for the value).

### 9.3 Pairing from the app itself

MacVPN pins the executable path of the process that pairs. So the app pairs itself, for example from a **Pair with MacVPN** button in its settings:

```rust
use macvpn::{Client, ErrorCode, default_socket_path};

fn pair_with_macvpn() -> Result<(), Box<dyn std::error::Error>> {
    // Blocks until the user answers MacVPN's window (at most about 2 minutes): run it off the UI thread.
    let pairing = match Client::pair(&default_socket_path()?, "Remote Desktop") {
        Err(e) if e.code() == Some(ErrorCode::Denied) => return Err("MacVPN did not allow the pairing".into()),
        other => other?,
    };
    store_token(&pairing.token)?; // the token is not shown again
    Ok(())
}
```

If the socket does not exist (`Error::Io` with `NotFound` or `ConnectionRefused`), tell the user to turn on **Allow other apps to control VPNs** in MacVPN. If `hello` later returns `unauthorized`, forget the token and offer to pair again.

### 9.4 Tying the socket to the remote session

Open **one socket per remote session**, take the lease when the session starts, and close the socket when it ends. Do not keep a long-lived socket for the whole app: the lease, and so the VPN, would outlive the session.

```rust
use macvpn::{Lease, State, default_socket_path};

fn run_session(connection_id: &str, host: &str) -> Result<(), Box<dyn std::error::Error>> {
    let Some(token) = load_token() else { return Err("pair with MacVPN first".into()) };
    // Connects, sends hello within the 5-second limit, sends up and waits for "connected".
    let mut vpn = Lease::acquire(&default_socket_path()?, &token, connection_id, |event| match event.state {
        State::WaitingForMfa => show_status("Confirm the sign-in in MacVPN"),
        State::WaitingForCredentials => show_status("Enter the VPN password in MacVPN"),
        ref state if state.is_in_progress() => show_status("Connecting the VPN…"),
        _ => {}
    })?;

    // Watch the VPN while the session runs: on a separate thread, or in your event loop.
    let closer = vpn.closer()?;
    let watcher = std::thread::spawn(move || {
        while let Ok(Some(change)) = vpn.next_change() {
            if change.state.is_down() {
                // The user disconnected it in MacVPN, or it dropped. The lease has ended.
                notify_user("The VPN went down");
                break;
            }
        }
        // `vpn` is dropped here: the socket closes.
    });

    let result = remote_desktop_session(host); // the actual session

    closer.close(); // the session is over: the socket closes, the lease ends
    let _ = watcher.join();
    Ok(result?)
}
```

The guarantees come from the socket itself: if your app crashes or is killed, the kernel closes the socket, and MacVPN ends the lease. Two sessions that need the same VPN each hold their own `Lease`; the VPN stays up until both have ended.

Choosing the connection: call `list` (for example in your connection settings), let the user pick, and store the `id` exactly as received. The `name` can change; the `id` stays.

## 10. Troubleshooting

- **The socket does not exist** (`No such file or directory`, or `Connection refused`). **Allow other apps to control VPNs** is off, or MacVPN is not running. Turn it on in the Connections window → **Paired apps**. If a message is shown under the switch, it names the cause.
- **`unauthorized` after a rebuild or a move.** The pairing is pinned to the executable path. A build in another folder (for example `target/debug` instead of the installed `/Applications/…`), or a moved app, does not match. The Paired apps list shows **Path changed** with the new path. Revoke the old entry and pair again from the new location.
- **`unauthorized` after it worked.** The program was revoked in **Paired apps**, or the token was stored wrong. Pair again.
- **`busy`.** The connection is being connected or disconnected by someone else (the user, MacVPN, or a lease that just ended). Wait a moment and retry. For `pair`: another pairing window is open. If you get it for `up` right after your own `down` or a closed socket, the disconnect is still running.
- **`setup_required`.** MacVPN's setup is incomplete: Homebrew, the root helper or this connection's VPN tool is missing or out of date. Open MacVPN's **System Status** window and finish the setup. MacVPN checks this only when the `up` has to start a connection run by the root helper; a system VPN, a native L2TP / Cisco IPsec connection and a connection that is already up never get it.
- **`not_allowed`.** Tick the connection under **Allowed connections** in **Paired apps**. Check that you send the id exactly as `list` returned it (ids are case-sensitive).
- **The connection closes right after connecting.** Send `hello` (or `pair`) within 5 seconds, keep under 20 requests per second, and keep reading the socket: a client that lets its replies and events pile up is disconnected.
- **`denied` at once, without a window.** Pairing is paused for 10 minutes after 3 rejections.
- **The VPN stays up after the session.** It was already up before the first lease (a pre-existing connection), or another socket still holds it. Check the **Held by …** label.

---

## 11. Windows (WinVPN)

WinVPN speaks exactly this protocol (sections 3 to 8: the same requests, events, error codes and lease rules). Only the transport, the client's identity and the place for the token differ. Turning it on and pairing work as in sections 2 and 3, in WinVPN's Connections window → **Paired apps** ([WinVPN user guide, 5.4](winvpn-user-guide.en.md#54-paired-apps-control-api)).

### 11.1 The pipe

- **Name:** `\\.\pipe\WinVPN-control-<SID>`, where `<SID>` is the user's security identifier (`S-1-5-21-…`; `whoami.exe /user` prints it). The example client's `default_endpoint()` builds it; pass it wherever a socket path goes (`Client::pair`, `Client::open`, `Lease::acquire`, `MACVPN_SOCKET`). It is not `\\.\pipe\WinVPN`, which is the WinVPN Service's own pipe.
- **Who can connect:** only programs running as the same user **in a local logon** of this PC. The pipe denies network logons and refuses remote clients, so another user, the network, and even the same user over SSH or another remote shell are refused (access denied). While **Allow other apps to control VPNs** is off, the pipe does not exist (`NotFound`).
- **Identity:** WinVPN reads the client's user (SID) from the pipe with identification-level impersonation, and its executable path from its process; the pairing is pinned to that path, as on macOS. A client that opens the pipe without allowing identification is closed.
- **The client checks the server:** before it sends anything (a token, a request), the example client checks that the process serving the pipe runs as the same user, and refuses a pipe another user created first (a squatter) with `PermissionDenied`. Use the example client's transport (it is `macvpn-winsys`' `pipe`, the implementation WinVPN itself uses), or do the same check.
- **Lifetime:** as on macOS, a lease ends when the pipe handle closes: when your program closes it, exits or is killed.
- **`kind`:** the same values; `system` is one of the user's own Windows VPNs (Settings → Network & internet → VPN).
- **Error codes** are the same. On Windows:
  - `setup_required`: an OpenVPN connection while OpenVPN Community is not installed (System Status installs it).
  - `failed` with the service's text: an OpenVPN or WireGuard connection while the WinVPN Service is missing, not reachable or from another WinVPN version (never `setup_required`: the fix is repairing WinVPN). L2TP/IPsec, IKEv2, SSTP and system VPNs do not need the service.
  - `failed` with the connection's reason: a connection Windows cannot run, such as Cisco IPsec ("Cisco IPsec is not supported by Windows. …") or IKEv2 with a pre-shared key, or a kind whose Windows VPN service is turned off.

### 11.2 Storing the token in Credential Manager

Keep the token in the user's Credential Manager, as a generic credential of your own (WinVPN never reads it). **Never put the token on a command line** (`cmdkey.exe /pass:…`, a program argument): every process of the user, and process-creation auditing, can see command lines.

With `windows-sys` (features `Win32_Foundation`, `Win32_Security_Credentials`):

```rust
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
};

const TARGET: &str = "com.example.remote-desktop.winvpn";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn store_token(token: &str) -> std::io::Result<()> {
    let (target, user) = (wide(TARGET), wide("control-token"));
    let mut blob = token.as_bytes().to_vec();
    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_ptr().cast_mut(),
        UserName: user.as_ptr().cast_mut(),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE, // DPAPI for this user, never roams
        ..Default::default()
    };
    // SAFETY: every pointer in `cred` outlives the call; CredWriteW copies the blob.
    let ok = unsafe { CredWriteW(&cred, 0) } != 0;
    blob.fill(0);
    if ok { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

fn load_token() -> Option<String> {
    let target = wide(TARGET);
    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target` is NUL-terminated; a returned credential is freed below.
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
        return None;
    }
    // SAFETY: CredReadW succeeded: the struct and its blob are valid until CredFree, called once.
    unsafe {
        let c = &*cred;
        let token = (!c.CredentialBlob.is_null())
            .then(|| std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize))
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok());
        CredFree(cred.cast());
        token
    }
}

fn forget_token() {
    let target = wide(TARGET);
    // SAFETY: `target` is NUL-terminated.
    unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
}
```

Pairing from the app itself, the remote-session lease and the rest of section 9 are the same, with `default_endpoint()` in place of `default_socket_path()`.

### 11.3 The command line tool on Windows

```powershell
cargo build -p macvpn-control-client
$bin = "target\debug\macvpn-control-client.exe"

# 1. Pair. WinVPN shows its window with this binary's path; the token is printed once.
& $bin pair "My test client"

# 2. List or hold: the tool asks "Token (or set MACVPN_TOKEN):" on its standard input.
#    Paste the token there; it never goes on a command line.
& $bin list
& $bin hold 6F1C2A4E-0B6D-4E43-9C55-1D2A7B8E9F01

# Or keep it in this PowerShell session only, read without echo:
$s = Read-Host -AsSecureString "WinVPN token"
$env:MACVPN_TOKEN = [System.Net.NetworkCredential]::new('', $s).Password
& $bin list
Remove-Item Env:MACVPN_TOKEN
```

`hold` ends when its standard input ends (Ctrl+Z, Enter) or when the VPN goes down. Run it in your own desktop session: over SSH the pipe refuses the connection.

### 11.4 Troubleshooting on Windows

- **`NotFound` (the pipe does not exist):** **Allow other apps to control VPNs** is off, WinVPN is not running, or it runs in another user's session.
- **Access denied when connecting:** you connect from another user or from a network logon (SSH, a remote shell, a service account). Run the client in the user's own desktop session.
- **`PermissionDenied` before anything was sent:** the pipe is served by another user's process (a squatter took the name). Sign out and in again; report it to the PC's administrator.
- **`unauthorized` after a rebuild:** as on macOS, the pairing is pinned to the executable path (`target\debug` and `target\release` differ).
