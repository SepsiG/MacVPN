# MacVPN – User Guide

[Magyar változat](user-guide.hu.md)

MacVPN is a menu bar app for macOS 14 or later. It manages OpenVPN, WireGuard, IKEv2 (strongSwan), L2TP/IPsec and Cisco IPsec connections in one place. You can import and edit configs there, passwords are kept in the Keychain, and every connection has a live log.

> **Language:** MacVPN follows the macOS language setting (System Settings → General → Language & Region, or the language set for MacVPN). It is available in English and Hungarian. If neither is among your preferred languages, it uses English. This guide uses the English labels; the [Hungarian guide](user-guide.hu.md) shows the Hungarian ones.

## Contents

1. [Installation](#1-installation)
2. [First launch and the System Status window](#2-first-launch-and-the-system-status-window)
3. [Adding connections by type](#3-adding-connections-by-type)
4. [Import and export](#4-import-and-export)
5. [Connecting](#5-connecting)
6. [Debug mode and the log](#6-debug-mode-and-the-log)
7. [Troubleshooting from the log](#7-troubleshooting-from-the-log)
8. [Updates](#8-updates)
9. [Uninstalling](#9-uninstalling)
10. [Security notes](#10-security-notes)

---

## 1. Installation

### 1.1 Download the DMG

1. Download the latest `MacVPN-x.y.z.dmg` from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Open the DMG and drag the **MacVPN** icon onto the **Applications** folder.
3. Eject the DMG in Finder.

### 1.2 Allow the first launch (Gatekeeper)

The app is not signed with an Apple Developer ID, so macOS blocks it on first launch ("cannot be opened because Apple cannot check it…"). To allow it:

1. Launch MacVPN once from the Applications folder. Close the warning (**Done** or **OK**).
2. Open **System Settings → Privacy & Security**.
3. Scroll down to the **Security** section. It says "MacVPN was blocked…". Click **Open Anyway**.
4. Enter your password, then click **Open Anyway** again in the dialog that appears.

You only need to do this once. Later updates are installed from inside the app (see [chapter 8](#8-updates)).

### 1.3 Homebrew and the VPN tools

For OpenVPN, WireGuard and IKEv2 connections, MacVPN uses tools installed with the [Homebrew](https://brew.sh) package manager: `openvpn`, `wireguard-tools`, `strongswan`, `bash`. You can install them from the System Status window (see the next chapter). If you already have Homebrew, you can also do it in Terminal:

```
brew install openvpn wireguard-tools strongswan bash
```

L2TP and Cisco IPsec connections use the built-in macOS VPN and do not need Homebrew.

---

## 2. First launch and the System Status window

After launch, MacVPN appears as a shield icon in the menu bar. It has no Dock icon.

- **grey shield:** no active connection
- **shield with a check mark:** at least one connection is active
- **shield with an exclamation mark:** an error (a failed connection, or the status cannot be queried)

If anything is missing, the **System Status** window opens automatically on first launch. You can open it later from the menu (**System Status**). It shows three checks, each green or red:

1. **Homebrew.** If it is missing, the **Install…** button opens Terminal with the official installer. The installer asks for your administrator password. When it finishes, come back and press **Check Again**.
2. **VPN tools.** Next to the list of missing tools, the **Install** button runs `brew install`. The output is shown live in the window. The installation continues even if you close the window.
3. **Permissions (root scripts + sudoers).** The **Authorize** button asks for the admin password once. It installs the `/usr/local/libexec/macvpn` scripts and the `/etc/sudoers.d/macvpn` rule. After that, connecting and disconnecting work without a password. If an app update brings newer root scripts, this row says **Update required**. Press **Authorize** again.

When all three are green, setup is done. L2TP and Cisco IPsec work without them.

---

## 3. Adding connections by type

You add connections in the **Connections** window. To open it, use the menu: **Manage Connections…** or **New Connection / Import…**.

- The list is on the left. **My Connections** are the ones created in MacVPN. **System VPNs** are VPNs configured elsewhere in macOS. You can only start and stop those. For L2TP and Cisco IPsec system VPNs you can also store the shared secret in MacVPN (see [3.5](#35-system-vpns-shared-secret-for-l2tp--cisco)).
- From the toolbar **New** (+) menu, pick a type (OpenVPN, WireGuard, IKEv2, L2TP, Cisco IPsec) or **Import from File…**.
- The selected connection has two tabs on the right: **Settings** and **Log**.

Text-based types (OpenVPN, WireGuard, IKEv2) have a monospace editor. **Save** (⌘S) checks the config first. If it finds errors, the faulty lines are shown in red with their line numbers (for example `Line 3: Directive not allowed: xyz – delete the line or comment it out (#)`), and nothing is saved. Passwords have their own fields (**Authentication (stored in the Keychain)**). They go into the macOS Keychain, not into the config.

If you switch connections or close the window with unsaved changes, the app asks: **Save**, **Discard** or **Cancel**.

### 3.1 OpenVPN

The easiest way is to import the `.ovpn` file from your provider (**New → Import from File…**, or drag the file onto the list).

- If the `.ovpn` refers to external files (for example `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), the import reads them from next to the `.ovpn` and embeds them (into `<ca>…</ca>` blocks). So before importing, keep those files next to the `.ovpn`. If a file is missing, the import reports an error.
- If the server asks for a username and password (an `auth-user-pass` line), fill in **Username** and **Password**.
- For security reasons some directives are not allowed, for example `up`, `down`, `script-security`, `plugin` and `log` (they would run external scripts or override MacVPN's own settings). MacVPN sets up DNS itself. See [section 7.7](#77-directive-not-allowed--forbidden-directive) for details.

### 3.2 WireGuard

Import the `.conf` file, or create a new one (**New → WireGuard**) and fill in the template:

```
[Interface]
PrivateKey = <your private key>
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <the server's public key>
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
```

- `AllowedIPs = 0.0.0.0/0` sends all traffic through the VPN. If you only need an internal network, enter that instead (for example `10.10.0.0/16`).
- The `PreUp`, `PostUp`, `PreDown`, `PostDown` and `SaveConfig` keys are not allowed.
- WireGuard needs no username or password. It authenticates with the key pair.

### 3.3 IKEv2 (strongSwan)

IKEv2 configs use strongSwan `swanctl.conf` syntax. A new connection (**New → IKEv2**) starts with a template. For username and password (EAP-MSCHAPv2):

```
connections {
  office {
    remote_addrs = vpn.example.com
    vips = 0.0.0.0
    local {
      auth = eap-mschapv2
      eap_id = john.smith
    }
    remote {
      auth = pubkey
      id = vpn.example.com
    }
    children {
      office {
        remote_ts = 0.0.0.0/0
      }
    }
  }
}
```

- The **Username** field must match `eap_id`. Put the password into **Password**. These are not stored in the config. MacVPN adds them in a `secrets` block when connecting.
- If the server uses a pre-shared key (PSK), set `auth = psk` on both sides and put the key into **Pre-shared key (PSK)**.
- If the server certificate is not signed by a well-known authority, its CA certificate must go into the strongSwan certificate directory (with Homebrew usually `/opt/homebrew/etc/swanctl/x509ca/`). Ask the server operator for help with this.
- `include`, `updown`, and `secrets` that refer to a file (`file = …`) are not allowed.

### 3.4 L2TP/IPsec and Cisco IPsec

These use the built-in macOS VPN. You set them up in a form (**New → L2TP** or **New → Cisco IPsec**):

- **Name**, **Server**, **Account name**, **Password**, **Pre-shared key (PSK)**
- for Cisco also **Group name**
- **Send all traffic over VPN**: when on, all traffic goes through the VPN

**Profile approval:** the **Save and Install Profile** button creates and opens a configuration profile. macOS does not install it on its own:

1. Open **System Settings → General → Device Management** (on older macOS: **Profiles**).
2. Double-click the MacVPN profile, click **Install…**, and enter your password.

You must approve the profile again after every change. When you delete a connection, MacVPN opens the Profiles pane, where you remove the profile yourself.

When connecting, MacVPN passes the saved PSK and password to macOS directly, so the connection does not depend on macOS finding them in the System keychain.

### 3.5 System VPNs: shared secret for L2TP / Cisco

A VPN set up in System Settings (for example **Office L2TP**) appears under **System VPNs**. MacVPN does not change its settings. Sometimes macOS cannot read the shared secret of such a VPN when it is started from another app: the connection does not come up, and macOS may show a "server not reachable" message, although connecting from System Settings works.

For L2TP and Cisco IPsec system VPNs, the detail view has two fields:

- **Shared secret (PSK)**
- **Password (optional, if not saved in macOS)**

Click **Save**. They are stored in the MacVPN keychain (not in the VPN's own settings), and passed to macOS each time you connect from MacVPN. **Forget saved secrets** deletes them. Leaving a field empty also deletes it.

If you switch away or close the window with unsaved changes here, the app asks the same **Save / Discard / Cancel** question as for other connections.

---

## 4. Import and export

**Import.** Use **New → Import from File…**, or drag one or more files into the Connections window. The type is detected from the extension and the content:

- `.ovpn`, or a `client` / `dev tun` line plus a `remote` line → OpenVPN
- `[Interface]` + `PrivateKey` → WireGuard
- `connections {` → IKEv2 (strongSwan)

If one file cannot be recognized or is invalid, the other files are still imported. One dialog lists all the errors.

**Export.** The export icon in the connection header (**Export… (without passwords)**) saves the config in its original format: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, or `.mobileconfig` for native connections.

- The password, PSK and username are **not** exported. In native profiles they are left empty.
- **Warning, WireGuard:** the `PrivateKey` is part of the config, so it **is** in the export. The app warns you about this. Store or share such a file only in a trusted place.
- The exported file is created with `600` permissions (only you can read it).
- `.ovpn`, WireGuard `.conf` and `.swanctl.conf` exports can be imported into MacVPN again.
- A `.mobileconfig` export (L2TP, Cisco IPSec) **cannot** be imported into MacVPN. To use it on another Mac, double-click it in Finder: macOS installs it as a profile, then approve it in **System Settings → General → Device Management** (Profiles). If you drop a `.mobileconfig` file on MacVPN's import, it tells you the same.

---

## 5. Connecting

- **From the menu:** click the switch next to the connection. The status indicator:
  - **green dot:** connected (with the IP address and the elapsed time)
  - **spinner:** connecting or disconnecting
  - **red dot:** error (with a short reason)
  - **empty circle:** not connected
- **From the Connections window:** the **Connect** / **Disconnect** button.
- Several connections can be active at the same time.
- If a tool is missing for a type, the connection is greyed out and shows **Missing tool**. Check the **System Status** window.
- When a connection fails, a macOS notification appears ("…: connection failed"). Clicking it opens the connection's **Log** tab. You also get a notification if a live connection drops unexpectedly. There is no automatic reconnect.
- **On quit**, if a connection is active, the app asks: **Disconnect and Quit**, **Quit, Keep Them Running** or **Cancel**. MacVPN recognizes connections that kept running on its next launch.

---

## 6. Debug mode and the log

If a connection does not come up, debug mode shows what happened, step by step.

**To start it:**

- in the menu, **Option (⌥) + click** the switch, or
- in the Connections window, the **Connect in Debug Mode** button.

The **Log** tab then opens automatically and follows the events live. Debug mode applies to this one connection attempt only.

In debug mode:

- **OpenVPN:** more verbose output (`--verb 5`): the TLS handshake, the settings pushed by the server, routes, DNS.
- **WireGuard:** the `wg-quick` steps, and after connecting the `wg show` output (handshake, bytes transferred, without keys).
- **IKEv2:** a detailed IKE log (IKE_SA_INIT, AUTH, CHILD_SA).
- **L2TP / Cisco:** the log of the macOS VPN processes (for up to 60 seconds, or until the connection is up). These types have no log outside debug mode.
- **Diagnostics** before and after connecting: server name resolution, the routing table, DNS state and the network interfaces.

**Log lines, colour-coded:**

| Prefix | Meaning |
|---|---|
| `═══` | start of a new connect or disconnect (with the date) |
| `▶ [mvpn]` | MacVPN's own steps (copying the config, validation, tools found) |
| `$ …` | a command that was run (passwords masked as `***`) |
| `✗` | an error |
| other | the tool's own output (openvpn, wg-quick, charon) |

**Log actions:** filters (**All**, **Commands**, **Errors**), **Search**, **Follow** (auto-scroll), **Copy**, **Save…**. Passwords, PSKs and private keys never appear in the log, so you can share a saved log (for example with your network administrator).

---

## 7. Troubleshooting from the log

First read the error message in the menu or the notification. If that is not enough, connect in debug mode and search the **Log** tab (the **Errors** filter shows only the error lines). The messages below are the English ones; with Hungarian as the system language, MacVPN shows them in Hungarian.

### 7.1 `AUTH_FAILED` (OpenVPN)

Message: **Authentication failed (AUTH_FAILED)**. The server rejected the username or password.

- Check the **Username** and **Password** fields, then press **Save**.
- If the account has expired or is locked, contact your provider.
- If the server asks for a one-time code (OTP), MacVPN does not support that yet.

### 7.2 `TLS handshake failed` / `TLS Error` (OpenVPN)

The encrypted channel was not established. A typical line: `TLS Error: TLS key negotiation failed to occur within 60 seconds`.

- Wrong server address, port or protocol (`proto udp` or `tcp`). Compare with your provider's details.
- A firewall, or a hotel or corporate network, blocks the port. Try from another network.
- A mismatched `<tls-auth>` or `<tls-crypt>` key or `key-direction`, or a wrong `<ca>`. Import a fresh `.ovpn` from your provider.

### 7.3 Timeout

Message: **Timed out: the connection was not established within 30 s**. For native connections: **Timed out**. The connection did not come up within 30 seconds, so MacVPN stopped it.

- Check your internet connection and whether the server is reachable. The diagnostics in the debug log show whether the server name resolves.
- Look at the last lines of the log. The real cause is often there (for example a TLS error or an unreachable server).

### 7.4 No WireGuard handshake

The WireGuard connection looks green (the interface exists), but no traffic flows. In debug mode the `wg show` output has no `latest handshake` line, or `received` is 0.

- Wrong `Endpoint` (address or port), or the network blocks UDP.
- The `PublicKey` in `[Peer]` is not the server's key, or your public key is not registered on the server.
- `AllowedIPs` does not cover the target network.
- Disconnect, fix the config, and connect again.

### 7.5 IKE AUTH failed (IKEv2)

Message: **IKE negotiation failed (details in the log)**. Typical log lines: `received AUTHENTICATION_FAILED notify error`, or `constraint check failed`.

- Wrong username, password or PSK. **Username** must match `eap_id`.
- The server identity (`remote { id = … }`) does not match the name in the server certificate.
- The CA that signed the server certificate is missing (see [3.3](#33-ikev2-strongswan)).
- A different `auth` mode (`eap-mschapv2`, `psk` or `pubkey`). Ask the server operator.

### 7.6 Profile not approved (L2TP / Cisco)

Message: **The profile is not installed: <name>**. The profile created by MacVPN has not been installed in macOS yet.

- Approve it under **System Settings → General → Device Management** (see [3.4](#34-l2tpipsec-and-cisco-ipsec)).
- After any change, approve the profile again.
- If the message is **The connection could not be established – for details, connect in debug mode**, connect in debug mode and look at the `racoon` / `pppd` lines (typically a wrong PSK or password).
- **System VPN** (for example **Office L2TP**): the message is **The connection did not come up. If this is an L2TP/IPsec VPN, enter its shared secret (PSK) in MacVPN → Connections → <name>.** Enter the PSK (and, if macOS does not have it saved, the password) as described in [3.5](#35-system-vpns-shared-secret-for-l2tp--cisco), then connect again. In the system log this case shows up as `L2TP: incorrect user shared secret found`.
- If a PSK is already saved and the message is **The connection did not come up.**, check that the PSK and password are correct, and that the server is reachable.

### 7.7 "Directive not allowed" / "Forbidden directive"

You get these errors on **Save** or when connecting, for example:

- `Line 3: Forbidden directive: up – delete the line or comment it out (#)`
- `Line 5: Directive not allowed: xyz – delete the line or comment it out (#)`
- `Line 7: External file reference, use an inline block: ca`
- WireGuard: `Line 4: Forbidden key: postup`, `Line 6: Key not allowed: …`
- IKEv2: `Line 2: Forbidden: include`, `Line 9: Forbidden key: updown`

MacVPN starts the VPN tools as root, so it only allows known, safe settings. To fix:

- **Forbidden directive / key** (for example `up`, `down`, `script-security`, `PostUp`): these would run external commands. Delete the line or put `#` in front of it. MacVPN handles DNS and routes itself, so these scripts are not needed.
- **Directive not allowed:** a rare or unknown setting. If it is not essential, comment it out. If you need it, open a GitHub issue.
- **External file reference:** a certificate refers to a file (`ca ca.crt`). Import the `.ovpn` again with the referenced files next to it, or paste their contents into a `<ca>…</ca>` block.
- **Control character not allowed**: the file contains an invisible character (for example text copied from Windows). Retype the line.

### 7.8 Other

- **"Cannot query the status: …"** warning in the menu: the root scripts or the sudoers rule are missing or outdated. Open the **System Status** window and press **Authorize**.
- **"openvpn not found (brew install openvpn)"** and similar: install the missing tool from the **System Status** window.

---

## 8. Updates

MacVPN looks for new versions on the GitHub Releases page: at launch, then every 24 hours.

- When a newer version exists, the menu shows **Update available: vX.Y.Z**. Clicking it opens a window with the release notes.
- The **Download and Install** button:
  1. downloads the DMG and its `.sha256` file, and verifies the SHA-256 checksum;
  2. mounts the DMG, and checks that the app inside is MacVPN (`local.macvpn`) and that its version matches the release;
  3. asks about unsaved changes and active connections, just like quitting;
  4. quits, replaces the app where it runs from (usually `/Applications/MacVPN.app`), and restarts it.
- To check manually: menu → **Check for Updates Now**.
- To turn off automatic checks: menu → the **Check for Updates Automatically** checkbox.
- If an update brings new root scripts, the **System Status** window shows **Update required**. Update them with **Authorize** and one admin password.
- If the app's location is not writable (for example it runs directly from Downloads or from the DMG), the update reports an error. Move the app to the Applications folder, or update manually: download the new DMG and replace the app with it.
- The update log is at `~/Library/Caches/MacVPN/update.log`.

---

## 9. Uninstalling

1. Open the **System Status** window and click **Uninstall MacVPN…**.
2. The confirmation dialog lists what will be removed:
   - `/usr/local/libexec/macvpn` (root scripts)
   - `/etc/sudoers.d/macvpn` (sudoers rule)
   - `/var/run/macvpn` (runtime data)
   - `/var/log/macvpn` (connection logs)
3. If you tick **Also delete user data (connections and Keychain passwords)**, your connections (`~/Library/Application Support/MacVPN`) and their passwords in the Keychain are deleted too, including the shared secrets saved for system VPNs.
4. Click **Uninstall** and enter the admin password. MacVPN disconnects active connections first.
   If a connection cannot be disconnected, the uninstall stops ("A connection could not be disconnected, uninstall cancelled.") and nothing is removed. Disconnect it (or restart the Mac), then try again.
5. At the end a window titled **MacVPN has been uninstalled** appears with this text:
   > You can now drag the app to the Trash. The Homebrew packages were kept (brew uninstall openvpn wireguard-tools strongswan).

   If you had L2TP or Cisco connections, a second paragraph is shown:
   > You can remove the L2TP / Cisco profiles in System Settings → General → Device Management.

   After **Quit MacVPN**, drag `MacVPN.app` to the Trash.

MacVPN does not remove the Homebrew packages, because other programs may use them. If you no longer need them:

```
brew uninstall openvpn wireguard-tools strongswan
```

Remove L2TP and Cisco profiles under **System Settings → General → Device Management**.

---

## 10. Security notes

- **Unsigned app.** MacVPN is not signed with an Apple Developer ID and is not notarized. That is why you need the "Open Anyway" step on first launch. Only download it from the official [Releases](https://github.com/SepsiG/MacVPN/releases) page.
- **Passwords.** Passwords, PSKs and usernames are stored in the macOS Keychain. They are masked (`***`) in the log, and exports do not contain them. The exception is the WireGuard `PrivateKey`, which is part of the config. While an OpenVPN connection with a password is up, the username and password are also kept in a root-only file (`/var/run/macvpn/<id>/auth`, permissions `600` in a `700` directory), so OpenVPN can log in again when it reconnects. The file is deleted when you disconnect.
- **Sudoers and Homebrew (known limitation).** To connect, MacVPN uses a sudoers rule to run the `/usr/local/libexec/macvpn/mvpn` script as root without a password, and that script runs the Homebrew tools (`openvpn`, `wg-quick`, `charon`). The Homebrew directory (`/opt/homebrew`) is writable by your user. Malware running in your user account could replace those programs and gain root that way. Config filtering protects against accidental or imported dangerous settings, not against malware already running in your account. On a single-user Mac that you administer yourself, this is an acceptable risk. If it is not for you, do not enable the root layer, and use only L2TP / Cisco connections.
- **Update integrity (limitation).** Without a Developer ID and a signed update feed, the authenticity of a download rests on HTTPS and on the SHA-256 checksum from the same GitHub release. This protects against corrupted or tampered-in-transit downloads. But if someone takes over the GitHub account or repository, they can publish a malicious release, and the updater cannot detect that. If you do not accept this risk, turn off **Check for Updates Automatically** and update manually after verifying the release.
