# MacVPN – User Guide

[Magyar változat](user-guide.hu.md)

MacVPN is a menu bar app for macOS 14 or later (Apple silicon or Intel). It manages OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec and Cisco IPsec connections in one place. You can import and edit configs there, passwords are kept in the Keychain, and every connection has a live log. This guide describes version 1.0. The menu's **Help** item opens it.

For short step-by-step instructions, see the [How-to guide](how-to.en.md). This guide is the full reference.

> **Language:** MacVPN follows the macOS language setting (System Settings → General → Language & Region, or the language set for MacVPN). It is available in English and Hungarian. If neither is among your preferred languages, it uses English. This guide uses the English labels; the [Hungarian guide](user-guide.hu.md) shows the Hungarian ones.

## Contents

1. [Installation](#1-installation)
2. [First launch and the System Status window](#2-first-launch-and-the-system-status-window)
3. [Adding connections by type](#3-adding-connections-by-type)
4. [Import and export](#4-import-and-export)
5. [Connecting](#5-connecting)
6. [Debug mode and the log](#6-debug-mode-and-the-log)
7. [Troubleshooting from the log](#7-troubleshooting-from-the-log)
8. [Updates](#8-updates) ([Upgrading from 0.x](#81-upgrading-from-0x))
9. [Uninstalling](#9-uninstalling)
10. [Security notes](#10-security-notes)

---

## 1. Installation

### 1.1 Download the DMG

1. Download the latest `MacVPN-x.y.z.dmg` from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Open the DMG and drag the **MacVPN** icon onto the **Applications** folder.
3. Eject the DMG in Finder.

### 1.2 Allow the first launch (Gatekeeper)

The app is ad-hoc signed (with the hardened runtime), not signed with an Apple Developer ID and not notarized, so macOS blocks it on first launch ("cannot be opened because Apple cannot check it…"). To allow it:

**macOS 14:**

1. In Finder, open the Applications folder.
2. Control-click (or right-click) **MacVPN** and choose **Open**.
3. Click **Open** in the dialog.

**macOS 15 or later** (the Control-click shortcut no longer works there):

1. Launch MacVPN once from the Applications folder. Close the warning (**Done** or **OK**).
2. Open **System Settings → Privacy & Security**.
3. Scroll down to the **Security** section. It says "MacVPN was blocked…". Click **Open Anyway**.
4. Enter your password, then click **Open Anyway** again in the dialog that appears.

You only need to do this once. Later updates are installed from inside the app (see [chapter 8](#8-updates)).

### 1.3 Homebrew and the VPN tools

For OpenVPN, WireGuard, IKEv2 and SSTP connections, MacVPN uses tools installed with the [Homebrew](https://brew.sh) package manager. You can install them from the System Status window (see the next chapter).

| Type | Homebrew package | Tools MacVPN looks for |
|---|---|---|
| OpenVPN | `openvpn` | `openvpn` |
| WireGuard | `wireguard-tools`, `bash` | `wg`, `wg-quick`, `wireguard-go`, `bash` (version 4 or later, for `wg-quick`) |
| IKEv2 (strongSwan) | `strongswan` | `swanctl`, `charon` |
| SSTP | `sstp-client` | `sstpc` (plus the `pppd` built into macOS) |
| L2TP/IPsec, Cisco IPsec | none | the built-in macOS VPN |

If you already have Homebrew, you can also install everything in Terminal:

```
brew install openvpn wireguard-tools strongswan sstp-client bash
```

If a tool is missing, only the connections of that type are greyed out; the other types still work.

---

## 2. First launch and the System Status window

After launch, MacVPN appears as a shield icon in the menu bar. It has no Dock icon.

- **grey shield:** no active connection
- **shield with a check mark:** at least one connection is active
- **shield with an exclamation mark:** an error (a failed connection, or the status cannot be queried)
- **key:** a connection is waiting for authentication (see [5.2](#52-multi-factor-authentication-mfa))

Click the icon to open the menu. It lists your connections, each with a switch, and these items: **New Connection / Import…**, **Manage Connections…**, **System Status**, **Help** (opens this guide), **Check for Updates Now**, **Check for Updates Automatically**, **Only Offer Updates Published at Least 24 Hours Ago**, **Launch at Login** and **Quit MacVPN**. When an update is available, **Update available: vX.Y.Z** appears too. The hint at the bottom reminds you: **Option-click a switch: debug mode**.

If anything is missing, the **System Status** window opens automatically at launch. You can open it any time from the menu (**System Status**). It shows three checks, each green or red:

1. **Homebrew.** If it is missing, the **Install…** button opens Terminal with the official installer. The installer asks for your administrator password. If the installer cannot be downloaded, the Terminal window says so and stops without running anything. When it finishes, come back and press **Check Again**.
2. **VPN tools.** Next to the list of missing tools, the **Install** button runs `brew install`. The output is shown live in the window. The installation continues even if you close the window.
3. **Permissions (root scripts + sudoers).** The **Authorize** button asks for the admin password once. It installs MacVPN's root layer: the single root binary `/usr/local/libexec/macvpn/mvpn` with its `VERSION` file (root layer 7), and the `/etc/sudoers.d/macvpn` rule. After that, connecting and disconnecting work without a password. The row shows **Installed (version 7)** when it is up to date. If an app update brings a newer root layer, it says **Update required (6 → 7)** (with the installed and the new version); if a file is missing, **Incomplete installation**. Press **Authorize** again. If connections are active, the window warns first: **Updating the system component will disconnect active VPN connections.**

When all three are green, setup is done. L2TP and Cisco IPsec work without them.

### 2.1 Launch at login

MacVPN does not start automatically by default. To start it every time you log in, tick **Launch at Login** in the menu (below **Check for Updates Automatically**) or in the **System Status** window. Untick it to stop. The checkbox shows what macOS reports, so it also follows changes you make in **System Settings → General → Login Items**.

- If macOS asks for approval, a note appears: "Approve MacVPN in System Settings → General → Login Items." The **Open Login Items Settings…** button opens that page. Turn MacVPN on there.
- MacVPN is not signed with an Apple Developer ID, so macOS often cannot register it the usual way. In that case MacVPN adds a small login LaunchAgent instead (`~/Library/LaunchAgents/local.macvpn.launcher.plist`, which runs `open -b local.macvpn`). The checkbox stays ticked with the note "Enabled via a login LaunchAgent (applies at next login)." MacVPN does not start right away; it starts at your next login. The LaunchAgent opens the app by its bundle ID, so it keeps working if you move the app. It may also appear in **System Settings → General → Login Items** under **Allow in the Background**. Unticking the checkbox (or uninstalling) removes the file.
- If turning it on fails both ways, an alert shows the reason, and the checkbox stays unticked.
- The checkbox is disabled when MacVPN is not running from the Applications folder (`/Applications` or `~/Applications`), for example straight from the DMG or from Downloads. Drag the app to Applications, open it from there, and try again.

---

## 3. Adding connections by type

You add connections in the **Connections** window. To open it, use the menu: **Manage Connections…** or **New Connection / Import…**.

- The list is on the left: the connections created in MacVPN and the **system VPNs** (VPNs configured elsewhere in macOS, marked **System VPN** under their name) in one list, pinned ones on top under **Pinned** (see [5.1](#51-order-of-connections)). You can only start and stop system VPNs. For L2TP and Cisco IPsec system VPNs you can also store the shared secret in MacVPN (see [3.5](#35-system-vpns-shared-secret-for-l2tp--cisco)).
- From the toolbar **New** (+) menu, pick a type (OpenVPN, WireGuard, IKEv2, SSTP, L2TP, Cisco IPsec) or **Import from File…**. A new connection starts with a template and a name like "New OpenVPN"; rename it in the name field.
- The selected connection's header has **Connect** / **Disconnect**, **Connect in Debug Mode**, the export icon and the delete icon (**Delete**, with a confirmation). Below it are two tabs: **Settings** and **Log**.
- If the status cannot be queried (for example the root layer is missing), a warning banner with a **System Status** button appears at the top of the window.

Text-based types (OpenVPN, WireGuard, IKEv2) have a monospace editor. **Save** (⌘S) checks the config first. If it finds errors, they are listed in red under the editor with their line numbers (for example `Line 3: Forbidden directive: up – delete the line or comment it out (#)`), and nothing is saved. Risky OpenVPN settings appear in a yellow panel while you type (see [3.1](#31-openvpn)). Passwords have their own fields (**Authentication (stored in the Keychain)**). They go into the macOS Keychain, not into the config.

SSTP, L2TP and Cisco IPsec have a form instead of a text editor (see [3.4](#34-l2tpipsec-and-cisco-ipsec) and [3.6](#36-sstp)).

**Stored passwords are never shown.** A password field that has a stored value says **Saved — type to replace**. Leave it alone to keep the stored value, type to replace it, or click **Remove saved password** and save to delete it. The status line under the editor shows **Unsaved changes** or **Saved: <time>**.

If you switch connections or close the window with unsaved changes, the app asks: **Save**, **Discard** or **Cancel**.

### 3.1 OpenVPN

The easiest way is to import the `.ovpn` file from your provider (**New → Import from File…**, or drag the file onto the list).

- If the `.ovpn` refers to external files (for example `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), the import reads them from next to the `.ovpn` and embeds them (into `<ca>…</ca>` blocks). So before importing, keep those files next to the `.ovpn`. If a file is missing, the import reports an error.
- If the server asks for a username and password (an `auth-user-pass` line), fill in **Username** and **Password**.
- If the private key is protected by a password (a password-protected PKCS#12 file, or an encrypted PEM key: `-----BEGIN ENCRYPTED PRIVATE KEY-----` or `Proc-Type: 4,ENCRYPTED`), enter it in **Private key password**. It is stored in the Keychain and passed to OpenVPN only while connecting.
- MacVPN sorts every directive into three tiers (the full list is in [openvpn-directives.md](openvpn-directives.md)):
  - **Allowed** directives work as usual, for example `setenv CONFIG_VERSION "2.0.4"`, `remap-usr1 SIGTERM`, `pull-filter`, `machine-readable-output`.
  - **Risky settings** (for example `user nobody`, `group nogroup`, `route-noexec`, server-side or Windows-only options, and every directive MacVPN does not know) are shown in a yellow **Risky settings** panel, each with a short reason. Tick **I acknowledge these settings and the security risks** to save and connect. The acknowledgement covers exactly the risky directives present when you save: if you add another one later, you have to tick the box again.
  - **Forbidden** directives, for example `up`, `down`, `script-security`, `plugin`, `log`, `chroot` and `echo`, are never allowed (they would run external scripts, load code, read or write files as root, or override MacVPN's own settings). MacVPN sets up DNS itself. See [section 7.7](#77-directive-not-allowed--forbidden-directive) for details.
- With `user` / `group`, OpenVPN drops root after connecting: add `persist-tun` so reconnects keep working. DNS is restored when you disconnect in MacVPN; if OpenVPN exits on its own, disconnect in MacVPN to restore it.
- The arguments of the allowed directives are checked too: for example `dev` can only be `tun`, `tap` or `utunN`, ports and timers must be numbers, and host names and cipher names cannot contain `/` or start with `-`. `<connection>` blocks are supported; their lines go through the same checks.

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
- Values are checked: keys must be 44-character base64, `Address`/`AllowedIPs` IP addresses with an optional prefix (`10.0.0.2/32`), `Endpoint` `host:port` or `[IPv6]:port`, `MTU`/`ListenPort`/`PersistentKeepalive` numbers. No value may start with `-`.
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
- Only the documented `swanctl.conf` keys are accepted, each in its own section. `certs`, `cacerts`, `cacert` and `pubkeys` take plain file names only (no `/` or `..`); strongSwan looks them up in its own certificate directories (for example `x509ca/`). `crl_uris`, `ocsp_uris` and `file:` URIs are not allowed.

### 3.4 L2TP/IPsec and Cisco IPsec

These use the built-in macOS VPN. You set them up in a form (**New → L2TP** or **New → Cisco IPsec**):

- **Name**, **Server**, **Account name**, **Password**, **Pre-shared key (PSK)**
- for Cisco also **Group name**
- **Send all traffic over VPN**: when on, all traffic goes through the VPN

**Profile approval:** the **Save and Install Profile** button creates and opens a configuration profile. macOS does not install it on its own:

1. Open **System Settings → General → Device Management** (on older macOS: **Profiles**).
2. Double-click the MacVPN profile, click **Install…**, and enter your password.

You must approve the profile again after every change. When you delete a connection, MacVPN opens the Profiles pane, where you remove the profile yourself.

**What is in the profile.** The profile contains the server, the account name and the PSK, but **not the password**. When you connect from MacVPN, it passes the saved PSK and password to macOS directly, so the connection does not depend on macOS finding them in the System keychain. If you start the VPN from System Settings instead, macOS asks for the password. The PSK stays in the profile because without it the VPN service would not work from System Settings.

The profile file is written to a private temporary folder (only you can read it), not next to your connections. MacVPN deletes it once the VPN shows up in macOS, or at the latest the next time MacVPN starts. If you approve the profile later than that, click **Save and Install Profile** again. Older MacVPN versions kept a `profile.mobileconfig` (with the password) in the connection's folder; MacVPN deletes these when it starts.

**Matching the macOS service.** Once the profile is installed, MacVPN remembers the ID of that macOS VPN service (a service with the same name and server address) and from then on connects, disconnects and shows the status by ID. A different VPN that happens to have the same name then appears in the list as a system VPN (marked **System VPN**). If MacVPN cannot tell which of several same-named services is its own, it does not connect (and does not pass the password) and shows: **More than one VPN service is named "<name>"…**. Rename or remove the other one in **System Settings → Network**.

The **account name** is saved in the connection's settings file (`meta.json`) in plain text: it is not a secret. The password and the PSK are in the Keychain.

### 3.5 System VPNs: shared secret for L2TP / Cisco

A VPN set up in System Settings (for example **Office L2TP**) appears in the list marked **System VPN**. MacVPN does not change its settings. Sometimes macOS cannot read the shared secret of such a VPN when it is started from another app: the connection does not come up, and macOS may show a "server not reachable" message, although connecting from System Settings works.

For L2TP and Cisco IPsec system VPNs, the detail view has two fields:

- **Shared secret (PSK)**
- **Password (optional, if not saved in macOS)**

Click **Save**. They are stored in the MacVPN keychain (not in the VPN's own settings), and passed to macOS each time you connect from MacVPN. **Forget saved secrets** deletes them. Leaving a field empty also deletes it.

If you switch away or close the window with unsaved changes here, the app asks the same **Save / Discard / Cancel** question as for other connections.

### 3.6 SSTP

SSTP (Secure Socket Tunneling Protocol, the Microsoft VPN over HTTPS, port 443) runs through the root layer with the Homebrew `sstp-client` package (`sstpc`) and the macOS built-in `pppd`. Install `sstp-client` from the **System Status** window (or `brew install sstp-client`).

Create it with **New → SSTP**, or import an `.sstp` file. It has a form, not a text editor:

- **Name**, **Server** (host name or IPv4/IPv6 address, without a port), **Port** (443 by default). Connecting to an IPv6 address has not been tested against a real server yet; prefer the host name.
- **Username** and **Password**. The password goes into the Keychain. Use `user@domain` instead of `DOMAIN\user`: backslashes, spaces and quotes are not allowed in the user name. **The SSTP password must not contain quotation marks (`"`), backslashes (`\`) or control characters**: `sstpc` passes the password to `pppd` without escaping, so these characters could change `pppd`'s settings. The form shows an error and does not save such a password; change the password on the server if needed.
- **Server certificate**:
  - **System CA**: the server certificate must be signed by a well-known authority. This uses the CA certificates of Homebrew's OpenSSL, not the macOS Keychain, so a company CA that is only installed in the Keychain is not trusted here.
  - **Custom CA file**: **Choose PEM File…** loads the CA certificate (`-----BEGIN CERTIFICATE-----`). It is stored inside the connection's config. A binary (DER) `.cer` file must be converted to PEM first, for example `openssl x509 -inform der -in ca.cer -out ca.pem`.
  - **No verification**: the server certificate is not checked (shown in red). Anyone between you and the server can impersonate it and capture your login. Use it only for testing.
- **Send all traffic over VPN** (on by default): all IPv4 traffic goes through the VPN. When off, only the VPN peer address is routed through it.
- **Use the server's DNS** (on by default): the DNS servers sent by the server are set on every network service while connected, and restored when you disconnect (the same way as for OpenVPN).

Authentication is MS-CHAPv2 with a user name and password. PAP, CHAP and EAP are refused, so certificate (EAP-TLS) login is not supported.

The config file (and the `.sstp` export) is plain `key=value` text, without the password:

```
server=vpn.example.com
port=443
user=john.smith@corp.example
cert=system
route_all=yes
peer_dns=yes
```

With `cert=ca` the CA certificate follows in a `<ca>…</ca>` block.

---

## 4. Import and export

**Import.** Use **New → Import from File…** (you can select several files), or drag one or more files into the Connections window (an empty window says **Or drop an .ovpn / .conf / .sstp file here.**). Each file must be a regular UTF-8 text file of at most 1 MB. The type is detected from the extension and the content:

- `.ovpn`, or a `client` / `dev tun` line plus a `remote` line → OpenVPN
- `[Interface]` + `PrivateKey` → WireGuard
- `connections {` → IKEv2 (strongSwan)
- `.sstp`, or a `server=…` line plus a `user=`, `cert=`, `route_all=` or `peer_dns=` line → SSTP

If one file cannot be recognized or cannot be imported, the other files are still imported. One dialog lists all the errors.

**OpenVPN files that refer to other files** (`ca ca.crt`, `tls-auth ta.key 1`, …): MacVPN copies the referenced files into the config as inline blocks. After the import it lists them, for example **Imported, inlined: ca.crt, ta.key**. For safety, a referenced file is only read if:

- it is inside the folder of the `.ovpn` file (or one of its subfolders). `../` paths, absolute paths outside that folder and symbolic links that point outside it are refused with **The referenced file is outside the config's folder**;
- it is at most 1 MB;
- its content matches the directive: a PEM certificate for `ca`, `cert` and `extra-certs`; a PEM private key (`-----BEGIN … PRIVATE KEY-----`) for `key`; an OpenVPN static key (`-----BEGIN OpenVPN Static key V1-----`) for `tls-auth`, `tls-crypt` and `secret`; a tls-crypt-v2 client key for `tls-crypt-v2`; DH parameters for `dh`. Otherwise: **The file for the … directive (…) does not have the expected format**.

A `pkcs12 client.p12` file is embedded the same way, as base64 in a `<pkcs12>` block (it must be a PKCS#12 file, inside the folder, at most 1 MB). If it has a password, enter it in **Private key password** after the import. A username/password file in `auth-user-pass` (for example `auth-user-pass auth.cfg`) is never copied into the config: if it is inside the folder, at most 1 KB and has exactly two lines (username, password), MacVPN asks **Use the credentials from … for this connection?**; if you choose **Use**, it stores them in the connection's **Username** and **Password** fields (Keychain) and says so in the import message; otherwise enter them yourself. An `askpass pass.txt` file is handled the same way for the **Private key password**. If the private key is encrypted, the import message reminds you to fill in **Private key password**.

**MikroTik RouterOS.** Configs exported from RouterOS v7 (`/interface ovpn-server server export-client-config`) and the classic v6 wiki configs (with `ca.crt`, `client.crt`, an encrypted `client.key` and `auth-user-pass auth.cfg` next to the `.ovpn`) import without errors or risky settings. Enter the key's export passphrase in **Private key password**.

**Checking imported configs.** The imported config is checked right away with the same rules as **Save**. If it has problems, it is still imported, and its editor opens with the problems in red, so you can fix them and save. If it contains risky settings, the import message says so (**Imported. It contains risky settings (…)**), and the editor shows them in the yellow **Risky settings** panel: tick the checkbox and save before connecting.

**Export.** The export icon in the connection header (**Export… (passwords are never included)**) saves the config in its original format: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, `.sstp`, or `.mobileconfig` for native connections.

- The password, PSK and username are **not** exported. In native profiles they are left empty. The SSTP user name is part of the config, so it is in the `.sstp` export; the password is not.
- **Private keys:** keys that are part of the config can be. If the config contains an OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<pkcs12>`, `<auth-user-pass>` or `<http-proxy-user-pass>` block, a WireGuard `PrivateKey` / `PresharedKey`, or a strongSwan `secrets` section, MacVPN warns you (**The config contains private keys or credentials**) and offers three choices: **Export Without Keys** (the default: these OpenVPN blocks and the strongSwan `secrets` section are removed, WireGuard keys are left empty), **Export With Keys**, or **Cancel**. Anyone who has the keys can connect as you: export them only if the recipient needs them, and keep the file in a trusted place.
- The exported file is created with `600` permissions (only you can read it).
- `.ovpn`, WireGuard `.conf`, `.swanctl.conf` and `.sstp` exports can be imported into MacVPN again.
- A `.mobileconfig` export (L2TP, Cisco IPSec) **cannot** be imported into MacVPN. To use it on another Mac, double-click it in Finder: macOS installs it as a profile, then approve it in **System Settings → General → Device Management** (Profiles). If you drop a `.mobileconfig` file on MacVPN's import, it tells you the same.

---

## 5. Connecting

- **From the menu:** click the switch next to the connection. The status indicator:
  - **green dot:** connected (with the IP address and the elapsed time)
  - **spinner:** connecting or disconnecting
  - **red dot:** error (with a short reason)
  - **key icon:** waiting for authentication: a one-time code or a sign-in in the browser (see [section 5.2](#52-multi-factor-authentication-mfa))
  - **empty circle:** not connected
- **From the Connections window:** the **Connect** / **Disconnect** button.
- Several connections can be active at the same time.
- If a tool is missing for a type, the connection is greyed out and shows **Missing tool**. Check the **System Status** window.
- **Notifications.** When a connection fails, a macOS notification appears ("…: connection failed", with the text **Open MacVPN for details**). The notification does not contain the error message itself, because notifications can be seen on the lock screen; the full reason is shown in MacVPN. Clicking it opens the connection in the **Connections** window, on its **Log** tab. You also get a notification if a live connection drops unexpectedly ("…: the connection dropped"), and when a connection waits for a code or a sign-in ("…: authentication needed"; clicking it brings the code window forward). macOS asks once for permission to show notifications. There is no automatic reconnect.
- **On quit** (**Quit MacVPN**, ⌘Q, and also logout, restart or shutdown), MacVPN first asks about unsaved changes in the Connections window (**Save**, **Discard** or **Cancel**). Then, if a connection is active, it asks: **Disconnect and Quit**, **Quit, Keep Them Running** or **Cancel**. Cancel keeps MacVPN running (and cancels the logout). MacVPN recognizes connections that kept running on its next launch.

### 5.1 Order of connections

The menu and the list in the **Connections** window use the same order. Connections created in MacVPN and system VPNs are ranked together.

- **Pinned connections come first**, in your order. To pin one, right-click it in the **Connections** window and choose **Pin to Top**; to remove it from the top, choose **Unpin**. Drag the pinned connections in the **Pinned** section to change their order. Pinned connections have a small pin icon, in the menu too.
- **The others follow, most used first.** Every successful connect that you start in MacVPN adds 1 point. The points lose half of their value every 14 days, so a connection you used a lot last month falls behind one you use now. Only the moment the connection comes up counts: status checks while it stays up, and connections started outside MacVPN (for example in System Settings) do not. Connections with equal points (for example, new ones with no points) are listed by name.
- The order is stored on this Mac in `~/Library/Application Support/MacVPN/connection-order.json`. It contains no secrets, and exports do not include it. When you delete a connection, or a system VPN disappears, its entry is removed.

### 5.2 Multi-factor authentication (MFA)

MacVPN handles one-time codes (OTP, TOTP, token PIN) and sign-in in the browser (SAML / SSO, push approval). A code is never stored and never written to the log.

**The code window.** When a code is needed, a small window opens with the connection's name, the question from the server (or from the config), a **Code** field, **Cancel** and **Continue**. The field hides what you type unless the server asks to show it. The window expires after 2 minutes, and the connection then fails with **Authentication was not completed in time**. While MacVPN waits, the menu row shows **Waiting for authentication** and the menu bar icon becomes a key. The window does not take the keyboard away from the app you are using: you also get a notification ("…: authentication needed"); click the notification or the window to type the code. Text from the server is marked **The VPN server says:**. For about a second after it appears, the window ignores input, so a stray keypress cannot answer it. Disconnecting closes the window and stops the attempt.

**OpenVPN: automatic.** Nothing to set up:

- **Static challenge** (`static-challenge "…" 0|1` in the config): MacVPN asks for the code before connecting, with the text from the config, and sends it to the server together with the password (in the SCRV1 format, or simply appended if the config says `concat`).
- **Challenge sent by the server** (dynamic challenge `CRV1`, or a text challenge): the code window opens during the connection, with the server's text.
- **Sign-in in the browser** (`OPEN_URL`, `WEB_AUTH`: SAML, SSO, push): MacVPN shows the host of the address (in plain ASCII, lowercase) and the full address, and asks **Open in Browser** (it is not the default button: click it). Only `https://` addresses are opened; any other address is ignored. After you sign in (or approve the push on your phone), the connection comes up. MacVPN waits up to 5 minutes (or the server's shorter limit).

**All types: code appended to the password.** Some servers expect the code typed after the password (for example `password123456` or `password,123456`). In the connection's settings, turn on **Ask for a one-time code at connect and append it to the password** and choose the **Separator**: none, `,` or `:`. It is available for OpenVPN, IKEv2, SSTP, L2TP and Cisco IPsec, and for L2TP / Cisco IPsec system VPNs (in their detail view in the **Connections** window). At connect, MacVPN asks for the code and sends password + separator + code. If no password is saved in MacVPN, the code alone is sent as the password. For SSTP the password with the code must not contain `"`, `\` or control characters. For an OpenVPN config with `static-challenge` the setting is not used, because the static challenge already carries the code.

**How it works (OpenVPN).** MacVPN starts OpenVPN with its management interface on a socket that only root can reach. Only MacVPN's root helper (the `mgmt-bridge` subcommand of the root binary `mvpn`; process lists show it as `mvpn-mgmt`) talks to it, with a fixed list of commands. The helper passes only the question, the `https` address and the state to the app (in `/var/run/macvpn-ui/<id>.json`, readable only by you), and your answer back to OpenVPN.

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
- **SSTP:** a detailed `sstpc` log (`--log-level 4`) and the `pppd` negotiation (`debug`): TLS, LCP, MS-CHAPv2 and IPCP. The password stays masked, but the MS-CHAPv2 exchange (challenge and response) is in the log, and it can be used for offline password guessing. Handle a debug log carefully: share it only with your network administrator, never publicly. The `pppd` lines appear with a `[pppd]` prefix.
- **L2TP / Cisco:** the log of the macOS VPN processes (for up to 60 seconds, or until the connection is up). These types have no log outside debug mode.
- **Diagnostics** before and after connecting: server name resolution, the routing table, DNS state and the network interfaces.

**Log lines, colour-coded:**

| Prefix | Meaning |
|---|---|
| `═══` | start of a new connect or disconnect (with the date) |
| `▶ [mvpn]` | MacVPN's own steps (copying the config, validation, tools found) |
| `$ …` | a command that was run (passwords masked as `***`) |
| `✗` | an error |
| other | the tool's own output (openvpn, wg-quick, charon, sstpc, pppd) |

**The Log tab** shows the last 5000 lines of the connection's log and follows it live, also outside debug mode (L2TP and Cisco IPsec only have a log in debug mode: **Native connections only have a log when connected in debug mode.**). The log files themselves are in `/var/log/macvpn`.

**Log actions:** filters (**All**, **Commands**, **Errors**), **Search**, **Follow** (auto-scroll), **Copy** (copies the filtered lines), **Save…** (saves the log as `<name>-log.txt`, readable only by you). Passwords, PSKs and private keys never appear in the log, so you can share a saved log (for example with your network administrator). A debug log of an SSTP connection is the exception, see above.

---

## 7. Troubleshooting from the log

First read the error message in the menu or the notification. If that is not enough, connect in debug mode and search the **Log** tab (the **Errors** filter shows only the error lines). The messages below are the English ones; with Hungarian as the system language, MacVPN shows them in Hungarian.

### 7.1 `AUTH_FAILED` (OpenVPN)

Message: **Authentication failed (AUTH_FAILED)**. The server rejected the username or password.

- Check the **Username** and **Password** fields, then press **Save**.
- If the account has expired or is locked, contact your provider.
- If the server asks for a one-time code, see [section 5.2](#52-multi-factor-authentication-mfa) and [section 7.11](#711-one-time-code-and-sign-in-in-the-browser-mfa).

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
- `Line 5: Risky directive, acknowledgement required: user` (the setting is in the yellow **Risky settings** panel)
- When connecting: `Risky settings are not acknowledged: user. Open the connection in MacVPN → Connections and tick the checkbox under Risky settings.`
- `Line 6: setenv not allowed: LD_PRELOAD – delete the line or comment it out (#)`
- `Line 7: External file reference, use an inline block: ca`
- WireGuard: `Line 4: Forbidden key: postup`, `Line 6: Key not allowed: …`
- IKEv2: `Line 2: Forbidden: include`, `Line 9: Forbidden key: updown`, `Line 6: Only a file name is allowed, no path: cacerts`
- Arguments: `Line 4: Invalid argument: dev`, `Line 8: Wrong number of arguments: keepalive`, WireGuard `Line 3: Invalid value: address`

MacVPN starts the VPN tools as root, so it only allows known, safe settings. To fix:

- **Forbidden directive / key** (for example `up`, `down`, `script-security`, `PostUp`): these would run external commands. Delete the line or put `#` in front of it. MacVPN handles DNS and routes itself, so these scripts are not needed.
- **Risky directive, acknowledgement required / Risky settings are not acknowledged:** the setting is allowed only after you acknowledge it. Read the reason in the yellow panel; if you want the setting, tick **I acknowledge these settings and the security risks** and **Save**, otherwise comment the line out. If you added a new risky line after acknowledging, tick the box again.
- **setenv not allowed:** the variable name could influence MacVPN's root DNS hook (for example `PATH`, `BASH_ENV`, `LD_*`, `DYLD_*`). Delete the line; it is not needed for the connection.
- **Invalid argument** on an unknown or risky directive: its arguments cannot contain paths (`/`, `..`, `~`, `file:`), a leading `-` or shell characters (`` ` $ ; | & < > ``).
- **Invalid argument / value, wrong number of arguments:** the setting is allowed, but its value is not in the expected form (for example a device path after `dev`, a word instead of a number). The message names the setting, not the value. Check the line against the provider's original config.
- **External file reference:** a certificate refers to a file (`ca ca.crt`). Import the `.ovpn` again with the referenced files next to it, or paste their contents into a `<ca>…</ca>` block.
- **Control character not allowed**: the file contains an invisible character (for example text copied from Windows). Retype the line.

### 7.8 Other

- **"Installation cancelled: /usr/local/libexec is not owned by root or is writable by other users…"** (or the same for `/usr/local`) when you press **Authorize**: a parent folder of the root layer belongs to your user or can be written by other users. Then anything running as that user could replace MacVPN's root binary, so MacVPN refuses to install there and does not change the folder itself. Fix it in Terminal and press **Authorize** again:
  ```
  sudo chown root:wheel /usr/local/libexec && sudo chmod go-w /usr/local/libexec
  ```
  (use the folder named in the message). On Intel Macs Homebrew may own `/usr/local/libexec`; after this change Homebrew can no longer write there without `sudo`, which may affect some formulae.
- **"Cannot query the status: …"** warning in the menu: the root layer or the sudoers rule is missing or outdated. Open the **System Status** window and press **Authorize**.
- **"openvpn not found (brew install openvpn)"** and similar: install the missing tool from the **System Status** window.

### 7.9 SSTP: certificate error

Message: **Server certificate error (see the log; check the certificate mode or the CA file)**. Typical log lines: `SSL certificate verification failed`, or `The certificate did not match the host`.

- The server certificate is signed by a company CA: choose **Custom CA file** and load the CA certificate in PEM format. **System CA** does not use the macOS Keychain.
- The **Server** name must match the name in the certificate. Connecting by IP address usually fails this check; use the host name.
- Expired certificate, or the clock on the Mac is wrong.
- **No verification** only as a temporary test, never for daily use.

### 7.10 SSTP: authentication failed

Message: **Authentication failed (wrong user name or password)**. Typical log line: `MS-CHAP authentication failed: E=691`.

- Check **Username** and **Password**, then **Save**. A Windows domain account is written as `user@domain` (not `DOMAIN\user`).
- The server must allow MS-CHAPv2. If it only accepts certificate login (EAP-TLS) or PAP, MacVPN cannot connect to it.
- If the log shows `sstpc exited` with no IP address, or the connection times out after authentication, the server may require the SSTP crypto binding in a form `sstpc` does not support. Connect in debug mode and send the log to the server operator.
- **SSTP needs a password**: the password field is empty. Enter it in the form and save.
- **sstpc not found (brew install sstp-client)**: install `sstp-client` from the **System Status** window.

### 7.11 One-time code and sign-in in the browser (MFA)

- **Authentication was not completed in time**: no code was entered within 2 minutes, or the sign-in in the browser did not finish within the time limit (at most 5 minutes). Connect again and answer sooner.
- **Authentication cancelled**: you clicked **Cancel** in the code or browser window, or disconnected.
- **Authentication failed**: the server rejected the code or the password. Codes expire quickly: use a fresh one. With the code appended to the password, check the **Separator** your provider expects.
- **No browser window appears**: MacVPN opens only `https://` addresses with a plain ASCII host name (international names only in their `xn--` form, no `%` or `@` before the path). The log then shows `web authentication URL dropped (only https with a plain ASCII host is accepted)`. Ask your provider for such a sign-in address.
- **The management bridge stopped**: MacVPN's root helper ended unexpectedly while signing in. Connect again; if it repeats, connect in debug mode and check the `[mgmt]` lines.
- **No connection is waiting for authentication**: the attempt had already ended (time limit or error) before your answer arrived. Connect again.
- **mvpn-mgmt not found** (the OpenVPN helper of the root binary `mvpn` could not start; `mvpn-mgmt` is the name it runs under), or **Incomplete installation** in **System Status**: the root layer is from an older version or incomplete. Click **Authorize** in **System Status** to reinstall it.
- The `[mgmt]` lines in the log are the helper's steps (for example `hold released`, `credentials sent`, `dynamic challenge received`). They never contain the code or the password, and for a sign-in address only its host is logged.

---

## 8. Updates

MacVPN looks for new versions on the GitHub Releases page: at launch, then once every 24 hours.

- When a newer version exists, the menu shows **Update available: vX.Y.Z**. Clicking it opens the **Update** window with the release notes and the installed version. **Later** closes it; **Open the Release on GitHub** opens the release page.
- The **Download and Install** button:
  1. downloads the DMG, its `.sha256` file and its `.sig` signature, verifies the SHA-256 checksum, and checks that the signature was made by the MacVPN maintainer's offline key for exactly this version and this file. If the signature is missing or not valid, it stops with **The update is not signed by the MacVPN maintainer** and installs nothing;
  2. mounts the DMG, and checks that the app inside is MacVPN (`local.macvpn`), that its version matches the release and that its code signature is valid;
  3. asks about unsaved changes and active connections, just like quitting;
  4. quits, replaces the app where it runs from (usually `/Applications/MacVPN.app`), and restarts it.
  The window shows each step (**Checking the install location…**, **Downloading…**, **Mounting the disk image…**, **Verifying the app…**, **Preparing the installation…**, **Quitting and restarting…**). If anything fails before the quit, the installed version stays and MacVPN keeps running.
- **Signed updates:** every release is signed by the maintainer with an Ed25519 key that is kept offline, never on GitHub. MacVPN only offers a release that has a signature file, and only installs it if the signature is valid. A newer release that is not signed yet is not offered; **Check for Updates Now** then says **Update waiting for signature**.
- To check manually: menu → **Check for Updates Now**. If you are up to date, it says **MacVPN is up to date**.
- To turn off automatic checks: menu → the **Check for Updates Automatically** checkbox.
- **Optional delay:** with the **Only Offer Updates Published at Least 24 Hours Ago** checkbox (off by default), MacVPN offers a new release only once it has been public for 24 hours (based on the release's publish time on GitHub). This gives time for a bad or malicious release to be noticed and removed before you install it. **Check for Updates Now** then tells you if a newer version exists but is not offered yet.
- **Keychain prompt after an update:** because MacVPN is ad-hoc signed (no Developer ID), macOS treats each new version as a new program, and may ask once after each update whether MacVPN may access its own Keychain items. Click **Always Allow** only if the prompt is MacVPN's own: it names MacVPN and its path (usually `/Applications/MacVPN.app`). If the prompt names another program, click **Deny**.
- If an update brings a new root layer, the **System Status** window opens and shows **Update required**. Update it with **Authorize** and one admin password.
- If the app's location is not writable (for example it runs directly from Downloads or from the DMG), the update reports an error. Move the app to the Applications folder, or update manually: download the new DMG and replace the app with it.
- The update log is at `~/Library/Caches/MacVPN/update.log`. If the previous update was cancelled (because MacVPN did not quit within 30 seconds) or failed, MacVPN shows a one-time notice at the next launch; the installed version stays in place. At launch MacVPN also removes leftovers of an interrupted update (hidden `.MacVPN.app.update-…` and `.MacVPN.app.old-…` folders next to the app).

### 8.1 Upgrading from 0.x

MacVPN 1.0 replaces the 0.x Swift app. The upgrade works like any other update:

1. **Update in the app.** In MacVPN 0.x, choose **Check for Updates Now**, then **Download and Install** in the Update window. The 0.x updater checks the 1.0 release's signature like any other update. (Versions before 0.2.2 do not check signatures: on those, download the DMG from the [Releases](https://github.com/SepsiG/MacVPN/releases) page instead, quit MacVPN, and replace the app in Applications.)
2. **Your data is kept.** Connections, passwords, pinned connections and their order, the one-time code settings of system VPNs, the update settings and **Launch at Login** carry over. Connections you left running stay connected. Nothing needs to be imported again.
3. **The Keychain asks once.** Version 1.0 has a new signature, so macOS may ask whether MacVPN may access its Keychain items. Click **Always Allow** if the prompt names MacVPN at `/Applications/MacVPN.app`. After that, the editors show **Saved — type to replace** for every stored password, and connecting asks no more. (Items that very old versions stored under the Keychain service `macvpn` are moved to `local.macvpn.secrets` automatically at launch.)
4. **Reinstall the root layer.** 1.0 replaces the separate root scripts of 0.x with the single `mvpn` binary (root layer 7). The **System Status** window opens with **Update required**, for example **Update required (6 → 7)** when coming from 0.4.0. Click **Authorize** and enter the admin password. Active VPN connections are disconnected first; the old files (`ovpn-dns`, `mvpn-validate`, `mvpn-mgmt`) are removed. Until you do this, OpenVPN, WireGuard, IKEv2 and SSTP connections show **Missing tool** and cannot connect.
5. **Hardened runtime.** The 1.0 app and its root binary are signed with the hardened runtime, so macOS refuses to load foreign libraries into them. This protects the passwords the app reads from the Keychain. Nothing changes for you; it is still ad-hoc signed, so Gatekeeper asks again only if you install the DMG manually.

---

## 9. Uninstalling

1. Open the **System Status** window and click **Uninstall MacVPN…**.
2. The confirmation dialog lists what will be removed:
   - `/usr/local/libexec/macvpn` (root scripts: the `mvpn` root binary and its `VERSION` file)
   - `/etc/sudoers.d/macvpn` (sudoers rule)
   - `/var/run/macvpn`, `/var/run/macvpn-ui` (runtime data)
   - `/var/log/macvpn` (connection logs)
3. If you tick **Also delete user data (connections and Keychain passwords)**, your connections (`~/Library/Application Support/MacVPN`) and their passwords in the Keychain are deleted too, including the shared secrets saved for system VPNs.
4. Click **Uninstall** and enter the admin password. MacVPN disconnects active connections first.
   If a connection cannot be disconnected, the uninstall stops ("A connection could not be disconnected, uninstall cancelled.") and nothing is removed. Disconnect it (or restart the Mac), then try again.
5. At the end a window titled **MacVPN has been uninstalled** appears with this text:
   > You can now drag the app to the Trash. The Homebrew packages were kept (brew uninstall openvpn wireguard-tools strongswan sstp-client).

   If you had L2TP or Cisco connections, a second paragraph is shown:
   > You can remove the L2TP / Cisco profiles in System Settings → General → Device Management.

   If **Launch at Login** was on, MacVPN removes itself from the login items (and deletes its login LaunchAgent, if it used one). If that fails, the window says so, and you can remove it in **System Settings → General → Login Items**.

   After **Quit MacVPN**, drag `MacVPN.app` to the Trash.

MacVPN does not remove the Homebrew packages, because other programs may use them. If you no longer need them:

```
brew uninstall openvpn wireguard-tools strongswan sstp-client
```

Remove L2TP and Cisco profiles under **System Settings → General → Device Management**.

If MacVPN created `/etc/ppp/options` for SSTP (it leaves a marker when it does) and the file is still empty, the uninstaller removes it too. A file that existed before, or that has content, is left alone.

---

## 10. Security notes

**Threat model.** MacVPN protects against dangerous *configs*: a downloaded or imported `.ovpn`, WireGuard or IKEv2 file cannot run commands, read or write arbitrary files as root, or fake a successful connection, because the root side checks every setting against an allowlist and decides only from root-only files. It does **not** protect against *programs already running in your user account*. Such a program can, in practice, become root: it can replace the Homebrew VPN tools (which your user can write) and then ask MacVPN's passwordless sudo rule to run them. Treat MacVPN like any tool that grants your account admin-level power, and only use it on a Mac where you are the administrator and trust the software running under your account.

- **Ad-hoc signed app.** MacVPN is not signed with an Apple Developer ID and is not notarized. That is why you need the Gatekeeper step on first launch (see [1.2](#12-allow-the-first-launch-gatekeeper)). Only download it from the official [Releases](https://github.com/SepsiG/MacVPN/releases) page. The app and the `mvpn` root binary are signed with the hardened runtime and no entitlements, so macOS does not let other programs inject a library into them (for example through `DYLD_INSERT_LIBRARIES`) to read the passwords MacVPN takes from the Keychain.
- **Passwords.** Passwords and PSKs are stored in the macOS Keychain (service `local.macvpn.secrets`). Usernames of the text-based types are in the Keychain too; the account name of L2TP / Cisco connections is in the connection's `meta.json` in plain text, as it is not a secret. Passwords and PSKs are masked (`***`) in the log, and exports do not contain them. Keys that are part of a config (WireGuard `PrivateKey`, OpenVPN `<key>` and similar) are only exported if you choose **Export With Keys**. The L2TP / Cisco profile contains the PSK (but not the password) and is deleted from disk once installed. User names, passwords and PSKs cannot contain line breaks or control characters (MacVPN refuses to save them). A saved log is created with `600` permissions. For OpenVPN, the username and password go to MacVPN's root helper (`mvpn mgmt-bridge`, shown as `mvpn-mgmt` in process lists) through a root-only file (permissions `600` in a `700` directory) that the helper deletes right after reading it. The helper keeps them in memory, so OpenVPN can log in again when it reconnects, and hands them to OpenVPN through its root-only management socket. One-time codes are never stored: they exist only in memory while connecting, and are masked in the log.
- **Root layer integrity.** The installer copies the root files (`mvpn` and `VERSION`) to a root-only staging folder and installs them only if their SHA-256 matches what the app computed just before asking for the admin password. It makes `/usr/local/libexec/macvpn` root-owned and not writable by others. If `/usr/local` or `/usr/local/libexec` is not root-owned or is writable by others, it stops with instructions instead of changing them (see [section 7.8](#78-other)). The sudoers rule starts `mvpn` with a clean environment (no `LANG`, `LC_*` or other variables from your session).
- **Sudoers and Homebrew (known limitation).** To connect, MacVPN uses a sudoers rule to run the `/usr/local/libexec/macvpn/mvpn` binary as root without a password, and that binary runs the Homebrew tools (`openvpn`, `wg-quick`, `charon`, `sstpc`). The Homebrew directory (`/opt/homebrew`) is writable by your user. Malware running in your user account could replace those programs and gain root that way. Config filtering protects against accidental or imported dangerous settings, not against malware already running in your account. On a single-user Mac that you administer yourself, this is an acceptable risk. If it is not for you, do not enable the root layer, and use only L2TP / Cisco connections.
- **SSTP password on the command line (known limitation).** The Homebrew `sstpc` computes the SSTP crypto binding keys from the password itself, so it only starts when the password is given on its command line (`--password`). MacVPN passes it there and never writes it into the log (`***`). `sstpc` masks its own command line right after reading it, but for that first moment other local users could see the password with `ps`. On a single-user Mac this is an acceptable risk. If it is not for you, do not use SSTP.
- **Update integrity.** MacVPN installs an update only if it carries a valid Ed25519 signature made with the maintainer's offline key. The public keys (a primary and a backup) are built into the app; the private keys are never on GitHub or in the build system. So even if someone takes over the GitHub account or repository, they cannot push an update to MacVPN: a release without a valid signature is not offered, or is refused with **The update is not signed by the MacVPN maintainer**. The signature covers the version and the SHA-256 of the DMG that MacVPN computes itself after downloading. **Remaining risk:** whoever holds the maintainer's signing key can sign an update.
- **How the updater limits the risk further.**
  - It asks GitHub for the latest release by the repository's fixed numeric ID (`MacVPNUpdateRepoID` in the app's `Info.plist`), not by its name. If the repository were renamed or deleted and someone created a new one under the old name, the app would not take updates from it. Without the ID, the app does not check for updates at all.
  - It accepts the DMG, its `.sha256` file and its `.sig` signature only from `https://github.com/SepsiG/MacVPN/releases/download/<tag>/<file name>`, for exactly the tag of the release; redirects may only lead to GitHub's own download hosts.
  - Releases are built by a hardened GitHub Actions workflow: actions pinned to exact commits, read-only build job, the tagged commit must be on `main`, and a separate job that runs no repository code and only creates a draft. The maintainer checks the checksum, signs the release offline on their own Mac, and only then publishes it.
  - The optional 24-hour delay (see [section 8](#8-updates)) gives time to notice and pull a bad release.
  - The app is ad-hoc signed; macOS may ask once after each update for Keychain access to MacVPN's items (see [section 8](#8-updates)). Allow it only for MacVPN's own prompt.
