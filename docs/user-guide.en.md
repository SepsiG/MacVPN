# MacVPN – User Guide

[Magyar változat](user-guide.hu.md)

MacVPN is a menu bar app for macOS 14 or later (Apple silicon or Intel). It manages OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec and Cisco IPsec connections in one place. You can import and edit configs there, sort them into folders, and every connection has a live log. Connections and their passwords are kept in an encrypted vault. This guide describes version 1.3 (see [What's new in 1.3](#whats-new-in-13)). The menu's **Help** item opens it.

For short step-by-step instructions, see the [How-to guide](how-to.en.md). This guide is the full reference. Developers who want another program on this Mac to bring MacVPN connections up and down (**Paired apps** in the Connections window) should read the [Control API guide](control-api.md).

> **Language:** MacVPN follows the macOS language setting (System Settings → General → Language & Region, or the language set for MacVPN). It is available in English and Hungarian. If neither is among your preferred languages, it uses English. This guide uses the English labels; the [Hungarian guide](user-guide.hu.md) shows the Hungarian ones.

## What's new in 1.3

- **Team catalogs.** An administrator publishes a set of connections, with their folders, colours and named sign-ins, as one signed and encrypted file on a web server, a file share or a synced folder. Every subscribed MacVPN picks up additions, changes and removals by itself, and each member signs in with their own user name and password. See [16](#16-team-catalogs).
- **For administrators:** an admin key with an offline backup key, a publish wizard, a team key that can be rotated to cut off someone who left, and a subscription string that carries everything a member needs. See [16.7](#167-for-administrators-the-admin-key).
- **Full backup.** Backups now also hold your catalog subscriptions, admin keys and publications. See [14.1](#141-what-a-backup-contains).
- **Upgrading from 1.2:** the vault is updated on the first launch (a copy of the old one is kept), the root layer stays 8, so no admin password is needed. See [8.3](#83-upgrading-from-12).

## What's new in 1.2

- **Encrypted vault.** Your connections, their passwords and the rest of MacVPN's data are now in one encrypted file, the vault, protected by a master password. A recovery key gets you back in if you forget the password. With **Unlock automatically** (on by default) MacVPN opens without asking; **Lock Now** locks it on demand. See [11](#11-vault).
- **Moving from 1.1.** On the first launch of 1.2, MacVPN moves your 1.1 connections and saved passwords into the vault, checks them, and only then deletes the old copies. macOS may ask for Keychain access once per old item. The root layer goes from 7 to 8, which needs your admin password once. Back up first: see [8.2](#82-upgrading-from-11).
- **Folders and colours.** Group connections and system VPNs into nested folders, give folders and connections one of 12 colours, and drag them where you want them. See [12](#12-folders-and-colours).
- **Shared credentials.** One user name and password used by several connections. Change it once, and every connection that uses it signs in with the new one. See [13](#13-shared-credentials).
- **Full backup and restore.** **Back Up Everything…** writes one encrypted file with every connection, secret, folder and shared credential; **Restore from Backup…** brings it back on this Mac or a new one. See [14](#14-backup-and-restore).
- **Credential prompt.** Its checkbox is now **Save in vault**. IKEv2 with EAP sign-in now asks once more after a rejected password, like OpenVPN and SSTP. See [5.3](#53-credentials-asked-when-connecting).
- **Licences.** The app bundle contains `THIRD-PARTY-NOTICES.txt` with the licences of the components MacVPN ships (among them SQLCipher).

## What's new in 1.1

- **Other apps can control VPNs (control API).** Off by default. A program of your user account that you pair, for example a Remote Desktop app, can bring the connections you allow up and down; the VPN stays up only while the program needs it. See [5.4](#54-paired-apps-control-api) and, for developers, the [Control API guide](control-api.md).
- **Credentials asked when connecting.** A user name, password, PSK or key password that is needed but not saved is asked for before connecting, saved only once the connection is up (or not at all), and asked again once after a rejected sign-in. See [5.3](#53-credentials-asked-when-connecting).
- **Live system VPN list.** A VPN added, renamed or deleted in System Settings shows up in the menu and the Connections window without reopening them. See [3.5](#35-system-vpns-shared-secret-for-l2tp--cisco).
- **New look.** The menu, the Connections window, System Status, Update and the prompts use rounded cards. Every connection has a coloured bubble for its type with a state badge. See [2](#2-first-launch-and-the-system-status-window) and [5](#5-connecting).
- **Dock icon.** While the Connections, System Status or Update window is open, MacVPN also shows a Dock icon, so Cmd+Tab reaches it. See [2](#2-first-launch-and-the-system-status-window).
- The root layer is unchanged (version 7): updating from 1.0 needs no admin password.

## Contents

1. [Installation](#1-installation)
2. [First launch and the System Status window](#2-first-launch-and-the-system-status-window)
3. [Adding connections by type](#3-adding-connections-by-type)
4. [Import and export](#4-import-and-export)
5. [Connecting](#5-connecting)
6. [Debug mode and the log](#6-debug-mode-and-the-log)
7. [Troubleshooting from the log](#7-troubleshooting-from-the-log)
8. [Updates](#8-updates) ([Upgrading from 0.x](#81-upgrading-from-0x), [Upgrading from 1.1](#82-upgrading-from-11), [Upgrading from 1.2](#83-upgrading-from-12))
9. [Uninstalling](#9-uninstalling)
10. [Security notes](#10-security-notes)
11. [Vault](#11-vault)
12. [Folders and colours](#12-folders-and-colours)
13. [Shared credentials](#13-shared-credentials)
14. [Backup and restore](#14-backup-and-restore)
15. [Vault FAQ](#15-vault-faq)
16. [Team catalogs](#16-team-catalogs) ([for users](#161-subscribing-to-a-catalog), [for administrators](#167-for-administrators-the-admin-key), [security model](#1611-security-model))

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

After launch, MacVPN appears as a shield icon in the menu bar. While one of its windows (Connections, System Status or Update) is open, MacVPN also shows a Dock icon, so you can reach that window with Cmd+Tab or a click on the icon; the icon goes away when the last of these windows closes.

- **grey shield:** no active connection
- **shield with a check mark:** at least one connection is active
- **shield with an exclamation mark:** an error (a failed connection, or the status cannot be queried)
- **key:** a connection is waiting for authentication (see [5.2](#52-multi-factor-authentication-mfa))

Click the icon to open the menu. Each connection is a card with the coloured bubble of its type, its name, its type and state, and a switch (see [5](#5-connecting)); with many connections the list scrolls. Folders appear as rows you can open and close (see [12](#12-folders-and-colours)). Below the cards:

- three tiles: **New Connection / Import…**, **Manage Connections…** and **System Status**;
- the **Settings** group (click it to open or close it): **Check for Updates Automatically**, **Only Offer Updates Published at Least 24 Hours Ago**, **Check for Updates Now** and **Launch at Login**; then the vault settings **Unlock automatically**, **Show “Lock Now”**, **Change Master Password…** and **New Recovery Key…** (see [11](#11-vault)), and **Back Up Everything…** and **Restore from Backup…** (see [14](#14-backup-and-restore));
- **Help** (opens this guide), **Lock Now** (when shown, see [11.4](#114-lock-now)) and **Quit MacVPN**.

While the vault is locked, the menu shows only an **Unlock…** row, the number of active connections and **Quit MacVPN** (see [11.5](#115-the-locked-menu)). Before the vault exists, the row says **Set Up the Vault…**.

When an update is available, an **Update available: vX.Y.Z** banner appears too. The hint at the bottom reminds you: **Option-click a switch: debug mode**.

If anything is missing, the **System Status** window opens automatically at launch. You can open it any time from the menu (**System Status**). It shows three checks, each green or red:

1. **Homebrew.** If it is missing, the **Install…** button opens Terminal with the official installer. The installer asks for your administrator password. If the installer cannot be downloaded, the Terminal window says so and stops without running anything. When it finishes, come back and press **Check Again**.
2. **VPN tools.** Next to the list of missing tools, the **Install** button runs `brew install`. The output is shown live in the window. The installation continues even if you close the window.
3. **Permissions (root scripts + sudoers).** The **Authorize** button asks for the admin password once. It installs MacVPN's root layer: the single root binary `/usr/local/libexec/macvpn/mvpn` with its `VERSION` file (root layer 8 in MacVPN 1.2), and the `/etc/sudoers.d/macvpn` rule. After that, connecting and disconnecting work without a password. The row shows **Installed (version 8)** when it is up to date. If an app update brings a newer root layer, it says **Update required (7 → 8)** (with the installed and the new version); if a file is missing, **Incomplete installation**. Press **Authorize** again. If connections are active, the window warns first: **Updating the system component will disconnect active VPN connections.**

When all three are green, setup is done. L2TP and Cisco IPsec work without them.

### 2.1 Launch at login

MacVPN does not start automatically by default. To start it every time you log in, tick **Launch at Login** in the menu's **Settings** group or in the **System Status** window. Untick it to stop. The checkbox shows what macOS reports, so it also follows changes you make in **System Settings → General → Login Items**.

- If macOS asks for approval, a note appears: "Approve MacVPN in System Settings → General → Login Items." The **Open Login Items Settings…** button opens that page. Turn MacVPN on there.
- MacVPN is not signed with an Apple Developer ID, so macOS often cannot register it the usual way. In that case MacVPN adds a small login LaunchAgent instead (`~/Library/LaunchAgents/local.macvpn.launcher.plist`, which runs `open -b local.macvpn`). The checkbox stays ticked with the note "Enabled via a login LaunchAgent (applies at next login)." MacVPN does not start right away; it starts at your next login. The LaunchAgent opens the app by its bundle ID, so it keeps working if you move the app. It may also appear in **System Settings → General → Login Items** under **Allow in the Background**. Unticking the checkbox (or uninstalling) removes the file.
- If turning it on fails both ways, an alert shows the reason, and the checkbox stays unticked.
- The checkbox is disabled when MacVPN is not running from the Applications folder (`/Applications` or `~/Applications`), for example straight from the DMG or from Downloads. Drag the app to Applications, open it from there, and try again.

---

## 3. Adding connections by type

You add connections in the **Connections** window. To open it, use the menu: **Manage Connections…** or **New Connection / Import…**.

- The list is on the left: the connections created in MacVPN and the **system VPNs** (VPNs configured elsewhere in macOS, marked **System VPN** under their name) in one tree with your folders, pinned ones on top of each folder (see [5.1](#51-order-of-connections) and [12](#12-folders-and-colours)). Below the list are **Credentials** (see [13](#13-shared-credentials)) and **Paired apps** (see [5.4](#54-paired-apps-control-api)). You can only start and stop system VPNs. For L2TP and Cisco IPsec system VPNs you can also store the shared secret in MacVPN (see [3.5](#35-system-vpns-shared-secret-for-l2tp--cisco)).
- From the toolbar **New** (+) menu, pick a type (OpenVPN, WireGuard, IKEv2, SSTP, L2TP, Cisco IPsec), **New Folder** or **Import from File…**. The same menu has **Back Up Everything…** and **Restore from Backup…** (see [14](#14-backup-and-restore)). A new connection starts with a template and a name like "New OpenVPN"; rename it in the name field.
- The selected connection's header has **Connect** / **Disconnect**, **Connect in Debug Mode**, the export icon and the delete icon (**Delete**, with a confirmation). Below it are two tabs: **Settings** and **Log**.
- If the status cannot be queried (for example the root layer is missing), a warning banner with a **System Status** button appears at the top of the window.

Text-based types (OpenVPN, WireGuard, IKEv2) have a monospace editor. **Save** (⌘S) checks the config first. If it finds errors, they are listed in red under the editor with their line numbers (for example `Line 3: Forbidden directive: up – delete the line or comment it out (#)`), and nothing is saved. Risky OpenVPN settings appear in a yellow panel while you type (see [3.1](#31-openvpn)). Passwords have their own fields in the **Authentication** section. They go into MacVPN's encrypted vault, not into the config. Where a connection signs in with a user name and password, the **Password from** selector chooses between **Own username and password** and a shared credential (see [13](#13-shared-credentials)).

SSTP, L2TP and Cisco IPsec have a form instead of a text editor (see [3.4](#34-l2tpipsec-and-cisco-ipsec) and [3.6](#36-sstp)).

**Stored passwords are never shown.** A password field that has a stored value says **Saved — type to replace**. Leave it alone to keep the stored value, type to replace it, or click **Remove saved password** and save to delete it. The status line under the editor shows **Unsaved changes** or **Saved: <time>**.

If you switch connections or close the window with unsaved changes, the app asks: **Save**, **Discard** or **Cancel**.

### 3.1 OpenVPN

The easiest way is to import the `.ovpn` file from your provider (**New → Import from File…**, or drag the file onto the list).

- If the `.ovpn` refers to external files (for example `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), the import reads them from next to the `.ovpn` and embeds them (into `<ca>…</ca>` blocks). So before importing, keep those files next to the `.ovpn`. If a file is missing, the import reports an error.
- If the server asks for a username and password (an `auth-user-pass` line), fill in **Username** and **Password**.
- If the private key is protected by a password (a password-protected PKCS#12 file, or an encrypted PEM key: `-----BEGIN ENCRYPTED PRIVATE KEY-----` or `Proc-Type: 4,ENCRYPTED`), enter it in **Private key password**. It is stored in the vault and passed to OpenVPN only while connecting.
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

The **account name** is saved with the connection's settings: it is not a secret, and it is written into the profile. The password and the PSK are in the vault. With a shared credential, the account name is only written into the profile, and MacVPN signs in with the shared credential (see [13](#13-shared-credentials)).

### 3.5 System VPNs: shared secret for L2TP / Cisco

A VPN set up in System Settings (for example **Office L2TP**) appears in the list marked **System VPN**. MacVPN does not change its settings. Sometimes macOS cannot read the shared secret of such a VPN when it is started from another app: the connection does not come up, and macOS may show a "server not reachable" message, although connecting from System Settings works.

For L2TP and Cisco IPsec system VPNs, the detail view has two fields:

- **Shared secret (PSK)**
- **Password (optional, if not saved in macOS)**

Click **Save**. They are stored in MacVPN's vault (not in the VPN's own settings), and passed to macOS each time you connect from MacVPN. **Forget saved secrets** deletes them. Leaving a field empty also deletes it.

If you switch away or close the window with unsaved changes here, the app asks the same **Save / Discard / Cancel** question as for other connections.

**The list is live.** When a VPN is added, renamed or deleted in System Settings (or by installing a profile), the menu and the **Connections** window follow without being reopened: usually within a second, and at the latest within 5 seconds while the menu or a MacVPN window is open (30 seconds otherwise).

If a system VPN is deleted while its detail is shown, the detail stays with the banner **This VPN was removed from macOS**: its fields and the **Connect**, **Save** and **Forget saved secrets** buttons are disabled. Select another connection to close it. The shared secret and password saved in MacVPN are not deleted, so they apply again if the same VPN comes back. If you no longer need them, click **Forget saved secrets** before deleting the VPN in System Settings (uninstalling with user data also removes them, see [9](#9-uninstalling)).

### 3.6 SSTP

SSTP (Secure Socket Tunneling Protocol, the Microsoft VPN over HTTPS, port 443) runs through the root layer with the Homebrew `sstp-client` package (`sstpc`) and the macOS built-in `pppd`. Install `sstp-client` from the **System Status** window (or `brew install sstp-client`).

Create it with **New → SSTP**, or import an `.sstp` file. It has a form, not a text editor:

- **Name**, **Server** (host name or IPv4/IPv6 address, without a port), **Port** (443 by default). Connecting to an IPv6 address has not been tested against a real server yet; prefer the host name.
- **Username** and **Password**. The password goes into the vault. Use `user@domain` instead of `DOMAIN\user`: backslashes, spaces and quotes are not allowed in the user name. **The SSTP password must not contain quotation marks (`"`), backslashes (`\`) or control characters**: `sstpc` passes the password to `pppd` without escaping, so these characters could change `pppd`'s settings. The form shows an error and does not save such a password; change the password on the server if needed.
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

A `pkcs12 client.p12` file is embedded the same way, as base64 in a `<pkcs12>` block (it must be a PKCS#12 file, inside the folder, at most 1 MB). If it has a password, enter it in **Private key password** after the import. A username/password file in `auth-user-pass` (for example `auth-user-pass auth.cfg`) is never copied into the config: if it is inside the folder, at most 1 KB and has exactly two lines (username, password), MacVPN asks **Use the credentials from … for this connection?**; if you choose **Use**, it stores them in the connection's **Username** and **Password** fields (in the vault) and says so in the import message; otherwise enter them yourself. An `askpass pass.txt` file is handled the same way for the **Private key password**. If the private key is encrypted, the import message reminds you to fill in **Private key password**.

**MikroTik RouterOS.** Configs exported from RouterOS v7 (`/interface ovpn-server server export-client-config`) and the classic v6 wiki configs (with `ca.crt`, `client.crt`, an encrypted `client.key` and `auth-user-pass auth.cfg` next to the `.ovpn`) import without errors or risky settings. Enter the key's export passphrase in **Private key password**.

**Checking imported configs.** The imported config is checked right away with the same rules as **Save**. If it has problems, it is still imported, and its editor opens with the problems in red, so you can fix them and save. If it contains risky settings, the import message says so (**Imported. It contains risky settings (…)**), and the editor shows them in the yellow **Risky settings** panel: tick the checkbox and save before connecting.

**Export.** The export icon in the connection header (**Export… (passwords are never included)**) saves the config in its original format: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, `.sstp`, or `.mobileconfig` for native connections.

- The password, PSK and username are **not** exported. In native profiles they are left empty. The SSTP user name is part of the config, so it is in the `.sstp` export; the password is not.
- **Private keys:** keys that are part of the config can be. If the config contains an OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<pkcs12>`, `<auth-user-pass>` or `<http-proxy-user-pass>` block, a WireGuard `PrivateKey` / `PresharedKey`, or a strongSwan `secrets` section, MacVPN warns you (**The config contains private keys or credentials**) and offers three choices: **Export Without Keys** (the default: these OpenVPN blocks and the strongSwan `secrets` section are removed, WireGuard keys are left empty), **Export With Keys**, or **Cancel**. Anyone who has the keys can connect as you: export them only if the recipient needs them, and keep the file in a trusted place.
- The exported file is created with `600` permissions (only you can read it).
- **Folder and shared credential.** If the connection is in a folder or uses a shared credential, a text export (`.ovpn`, `.conf`, `.swanctl.conf`, `.sstp`) starts with one comment line such as `# macvpn-meta: {"folder":["Work","Clients"],"credentialName":"Office AD"}`. It holds only these names, never a secret. On import, MacVPN recreates the folders that are missing and puts the connection there (if a folder cannot be created, the connection goes to the top level and the message says so). A `credentialName` is never linked silently: MacVPN asks first and names the server (see [13.4](#134-import-and-export)). Files without this line import to the top level, as before. A `.mobileconfig` export has no such line.
- A full backup of everything, with the passwords, is a different feature: see [14](#14-backup-and-restore).
- `.ovpn`, WireGuard `.conf`, `.swanctl.conf` and `.sstp` exports can be imported into MacVPN again.
- A `.mobileconfig` export (L2TP, Cisco IPSec) **cannot** be imported into MacVPN. To use it on another Mac, double-click it in Finder: macOS installs it as a profile, then approve it in **System Settings → General → Device Management** (Profiles). If you drop a `.mobileconfig` file on MacVPN's import, it tells you the same.

---

## 5. Connecting

- **From the menu:** click the switch on the connection's card. The badge on the type bubble and the line under the name show the state:
  - **green:** connected (with the IP address and the elapsed time); the switch is green too
  - **amber, pulsing:** **Connecting…** or **Disconnecting…** (the switch is amber), or **Waiting for authentication**: a one-time code, a sign-in in the browser or missing credentials (see [5.2](#52-multi-factor-authentication-mfa) and [5.3](#53-credentials-asked-when-connecting))
  - **red:** error (with a short reason)
  - **grey:** not connected
  - **Held by …** under the card: a paired app holds the connection (see [5.4](#54-paired-apps-control-api))
- **From the Connections window:** the **Connect** / **Disconnect** button.
- Several connections can be active at the same time.
- If a tool is missing for a type, the connection is greyed out and shows **Missing tool**. Check the **System Status** window.
- **Notifications.** When a connection fails, a macOS notification appears ("…: connection failed", with the text **Open MacVPN for details**). The notification does not contain the error message itself, because notifications can be seen on the lock screen; the full reason is shown in MacVPN. Clicking it opens the connection in the **Connections** window, on its **Log** tab. You also get a notification if a live connection drops unexpectedly ("…: the connection dropped"), and when a connection waits for a code or a sign-in ("…: authentication needed"; clicking it brings the code window forward). macOS asks once for permission to show notifications. There is no automatic reconnect.
- **On quit** (**Quit MacVPN**, ⌘Q, and also logout, restart or shutdown), MacVPN first asks about unsaved changes in the Connections window (**Save**, **Discard** or **Cancel**). Then, if a connection is active, it asks: **Disconnect and Quit**, **Quit, Keep Them Running** or **Cancel**. Cancel keeps MacVPN running (and cancels the logout). MacVPN recognizes connections that kept running on its next launch.

### 5.1 Order of connections

The menu and the list in the **Connections** window use the same order. Connections created in MacVPN and system VPNs are ranked together. With folders, the same rules apply inside every folder, after its subfolders (see [12.3](#123-order-inside-a-folder)).

- **Pinned connections come first**, in your order. To pin one, right-click it in the **Connections** window and choose **Pin to Top**; to remove it from the top, choose **Unpin**. Drag a pinned connection onto another pinned connection of the same folder to change their order. Pinned connections have a small pin icon, in the menu too.
- **The others follow, most used first.** Every successful connect that you start in MacVPN adds 1 point. The points lose half of their value every 14 days, so a connection you used a lot last month falls behind one you use now. Only the moment the connection comes up counts: status checks while it stays up, and connections started outside MacVPN (for example in System Settings) do not. Connections with equal points (for example, new ones with no points) are listed by name.
- The order is stored in the vault (until 1.1 it was `connection-order.json`). Single-connection exports do not include it; a full backup does. When you delete a connection, its entry is removed.

### 5.2 Multi-factor authentication (MFA)

MacVPN handles one-time codes (OTP, TOTP, token PIN) and sign-in in the browser (SAML / SSO, push approval). A code is never stored and never written to the log.

**The code window.** When a code is needed, a small window opens with the connection's name, the question from the server (or from the config), a **Code** field, **Cancel** and **Continue**. The field hides what you type unless the server asks to show it. The window expires after 2 minutes, and the connection then fails with **Authentication was not completed in time**. While MacVPN waits, the menu row shows **Waiting for authentication** and the menu bar icon becomes a key. The window does not take the keyboard away from the app you are using: you also get a notification ("…: authentication needed"); click the notification or the window to type the code. Text from the server is marked **The VPN server says:**. For about a second after it appears, the window ignores input, so a stray keypress cannot answer it. Disconnecting closes the window and stops the attempt.

**OpenVPN: automatic.** Nothing to set up:

- **Static challenge** (`static-challenge "…" 0|1` in the config): MacVPN asks for the code before connecting, with the text from the config, and sends it to the server together with the password (in the SCRV1 format, or simply appended if the config says `concat`).
- **Challenge sent by the server** (dynamic challenge `CRV1`, or a text challenge): the code window opens during the connection, with the server's text.
- **Sign-in in the browser** (`OPEN_URL`, `WEB_AUTH`: SAML, SSO, push): MacVPN shows the host of the address (in plain ASCII, lowercase) and the full address, and asks **Open in Browser** (it is not the default button: click it). Only `https://` addresses are opened; any other address is ignored. After you sign in (or approve the push on your phone), the connection comes up. MacVPN waits up to 5 minutes (or the server's shorter limit).

**All types: code appended to the password.** Some servers expect the code typed after the password (for example `password123456` or `password,123456`). In the connection's settings, turn on **Ask for a one-time code at connect and append it to the password** and choose the **Separator**: none, `,` or `:`. It is available for OpenVPN, IKEv2, SSTP, L2TP and Cisco IPsec, and for L2TP / Cisco IPsec system VPNs (in their detail view in the **Connections** window). At connect, MacVPN asks for the code and sends password + separator + code. If no password is saved in MacVPN, the code alone is sent as the password. For SSTP the password with the code must not contain `"`, `\` or control characters. For an OpenVPN config with `static-challenge` the setting is not used, because the static challenge already carries the code.

**How it works (OpenVPN).** MacVPN starts OpenVPN with its management interface on a socket that only root can reach. Only MacVPN's root helper (the `mgmt-bridge` subcommand of the root binary `mvpn`; process lists show it as `mvpn-mgmt`) talks to it, with a fixed list of commands. The helper passes only the question, the `https` address and the state to the app (in `/var/run/macvpn-ui/<id>.json`, readable only by you), and your answer back to OpenVPN.

### 5.3 Credentials asked when connecting

If a connection needs a user name, password, shared secret (PSK) or private key password that is not saved in MacVPN, MacVPN asks for it in a small **Credentials needed** window before it connects. Nothing has to be set up for this.

- **When it appears:**
  - **OpenVPN:** the config has `auth-user-pass` without a file and without an inline `<auth-user-pass>` block, and the user name or password is not saved. An encrypted private key whose password is not saved.
  - **IKEv2:** EAP sign-in (`auth = eap…` in the `local` section) and the user name or password is not saved.
  - **SSTP:** the password is not saved (the user name is in the connection's settings).
  - **L2TP / Cisco IPsec created in MacVPN:** the account, the password or the shared secret is not saved.
  - **WireGuard,** IKEv2 with certificates, and **system VPNs** never ask: for a system VPN, macOS may keep the secrets in the profile itself.
- **The window** shows only the missing fields. A saved user name is filled in. **Save in vault** is ticked (**Kept encrypted in the MacVPN vault, used from the next connect on**). Untick it to use the values for this connect only. If the connection uses a shared credential without a saved password, the window names it (**Password for Office AD — used by 4 connections**), and **Save in vault** stores the password in the shared credential, for every connection that uses it.
- **Save happens only after the connection is up.** A wrong password is never stored.
- **Wrong user name or password:** if the server rejects the sign-in (OpenVPN `AUTH_FAILED`, SSTP "wrong user name or password"), the window opens **once** more with **Sign-in failed — check the username and password** and the user name filled in. A second failure ends with the normal error and notification. From 1.2, IKEv2 with EAP sign-in asks again too (root layer 8 reports **Authentication failed (EAP)**). L2TP and Cisco IPsec do not ask again: macOS does not report a wrong password separately from other failures.
- **Cancel** (or Escape, or closing the window) stops the connect without an error or a notification. Disconnecting while the window is open closes it. It expires after 2 minutes, which counts as Cancel.
- **Like the code window,** it does not take the keyboard away from the app you are using: click the window or the "…: credentials needed" notification to type. It ignores input for about a second after it appears, and it has no default button: Return does nothing, so click **Connect**. While it is open, the row shows **Waiting for authentication**.
- **Known limitation:** the password of a private key in a PKCS#12 bundle (`<pkcs12>`) is not asked for, because MacVPN cannot tell whether the bundle has one. Save it in the connection's editor (**Private key password**).
- What you type goes to the VPN tool for this connect. MacVPN wipes its own copies after use; copies the system makes on the way (the web view and the app's internal messaging) cannot be wiped by MacVPN. What you type is never written to the log. A control-API client only sees the state `waiting_for_credentials`, and `credentials_cancelled` if you cancel.

### 5.4 Paired apps (control API)

Another program of your user account, for example a Remote Desktop app, can bring MacVPN connections up and down for you once you pair it. This is off by default.

1. Open the **Connections** window (**Manage Connections…**) and select **Paired apps** in the sidebar.
2. Turn on **Allow other apps to control VPNs**. While it is off, no program can reach MacVPN this way.
3. Start the pairing in the other program. MacVPN shows the **Allow an App to Control VPNs?** window with **Name (self-reported)** (the program chose it, so it proves nothing), the full path of its **Executable**, and **Connections it may use**, a checkbox per connection, none ticked. Check the path, tick the connections, and click **Allow**. **Deny**, closing the window, or 2 minutes without an answer refuses. Like the code window, it does not take the keyboard away and ignores input for about a second.

What a paired program can do:

- It sees only the connections you allowed, and can only bring them up and down. It never sees configs, user names or passwords. If a connection needs a code or a password, MacVPN asks you in its own windows, as for a manual connect.
- The VPN stays up while the program needs it, and the card shows **Held by <name>**. When the program closes its connection to MacVPN, quits or crashes, MacVPN disconnects the VPN, unless it was already up before the program asked for it, or another app still holds it.
- If you disconnect the VPN yourself, it stays down; the program has to ask again.

In **Paired apps** every program is listed with its executable path, **Last used** (or **Never used**), **Paired:** and its **Allowed connections**, which you can change any time. **Revoke** unpairs it at once and ends its sessions; connections only it brought up are disconnected. If the program is rebuilt to another path or moved, it shows **Path changed** and must be revoked and paired again. **Activity** lists the recent pairings, logins and leases (**Save…** writes it to a file). When you quit MacVPN while a paired app holds a connection, the quit question names it.

Developers: the protocol, the security model and an example client are in the [Control API guide](control-api.md).

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
- **Keychain prompt after an update:** because MacVPN is ad-hoc signed (no Developer ID), macOS treats each new version as a new program. From 1.2, MacVPN keeps only one item in the Keychain, the vault key of **Unlock automatically**, so macOS asks at most once after an update (and not at all when **Unlock automatically** is off). Click **Always Allow** only if the prompt is MacVPN's own: it names MacVPN and its path (usually `/Applications/MacVPN.app`). If the prompt names another program, click **Deny**; MacVPN then asks for the master password instead.
- If an update brings a new root layer, the **System Status** window opens and shows **Update required**. Update it with **Authorize** and one admin password.
- If the app's location is not writable (for example it runs directly from Downloads or from the DMG), the update reports an error. Move the app to the Applications folder, or update manually: download the new DMG and replace the app with it.
- The update log is at `~/Library/Caches/MacVPN/update.log`. If the previous update was cancelled (because MacVPN did not quit within 30 seconds) or failed, MacVPN shows a one-time notice at the next launch; the installed version stays in place. At launch MacVPN also removes leftovers of an interrupted update (hidden `.MacVPN.app.update-…` and `.MacVPN.app.old-…` folders next to the app).

### 8.1 Upgrading from 0.x

MacVPN 1.0 replaced the 0.x Swift app; 1.1 and 1.2 continue it. Every older version, 0.x and 1.x alike, goes straight to 1.2 with the in-app update, and the first launch of 1.2 moves your data into the vault (the migration of [8.2](#82-upgrading-from-11)). Read [8.2](#82-upgrading-from-11) first and back up your data folder before you update.

1. **Update in the app.** In MacVPN 0.x, choose **Check for Updates Now**, then **Download and Install** in the Update window. The 0.x updater checks the new release's signature like any other update. (Versions before 0.2.2 do not check signatures: on those, download the DMG from the [Releases](https://github.com/SepsiG/MacVPN/releases) page instead, quit MacVPN, and replace the app in Applications.)
2. **Create the vault.** At the first launch of 1.2 the **Set Up the Vault** window opens in migration mode: choose the master password, save the recovery key, and let MacVPN move your connections, passwords, pinned connections and their order, and the one-time code settings of system VPNs into the vault ([8.2](#82-upgrading-from-11), steps 3 to 5). The update settings and **Launch at Login** stay as they were. Connections you left running stay connected. Nothing needs to be imported again.
3. **The Keychain asks during the migration.** The new version has a new signature, so macOS asks whether MacVPN may read each old Keychain item: up to one prompt per item, and the window tells you how many to expect. Click **Always Allow** if the prompt names MacVPN at `/Applications/MacVPN.app`. (Items that very old versions stored under the Keychain service `macvpn` are moved to `local.macvpn.secrets` first, automatically.) After the migration the old items are deleted and the passwords are only in the vault.
4. **Reinstall the root layer.** 1.0 replaced the separate root scripts of 0.x with the single `mvpn` binary; 1.2 brings root layer 8. The **System Status** window opens with **Update required**, for example **Update required (6 → 8)** when coming from 0.4.0. Click **Authorize** and enter the admin password. Active VPN connections are disconnected first; the old files (`ovpn-dns`, `mvpn-validate`, `mvpn-mgmt`) are removed. Until you do this, OpenVPN, WireGuard, IKEv2 and SSTP connections show **Missing tool** and cannot connect.
5. **Hardened runtime.** The app and its root binary are signed with the hardened runtime, so macOS refuses to load foreign libraries into them. This protects the passwords the app holds in memory. Nothing changes for you; it is still ad-hoc signed, so Gatekeeper asks again only if you install the DMG manually.

### 8.2 Upgrading from 1.1

MacVPN 1.2 moves everything into an encrypted vault (see [11](#11-vault)) and brings root layer 8. The upgrade itself is the usual in-app update; take your time over the first launch.

1. **Back up first.** Quit MacVPN 1.1 (you can leave connections running), then copy its data folder in Terminal:
   ```
   cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.1
   ```
   The passwords are in the Keychain, not in this folder; keep them somewhere safe too (for example in a password manager) until the upgrade is done. Start MacVPN 1.1 again.
2. **Update in the app.** Menu → **Check for Updates Now** → **Download and Install** (see [8](#8-updates)). MacVPN restarts as 1.2.
3. **Create the vault.** The **Set Up the Vault** window opens. It says that your connections and saved passwords move into the vault, and how many times macOS may ask for Keychain access (for example **macOS may ask up to 5 times for access to the Keychain — choose Always Allow each time. This happens only once.**). Click **Continue**, choose the master password, keep **Unlock automatically** as you like, and click **Create Vault**. Save the recovery key and confirm it (see [11.1](#111-master-password-and-recovery-key)).
4. **The migration.** **Moving your data into the vault…**: every connection directory, every saved password, PSK and key password, the order and pins, the one-time-code settings of system VPNs and the paired apps are copied into the vault in one step, read back and compared. Only after that check are the old files overwritten and deleted and the old Keychain items deleted. The result says **Your data is in the vault** with the number of connections and secrets. If some items could not be read, it says so (**1 item could not be read and was left where it was.**); they stay in their old place.
5. **Keychain prompts.** During the migration macOS may ask once for each old Keychain item, because the 1.2 app has a new ad-hoc signature. Each prompt names MacVPN and `/Applications/MacVPN.app`: choose **Always Allow** (Hungarian macOS: „Mindig engedélyez”). If you click **Deny**, that secret cannot be read: it stays in the Keychain, and the connection asks for it at the next connect. This happens only once: afterwards MacVPN keeps one Keychain item at most (see [8](#8-updates)).
6. **Root layer 7 → 8.** The **System Status** window shows **Update required (7 → 8)**. Click **Authorize** and enter the admin password once. Active VPN connections are disconnected first. Until you do this, OpenVPN, WireGuard, IKEv2 and SSTP connections show **Missing tool**; L2TP, Cisco IPsec and system VPNs work without it.
7. **Check.** Connect each connection once. Saved passwords show **Saved — type to replace** in the editors.

**If the migration fails** (**The migration did not finish**), nothing is deleted. MacVPN removes the new, half-filled vault and keeps working from your 1.1 data in **read-only** mode: you can connect, but you cannot add, edit or delete anything (**MacVPN is using the old storage in read-only mode until the migration succeeds**). The menu shows a **The move into the vault did not finish. Try again…** banner. Click it (or **Try Again** in the window) and create the vault again with a new master password; the recovery key of the failed attempt is void. If you close the setup window before creating the vault, MacVPN also runs read-only from the 1.1 data, and the menu banner says **Finish setting up the vault…**.

**Paired apps** (control API) carry over and keep working after the migration.

### 8.3 Upgrading from 1.2

MacVPN 1.3 is the usual in-app update. The root layer stays 8, so **System Status** does not ask for the admin password.

- **The vault is updated on the first launch.** MacVPN 1.3 adds the tables for team catalogs. Before it changes anything, it keeps a copy of the still-encrypted old vault as `vault.db.bak-v1` next to `vault.db`. Nothing else changes in your data.
- **Going back to 1.2** only works read-only: 1.2 opens the updated vault read-only (it can connect, but it cannot edit, and it cannot restore a backup into it either). Do not put `vault.db.bak-v1` back by hand: that is not a supported way back. To edit your connections again, update to 1.3.
- **Keychain:** macOS may ask once whether MacVPN may read the vault key (only with **Unlock automatically** on), as after every update. Allow it only for MacVPN's own prompt (see [8](#8-updates)).
- **Team catalogs** need MacVPN 1.3 on every Mac that publishes or subscribes.
- **When to delete `vault.db.bak-v1`:** once you are happy with 1.3 (you will not go back to 1.2, and you have a fresh full backup, see [14.2](#142-back-up-everything)), delete it. It holds your data as it was before the upgrade, encrypted with the same vault key, so whoever can open your vault can open it too; MacVPN never updates or uses it.

---

## 9. Uninstalling

1. Open the **System Status** window and click **Uninstall MacVPN…**.
2. The confirmation dialog lists what will be removed:
   - `/usr/local/libexec/macvpn` (root scripts: the `mvpn` root binary and its `VERSION` file)
   - `/etc/sudoers.d/macvpn` (sudoers rule)
   - `/var/run/macvpn`, `/var/run/macvpn-ui` (runtime data)
   - `/var/log/macvpn` (connection logs)
3. If you tick **Also delete user data**, your data is deleted too: the vault with every connection, password, folder and shared credential (`~/Library/Application Support/MacVPN`, with `vault.db` and `vault.keys`), the vault key that **Unlock automatically** keeps in the Keychain (`local.macvpn.vault`), and any MacVPN Keychain items left from 1.1 (`local.macvpn.secrets`), including the shared secrets saved for system VPNs. Without the tick, the vault and its Keychain key stay, and a later install opens them again. Backup files you made with **Back Up Everything…** are not touched: delete them yourself if you no longer need them.
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

- **Ad-hoc signed app.** MacVPN is not signed with an Apple Developer ID and is not notarized. That is why you need the Gatekeeper step on first launch (see [1.2](#12-allow-the-first-launch-gatekeeper)). Only download it from the official [Releases](https://github.com/SepsiG/MacVPN/releases) page. The app and the `mvpn` root binary are signed with the hardened runtime and no entitlements, so macOS does not let other programs inject a library into them (for example through `DYLD_INSERT_LIBRARIES`) to read the passwords MacVPN holds in memory.
- **The vault (1.2).** Connections, configs, user names, passwords, PSKs, key passwords, shared credentials, folders and the order are in one encrypted SQLCipher database (`vault.db`, AES-256 with a per-page HMAC; the whole file is encrypted). Its random 256-bit key is stored only wrapped, in `vault.keys`: once with a key derived from the master password and once with a key derived from the recovery key (Argon2id, then XChaCha20-Poly1305). Neither the master password nor the recovery key is stored. The recovery key is shown once, when it is made, and never again. With **Unlock automatically**, the vault key itself is in the macOS Keychain (service `local.macvpn.vault`), readable by MacVPN's code signature; turn it off if you want the master password asked at every launch. **Lock Now** wipes the key from memory. Wrong master passwords are slowed down (up to 30 seconds between tries), never locked out. Both vault files are safe to copy, as they are encrypted; quit MacVPN first, so the database has written everything into `vault.db` (while it runs, recent changes may still be in its `vault.db-wal` file). Details: [11](#11-vault).
- **Passwords.** Passwords and PSKs are stored in the vault. Until 1.1 they were in the macOS Keychain (service `local.macvpn.secrets`); the migration to 1.2 deletes those items once their copies in the vault were checked (see [8.2](#82-upgrading-from-11)). The account name of L2TP / Cisco connections is not a secret: it is also written into the macOS profile. Passwords and PSKs are masked (`***`) in the log, and exports do not contain them. Keys that are part of a config (WireGuard `PrivateKey`, OpenVPN `<key>` and similar) are only exported if you choose **Export With Keys**. The L2TP / Cisco profile contains the PSK (but not the password) and is deleted from disk once installed. User names, passwords and PSKs cannot contain line breaks or control characters (MacVPN refuses to save them). A saved log is created with `600` permissions. For OpenVPN, the username and password go to MacVPN's root helper (`mvpn mgmt-bridge`, shown as `mvpn-mgmt` in process lists) through a root-only file (permissions `600` in a `700` directory) that the helper deletes right after reading it. The helper keeps them in memory, so OpenVPN can log in again when it reconnects, and hands them to OpenVPN through its root-only management socket. One-time codes are never stored: they exist only in memory while connecting, and are masked in the log.
- **Secrets in memory.** MacVPN wipes its own copies of the master password, the recovery key, the vault key and the passwords you type as soon as it no longer needs them. Copies made on the way in, by the web view that shows the windows and by the app's internal messaging (IPC), cannot be wiped by MacVPN; they live in the app's memory until it is reused. Stored passwords are never sent to the web view at all: the editors only learn that a value is saved.
- **Shared credentials.** A connection linked to a shared credential takes its user name and password from it. The connection's editor never changes the shared credential, even when you save the connection: it is changed only in **Credentials**, or by **Save in vault** in the credential prompt. An imported file is never linked to a shared credential silently, because the file chooses its own server: MacVPN asks first and shows the server the password would be sent to (see [13.4](#134-import-and-export)).
- **Backups.** A file made by **Back Up Everything…** contains every secret, encrypted with the backup password (Argon2id, XChaCha20-Poly1305). Anyone with the file and its password can read all your VPN credentials: keep the two apart. MacVPN treats a backup as untrusted input, because anyone who knows its password can craft one: before anything is written, it checks every item with the same rules as the editors and refuses an invalid backup as a whole. A restore never turns on **Allow other apps to control VPNs** by itself: that preference is unticked in the restore window, and every other backed-up preference is applied only if you tick it. Details: [14](#14-backup-and-restore).
- **L2TP / Cisco profiles and the vault (1.2).** macOS keeps the PSK of an L2TP / Cisco profile installed by MacVPN in its System keychain, as part of the profile: macOS owns these profiles, and without the PSK the VPN would not work when started from System Settings. The password is never in the profile. MacVPN's own copies of the PSK and the password (shown in the editor, and passed to macOS each time you connect from MacVPN) are kept in MacVPN's encrypted vault, not in the Keychain. To remove the PSK from the System keychain, remove the profile in **System Settings → General → Device Management**.
- **Root layer integrity.** The installer copies the root files (`mvpn` and `VERSION`) to a root-only staging folder and installs them only if their SHA-256 matches what the app computed just before asking for the admin password. It makes `/usr/local/libexec/macvpn` root-owned and not writable by others. If `/usr/local` or `/usr/local/libexec` is not root-owned or is writable by others, it stops with instructions instead of changing them (see [section 7.8](#78-other)). The sudoers rule starts `mvpn` with a clean environment (no `LANG`, `LC_*` or other variables from your session).
- **Sudoers and Homebrew (known limitation).** To connect, MacVPN uses a sudoers rule to run the `/usr/local/libexec/macvpn/mvpn` binary as root without a password, and that binary runs the Homebrew tools (`openvpn`, `wg-quick`, `charon`, `sstpc`). The Homebrew directory (`/opt/homebrew`) is writable by your user. Malware running in your user account could replace those programs and gain root that way. Config filtering protects against accidental or imported dangerous settings, not against malware already running in your account. On a single-user Mac that you administer yourself, this is an acceptable risk. If it is not for you, do not enable the root layer, and use only L2TP / Cisco connections.
- **SSTP password on the command line (known limitation).** The Homebrew `sstpc` computes the SSTP crypto binding keys from the password itself, so it only starts when the password is given on its command line (`--password`). MacVPN passes it there and never writes it into the log (`***`). `sstpc` masks its own command line right after reading it, but for that first moment other local users could see the password with `ps`. On a single-user Mac this is an acceptable risk. If it is not for you, do not use SSTP.
- **Paired apps (control API).** Off by default. When you turn on **Allow other apps to control VPNs** (Connections window → **Paired apps**), programs of your user account that you pair can list the connections you allow and bring them up and down, through a private socket; they never see configs or passwords. Pairing pins the program's executable path, and every action is listed under **Activity**. Details and limitations: [Control API guide](control-api.md#4-security-model).
- **Team catalogs (1.3).** A catalog is signed with the administrator's admin key and encrypted with the team key; MacVPN checks the signature against the fingerprint you pinned, refuses older versions, and checks every config like an import. What each part protects, and what it does not: [16.11](#1611-security-model).
- **No proxy (updates, team catalogs).** MacVPN downloads updates and HTTPS team catalogs with the system `curl` in a cleared environment, so proxy settings (`https_proxy`, `all_proxy`, the macOS proxy settings) are not used: the update server and the catalog host must be reachable directly. A proxy setting may come in a later version.
- **Update integrity.** MacVPN installs an update only if it carries a valid Ed25519 signature made with the maintainer's offline key. The public keys (a primary and a backup) are built into the app; the private keys are never on GitHub or in the build system. So even if someone takes over the GitHub account or repository, they cannot push an update to MacVPN: a release without a valid signature is not offered, or is refused with **The update is not signed by the MacVPN maintainer**. The signature covers the version and the SHA-256 of the DMG that MacVPN computes itself after downloading. **Remaining risk:** whoever holds the maintainer's signing key can sign an update.
- **How the updater limits the risk further.**
  - It asks GitHub for the latest release by the repository's fixed numeric ID (`MacVPNUpdateRepoID` in the app's `Info.plist`), not by its name. If the repository were renamed or deleted and someone created a new one under the old name, the app would not take updates from it. Without the ID, the app does not check for updates at all.
  - It accepts the DMG, its `.sha256` file and its `.sig` signature only from `https://github.com/SepsiG/MacVPN/releases/download/<tag>/<file name>`, for exactly the tag of the release; redirects may only lead to GitHub's own download hosts.
  - Releases are built by a hardened GitHub Actions workflow: actions pinned to exact commits, read-only build job, the tagged commit must be on `main`, and a separate job that runs no repository code and only creates a draft. The maintainer checks the checksum, signs the release offline on their own Mac, and only then publishes it.
  - The optional 24-hour delay (see [section 8](#8-updates)) gives time to notice and pull a bad release.
  - The app is ad-hoc signed; macOS may ask once after each update for Keychain access to the vault key (see [section 8](#8-updates)). Allow it only for MacVPN's own prompt.
- **Third-party licences.** MacVPN is MIT-licensed ([LICENSE](../LICENSE)). The app bundle contains `THIRD-PARTY-NOTICES.txt` with the licences of the components it ships, among them SQLCipher (BSD-style, © Zetetic LLC).

---

## 11. Vault

From 1.2, MacVPN keeps your connections, their configs, user names, passwords, PSKs and key passwords, the shared credentials, the folders and colours, the order and pins, the one-time-code settings of system VPNs and the paired apps in one encrypted file, the **vault**: `~/Library/Application Support/MacVPN/vault.db`, with its key file `vault.keys` next to it. The whole database is encrypted; without the vault key nothing in it can be read, not even the connection names.

### 11.1 Master password and recovery key

The **Set Up the Vault** window opens on the first launch of 1.2 (later, while there is no vault, from the menu's **Set Up the Vault…** row).

1. **Set up the vault.** It explains the vault. If you are upgrading, it also says that your data moves into the vault and how often macOS may ask for Keychain access (see [8.2](#82-upgrading-from-11)). On a new Mac you can choose **Restore from backup…** here instead (see [14.3](#143-restore-on-a-new-mac)). Click **Continue**.
2. **Choose a master password.** At least 10 characters; a long phrase is easier to remember and harder to guess. A hint under the field rates it (**Too short**, **Weak — easy to guess**, **Fair**, **Strong**); weak passwords are allowed but not advised. Type it again in **Repeat the master password**. **Unlock automatically** is ticked (see [11.2](#112-unlock-automatically)). Click **Create Vault**.
3. **Your recovery key.** 24 letters and digits in six groups, like `7K2M-…-QX4T`. If you forget the master password, this key is the only way back into the vault. Write it down or keep it in a password manager: **it is shown only now**. **Copy** copies it. Click **I Saved It**.
4. **Check your recovery key.** Type the group the window asks for (**Type group 3 of your recovery key, counting from the left.**) and click **Confirm**.
5. **The vault is ready.** Click **Done**. When upgrading, the migration runs first (**Moving your data into the vault…**, then **Your data is in the vault**).

The window has no default button: Return in a field does nothing, so click the buttons. The recovery key is not case-sensitive; `O` counts as `0`, `I` and `L` as `1`, and dashes and spaces are ignored.

### 11.2 Unlock automatically

- **On** (the default): the vault key is kept in the macOS Keychain (service `local.macvpn.vault`), so MacVPN opens without asking. After an update macOS may ask once whether MacVPN may read it: choose **Always Allow** if the prompt names MacVPN at `/Applications/MacVPN.app`.
- **Off:** MacVPN asks for the master password at every launch. To turn it off, open the menu's **Settings** and switch off **Unlock automatically**, then confirm with **Turn Off** (**Turn off automatic unlock?**). The Keychain item is deleted.
- **To turn it on again,** switch it on: the **Turn on automatic unlock** window asks for the master password; click **Turn On**.
- If the Keychain item cannot be read (for example you clicked **Deny**), MacVPN asks for the master password instead.

### 11.3 Unlocking

The **Unlock MacVPN** window opens at launch when the vault is not unlocked automatically, and from the locked menu's **Unlock…** row. Enter the **Master password** and click **Unlock**.

A wrong password shows **Wrong password or recovery key**. Each further wrong try makes the next one wait longer (1, 2, 4, 8, 16, then 30 seconds; the button shows **Try again in 8 s**). There is no lockout. If you forgot the password, click **Use recovery key** (see [11.8](#118-forgotten-master-password)).

### 11.4 Lock Now

**Lock Now** in the menu's footer locks the vault at once. It is shown when **Unlock automatically** is off, or when you switch on **Show “Lock Now”** in the menu's **Settings**.

Locking closes the vault and wipes its key from memory. It does **not** delete the Keychain item: with **Unlock automatically** on, the next launch opens without asking again. Running VPNs stay up. Unsaved changes in the Connections window are discarded, and the master password and recovery key windows close.

### 11.5 The locked menu

While the vault is locked, the menu shows only:

- an **Unlock…** row (**MacVPN is locked**),
- the number of active connections (**1 connection active**, **3 connections active**), without their names,
- **Quit MacVPN**.

Nothing that needs the vault works while it is locked: connecting, editing, importing, exporting, the folders (hidden, and they cannot be changed: **Folders cannot be changed while the vault is locked**), shared credentials and backups. Such actions answer **The vault is locked. Unlock it and try again.** Paired apps get the `locked` error; they can still bring a VPN down (see the [Control API guide](control-api.md)).

### 11.6 Changing the master password

1. Menu → **Settings** → **Change Master Password…**.
2. Enter the **Current master password**, then the **New master password** twice.
3. Click **Change Password**. **The master password was changed**: use the new one from now on.

Your recovery key stays the same. The vault is not re-encrypted; only its password-wrapped key is rewritten. A wrong current password is slowed down like an unlock.

### 11.7 A new recovery key

If your recovery key may have been seen by someone, or you lost it while you still know the master password:

1. Menu → **Settings** → **New Recovery Key…**.
2. Enter the **Master password** and click **Make New Key**. The new key replaces the old one: the old key stops working at once.
3. Save the new key (it is shown only now), click **I Saved It**, type the group asked for, and click **Confirm**.

### 11.8 Forgotten master password

1. In the **Unlock MacVPN** window, click **Use recovery key**.
2. Type the **Recovery key**, then a **New master password** twice.
3. Click **Reset and Unlock**.

Your connections stay as they are, and the recovery key keeps working. **Use the master password** goes back to the password field.

---

## 12. Folders and colours

Folders group connections in the **Connections** window and in the menu. They nest to any depth. Connections created in MacVPN and system VPNs can both be put in folders, or stay at the top level.

### 12.1 Folders

- **Create:** toolbar **New** (+) → **New Folder**, or right-click a folder → **New Folder** (a subfolder), or right-click a connection or an empty area → **New Folder** (at the top level). The new folder is named "New Folder", and its name field is open: type the name and press Return.
- **Folder context menu:** **New Folder**, **Rename**, **Colour…**, **Move to Top Level** (for a subfolder), **Delete…**.
- **Connection context menu:** **Pin to Top** / **Unpin**, **Colour…**, **Move to Top Level** (for a connection in a folder), **New Folder**.
- **Names:** 1 to 64 characters, no control characters (**A folder name needs 1 to 64 characters and no control characters**).

### 12.2 Colours

**Colour…** opens a palette of 12 colours: Red, Orange, Amber, Yellow, Lime, Green, Teal, Cyan, Blue, Indigo, Purple and Pink. They are tuned for light and dark mode.

- A **folder** can also have **None**. A folder without its own colour takes its parent folder's colour.
- A **connection** without its own colour takes the colour of its nearest coloured folder. A connection with its own colour shows an **Own colour** dot; **Use folder colour** in the palette removes it.
- The colour shows as a slim bar on the connection's row and on the folder icon.

### 12.3 Order inside a folder

Inside every folder (and at the top level): first the subfolders, in the order you dragged them; then the pinned connections, in your order; then the others, most used first (see [5.1](#51-order-of-connections)); connections with equal use by name.

### 12.4 Drag and drop

- **Folders** can be dropped into another folder (they nest) or between folders (they are reordered).
- **Connections** only change folder when dropped on a folder. The exception is a pinned connection dropped on another pinned connection in the same folder: that changes the order of the pins.
- While you drag, a **Top level** drop zone appears: drop there to move an item out of all folders.
- A folder cannot be dropped into itself or one of its subfolders: **A folder cannot be moved into itself or one of its subfolders**.

### 12.5 Deleting a folder

**Delete…** asks **What should happen to its contents?**

- **Move its contents to the parent folder** (or **Move its contents to the top level** for a top-level folder) is the default. The connections and subfolders stay.
- **Delete the connections too** deletes the connections in the folder and its subfolders, with their saved passwords. A second confirmation asks first (**Delete 3 connections?**, **This cannot be undone.**, **Delete Connections**).
- System VPNs are never deleted this way: **System VPNs are moved to the top level.**
- While a connection inside the folder is active, the folder cannot be deleted: **Disconnect the connections in this folder before deleting them**.

### 12.6 Folders in the menu

- Folders are rows you can open and close; MacVPN remembers which are closed.
- A folder's badge shows how many connections inside are active (**2 active**), also when it is closed.
- Nesting is shown by indentation, up to 3 levels; deeper folders work but are not indented further.

### 12.7 Export, import and system VPNs

- An export writes the folder path in its `# macvpn-meta` line; an import recreates the missing folders (see [4](#4-import-and-export)).
- A system VPN keeps its folder and colour for 30 days after it disappears from macOS, so it comes back in its place if it is reinstalled (for example after a restore on a new Mac).
- While the vault is locked, folders are hidden and cannot be edited.

---

## 13. Shared credentials

A **shared credential** is a named user name and password that several connections use, for example "Office AD". Change it once, and every connection that uses it signs in with the new one. Passwords are stored in the vault and never shown.

### 13.1 The Credentials section

Open the **Connections** window and select **Credentials** in the sidebar. Each credential shows its name, its user name (or **No user name**), **Password saved** or **No password saved: asked when connecting**, and **Used by 3 connections**.

- **Add Credential…** → **New Shared Credential**: **Name** (1 to 64 characters), **Username**, **Password**. The password is optional: without it, MacVPN asks for it when connecting and can save it here.
- **Edit…**: change the user name or password. The password field shows **Saved — type to replace**, as in the editors.
- **Rename…**: a new name; the links stay.
- **Delete**: a credential that no connection uses is deleted. If connections use it, MacVPN lists them and asks **Copy into Each Connection** (each gets the user name and password as its own, then the credential is deleted) or **Cancel**. A credential in use is never deleted silently.

### 13.2 Create from a connection

Nothing is converted automatically when you upgrade. To turn a connection's sign-in into a shared credential:

1. **Credentials** → **Create from Connection…**.
2. Pick the **Connection** and a **Name**, and click **Next**. The connection's stored user name and password become the shared credential, and the connection uses it. The values are not shown.
3. **Link the Same Sign-in?** lists the other connections with the same user name and password (compared inside MacVPN, never shown). Tick the ones that should use the credential too, and click **Create and Link**. If there are none: **No other connection has the same user name and password.**

### 13.3 Using a credential in a connection

Editors with a user name and password (OpenVPN with `auth-user-pass`, IKEv2 with EAP, SSTP, L2TP, Cisco IPsec, and L2TP / Cisco system VPNs) have a **Password from** selector:

- **Own username and password** (the default): the fields of the connection itself.
- **Use credential: Office AD**: MacVPN asks **Use the shared credential Office AD?** and explains that the user name and password stored for this connection are deleted. Click **Use Credential**. The connection's own fields are then hidden, and the editor says **The user name and password come from the shared credential Office AD. Change them in the Credentials section.**

Other secrets (PSK, private key password, one-time-code settings) stay with each connection. **The editor never changes a shared credential**: saving a connection cannot change what other connections use. A shared credential changes only in **Credentials**, or when you tick **Save in vault** in the credential prompt (see [5.3](#53-credentials-asked-when-connecting)); a new password saved there after a rejected sign-in updates the shared credential for every connection.

### 13.4 Import and export

- An export writes only the credential's **name** (`credentialName` in the `# macvpn-meta` line), never its user name or password.
- An import never links a credential silently: the imported file chooses its own server, and a silent link would send your shared password there. If a credential with that name exists, MacVPN asks **Use the shared credential 'Office AD' for this connection to vpn.example.com?** and names the server read from the file. **Use Own Fields** (the safe choice) keeps the connection's own user name and password; choose **Use Shared Credential** only if you trust the file. If no credential has that name, you can pick another credential or use the connection's own fields.
- Paired apps (control API) never see shared credentials.

---

## 14. Backup and restore

The per-connection export (see [4](#4-import-and-export)) never contains passwords. For reinstalling macOS or moving to another Mac there is a **full backup**: one encrypted file with everything.

### 14.1 What a backup contains

- every connection with its config and secrets,
- the folders, colours, order, pins and usage ranking,
- the shared credentials,
- the one-time-code settings and folder placement of system VPNs,
- the app preferences: automatic update checks, the 24-hour delay, **Launch at Login**, **Allow other apps to control VPNs** and **Unlock automatically**,
- from 1.3: your **team catalog subscriptions** (source, team key, access token, the pinned publisher key and the last applied version), your **admin keys**, and your **publications** with their team keys. The catalog's connections and folders themselves are not in the backup: after a restore, the next refresh brings them back from the source, with your filled-in credential slots, pins and order. No restore, a merge or **Replace everything**, lowers the last applied version of a catalog this Mac already follows, so the rollback protection keeps working.

A backup with admin keys can sign catalogs for your team: protect it like the admin key. Not included: the **paired apps** (they are tied to program paths on this Mac: pair them again after a restore), the vault key and the recovery key, and the logs.

### 14.2 Back Up Everything

1. Menu → **Settings** → **Back Up Everything…** (or **New** (+) → **Back Up Everything…** in the Connections window). It needs an unlocked vault.
2. Read the warning: **Anyone with this file and its password can read all your VPN credentials.**
3. Choose a **Backup password** (at least 10 characters) and repeat it. MacVPN does not store it: without it the backup cannot be opened.
   - Instead you can click **Use my master password…** and confirm with **Use Master Password**. Then anyone who learns your master password can also open this file, wherever it is kept; a separate backup password keeps the two apart.
   - Type your **Master password** too. MacVPN checks it before every backup (with the same delay after a wrong one as the unlock), so an unlocked Mac left alone is not enough to take a copy of all your passwords.
4. Click **Back Up…** and choose where to save. The file is named `MacVPN-backup-<date>.macvpnbackup`, readable only by you.
5. Keep the file and its password apart, for example the file on an external disk and the password in a password manager.

### 14.3 Restore on a new Mac

1. Install MacVPN, and start it. A backup made by 1.2 needs 1.2 or later; a 1.3 backup needs 1.3 or later (1.2 refuses it as made by a newer MacVPN).
2. In the **Set Up the Vault** window, click **Restore from backup…**. (This needs a new, empty vault.)
3. **Choose File…**, enter the **Backup password**, and click **Open Backup**.
4. Choose a new master password for this Mac and save the new recovery key, as in [11.1](#111-master-password-and-recovery-key).
5. Everything is restored in one step. Then follow the after-restore steps in [14.5](#145-after-a-restore).

### 14.4 Restore into an existing vault

1. Menu → **Settings** → **Restore from Backup…**. Nothing changes before you confirm what to restore.
2. **Choose File…**, enter the **Backup password**, **Open Backup**. A wrong password or a damaged file gives one message: **The backup cannot be opened. The password is wrong, or the file is damaged.**
3. The summary shows when and by which version it was made (**Made on … by MacVPN 1.2.0**) and how many **Connections**, **Folders** and **Shared credentials** it holds. It lists first the connections whose risky OpenVPN settings were acknowledged (such as scripts that run as root): restore only a backup you made yourself.
4. Choose:
   - **Merge**: adds what is missing here. For items that already exist, choose once for all (**When an item already exists:**): **Overwrite it with the backup’s copy**, **Keep the item that is here**, or **Keep both (the backup’s copy is named “(backup)”)**. A merge drops the risky-setting acknowledgements of the restored connections, unless the same connection with the same config is already here; its editor then asks again. A merge never changes a team catalog's connections or folders: a backup item with the same id (a 1.2 backup made from a 1.3 vault holds them as ordinary items) is skipped in every mode, and the result names it.
   - **Replace everything**: clears the vault first. A confirmation says how many connections, folders and shared credentials will be deleted; **This cannot be undone.** **Back Up the Current State First…** makes a backup of the current state before you go on. Paired apps stay. Replace keeps the acknowledgements.
     - **Team catalog subscriptions** are replaced by the backup's. The confirmation names the subscriptions here that are not in the backup: they go, with their connections and folders. A catalog in both keeps the higher applied version.
     - **Admin keys and publications** belong to this Mac, like the paired apps: a role (primary or backup key) or a catalog that the backup has nothing for keeps this Mac's key or publication (a 1.2 backup has none, so they all stay). Where the backup has its own, the backup's is used, and the confirmation counts the keys and names the publications it replaces. A publication's version is never lowered.
5. **The backup was restored.**

If anything fails, **The restore failed. Nothing was changed.** A backup whose folders would form a loop with the folders here is refused too.

### 14.5 After a restore

- **Preferences.** **The backup’s preferences are not applied by themselves.** Each row shows the backup's value and this Mac's (**Backup: On · This Mac: Off**). Tick the ones to use on this Mac and click **Apply Selected Preferences**. **Allow other apps to control VPNs** is never ticked for you: tick it only if you use paired apps on this Mac, and pair them again.
- **Native profiles.** L2TP and Cisco IPsec connections need their profile on this Mac. **Reinstall 2 Native Profiles** opens them; macOS asks you to approve each one in **System Settings → General → Device Management**.
- **Tools.** A missing Homebrew tool or root layer shows in **System Status**, as usual.
- **System VPNs** that do not exist on this Mac keep their folder and colour for 30 days, in case you set them up again.

### 14.6 A backup is untrusted input

Anyone who knows a backup's password can make one, so MacVPN checks every item with the same rules as the editors (names, user names, passwords, folder names, sizes, the number of entries, no control characters) before it writes anything. An invalid backup is refused as a whole (**This backup cannot be restored: it holds data MacVPN does not accept.**). A backup made by a newer MacVPN is refused with **This backup was made by a newer MacVPN. Update MacVPN to restore it.** No restore ever turns on the control API by itself.

---

## 15. Vault FAQ

**I forgot the master password.**
Click **Use recovery key** in the **Unlock MacVPN** window and set a new master password with your recovery key ([11.8](#118-forgotten-master-password)). If **Unlock automatically** is on, MacVPN still opens without the password, but **Change Master Password…** and **New Recovery Key…** need it: lock MacVPN (**Lock Now**), then reset it with the recovery key.

**I lost the recovery key.**
If you still know the master password, make a new one at once: **Settings → New Recovery Key…** ([11.7](#117-a-new-recovery-key)). If you lost both the master password and the recovery key:

- With **Unlock automatically** on, MacVPN still opens the vault and your connections keep working, but nothing that needs the master password does (changing it, a new recovery key, a new backup). Export the connections you need now ([4](#4-import-and-export); the saved passwords are not in an export).
- With **Unlock automatically** off, the vault cannot be opened by anyone, MacVPN included.
- A backup opens only with its own password. A backup made with **Use my master password…** needs the master password as it was when the backup was made. The recovery key never opens a backup.

Restore from a backup you can still open ([14](#14-backup-and-restore)), or set MacVPN up again: uninstall with **Also delete user data** ([9](#9-uninstalling)) and import your connections again.

**MacVPN says it is locked.**
Click **Unlock…** in the menu and enter the master password. Running VPNs stayed up while it was locked. If it locks at every launch, **Unlock automatically** is off or macOS refused the Keychain access: switch it on in **Settings** ([11.2](#112-unlock-automatically)).

**The migration from 1.1 failed.**
Nothing was deleted, and MacVPN works read-only from your 1.1 data. Click the **The move into the vault did not finish. Try again…** banner in the menu and create the vault again with a new master password ([8.2](#82-upgrading-from-11)). If it fails again, quit MacVPN, check that your 1.1 data folder is intact (and your backup of it), and report the message shown in the window.

**How many Keychain prompts should I expect?**
During the migration from 1.1: up to one per old Keychain item; the setup window tells you the number beforehand. Answer **Always Allow** each time. After that, at most one after each update (for the vault key), and none if **Unlock automatically** is off. A prompt that does not name MacVPN at `/Applications/MacVPN.app` is not MacVPN's: click **Deny**.

**I clicked Deny by mistake during the migration.**
That item could not be read and was left in the Keychain; the result says how many. The connection asks for the missing password at the next connect (**Save in vault** stores it).

**"The vault is damaged and cannot be opened."**
`vault.db` or `vault.keys` was changed or is incomplete. Restore from a backup ([14](#14-backup-and-restore)), or quit MacVPN and put back a copy of both files (made while MacVPN was not running).

**"This vault was saved by a newer MacVPN."**
You started an older MacVPN after a newer one. Install the latest version.

**How do I remove everything when uninstalling?**
Tick **Also delete user data** in **Uninstall MacVPN…**: it deletes the vault, the vault key in the Keychain and any 1.1 Keychain items ([9](#9-uninstalling)). Delete your `.macvpnbackup` files yourself.

---

## 16. Team catalogs

A **team catalog** shares VPN connections with a team. An administrator publishes a set of connections once, with their folders, colours and named sign-in placeholders. Every team member's MacVPN subscribes to it and picks up additions, changes and removals by itself. Each member keeps their own user names, passwords and one-time-code secrets, and their own pins, order and collapsed folders.

- The catalog is one file, `<name>.macvpncatalog`. It is **signed** with the administrator's **admin key** and **encrypted** with the **team key**.
- MacVPN never uploads anything. The administrator puts the file on an HTTPS web server, a file share or a synced folder, and every member reads it from there.
- Every team member needs MacVPN 1.3 or later.
- Several catalogs can be used side by side, and you can publish and subscribe on the same Mac.

What a member needs from the administrator: the **source** (an `https://` URL or a file path), the **team key** (`TEAM-` followed by 14 groups of 4 characters) and the **publisher fingerprint** (8 groups of 4 hex digits). A **subscription string** (`macvpn-sub:…`) carries all three in one line.

### 16.1 Subscribing to a catalog

1. Open the **Connections** window and select **Team catalogs** in the sidebar. Click **Add team catalog…**.
2. Paste the **subscription string** you got from your administrator. It fills in the source and the fingerprint; the team key is checked and kept hidden. Without a subscription string, fill in the fields yourself:
   - **Source:** an `https://` URL, or **File** and **Choose File…** for a file on a share or in a synced folder (iCloud Drive, OneDrive, Dropbox).
   - **Team key:** `TEAM-XXXX-…`. Case, dashes and spaces do not matter; `O` counts as `0`, `I` and `L` as `1`. The last group is a check group, so a typo is caught as you enter it and is almost never mistaken for a wrong key.
   - **Publisher fingerprint:** 8 groups of 4 characters. It is required: MacVPN never trusts the first download without it.
3. **Access token** (optional, HTTPS only): if the web server needs a bearer token, enter it here. It is not part of the subscription string, because a token is often personal; ask your administrator.
4. Click **Check**. MacVPN downloads the catalog, checks its signature against the fingerprint you entered and opens it with the team key. The preview shows the catalog's name, version and fingerprint, the number of connections and folders, the credential slots (see [16.3](#163-credential-slots)), and how many connections have risky settings.
5. **Compare the fingerprint** with what your administrator told you through another channel, for example by phone. If it differs, do not subscribe.
6. Tick **The fingerprint matches what my administrator sent me** and click **Subscribe**. The catalog's connections appear at once, and **Team catalogs** shows the new subscription. **Cancel** or **Back** drops the downloaded preview.

A subscription string that a mail program broke across lines is refused: copy it again as one line. The preview expires after 10 minutes (**The catalog preview expired. Add the catalog again.**). A catalog you already have is refused with **You are already subscribed to this catalog.**

**Sources.**
- **HTTPS:** `https://` only, checked against the macOS trust store. Redirects are followed only to `https://` addresses, at most 5. The access token is sent only to the subscription URL's own host and port, never to another host after a redirect. **Proxies are not supported:** MacVPN fetches with the system `curl` in a cleared environment, so `https_proxy`, `all_proxy` and the macOS proxy settings are not used, and the catalog host must be reachable directly.
- **File:** a path on a mounted network share (SMB, NFS) or in a synced folder. The file itself must not be a symbolic link and must be a regular file of at most 8 MB. A share that is not mounted, or a cloud file that cannot be downloaded right now, counts as **unavailable**, not as an error (see [16.6](#166-troubleshooting-for-users)).

### 16.2 Catalog connections

- Each catalog has its own top-level folder named after the catalog, with a **Team** badge, in the menu and in the Connections window. The publisher's folders and colours are inside it.
- **Read-only:** the name, the config, the folder and the publisher's colour. The editor says **Managed by the team catalog “Acme VPN”**, and its fields are disabled.
- **Yours to change:** connect and disconnect, pin and order, collapse folders, your own colour for a connection (**Use team colour** goes back to the publisher's), and the risky-settings checkbox (the only part of the editor you save). Your user name and password come from the catalog's credential slot (see [16.3](#163-credential-slots)), which you change in **Credentials**. Catalog connections and folders cannot be renamed, moved, dragged or deleted; their context menu offers only **Pin to Top** / **Unpin**, **Colour…**, **Duplicate as personal connection…** and, when the catalog changed a native connection, **Install profile**.
- **Risky settings** (see [7.7](#77-directive-not-allowed--forbidden-directive)) are never acknowledged by the catalog: you tick them yourself in the editor's yellow panel. When a new catalog version changes the config, you are asked again.
- **L2TP and Cisco IPsec** connections need their macOS profile, as usual (**Install profile**, then approval in System Settings). When the catalog changes such a connection, the connection's detail says **The team catalog changed this connection: reinstall its profile**, and the connect is refused until the new profile is installed. Click **Install profile** and approve it in System Settings. The mark clears once macOS shows the new profile. When only the group name or **Send all traffic over VPN** changed, macOS shows no difference: after approving the profile, click **I installed it** and confirm. Confirm only after the approval: with the old profile still installed, the connection would use settings the catalog has replaced.
- **Paired apps** (control API) see catalog connections like any other; you allow them per connection, as in [5.4](#54-paired-apps-control-api). A catalog connection's id stays the same across versions.
- **Duplicate as personal connection…** (in the connection's detail or context menu) makes an independent, editable copy at the top level, named “<name> (personal)” unless you change it. The copy keeps the config, your own secrets and the provided secrets, and the same shared credential. Its risky-settings acknowledgement starts empty. The copy is yours: later catalog versions do not change it.

### 16.3 Credential slots

A **credential slot** is a named sign-in, such as “Office AD”, that the catalog uses without any user name or password in it. Each member fills it in with their own.

- When the catalog is first applied, MacVPN creates a **shared credential** (see [13](#13-shared-credentials)) named after each slot, empty. If you already have a credential with that name, the new one gets the catalog's name as a suffix, such as “Office AD (Acme VPN)”. A slot is never linked to one of your existing credentials automatically.
- At the first connect, the credential prompt asks: **Office AD (team catalog “Acme VPN”) — enter your user name and password**. With **Save in vault** they are saved into that shared credential, and every other catalog connection with the same slot connects without asking. Your user name and password stay in your vault: they never go to the administrator or into the catalog.
- **SSTP** connections use the slot's user name in place of the config's `user=` line, and **L2TP / Cisco** connections use it as the account name. Nothing in the stored config changes.
- You can change the user name or password later in **Credentials**, like any shared credential. A connection that already has its own saved user name and password is not linked to the slot.

### 16.4 Refresh and updates

MacVPN checks every catalog:

- at launch and when the vault is unlocked (nothing is checked while it is locked),
- every 15 minutes,
- when the Mac wakes from sleep,
- when you click **Refresh now** in **Team catalogs**.

While a source keeps failing, MacVPN waits longer between attempts: 1, 2, 4, 8, 16, 32 minutes, then every 60 minutes (with a little random delay). Waking from sleep and **Refresh now** always try at once. An HTTPS server that has not changed the file answers “not modified”; a file source is read and compared with what was applied last.

A new version is applied in one step: everything or nothing. A notification lists the changes, for example **Team catalog “Acme VPN” updated: 2 added, 3 changed, 1 removed**.

- A connection that is **up** when it changes stays up with the settings it was started with. The new config is used from the next connect.
- A connection that is **up** when it is removed from the catalog stays up, moves to the catalog's top folder and shows **Removed from the team catalog — disappears after you disconnect**. After you disconnect, it is deleted, with its pin and order.
- The same version uploaded again changes nothing and gives no notification.

**Team catalogs** shows each subscription with its source (an HTTPS address without its query part), status, version, last refresh, publisher fingerprint and the last error.

### 16.5 Changing or removing a subscription

- **Change team key…** (after the administrator rotated it), **Change access token…** and **Edit source…** are in the subscription's detail. If the new source is on another host or port, or is a file, the stored access token is dropped: the token is never sent to a new address. Enter the token for the new address if it needs one.
- **Unsubscribe…** names the catalog and how many connections it removes. Connections that are up are disconnected first. Then every catalog connection and folder is removed, and paired apps lose access to them. Credential slots you filled in are kept as ordinary shared credentials in **Credentials**; empty ones are deleted.
- To keep a connection after unsubscribing, duplicate it first (**Duplicate as personal connection…**).

### 16.6 Troubleshooting for users

- **The catalog is signed by a different key than the fingerprint you entered.** (when subscribing): the file was not signed by the key your administrator gave you. Check the fingerprint with your administrator by phone. Never “fix” it by typing the fingerprint the file has.
- **The team catalog was signed by another publisher than the one you trust.** (on refresh): the file on the source is signed by a key your MacVPN does not trust. Either someone else placed a file there, or your administrator changed keys without the announcement reaching you (see [16.10](#1610-changing-the-admin-key-and-compromise)). Ask your administrator; you may have to unsubscribe and subscribe again with the new fingerprint.
- **The team catalog's signature is not valid: it was changed.**: the file was modified or damaged after it was signed. The items stay as they were. Ask your administrator to publish again.
- **The team key of “Acme VPN” has changed. Ask your administrator for the new key.** (notification; status **The team key does not open this catalog (it is wrong or was rotated).**): the administrator rotated the team key. Get the new key through a secure channel, then **Change team key…** and **Refresh now**. Until then the catalog's connections stay as they were.
- **Team catalog “Acme VPN” offered an older version (v3 after v5) and was not applied.**: the source holds an older version than the one you already have. This is the rollback protection (see [16.11](#1611-security-model)): an old copy came back on the server (a restored server backup, a sync conflict), or someone tries to bring back old settings. Your connections are unchanged. Tell your administrator; publishing a new version solves it.
- **The team catalog source is unavailable (…).**: the share is not mounted, the server or the network is down, or a cloud file cannot be downloaded right now. There is no error notification for this; MacVPN tries again with the back-off of [16.4](#164-refresh-and-updates). Mount the share, or download the file in Finder, then click **Refresh now**.
- **The team catalog could not be read: access denied (check the access token)**: the HTTPS server refused the request (HTTP 401 or 403). Enter the current token with **Change access token…**. If you just changed the source to another host, the token was dropped on purpose (see [16.5](#165-changing-or-removing-a-subscription)): enter it again.
- **… certificate not trusted**: the server's certificate is not trusted by macOS. Ask the server's administrator; MacVPN has no option to skip the check.
- **… redirect to a non-HTTPS address**: the server redirects to `http://`. The catalog must be served over HTTPS end to end.
- **The source holds another team catalog.**: the file at the source is a different catalog. Check the source with your administrator.
- **The team catalog was made by a newer MacVPN.**: update MacVPN.
- **The team catalog contains a connection MacVPN cannot use.**: a connection in the catalog does not pass MacVPN's checks. Nothing was applied; ask your administrator.
- **Behind a proxy:** proxies are not supported (see [16.1](#161-subscribing-to-a-catalog)). The catalog host must be reachable directly, or the catalog must be on a file share.

### 16.7 For administrators: the admin key

Publishing needs an **admin key**: an Ed25519 signing key kept in your vault. Its **fingerprint** is what your team compares when subscribing.

1. **Connections** window → **Publishing** → **Generate Admin Key**. The fingerprint is shown in 8 groups; **Copy** copies it.
2. **Generate Backup Admin Key**, then **Export Backup Key…**: choose where to save the `.macvpnadminkey` file and a password of at least 10 characters (twice). Tick **Remove the backup key from this Mac after export**: the backup key is then only in that file. Keep the file offline (for example on a USB stick in a safe) and its password somewhere else (for example in a password manager).

Every catalog you publish announces the backup key as the **successor** of the current key, inside the signed part of the file. Subscribers that refresh store the announcement. When you switch to the backup key, they accept catalogs signed by it and stop accepting the old key.

**Switching to the backup key** (a planned key change):
1. On the Mac that publishes from now on: **Publishing** → **Import Admin Key…**, choose the `.macvpnadminkey` file and enter its password. This Mac must also have your publications (each catalog's id, version and team key): they are in the vault, not in the key file, so use the same vault or restore a full backup first. Without them, the next publish makes a new catalog, and every member must subscribe to it again.
2. **Switch to the Backup Key…**: the backup key becomes the admin key, and the old admin key is deleted from this Mac.
3. Publish a new version of each catalog. Subscribers that refreshed since the backup key was created follow automatically. Those that did not must subscribe again with the new fingerprint.
4. Generate and export a new backup key, so the next change is prepared too.

The admin keys, your publications and their team keys are part of the vault, so a full backup ([14](#14-backup-and-restore)) contains them. Keep backups as safe as the admin key itself.

### 16.8 For administrators: publishing a catalog

**Publishing** → **Publish Catalog…** opens the wizard:

1. **Connections.** Tick folders and connections. A ticked folder brings everything inside it; a connection whose folder is not ticked goes to the catalog's top level. System VPNs and connections from other catalogs cannot be published.
2. **Secrets.** Each stored PSK and key password of the selection, none ticked. Tick only the team secrets everyone may know, such as a shared L2TP PSK; ticking one says **Everyone with the team key can read this secret**. Secrets written inside a config are listed for a tick each too: a WireGuard `PresharedKey`, and OpenVPN `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>` and `<secret>` blocks.
3. **Credential slots.** The shared credentials the selected connections use, ticked, **without user names or passwords**: only the name and an id go into the catalog. Without a slot, each member is asked for that connection's sign-in separately.
4. **Review.**
   - Connections MacVPN refuses to publish are listed; fix them first. Refused are an OpenVPN config with an inline `<auth-user-pass>` or `<http-proxy-user-pass>` block, a strongSwan config with a `secrets` section (a catalog never carries a user's password; use a slot instead), and a config with errors.
   - Personal fields are listed: an SSTP `user=` line (replaced at each member's connect by the slot's user name), an OpenVPN inline `<key>` or `<pkcs12>`, and a WireGuard `PrivateKey`. A WireGuard private key needs the tick **Everyone with this catalog uses the same WireGuard key**: everyone then appears to the server as the same peer. The account name of L2TP / Cisco connections is never published.
5. **Name and file.** A name for a new catalog, and where to save `<name>.macvpncatalog`. **MacVPN does not upload anything: put the file on your web server or share.**
6. **Done.** Version N is written. The version goes up by one at every publish. For a new catalog, the **team key is shown once**: **Copy** it, keep it safe, click **I Saved It** and type the group the window asks for. Then **Copy Subscription String…** (see [16.9](#169-for-administrators-the-team-key-and-the-subscription-string)).

**Where to put the file.** Publish to the same place every time, so the members' source stays valid.
- **Web server:** serve the file over `https://` with a certificate macOS trusts. `ETag` or `Last-Modified` headers let MacVPN skip unchanged downloads. An access token (`Authorization: Bearer …`) is optional; members enter it in **Add team catalog…**.
- **File share (SMB, NFS):** members mount the share and choose the file. Replace the file as a whole (MacVPN writes it that way when you save it there directly).
- **Synced folder (iCloud Drive, OneDrive, Dropbox):** members choose the file in their synced folder. An online-only file is downloaded when MacVPN reads it. A sync conflict that brings back an older copy triggers the members' rollback warning; publish again to fix it.

The file is written readable by others (`644`), because it is meant to be served; it is signed and encrypted.

**After publishing.** The connections you published stay normal, editable connections on your Mac. They show **Published in “Acme VPN” (v12)**, and **changed since the last publish** once you edit them. **Publishing** lists each publication with its version, last publish time, file and the number of changed connections, with **Publish New Version…** (the wizard with the saved selection), **Rotate Team Key…**, **Copy Subscription String…** and **Forget…**. A rotation needs a reviewed publish first: while connections changed since the last publish, MacVPN offers **Publish New Version…** in its place.

### 16.9 For administrators: the team key and the subscription string

- The **team key** is 256 random bits, made at the first publish of a catalog. It is **shown once**. MacVPN keeps it in your vault to publish later versions, but never shows it again.
- **Copy Subscription String…** asks for your **master password** and for the source your team will use (the URL, or the path as it looks on the members' Macs). It puts the `macvpn-sub:…` string on the clipboard without showing it. The string contains the team key: send it only through a secure channel (a shared vault of your password manager, an end-to-end encrypted messenger), never by plain e-mail. Tell members the fingerprint separately, ideally by voice, so they can compare it. The access token is not in the string.
- **Rotate Team Key…** (to cut off someone who left the team): a new team key is made and published at once as the next version, to the last file location (confirm it in the save panel). The new key is shown once. Send it, or a new subscription string, to the remaining members; they enter it with **Change team key…**. **Rotating the team key is the only way to revoke access to a catalog someone already has.** The person who left keeps what they already downloaded, including any team secrets in it: change those secrets (for example the PSK on the server) and their server-side account too.

### 16.10 Changing the admin key, and compromise

- **Switching to the backup key** ([16.7](#167-for-administrators-the-admin-key)) is a planned key change. **It is not recovery from a compromise:** whoever holds a leaked admin key can announce their own successor and sign new versions that your members accept.
- **If the admin key may have leaked** (a stolen Mac without the vault locked, a leaked backup with its password, an exported key file with its password):
  1. Generate a new admin key on a Mac you trust, and publish the connections as a **new catalog** (a new name, so a new catalog id and a new team key).
  2. Remove the old catalog file from the web server or share, so nobody can publish to the old subscription there.
  3. Send every member the new subscription string and the new fingerprint through a trusted channel. They **Unsubscribe…** from the old catalog and subscribe to the new one.
  4. Change any team secrets that were in the old catalog.
  Until members unsubscribe, whoever holds the old key can sign versions for them, if they can also write the file at the source. Even then the connections still pass MacVPN's checks and every risky setting needs each member's own tick.
- **If only the team key leaked:** rotate it ([16.9](#169-for-administrators-the-team-key-and-the-subscription-string)).

### 16.11 Security model

- **Signature (admin key, Ed25519).** Every catalog is signed. MacVPN checks the signature first, against the publisher key you pinned with the fingerprint, before it decrypts or uses anything.
  - *Protects against:* changes by anyone without the admin key, including people who have the team key and people who can write the web server or the share.
  - *Does not protect against:* a leaked admin key, or an administrator who publishes something bad. Trust your administrator as you would trust a config file they send you.
- **Encryption (team key, XChaCha20-Poly1305).** The contents (connections, configs, folders, slot names, team secrets) are encrypted with the team key. The key is random, not a password, so it cannot be guessed.
  - *Protects against:* reading the catalog from a leaked file, a web server log or a share, without the team key.
  - *Does not protect against:* anyone who has the team key, including a former member until you rotate it. They can read everything in the catalog, including the team secrets you ticked. The catalog's id, name, version, creation date, publisher key and successor public key are in the unencrypted header, and the file size is visible.
- **Rollback protection (version number).** Each subscription remembers the last applied version. A lower version is refused with a warning; the same version is ignored.
  - *Protects against:* someone putting back an older signed version, for example one with a server you removed or a team secret you replaced.
  - *Does not protect against:* a source that simply stops showing new versions; the status shows the last successful refresh, so a member can notice it. A subscription string can name the catalog and its lowest acceptable version, so the first download is bound too.
- **Checks like an import.** Every config in a catalog goes through the same validators as an import, and risky settings need each member's own tick. A catalog cannot carry a user's password, and nothing changes in the root layer.
- **Your secrets.** The team key and the access token are kept in the vault, and in a full backup (sealed with its password, see [14](#14-backup-and-restore)); they are never logged. The subscription string is never stored or shown: **Copy Subscription String…** puts it on the clipboard, marked so that clipboard managers skip it and Universal Clipboard does not send it to your other devices, and clears it after 60 seconds, at **Lock Now** and at quit (unless you copied something else meanwhile). The team key's **Copy** works the same way. The access token goes to `curl` on its standard input, never on its command line, and never to another host. Your own user names and passwords never leave your vault.
- **Paired apps.** Removing a catalog connection or unsubscribing removes it from every paired app's allowed connections, so subscribing again later never gives an app access silently.
