# MacVPN – How-to

[Magyar változat](how-to.hu.md)

Short step-by-step instructions for MacVPN 1.0. The [user guide](user-guide.en.md) has the details; the links below point to its chapters.

## Contents

1. [Install MacVPN from the DMG](#1-install-macvpn-from-the-dmg)
2. [Finish the setup](#2-finish-the-setup)
3. [Add a connection](#3-add-a-connection)
4. [Connect and disconnect](#4-connect-and-disconnect)
5. [Answer a code or sign-in prompt (MFA)](#5-answer-a-code-or-sign-in-prompt-mfa)
6. [Pin and reorder connections](#6-pin-and-reorder-connections)
7. [View and save a log for troubleshooting](#7-view-and-save-a-log-for-troubleshooting)
8. [Export and back up](#8-export-and-back-up)
9. [Update MacVPN](#9-update-macvpn)
10. [Start MacVPN at login](#10-start-macvpn-at-login)
11. [Uninstall MacVPN](#11-uninstall-macvpn)
12. [Troubleshooting FAQ](#12-troubleshooting-faq)

---

## 1. Install MacVPN from the DMG

You need macOS 14 or later and an administrator account.

1. Download the latest `MacVPN-x.y.z.dmg` from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Open the DMG and drag **MacVPN** onto **Applications**. Eject the DMG.
3. Open MacVPN for the first time. It is ad-hoc signed (not with an Apple Developer ID), so Gatekeeper blocks a normal double-click:
   - **macOS 14:** in Applications, Control-click (right-click) **MacVPN**, choose **Open**, then click **Open**.
   - **macOS 15 or later:** double-click MacVPN, close the warning, then go to **System Settings → Privacy & Security**, click **Open Anyway**, enter your password and click **Open Anyway** again.
4. A shield appears in the menu bar. MacVPN has no Dock icon.

Details: [user guide, 1](user-guide.en.md#1-installation).

## 2. Finish the setup

The **System Status** window opens by itself when something is missing (later: menu → **System Status**). L2TP and Cisco IPsec work without these steps.

1. **Homebrew:** if it is red, click **Install…**. Terminal opens with the official installer; follow it, then click **Check Again**.
2. **VPN tools:** click **Install**. The `brew install` output appears in the window. You can close the window meanwhile; it keeps going.
3. **Permissions (root scripts + sudoers):** click **Authorize** and enter your admin password once. This installs the `mvpn` root binary and the sudoers rule, so connecting needs no password later.
4. When all three rows are green, you are done.

Details: [user guide, 2](user-guide.en.md#2-first-launch-and-the-system-status-window).

## 3. Add a connection

Open the menu → **New Connection / Import…** (or **Manage Connections…**). This opens the **Connections** window.

**To import files:** click **New** (+) → **Import from File…** and select one or more files, or drag the files into the window. Then select the new connection, fill in the password fields and click **Save** (⌘S).

**To create one by hand:** click **New** (+) and pick the type. Fill in the template or form and click **Save**.

| Type | Import | Create | What to fill in |
|---|---|---|---|
| OpenVPN | `.ovpn` file; keep the files it refers to (`ca.crt`, `client.key`, `.p12`, …) in the same folder | **New → OpenVPN** | **Username**, **Password**; **Private key password** if the key is encrypted. If the import asks **Use the credentials from … for this connection?**, choose **Use** to take them from the file. If a yellow **Risky settings** panel appears, read it and tick **I acknowledge these settings and the security risks** before saving. |
| WireGuard | `.conf` file | **New → WireGuard** (template) | Nothing extra: the keys are in the config. |
| IKEv2 (strongSwan) | `swanctl.conf` file | **New → IKEv2** (template) | **Username** (the same as `eap_id`) and **Password**, or **Pre-shared key (PSK)**. |
| SSTP | `.sstp` file | **New → SSTP** (form) | **Server**, **Port**, **Username**, **Password**, **Server certificate**. |
| L2TP / Cisco IPsec | not possible (a `.mobileconfig` cannot be imported) | **New → L2TP** or **New → Cisco IPsec** (form) | **Server**, **Account name**, **Password**, **Pre-shared key (PSK)**, for Cisco **Group name**. Click **Save and Install Profile**, then approve the profile in **System Settings → General → Device Management**. |

**VPNs already set up in macOS** appear in the list by themselves, marked **System VPN**. You can start and stop them. For an L2TP or Cisco IPsec system VPN that does not connect from MacVPN, enter its **Shared secret (PSK)** (and, if needed, the password) in its detail view and click **Save**.

Details: [user guide, 3](user-guide.en.md#3-adding-connections-by-type) and [4](user-guide.en.md#4-import-and-export).

## 4. Connect and disconnect

1. Click the shield in the menu bar.
2. Click the switch next to the connection. A spinner shows while it connects; a green dot, the IP address and the elapsed time show when it is up.
3. Click the switch again to disconnect.

You can also use **Connect** / **Disconnect** in the Connections window. Several connections can be active at once. A red dot means an error; the short reason is next to it, and a notification tells you too.

When you quit with active connections, MacVPN asks: **Disconnect and Quit**, **Quit, Keep Them Running** or **Cancel**.

## 5. Answer a code or sign-in prompt (MFA)

- **Code from the server** (OpenVPN challenge, or a static challenge in the config): a small window opens with a **Code** field. It does not take the keyboard away from your current app: click the window (or the "…: authentication needed" notification), type the code and click **Continue**. You have 2 minutes.
- **Sign-in in the browser** (SAML, SSO, push): the window shows the address. If you started this connection and trust the address, click **Open in Browser**, then sign in or approve the push on your phone. You have up to 5 minutes.
- **Code appended to the password** (some RADIUS / LDAP servers): open the connection in the Connections window, tick **Ask for a one-time code at connect and append it to the password**, choose the **Separator** (**None**, `,` or `:`) and save. MacVPN then asks for the code at every connect. This also works for L2TP / Cisco IPsec system VPNs.

While MacVPN waits, the menu bar icon is a key and the row says **Waiting for authentication**. **Cancel** stops the connection attempt.

Details: [user guide, 5.2](user-guide.en.md#52-multi-factor-authentication-mfa).

## 6. Pin and reorder connections

1. Open the **Connections** window (menu → **Manage Connections…**).
2. Right-click a connection and choose **Pin to Top**. It moves to the **Pinned** section, in the menu too.
3. Drag pinned connections up or down to change their order.
4. To remove one from the top, right-click it and choose **Unpin**.

The other connections are ordered by use: each successful connect from MacVPN counts, and the count halves every 14 days. Details: [user guide, 5.1](user-guide.en.md#51-order-of-connections).

## 7. View and save a log for troubleshooting

1. Connect in debug mode: **Option-click** the switch in the menu, or click **Connect in Debug Mode** in the Connections window. The **Log** tab opens and follows the attempt live.
2. Use the filter (**All**, **Commands**, **Errors**) and **Search** to find the problem. Match the message with the [troubleshooting chapter](user-guide.en.md#7-troubleshooting-from-the-log).
3. To send the log to your network administrator, click **Save…** (or **Copy**). Passwords, PSKs and keys are never in the log. An SSTP debug log contains the MS-CHAPv2 exchange, so share it only with your administrator.

L2TP and Cisco IPsec only have a log in debug mode.

## 8. Export and back up

1. In the Connections window, select the connection and click the export icon (**Export… (passwords are never included)**).
2. If the config contains private keys or credentials, choose **Export Without Keys** (safer) or **Export With Keys** (only if the recipient needs them).
3. Choose where to save the file. It is readable only by you.

Exports never contain passwords or PSKs. To back up, export every connection and keep the passwords somewhere safe (for example in a password manager). `.ovpn`, WireGuard `.conf`, `.swanctl.conf` and `.sstp` files can be imported again; an L2TP / Cisco `.mobileconfig` export is installed on another Mac by double-clicking it in Finder.

Your connections live in `~/Library/Application Support/MacVPN`, and their passwords in the Keychain. Copying the folder alone does not copy the passwords.

## 9. Update MacVPN

1. When a new version is out, the menu shows **Update available: vX.Y.Z**. (Or choose **Check for Updates Now**.)
2. Click it, read the notes, then click **Download and Install**.
3. Answer the questions about unsaved changes and active connections. MacVPN checks the signature, replaces itself and restarts.
4. If macOS asks whether MacVPN may use its Keychain items, click **Always Allow**, but only if the prompt names MacVPN at `/Applications/MacVPN.app`.
5. If **System Status** opens with **Update required**, click **Authorize** and enter your admin password.

Coming from 0.x? Read [Upgrading from 0.x](user-guide.en.md#81-upgrading-from-0x) first. Details: [user guide, 8](user-guide.en.md#8-updates).

## 10. Start MacVPN at login

1. Make sure MacVPN runs from the Applications folder.
2. Open the menu and tick **Launch at Login** (also in the System Status window).
3. If a note asks you to approve it, click **Open Login Items Settings…** and turn MacVPN on there.

If the note says **Enabled via a login LaunchAgent (applies at next login).**, it starts from your next login. Untick the box to turn it off. Details: [user guide, 2.1](user-guide.en.md#21-launch-at-login).

## 11. Uninstall MacVPN

1. Open **System Status** and click **Uninstall MacVPN…**.
2. To delete your connections and their passwords too, tick **Also delete user data (connections and Keychain passwords)**.
3. Click **Uninstall** and enter your admin password. Active connections are disconnected first.
4. Click **Quit MacVPN**, then drag `MacVPN.app` to the Trash.
5. Optionally remove the Homebrew packages (`brew uninstall openvpn wireguard-tools strongswan sstp-client`) and any L2TP / Cisco profiles in **System Settings → General → Device Management**.

Details: [user guide, 9](user-guide.en.md#9-uninstalling).

## 12. Troubleshooting FAQ

**A connection is grey and says "Missing tool".**
A Homebrew tool for that type is missing, or the root layer is not installed or outdated. Open **System Status**, install what is red, and click **Authorize** if the permissions row asks for it.

**The menu shows "Cannot query the status: …".**
The root layer or the sudoers rule is missing or outdated. Open **System Status** and click **Authorize**.

**OpenVPN says "Authentication failed (AUTH_FAILED)".**
Check **Username** and **Password** and save. If the server wants a one-time code, see [section 5](#5-answer-a-code-or-sign-in-prompt-mfa). [More](user-guide.en.md#71-auth_failed-openvpn)

**The connection times out after 30 seconds.**
Check your network and the server address, then connect in debug mode and read the last lines of the log. [More](user-guide.en.md#73-timeout)

**Saving fails with "Forbidden directive" or "Risky directive, acknowledgement required".**
Forbidden lines (such as `up`, `down`, `script-security 2`) must be deleted or commented out. Risky ones need the checkbox under **Risky settings**. [More](user-guide.en.md#77-directive-not-allowed--forbidden-directive)

**WireGuard is green but no traffic flows.**
Usually a wrong `Endpoint`, `PublicKey` or `AllowedIPs`, or the network blocks UDP. [More](user-guide.en.md#74-no-wireguard-handshake)

**L2TP / Cisco: "The profile is not installed".**
Approve the profile in **System Settings → General → Device Management**, again after every change. [More](user-guide.en.md#76-profile-not-approved-l2tp--cisco)

**An L2TP system VPN works from System Settings but not from MacVPN.**
Enter its **Shared secret (PSK)** in MacVPN → Connections → the VPN, and save. [More](user-guide.en.md#35-system-vpns-shared-secret-for-l2tp--cisco)

**SSTP: "Server certificate error".**
For a company CA, choose **Custom CA file** and load the CA in PEM format; use the host name, not the IP address. [More](user-guide.en.md#79-sstp-certificate-error)

**The code window expired ("Authentication was not completed in time").**
Connect again and enter the code within 2 minutes (5 minutes for a browser sign-in). [More](user-guide.en.md#711-one-time-code-and-sign-in-in-the-browser-mfa)

**macOS asks for Keychain access after an update.**
This is expected once per update, because MacVPN is ad-hoc signed. Allow it only if the prompt names MacVPN at `/Applications/MacVPN.app`.

**"Installation cancelled: /usr/local/libexec is not owned by root…" when clicking Authorize.**
Fix the folder's owner in Terminal as the message says, then click **Authorize** again. [More](user-guide.en.md#78-other)

**The update says the app's location is not writable.**
Move MacVPN to the Applications folder and try again, or install the new DMG by hand.
