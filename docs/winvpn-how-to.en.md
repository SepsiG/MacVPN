# WinVPN – How-to

[Magyar változat](winvpn-how-to.hu.md)

Short step-by-step instructions for WinVPN 2.0 on Windows 10 and 11. The [WinVPN user guide](winvpn-user-guide.en.md) has the details; the links below point to its chapters. (MacVPN on a Mac: [MacVPN How-to](how-to.en.md).)

## Contents

1. [Install WinVPN from the MSI](#1-install-winvpn-from-the-msi)
2. [Finish the setup](#2-finish-the-setup)
3. [Add a connection](#3-add-a-connection)
4. [Connect and disconnect](#4-connect-and-disconnect)
5. [Answer a code or sign-in prompt (MFA)](#5-answer-a-code-or-sign-in-prompt-mfa)
6. [Pin and reorder connections](#6-pin-and-reorder-connections)
7. [View and save a log for troubleshooting](#7-view-and-save-a-log-for-troubleshooting)
8. [Export and back up](#8-export-and-back-up)
9. [Update WinVPN](#9-update-winvpn)
10. [Start WinVPN at login](#10-start-winvpn-at-login)
11. [Uninstall WinVPN](#11-uninstall-winvpn)
12. [Troubleshooting FAQ](#12-troubleshooting-faq)
13. [Upgrade from the 1.5 preview](#13-upgrade-from-the-15-preview)
14. [Set up, lock and unlock the vault](#14-set-up-lock-and-unlock-the-vault)
15. [Organize connections in folders](#15-organize-connections-in-folders)
16. [Share one sign-in between connections](#16-share-one-sign-in-between-connections)
17. [Back up everything and restore](#17-back-up-everything-and-restore)
18. [Subscribe to a team catalog](#18-subscribe-to-a-team-catalog)
19. [Share connections with your team (publish a catalog)](#19-share-connections-with-your-team-publish-a-catalog)
20. [Remove a team member's access (rotate the team key)](#20-remove-a-team-members-access-rotate-the-team-key)
21. [Move the admin key to a new PC](#21-move-the-admin-key-to-a-new-pc)
22. [Use a VPN you set up in Windows](#22-use-a-vpn-you-set-up-in-windows)
23. [Use a Cisco IPsec connection from a Mac](#23-use-a-cisco-ipsec-connection-from-a-mac)
24. [Test with the VPN lab (testers)](#24-test-with-the-vpn-lab-testers)
25. [Choose the appearance and the connection notifications](#25-choose-the-appearance-and-the-connection-notifications)
26. [Reconnect automatically after sleep](#26-reconnect-automatically-after-sleep)
27. [Connect to a UniFi, pfSense or OPNsense VPN](#27-connect-to-a-unifi-pfsense-or-opnsense-vpn)

---

## 1. Install WinVPN from the MSI

You need Windows 10 or 11 and an administrator to install.

1. Download `WinVPN-x.y.z-x64.msi` (most PCs) or `WinVPN-x.y.z-arm64.msi` (ARM PCs) from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Double-click it. SmartScreen may warn (**Windows protected your PC**): click **More info** → **Run anyway**. An administrator confirms the prompt.
3. Start **WinVPN** from the Start menu. A shield appears in the notification area, and the **Set Up the Vault** window opens: choose a master password and save the recovery key ([section 14](#14-set-up-lock-and-unlock-the-vault)).

The installer also adds the **WinVPN Service**, which connects OpenVPN and WireGuard. Details: [user guide, 1](winvpn-user-guide.en.md#1-installation).

## 2. Finish the setup

The **System Status** window opens by itself when something is missing (later: popover → **System Status**). OpenVPN Community not being installed does not count: it is optional.

1. **WinVPN Service** and **WireGuard** should be green right after the install.
2. **OpenVPN Community** (only if you use OpenVPN): click **Install**, let an administrator confirm (on Windows 11 winget asks once, then WinVPN once more). The output appears under the row.
3. **Windows VPN client** (L2TP/IPsec, IKEv2, SSTP) is built into Windows and should be green.
4. When the rows are green, you are done.

Details: [user guide, 2](winvpn-user-guide.en.md#2-first-launch-and-the-system-status-window).

## 3. Add a connection

Open the popover → **New Connection / Import…** (or **Manage Connections…**). This opens the **Connections** window.

- **From a file:** **New (+)** → **Import from File…**, or drag `.ovpn`, `.conf`, `.sstp` or strongSwan files onto the list. Keep files the `.ovpn` refers to (`ca.crt`, …) next to it. Double-clicking a `.ovpn` or `.sstp` in File Explorer imports it too.
- **By hand:** **New (+)** → OpenVPN, WireGuard, IKEv2, SSTP or L2TP. Fill in the template or the form and click **Save** (Ctrl+S).
- **L2TP/IPsec:** server, account name, password and PSK; **Save** writes its Windows VPN entry at once, nothing to approve.
- **IKEv2:** use EAP-MSCHAPv2 (user name and password) or a computer certificate; Windows does not support IKEv2 with a pre-shared key. The grey line under the editor shows what Windows will use.
- **SSTP with a company CA:** choose **Custom CA file**, then **Trust This CA in Windows…** (an administrator confirms once).

A greyed connection shows why Windows cannot run it. **New** offers only the types that can be used here (never Cisco IPsec). Details: [user guide, 3](winvpn-user-guide.en.md#3-adding-connections-by-type).

## 4. Connect and disconnect

- **Popover:** click the switch on the connection's card. Green = connected, amber = connecting or waiting for you, red = error.
- **Connections window:** **Connect** / **Disconnect**.
- If WinVPN asks for a user name, password or PSK (**Credentials needed**), enter it; **Save in vault** keeps it for next time.
- When you quit WinVPN with connections up, choose **Disconnect and Quit** or **Quit, Keep Them Running**. Signing out of Windows always ends your connections.

Details: [user guide, 5](winvpn-user-guide.en.md#5-connecting).

## 5. Answer a code or sign-in prompt (MFA)

1. When the server asks for a code, a small window appears (and a notification "…: authentication needed"). Click it, type the code, click **Continue**, within 2 minutes.
2. For a sign-in in the browser, click **Open in Browser**, sign in or approve the push, and come back; WinVPN waits up to 5 minutes.
3. If your server wants the code after the password: in the connection's settings turn on **Ask for a one-time code at connect and append it to the password** and pick the **Separator**.

Details: [user guide, 5.2](winvpn-user-guide.en.md#52-multi-factor-authentication-mfa).

## 6. Pin and reorder connections

Right-click a connection in the **Connections** window → **Pin to Top**. Drag a pinned connection onto another pinned one to reorder. The others are sorted by use. Details: [user guide, 5.1](winvpn-user-guide.en.md#51-order-of-connections).

## 7. View and save a log for troubleshooting

1. Alt-click the switch in the popover (or **Connect in Debug Mode** in the Connections window). The **Log** tab opens and follows live.
2. Filter with **Errors**, search, then **Save…** (`<name>-log.txt`). Passwords, PSKs and codes are never in it, so you can send it to your network administrator.

Details: [user guide, 6](winvpn-user-guide.en.md#6-debug-mode-and-the-log) and [7](winvpn-user-guide.en.md#7-troubleshooting-from-the-log).

## 8. Export and back up

- **One connection:** the export icon in its header. Passwords are never exported; for private keys you choose **Export Without Keys** or **Export With Keys**. An L2TP connection exports as a macOS `.mobileconfig`.
- **Everything:** see [section 17](#17-back-up-everything-and-restore).

Details: [user guide, 4](winvpn-user-guide.en.md#4-import-and-export).

## 9. Update WinVPN

1. When the popover shows **Update available: vX.Y.Z**, click it, read the notes, click **Download and Install**.
2. Answer the quit questions, then let an administrator confirm. WinVPN updates and starts again by itself.
3. OpenVPN Community and WireGuard are updated separately, without a new WinVPN: WinVPN checks once a day, and **System Status** offers **Update** on their row (**Update available: …**). OpenVPN's update needs an administrator; WireGuard's needs no WireGuard connection up on the PC. The Windows VPN client is updated by Windows Update.

Details: [user guide, 8](winvpn-user-guide.en.md#8-updates) and [2.5](winvpn-user-guide.en.md#25-updating-openvpn-and-wireguard).

## 10. Start WinVPN at login

Popover → **Settings** → **Launch at Login** (or in **System Status**). If Windows turned it off in Settings → Apps → Startup, WinVPN shows **Open Startup Apps Settings…** for that page. Details: [user guide, 2.1](winvpn-user-guide.en.md#21-launch-at-login).

## 11. Uninstall WinVPN

1. **System Status** → **Remove WinVPN from This Account…**. Tick **Also delete user data** only if you want your connections and the vault gone too. Click **Remove**.
2. Quit WinVPN. In **Settings → Apps → Installed apps** (opened for you), uninstall **WinVPN**; an administrator confirms.
3. OpenVPN Community stays: uninstall it there too if you no longer need it.

Details: [user guide, 9](winvpn-user-guide.en.md#9-uninstalling).

## 12. Troubleshooting FAQ

**A connection is grey and says "Not installed: OpenVPN Community – System Status".**
Click **System Status** in that line and **Install**. OpenVPN Community is optional, so a missing one does not open System Status by itself. [More](winvpn-user-guide.en.md#24-missing-vpn-engines)

**OpenVPN and WireGuard say "The WinVPN Service is not reachable".**
An administrator starts it with `sc.exe start WinVPN`, or repairs WinVPN in Installed apps. L2TP, IKEv2 and SSTP keep working meanwhile. [More](winvpn-user-guide.en.md#78-the-winvpn-service-and-other-messages)

**OpenVPN says "Authentication failed (AUTH_FAILED)".**
Check **Username** and **Password** and save. If the server wants a one-time code, see [section 5](#5-answer-a-code-or-sign-in-prompt-mfa). [More](winvpn-user-guide.en.md#71-auth_failed-openvpn)

**An OpenVPN config with `cryptoapicert` or `windows-driver` cannot be saved.**
These are forbidden on Windows: put the certificate and key into the config (or a PKCS#12 file); WinVPN picks the driver itself. [More](winvpn-user-guide.en.md#31-openvpn)

**L2TP/IPsec: "The server did not answer on the VPN ports … Allow L2TP Behind NAT…".**
The server is behind NAT. Click **Allow L2TP Behind NAT…**, let an administrator confirm, restart Windows. [More](winvpn-user-guide.en.md#37-administrator-steps-for-native-vpns)

**IKEv2 is grey: "Not supported on Windows: local auth = psk".**
Windows' IKEv2 client cannot use a pre-shared key. Ask for EAP access, or use L2TP/IPsec with the PSK. [More](winvpn-user-guide.en.md#33-ikev2-strongswan)

**IKEv2: "No computer certificate for IKEv2 was found".**
An administrator imports the `.p12` into the computer's Personal store with `certlm.msc`. [More](winvpn-user-guide.en.md#37-administrator-steps-for-native-vpns)

**SSTP: "The server’s CA is not trusted by Windows".**
Open the connection and click **Trust This CA in Windows…** (an administrator confirms). [More](winvpn-user-guide.en.md#79-sstp-and-ikev2-certificate-errors)

**A Cisco IPsec connection from my Mac is grey.**
Windows has no Cisco IPsec client. See [section 23](#23-use-a-cisco-ipsec-connection-from-a-mac).

**"Windows error … (see the log)".**
Connect in debug mode and look at the `Windows error` line; the table in the guide explains the common codes. [More](winvpn-user-guide.en.md#76-windows-vpn-client-errors-l2tp-ikev2-sstp)

**WireGuard is green but no traffic flows.**
Usually a wrong `Endpoint`, `PublicKey` or `AllowedIPs`, or the network blocks UDP. [More](winvpn-user-guide.en.md#74-no-wireguard-handshake)

**The code window expired ("Authentication was not completed in time").**
Connect again and enter the code within 2 minutes (5 minutes for a browser sign-in). [More](winvpn-user-guide.en.md#711-one-time-code-and-sign-in-in-the-browser-mfa)

**I forgot the master password.**
In the **Unlock WinVPN** window click **Use recovery key**, type the recovery key and a new master password, then **Reset and Unlock**. [More](winvpn-user-guide.en.md#118-forgotten-master-password)

**The popover only shows "Unlock…".**
The vault is locked; running VPNs are still up. Click **Unlock…** and enter the master password. [More](winvpn-user-guide.en.md#115-the-locked-popover)

**The backup cannot be opened.**
The backup password is wrong, or the file is damaged; WinVPN does not tell which. [More](winvpn-user-guide.en.md#14-backup-and-restore)

## 13. Upgrade from the 1.5 preview

1. An administrator installs the 2.0 MSI over the preview (double-click). Your vault and connections stay.
2. Open **System Status** and install OpenVPN Community if you use OpenVPN.
3. Your L2TP connections are ready after you unlock the vault; check greyed connections for their reason.

Details: [user guide, 8.1](winvpn-user-guide.en.md#81-upgrading-from-the-15-preview).

## 14. Set up, lock and unlock the vault

1. At the first launch: **Continue**, choose a master password (twice), keep **Unlock automatically** ticked if you like, **Create Vault**.
2. Save the recovery key (shown only now), **I Saved It**, type the group asked for, **Confirm**, **Done**.
3. To lock: **Lock Now** in the popover (shown when **Unlock automatically** is off, or with **Show “Lock Now”**). To unlock: **Unlock…** and the master password.

Details: [user guide, 11](winvpn-user-guide.en.md#11-vault).

## 15. Organize connections in folders

**New (+)** → **New Folder**, type the name, Enter. Drag connections onto the folder. Right-click for **Colour…**, **Rename**, **Delete…**. Details: [user guide, 12](winvpn-user-guide.en.md#12-folders-and-colours).

## 16. Share one sign-in between connections

**Connections** window → **Credentials** → **Add Credential…** (or **Create from Connection…**). In each editor choose it under **Password from**. Details: [user guide, 13](winvpn-user-guide.en.md#13-shared-credentials).

## 17. Back up everything and restore

1. Popover → **Settings** → **Back Up Everything…**: a backup password (twice) and your master password, **Back Up…**, choose where to save.
2. On a new PC (or after reinstalling Windows): in **Set Up the Vault** click **Restore from backup…**, choose the file, enter its password. A MacVPN backup works too.
3. Into an existing vault: **Settings** → **Restore from Backup…**, then **Merge** or **Replace everything**.

L2TP connections get their Windows VPN entries at once. Details: [user guide, 14](winvpn-user-guide.en.md#14-backup-and-restore).

## 18. Subscribe to a team catalog

1. **Connections** window → **Team catalogs** → **Add team catalog…**.
2. Paste the subscription string (or enter the source: an `https://` URL or a file, the team key and the publisher fingerprint; for HTTPS maybe an access token).
3. **Check**, compare the fingerprint with your administrator by phone, tick the box, **Subscribe**.

Details: [user guide, 16.1](winvpn-user-guide.en.md#161-subscribing-to-a-catalog).

## 19. Share connections with your team (publish a catalog)

1. **Publishing** → **Generate Admin Key** (and a backup admin key, exported to a file kept offline).
2. **Publish Catalog…**: tick connections, team secrets and credential slots, save `<name>.macvpncatalog`, and save the team key shown once.
3. Put the file on your web server or share, and send each member **Copy Subscription String…** through a secure channel; tell them the fingerprint separately.

Details: [user guide, 16.7](winvpn-user-guide.en.md#167-for-administrators-the-admin-key) and [16.8](winvpn-user-guide.en.md#168-for-administrators-publishing-a-catalog).

## 20. Remove a team member's access (rotate the team key)

**Publishing** → the catalog → **Rotate Team Key…**, upload the new file, and send the remaining members the new key. Details: [user guide, 16.9](winvpn-user-guide.en.md#169-for-administrators-the-team-key-and-the-subscription-string).

## 21. Move the admin key to a new PC

1. Restore a full backup on the new PC (it brings your publications).
2. **Publishing** → **Import Admin Key…** with the `.macvpnadminkey` file and its password, then **Switch to the Backup Key…** if you are switching keys.
3. Publish a new version of each catalog.

Details: [user guide, 16.7](winvpn-user-guide.en.md#167-for-administrators-the-admin-key).

## 22. Use a VPN you set up in Windows

1. Add the VPN in **Settings → Network & internet → VPN** as usual. It appears in WinVPN within seconds as **System VPN**.
2. Connect it from the popover. Windows' own saved password is used, or Windows' sign-in window opens.
3. For an L2TP VPN you can store the password and the PSK in WinVPN (its detail in the Connections window).

WinVPN never changes or deletes it. Details: [user guide, 3.5](winvpn-user-guide.en.md#35-system-vpns-your-own-windows-vpns).

## 23. Use a Cisco IPsec connection from a Mac

Windows cannot connect Cisco IPsec (IKEv1 with XAUTH).

1. Ask your VPN administrator whether the server offers L2TP/IPsec (with the same PSK) or IKEv2.
2. For L2TP/IPsec: open the Cisco connection and click **Make an L2TP/IPsec Copy**. The copy "<name> (L2TP)" has the same server, account, password and PSK. Connect it.
3. For IKEv2: create an IKEv2 connection with the details your administrator gives.

The Cisco connection stays and keeps working on your Mac. Details: [user guide, 3.4](winvpn-user-guide.en.md#34-l2tpipsec-and-cisco-ipsec).

## 24. Test with the VPN lab (testers)

The repository has a throwaway VPN lab for testing both apps: `scripts/vpn-lab/` (its [README](../scripts/vpn-lab/README.md) is the manual). It runs every server kind (OpenVPN, WireGuard, L2TP/IPsec, IKEv2 with EAP / PSK / certificate, Cisco IPsec, SSTP) in Docker on a Mac or a Linux machine of the LAN, with generated credentials and a lab CA.

1. On the lab machine: `scripts/vpn-lab/up.sh --bind <its LAN address>`, then `scripts/vpn-lab/check.sh --selftest` (every line `ok`).
2. Copy the client profiles of `scripts/vpn-lab/.state/client/windows` (or `macos`) to the test PC; the passwords, the PSK and the codes are in `scripts/vpn-lab/.state/client/CREDENTIALS.txt` (do not copy that file around).
3. Import the profiles into WinVPN, connect, and open `http://10.99.0.10/` (the lab's test page says which server you came through). The lab is behind Docker's NAT, so Windows L2TP/IPsec needs **Allow L2TP Behind NAT…** once, and SSTP/IKEv2 need the lab CA trusted (**Trust This CA in Windows…**).
4. Afterwards remove the lab CA and certificate (`certlm.msc`) and stop the lab: `scripts/vpn-lab/down.sh`.

## 25. Choose the appearance and the connection notifications

**Appearance:** popover → **Settings** → **Appearance**: **Match System** (the default, follows Windows' app mode), **Light** or **Dark**. It applies at once to the popover and every window.

**Connection notifications:** WinVPN tells you when a connection connects, drops, is reconnected or fails, with a short reason in plain words. The notification names only the connection; click it to open the connection's **Log** tab. To turn them off: popover → **Settings** → switch off **Connection Notifications**. Code and credential requests still notify you. Windows' own switch is in Settings → System → Notifications → **WinVPN**.

Details: [user guide, 2.2](winvpn-user-guide.en.md#22-appearance) and [2.3](winvpn-user-guide.en.md#23-notifications).

## 26. Reconnect automatically after sleep

A connection that went down because the PC slept or the network went away comes back by itself, but only when both hold:

1. **None of the VPN's own networks or DNS servers is directly reachable** on the network you are on (for example you are in the office the VPN leads to). This is checked first.
2. **You are on the same network** as when the connection came up (the same router; WinVPN does not reconnect on a network it cannot identify).

WinVPN tries up to 3 times and tells you the result (**… reconnected**, **… not reconnected** with the reason, or **… could not reconnect**). A connection you disconnected yourself (also by quitting WinVPN or signing out) is never reconnected. A tunnel that stayed up through the sleep is disconnected when its network is directly reachable on the new network.

**To turn it off for one connection:** **Connections** window → the connection → switch off **Reconnect Automatically** (system VPNs do not have it).

Details: [user guide, 5.5](winvpn-user-guide.en.md#55-reconnect-automatically).

## 27. Connect to a UniFi, pfSense or OPNsense VPN

These gateways and firewalls make client files that WinVPN imports as they are. The console steps are the same as for MacVPN: [MacVPN How-to, 24](how-to.en.md#24-connect-to-a-unifi-pfsense-or-opnsense-vpn) (with the sources). What is different on Windows:

**Ubiquiti UniFi (UniFi OS gateways)**

- **WireGuard** (recommended): **Settings → VPN → VPN Server → WireGuard → Add Client → Download**, then **New (+) → Import from File…** → the `.conf`. The QR code is for phones; WinVPN cannot read it. `AllowedIPs` with `0.0.0.0/0` = all traffic; replace it with the office networks for a split tunnel. Add `PersistentKeepalive = 25` under `[Peer]` if the file has none, so WinVPN notices a dead tunnel even while it is idle.
- **OpenVPN:** install **OpenVPN Community** in System Status first. Import the `.ovpn` UniFi downloads, fill in **Username** / **Password**. UniFi's file uses `cipher AES-256-CBC` (older ones `comp-lzo` too), so WinVPN runs it on the **TAP-Windows6** driver; it works, but only one TAP-Windows6 connection can be up at a time ([user guide, 7.5](winvpn-user-guide.en.md#75-openvpn-drivers-dco-and-tap-windows6)). Delete `user nobody` / `group nogroup` lines if a guide's file has them.
- **L2TP/IPsec** (USG / USG-Pro remote-user VPN): **New → L2TP** with **Server**, **Account name**, **Password** and **Pre-shared key (PSK)**; WinVPN signs in with MS-CHAP v2, which Ubiquiti requires for Windows (turn on **Require Strong Authentication** in the UniFi L2TP server's advanced settings if it offers it). If the gateway is behind another router, Windows needs **Allow L2TP Behind NAT…** once (Ubiquiti's "modify the registry" step; an administrator confirms, then restart Windows). UniFi pushes no routes: keep **Send all traffic over VPN** on, or add routes yourself.
- **Teleport (WiFiman) is not supported:** it goes through Ubiquiti's cloud and has no exportable configuration. Use the WireGuard server.

**pfSense and OPNsense**

- **OpenVPN:** pfSense **VPN → OpenVPN → Client Export → Inline Configurations → Most Clients**; OPNsense **VPN → OpenVPN → Client Export → File Only**. Both import with no error. Leave **Microsoft Certificate Storage** off: `cryptoapicert` is forbidden in WinVPN (the service runs as SYSTEM and would reach the computer's certificate store); the inline export puts the certificate into the file instead. The **Archive** export works when unpacked into one folder (the `.p12` password goes into **Private key password**).
- **Faster driver:** pfSense's default **Fallback Data Encryption Algorithm** is AES-256-CBC, and OPNsense's exports carry the server's fallback cipher too: with a CBC fallback, or with compression, WinVPN uses TAP-Windows6. Set the fallback to **AES-256-GCM** (and compression off) on the server and export again, and WinVPN uses the faster DCO driver.
- **WireGuard:** pfSense has no client export (write the `.conf` from the peer, see the MacVPN section); OPNsense's **VPN → WireGuard → Peer generator** shows one to copy. IPv6, several `AllowedIPs` and DNS search domains work.
- **IPsec (mobile clients) — IKEv2 only, with EAP-MSCHAPv2 or a computer certificate.** Write the `swanctl.conf` as in the MacVPN section; WinVPN translates it. Windows uses one IKE and one ESP combination: the first of your `proposals` / `esp_proposals` it supports (Netgate's recipe works: AES-256-GCM with DH 16 is skipped, AES-256 / SHA-256 / DH 14 is used, ESP AES-256-GCM with PFS 14). Give the firewall's Phase 1 at least one of AES-256 / SHA-256 / DH 14 or AES-GCM / ECP-256, as Windows offers nothing else. `remote_addrs` must be the name in the server certificate, and the CA must be trusted (**Trust This CA in Windows…**).
- **Not on Windows:** IKEv2 with a **pre-shared key** and **EAP-TLS** (the Windows IKEv2 client here signs in with EAP-MSCHAPv2 or the computer certificate), and the IKEv1 **XAuth "Cisco-style"** mobile setup (Windows has no Cisco IPsec client). Ask for EAP-MSCHAPv2 or a computer certificate, see [user guide, 3.3](winvpn-user-guide.en.md#33-ikev2-strongswan).
