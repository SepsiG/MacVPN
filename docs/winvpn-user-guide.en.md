# WinVPN – User Guide

[Magyar változat](winvpn-user-guide.hu.md)

WinVPN is the Windows version of [MacVPN](user-guide.en.md): an app in the notification area of the taskbar for Windows 10 and 11 (x64 or ARM64) that keeps OpenVPN, WireGuard, IKEv2 (strongSwan), SSTP, L2TP/IPsec and Cisco IPsec connections in one place, connects them, and lists the VPNs you set up in Windows itself. Connections and their passwords are kept in an encrypted vault. WinVPN and MacVPN share their code, their vault, backup and team catalog formats, and this guide follows the structure of the MacVPN guide.

- **Short, task-oriented steps** (install, connect, back up, uninstall, …): the [WinVPN How-to](winvpn-how-to.en.md).
- **Everything WinVPN connects, and how:** OpenVPN and WireGuard through the **WinVPN Service** (see [1.3](#13-the-winvpn-service)); L2TP/IPsec, IKEv2 and SSTP through **Windows' own VPN client** (see [1.5](#15-wireguard-and-the-windows-vpn-client)). **Cisco IPsec** connections are kept, but Windows cannot connect them (see [3.4](#34-l2tpipsec-and-cisco-ipsec)).
- Developers who want another program on this PC to bring WinVPN connections up and down (**Paired apps** in the Connections window) should read the [Control API guide](control-api.md#11-windows-winvpn) and the [example client](../examples/macvpn-control-client/README.md#windows).

> **Language:** WinVPN follows the Windows display language and your preferred languages (Settings → Time & language → Language & region). It is available in English and Hungarian. If neither is among your preferred languages, it uses English. This guide uses the English labels; the [Hungarian guide](winvpn-user-guide.hu.md) shows the Hungarian ones.

## What's new in 2.0

2.0 is the first WinVPN that connects. It has every feature of MacVPN 2.0, with the Windows differences this guide names.

- **Connecting.** OpenVPN and WireGuard through the WinVPN Service, which the installer adds; L2TP/IPsec, IKEv2 and SSTP through the VPN client built into Windows, from your own user account, without an administrator for the normal case. See [5](#5-connecting).
- **Your own Windows VPNs** (Settings → Network & internet → VPN) are listed as **system VPNs**, with their live state; WinVPN connects and disconnects them. See [3.5](#35-system-vpns-your-own-windows-vpns).
- **OpenVPN Community** is installed and updated from **System Status** (winget or OpenVPN's official installer); **wireguard-nt** comes with WinVPN and is updated by the WinVPN Service. The engines are updated as soon as they are published, without a new WinVPN. See [1.4](#14-openvpn-community) and [2.5](#25-updating-openvpn-and-wireguard).
- **One-time codes, sign-in in the browser and credential prompts** as in MacVPN. See [5.2](#52-multi-factor-authentication-mfa) and [5.3](#53-credentials-asked-when-connecting).
- **Debug mode and the live log** for every type, also for the Windows VPN client. See [6](#6-debug-mode-and-the-log) and [7](#7-troubleshooting-from-the-log).
- **WinVPN updates itself** from signed releases. See [8](#8-updates).
- **HTTPS team catalogs.** See [16.1](#161-subscribing-to-a-catalog).
- **Remove WinVPN from This Account…** in System Status cleans up before you uninstall. See [9](#9-uninstalling).
- **Appearance**, **connection notifications**, **missing VPN engines**, **reconnect automatically** and **log size limits**: the same as in MacVPN 2.0. See [2.2](#22-appearance), [2.3](#23-notifications), [2.4](#24-missing-vpn-engines), [5.5](#55-reconnect-automatically) and [6](#6-debug-mode-and-the-log).

**Known limits on Windows:**

- **Cisco IPsec cannot connect:** Windows has no client for it. The connections stay (editable, exportable, in backups and catalogs), and **Make an L2TP/IPsec Copy** makes a working L2TP/IPsec connection of the same server. See [3.4](#34-l2tpipsec-and-cisco-ipsec).
- **IKEv2 with a pre-shared key is not supported:** the Windows IKEv2 client signs in only with EAP-MSCHAPv2 or a computer certificate. See [3.3](#33-ikev2-strongswan).
- **L2TP/IPsec to a server behind NAT** needs a one-time administrator step (**Allow L2TP Behind NAT…**, then a restart). See [3.7](#37-administrator-steps-for-native-vpns).
- OpenVPN certificates from the Windows certificate store (`cryptoapicert`) are not supported; WireGuard `FwMark` and `Table` work only as `auto` / `off`. See [3.1](#31-openvpn) and [3.2](#32-wireguard).

## Contents

1. [Installation](#1-installation) ([The WinVPN Service](#13-the-winvpn-service), [OpenVPN Community](#14-openvpn-community), [WireGuard and the Windows VPN client](#15-wireguard-and-the-windows-vpn-client), [Where WinVPN keeps your data](#16-where-winvpn-keeps-your-data))
2. [First launch and the System Status window](#2-first-launch-and-the-system-status-window) ([Appearance](#22-appearance), [Notifications](#23-notifications), [Missing VPN engines](#24-missing-vpn-engines), [Updating OpenVPN and WireGuard](#25-updating-openvpn-and-wireguard))
3. [Adding connections by type](#3-adding-connections-by-type) ([System VPNs](#35-system-vpns-your-own-windows-vpns), [Administrator steps](#37-administrator-steps-for-native-vpns), [Where the native VPNs are kept](#38-where-winvpn-keeps-the-native-vpns))
4. [Import and export](#4-import-and-export) ([Opening VPN files from File Explorer](#41-opening-vpn-files-from-file-explorer))
5. [Connecting](#5-connecting) ([Order](#51-order-of-connections), [MFA](#52-multi-factor-authentication-mfa), [Credentials asked when connecting](#53-credentials-asked-when-connecting), [Paired apps](#54-paired-apps-control-api), [Reconnect automatically](#55-reconnect-automatically), [DNS](#56-dns-while-connected), [Quitting and signing out](#57-quitting-signing-out-and-sleep))
6. [Debug mode and the log](#6-debug-mode-and-the-log)
7. [Troubleshooting from the log](#7-troubleshooting-from-the-log)
8. [Updates](#8-updates)
9. [Uninstalling](#9-uninstalling)
10. [Security notes](#10-security-notes)
11. [Vault](#11-vault)
12. [Folders and colours](#12-folders-and-colours)
13. [Shared credentials](#13-shared-credentials)
14. [Backup and restore](#14-backup-and-restore)
15. [Vault FAQ](#15-vault-faq)
16. [Team catalogs](#16-team-catalogs)

---

## 1. Installation

### 1.1 The installer

WinVPN comes as an MSI installer, one per processor type:

- `WinVPN-x.y.z-x64.msi` for Intel and AMD processors (most PCs),
- `WinVPN-x.y.z-arm64.msi` for ARM processors (for example Snapdragon; built and checked, but not yet tested on ARM hardware).

An **administrator** installs it: double-click the MSI and confirm the administrator prompt. WinVPN is installed for every user of the PC into `C:\Program Files\WinVPN`: `WinVPN.exe` (the app), `WinVPNService.exe` (the WinVPN Service, see [1.3](#13-the-winvpn-service)), `wireguard.dll` (WireGuard's signed driver library) and `THIRD-PARTY-NOTICES.txt` (the licences of the components it ships), with a **WinVPN** entry in the Start menu. The folder cannot be changed: the WinVPN Service runs from it with full rights, so only administrators may change it, and the service does not start from any other folder. An older WinVPN cannot be installed over a newer one (uninstall first); the same version can be installed again. WinVPN's windows use the Microsoft Edge WebView2 Runtime, which Windows 11 already has; if it is missing, the installer downloads it (this needs an internet connection).

Running the same installer again repairs the installation; it never installs a second copy. A newer MSI installed over an older WinVPN (also over the 1.5.0 preview) updates it and keeps your data (see [8.1](#81-upgrading-from-the-15-preview)).

### 1.2 SmartScreen

The installer is not signed with a code signing certificate (Authenticode), so Microsoft Defender SmartScreen may warn the first time: **Windows protected your PC**. Check that you downloaded the file from the official place, then click **More info** and **Run anyway**. You only need to do this once per installer file. (WinVPN's own updates are checked with the maintainer's offline signature instead, see [8](#8-updates).)

### 1.3 The WinVPN Service

OpenVPN and WireGuard need system rights to create network adapters, routes and DNS settings. A standard user does not have them, so the installer adds the **WinVPN Service** (`WinVPN`, display name **WinVPN Service**), which runs in the background as the system (LocalSystem) and starts with Windows. The app asks it, over a local channel only programs of this PC can reach (`\\.\pipe\WinVPN`), to bring a connection up or down; the service never accepts a request from the network.

- **Each user's connections are their own.** A connection belongs to the Windows user who brought it up: another user of the PC cannot see it, end it, answer its code prompt or read its log. But while a VPN is up it carries the traffic of the whole PC (that is how every Windows VPN works).
- **Signing out ends them.** When you sign out, the service takes down your OpenVPN and WireGuard connections. Locking the screen or switching users keeps them.
- **It checks what it runs:** `openvpn.exe` only from an installation in an administrators-only folder, signed by **OpenVPN Inc.** and at least version 2.6.0; `wireguard.dll` only when it is signed by **WireGuard LLC**.
- **Its data** is in `C:\ProgramData\WinVPN` (readable only by administrators and the system): the connection logs (`logs`, passwords and codes masked, see [6](#6-debug-mode-and-the-log)), its own log `service.log` and downloaded engines (`engines`). If an ordinary user created that folder before the installation, the service does not trust it: **System Status** says **The folder … has unsafe permissions. An administrator must delete it, then restart the WinVPN Service.**
- If the service stops unexpectedly, Windows restarts it (after 5 s, then after 30 s). If it is missing or from another WinVPN version, **System Status** says **The WinVPN Service is missing or from another WinVPN version. Repair WinVPN: Settings → Apps → Installed apps → WinVPN → Modify → Repair.**; if it does not answer, **The WinVPN Service is not reachable.** OpenVPN and WireGuard connections then cannot connect; L2TP/IPsec, IKEv2, SSTP and system VPNs still can (they do not use the service). Until it is fixed, the **System Status** tile has a **!** mark and the window opens by itself at launch.

### 1.4 OpenVPN Community

WinVPN runs OpenVPN connections with **OpenVPN Community** (`openvpn.exe`), which is not part of the WinVPN installer. **System Status** installs it when you need it: the **OpenVPN Community** row is red with **Install**.

- **Install** uses **winget** (Windows' package manager, present on Windows 11) to install the newest OpenVPN Community; without winget, or when winget fails or leaves a driver out, it downloads OpenVPN's official installer, checks its signer (**OpenVPN Inc.**) and runs it. An administrator confirms (on the winget path a second prompt, for WinVPN itself, follows). The installer's output is shown live under the row; **Cancelled** when the prompt is declined.
- **What is installed:** `openvpn.exe` with its libraries and two network drivers, **DCO** (OpenVPN's fast kernel driver) and **TAP-Windows6**. Not installed: the OpenVPN GUI and the OpenVPN service that starts configs by itself.
- **OpenVPN's Interactive Service** comes with every OpenVPN installation. WinVPN does not use it, so when WinVPN installed (or updated, or repaired) OpenVPN, it disables and stops that service. An OpenVPN Community you installed before (or by hand) is used as it is: WinVPN never changes its Interactive Service, so the OpenVPN GUI keeps working.
- **Which driver a connection gets.** WinVPN decides from the config: **DCO** by default; **TAP-Windows6** when the config uses something DCO cannot run (compression, an older non-AEAD cipher such as `AES-256-CBC`, `fragment`, a proxy, a static key, or `dev tap`). If the server pushes such a setting while connecting, WinVPN retries once with TAP-Windows6 (the log says so). There is one TAP-Windows6 adapter, so only one TAP-Windows6 connection can be up at a time.
- **Repair:** if a driver is missing, the row says **Missing: … Repair adds them.**; a connection that needs the missing driver says **This connection needs the … driver. Repair OpenVPN Community in System Status.**
- **Compression** (`comp-lzo`, `compress`) is allowed because some servers still use it, but compressed encrypted traffic can leak information (VORACLE): ask the server's administrator to turn it off.
- Uninstalling WinVPN leaves OpenVPN Community, its drivers and its TAP adapters (they belong to OpenVPN; remove OpenVPN in Installed apps).

### 1.5 WireGuard and the Windows VPN client

- **WireGuard** needs nothing to install: WinVPN ships WireGuard's own driver library (wireguard-nt, signed by WireGuard LLC), and the WinVPN Service creates a WireGuard adapter per connection.
- **L2TP/IPsec, IKEv2 and SSTP** use the **Windows VPN client** (Remote Access, built into Windows and updated by Windows Update). WinVPN dials them from your own user account, without the WinVPN Service and without administrator rights. System Status shows a **Windows VPN client** row: green **Built into Windows**, or red when a Windows service it needs is disabled (**The Windows service … is disabled. An administrator must set it to Manual (services.msc).**): Remote Access Connection Manager (`RasMan`), IKE and AuthIP IPsec Keying Modules (`IKEEXT`, L2TP and IKEv2), IPsec Policy Agent (`PolicyAgent`, L2TP) and Secure Socket Tunneling Protocol Service (`SstpSvc`, SSTP). These services start on demand: "stopped" is normal.

### 1.6 Where WinVPN keeps your data

Each Windows user has their own WinVPN data in `%LOCALAPPDATA%\WinVPN` (usually `C:\Users\<you>\AppData\Local\WinVPN`):

- the vault (`vault.db` with its key file `vault.keys`) and the preferences (`preferences.json`);
- `ras\`: WinVPN's own phonebook of Windows VPN entries (`WinVPN.pbk`) and one small settings file per L2TP connection (see [3.8](#38-where-winvpn-keeps-the-native-vpns));
- `logs\ras\`: the logs of the L2TP/IPsec, IKEv2 and SSTP connections;
- `downloads\` and `updates\`: OpenVPN installers and WinVPN updates while they are installed, and the installer logs.

The folder and its files are readable only by you and by Windows itself (SYSTEM); other users of the PC cannot open them. The folder is not part of a roaming profile: it stays on this PC. To move to another PC (or from a Mac), use a full backup (see [14](#14-backup-and-restore)). The logs of OpenVPN and WireGuard connections are kept by the WinVPN Service in `C:\ProgramData\WinVPN\logs` (see [6](#6-debug-mode-and-the-log)).

---

## 2. First launch and the System Status window

Start WinVPN from the Start menu. It appears as a shield icon in the notification area at the right end of the taskbar; the icon is white on a dark taskbar and black on a light one. If Windows hides it under **Show hidden icons** (the **^** arrow), you can drag it onto the taskbar, or turn it on in Settings → Personalization → Taskbar → **Other system tray icons**. Pointing at the icon shows **WinVPN**.

On the very first launch the **Set Up the Vault** window opens (see [11.1](#111-master-password-and-recovery-key)).

Click the icon to open the popover. It opens above the icon (on Windows 11 with rounded corners). Each connection is a card with the coloured bubble of its type, its name, its type and state, and a switch; with many connections the list scrolls. Folders appear as rows you can open and close (see [12](#12-folders-and-colours)). Below the cards:

- three tiles: **New Connection / Import…**, **Manage Connections…** and **System Status**;
- the **Settings** group (click it to open or close it): **Appearance** (see [2.2](#22-appearance)), **Connection Notifications** (see [2.3](#23-notifications)), the update settings (see [8](#8-updates)), **Launch at Login**; then the vault settings **Unlock automatically**, **Show “Lock Now”**, **Change Master Password…** and **New Recovery Key…** (see [11](#11-vault)), and **Back Up Everything…** and **Restore from Backup…** (see [14](#14-backup-and-restore));
- **Help**, **Lock Now** (when shown, see [11.4](#114-lock-now)) and **Quit WinVPN**. **Help** opens this guide on GitHub (in Hungarian when WinVPN's language is Hungarian).

While the vault is locked, the popover shows only an **Unlock…** row, the number of active connections and **Quit WinVPN** (see [11.5](#115-the-locked-popover)). Before the vault exists, the row says **Set Up the Vault…**.

**The System Status window** says **WinVPN connects OpenVPN and WireGuard through the WinVPN Service. OpenVPN Community is installed here when you need it.** and shows four rows:

1. **WinVPN Service:** **Running (version …)**, or why it cannot run connections (see [1.3](#13-the-winvpn-service)).
2. **OpenVPN Community:** the installed version and its drivers (**Version 2.7.8 · drivers: OpenVPN DCO 2.8.13.0, TAP-Windows6 9.27.0.0**), or **Install**, **Repair** or **Update** (see [1.4](#14-openvpn-community) and [2.5](#25-updating-openvpn-and-wireguard)).
3. **WireGuard:** the wireguard-nt version, and **Update** when a newer one exists.
4. **Windows VPN client:** **Built into Windows**, or the Windows service that is disabled (see [1.5](#15-wireguard-and-the-windows-vpn-client)).

While a row needs something, the **System Status** tile has a **!** mark and the window opens by itself at launch. OpenVPN Community is optional: while it is only not installed, its row stays red with **Install**, but there is no **!** mark and the window does not open at launch (an installed OpenVPN that needs **Repair**, or an **Update** because the service refuses its version, still counts). A missing or unreachable WinVPN Service always counts. A newer engine version alone does not: the row stays green and offers **Update** (see [2.5](#25-updating-openvpn-and-wireguard)). **Check Again** checks everything again. Below the rows is the **Launch at Login** switch, the uninstall note with **Open Installed Apps…**, and **Remove WinVPN from This Account…** (see [9](#9-uninstalling)).

**Windows and the keyboard.** Every WinVPN window (Connections, System Status, the vault windows) has its own taskbar button, so Alt+Tab reaches it; while only the popover is open, WinVPN has no taskbar button. WinVPN has no menu bar: the text fields have the usual shortcuts (Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+A, Ctrl+Z), **Ctrl+S** saves in an editor and **Ctrl+F** jumps to the search field of the Connections window. Starting WinVPN again while it runs (from the Start menu, for example) does not start a second copy: the running WinVPN brings its open windows forward, or opens the Connections window (the vault's window while the vault is locked).

### 2.1 Launch at login

WinVPN does not start automatically by default. To start it every time you sign in to Windows, tick **Launch at Login** in the popover's **Settings** group or in the **System Status** window. Untick it to stop. It applies from your next sign-in.

- WinVPN registers itself for your user only (the `WinVPN` value under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`).
- Windows lets you turn it off in **Settings → Apps → Startup**. Then the switch in WinVPN is off, with the note **Turned off in Settings → Apps → Startup.**, and the **Open Startup Apps Settings…** button opens that page. Ticking **Launch at Login** in WinVPN turns it on again.
- Only the installed WinVPN can be registered; the switch is disabled in a development build.

### 2.2 Appearance

**Settings → Appearance** has three choices: **Match System** (the default: WinVPN follows Windows' app mode in Settings → Personalization → Colors, also when you switch it while WinVPN runs), **Light** and **Dark**. The choice applies at once to the popover and every open window, title bars included, and to every window opened later; WinVPN remembers it. Windows' own dialogs (choosing a file, message boxes, the administrator prompt) keep following Windows' mode, and the notification-area icon keeps following the taskbar's colour.

### 2.3 Notifications

WinVPN shows Windows notifications, for example when a code is needed, when a team catalog was updated (see [16.4](#164-refresh-and-updates)), and about connections. They work with the installed WinVPN (its Start-menu entry carries the identity Windows needs for them). You can turn them off in Settings → System → Notifications → **WinVPN**. Clicking a notification while WinVPN runs opens the window it belongs to; after WinVPN was quit, a click only starts WinVPN. A notification never shows a password, a key or a server's error text.

**Connection notifications.** WinVPN tells you when a connection **connected** (**Office VPN connected**), was **reconnected** automatically (**Office VPN reconnected**, see [5.5](#55-reconnect-automatically)), **dropped** without you disconnecting it (**Office VPN disconnected**), **failed** (**Office VPN: connection failed**), or was **not reconnected** / **could not reconnect**. Under the title is a short reason in plain words, read from the end of the connection's log (see [7.12](#712-the-reasons-in-notifications)); otherwise **Click to see the log.** (for a failed connect: **Open WinVPN for details**). A click opens the connection's **Log** tab in the Connections window.

- They name only the connection, never a server, an address, a user name or an error message (notifications can be seen on the lock screen); while the vault is locked, not even the connection (**A VPN connection dropped**, …).
- A disconnect you start (also by quitting WinVPN, signing out, or when a paired app lets go) is never notified, and neither is a connection that is already up when WinVPN starts.
- **Settings → Connection Notifications** (on by default) turns them off; the notifications that ask you for something (a code, credentials) and the team catalog notices stay.
- Toasts appear only from the installed WinVPN (started from the Start menu). A click on an old notification, after WinVPN restarted or when more than 32 newer ones arrived, does nothing.

### 2.4 Missing VPN engines

When a connection's engine cannot be used, the connection stays in the list, greyed out, and its line says why: **Not installed: OpenVPN Community – System Status** when OpenVPN Community is not installed, **Not ready: OpenVPN Community – System Status** when it needs a repair or an update, **Not ready: WinVPN Service – System Status** when the WinVPN Service cannot run connections (only OpenVPN and WireGuard connections show this). **System Status** in that line is a link that opens the window, where **Install**, **Repair** or **Update** fixes it. A type or a connection that Windows cannot run for another reason shows its own text, without a link: for example a Cisco IPsec connection (see [3.4](#34-l2tpipsec-and-cisco-ipsec)), an IKEv2 config with a setting Windows does not support (see [3.3](#33-ikev2-strongswan)), or an SSTP connection while its Windows service is disabled.

- The switch and **Connect** are disabled; **New** in the Connections window lists only the types that can be used (so **New** never offers **Cisco IPsec** on Windows).
- **Import refuses such a file** before anything is saved, for example **office.ovpn: OpenVPN Community is not installed. Install it in System Status first.**; the other files of the same import are imported.
- **Team catalogs and backups keep their connections:** a connection of a missing type is shown greyed like any other and works once the engine is installed.
- After installing OpenVPN Community outside WinVPN, you do not need **Check Again**: when you open the popover or the Connections window while a type is unavailable, WinVPN checks again in the background (at most once a minute).

### 2.5 Updating OpenVPN and WireGuard

WinVPN does not need a new release for a newer VPN engine. **System Status** checks when you open it or press **Check Again**, and WinVPN also checks once a day in the background, so the offer appears without opening the window:

- **OpenVPN Community:** if winget or OpenVPN's official download page (`openvpn.net`) has a newer version than the installed one, the row says **Update available: 2.7.7 → 2.7.8** and offers **Update**. It installs that version (with winget, or the official MSI from OpenVPN's servers, whose signer **OpenVPN Inc.** WinVPN checks first) after one administrator confirmation; the output is shown live under the row. WinVPN never offers an older version than the installed one.
- **WireGuard (wireguard-nt):** the WinVPN Service looks for a newer driver library on `download.wireguard.com`. When there is one, the row says **Update available: 1.1.0 → 1.2.0** and offers **Update**. The service downloads it, checks its signer (**WireGuard LLC**), its version and its processor type, and only then uses it (**wireguard-nt 1.2.0 is installed.**); no administrator confirmation is needed. It can update only while no WireGuard connection is up on this PC, for any user: **wireguard-nt can be updated only while no WireGuard connection is up on this computer. Disconnect WireGuard, then try again.**
- **The Windows VPN client** is updated by Windows Update.
- If the check cannot reach the internet, the rows simply offer nothing.

---

## 3. Adding connections by type

You add connections in the **Connections** window. To open it, use the popover: **Manage Connections…** or **New Connection / Import…**.

- The list is on the left: your connections and your Windows VPNs (system VPNs, see [3.5](#35-system-vpns-your-own-windows-vpns)) in one tree with your folders, pinned ones on top of each folder (see [5.1](#51-order-of-connections) and [12](#12-folders-and-colours)). Below the list are **Credentials** (see [13](#13-shared-credentials)), **Paired apps** (see [5.4](#54-paired-apps-control-api)), **Team catalogs** and **Publishing** (see [16](#16-team-catalogs)).
- From the toolbar **New** (+) menu, pick a type (OpenVPN, WireGuard, IKEv2, SSTP, L2TP; **Cisco IPsec** is not offered on Windows), **New Folder** or **Import from File…**. The same menu has **Back Up Everything…** and **Restore from Backup…** (see [14](#14-backup-and-restore)). A new connection starts with a template and a name like "New OpenVPN"; rename it in the name field.
- The selected connection's header has **Connect** / **Disconnect**, **Connect in Debug Mode**, the export icon and the delete icon (**Delete**, with a confirmation). Below it are two tabs: **Settings** and **Log**.

Text-based types (OpenVPN, WireGuard, IKEv2) have a monospace editor. **Save** (Ctrl+S) checks the config first. If it finds errors, they are listed in red under the editor with their line numbers (for example `Line 3: Forbidden directive: up – delete the line or comment it out (#)`), and nothing is saved. Risky OpenVPN settings appear in a yellow panel while you type (see [3.1](#31-openvpn)). Passwords have their own fields in the **Authentication** section. They go into WinVPN's encrypted vault, not into the config. Where a connection signs in with a user name and password, the **Password from** selector chooses between **Own username and password** and a shared credential (see [13](#13-shared-credentials)).

SSTP, L2TP and Cisco IPsec have a form instead of a text editor.

**What Windows cannot do is shown, not hidden.** A connection whose settings the Windows VPN client cannot run (a Cisco IPsec connection, an IKEv2 config with an unsupported setting, SSTP with **No verification**) is greyed in the list with the reason, and its editor shows the same reason in a yellow note above the form. You can still edit, save, export and back it up: the same connection works in MacVPN.

**Stored passwords are never shown.** A password field that has a stored value says **Saved — type to replace**. Leave it alone to keep the stored value, type to replace it, or click **Remove saved password** and save to delete it. The status line under the editor shows **Unsaved changes** or **Saved: <time>**.

If you switch connections or close the window with unsaved changes, the app asks: **Save**, **Discard** or **Cancel**.

**Deleting** a connection deletes its config and saved passwords, and for L2TP/IPsec, IKEv2 and SSTP also its Windows VPN entry (**The config and the saved passwords will be deleted, and its Windows VPN entry too.**). Nothing needs to be removed in Settings by hand.

### 3.1 OpenVPN

The easiest way is to import the `.ovpn` file from your provider (**New → Import from File…**, or drag the file onto the list). OpenVPN connections need OpenVPN Community (see [1.4](#14-openvpn-community)).

- If the `.ovpn` refers to external files (for example `ca ca.crt`, `cert client.crt`, `key client.key`, `tls-auth ta.key`), the import reads them from next to the `.ovpn` and embeds them (into `<ca>…</ca>` blocks). So before importing, keep those files next to the `.ovpn`. If a file is missing, the import reports an error.
- If the server asks for a username and password (an `auth-user-pass` line), fill in **Username** and **Password**, or leave them empty: WinVPN asks when you connect (see [5.3](#53-credentials-asked-when-connecting)).
- If the private key is protected by a password (a password-protected PKCS#12 file, or an encrypted PEM key), enter it in **Private key password**. It is stored in the vault.
- WinVPN sorts every directive into three tiers, like MacVPN (the full list is in [openvpn-directives.md](openvpn-directives.md)):
  - **Allowed** directives work as usual.
  - **Risky settings** (for example `user nobody`, server-side options, and every directive WinVPN does not know) are shown in a yellow **Risky settings** panel, each with a short reason. Tick **I acknowledge these settings and the security risks** to save. The acknowledgement covers exactly the risky directives present when you save: if you add another one later, you have to tick the box again.
  - **Forbidden** directives, for example `up`, `down`, `script-security`, `plugin`, `log`, `chroot` and `echo`, are never allowed (they would run external scripts, load code, or read or write files with the VPN's rights). On Windows also the options the WinVPN Service sets itself (`win-sys`, `service`, `msg-channel`, `allow-nonadmin`, `rdns-internal`, `dhcp-internal`), `windows-driver` (WinVPN picks the driver, see [1.4](#14-openvpn-community)) and **`cryptoapicert`**: `openvpn.exe` runs as the system, so a certificate selector would reach the computer's certificate store instead of yours. Use a certificate and key in the config (or a PKCS#12 file) instead. See [3.9](#39-errors-when-saving).
- The arguments of the allowed directives are checked too: for example ports and timers must be numbers, and host names and cipher names cannot contain `/` or start with `-`. `<connection>` blocks are supported; their lines go through the same checks.
- **Every line is at most 255 bytes** (also inside inline blocks such as `<ca>`), as OpenVPN reads a line in 256-byte pieces; a longer line gives **Line too long**. A line with more than 16 words gives **Wrong number of arguments**.
- **`setenv` on Windows** takes only the names OpenVPN itself reads (`FORWARD_COMPATIBLE`, `PUSH_PEER_INFO`, `SERVER_POLL_TIMEOUT`, `REMOTE_RANDOM_HOSTNAME`, `CLIENT_CERT`, `CONFIG_VERSION`) and the peer-info names starting with `UV_` or `IV_`; any other name gives **setenv not allowed**. OpenVPN passes these variables to the Windows programs it runs as the system, so a name such as `SystemRoot` could change what they load. `setenv opt <directive>` is checked like the directive itself, once.

### 3.2 WireGuard

Import the `.conf` file, or create a new one (**New → WireGuard**) and fill in the template (`[Interface]` with `PrivateKey`, `Address`, `DNS`; `[Peer]` with `PublicKey`, `AllowedIPs`, `Endpoint`).

- The `PreUp`, `PostUp`, `PreDown`, `PostDown` and `SaveConfig` keys are not allowed.
- Values are checked: keys must be 44-character base64, `Address`/`AllowedIPs` IP addresses with an optional prefix (`10.0.0.2/32`), `Endpoint` `host:port` or `[IPv6]:port`, `MTU`/`ListenPort`/`PersistentKeepalive` numbers. No value may start with `-`.
- On Windows `FwMark` and `Table` can only be `auto` or `off` (`Table = off`: no routes are added); other values are refused when you save.

### 3.3 IKEv2 (strongSwan)

IKEv2 configs use strongSwan `swanctl.conf` syntax, as in MacVPN, so the same connection works on both. A new connection (**New → IKEv2**) starts with a template.

- The **Username** field must match `eap_id`. Put the password into **Password**. These are stored in the vault, not in the config.
- `include`, `updown`, and `secrets` that refer to a file (`file = …`) are not allowed. Only the documented `swanctl.conf` keys are accepted, each in its own section; `certs`, `cacerts`, `cacert` and `pubkeys` take plain file names only.

**On Windows** WinVPN translates the first connection of the config and its first child into an entry of the Windows IKEv2 client. Under the editor a grey line shows what Windows will use, for example **On Windows: EAP-MSCHAPv2 · AES-256, SHA-256, DH group 14; ESP AES-256, SHA-256 · split tunnel** (or **computer certificate**, **all traffic**).

- **Sign-in:** `local { auth = eap-mschapv2 }` (or `eap` with an `eap_id`) with `remote { auth = pubkey }`, or a **computer certificate** (`local { auth = pubkey }`). The certificate files named in the config are not used: Windows takes the client certificate from the computer's **Personal** store, where an administrator imports it (see [3.7](#37-administrator-steps-for-native-vpns)). Without it: **No computer certificate for IKEv2 was found. An administrator must import it (see the user guide).**
- **No pre-shared key:** a config with `local { auth = psk }` shows **Not supported on Windows: local auth = psk (the Windows IKEv2 client cannot sign in with a pre-shared key; use EAP-MSCHAPv2 or a computer certificate)**. Ask your VPN administrator for EAP access, or use L2TP/IPsec with the PSK.
- **The server's certificate** is checked by Windows against the computer's **Trusted Root Certification Authorities**, and its name must match the address in `remote_addrs`. A company CA must be trusted there first: **Trust This CA in Windows…** under the editor, with the CA's PEM file (see [3.7](#37-administrator-steps-for-native-vpns)). If `remote { id = … }` differs from the address: **On Windows the server's identity must be its address: set remote_addrs to the name in the server certificate.**
- **Routes:** `remote_ts = 0.0.0.0/0` (or no `remote_ts`) sends all traffic over the VPN; other `remote_ts` networks are used as routes (split tunnel).
- **Proposals:** Windows uses one IKE and one ESP proposal: the first of `proposals` / `esp_proposals` that Windows supports, else **Windows supports none of these IKE proposals: … Windows offers: …**. Without `proposals` WinVPN uses AES-256, SHA-256 and DH group 14 for IKE and AES-256, SHA-256 for ESP.
- **Ignored on Windows** (a grey note, the connection still runs): `dpd_action = restart` (**Ignored on Windows: dpd_action = restart (Windows itself redials a dropped connection)**) and `start_action` (the connection starts when you connect it).
- **Not supported on Windows** (the connection is greyed, with the exact key and value, for example **Not supported on Windows: local auth = eap-tls**): EAP-TLS, EAP-MD5, EAP-GTC, EAP-RADIUS, XAUTH, IKEv1 (`version = 1`), more than one authentication round, `remote_port` other than 500, a fixed virtual IP in `vips`, traffic selectors with a protocol or port, `::/0` without `0.0.0.0/0`, a missing `remote_addrs`.

### 3.4 L2TP/IPsec and Cisco IPsec

You set up L2TP/IPsec in a form (**New → L2TP**): **Name**, **Server**, **Account name**, **Password**, **Pre-shared key (PSK)** and **Send all traffic over VPN**.

- **Save** saves the connection (the password and the PSK go into the vault) and writes its Windows VPN entry at once: there is nothing to approve (**Saving writes the Windows VPN entry of this connection at once; there is nothing to approve. The password is not in it: WinVPN passes it when connecting.**). The entry is WinVPN's own and does not appear in Settings → VPN (see [3.8](#38-where-winvpn-keeps-the-native-vpns)).
- **Behind NAT:** Windows refuses L2TP/IPsec to a server behind a NAT router until an administrator allows it once. The error then offers **Allow L2TP Behind NAT…** (see [3.7](#37-administrator-steps-for-native-vpns)).
- The server must accept MS-CHAPv2 sign-in and a pre-shared key (as in MacVPN; there is no certificate-based L2TP).

**Cisco IPsec on Windows.** Windows has no client for Cisco IPsec (IKEv1 with XAUTH), and no maintained, signed client exists that WinVPN could install. So a Cisco IPsec connection (from a MacVPN backup, an import of a MacVPN export, or a team catalog) is kept on Windows: you can edit, export, back up and share it, and it works on a Mac. But it cannot connect here: its card is greyed with **Cisco IPsec is not supported by Windows. Ask your VPN administrator for L2TP/IPsec or IKEv2 access, or make an L2TP/IPsec copy of this connection.**, and **New** does not offer Cisco IPsec.

- **Make an L2TP/IPsec Copy** in the Cisco editor makes a new L2TP/IPsec connection named "<name> (L2TP)" in the same folder, with the same server, account name, password and PSK (or the same shared credential), and **Send all traffic over VPN** as set; the group name is dropped. The Cisco connection stays as it is. The copy works if the server also offers L2TP/IPsec with the same PSK: ask your VPN administrator.

### 3.5 System VPNs: your own Windows VPNs

The VPNs set up in Windows (Settings → Network & internet → VPN, for your user or for every user of the PC) are listed in WinVPN as **System VPN**s, with their type (**L2TP**, **IKEv2**, **SSTP** or **VPN**) and live state. A VPN you add or remove in Settings appears or disappears within seconds. If a listed VPN is removed while you look at it, its detail says **This VPN was removed from Windows**.

- **Connect / disconnect** from the popover or the Connections window, like any other connection. Their settings stay in Windows: **This connection can only be connected and disconnected here. Its settings are in Settings or in its own app.** WinVPN never edits, renames or deletes them.
- **Secrets:** for an L2TP system VPN you can store a **password** and a **pre-shared key (PSK)** in WinVPN's vault (its detail view in the Connections window; **Forget saved secrets** removes them). WinVPN passes the password when connecting, with the user name Windows has saved for the VPN. The PSK: **Windows uses its own PSK for this VPN if it has one; otherwise WinVPN stores this one there.** That is the only change WinVPN ever makes to your own VPN, and only after you saved a PSK for it.
- **Without stored secrets** WinVPN uses the user name and password Windows saved for the VPN; if Windows has none, Windows' own sign-in window opens.
- **One-time codes:** an L2TP system VPN can ask for a code and append it to the password (see [5.2](#52-multi-factor-authentication-mfa)).
- System VPNs can be put into folders, pinned and coloured like your connections.

### 3.6 SSTP

Create it with **New → SSTP**, or import an `.sstp` file. It has a form: **Name**, **Server** (host name or IP address, without a port), **Port** (443 by default), **Username** and **Password**, the **Server certificate** mode, **Send all traffic over VPN** and **Use the server's DNS**.

- **System CA:** Windows checks the server's certificate against the computer's trusted root CAs (unlike MacVPN, which uses Homebrew's OpenSSL store). A public certificate works at once.
- **Custom CA file** (**Choose PEM File…**): the CA must also be trusted by Windows, because the Windows SSTP client only uses the computer's trust store. Under the form, **Trust This CA in Windows…** does it once, with an administrator's confirmation (see [3.7](#37-administrator-steps-for-native-vpns)); afterwards the form says **Trusted by Windows**. Until then connecting fails with **The server’s CA is not trusted by Windows. Use Trust This CA in Windows… in the editor.**
- **No verification** cannot be chosen on Windows (it is shown disabled): **Windows always checks the SSTP server's certificate. Choose System CA or Custom CA file.** An imported connection with `cert=insecure` is greyed with that reason.
- Windows also checks that the server's certificate was not revoked: the server's revocation list must be reachable.
- **Use the server's DNS** turned off is best effort on Windows: WinVPN gives the VPN adapter a low priority, so your own network's DNS servers are asked first.
- Use `user@domain` instead of `DOMAIN\user`: backslashes, spaces and quotes are not allowed in the user name. The password must not contain quotation marks (`"`), backslashes (`\`) or control characters.
- The server must accept MS-CHAPv2.

The config file (and the `.sstp` export) is plain `key=value` text, without the password, for example `server=vpn.example.com`, `port=443`, `user=john.smith@corp.example`, `cert=system`, `route_all=yes`, `peer_dns=yes`.

### 3.7 Administrator steps for native VPNs

A few things only an administrator can change on Windows. WinVPN never does them in the background (and never through the WinVPN Service): each one is a button that shows what will happen and then asks for an administrator's confirmation (UAC). Declining it answers **Cancelled**.

- **Trust This CA in Windows…** (SSTP with **Custom CA file**, IKEv2): first a confirmation names the CA (**Subject: …**, **Valid from … to …**, **SHA-256 fingerprint: …**) and warns **Every program on this PC will trust server and client certificates from this CA (not software it signs).** Click **Trust** only for your organisation's VPN CA. Then WinVPN (after the administrator's confirmation) adds it to the computer's Trusted Root Certification Authorities for server and client authentication only, never for code signing, and checks the result (**The CA is now trusted by Windows.**). This needs WinVPN installed in Program Files. A certificate that is not a CA, or has expired, is refused. To remove it later: `certlm.msc` → Trusted Root Certification Authorities → Certificates → delete it.
- **Allow L2TP Behind NAT…** (offered in the error of an L2TP/IPsec connection that got no answer, Windows error 809): sets the `AssumeUDPEncapsulationContextOnSendRule` value (2) under `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent` with Windows' `reg.exe`, then says **L2TP/IPsec behind NAT is allowed. Restart Windows to apply it.** It applies to every L2TP/IPsec VPN of the PC.
- **A computer certificate for IKEv2** is imported by an administrator with Windows' own tool (WinVPN never handles the certificate's password): run `certlm.msc` → **Personal** → **Certificates** → right-click → **All Tasks** → **Import…**, choose the `.p12` / `.pfx` file, enter its password, keep the store **Personal**, finish. The certificate's issuing CA must be in **Trusted Root Certification Authorities** too.

### 3.8 Where WinVPN keeps the native VPNs

- WinVPN writes the Windows VPN entries of its L2TP/IPsec, IKEv2 and SSTP connections into **its own phonebook**, `%LOCALAPPDATA%\WinVPN\ras\WinVPN.pbk`, never into Windows' phonebooks. So they do not appear in Settings → VPN and can only be connected in WinVPN (popover, Connections window, paired apps).
- Each entry is named `WinVPN-<connection ID>`. `ipconfig` shows a connected one as **PPP adapter WinVPN-…**.
- L2TP entries are written when you save; IKEv2 and SSTP entries at each connect (from the current config). Deleting a connection deletes its entry; after the vault is unlocked, WinVPN also removes entries whose connection no longer exists.
- **Secrets:** the password (with a one-time code) is passed to Windows only at the moment of dialling; it is never stored in Windows. The **pre-shared key** has no such field: WinVPN writes it into Windows' encrypted VPN credential store for that one entry just before each connect (from the vault, so a changed PSK is used at once), and removes it when the entry is deleted. Neither is ever in the phonebook file or a log.

### 3.9 Errors when saving

You get these errors on **Save**, for example:

- `Line 3: Forbidden directive: up – delete the line or comment it out (#)`
- `Line 5: Risky directive, acknowledgement required: user` (the setting is in the yellow **Risky settings** panel)
- `Line 7: External file reference, use an inline block: ca`
- WireGuard: `Line 4: Forbidden key: postup`; IKEv2: `Line 2: Forbidden: include`
- Arguments: `Line 4: Invalid argument: dev`, `Line 8: Wrong number of arguments: keepalive`
- OpenVPN: `Line 12: Line too long`, `Line 9: setenv not allowed: SystemRoot – delete the line or comment it out (#)`

To fix: see [7.7](#77-directive-not-allowed--forbidden-directive). A Windows limit of an IKEv2 or SSTP connection is not a save error: the connection is saved and shown greyed with its reason (see [3](#3-adding-connections-by-type)).

---

## 4. Import and export

**Import.** Use **New → Import from File…** (you can select several files), or drag one or more files into the Connections window. Each file must be a regular UTF-8 text file of at most 1 MB. The type is detected from the extension and the content:

- `.ovpn`, or a `client` / `dev tun` line plus a `remote` line → OpenVPN
- `[Interface]` + `PrivateKey` → WireGuard
- `connections {` → IKEv2 (strongSwan)
- `.sstp`, or a `server=…` line plus a `user=`, `cert=`, `route_all=` or `peer_dns=` line → SSTP

If one file cannot be recognized or cannot be imported, the other files are still imported. One dialog lists all the errors. A `.mobileconfig` profile (MacVPN's export of an L2TP or Cisco IPsec connection) cannot be imported: **A .mobileconfig profile cannot be imported into WinVPN. Create the connection with New → L2TP, or restore a backup that has it.**

**OpenVPN files that refer to other files** (`ca ca.crt`, `tls-auth ta.key 1`, …): WinVPN copies the referenced files into the config as inline blocks. After the import it lists them, for example **Imported, inlined: ca.crt, ta.key**. For safety, a referenced file is only read if:

- it is inside the folder of the `.ovpn` file (or one of its subfolders). `..\` paths, paths outside that folder, network paths (`\\server\share\…`) and links that point outside the folder are refused with **The referenced file is outside the config's folder**; a name with a `:` in it (an alternate data stream such as `ca.crt:hidden`) is refused as a missing file;
- it is at most 1 MB;
- its content matches the directive: a PEM certificate for `ca`, `cert` and `extra-certs`; a PEM private key for `key`; an OpenVPN static key for `tls-auth`, `tls-crypt` and `secret`; a tls-crypt-v2 client key for `tls-crypt-v2`; DH parameters for `dh`. Otherwise: **The file for the … directive (…) does not have the expected format**.

A file in a OneDrive folder that is only online is downloaded when WinVPN reads it. A `pkcs12 client.p12` file is embedded the same way, as base64 in a `<pkcs12>` block. A username/password file in `auth-user-pass` (for example `auth-user-pass auth.cfg`) is never copied into the config: if it is inside the folder, at most 1 KB and has exactly two lines, WinVPN asks **Use the credentials from … for this connection?**; if you choose **Use**, it stores them in the connection's **Username** and **Password** fields (in the vault). An `askpass pass.txt` file is handled the same way for the **Private key password**.

**Checking imported configs.** The imported config is checked right away with the same rules as **Save**. If it has problems, it is still imported, and its editor opens with the problems in red. If it contains risky settings, the import message says so, and the editor shows them in the yellow **Risky settings** panel. An IKEv2 or SSTP config with a setting Windows does not support is imported and shown greyed with its reason (see [3.3](#33-ikev2-strongswan), [3.6](#36-sstp)).

**Export.** The export icon in the connection header (**Export… (passwords are never included)**) saves the config in its original format: `.ovpn`, WireGuard `.conf`, `.swanctl.conf`, `.sstp`, or `.mobileconfig` for L2TP and Cisco IPsec.

- The password, PSK and username are **not** exported. The SSTP user name is part of the config, so it is in the `.sstp` export; the password is not.
- **Private keys** that are part of the config (an OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<pkcs12>`, `<auth-user-pass>` or `<http-proxy-user-pass>` block, a WireGuard `PrivateKey` / `PresharedKey`, a strongSwan `secrets` section) trigger a warning (**The config contains private keys or credentials**) with three choices: **Export Without Keys** (the default), **Export With Keys**, or **Cancel**. Anyone who has the keys can connect as you.
- The exported file is readable only by you (and by SYSTEM).
- **Folder and shared credential.** If the connection is in a folder or uses a shared credential, a text export starts with one comment line such as `# macvpn-meta: {"folder":["Work","Clients"],"credentialName":"Office AD"}`. It holds only these names, never a secret. On import, WinVPN recreates the missing folders and puts the connection there. A `credentialName` is never linked silently: WinVPN asks first and names the server (see [13.4](#134-import-and-export)).
- These exports can be imported into WinVPN and MacVPN again. The `.mobileconfig` export of an L2TP or Cisco IPsec connection is a macOS profile: double-clicked on a Mac it installs the VPN there; Windows cannot use it, and there is no Windows-only export format. To move an L2TP connection to another PC, use a full backup (see [14](#14-backup-and-restore)) or a team catalog.

### 4.1 Opening VPN files from File Explorer

Double-click a `.ovpn` or `.sstp` file in File Explorer: WinVPN opens the **Connections** window and imports it. This is the same import as **Import from File…**, with the same checks, the same questions and the same report. Nothing connects. If WinVPN is not running, the double-click starts it; if it runs, the running WinVPN gets the file.

- **Which files open in WinVPN.** The installer makes WinVPN the default app for `.ovpn` and `.sstp` files, and for `.macvpncatalog` files, which open the team catalog dialog (see [16.1](#161-subscribing-to-a-catalog)).
- **`.conf` files are not taken over**, because WireGuard and many other programs use that extension. For a WireGuard or strongSwan `.conf`, right-click it and choose **Open with → WinVPN**.
- **Another VPN app opens `.ovpn` files:** right-click one `.ovpn` file → **Open with** → **Choose another app**, pick **WinVPN** and choose **Always**.
- **Not opened from File Explorer:** admin key files (`.macvpnadminkey`) and backups (`.macvpnbackup`). Use their buttons in WinVPN. If you open one with WinVPN anyway, the report says **This file is opened from its own panel in WinVPN, not from File Explorer.**
- **Downloaded files ask first.** Windows marks a file you downloaded from the internet (the "Mark of the Web"). Such a file is not imported straight away: WinVPN asks once for all of them, **Import the downloaded file?** or **Import N downloaded files?**, names the files and adds **Only import files you trust.** **Import** imports them, **Cancel** skips them. Files that were not downloaded are imported either way. WinVPN only reads the mark, it does not remove it.
- **The vault is locked or not set up yet:** WinVPN shows the unlock (or setup) window first and imports the files once the vault is open. If you close that window instead, nothing is imported.
- An opened file is untrusted input, exactly like a file you drag into the window: it is imported only if it passes the checks.

---

## 5. Connecting

- **From the popover:** click the switch on the connection's card. The badge on the type bubble and the line under the name show the state:
  - **green:** connected (with the IP address and the elapsed time); the switch is green too
  - **amber, pulsing:** **Connecting…** or **Disconnecting…** (the switch is amber), or **Waiting for authentication**: a one-time code, a sign-in in the browser or missing credentials (see [5.2](#52-multi-factor-authentication-mfa) and [5.3](#53-credentials-asked-when-connecting))
  - **red:** error (with a short reason)
  - **grey:** not connected
  - **Held by …** under the card: a paired app holds the connection (see [5.4](#54-paired-apps-control-api))
- **From the Connections window:** the **Connect** / **Disconnect** button.
- **How each type connects:** OpenVPN and WireGuard through the WinVPN Service (see [1.3](#13-the-winvpn-service)); L2TP/IPsec, IKEv2 and SSTP through the Windows VPN client, dialled by WinVPN in your own user account; system VPNs too (see [3.5](#35-system-vpns-your-own-windows-vpns)).
- Several connections can be active at the same time, of any types.
- If an engine is missing for a type, the connection is greyed out and shows **Not installed: … – System Status** (see [2.4](#24-missing-vpn-engines)).
- **Notifications** when a connection connects, drops, is reconnected or fails, and when it waits for a code or a sign-in ("…: authentication needed"; clicking it brings the code window forward): see [2.3](#23-notifications). After sleep or a network loss WinVPN can bring a connection back by itself: see [5.5](#55-reconnect-automatically).

### 5.1 Order of connections

The popover and the list in the **Connections** window use the same order. Connections created in WinVPN and system VPNs are ranked together. With folders, the same rules apply inside every folder, after its subfolders (see [12.3](#123-order-inside-a-folder)).

- **Pinned connections come first**, in your order. To pin one, right-click it in the **Connections** window and choose **Pin to Top**; to remove it from the top, choose **Unpin**. Drag a pinned connection onto another pinned connection of the same folder to change their order.
- **The others follow, most used first.** Every successful connect that you start in WinVPN adds 1 point, and the points lose half of their value every 14 days. Connections started outside WinVPN (for example in Settings) do not count. Connections with equal points (for example, new ones with no points) are listed by name.
- The order is stored in the vault. Single-connection exports do not include it; a full backup does.

### 5.2 Multi-factor authentication (MFA)

WinVPN handles one-time codes (OTP, TOTP, token PIN) and sign-in in the browser (SAML / SSO, push approval), exactly as MacVPN does. A code is never stored and never written to the log.

**The code window.** When a code is needed, a small window opens with the connection's name, the question from the server (or from the config), a **Code** field, **Cancel** and **Continue**. The field hides what you type unless the server asks to show it. The window expires after 2 minutes, and the connection then fails with **Authentication was not completed in time**. While WinVPN waits, the row shows **Waiting for authentication** and the notification-area icon becomes a key. The window does not take the keyboard away from the app you are using: you also get a notification ("…: authentication needed"); click the notification or the window to type the code. Text from the server is marked **The VPN server says:**. For about a second after it appears, the window ignores input, so a stray keypress cannot answer it. Disconnecting closes the window and stops the attempt.

**OpenVPN: automatic.** Nothing to set up:

- **Static challenge** (`static-challenge "…" 0|1` in the config): WinVPN asks for the code before connecting, with the text from the config, and sends it to the server together with the password (in the SCRV1 format, or simply appended if the config says `concat`).
- **Challenge sent by the server** (dynamic challenge `CRV1`, or a text challenge): the code window opens during the connection, with the server's text.
- **Sign-in in the browser** (`OPEN_URL`, `WEB_AUTH`: SAML, SSO, push): WinVPN shows the host of the address (in plain ASCII, lowercase) and the full address, and asks **Open in Browser** (it is not the default button: click it). Only `https://` addresses are opened; any other address is ignored. After you sign in (or approve the push on your phone), the connection comes up. WinVPN waits up to 5 minutes (or the server's shorter limit).

**All types: code appended to the password.** Some servers expect the code typed after the password (for example `password123456` or `password,123456`). In the connection's settings, turn on **Ask for a one-time code at connect and append it to the password** and choose the **Separator**: none, `,` or `:`. It is available for OpenVPN, IKEv2, SSTP and L2TP, and for L2TP system VPNs (in their detail view in the **Connections** window). At connect, WinVPN asks for the code and sends password + separator + code. If no password is saved in WinVPN, the code alone is sent as the password. For SSTP the password with the code must not contain `"`, `\` or control characters. For an OpenVPN config with `static-challenge` the setting is not used, because the static challenge already carries the code.

**How it works (OpenVPN).** The WinVPN Service starts `openvpn.exe` with its management interface on the computer's own loopback address, and before it sends the management password it checks that the program answering is that `openvpn.exe`. Only the service talks to it, with a fixed list of commands. The service passes only the question, the `https` address and the state to the app (over its channel, only to your user account), and your answer back to OpenVPN.

### 5.3 Credentials asked when connecting

If a connection needs a user name, password, shared secret (PSK) or private key password that is not saved in WinVPN, WinVPN asks for it in a small **Credentials needed** window before it connects. Nothing has to be set up for this.

- **When it appears:**
  - **OpenVPN:** the config has `auth-user-pass` without a file and without an inline `<auth-user-pass>` block, and the user name or password is not saved. An encrypted private key whose password is not saved.
  - **IKEv2:** EAP sign-in (`auth = eap…` in the `local` section) and the user name or password is not saved.
  - **SSTP:** the password is not saved (the user name is in the connection's settings).
  - **L2TP/IPsec:** the account, the password or the shared secret is not saved.
  - **WireGuard,** IKEv2 with a computer certificate, and **system VPNs** never ask WinVPN's window: for a system VPN, Windows uses its own saved credentials or opens its own sign-in window (see [3.5](#35-system-vpns-your-own-windows-vpns)).
- **The window** shows only the missing fields. A saved user name is filled in. **Save in vault** is ticked (**Kept encrypted in the WinVPN vault, used from the next connect on**). Untick it to use the values for this connect only. If the connection uses a shared credential without a saved password, the window names it (**Password for Office AD — used by 4 connections**), and **Save in vault** stores the password in the shared credential, for every connection that uses it.
- **Save happens only after the connection is up.** A wrong password is never stored.
- **Wrong user name or password:** if the server rejects the sign-in (OpenVPN `AUTH_FAILED`, SSTP and IKEv2 with EAP: **Authentication failed (wrong user name or password)** / **Authentication failed (EAP)**), the window opens **once** more with **Sign-in failed — check the username and password** and the user name filled in. A second failure ends with the normal error and notification. L2TP/IPsec does not ask again (as in MacVPN); its error says the sign-in failed.
- **Cancel** (or Escape, or closing the window) stops the connect without an error or a notification. Disconnecting while the window is open closes it. It expires after 2 minutes, which counts as Cancel.
- **Like the code window,** it does not take the keyboard away from the app you are using: click the window or the "…: credentials needed" notification to type. It ignores input for about a second after it appears, and it has no default button: Enter does nothing, so click **Connect**. While it is open, the row shows **Waiting for authentication**.
- **Known limitation:** the password of a private key in a PKCS#12 bundle (`<pkcs12>`) is not asked for, because WinVPN cannot tell whether the bundle has one. Save it in the connection's editor (**Private key password**).
- What you type goes to the VPN engine for this connect. WinVPN wipes its own copies after use; copies the system makes on the way (the web view and the app's internal messaging) cannot be wiped by WinVPN. What you type is never written to the log, and never appears on a command line. A control-API client only sees the state `waiting_for_credentials`, and `credentials_cancelled` if you cancel.

### 5.4 Paired apps (control API)

Another program of your user account, for example a Remote Desktop app, can bring WinVPN connections up and down for you once you pair it. This is off by default.

1. Open the **Connections** window (**Manage Connections…**) and select **Paired apps** in the sidebar.
2. Turn on **Allow other apps to control VPNs**. While it is off, no program can reach WinVPN this way.
3. Start the pairing in the other program. WinVPN shows the **Allow an App to Control VPNs?** window with **Name (self-reported)** (the program chose it, so it proves nothing), the full path of its **Executable**, and **Connections it may use**, a checkbox per connection, none ticked. Check the path, tick the connections, and click **Allow**. **Deny**, closing the window, or 2 minutes without an answer refuses.

A paired program sees only the connections you allowed, and can only ask to bring them up and down (with the same code and credential windows as a manual connect); it never sees configs, user names or passwords.

On Windows the programs reach WinVPN through a named pipe of your user account (`\\.\pipe\WinVPN-control-<your user SID>`). Windows lets only programs running in your own desktop session as you connect to it: not other users, not the network, and not your own account over a remote shell such as SSH. WinVPN identifies each program by its user account and its executable path. Details for developers: [Control API guide, Windows](control-api.md#11-windows-winvpn).

In **Paired apps** every program is listed with its executable path, **Last used** (or **Never used**), **Paired:** and its **Allowed connections**, which you can change any time. **Revoke** unpairs it at once. If the program is moved or rebuilt to another path, it shows **Path changed** and must be revoked and paired again. **Activity** lists the recent pairings, logins and leases.

### 5.5 Reconnect automatically

When a connection goes down because the PC slept or the network went away, WinVPN can connect it again by itself, with exactly the rules of [MacVPN's automatic reconnect](user-guide.en.md#55-reconnect-automatically), for every type WinVPN connects itself (the Windows VPN client's types too; system VPNs are never reconnected):

WinVPN checks, in this order:

1. **None of the VPN's own networks is directly reachable there** (its routes, WireGuard `AllowedIPs` and OpenVPN `route` lines and pushed routes, without the "send everything" routes, and its DNS servers). This is checked first, so the office network stops a reconnect even behind a new router. L2TP, IKEv2 and SSTP have no such list, so only rule 2 applies to them.
2. **The same network** as when the connection came up: the router's address and hardware address, and the Wi-Fi name where Windows tells it. Windows 11 24H2 and later show the Wi-Fi name only to apps with location permission; WinVPN does not ask for it, so usually the router's hardware address decides. A network that cannot be identified means no reconnect (**The network could not be identified.**).

Example: "Office VPN" routes the office network 10.20.30.0/24. Brought up at home, it comes back after sleep at home. In the office, where the PC is on 10.20.30.0/24, it stays down (**Office VPN not reconnected** / **The VPN’s network is directly reachable here.**). On another network where nothing of the VPN is local (a café), it stays down with **You are on a different network.**


- It runs for a connection that was up before sleep and is down after waking (or drops within 3 minutes), and for a drop while the network is gone or within a minute after a network change; up to 3 attempts (at once, after 10 s, after 30 s).
- **Never reconnected:** a connection you disconnected (also by quitting WinVPN or signing out), a failed connect you started, a refused sign-in or certificate, a cancelled code or credential window. A locked vault means no reconnect (**Unlock the vault to reconnect.**).
- **Tunnels that survive the sleep** (OpenVPN's `ping-restart`, WireGuard, and the Windows VPN client, which redials a dropped connection itself): after waking on a network where the VPN's networks or DNS servers are directly reachable (the office), WinVPN disconnects such a tunnel and tells you why (**The VPN’s network is directly reachable here, so it was disconnected.**); on any other network (a café) it stays up. It is then not reconnected automatically until you connect it again.
- **The switch:** **Reconnect Automatically** in the connection's details in the Connections window (on by default), kept on this PC only.
- **Modern Standby:** on PCs that sleep with Modern Standby, Windows may not tell apps that it went to sleep; WinVPN then relies on the network coming back after waking.

### 5.6 DNS while connected

- **WireGuard** sets its `DNS =` servers only on its own adapter; the adapter and its settings go away when the connection ends, also when something crashes. Nothing else of your network settings changes.
- **OpenVPN** applies the DNS the server pushes to its own adapter (TAP-Windows6 through its DHCP, DCO with a setting OpenVPN removes when it disconnects). OpenVPN's `dns` directive (Windows' name resolution policy) is not used on Windows: a server that pushes DNS only that way gives no DNS on a DCO connection. Ask the server's administrator to push `dhcp-option DNS` too.
- **L2TP/IPsec, IKEv2, SSTP and system VPNs:** Windows applies the server's DNS to the VPN adapter itself (SSTP's **Use the server's DNS** off: see [3.6](#36-sstp)).
- So unlike older MacVPN versions, nothing has to be reset by hand after a crash or a restart.

### 5.7 Quitting, signing out and sleep

- **On quit** (**Quit WinVPN** in the popover, and also when you sign out, restart or shut down Windows), WinVPN first asks about unsaved changes in the Connections window (**Save**, **Discard** or **Cancel**). Then, if a connection is active, it asks: **Disconnect and Quit**, **Quit, Keep Them Running** or **Cancel**. When you sign out or shut down, Windows waits for your answer and shows **Closing WinVPN…** in its list of apps that hold up the sign-out; **Cancel** keeps WinVPN running.
- **Connections that keep running** after a quit (OpenVPN and WireGuard in the WinVPN Service, the others in Windows' VPN client) are shown as connected again at WinVPN's next launch.
- **Signing out ends your connections:** the WinVPN Service takes down your OpenVPN and WireGuard connections; Windows hangs up the L2TP/IPsec, IKEv2 and SSTP ones, and WinVPN makes sure of it (also when an administrator told Windows to keep VPN connections across a sign-out). Locking the screen or switching users keeps them.
- **Closing a window** does not quit WinVPN: it keeps running in the notification area.
- **After sleep**, WinVPN refreshes its state, checks its team catalogs (see [16.4](#164-refresh-and-updates)) and may reconnect (see [5.5](#55-reconnect-automatically)).

---

## 6. Debug mode and the log

If a connection does not come up, debug mode shows what happened, step by step.

**To start it:**

- in the popover, **Alt + click** the switch (**Alt-click a switch: debug mode**), or
- in the Connections window, the **Connect in Debug Mode** button.

The **Log** tab then opens automatically and follows the events live. Debug mode applies to this one connection attempt only.

In debug mode:

- **OpenVPN:** more verbose output (`--verb 5`): the TLS handshake, the settings pushed by the server, routes, DNS.
- **WireGuard:** after connecting, the peer status (as MacVPN's `wg show`: endpoint, allowed IPs, latest handshake, bytes received and sent; never a key) under `▶ [WinVPN] WireGuard peer status (…)`.
- **OpenVPN and WireGuard:** **diagnostics** before and after connecting (`▶ [WinVPN] diagnostics (before)` / `(after)`): the server name's resolution, the IPv4 routes, DNS and the network interfaces.
- **L2TP/IPsec, IKEv2, SSTP:** the Windows VPN entry WinVPN wrote, under **Windows VPN entry (debug mode):** (type, server, sign-in, routing, the IPsec proposal for IKEv2; never a password or a PSK), then every dial step as always.

**What is logged, per type:**

- **OpenVPN and WireGuard:** the WinVPN Service's log of the connection (`C:\ProgramData\WinVPN\logs\<ID>.log`, readable only by administrators and the system): OpenVPN's own output, the management steps as `[mgmt] …`, WinVPN's own notes as `[WinVPN] …` (for example the switch to TAP-Windows6), and the WireGuard service steps.
- **L2TP/IPsec, IKEv2 and SSTP:** WinVPN's own log of the dial (`%LOCALAPPDATA%\WinVPN\logs\ras\<ID>.log`), also outside debug mode: **Connecting to vpn.example.com…**, **Authenticating…**, **Authenticated**, **Projecting (IP configuration)…**, **Connected, IPv4 10.20.30.6**, and on an error a `✗` line with WinVPN's explanation plus `Windows error <code>: <Windows' own text>` (Windows' text is in Windows' display language). Unlike MacVPN, these types have a log on Windows even without debug mode.
- **System VPNs** have no log in WinVPN (Windows dials them; WinVPN shows the error Windows reported).

**Log lines, colour-coded:**

| Prefix | Meaning |
|---|---|
| `═══` | start of a new connect (with the date and time) |
| `▶ [WinVPN]`, `[WinVPN]`, `[mgmt]` | WinVPN's own steps (the service, its diagnostics, the OpenVPN management channel) |
| `✗` | an error |
| other | the engine's own output (openvpn, wireguard-nt) or the Windows VPN client's dial steps |

**The Log tab** shows the last 5000 lines of the connection's log and follows it live, also outside debug mode.

**Log size.** An OpenVPN or WireGuard log is at most 8 MiB: when it is full, it becomes the older part `<ID>.log.1`, a new log starts with a line that says so (**The log reached its size limit; its earlier part is in …**), and the **Log** tab starts over. A new connect removes the older part. OpenVPN runs with `--mute 20`, so a message repeated many times in a row (for example `Network is unreachable` while the network is gone) is written only 20 times followed by a count. An L2TP/IPsec, IKEv2 or SSTP log starts again at each connect and is at most 1 MiB plus an older part of 1 MiB.

**Log actions:** filters (**All**, **Commands**, **Errors**), **Search**, **Follow** (auto-scroll), **Copy** (copies the filtered lines), **Save…** (saves the log as `<name>-log.txt`, readable only by you). Passwords, PSKs, one-time codes and private keys never appear in the log, so you can share a saved log (for example with your network administrator).

---

## 7. Troubleshooting from the log

First read the error message in the popover or the notification. If that is not enough, connect in debug mode and search the **Log** tab (the **Errors** filter shows only the error lines). The messages below are the English ones; with Hungarian as the Windows display language, WinVPN shows them in Hungarian.

### 7.1 `AUTH_FAILED` (OpenVPN)

Message: **Authentication failed (AUTH_FAILED)**. The server rejected the username or password.

- Check the **Username** and **Password** fields, then press **Save**.
- If the account has expired or is locked, contact your provider.
- If the server asks for a one-time code, see [5.2](#52-multi-factor-authentication-mfa) and [7.11](#711-one-time-code-and-sign-in-in-the-browser-mfa).

### 7.2 `TLS handshake failed` / `TLS Error` (OpenVPN)

The encrypted channel was not established. A typical line: `TLS Error: TLS key negotiation failed to occur within 60 seconds`.

- Wrong server address, port or protocol (`proto udp` or `tcp`). Compare with your provider's details.
- A firewall, or a hotel or corporate network, blocks the port. Try from another network.
- A mismatched `<tls-auth>` or `<tls-crypt>` key or `key-direction`, or a wrong `<ca>`. Import a fresh `.ovpn` from your provider.

### 7.3 Timeout

Message: **Timed out: the connection was not established within 30 s** (OpenVPN, WireGuard), **Timed out** (L2TP/IPsec, IKEv2, SSTP: WinVPN waits up to 150 seconds, then hangs up). The connection did not come up in time, so WinVPN stopped it.

- Check your internet connection and whether the server is reachable.
- Look at the last lines of the log. The real cause is often there (for example a TLS error or an unreachable server).

### 7.4 No WireGuard handshake

The WireGuard connection looks green (the adapter exists), but no traffic flows.

- Wrong `Endpoint` (address or port), or the network blocks UDP.
- The `PublicKey` in `[Peer]` is not the server's key, or your public key is not registered on the server.
- `AllowedIPs` does not cover the target network.
- Disconnect, fix the config, and connect again.
- **Cannot create the WireGuard adapter (…)** or **Cannot configure the WireGuard adapter: …**: the WinVPN Service could not set up the adapter; the details are in the log. If **wireguard.dll does not match its pinned version. Repair WinVPN.** appears, repair WinVPN in Installed apps.

### 7.5 OpenVPN drivers (DCO and TAP-Windows6)

- **This connection needs the TAP-Windows6 driver. Repair OpenVPN Community in System Status.** (or the DCO driver): the driver is not installed. **Repair** on the OpenVPN row adds it (see [1.4](#14-openvpn-community)). The Windows message **Add the DCO and TAP-Windows6 drivers in Settings → Apps → Installed apps → OpenVPN → Modify.** means WinVPN could not add them itself (an OpenVPN that WinVPN did not install).
- `[WinVPN] DCO cannot run this connection (pushed options); retrying with TAP-Windows6` in the log: the server pushed a setting DCO cannot run (compression, an older cipher). WinVPN retried once with TAP-Windows6; nothing to do, but ask the server's administrator to turn compression off.
- A second TAP-Windows6 connection while one is up fails: there is one TAP-Windows6 adapter. Disconnect the first one.
- **openvpn.exe is not signed by OpenVPN Inc.** / **openvpn.exe is in a folder other users can change: …** / **OpenVPN Community … is too old (2.6.0 or newer is needed).**: the installed OpenVPN failed the service's checks. Use **Repair** or **Update** in System Status, or reinstall OpenVPN Community from the official installer into `C:\Program Files`.

### 7.6 Windows VPN client errors (L2TP, IKEv2, SSTP)

WinVPN turns the Windows error code of a failed dial into a sentence that says what to do; the log has the code and Windows' own text (`Windows error 809: …`). The common ones:

| Windows error | Message | What to do |
|---|---|---|
| 691 | **Authentication failed (wrong user name or password)** | Check the user name and password; WinVPN asks once more for SSTP and IKEv2 (see [5.3](#53-credentials-asked-when-connecting)). |
| 13801 | **Authentication failed (EAP)** (IKEv2 EAP); **The server did not accept the computer certificate.** (IKEv2 certificate) | Check the EAP user name (`eap_id`) and password; for a certificate, ask the administrator which certificate the server expects. |
| 13806 | **No computer certificate for IKEv2 was found. An administrator must import it (see the user guide).** | Import the certificate (see [3.7](#37-administrator-steps-for-native-vpns)). |
| 789 | **The IPsec negotiation with the server failed. Check the pre-shared key and the server’s IPsec settings, or the server did not answer (check the address and that UDP 500/4500 reach it).** | Check the PSK, the address and that UDP 500 and 4500 reach the server (a silent server ends this way after about a minute). |
| 766 (L2TP) | **Windows has no pre-shared key for this connection. Save it again and reconnect.** | Open the connection, enter the PSK, **Save**, connect again. |
| 809 | **The server did not answer on the VPN ports. A firewall may block them, or the server is behind NAT: Windows allows that for L2TP/IPsec only after Allow L2TP Behind NAT… (an administrator confirms).** | For L2TP/IPsec: click **Allow L2TP Behind NAT…** in the error, let an administrator confirm, restart Windows (see [3.7](#37-administrator-steps-for-native-vpns)). Otherwise check the firewall. |
| 812 | **The server’s policy refused the connection (for example the authentication method). Ask your VPN administrator.** | Ask your VPN administrator. |
| 13868 | **The server accepted none of the IPsec proposals WinVPN offered (…).** | The server wants other algorithms: set `proposals` / `esp_proposals` to ones both sides support (see [3.3](#33-ikev2-strongswan)). |
| 868 | **The server’s name could not be resolved. Check the server address and your network’s DNS.** | Check the server name. |
| 800, 815 | **The server did not answer. Check the server address and your network connection.** | Check the address and the network. |
| 720, 734 | **The PPP negotiation with the server failed. Ask your VPN administrator which authentication and encryption the server needs.** | The server wants another sign-in (WinVPN uses MS-CHAPv2). |
| 619, 628 | **The server closed the connection before it was complete.**; for IKEv2: **The server did not answer or closed the connection.** | Check the address, that UDP 500 and 4500 reach the server, and the log. |
| 0x8007274C (SSTP) | **The server did not answer on its port. Check the server address and your network connection.** | Check the address and the port (443 or the one set). |
| 633 | **Windows is still closing the previous connection. Try again in a moment.** | Wait a few seconds and connect again. |
| 756 | **This connection is already being dialled.** | Wait for the running attempt. |
| 631 | **The connection was cancelled.** | You disconnected. |
| other | **Windows error … (see the log)** | Look up the code in the log; connect in debug mode and send the log to your administrator. |

Other messages of these types:

- **This connection is already connecting.**: wait for the running attempt or disconnect first.
- **Save this connection again: its Windows VPN entry is missing or damaged.**: open the L2TP connection and click **Save**.
- **WinVPN's folder … is not a private folder of this user. Delete it, then start WinVPN again.**: a folder under `%LOCALAPPDATA%\WinVPN` (`ras` or `logs`) belongs to someone else or is a link; delete it and start WinVPN again (it recreates it).
- **The Windows service … is disabled. An administrator must set it to Manual (services.msc).**: see [1.5](#15-wireguard-and-the-windows-vpn-client).
- **System VPN:** **This Windows VPN no longer exists. It may have been removed in Settings → Network & internet → VPN.**; a cancelled Windows sign-in window ends with **The connection did not come up.**

### 7.7 "Directive not allowed" / "Forbidden directive"

You get these errors on **Save** or when connecting, for example:

- `Line 3: Forbidden directive: up – delete the line or comment it out (#)`
- `Line 5: Risky directive, acknowledgement required: user` (the setting is in the yellow **Risky settings** panel)
- When connecting: `Risky settings are not acknowledged: user. Open the connection in WinVPN → Connections and tick the checkbox under Risky settings.`
- `Line 7: External file reference, use an inline block: ca`
- WireGuard: `Line 4: Forbidden key: postup`, `Line 6: Key not allowed: …`
- IKEv2: `Line 2: Forbidden: include`, `Line 9: Forbidden key: updown`, `Line 6: Only a file name is allowed, no path: cacerts`
- Arguments: `Line 4: Invalid argument: dev`, `Line 8: Wrong number of arguments: keepalive`, WireGuard `Line 3: Invalid value: address`
- OpenVPN: `Line 12: Line too long`, `Line 9: setenv not allowed: SystemRoot – delete the line or comment it out (#)`

The WinVPN Service runs OpenVPN with system rights, so WinVPN only allows known, safe settings. To fix:

- **Forbidden directive / key** (for example `up`, `down`, `script-security`, `PostUp`, and on Windows `cryptoapicert`, `windows-driver`, `win-sys`): these would run external commands or let the config reach what only the system should. Delete the line or put `#` in front of it. WinVPN handles DNS, routes and the driver itself.
- **Risky directive, acknowledgement required / Risky settings are not acknowledged:** read the reason in the yellow panel; if you want the setting, tick **I acknowledge these settings and the security risks** and **Save**, otherwise comment the line out.
- **Invalid argument / value, wrong number of arguments:** the setting is allowed, but its value is not in the expected form. The message names the setting, not the value.
- **External file reference:** a certificate refers to a file (`ca ca.crt`). Import the `.ovpn` again with the referenced files next to it, or paste their contents into a `<ca>…</ca>` block.
- **Control character not allowed**: the file contains an invisible character. Retype the line.
- **Line too long**: the line is longer than 255 bytes. A certificate or key in an inline block normally has 64-character lines; re-export it from its source, or split the line. A config made for another program may have long comment lines: shorten or delete them.
- **setenv not allowed**: on Windows only the `setenv` names listed in [3.1](#31-openvpn) are allowed. Delete the line, or ask your provider whether the setting is needed.

### 7.8 The WinVPN Service and other messages

- **The WinVPN Service is not reachable.** / **The WinVPN Service is missing or from another WinVPN version. Repair WinVPN: …**: OpenVPN and WireGuard cannot connect. An administrator can check it with `sc.exe query WinVPN` (it should be `RUNNING`) and start it with `sc.exe start WinVPN`, or repair WinVPN in Installed apps. L2TP/IPsec, IKEv2, SSTP and system VPNs keep working.
- **The folder C:\ProgramData\WinVPN has unsafe permissions. An administrator must delete it, then restart the WinVPN Service.**: see [1.3](#13-the-winvpn-service).
- **Only a WinVPN installed in Program Files can install OpenVPN Community.**: you run a development build; install WinVPN with its MSI.
- **The OpenVPN installer could not be downloaded: …** / **The OpenVPN installer failed (…).**: the installation did not finish; nothing was changed. Try again later, or install OpenVPN Community from openvpn.net yourself.
- **OpenVPN's Interactive Service could not be disabled.**: OpenVPN was installed, but the second administrator prompt was declined; OpenVPN works anyway.
- **Updating WinVPN disconnects active VPN connections.**: shown before an update (see [8](#8-updates)).
- **`cert` and `key` pointing to the same file** (a combined PEM file: certificate plus private key, possibly encrypted, also with Windows line ends): supported. WinVPN puts only the certificate blocks into `<cert>` and only the key into `<key>`, and asks for the **Private key password** when you connect.

### 7.9 SSTP and IKEv2: certificate errors

- **The server’s CA is not trusted by Windows. Use Trust This CA in Windows… in the editor.**: SSTP with **Custom CA file** before the CA was trusted (see [3.6](#36-sstp), [3.7](#37-administrator-steps-for-native-vpns)).
- **The server’s certificate is not issued by a CA Windows trusts. Ask your VPN administrator.**: with **System CA** (or IKEv2): the issuing CA is not in the computer's trusted roots. Ask for the CA certificate and trust it, or use **Custom CA file**.
- **The server’s certificate does not match the server address. Use the name in the certificate as the server address.**: connect by the name in the certificate, not by an IP address or another alias (IKEv2: `remote_addrs`).
- **Windows could not check whether the server’s certificate was revoked (the revocation server is unreachable).**: the server's revocation list (CRL) cannot be reached from your network. Ask your VPN administrator.
- Expired certificate, or the clock of the PC is wrong.

### 7.10 Sign-in failed (L2TP, IKEv2, SSTP)

Message: **Authentication failed (wrong user name or password)** (Windows error 691) or **Authentication failed (EAP)** (IKEv2, 13801).

- Check **Username** and **Password**, then **Save**. A Windows domain account is written as `user@domain` (not `DOMAIN\user`).
- The server must allow MS-CHAPv2 (L2TP, SSTP) or EAP-MSCHAPv2 (IKEv2). If it only accepts certificate sign-in (EAP-TLS) or PAP, WinVPN cannot connect to it.
- With the one-time code appended to the password, check the **Separator** your provider expects.

### 7.11 One-time code and sign-in in the browser (MFA)

- **Authentication was not completed in time**: no code was entered within 2 minutes, or the sign-in in the browser did not finish within the time limit (at most 5 minutes). Connect again and answer sooner.
- **Authentication cancelled**: you clicked **Cancel** in the code or browser window, or disconnected.
- **Authentication failed**: the server rejected the code or the password. Codes expire quickly: use a fresh one. With the code appended to the password, check the **Separator** your provider expects.
- **No browser window appears**: WinVPN opens only `https://` addresses with a plain ASCII host name (international names only in their `xn--` form, no `%` or `@` before the path). The log then shows `web authentication URL dropped (only https with a plain ASCII host is accepted)`. Ask your provider for such a sign-in address.
- **The management connection to OpenVPN failed**: the WinVPN Service could not reach OpenVPN's management interface. Connect again; if it repeats, connect in debug mode and check the `[mgmt]` lines.
- **No connection is waiting for authentication**: the attempt had already ended (time limit or error) before your answer arrived. Connect again.
- The `[mgmt]` lines in the log are the service's steps (for example `hold released`, `credentials sent`, `dynamic challenge received`). They never contain the code or the password, and for a sign-in address only its host is logged.

### 7.12 The reasons in notifications

A notification about a drop or a failure (see [2.3](#23-notifications)) gives one of these reasons. WinVPN takes it from the last matching line of the connection's log; open the **Log** tab and search for the text in the middle column.

| Reason | Log lines behind it (examples) | Automatic reconnect |
|---|---|---|
| **The server stopped responding.** | `Inactivity timeout (--ping-restart)`, `Inactivity timeout (--ping-exit)` (OpenVPN), `peer not responding` | tried |
| **The server could not be reached.** | `TLS key negotiation failed`, `Connection refused`, `Connection timed out`, `Windows error 800:`, `809:`, `815:`, `0x8007274C:` | tried |
| **The server’s name could not be resolved.** | `Cannot resolve host address`, `Windows error 868:` | tried |
| **The server refused the sign-in.** | `AUTH_FAILED`, `Windows error 691:`, `Windows error 13801:` | not tried |
| **A certificate was not accepted.** | `VERIFY ERROR`, `certificate verify failed`, `Windows error 13806:`, `Windows error 0x800B0109:`, `0x80092013:`, `0x800B010F:` | not tried |
| **The network connection was lost.** | `Network is unreachable`, `No route to host` | tried |

Anything else gives **Click to see the log.** (**Open WinVPN for details** for a failed connect). The reason is only a hint: the sections above explain each error in full.

---

## 8. Updates

WinVPN looks for new versions on the GitHub Releases page: at launch, then once every 24 hours. This works in the installed WinVPN (not in a development build).

- When a newer version exists, the popover shows **Update available: vX.Y.Z**. Clicking it opens the **Update** window with the release notes and the installed version. **Later** closes it; **Open the Release on GitHub** opens the release page.
- The **Download and Install** button:
  1. downloads the MSI for this PC's processor (`WinVPN-X.Y.Z-x64.msi` or `-arm64.msi`), its `.sha256` file and its `.sig` signature, verifies the SHA-256 checksum, and checks that the signature was made by the maintainer's offline key for exactly this version and this installer file. If the signature is missing or not valid, it stops with **The update is not signed by the WinVPN maintainer** and installs nothing;
  2. asks about unsaved changes and active connections, just like quitting (**Updating WinVPN disconnects active VPN connections.**: the installer restarts the WinVPN Service);
  3. asks for an **administrator's confirmation** (as the first installation did; a standard user needs an administrator's password), then quits; Windows Installer updates WinVPN and the WinVPN Service, and WinVPN starts again by itself.
  The window shows each step (**Downloading…**, **Preparing the installation…**, **Quitting and restarting…**). If anything fails before the quit, the installed version stays and WinVPN keeps running. Declining the administrator prompt cancels the update.
- **Signed updates:** every release is signed by the maintainer with an Ed25519 key that is kept offline, never on GitHub; the signature names the installer file, so a signature for another product or processor never verifies. WinVPN only offers a release that has a signature file. A newer release that is not signed yet is not offered; **Check for Updates Now** then says **Update waiting for signature**.
- **Settings** in the popover: **Check for Updates Now** (if you are up to date: **WinVPN is up to date**), **Check for Updates Automatically**, and **Only Offer Updates Published at Least 24 Hours Ago** (off by default; gives time for a bad release to be noticed and removed before you install it).
- **The VPN engines** (OpenVPN Community, wireguard-nt) are updated separately, without a WinVPN release (see [2.5](#25-updating-openvpn-and-wireguard)); the Windows VPN client by Windows Update.
- The installer logs are kept for a week in `%LOCALAPPDATA%\WinVPN\updates` (`msiexec-<version>.log`). If an update failed, WinVPN shows a one-time notice at the next launch with the log's path; the installed version stays in place.

### 8.1 Upgrading from the 1.5 preview

WinVPN 1.5.0 could not check for updates, so install 2.0 once by hand: an administrator double-clicks the 2.0 MSI (see [1.1](#11-the-installer)). It updates the preview in place (one WinVPN in Installed apps) and adds the WinVPN Service. Your vault, connections and settings stay. Then:

1. Open **System Status**: install OpenVPN Community if you use OpenVPN (see [1.4](#14-openvpn-community)).
2. Your L2TP/IPsec connections get their Windows VPN entry when the vault is unlocked; IKEv2 and SSTP at their first connect. Check the greyed connections for their reason (for example Cisco IPsec, IKEv2 with a PSK).
3. From now on WinVPN updates itself (see [8](#8-updates)).

---

## 9. Uninstalling

WinVPN is uninstalled through Windows (Installed apps). Because each user also has WinVPN data and Windows VPN entries in their own account, **System Status** offers a clean-up for your account first.

### 9.1 Remove WinVPN from This Account

**System Status** → **Remove WinVPN from This Account…** (under the note **Uninstall WinVPN in Windows: …**). The confirmation lists what is removed:

- **Launch at Login**;
- **WinVPN's Windows VPN entries and the pre-shared keys Windows keeps for them** (every `WinVPN-…` entry, also those of connections a locked vault did not list);
- with **Also delete user data (connections, the vault and its key)** ticked: your connections and passwords (`%LOCALAPPDATA%\WinVPN`, with the logs and the preferences) and the vault key in Credential Manager (`local.winvpn.vault`).

Active connections are disconnected first. **Your own Windows VPNs are kept** (WinVPN never touches them). Click **Remove**: WinVPN says **WinVPN has been removed from this account**, and Settings → Apps → **Installed apps** opens. Then:

1. Quit WinVPN (**Quit WinVPN** in the popover).
2. In **Installed apps**, find **WinVPN**, choose **Uninstall** (an administrator confirms). The program, the WinVPN Service, `wireguard.dll` and the Start-menu entry are removed.

If other Windows users of the PC used WinVPN, each of them should run **Remove WinVPN from This Account…** in their own account before the program is uninstalled.

If you keep your data (box unticked) and install WinVPN again later, the vault opens as before; open each L2TP/IPsec connection once and click **Save** to write its Windows VPN entry again.

### 9.2 What stays after uninstalling

- **OpenVPN Community**, its DCO and TAP-Windows6 drivers and its TAP adapters: they belong to OpenVPN. Remove **OpenVPN** in Installed apps if you no longer need it. If WinVPN installed it, its Interactive Service stays disabled.
- **`C:\ProgramData\WinVPN`**: the masked connection logs of OpenVPN and WireGuard, `service.log`, and a wireguard-nt the service downloaded. An administrator may delete the folder.
- **Your data**, if you did not tick **Also delete user data**: `%LOCALAPPDATA%\WinVPN` and the `local.winvpn.vault` credential (Control Panel → User Accounts → Credential Manager → Windows Credentials). Deleting both by hand is the same as the box.
- **Backup files** you made with **Back Up Everything…**: delete them yourself if you no longer need them.
- **Without the clean-up** (for example the program was uninstalled first): WinVPN's phonebook stays in `%LOCALAPPDATA%\WinVPN\ras` with the PSKs Windows keeps for its entries. They do nothing (Windows does not list or dial them), but to remove them install WinVPN again and run **Remove WinVPN from This Account…**, or delete the folder; a VPN connection that is still up stays up until you sign out. Disconnect before uninstalling.

---

## 10. Security notes

**What WinVPN protects, and what not.** WinVPN keeps your connections and their passwords in an encrypted vault (see [11](#11-vault)), in a folder only you can read. It does **not** protect against programs already running in your Windows account: such a program can read what you can read.

- **Unlock automatically and Credential Manager.** With **Unlock automatically** on (the default), the vault key is kept in Windows Credential Manager as the generic credential `local.winvpn.vault`. Windows encrypts it for your Windows account (DPAPI) and keeps it on this PC only (it never roams to another PC).
  - *It protects against:* other users of this PC, and someone who takes the disk (or a copy of `%LOCALAPPDATA%\WinVPN`) without your Windows password.
  - *It does not protect against:* malware running as you. Credential Manager has no per-app access control: any program running in your Windows account can read the vault key, and with it the vault. (On macOS the Keychain releases the key only to MacVPN's own code signature; Windows has no such check.)
  - If that is not acceptable for you, turn **Unlock automatically** off (see [11.2](#112-unlock-automatically)): the key is deleted from Credential Manager, and WinVPN asks for the master password at every launch.
- **Your data folder.** `%LOCALAPPDATA%\WinVPN` and every file in it get an access list that lets in only your user and SYSTEM (the operating system itself, which backup and antivirus software use); Administrators are not listed, though an administrator can still take ownership deliberately. WinVPN refuses a vault file whose access list is wider.
- **The WinVPN Service.** It accepts requests only from programs on this PC, and before the app sends anything it checks that the channel really belongs to the system (so a program that took the name first never receives a password). Every request is tied to the Windows user who sent it: one user can never see, end or read another user's connections. It runs only an `openvpn.exe` signed by OpenVPN Inc. from an administrators-only folder, and only a `wireguard.dll` signed by WireGuard LLC; OpenVPN settings that would let a config run programs or read files with system rights are forbidden (see [3.1](#31-openvpn)). It never changes certificates or Windows settings for a user.
- **Secrets never on a command line or in a log.** Passwords, PSKs and one-time codes reach OpenVPN over a private file or the management channel, WireGuard keys go to the driver directly, and the Windows VPN client gets the password at dial time only. The one exception is the L2TP/IPsec **pre-shared key**, which Windows can only take from its own encrypted VPN credential store: WinVPN puts it there for its own entry (see [3.8](#38-where-winvpn-keeps-the-native-vpns)) and removes it with the entry. Every log line is masked.
- **Administrator steps** (trusting a CA, allowing L2TP behind NAT) are always shown first and need an administrator's confirmation; trusting a CA lets every program of the PC trust it, so do it only for your organisation's VPN CA (see [3.7](#37-administrator-steps-for-native-vpns)).
- **The open vault in memory.** While the vault is open, its key and the decrypted pages are in WinVPN's memory, and WinVPN wipes that memory when it frees it. Keeping those pages out of the pagefile is best effort on Windows (Windows lets a program lock only a small amount of memory): like macOS' swap, the pagefile can receive some of them. To protect the pagefile on a stolen disk, use BitLocker (or another full-disk encryption) on the system drive, or encrypt the pagefile (`fsutil behavior set EncryptPagingFile 1`, as an administrator).
- **Unsigned installer.** The MSI is not Authenticode-signed (see [1.2](#12-smartscreen)). Only download it from the official place. Updates installed by WinVPN itself are checked against the maintainer's offline Ed25519 signature, bound to the installer's name, version and processor type (see [8](#8-updates)).
- **Engine updates** are trusted by their publishers' signatures (OpenVPN Inc., WireGuard LLC) and never install an older version (see [2.5](#25-updating-openvpn-and-wireguard)).
- **Downloaded files.** A file Windows marked as downloaded is imported only after a question (see [4.1](#41-opening-vpn-files-from-file-explorer)).
- **Secrets on the clipboard.** The recovery key, a team key and a subscription string are copied so that they stay out of the Windows clipboard history (Win+V) and cloud clipboard sync, and clipboard monitors are asked to skip them. WinVPN clears the clipboard after 60 seconds, at **Lock Now** and at quit, unless you copied something else meanwhile.
- **Paired apps.** Off by default; only programs in your own desktop session can reach the control pipe (see [5.4](#54-paired-apps-control-api)). Details: [Control API guide](control-api.md#4-security-model).
- **Backups.** A file made by **Back Up Everything…** contains every secret, encrypted with the backup password. Anyone with the file and its password can read all your VPN credentials: keep the two apart. See [14](#14-backup-and-restore).
- **Team catalogs.** See [16.11](#1611-security-model).
- **Third-party licences.** WinVPN is MIT-licensed ([LICENSE](../LICENSE)). `C:\Program Files\WinVPN\THIRD-PARTY-NOTICES.txt` lists the licences of the components it ships, among them SQLCipher (BSD-style, © Zetetic LLC), OpenSSL and wireguard-nt.

---

## 11. Vault

WinVPN keeps your connections, their configs, user names, passwords, PSKs and key passwords, the shared credentials, the folders and colours, the order and pins, the team catalogs and the paired apps in one encrypted file, the **vault**: `%LOCALAPPDATA%\WinVPN\vault.db`, with its key file `vault.keys` next to it. The whole database is encrypted; without the vault key nothing in it can be read, not even the connection names.

### 11.1 Master password and recovery key

The **Set Up the Vault** window opens on the first launch (later, while there is no vault, from the popover's **Set Up the Vault…** row).

1. **Set up the vault.** It explains the vault. On a new PC you can choose **Restore from backup…** here instead (see [14.3](#143-restore-on-a-new-pc)). Click **Continue**.
2. **Choose a master password.** At least 10 characters; a long phrase is easier to remember and harder to guess. A hint under the field rates it (**Too short**, **Weak — easy to guess**, **Fair**, **Strong**); weak passwords are allowed but not advised. Type it again in **Repeat the master password**. **Unlock automatically** is ticked (see [11.2](#112-unlock-automatically)). Click **Create Vault**.
3. **Your recovery key.** 24 letters and digits in six groups, like `7K2M-…-QX4T`. If you forget the master password, this key is the only way back into the vault. Write it down or keep it in a password manager: **it is shown only now**. **Copy** copies it (see the clipboard note in [10](#10-security-notes)). Click **I Saved It**.
4. **Check your recovery key.** Type the group the window asks for (**Type group 3 of your recovery key, counting from the left.**) and click **Confirm**.
5. **The vault is ready.** Click **Done**.

The window has no default button: Enter in a field does nothing, so click the buttons. The recovery key is not case-sensitive; `O` counts as `0`, `I` and `L` as `1`, and dashes and spaces are ignored.

### 11.2 Unlock automatically

- **On** (the default): the vault key is kept in Windows Credential Manager (`local.winvpn.vault`), so WinVPN opens without asking. Read what this protects against in [10](#10-security-notes).
- **Off:** WinVPN asks for the master password at every launch. To turn it off, open the popover's **Settings** and switch off **Unlock automatically**, then confirm with **Turn Off** (**Turn off automatic unlock?**). The credential is deleted from Credential Manager.
- **To turn it on again,** switch it on: the **Turn on automatic unlock** window asks for the master password; click **Turn On**.
- If the credential cannot be read (for example you deleted it in Credential Manager), WinVPN asks for the master password instead.

### 11.3 Unlocking

The **Unlock WinVPN** window opens at launch when the vault is not unlocked automatically, and from the locked popover's **Unlock…** row. Enter the **Master password** and click **Unlock**.

A wrong password shows **Wrong password or recovery key**. Each further wrong try makes the next one wait longer (1, 2, 4, 8, 16, then 30 seconds; the button shows **Try again in 8 s**). There is no lockout. If you forgot the password, click **Use recovery key** (see [11.8](#118-forgotten-master-password)).

### 11.4 Lock Now

**Lock Now** in the popover's footer locks the vault at once. It is shown when **Unlock automatically** is off, or when you switch on **Show “Lock Now”** in the popover's **Settings**.

Locking closes the vault and wipes its key from memory. It does **not** delete the credential in Credential Manager: with **Unlock automatically** on, the next launch opens without asking again. Unsaved changes in the Connections window are discarded, and the master password and recovery key windows close.

### 11.5 The locked popover

While the vault is locked, the popover shows only an **Unlock…** row (**WinVPN is locked**), the number of active connections, and **Quit WinVPN**.

Nothing that needs the vault works while it is locked: editing, importing, exporting, the folders (hidden, and they cannot be changed: **Folders cannot be changed while the vault is locked**), shared credentials, team catalogs and backups. Such actions answer **The vault is locked. Unlock it and try again.** Paired apps get the `locked` error.

### 11.6 Changing the master password

1. Popover → **Settings** → **Change Master Password…**.
2. Enter the **Current master password**, then the **New master password** twice.
3. Click **Change Password**. **The master password was changed**: use the new one from now on.

Your recovery key stays the same. The vault is not re-encrypted; only its password-wrapped key is rewritten. A wrong current password is slowed down like an unlock.

### 11.7 A new recovery key

If your recovery key may have been seen by someone, or you lost it while you still know the master password:

1. Popover → **Settings** → **New Recovery Key…**.
2. Enter the **Master password** and click **Make New Key**. The new key replaces the old one: the old key stops working at once.
3. Save the new key (it is shown only now), click **I Saved It**, type the group asked for, and click **Confirm**.

### 11.8 Forgotten master password

1. In the **Unlock WinVPN** window, click **Use recovery key**.
2. Type the **Recovery key**, then a **New master password** twice.
3. Click **Reset and Unlock**.

Your connections stay as they are, and the recovery key keeps working. **Use the master password** goes back to the password field.

---

## 12. Folders and colours

Folders group connections in the **Connections** window and in the popover. They nest to any depth.

### 12.1 Folders

- **Create:** toolbar **New** (+) → **New Folder**, or right-click a folder → **New Folder** (a subfolder), or right-click a connection or an empty area → **New Folder** (at the top level). The new folder is named "New Folder", and its name field is open: type the name and press Enter.
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

### 12.6 Folders in the popover

- Folders are rows you can open and close; WinVPN remembers which are closed.
- Nesting is shown by indentation, up to 3 levels; deeper folders work but are not indented further.

### 12.7 Searching connections

The **Search connections** field at the top of the **Connections** window's sidebar (**Ctrl+F**) filters the list as you type. Case and accents do not matter: "arvizturo" finds "Árvíztűrő". It looks at the connection's name, its type, its server (the host from the settings or the config, such as OpenVPN's first `remote`), its team catalog's name and the names of its folders. **↑** and **↓** move through the results, Enter opens the highlighted one, Esc clears the field (a second Esc leaves it). While a search is on, drag and drop is off. When nothing matches, **Clear Search** brings the whole list back.

---

## 13. Shared credentials

A **shared credential** is a named user name and password that several connections use, for example "Office AD". Change it once, and every connection that uses it signs in with the new one. Passwords are stored in the vault and never shown.

### 13.1 The Credentials section

Open the **Connections** window and select **Credentials** in the sidebar. Each credential shows its name, its user name (or **No user name**), **Password saved** or **No password saved: asked when connecting**, and **Used by 3 connections**.

- **Add Credential…** → **New Shared Credential**: **Name** (1 to 64 characters), **Username**, **Password**. The password is optional.
- **Edit…**: change the user name or password. The password field shows **Saved — type to replace**, as in the editors.
- **Rename…**: a new name; the links stay.
- **Delete**: a credential that no connection uses is deleted. If connections use it, WinVPN lists them and asks **Copy into Each Connection** (each gets the user name and password as its own, then the credential is deleted) or **Cancel**.

### 13.2 Create from a connection

1. **Credentials** → **Create from Connection…**.
2. Pick the **Connection** and a **Name**, and click **Next**. The connection's stored user name and password become the shared credential, and the connection uses it. The values are not shown.
3. **Link the Same Sign-in?** lists the other connections with the same user name and password (compared inside WinVPN, never shown). Tick the ones that should use the credential too, and click **Create and Link**.

### 13.3 Using a credential in a connection

Editors with a user name and password (OpenVPN with `auth-user-pass`, IKEv2 with EAP, SSTP, L2TP, Cisco IPsec) have a **Password from** selector:

- **Own username and password** (the default): the fields of the connection itself.
- **Use credential: Office AD**: WinVPN asks **Use the shared credential Office AD?** and explains that the user name and password stored for this connection are deleted. Click **Use Credential**. The connection's own fields are then hidden.

Other secrets (PSK, private key password, one-time-code settings) stay with each connection. **The editor never changes a shared credential**: saving a connection cannot change what other connections use. A shared credential changes only in **Credentials**.

### 13.4 Import and export

- An export writes only the credential's **name** (`credentialName` in the `# macvpn-meta` line), never its user name or password.
- An import never links a credential silently: the imported file chooses its own server, and a silent link would send your shared password there. If a credential with that name exists, WinVPN asks **Use the shared credential 'Office AD' for this connection to vpn.example.com?** and names the server read from the file. **Use Own Fields** (the safe choice) keeps the connection's own user name and password; choose **Use Shared Credential** only if you trust the file.
- Paired apps (control API) never see shared credentials.

---

## 14. Backup and restore

The per-connection export (see [4](#4-import-and-export)) never contains passwords. For reinstalling Windows or moving to another PC there is a **full backup**: one encrypted file with everything. WinVPN and MacVPN use the same backup format, so you can also move from a Mac to a PC this way.

### 14.1 What a backup contains

- every connection with its config and secrets,
- the folders, colours, order, pins and usage ranking,
- the shared credentials,
- the app preferences, among them **Launch at Login**, **Allow other apps to control VPNs** and **Unlock automatically**,
- your **team catalog subscriptions**, your **admin keys** and your **publications** with their team keys. The catalog's connections and folders themselves are not in the backup: after a restore, the next refresh brings them back from the source.

A backup with admin keys can sign catalogs for your team: protect it like the admin key. Not included: the **paired apps** (they are tied to program paths on this PC: pair them again after a restore), the vault key and the recovery key.

### 14.2 Back Up Everything

1. Popover → **Settings** → **Back Up Everything…** (or **New** (+) → **Back Up Everything…** in the Connections window). It needs an unlocked vault.
2. Read the warning: **Anyone with this file and its password can read all your VPN credentials.**
3. Choose a **Backup password** (at least 10 characters) and repeat it. WinVPN does not store it: without it the backup cannot be opened.
   - Instead you can click **Use my master password…** and confirm with **Use Master Password**. Then anyone who learns your master password can also open this file; a separate backup password keeps the two apart.
   - Type your **Master password** too. WinVPN checks it before every backup, so an unlocked PC left alone is not enough to take a copy of all your passwords.
4. Click **Back Up…** and choose where to save. The file is named `WinVPN-backup-<date>.macvpnbackup` (`.macvpnbackup` is the format MacVPN and WinVPN share), readable only by you.
5. Keep the file and its password apart, for example the file on an external disk and the password in a password manager.

### 14.3 Restore on a new PC

1. Install WinVPN, and start it.
2. In the **Set Up the Vault** window, click **Restore from backup…**. (This needs a new, empty vault.) A backup made by MacVPN works too.
3. **Choose File…**, enter the **Backup password**, and click **Open Backup**.
4. Choose a new master password for this PC and save the new recovery key, as in [11.1](#111-master-password-and-recovery-key).
5. Everything is restored in one step. Then follow the after-restore steps in [14.5](#145-after-a-restore).

### 14.4 Restore into an existing vault

1. Popover → **Settings** → **Restore from Backup…**. Nothing changes before you confirm what to restore.
2. **Choose File…**, enter the **Backup password**, **Open Backup**. A wrong password or a damaged file gives one message: **The backup cannot be opened. The password is wrong, or the file is damaged.**
3. The summary shows when it was made and how many **Connections**, **Folders** and **Shared credentials** it holds. It lists first the connections whose risky OpenVPN settings were acknowledged: restore only a backup you made yourself.
4. Choose:
   - **Merge**: adds what is missing here. For items that already exist, choose once for all: **Overwrite it with the backup’s copy**, **Keep the item that is here**, or **Keep both (the backup’s copy is named “(backup)”)**. A merge drops the risky-setting acknowledgements of the restored connections, unless the same connection with the same config is already here.
   - **Replace everything**: clears the vault first. A confirmation says how many connections, folders and shared credentials will be deleted; **This cannot be undone.** **Back Up the Current State First…** makes a backup of the current state before you go on. Paired apps stay. Team catalog subscriptions are replaced by the backup's; admin keys and publications the backup does not have stay on this PC.
5. **The backup was restored.**

If anything fails, **The restore failed. Nothing was changed.**

### 14.5 After a restore

- **Preferences.** **The backup’s preferences are not applied by themselves.** Each row shows the backup's value and this PC's (**Backup: On · This PC: Off**). Tick the ones to use on this PC and click **Apply Selected Preferences**. **Allow other apps to control VPNs** is never ticked for you: tick it only if you use paired apps on this PC, and pair them again.
- **Native connections.** **WinVPN wrote the Windows VPN entries of the L2TP connections. IKEv2 and SSTP get theirs when they first connect.** Each restored L2TP connection is listed as **Ready**. A connection Windows cannot run (a Cisco IPsec connection from a Mac, an IKEv2 config with a pre-shared key) is restored and shown with its reason instead (see [3.4](#34-l2tpipsec-and-cisco-ipsec)).
- A backup made by MacVPN may hold system VPNs' stored secrets: they apply only to a Windows VPN of the same ID, so set them again for your Windows VPNs (see [3.5](#35-system-vpns-your-own-windows-vpns)).

### 14.6 A backup is untrusted input

Anyone who knows a backup's password can make one, so WinVPN checks every item with the same rules as the editors before it writes anything. An invalid backup is refused as a whole (**This backup cannot be restored: it holds data WinVPN does not accept.**). A backup made by a newer version is refused and asks you to update WinVPN. No restore ever turns on the control API by itself.

---

## 15. Vault FAQ

**I forgot the master password.**
Click **Use recovery key** in the **Unlock WinVPN** window and set a new master password with your recovery key ([11.8](#118-forgotten-master-password)). If **Unlock automatically** is on, WinVPN still opens without the password, but **Change Master Password…** and **New Recovery Key…** need it: lock WinVPN (**Lock Now**), then reset it with the recovery key.

**I lost the recovery key.**
If you still know the master password, make a new one at once: **Settings → New Recovery Key…** ([11.7](#117-a-new-recovery-key)). If you lost both the master password and the recovery key: with **Unlock automatically** on, WinVPN still opens the vault, but nothing that needs the master password works (changing it, a new recovery key, a new backup); export the connections you need now. With **Unlock automatically** off, the vault cannot be opened by anyone, WinVPN included.

**WinVPN says it is locked.**
Click **Unlock…** in the popover and enter the master password. If it locks at every launch, **Unlock automatically** is off, or its credential is missing from Credential Manager: switch it on in **Settings** ([11.2](#112-unlock-automatically)).

**"The vault is damaged and cannot be opened."**
`vault.db` or `vault.keys` was changed or is incomplete. Restore from a backup ([14](#14-backup-and-restore)), or quit WinVPN and put back a copy of both files (made while WinVPN was not running).

**How do I remove everything?**
**System Status → Remove WinVPN from This Account…** with **Also delete user data** ticked (see [9](#9-uninstalling)), then delete your `.macvpnbackup` files.

---

## 16. Team catalogs

A **team catalog** shares VPN connections with a team. An administrator publishes a set of connections once, with their folders, colours and named sign-in placeholders. Every team member's WinVPN or MacVPN subscribes to it and picks up additions, changes and removals by itself. Each member keeps their own user names and passwords, and their own pins, order and collapsed folders.

- The catalog is one file, `<name>.macvpncatalog`. It is **signed** with the administrator's **admin key** and **encrypted** with the **team key**. WinVPN and MacVPN read and publish the same catalogs.
- WinVPN never uploads anything. The administrator puts the file on an HTTPS web server, a file share or a synced folder, and every member reads it from there.

What a member needs from the administrator: the **source** (an `https://` URL or a file path), the **team key** (`TEAM-` followed by 14 groups of 4 characters) and the **publisher fingerprint** (8 groups of 4 hex digits). A **subscription string** (`macvpn-sub:…`) carries all three in one line.

### 16.1 Subscribing to a catalog

1. Open the **Connections** window and select **Team catalogs** in the sidebar. Click **Add team catalog…**.
2. Paste the **subscription string** you got from your administrator. It fills in the source and the fingerprint; the team key is checked and kept hidden. Without a subscription string, fill in the fields yourself:
   - **Source:** an `https://` URL, or **File** and **Choose File…** for a file on a network share or in a synced folder (OneDrive, Dropbox).
   - **Access token** (optional, HTTPS only): if the web server needs a bearer token, enter it here. It is not part of the subscription string; ask your administrator.
   - **Team key:** `TEAM-XXXX-…`. Case, dashes and spaces do not matter; `O` counts as `0`, `I` and `L` as `1`. The last group is a check group, so a typo is caught as you enter it.
   - **Publisher fingerprint:** 8 groups of 4 characters. It is required: WinVPN never trusts the first download without it.
3. Click **Check**. WinVPN reads the catalog, checks its signature against the fingerprint you entered and opens it with the team key. The preview shows the catalog's name, version and fingerprint, the number of connections and folders, the credential slots, and how many connections have risky settings.
4. **Compare the fingerprint** with what your administrator told you through another channel, for example by phone. If it differs, do not subscribe.
5. Tick **The fingerprint matches what my administrator sent me** and click **Subscribe**. The catalog's connections appear at once.

**From File Explorer.** Double-click a `.macvpncatalog` file. WinVPN opens **Team catalogs** with the **Add team catalog…** dialog, **File** chosen as the source and that file filled in. You still enter the team key and the publisher fingerprint, click **Check**, compare the fingerprint and tick the box: opening the file subscribes to nothing.

**HTTPS sources.** `https://` only, checked against the Windows trust store, fetched with Windows' own `curl.exe` (from `System32`) in a cleared environment; redirects only to `https://` addresses, at most 5; the access token is sent only to the subscription URL's own host and port, and never appears on a command line. **Proxies are not supported:** the catalog host must be reachable directly. A server that has not changed the file answers "not modified".

**File sources.** A path on a network share (a mapped drive or `\\server\share\…`) or in a synced folder. The file itself must not be a link and must be a regular file of at most 8 MB. A share that cannot be reached, or a cloud file that cannot be downloaded right now, counts as **unavailable**, not as an error. Choose the file at the path every member's PC uses.

### 16.2 Catalog connections

- Each catalog has its own top-level folder named after the catalog, with a **Team** badge. The publisher's folders and colours are inside it.
- **Read-only:** the name, the config, the folder and the publisher's colour. The editor says **Managed by the team catalog “Acme VPN”**.
- **Yours to change:** pin and order, collapse folders, your own colour for a connection, and the risky-settings checkbox. Your user name and password come from the catalog's credential slot (see [16.3](#163-credential-slots)). **Duplicate as personal connection…** makes an independent, editable copy at the top level.
- **Paired apps** see catalog connections like any other; you allow them per connection.

### 16.3 Credential slots

A **credential slot** is a named sign-in, such as “Office AD”, that the catalog uses without any user name or password in it. When the catalog is first applied, WinVPN creates an empty **shared credential** (see [13](#13-shared-credentials)) named after each slot; fill in your own user name and password in **Credentials**. They stay in your vault: they never go to the administrator or into the catalog.

### 16.4 Refresh and updates

WinVPN checks every catalog at launch and when the vault is unlocked, every 15 minutes, when the PC wakes from sleep, and when you click **Refresh now** in **Team catalogs**. While a source keeps failing, WinVPN waits longer between attempts (up to 60 minutes); waking from sleep and **Refresh now** always try at once.

A new version is applied in one step: everything or nothing. A notification lists the changes, for example **Team catalog “Acme VPN” updated: 2 added, 3 changed, 1 removed**. The same version saved again changes nothing.

### 16.5 Changing or removing a subscription

- **Change team key…** (after the administrator rotated it), **Change access token…** and **Edit source…** are in the subscription's detail. If the new source is on another host or port, or is a file, the stored access token is dropped: the token is never sent to a new address.
- **Unsubscribe…** names the catalog and how many connections it removes. Every catalog connection and folder is removed, and paired apps lose access to them. Credential slots you filled in are kept as ordinary shared credentials.

### 16.6 Troubleshooting for users

- **The catalog is signed by a different key than the fingerprint you entered.**: the file was not signed by the key your administrator gave you. Check the fingerprint with your administrator by phone.
- **The team catalog was signed by another publisher than the one you trust.**: ask your administrator; you may have to subscribe again with the new fingerprint.
- **The team key of “Acme VPN” has changed. Ask your administrator for the new key.**: get the new key through a secure channel, then **Change team key…** and **Refresh now**.
- **Team catalog “Acme VPN” offered an older version (v3 after v5) and was not applied.**: the rollback protection (see [16.11](#1611-security-model)). Tell your administrator; publishing a new version solves it.
- **The team catalog could not be read: access denied (check the access token)**: the HTTPS server refused the request (HTTP 401 or 403). Enter the current token with **Change access token…**.
- **The team catalog source is unavailable (…).**: the share cannot be reached, or a cloud file cannot be downloaded right now. WinVPN tries again later; you can also click **Refresh now**.

### 16.7 For administrators: the admin key

Publishing needs an **admin key**: an Ed25519 signing key kept in your vault. Its **fingerprint** is what your team compares when subscribing.

1. **Connections** window → **Publishing** → **Generate Admin Key**. The fingerprint is shown in 8 groups; **Copy** copies it.
2. **Generate Backup Admin Key**, then **Export Backup Key…**: choose where to save the `.macvpnadminkey` file and a password of at least 10 characters (twice). Tick **Remove the backup key from this PC after export**. Keep the file offline and its password somewhere else.

To switch to the backup key, **Import Admin Key…** on the PC that publishes from now on (it must also have your publications: use the same vault or restore a full backup first), then **Switch to the Backup Key…**, publish a new version of each catalog, and make a new backup key.

### 16.8 For administrators: publishing a catalog

**Publishing** → **Publish Catalog…** opens the wizard: **Connections** (tick folders and connections), **Review** (what the catalog contains; under **Team secrets** tick only the secrets everyone in the team may know, and under **Credential slots** the named sign-ins, without user names or passwords), **Name and File** (where to save `<name>.macvpncatalog`; **WinVPN does not upload anything: put the file on your web server or share.**), and **Done**. For a new catalog, the **team key is shown once**: **Copy** it, keep it safe, click **I Saved It** and type the group the window asks for. Then **Copy Subscription String…**.

Publish to the same place every time, so the members' source stays valid. On a file share, replace the file as a whole (WinVPN writes it that way when you save it there directly). The file is written so that every user of the PC can read it (it is meant to be shared; it is signed and encrypted).

### 16.9 For administrators: the team key and the subscription string

- The **team key** is 256 random bits, made at the first publish of a catalog, and **shown once**.
- **Copy Subscription String…** asks for your **master password** and for the source your team will use (the path as it looks on the members' PCs). It puts the `macvpn-sub:…` string on the clipboard without showing it. The string contains the team key: send it only through a secure channel. Tell members the fingerprint separately.
- **Rotate Team Key…** (to cut off someone who left the team) makes a new team key and publishes it as the next version. **Rotating the team key is the only way to revoke access to a catalog someone already has.**

### 16.10 Changing the admin key, and compromise

Switching to the backup key is a planned key change, **not recovery from a compromise**. If the admin key may have leaked: generate a new admin key on a PC you trust, publish the connections as a new catalog, remove the old catalog file from the share, and send every member the new subscription string and fingerprint through a trusted channel. Change the team secrets of the old catalog too. If only the team key leaked, rotate it.

### 16.11 Security model

- **Signature (admin key, Ed25519).** Every catalog is signed; WinVPN checks the signature against the publisher key you pinned with the fingerprint before it decrypts or uses anything. It protects against changes by anyone without the admin key, including people who can write the share; not against a leaked admin key or an administrator who publishes something bad.
- **Encryption (team key, XChaCha20-Poly1305).** The contents are encrypted with the team key. Anyone who has the team key, including a former member until you rotate it, can read everything in the catalog, including the team secrets you ticked.
- **Rollback protection.** Each subscription remembers the last applied version; a lower version is refused with a warning.
- **Checks like an import.** Every config in a catalog goes through the same validators as an import, and risky settings need each member's own tick. A catalog cannot carry a user's password.
- **Your secrets.** The team key is kept in the vault, and in a full backup; it is never logged. The subscription string and the team key's **Copy** use the protected clipboard of [10](#10-security-notes).
