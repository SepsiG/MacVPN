# LinVPN – User Guide

[Magyar változat](linvpn-user-guide.hu.md)

LinVPN is the Linux version of [MacVPN](user-guide.en.md) and [WinVPN](winvpn-user-guide.en.md): an app in the top bar for Debian and Ubuntu based desktops (amd64 or arm64), built from the same code. It keeps OpenVPN, WireGuard, IKEv2 (strongSwan), L2TP/IPsec, Cisco IPsec and SSTP connections in one place and connects them **through NetworkManager**, the network service of the desktop, as you (no administrator is needed to connect). It also lists the VPNs you set up in GNOME's own network settings. It has the same encrypted vault, connections, folders, shared credentials, backups, team catalogs and control API as MacVPN, in the same formats: a MacVPN or WinVPN backup restores on LinVPN, and the other way round. It is tested on Ubuntu with GNOME.

Everything this guide does not mention works as in MacVPN: the vault, folders and colours, shared credentials, import and export, backup and restore, and team catalogs are described in the [MacVPN user guide](user-guide.en.md#11-vault). This guide follows the MacVPN guide's structure and says what is different on Linux.

> **Language:** LinVPN follows your desktop's language (Settings → System → Region & Language; LinVPN reads the `LANGUAGE`, `LC_ALL`, `LC_MESSAGES` and `LANG` variables the desktop sets). It is available in English and Hungarian; if neither is among your languages, it uses English. This guide uses the English labels; the [Hungarian guide](linvpn-user-guide.hu.md) shows the Hungarian ones.

## Contents

1. [Installation](#1-installation) ([Requirements](#11-requirements), [Installing the package](#12-installing-the-package), [NetworkManager and its VPN plugins](#13-networkmanager-and-its-vpn-plugins), [Where LinVPN keeps your data](#14-where-linvpn-keeps-your-data))
2. [The tray icon, the panel and System Status](#2-the-tray-icon-the-panel-and-system-status) ([Launch at login](#21-launch-at-login), [Appearance](#22-appearance), [Notifications](#23-notifications), [Missing VPN plugins](#24-missing-vpn-plugins))
3. [Adding connections by type](#3-adding-connections-by-type) ([OpenVPN](#31-openvpn), [WireGuard](#32-wireguard), [IKEv2](#33-ikev2-strongswan), [L2TP/IPsec and Cisco IPsec](#34-l2tpipsec-and-cisco-ipsec), [System VPNs](#35-system-vpns-your-own-networkmanager-vpns), [SSTP](#36-sstp), ["Not supported on Linux"](#37-not-supported-on-linux))
4. [Import and export](#4-import-and-export) ([Opening files from Files](#41-opening-files-from-files))
5. [Connecting](#5-connecting) ([MFA](#51-multi-factor-authentication-mfa), [Credentials](#52-credentials-asked-when-connecting), [Paired apps](#53-paired-apps-control-api), [Reconnect automatically](#54-reconnect-automatically), [DNS](#55-dns-while-connected), [Quitting and signing out](#56-quitting-signing-out-and-sleep))
6. [Debug mode and the log](#6-debug-mode-and-the-log)
7. [Troubleshooting](#7-troubleshooting)
8. [Updates](#8-updates)
9. [Removing LinVPN](#9-removing-linvpn)
10. [Security notes](#10-security-notes)

---

## 1. Installation

### 1.1 Requirements

- **Ubuntu 26.04 or later**, on amd64 (Intel and AMD processors) or arm64. Other distributions based on them may work if they have glibc 2.39 or newer. LinVPN is tested on Ubuntu 26.04 with GNOME on Wayland; the arm64 package is built and checked, but not tested by hand.
- **A tray host** (StatusNotifierItem): Ubuntu's own AppIndicator support (on by default), the **AppIndicator and KStatusNotifierItem Support** extension on other GNOME desktops, or KDE Plasma, which has one built in. The package depends on one of them. Without a tray host LinVPN has no icon.
- **NetworkManager 1.54.3 or later** (Ubuntu 26.04 has 1.54), which LinVPN connects through, with its VPN plugins (see [1.3](#13-networkmanager-and-its-vpn-plugins)). WireGuard needs no plugin.
- **OpenVPN 2.7 or later** for OpenVPN connections to follow the server's `redirect-gateway` (see [3.1](#31-openvpn)). Ubuntu 26.04 has 2.7; with an older OpenVPN, LinVPN still connects, as a split tunnel unless set otherwise.
- **An administrator** (a user who may use `sudo`) for the installation, for each update and for installing a missing VPN plugin. Connecting needs no administrator.

### 1.2 Installing the package

Download `linvpn_<version>_amd64.deb` (or `linvpn_<version>_arm64.deb` on an ARM computer) and its `.sha256` file. They are on the [Releases](https://github.com/SepsiG/MacVPN/releases) page, released together with MacVPN and WinVPN from 2.1.0, the first LinVPN release.

Check the download, then install it as an administrator:

    sha256sum -c linvpn_<version>_amd64.deb.sha256
    sudo apt install ./linvpn_<version>_amd64.deb

Keep the `./`: without it apt looks for a package of that name in its repositories instead of the file. apt installs the dependencies as well (NetworkManager, its OpenVPN plugin and OpenVPN) and, by default, the recommended VPN plugins. To install a newer package by hand later, run the same command with the new file; your data stays. If LinVPN is running meanwhile, it restarts into the installed version by itself within a few seconds (an older package too) and your connections stay up; while the Connections window has unsaved changes it waits until you save or discard them.

The package installs:

- the app (`/usr/bin/linvpn`), the entry in the app grid with its icon, and the file types LinVPN opens (see [4.1](#41-opening-files-from-files));
- **LinVPN's own NetworkManager OpenVPN service** (`/usr/lib/linvpn/nm-openvpn-service` and its helper, registered with NetworkManager as `linvpn-openvpn`): the standard NetworkManager OpenVPN plugin with a small change that lets OpenVPN connections follow a `redirect-gateway` the server pushes (see [3.1](#31-openvpn)). The standard plugin stays installed and untouched for every other OpenVPN connection of the computer. Its source (GPL-2.0-or-later) is in `/usr/share/linvpn/source/`;
- **`linvpn-logd`**, a small system service that gives LinVPN the system log lines of your own VPN connections (see [6](#6-debug-mode-and-the-log)). It is started on demand, never as root, and can read nothing but the system journal;
- **`linvpn-xfrmd`**, a small system service that gives LinVPN the byte counters of your own IKEv2 connections when strongSwan is older than 6 (see [5](#5-connecting)). It is started on demand, never as root, with one permission only: reading the kernel's IPsec state;
- **`90-linvpn-route`**, a NetworkManager dispatcher script that adds the class-based route of an L2TP or SSTP split tunnel (see [3.4](#34-l2tpipsec-and-cisco-ipsec));
- the update step (`/usr/libexec/linvpn/linvpn-install-update`, see [8](#8-updates)) and a system permission (a polkit action) that lets LinVPN ask for an administrator's password when it installs an update.

When it is installed, the package runs one step of its own: it turns on the sockets of `linvpn-logd` and `linvpn-xfrmd` (`systemctl enable --now linvpn-logd.socket linvpn-xfrmd.socket`); when it is removed, it turns them off again.

Start **LinVPN** from the app grid. On the very first launch the **Set Up the Vault** window opens (see [the MacVPN guide](user-guide.en.md#111-master-password-and-recovery-key)).

### 1.3 NetworkManager and its VPN plugins

LinVPN does not run VPN programs itself: for each connect it hands NetworkManager a temporary connection that only your user can use and that NetworkManager forgets when it goes down. NetworkManager runs the VPN with its plugins:

| Type | NetworkManager runs it with | Package |
|---|---|---|
| WireGuard | NetworkManager itself | none |
| OpenVPN | LinVPN's own OpenVPN service (OpenVPN as the `nm-openvpn` user) | `network-manager-openvpn` (a dependency of LinVPN) |
| L2TP/IPsec | the L2TP plugin | `network-manager-l2tp` |
| IKEv2 | the strongSwan plugin (charon-nm) | `network-manager-strongswan`; for EAP (user name and password) also `libcharon-extauth-plugins` and `libcharon-extra-plugins` |
| Cisco IPsec | the vpnc plugin | `network-manager-vpnc` |
| SSTP | the SSTP plugin (sstpc) | `network-manager-sstp` |

The LinVPN package recommends the plugins, so apt installs them with LinVPN unless recommended packages are turned off. A missing one is shown in **System Status** and installed from there (see [2.4](#24-missing-vpn-plugins)).

**No password while you connect.** NetworkManager lets the user who is logged in at the desktop add and connect a connection that belongs only to them. LinVPN asks the system first (without showing anything) whether that is allowed without a password; if it is not (for example in a remote SSH session, or on a computer whose administrator restricted it), LinVPN connects nothing and says **LinVPN may not change this computer's network settings without asking for a password. Log in at the desktop and try again.** LinVPN never opens a password window for connecting.

### 1.4 Where LinVPN keeps your data

Every user has their own LinVPN data, readable only by that user:

- **The vault and the connections:** `~/.local/share/LinVPN` (`vault.db` and its key file `vault.keys`, the control API's audit file in `control/`).
- **The connection logs:** `~/.local/share/LinVPN/logs` (one `<connection ID>.log` per connection; see [6](#6-debug-mode-and-the-log)).
- **The L2TP and Cisco IPsec connection records:** `~/.local/share/LinVPN/nm` (one `<connection ID>.json` each: type, server, account name, group name and "send all traffic", never a password or a PSK; see [3.4](#34-l2tpipsec-and-cisco-ipsec)).
- **IKEv2 certificates and keys:** a client certificate imported in the app is in the vault; files you put in `~/.local/share/LinVPN/swanctl` stay there (see [3.3](#33-ikev2-strongswan)).
- **The settings:** `~/.config/LinVPN` (`preferences.json`).
- **Downloaded updates and their logs:** `~/.cache/LinVPN/updates`.
- **The vault's auto-unlock key:** your login keyring (the Secret Service; on GNOME it is shown in **Passwords and Keys**), as the item **LinVPN vault key**.
- **Launch at login:** `~/.config/autostart/linvpn.desktop`, when it is on.
- **Run files:** `$XDG_RUNTIME_DIR/linvpn` (the control API's socket, and while a connection is up the certificates and keys of its config in `nm/`, readable only by you and deleted when it disconnects). The system empties this folder when you sign out.

When the `XDG_DATA_HOME`, `XDG_CONFIG_HOME` or `XDG_CACHE_HOME` variable is set to an absolute path, LinVPN uses it instead of `~/.local/share`, `~/.config` or `~/.cache`.

**Nothing is stored in NetworkManager.** The connections LinVPN hands NetworkManager exist only in memory while they are up, and their passwords are not in them: NetworkManager asks LinVPN for them at each connect (see [10](#10-security-notes)). So LinVPN's connections do not appear in Settings → Network, and there is nothing to clean up there.

**Unlock automatically** (on by default) keeps the vault key in your login keyring, so LinVPN opens without asking. The keyring is unlocked by your login password; if it is locked (for example after an automatic login), GNOME's own window asks for its password the first time LinVPN needs the key; if you cancel it, LinVPN asks for the master password instead. Auto-unlock protects the vault against other users and a stolen disk, but not against software that runs as you: any app of yours can ask your keyring for the key. If that matters to you, switch off **Unlock automatically** in **Settings**: LinVPN then deletes the key from the keyring and asks for the master password at every launch.

To move to another computer (or from a Mac or a Windows PC), use a full backup: **Back Up Everything…** there, **Restore from Backup…** in LinVPN.

---

## 2. The tray icon, the panel and System Status

LinVPN's icon sits at the right of the top bar. LinVPN shows its connections in a **panel** of cards, like the menu of MacVPN and the popover of WinVPN:

- **A single click** (left or right) on the icon opens a short menu: **Open LinVPN** (opens the panel) and **Quit LinVPN**. On Ubuntu's GNOME the menu appears after a short pause: the top bar first waits to see whether the click is a double click.
- **A double click or a middle click** on the icon opens the panel directly; doing it again closes it.
- On KDE Plasma a single left click opens the panel directly, and a right click opens the menu.

The panel opens at the top-right corner of the screen the pointer is on, just below the top bar. Each connection is a card with the coloured bubble of its type, its name, its type and state, and a switch; system VPNs (see [3.5](#35-system-vpns-your-own-networkmanager-vpns)) are cards too. Below the cards are the tiles **New Connection / Import…**, **Manage Connections…** and **System Status**, the **Settings** group, **Help** (it opens this guide on GitHub, in Hungarian when LinVPN's language is Hungarian) and **Quit LinVPN**. The panel closes when you click anywhere outside it or switch to another window.

LinVPN runs once per user: starting it again (from the app grid, or by opening a file with it) brings the running LinVPN forward instead of starting a second one. Closing a window does not quit LinVPN: it keeps running in the top bar.

**The System Status window** says **LinVPN connects through NetworkManager and its VPN plugins (OpenVPN, L2TP, strongSwan, vpnc, SSTP). You can install the missing ones here.** and shows one row for NetworkManager and one per type:

1. **NetworkManager:** its version (**NetworkManager 1.54.3**), or **NetworkManager is not running.** / **NetworkManager 1.36 or later is needed.**: then no type can connect.
2. **WireGuard:** **Built into NetworkManager**.
3. **OpenVPN:** the OpenVPN version and whether it follows the server: **OpenVPN 2.7.0 · follows the server's redirect-gateway**, or with an older OpenVPN **OpenVPN 2.6.14 · split tunnel unless set to Always (needs 2.7 to follow the server)** (see [3.1](#31-openvpn)). **LinVPN's OpenVPN service is missing: reinstall LinVPN.** means the package's files are damaged: install the package again.
4. **L2TP/IPsec**, **IKEv2**, **Cisco IPsec**, **SSTP:** **Installed**, or **Not installed: <package>** with an **Install** button. For IKEv2 the row stays usable but says **EAP needs libcharon-extauth-plugins, libcharon-extra-plugins** (with **Install**; only the missing ones are named) when only the EAP part is missing: IKEv2 with a certificate or a PSK works without it.

**Check Again** checks everything again.

### 2.1 Launch at login

LinVPN does not start by itself by default. Switch on **Launch at Login** in the panel's **Settings** group to start it at every sign-in; switch it off to stop. LinVPN writes (or deletes) the file `~/.config/autostart/linvpn.desktop` for your user only.

- If another tool turned that entry off (for example **Startup Applications** in GNOME Tweaks), the switch shows off with the note **Turned off by another app.** Switching it on in LinVPN turns it on again.
- Only the installed LinVPN (`/usr/bin/linvpn`) can be registered. A development build shows **Launch at login is available when LinVPN is installed from its package.**

### 2.2 Appearance

**Settings → Appearance** offers **Match System** (the default: LinVPN follows the desktop's light or dark style, Settings → Appearance, also when you change it while LinVPN runs), **Light** and **Dark**. The choice applies to the panel and every window at once.

### 2.3 Notifications

LinVPN posts desktop notifications: when a connection connects, drops, is reconnected, fails or stops responding, when it needs a code or credentials, and when a team catalog was updated. They work as in MacVPN (see [the MacVPN guide](user-guide.en.md#23-connection-notifications)), including the **Connection Notifications** switch in **Settings**. They appear under the name **LinVPN** with its icon; GNOME lets you turn them off in Settings → Notifications → **LinVPN**. Clicking a notification while LinVPN runs opens the window it belongs to. A notification never shows a password, a key, a token or a server's address.

### 2.4 Missing VPN plugins

When a type's NetworkManager plugin is not installed, its connections stay in the list, greyed out, and their line says why, for example **Not installed: NetworkManager SSTP plugin – System Status** (or **Not installed: NetworkManager** when NetworkManager is not running). **System Status** in that line is a link that opens the window.

**Install** on a plugin's row installs exactly the packages the row names, through **PackageKit**, the system's software installer: the system's own window asks for an administrator's password (LinVPN never sees it). While it runs the row shows **Installing…** and the output appears under it; afterwards the row turns green and the connections become usable. **The installation was cancelled.** or **The installation was not authorized.** means the password window was closed or refused: nothing was installed. LinVPN can install only the NetworkManager VPN plugins of the table in [1.3](#13-networkmanager-and-its-vpn-plugins), never another package. You can also install them yourself (`sudo apt install network-manager-sstp`), then press **Check Again**.

---

## 3. Adding connections by type

You add connections in the **Connections** window (**Manage Connections…** or **New Connection / Import…** in the panel), exactly as in MacVPN: **New** (+) offers OpenVPN, WireGuard, IKEv2, SSTP, L2TP and Cisco IPsec, **Import from File…** imports a file, text types have a text editor that checks the config when you save, and passwords go into the vault, not into the config (see [the MacVPN guide](user-guide.en.md#3-adding-connections-by-type)).

**Secrets in the config are hidden** until you tick **Show secrets**, and the **Certificates** box under the config lists the connection's certificates with **Copy** (the SHA-256 fingerprint) and **Copy PEM**, as in MacVPN (see [the MacVPN guide, 3.7](user-guide.en.md#37-certificates)).

**What Linux runs differently is shown under the editor.** A grey line says how NetworkManager will run the connection (for example **On Linux: NetworkManager with LinVPN's OpenVPN service · the server decides about all traffic**), followed by notes on what is ignored on Linux. A connection Linux cannot run is greyed in the list with the reason (see [3.7](#37-not-supported-on-linux)).

### 3.1 OpenVPN

Import the `.ovpn` file from your provider, as in MacVPN (see [the MacVPN guide](user-guide.en.md#31-openvpn)). OpenVPN connections run through LinVPN's own NetworkManager OpenVPN service (see [1.2](#12-installing-the-package)). The certificates and keys of the config are written for the duration of the connection into a folder only you can read (`$XDG_RUNTIME_DIR/linvpn/nm/…`) and deleted when it disconnects.

**The directives.** The three tiers (allowed, **Risky settings**, forbidden) are the same as in MacVPN; Linux adds its own column ([openvpn-directives.md](openvpn-directives.md#linux-linvpn)):

- **69 directives are ignored on Linux:** NetworkManager has no setting for them (buffer and socket tuning, some timers and TLS details, the other systems' options), so they have no effect. They appear in the yellow **Risky settings** panel with the reason **Ignored by NetworkManager on Linux**; tick **I acknowledge these settings and the security risks** to save. Everyday profiles from VPN servers rarely have them.
- **8 kinds of setting cannot run on Linux:** `peer-fingerprint`, `verify-hash`, `remote-cert-ku`, `remote-cert-eku`, a `route` past the tunnel (`net_gateway`, `remote_host`), a `<connection>` block with anything but `remote`, `proto`, `port` and `nobind`, a `pull-filter` the service cannot pass, and `compress stub`/`stub-v2`/`migrate`. Dropping any of them would weaken the server check or send traffic past the tunnel, so the connection is greyed instead (see [3.7](#37-not-supported-on-linux)).
- A few arguments NetworkManager drops (`redirect-gateway … block-local`, some `dns` options, a `route` with a host name) are listed under the editor as **Ignored by NetworkManager on Linux: …**.

**Send all traffic over VPN.** OpenVPN's editor has a three-way setting (only on Linux; it is written into the config, so it travels with backups, exports and team catalogs, and MacVPN's and WinVPN's OpenVPN honour it too):

- **Server decides** (the default): **The server's redirect-gateway decides.** If the server pushes `redirect-gateway` (or the profile has it), all traffic goes through the VPN; otherwise only the VPN's networks do. This is how OpenVPN behaves on macOS. It needs OpenVPN 2.7 (see [2](#2-the-tray-icon-the-panel-and-system-status)): with an older OpenVPN the editor says **This system's OpenVPN is older than 2.7: “Server decides” keeps a split tunnel unless the profile says otherwise.**
- **Always:** **All traffic goes through the VPN (redirect-gateway def1).** LinVPN adds a `redirect-gateway def1` line to the config.
- **Never (split tunnel):** **Only the VPN's own networks go through it; a redirect-gateway from the server is ignored.** LinVPN adds `pull-filter ignore "redirect-gateway"`.

A profile that already has one of these lines shows the matching choice; choosing **Server decides** removes them. The change is an ordinary edit: **Save** keeps it.

**User name, password, private key password, static challenge and CRV1** work as in MacVPN (see [5.1](#51-multi-factor-authentication-mfa)). The `verb` level of the config (up to 4) is passed to OpenVPN; its lines appear in the Log tab.

### 3.2 WireGuard

Import the `.conf` file, or create a new one and fill in the template, as in MacVPN (the key generator under the config works the same; see [the MacVPN guide](user-guide.en.md#32-wireguard)). NetworkManager runs WireGuard itself, on an interface named `lvw` plus 8 letters and digits; the line under the editor names it (**On Linux: NetworkManager's WireGuard (interface lvw1a2b3c4d)**).

- `Table` other than `auto` cannot run: **Not supported on Linux: Table = … (NetworkManager uses its own routing table)**. `Table = off` is the exception: no routes are added.
- A `DNS` server of an IP version the connection has no `Address` for is dropped, with the note **Ignored on Linux: DNS = … (the connection has no Address of that IP version)**.
- The private key and the preshared keys are never put into NetworkManager's settings: NetworkManager asks LinVPN for them at connect.
- **Copying the private key** (**Copy** next to **Private key**) is cleared from the clipboard after 60 seconds, at **Lock Now** and at quit (unless you copied something else meanwhile), as in MacVPN. Linux has no system-wide way to keep it out of clipboard history: LinVPN marks it as a password (`x-kde-passwordManagerHint`), which only clipboard managers that honour the mark skip (KDE's Klipper, GNOME extensions that implement it); other clipboard managers and GNOME extensions may keep a copy in their history. Turn such an extension off, or clear its history, before you copy a key.

### 3.3 IKEv2 (strongSwan)

IKEv2 configs use strongSwan `swanctl.conf` syntax, as in MacVPN, so the same connection works on every system. NetworkManager's strongSwan plugin (charon-nm) runs the **first connection of the config and its first child**:

- **Sign-in:** EAP with a user name and password (`local { auth = eap-mschapv2 }` or `eap`; this needs `libcharon-extauth-plugins` and `libcharon-extra-plugins`, see [2.4](#24-missing-vpn-plugins)), a client certificate (`auth = pubkey`), or a pre-shared key (`auth = psk` on both sides).
- **A pre-shared key must be at least 20 characters** on Linux: the strongSwan plugin refuses a shorter one. LinVPN checks it before connecting: **IKEv2 on Linux needs a pre-shared key of at least 20 characters: strongSwan's NetworkManager plugin refuses a shorter one.**
- **Routes:** without `remote_ts`, or with `0.0.0.0/0`, all traffic goes through the VPN; other `remote_ts` networks make a split tunnel.
- **Not supported on Linux** (the connection is greyed with the key and value, for example **Not supported on Linux: local auth = eap-tls**): other EAP methods and XAUTH, IKEv1 (`version = 1`), more than one authentication round (**Not supported on Linux: more than one authentication round**), more than one server address (**Not supported on Linux: more than one remote address**), a missing server address (**On Linux the server address is required: set remote_addrs to the server's name or address.**), transport mode, and more than one client or CA certificate.

**Client certificate in the app (as in MacVPN 2.0.7).** For certificate sign-in (`auth = pubkey` in `local`, or no `auth`) press **Import Client Certificate…** under the config and choose either a PKCS#12 file (`.p12`, `.pfx`) or your certificate and its private key as PEM (one file or two; select both in the panel). LinVPN checks the files strictly (at most 16 KB each) and keeps the certificate and key in the vault, never in a folder of yours. The editor then shows **PEM certificate and key** with the SHA-256 fingerprint, and **Remove** deletes it from the vault. A CA or chain certificate in the PEM files is not imported (the editor says how many were left out): name the server's CA with `cacerts`, see below.

- **A PKCS#12 file is converted automatically.** strongSwan's NetworkManager plugin reads only PEM files, so LinVPN asks for the file's password (**Password of the PKCS#12 file**) and converts it at once with the system's `openssl` (older RC2 / 3DES files too); the vault then keeps the PEM certificate and key, and the key keeps that password, so it is your **Private key password**: LinVPN fills it into that field, and it is stored when you save the connection (**Discard** drops it; empty, it is asked when connecting). A wrong password says **The PKCS#12 password is wrong.** and asks again; **Cancel** imports nothing. Without the `openssl` package (the LinVPN package depends on it): **Reading a PKCS#12 file needs the openssl package: install openssl, then try again.** A PKCS#12 certificate imported on a Mac and restored from a backup is converted the same way at each connect, with its key password.
- **When connecting,** LinVPN writes the certificate and its key into the connection's own folder under `$XDG_RUNTIME_DIR/linvpn` (readable only by you, in memory, deleted at disconnect), and NetworkManager's strongSwan plugin reads them from there. The key never goes into NetworkManager's settings or the log. The imported certificate is used when the config names no `certs` of its own; a config with `certs` keeps its file from LinVPN's folder (below).
- **Private key password:** shown for an IKEv2 config that signs with a key. If the key is encrypted, save its password there, or leave it empty and LinVPN asks for it when connecting. It is stored in the vault and given to strongSwan only to open the key (never written to the log).
- A config with `auth = pubkey`, no `certs` and no imported certificate shows **On Linux a client certificate is needed: import it with Import Client Certificate…, or set certs to its file in LinVPN's strongSwan folder (x509).**

**Certificates in LinVPN's strongSwan folder** (as before) still work. The certificate files a config names are read from your own folder `~/.local/share/LinVPN/swanctl` (the counterpart of Homebrew's `etc/swanctl` on a Mac), with the same three subfolders. Create it and copy the files there, readable only by you:

    mkdir -p ~/.local/share/LinVPN/swanctl/{x509,x509ca,private}
    cp client.pem ~/.local/share/LinVPN/swanctl/x509/
    cp client.key ~/.local/share/LinVPN/swanctl/private/
    cp ca.pem ~/.local/share/LinVPN/swanctl/x509ca/
    chmod -R go-rwx ~/.local/share/LinVPN/swanctl

- **The client certificate:** `certs = client.pem` in the `local` section → `x509/client.pem`; its private key must be `private/client.key` (the certificate's name with `.key`). If the key has a password, save it in **Private key password** (LinVPN cannot see whether a key in the folder is encrypted, so it does not ask for it when connecting).
- **The server's CA:** `cacerts = ca.pem` in the `remote` section → `x509ca/ca.pem`. Without `cacerts`, the one file in `x509ca` is used if there is exactly one; otherwise the system's CA certificates check the server, and the editor says **No CA certificate is named and LinVPN's strongSwan folder (x509ca) does not hold exactly one: the system's CA certificates check the server.**

**Certificates box.** As in MacVPN, the **Certificates** box under the config lists the imported client certificate first, then the files `certs` and `cacerts` name from LinVPN's strongSwan folder (`x509`, `x509ca`), with their validity: one that expires within 30 days says **Expires in 12 days**, an expired one **Expired**. (A CA LinVPN picks because it is the only file in `x509ca`, without `cacerts`, is not listed.) OpenVPN and SSTP certificates are shown from the config, as in MacVPN, and their row warns before they expire.

### 3.4 L2TP/IPsec and Cisco IPsec

You set them up in a form (**New → L2TP** or **New → Cisco IPsec**), with the same fields as in MacVPN: **Name**, **Server**, **Account name**, **Password**, **Shared secret (PSK)**, for Cisco also **Group name**, and **Send all traffic over VPN** (see [the MacVPN guide](user-guide.en.md#34-l2tpipsec-and-cisco-ipsec)).

- **There is no profile to approve.** The button is **Save**: LinVPN stores the connection (the password and the PSK in the vault) and a small record without secrets in `~/.local/share/LinVPN/nm`, and builds the NetworkManager connection from it at each connect. Deleting the connection deletes the record.
- **L2TP/IPsec** runs through the L2TP plugin with the PSK and MS-CHAPv2 sign-in (**On Linux: NetworkManager L2TP/IPsec (MS-CHAPv2)**), as in MacVPN.
- **Without Send all traffic over VPN** (L2TP and SSTP), the network of your VPN address's class is routed through the VPN, as on macOS and Windows: an address `10.x.x.x` gets `10.0.0.0/8`, `172.16.x.x` gets `172.16.0.0/16`, `192.0.2.x` gets `192.0.2.0/24` (classes A, B and C), plus whatever routes the server sends. So the network behind the server is reachable. A small NetworkManager script of the package adds it (`/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route`; its lines are in the system log under `linvpn-route`). It adds nothing when your own network or your default gateway is in that network, so your local network keeps working. Cisco IPsec takes the networks the server sends, as on macOS.
- **Cisco IPsec works on Linux** (unlike Windows): it runs through the vpnc plugin (IKEv1 with XAUTH and the group's PSK: **On Linux: NetworkManager vpnc (Cisco IPsec)**).
- **One-time codes** appended to the password work for both (see [5.1](#51-multi-factor-authentication-mfa)).

### 3.5 System VPNs: your own NetworkManager VPNs

The VPNs set up in GNOME (Settings → Network → VPN) or with `nmcli`, that your user may use, are listed in LinVPN as system VPNs (**system VPN (not created by LinVPN)**), with their type: **L2TP**, **Cisco IPsec**, **IKEv2**, **WireGuard (app)**, **OpenVPN (app)** or **VPN**. A VPN you add or remove in Settings appears or disappears by itself; if one is removed while you look at it, its detail says **This VPN was removed from NetworkManager**.

- **Connect and disconnect** them from the panel or the Connections window, like any other connection; LinVPN shows their state, address and traffic. Their settings stay in NetworkManager: **This connection can only be connected and disconnected here. Its settings are in Settings → Network or in its own app.** LinVPN never edits, renames or deletes them.
- **Secrets (L2TP and Cisco IPsec):** as in MacVPN, the detail view has **Shared secret (PSK)** and **Password (optional, if not saved in NetworkManager)**. They are kept in LinVPN's vault and given to NetworkManager only for a connect LinVPN starts; NetworkManager's own settings are not changed. **Forget saved secrets** deletes them. Without them NetworkManager uses what it saved for the VPN; if it has nothing, GNOME's own password window may ask.
- **What is listed:** only the VPN and WireGuard profiles your user may use (those for all users, and those restricted to you); never the temporary connections LinVPN makes for its own connections. A VPN available to all users may ask for an administrator's password when GNOME saves it; that is GNOME's prompt, not LinVPN's.
- System VPNs can be put into folders, pinned and coloured like your connections. They have no **Reconnect Automatically** switch.

### 3.6 SSTP

Create it with **New → SSTP**, or import an `.sstp` file. The form is the same as in MacVPN (**Server**, **Port**, **Username**, **Password**, **Server certificate**, **Send all traffic over VPN**, **Use the server's DNS**; see [the MacVPN guide](user-guide.en.md#36-sstp)); NetworkManager's SSTP plugin runs it with `sstpc` and MS-CHAPv2.

- **System CA:** the server's certificate is checked against the system's CA certificates (`/etc/ssl/certs`). A company CA installed there (`/usr/local/share/ca-certificates` and `sudo update-ca-certificates`) is trusted.
- **Custom CA file** (**Choose PEM File…**): the CA is kept in the connection's config and written for the duration of the connection into your private run folder.
- **No verification:** allowed, as on macOS, with the warning **Without verification the server's certificate is not checked.** Use it only for testing.
- **Use the server's DNS** turned off: NetworkManager ignores the DNS servers the server sends.
- **Send all traffic over VPN** turned off: the network of your VPN address's class goes through the VPN, as on macOS and Windows (see [3.4](#34-l2tpipsec-and-cisco-ipsec)).

### 3.7 "Not supported on Linux"

A connection whose settings Linux cannot run keeps all its data: you can still edit, save, export, back up and share it, and the same connection works in MacVPN and WinVPN. On Linux it is greyed in the list with the reason (**Not supported on Linux: …**, with the exact setting), its editor shows the reason in a yellow note, and connecting is refused. Change the setting (for example remove a `peer-fingerprint` line and use the server's CA instead), or ask your VPN administrator for a profile without it. The reasons are listed in [3.1](#31-openvpn), [3.2](#32-wireguard) and [3.3](#33-ikev2-strongswan).

---

## 4. Import and export

Import and export work as in MacVPN (see [the MacVPN guide](user-guide.en.md#4-import-and-export)), including **Export Without Keys**: it removes your personal keys and keeps the server's shared `<tls-auth>` / `<tls-crypt>` key, so the copy can connect. A `.mobileconfig` profile cannot be imported into LinVPN: **A .mobileconfig profile cannot be imported into LinVPN. Create the connection with New, or restore a backup that has it.**

### 4.1 Opening files from Files

Double-click a `.ovpn` or `.sstp` file in Files (or another file manager): LinVPN opens the **Connections** window and imports it, with the same checks and questions as **Import from File…**. A `.macvpncatalog` file opens the team catalog dialog. Nothing connects. If LinVPN is not running, the double click starts it.

- **`.conf` files are not taken over:** on Linux they are plain text files, and claiming them would offer LinVPN for every text file. Import WireGuard and strongSwan `.conf` files from the Connections window. Backups (`.macvpnbackup`) are restored with **Restore from Backup…**.
- **Downloaded files are asked about first.** Browsers mark the files they download (the `user.xdg.origin.url` attribute). LinVPN imports such a file only after you confirm **Import the downloaded file?**; it reads the mark and never removes it.

---

## 5. Connecting

Connecting works as in MacVPN (see [the MacVPN guide](user-guide.en.md#5-connecting)): the switch on a card, or **Connect** / **Disconnect** in the Connections window. The card shows the state, the address, the connected time and the live traffic (**↓ 12.4 MB  ↑ 1.2 MB · ↓ 350 kB/s  ↑ 20.0 kB/s**). Several connections can be up at the same time.

- **Traffic** is read from the connection's network interface: WireGuard and OpenVPN from the one LinVPN named (`lvw…`, `lvo…`), L2TP, Cisco IPsec, SSTP and system VPNs from the one holding the VPN's address. **IKEv2** with strongSwan 6 (Ubuntu 26.04) is read from the interface strongSwan's plugin creates for the connection (`nm-xfrm-…`). With an older strongSwan there is no interface (the plugin works with the kernel's IPsec policies), so the traffic comes from the kernel's IPsec counters through **`linvpn-xfrmd`**, which answers only for your own connections; then an IKEv2 system VPN shows traffic only when it is set up for every user of the computer (in NetworkManager: no user restriction); one restricted to your user shows none, because the service cannot tell whose it is. Without `linvpn-xfrmd` (a development build) such an IKEv2 connection shows no traffic.
- A greyed connection says why (a missing plugin: [2.4](#24-missing-vpn-plugins); a setting Linux cannot run: [3.7](#37-not-supported-on-linux)).

### 5.1 Multi-factor authentication (MFA)

- **OpenVPN static challenge** (`static-challenge` in the config): LinVPN asks for the code before connecting, as in MacVPN.
- **OpenVPN challenge sent by the server (CRV1):** the code window opens during the connection, with the server's text. Answer it promptly: NetworkManager waits less than 2 minutes.
- **Code appended to the password** (**Ask for a one-time code at connect and append it to the password**, with the **Separator**): OpenVPN, IKEv2, SSTP, L2TP and Cisco IPsec, and L2TP / Cisco IPsec system VPNs, as in MacVPN.
- **Sign-in in the browser** (`OPEN_URL`, `WEB_AUTH`: SAML, SSO) is not available on Linux: NetworkManager's OpenVPN service does not pass it on. Ask your provider for a code-based or password sign-in.

Every code and password reaches NetworkManager only through LinVPN's own **secret agent**: NetworkManager asks LinVPN for them at the moment it needs them, and LinVPN answers only NetworkManager itself, and only for a connect LinVPN started. GNOME's own password windows do not appear for LinVPN's connections.

### 5.2 Credentials asked when connecting

As in MacVPN (see [the MacVPN guide](user-guide.en.md#53-credentials-asked-when-connecting)): a missing user name, password, PSK or private key password is asked for in the **Credentials needed** window before connecting, and **Save in vault** stores it only after the connection came up.

### 5.3 Paired apps (control API)

Another program of your user account, for example the companion app [RemoteDesktop](https://github.com/LovaszCC/RemoteDesktop), can bring LinVPN connections up and down for you once you pair it through the [control API](control-api.md#12-linux-linvpn), as with MacVPN (see [the MacVPN guide](user-guide.en.md#54-paired-apps-control-api)). Turn it on in the Connections window (**Manage Connections…**) under **Paired apps** → **Allow other apps to control VPNs**; it is off by default. On Linux its socket is `$XDG_RUNTIME_DIR/linvpn/control/linvpn.sock` (usually `/run/user/<your user ID>/linvpn/control/linvpn.sock`), readable only by you.

### 5.4 Reconnect automatically

The rules are those of MacVPN (see [the MacVPN guide](user-guide.en.md#55-reconnect-automatically)): after sleep, a network loss or a network switch, a connection comes back by itself on the same network, when none of its own networks is directly reachable there; a dead tunnel is disconnected and reconnected; the slow attempts every 5 minutes for up to an hour; the **Reconnect Automatically** switch per connection. NetworkManager's own automatic reconnect is off for LinVPN's connections: LinVPN alone decides.

- **Retrying and not responding:** while the slow attempts run, the row says **Retrying in 4 min**; a dead tunnel left down (the switch off, or started by a paired app) says **Not responding**, as in MacVPN.
- **Disconnecting outside LinVPN** (GNOME's network menu, `nmcli connection down`) counts as your own disconnect: the connection shows off, is not reconnected, and no notification is posted. Any other end of the connection is a drop, reconnected by the rules above.
- **The network** is what NetworkManager's Ethernet and Wi-Fi devices carry (the router's address and hardware address, and the Wi-Fi name); a VPN is never counted as the network. Turning the network off (GNOME's quick settings, a cable) shows **Waiting for network…**.
- **Dead tunnels.** **WireGuard:** Linux does not let a normal user read WireGuard's last handshake, so LinVPN watches the interface's byte counters: the tunnel is dead when it keeps sending but has received nothing for **200 seconds** (past WireGuard's 3-minute session lifetime). An idle tunnel, which sends nothing, is never called dead. **OpenVPN:** while OpenVPN restarts the tunnel by itself (`ping-restart`), NetworkManager reports it and the row shows **Reconnecting…**; if the restart does not succeed within 2 minutes, the tunnel counts as dead. Otherwise the same counter rule applies to its interface. If NetworkManager keeps the VPN activated through such a restart (it does not report it), the row stays connected and the counter rule decides: once the tunnel keeps sending and has received nothing for 200 seconds, it is disconnected and reconnected. **IKEv2:** the same counter rule applies to its interface's counters (with an older strongSwan, its IPsec counters through `linvpn-xfrmd`): dead when it keeps sending but has received nothing for 200 seconds; an idle IKEv2 tunnel is never called dead (strongSwan's own checks of the server do not count as traffic). strongSwan also ends a connection whose server stops answering its checks, and the drop is reconnected as usual. **SSTP, L2TP and Cisco IPsec** end a dead connection themselves, and the drop is reconnected as usual.

### 5.5 DNS while connected

LinVPN has no DNS manager of its own on Linux: NetworkManager and systemd-resolved set the VPN's DNS while it is up and restore yours when it goes down, also after a crash.

- **Split tunnel:** the VPN's DNS servers answer only for the VPN's own domains (for example `corp.example`); every other name goes to your normal DNS.
- **All traffic over the VPN:** every name is resolved by the VPN's DNS servers.
- `resolvectl status` shows which DNS each interface uses.

### 5.6 Quitting, signing out and sleep

- **On quit** (**Quit LinVPN** in the menu or the panel), LinVPN first asks about unsaved changes in the Connections window (**Save**, **Discard** or **Cancel**). Then, if a connection is active, it asks: **Disconnect and Quit**, **Quit, Keep Them Running** or **Cancel**. **Disconnect and Quit** takes LinVPN's connections and active system VPNs down. With **Quit, Keep Them Running** they stay up, as on macOS and Windows; this is also what happens if LinVPN stops unexpectedly. LinVPN recognizes the connections that kept running on its next launch and shows them as connected again. While LinVPN is not running, you can disconnect them from GNOME's network menu; NetworkManager then forgets them, as it does after any disconnect.
- **Signing out:** LinVPN gets the system's quit request. With unsaved changes in the Connections window it asks about them (**Save**, **Discard** or **Cancel**), but the system does not wait for the answer: it ends the session after a timeout anyway, so save before you sign out.
- **Sleep:** after waking, connections come back by the rules of [5.4](#54-reconnect-automatically).

---

## 6. Debug mode and the log

**The Log tab** of a connection in the Connections window shows, for every type, LinVPN's own steps and the system log lines of that connection:

- LinVPN's lines: the connect (**Connecting with NetworkManager (…)**), the address (**Connected, IPv4 …**; WireGuard and IKEv2 get it a moment later: **Connected (IPv4 address not known yet)**, then **IPv4 address: …**), NetworkManager's state changes and the reason of a failure (for example **AUTH_FAILED: the server refused the login (NetworkManager)**, **Connection timed out (NetworkManager)**).
- The system log's lines, marked with their source: `[nm]` NetworkManager, `[openvpn]` OpenVPN, and the plugin's name (`[charon-nm]`, `[nm-l2tp-service]`, `[pppd]`, `[sstpc]`, `[vpnc]`, …). They come from the system journal through **`linvpn-logd`**, which returns only lines of your own connections. A VPN plugin does not name the connection in its lines, so its lines are shown only when no other VPN was active on the computer at the same time; otherwise they are withheld and the log says **Some plugin lines were withheld: another VPN was active at the same time.**
- Without `linvpn-logd` (a development build, or a damaged installation) only LinVPN's own lines appear, with **The system log is not available (linvpn-logd is not installed).**

The log is the file `~/.local/share/LinVPN/logs/<connection ID>.log` (at most 5 MiB; when it is full its older half is dropped). The filters, **Search**, the time filter, **Follow**, **Copy** and **Save…** work as in MacVPN (see [the MacVPN guide](user-guide.en.md#6-debug-mode-and-the-log)); every line starts with its time, the system log's lines with the journal's time. Passwords, PSKs, keys and codes never appear in it. **Clear Log…** empties LinVPN's copy only: the system journal is not changed, and an administrator can still read it there (`journalctl`).

**Debug mode** (**Alt-click** a switch, or **Connect in Debug Mode** in the Connections window) opens the Log tab and adds the settings LinVPN handed NetworkManager (without passwords: a protected value shows `***`). OpenVPN logs more if its config has a higher `verb` (up to 4).

---

## 7. Troubleshooting

First read the message on the card or in the notification, then the **Log** tab. The causes are those of MacVPN (see [the MacVPN guide's troubleshooting](user-guide.en.md#7-troubleshooting-from-the-log)); on Linux also:

- **LinVPN may not change this computer's network settings without asking for a password. Log in at the desktop and try again.**: LinVPN runs outside a desktop session (for example over SSH), or the administrator restricted NetworkManager. See [1.3](#13-networkmanager-and-its-vpn-plugins).
- **NetworkManager is not running.**: start it (`systemctl status NetworkManager`); an administrator may need to enable it.
- **Another LinVPN (or a LinVPN test) is already registered with NetworkManager for this user.**: NetworkManager accepts one LinVPN per user (its password helper, the secret agent). Quit the other one (a second desktop session of yours, a test run) and connect again.
- **LinVPN needs the user's runtime directory ($XDG_RUNTIME_DIR) to connect.**: LinVPN was started without a normal login session. Start it from the app grid.
- **Not installed: NetworkManager … plugin – System Status**: see [2.4](#24-missing-vpn-plugins).
- **Not supported on Linux: …**: see [3.7](#37-not-supported-on-linux).
- **IKEv2 on Linux needs a pre-shared key of at least 20 characters…**: ask your VPN administrator for a longer PSK, or use EAP or a certificate.
- **AUTH_FAILED: …** in the log: the server refused the user name, password or code (see [the MacVPN guide](user-guide.en.md#71-auth_failed-openvpn)). **AUTH_FAILED: no secrets were given (NetworkManager)** means NetworkManager asked for a secret LinVPN did not have: save the password (or PSK) in the connection and connect again.
- **NetworkManager: the VPN plugin did not start (…)**: the plugin is missing or broken. Check its row in System Status; reinstall the plugin.
- **IKEv2 with EAP fails at once** and the row says **EAP needs …**: install the named packages from System Status. (Without `libcharon-extra-plugins` strongSwan cannot answer the server's EAP identity request; the connection log shows `EAP_IDENTITY not supported, sending EAP_NAK`.)
- **This connection's settings are missing on this computer. Open it and save it again.**: an L2TP or Cisco IPsec connection's record is gone (for example after a restore). Open it and click **Save**.
- **NetworkManager has no VPN with this ID that this user may use.**: a system VPN was removed or restricted to another user.

---

## 8. Updates

LinVPN looks for new versions on the GitHub Releases page at launch and once every 24 hours. This works in the installed LinVPN, not in a development build. The settings are the same as in MacVPN: **Check for Updates Now**, **Check for Updates Automatically** and **Only Offer Updates Published at Least 24 Hours Ago** in the panel's **Settings** group.

When a newer version exists, the panel shows **Update available: vX.Y.Z**; the **Update** window's **Download and Install** button:

1. downloads the package for your computer's architecture (`linvpn_X.Y.Z_amd64.deb` or `_arm64.deb`), its `.sha256` file and its `.sig` signature into `~/.cache/LinVPN/updates`, and checks that the maintainer signed exactly this version and this package file with the offline release key. A package that is not signed by the maintainer is never installed;
2. asks about unsaved changes and active connections, as quitting does (see [5.6](#56-quitting-signing-out-and-sleep): with **Quit, Keep Them Running** the connections stay up and the updated LinVPN shows them as connected);
3. asks for an **administrator's password** in the system's own window (the message says LinVPN wants to install its update). Cancelling the window cancels the update and installs nothing.

The update step then runs as root and checks everything again on its own copy of the package (the signature, that the package is `linvpn`, your architecture, the signed version, and newer than the installed one) before apt installs it. LinVPN never installs an older version. After the installation LinVPN starts again by itself and says **LinVPN was updated to X.Y.Z.** If the update fails, the installed version stays and the installation log is in `~/.cache/LinVPN/updates` (`install-<version>.log`).

NetworkManager, OpenVPN and the VPN plugins are updated by the system's own updates (Software Updater, `apt upgrade`), not by LinVPN. LinVPN's own OpenVPN service comes with LinVPN's package.

You can also install a newer package by hand at any time, as in [1.2](#12-installing-the-package).

## 9. Removing LinVPN

Quit LinVPN (**Quit LinVPN** in the menu or the panel, then **Disconnect and Quit**, so its connections go down), then remove the package as an administrator:

    sudo apt remove linvpn

This removes the app, LinVPN's OpenVPN service, `linvpn-logd` and `linvpn-xfrmd` (their sockets are turned off first), the update step, the app grid entry, the file types and the update permission. NetworkManager, OpenVPN and the VPN plugins stay; remove them with apt if you no longer need them. Your own NetworkManager VPNs (system VPNs) are not touched, and LinVPN left no connection in NetworkManager.

**Your data stays**, also with `apt purge`: the package manager never touches the files in your home folder or your keyring. To remove them too, delete:

- `~/.local/share/LinVPN` (the vault, the connections and their passwords, the connection logs, the L2TP / Cisco IPsec records and the IKEv2 certificate folder `swanctl`),
- `~/.config/LinVPN` (the settings),
- `~/.cache/LinVPN` (downloaded updates and their logs),
- `~/.config/autostart/linvpn.desktop` (launch at login, if it was on),
- the **LinVPN vault key** item in **Passwords and Keys** (the login keyring).

`$XDG_RUNTIME_DIR/linvpn` is emptied by the system when you sign out. Backup files you made with **Back Up Everything…** are yours to delete. If another user of the computer used LinVPN, each of them has their own copy of these.

## 10. Security notes

- **LinVPN runs as you.** Nothing of LinVPN runs as root while you work, except the VPN programs NetworkManager starts for a connection, as for any NetworkManager VPN: LinVPN's OpenVPN service is started by NetworkManager and runs OpenVPN as the `nm-openvpn` user in its own folder, exactly as the standard plugin does, and the route script `90-linvpn-route` NetworkManager runs when a VPN connects (below). The update step runs as root only after you approve an update with an administrator's password; it installs only a package signed by the maintainer, of package `linvpn`, for your architecture, and never an older version.
- **The connections** LinVPN hands NetworkManager are temporary, exist only in memory, and can be used only by your user. They contain no password, PSK or key: NetworkManager asks LinVPN's secret agent for them at connect, and the agent answers only NetworkManager itself, and only for a connect LinVPN started. Nothing goes into GNOME's keyring or NetworkManager's stored connections. The certificate and key files of a config live in your private run folder only while the connection is up.
- **`linvpn-logd`** is not root: systemd starts it for one request at a time as a temporary user in the system journal's group, with no network and no write access. It identifies the caller by the kernel and returns only the lines of that user's own LinVPN connections: it derives the connection's NetworkManager ID from the caller's user ID, so no user can ask for another's.
- **`90-linvpn-route`** runs as root, started by NetworkManager when a VPN connects: it acts only for L2TP and SSTP split tunnels LinVPN marked, checks the interface name and the address strictly, and adds one route through the VPN's own interface, which goes away with it. It gives no new power: a user's own NetworkManager VPN may set any routes through its tunnel without an administrator anyway.
- **`linvpn-xfrmd`** is not root either: systemd starts it for one request at a time as a temporary user whose only permission is to read the kernel's IPsec state (`CAP_NET_ADMIN`; it never changes anything), with no write access and no IP network. It identifies the caller by the kernel, asks NetworkManager which connection is the caller's own (the same derived ID as `linvpn-logd`; a system VPN only when it is for every user) and returns two numbers, the bytes received and sent: never a key, an address or another connection's data.
- **The vault** is encrypted (SQLCipher) with your master password and recovery key, as in MacVPN; the auto-unlock key in the keyring is the trade-off described in [1.4](#14-where-linvpn-keeps-your-data).
- **OpenVPN** keeps MacVPN's directive policy (forbidden and risky directives); the Linux column only adds what NetworkManager cannot run.
- **The control API** listens only on a socket in your private run folder; only programs of your user account can reach it, and only after you pair them.
- **Notifications and window titles** never show a password, a key or a token.
- More in the [MacVPN guide's security notes](user-guide.en.md#10-security-notes), which apply to LinVPN except what they say about the macOS root layer.
