# MacVPN – How-to

[Magyar változat](how-to.hu.md)

Short step-by-step instructions for MacVPN 2.0. The [user guide](user-guide.en.md) has the details; the links below point to its chapters. (WinVPN on Windows: [WinVPN How-to](winvpn-how-to.en.md).)

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
13. [Upgrade from 1.1](#13-upgrade-from-11)
14. [Set up, lock and unlock the vault](#14-set-up-lock-and-unlock-the-vault)
15. [Organize connections in folders](#15-organize-connections-in-folders)
16. [Share one sign-in between connections](#16-share-one-sign-in-between-connections)
17. [Back up everything and restore](#17-back-up-everything-and-restore)
18. [Subscribe to a team catalog](#18-subscribe-to-a-team-catalog)
19. [Share connections with your team (publish a catalog)](#19-share-connections-with-your-team-publish-a-catalog)
20. [Remove a team member's access (rotate the team key)](#20-remove-a-team-members-access-rotate-the-team-key)
21. [Move the admin key to a new Mac](#21-move-the-admin-key-to-a-new-mac)
22. [Choose the appearance and the connection notifications](#22-choose-the-appearance-and-the-connection-notifications)
23. [Reconnect automatically after sleep](#23-reconnect-automatically-after-sleep)

---

## 1. Install MacVPN from the DMG

You need macOS 14 or later and an administrator account.

1. Download the latest `MacVPN-x.y.z.dmg` from the [Releases](https://github.com/SepsiG/MacVPN/releases) page.
2. Open the DMG and drag **MacVPN** onto **Applications**. Eject the DMG.
3. Open MacVPN for the first time. It is ad-hoc signed (not with an Apple Developer ID), so Gatekeeper blocks a normal double-click:
   - **macOS 14:** in Applications, Control-click (right-click) **MacVPN**, choose **Open**, then click **Open**.
   - **macOS 15 or later:** double-click MacVPN, close the warning, then go to **System Settings → Privacy & Security**, click **Open Anyway**, enter your password and click **Open Anyway** again.
4. A shield appears in the menu bar, and the **Set Up the Vault** window opens: choose a master password and save the recovery key ([section 14](#14-set-up-lock-and-unlock-the-vault)).

Details: [user guide, 1](user-guide.en.md#1-installation).

## 2. Finish the setup

The **System Status** window opens by itself when something is missing (later: menu → **System Status**). L2TP and Cisco IPsec work without these steps.

1. **Homebrew:** if it is red, click **Install…**. Terminal opens with the official installer; follow it, then click **Check Again**.
2. **VPN tools:** click **Install**. The `brew install` output appears in the window. You can close the window meanwhile; it keeps going. Later, when Homebrew has a newer version of a VPN tool, the row says **Update available: …** and **Update** upgrades just those packages. MacVPN runs `brew update` about once a day by itself, so the offer stays current.
3. **Permissions (root scripts + sudoers):** click **Authorize** and enter your admin password once (MacVPN 2.0 installs root layer 9). This installs the `mvpn` root binary and the sudoers rule, so connecting needs no password later.
4. When all three rows are green, you are done.

Details: [user guide, 2](user-guide.en.md#2-first-launch-and-the-system-status-window).

## 3. Add a connection

Open the menu → **New Connection / Import…** (or **Manage Connections…**). This opens the **Connections** window.

**To import files:** click **New** (+) → **Import from File…** and select one or more files, or drag the files into the window. Then select the new connection, fill in the password fields and click **Save** (⌘S).

**From Finder:** double-click a `.ovpn` or `.sstp` file (or select several and press ⌘↓). MacVPN opens the Connections window and imports them, asking the same questions; nothing connects. A downloaded file asks once more first (**Import** or **Cancel**). If the vault is locked, unlock it first in the window that appears. For a WireGuard or strongSwan `.conf`, Control-click it → **Open With → MacVPN** (MacVPN does not take `.conf` files over, other programs use them too). If another VPN app opens your `.ovpn` files, use **File → Get Info → Open with → MacVPN → Change All…**. Details: [user guide, 4.1](user-guide.en.md#41-opening-vpn-files-from-finder).

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
2. Click the switch on the connection's card. While it connects, the switch and the badge on the type bubble are amber and the card says **Connecting…**; when it is up, they turn green and the card shows the IP address and the elapsed time.
3. Click the switch again to disconnect.

You can also use **Connect** / **Disconnect** in the Connections window. Several connections can be active at once. A red badge means an error; the short reason is on the card, and a notification tells you too ([section 22](#22-choose-the-appearance-and-the-connection-notifications)). **Held by …** on a card means a paired app keeps that VPN up ([user guide, 5.4](user-guide.en.md#54-paired-apps-control-api)).

When you quit with active connections, MacVPN asks: **Disconnect and Quit**, **Quit, Keep Them Running** or **Cancel**.

**If a password is not saved,** MacVPN asks for it in a **Credentials needed** window before connecting (only the missing fields). Click the window (it does not take the keyboard from your current app), type, and click **Connect**; Return does nothing. With **Save in vault** ticked, the values go into MacVPN's encrypted vault once the connection is up. If the server rejects them, the window asks once more. **Cancel** stops the connect without an error.

**Connect without storing the password:** untick **Save in vault** in the **Credentials needed** window before clicking **Connect**. The values are used for this connect only, and MacVPN asks again next time. To make it ask again for a password you saved earlier, open the connection in the Connections window and use **Remove saved password** (or **Forget saved secrets**).

Details: [user guide, 5.3](user-guide.en.md#53-credentials-asked-when-connecting).

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

Exports never contain passwords or PSKs. They carry the connection's folder and the name of its shared credential, so an import puts it back in its folder. `.ovpn`, WireGuard `.conf`, `.swanctl.conf` and `.sstp` files can be imported again; an L2TP / Cisco `.mobileconfig` export is installed on another Mac by double-clicking it in Finder.

**To back up everything with the passwords,** use **Back Up Everything…** instead ([section 17](#17-back-up-everything-and-restore)). Your data lives in the encrypted vault in `~/Library/Application Support/MacVPN`; copying that folder copies the vault, but you need the master password or the recovery key to open it.

## 9. Update MacVPN

1. When a new version is out, the menu shows **Update available: vX.Y.Z**. (Or open **Settings** in the menu and choose **Check for Updates Now**.)
2. Click it, read the notes, then click **Download and Install**.
3. Answer the questions about unsaved changes and active connections. MacVPN checks the signature, replaces itself and restarts.
4. If macOS asks whether MacVPN may use its Keychain item (the vault key, at most once per update), click **Always Allow**, but only if the prompt names MacVPN at `/Applications/MacVPN.app`.
5. If **System Status** opens with **Update required**, click **Authorize** and enter your admin password. Updating from 1.x to 2.0 always asks for this once (**Update required (8 → 9)**); until then OpenVPN, WireGuard, IKEv2 and SSTP connections are greyed.

Coming from 1.1? Follow [section 13](#13-upgrade-from-11). Coming from 0.x? Read [Upgrading from 0.x](user-guide.en.md#81-upgrading-from-0x) first. Details: [user guide, 8](user-guide.en.md#8-updates) and [Upgrading from 1.5](user-guide.en.md#84-upgrading-from-15).

## 10. Start MacVPN at login

1. Make sure MacVPN runs from the Applications folder.
2. Open the menu → **Settings** and turn on **Launch at Login** (also in the System Status window).
3. If a note asks you to approve it, click **Open Login Items Settings…** and turn MacVPN on there.

If the note says **Enabled via a login LaunchAgent (applies at next login).**, it starts from your next login. Untick the box to turn it off. Details: [user guide, 2.1](user-guide.en.md#21-launch-at-login).

## 11. Uninstall MacVPN

1. Open **System Status** and click **Uninstall MacVPN…**.
2. To delete your data too, tick **Also delete user data**: the vault with every connection and password, the vault key in the Keychain, and the old MacVPN 1.1 Keychain items. Backup files you made are not deleted.
3. Click **Uninstall** and enter your admin password. Active connections are disconnected first.
4. Click **Quit MacVPN**, then drag `MacVPN.app` to the Trash.
5. Optionally remove the Homebrew packages (`brew uninstall openvpn wireguard-tools strongswan sstp-client`) and any L2TP / Cisco profiles in **System Settings → General → Device Management**.

Details: [user guide, 9](user-guide.en.md#9-uninstalling).

## 12. Troubleshooting FAQ

**A connection is grey and says "Not installed: … – System Status".**
The Homebrew tool for that type is missing. Click **System Status** in that line and **Install**. New and import offer only the types that can be used. [More](user-guide.en.md#24-missing-vpn-tools)

**A connection is grey and says "Not ready: Permissions (root scripts + sudoers) – System Status".**
The root layer is not installed or outdated (for example right after updating from 1.x). Open **System Status** and click **Authorize**.

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
With **Unlock automatically** on, this is expected once per update (for the vault key), because MacVPN is ad-hoc signed; with it off, an update asks nothing. Allow it only if the prompt names MacVPN at `/Applications/MacVPN.app`.

**"Installation cancelled: /usr/local/libexec is not owned by root…" when clicking Authorize.**
Fix the folder's owner in Terminal as the message says, then click **Authorize** again. [More](user-guide.en.md#78-other)

**A connection did not come back after sleep.**
The notification says why: **You are on a different network.**, **The VPN’s network is directly reachable here.** (for example at the office), or **Unlock the vault to reconnect.** Connect it by hand. [More](user-guide.en.md#55-reconnect-automatically)

**Websites do not open on my normal network with no VPN connected.**
An older MacVPN could leave a VPN's DNS server set after a crash or a restart while connected. Remove the VPN's DNS servers once in **System Settings → Network →** the service **→ Details… → DNS**. From 2.0 the root layer restores the DNS itself. [More](user-guide.en.md#56-dns-while-connected)

**The update says the app's location is not writable.**
Move MacVPN to the Applications folder and try again, or install the new DMG by hand.

**I forgot the master password.**
In the **Unlock MacVPN** window click **Use recovery key**, type the recovery key and a new master password, then **Reset and Unlock**. [More](user-guide.en.md#118-forgotten-master-password)

**I lost the recovery key.**
While you still know the master password: menu → **Settings** → **New Recovery Key…**. If both are lost, **Unlock automatically** still opens the vault (export what you need); without it nobody can open the vault. A backup made with your master password needs the master password of that time; the recovery key never opens a backup. Restore a backup you can open, or set MacVPN up again. [More](user-guide.en.md#15-vault-faq)

**The menu only shows "Unlock…".**
The vault is locked; running VPNs are still up. Click **Unlock…** and enter the master password. [More](user-guide.en.md#115-the-locked-menu)

**The upgrade from 1.1 says "The migration did not finish".**
Nothing was deleted, and MacVPN runs read-only from your 1.1 data. Click the banner in the menu and create the vault again with a new master password. [More](user-guide.en.md#82-upgrading-from-11)

**macOS asked many times for Keychain access after the upgrade to 1.2.**
Expected once: one prompt per old saved password during the migration. Choose **Always Allow** each time. Later updates ask at most once, and only while **Unlock automatically** is on. [More](user-guide.en.md#15-vault-faq)

**A folder cannot be deleted.**
A connection inside it is active. Disconnect it first. [More](user-guide.en.md#125-deleting-a-folder)

**I cannot change the password field of a connection.**
It uses a shared credential. Change it in **Credentials**. [More](user-guide.en.md#133-using-a-credential-in-a-connection)

**The backup cannot be opened.**
The backup password is wrong, or the file is damaged; MacVPN does not tell which. [More](user-guide.en.md#14-backup-and-restore)

## 13. Upgrade from 1.1

The in-app update of 1.1 goes straight to the current version (2.0), and its first launch moves your data into the vault.


1. Quit MacVPN 1.1 and copy its data: `cp -R ~/Library/Application\ Support/MacVPN ~/MacVPN-backup-1.1`. Keep your passwords at hand (for example in a password manager). Start MacVPN again.
2. Menu → **Check for Updates Now** → **Download and Install**.
3. In the **Set Up the Vault** window, note how many Keychain prompts it announces, click **Continue**, choose a master password (at least 10 characters) and click **Create Vault**.
4. Save the recovery key (it is shown only once), click **I Saved It**, type the group it asks for and click **Confirm**.
5. While **Moving your data into the vault…** runs, answer every Keychain prompt that names MacVPN at `/Applications/MacVPN.app` with **Always Allow**.
6. Check the result (**Your data is in the vault**) and click **Continue**, then **Done**.
7. In **System Status**, click **Authorize** for **Update required (7 → 9)** and enter your admin password.
8. Connect each connection once.

If the migration fails, nothing is deleted: click the menu's banner and try again. Details: [user guide, 8.2](user-guide.en.md#82-upgrading-from-11).

## 14. Set up, lock and unlock the vault

**Lock it now:** click **Lock Now** at the bottom of the menu. If you do not see it, open **Settings** and switch on **Show “Lock Now”** (it is always shown when **Unlock automatically** is off). Running VPNs stay up.

**Unlock it:** click **Unlock…** in the menu, type the master password and click **Unlock**.

**Ask for the password at every launch:** **Settings** → switch off **Unlock automatically** → **Turn Off**. To go back, switch it on and enter the master password.

**Change the master password:** **Settings** → **Change Master Password…** → the current password, the new one twice → **Change Password**. The recovery key stays the same.

**Make a new recovery key:** **Settings** → **New Recovery Key…** → master password → **Make New Key**, save it, **I Saved It**, type the group, **Confirm**. The old key stops working.

**Reset a forgotten master password:** in the **Unlock MacVPN** window, **Use recovery key** → the recovery key and a new password twice → **Reset and Unlock**.

Details: [user guide, 11](user-guide.en.md#11-vault).

## 15. Organize connections in folders

1. Open the **Connections** window. Click **New** (+) → **New Folder**, type a name (up to 64 characters) and press Return.
2. Drag connections onto the folder. Drag a folder onto another folder to nest it, or between folders to reorder. Drop on **Top level** to take something out of all folders.
3. Right-click a folder for **Rename**, **Colour…**, **Move to Top Level** and **Delete…**; right-click a connection for **Colour…** (or **Use folder colour**) and **Pin to Top**.
4. To delete a folder, choose **Delete…**. By default its contents move up one level; **Delete the connections too** asks again before deleting them.

In the menu, click a folder to open or close it; its badge shows how many connections inside are active. Details: [user guide, 12](user-guide.en.md#12-folders-and-colours).

To find a connection, press **⌘F** in the **Connections** window (or click **Search connections**) and type part of its name, type, server, folder or team catalog; accents and case do not matter. Use **↑** / **↓** and Return to open a result, Esc to clear the search. Details: [user guide, 12.8](user-guide.en.md#128-searching-connections).

## 16. Share one sign-in between connections

**From scratch:**
1. **Connections** window → **Credentials** in the sidebar → **Add Credential…**.
2. Enter a **Name**, the **Username** and (optionally) the **Password**, and save.
3. Open each connection that should use it, set **Password from** to **Use credential: <name>**, confirm with **Use Credential**, and save.

**From a connection that already has the user name and password:**
1. **Credentials** → **Create from Connection…**, pick the connection and a name, click **Next**.
2. Tick the other connections with the same sign-in, and click **Create and Link**.

**Change the password for all of them:** **Credentials** → the credential → **Edit…**, type the new password, save.

**Stop sharing:** delete the credential and choose **Copy into Each Connection**.

When you import a file that names a shared credential, MacVPN asks before linking it and shows the server; choose **Use Own Fields** unless you trust the file. Details: [user guide, 13](user-guide.en.md#13-shared-credentials).

## 17. Back up everything and restore

**Back up:**
1. Menu → **Settings** → **Back Up Everything…**.
2. Type a backup password (at least 10 characters) twice, and your master password. (Or **Use my master password…**, which ties the file to your master password.)
3. Click **Back Up…** and choose where to save `MacVPN-backup-<date>.macvpnbackup`.
4. Keep the file and its password in different places.

**Restore on a new Mac:**
1. Install and start MacVPN. In the **Set Up the Vault** window click **Restore from backup…**.
2. **Choose File…**, type the backup password, **Open Backup**.
3. Choose a new master password and save the new recovery key.
4. Tick the preferences you want, then **Apply Selected Preferences**. Reinstall the L2TP / Cisco profiles with **Reinstall … Native Profiles** and approve them in System Settings. Pair your paired apps again.

**Restore into the current vault:** menu → **Settings** → **Restore from Backup…**, open the file, read the summary, then choose **Merge** (adds what is missing; choose what happens to items that already exist) or **Replace Everything…** (deletes what is not in the backup; you can **Back Up the Current State First…**).

Details: [user guide, 14](user-guide.en.md#14-backup-and-restore).

## 18. Subscribe to a team catalog

You need from your administrator: a subscription string (`macvpn-sub:…`), or the source, the team key and the publisher fingerprint; and, for some web servers, an access token.

1. **Connections** window → **Team catalogs** in the sidebar → **Add team catalog…**. Or double-click the `.macvpncatalog` file in Finder: the dialog opens with that file as the source (go on with the team key and the fingerprint).
2. Paste the subscription string (as one line). Or enter the **Source** (an `https://` URL, or **Choose File…** on a share or in iCloud Drive, OneDrive or Dropbox), the **Team key** and the **Publisher fingerprint**.
3. If the web server needs it, enter the **Access token**.
4. Click **Check**. Compare the fingerprint in the preview with the one your administrator gave you by phone or in person. If it differs, stop.
5. Click **Subscribe**. The connections appear in a folder named after the catalog, with a **Team** badge.
6. Connect. The first time, MacVPN asks for your own user name and password for each credential slot (for example **Office AD**); tick **Save in vault**.

MacVPN refreshes the catalog at launch, every 15 minutes and on wake; **Refresh now** checks at once. To leave, select the catalog and click **Unsubscribe…** (connections that are up are disconnected first). To keep a connection for yourself, use **Duplicate as personal connection…** first. Details: [user guide, 16](user-guide.en.md#16-team-catalogs).

## 19. Share connections with your team (publish a catalog)

**Once:**
1. **Connections** window → **Publishing** → **Generate Admin Key**. Note the fingerprint.
2. **Generate Backup Admin Key** → **Export Backup Key…**, a password of at least 10 characters, tick **Remove the backup key from this Mac after export**. Keep the file offline and its password elsewhere.

**Publish:**
1. **Publishing** → **Publish Catalog…**.
2. Tick the folders and connections to share.
3. Tick only the team secrets everyone may know (for example a shared PSK). Leave the rest unticked.
4. Keep the credential slots ticked: members then enter their own user names and passwords.
5. Fix anything the review lists as refused. For a WireGuard private key, tick that everyone uses the same key, or leave the connection out.
6. Name the catalog and save `<name>.macvpncatalog`.
7. Copy the **team key** (shown only now), keep it safe, click **I Saved It** and type the group it asks for.
8. Put the file where the team reads it:
   - **Web server:** upload it so it is served over `https://` with a certificate macOS trusts (optionally behind a bearer token).
   - **File share:** copy it to the SMB or NFS share the team mounts.
   - **Synced folder:** save it in a shared iCloud Drive, OneDrive or Dropbox folder.
9. **Copy Subscription String…**: enter your master password and the URL or path your team will use. Send the string through a secure channel (not plain e-mail), and tell the fingerprint separately, by voice.

**A new version:** edit the connections as usual, then **Publish New Version…** in **Publishing**, and save to the same place (upload it again for a web server). Members get it within 15 minutes, or at once with **Refresh now**. Details: [user guide, 16.8](user-guide.en.md#168-for-administrators-publishing-a-catalog).

## 20. Remove a team member's access (rotate the team key)

1. **Connections** window → **Publishing** → the catalog → **Rotate Team Key…**. Read the explanation and confirm.
2. Confirm the file location in the save panel. The new version is published there at once (upload it again for a web server).
3. Copy the **new team key** (shown only now), click **I Saved It** and type the group.
4. Send the remaining members the new key (or a new subscription string from **Copy Subscription String…**) through a secure channel. They see **The team key of “…” has changed**, and enter it with **Change team key…** in **Team catalogs**.
5. Change any team secrets that were in the catalog (for example the PSK on the server), and disable the person's account on the VPN server.

The person who left keeps what they already downloaded, but cannot open any newer version. Details: [user guide, 16.9](user-guide.en.md#169-for-administrators-the-team-key-and-the-subscription-string).

## 21. Move the admin key to a new Mac

Your publications (each catalog's id, version and team key) are in the vault, next to the admin key. Move them together, with a full backup.

1. On the old Mac: **Settings** → **Back Up Everything…** ([17](#17-back-up-everything-and-restore)).
2. On the new Mac: install MacVPN 1.3 or later and restore the backup (**Restore from backup…** in **Set Up the Vault**).
3. **Connections** window → **Publishing**: check that the admin key's fingerprint is the old one and that every publication is listed.
4. Publish the next version of each catalog to the same place. Members notice nothing.
5. Delete the backup file once you no longer need it, or keep it as safely as the admin key. On the old Mac, **Uninstall MacVPN…** with **Also delete user data (connections, the vault and its key)** ticked.

**To retire the old key at the same time** (for example the old Mac goes to someone else): after step 2, **Import Admin Key…** with your `.macvpnadminkey` file, then **Switch to the Backup Key…**, publish each catalog, and generate and export a new backup key. Members who refreshed since the backup key was created follow automatically; the others must subscribe again.

**Without a full backup** (the old Mac is lost): the backup key file alone does not hold the publications, so the next publish makes a new catalog. Publish the connections as a new catalog and send every member the new subscription string; they unsubscribe from the old one. If the lost Mac's vault may have been open, treat the admin key as leaked: see [user guide, 16.10](user-guide.en.md#1610-changing-the-admin-key-and-compromise).

## 22. Choose the appearance and the connection notifications

**Appearance:** menu → **Settings** → **Appearance**: **Match System** (the default), **Light** or **Dark**. It applies at once to the menu and every window.

**Connection notifications:** MacVPN tells you when a connection connects, drops, is reconnected or fails, with a short reason in plain words. The notification names only the connection. Click it to open the connection's **Log** tab. To turn them off: menu → **Settings** → switch off **Connection Notifications**. Code and credential requests still notify you. To change how they look, use **System Settings → Notifications → MacVPN**.

Details: [user guide, 2.2](user-guide.en.md#22-appearance) and [2.3](user-guide.en.md#23-connection-notifications).

## 23. Reconnect automatically after sleep

A connection that went down because the Mac slept or the network went away comes back by itself, but only when both hold:

1. **None of the VPN's own networks or DNS servers is directly reachable** on the network you are on (for example you are in the office the VPN leads to). This is checked first.
2. **You are on the same network** as when the connection came up (the same router; MacVPN does not reconnect on a network it cannot identify).

MacVPN tries up to 3 times and tells you the result (**… reconnected**, **… not reconnected** with the reason, or **… could not reconnect**). A connection you disconnected yourself is never reconnected. A tunnel that stayed up through the sleep is disconnected when its network is directly reachable on the new network.

**To turn it off for one connection:** **Connections** window → the connection → switch off **Reconnect Automatically** (system VPNs do not have it).

Details: [user guide, 5.5](user-guide.en.md#55-reconnect-automatically).
