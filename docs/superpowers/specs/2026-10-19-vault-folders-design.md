# MacVPN – Encrypted vault, folders, shared credentials and credential prompts – design

**Date:** 2026-10-19
**Status:** design agreed in conversation (scope, recovery key, auto-unlock, folders, colours); this written spec awaits review.
**Base:** MacVPN 1.0/1.1 (Rust/Tauri). The main spec (`2026-10-16-macvpn-design.md`) and its section 3 security rules still apply.
**Release:** sections 4–5 ship in 1.1.0; sections 2, 3, 3a and 3b ship in 1.2.0, where the root layer changes and root `VERSION` goes to 8.

## 1. Goals

1. **Encrypted vault.** Every piece of user data moves into one encrypted SQLite database. A master password protects it, and the database key is cached in the OS key store so the app unlocks on its own. That data is:
   - connections and their configs, including embedded private keys
   - usernames, passwords, PSKs, key passwords and OTP secrets
   - folders and colours
   - order and ranking
   - system-VPN OTP settings
   - paired control-API clients

   The vault has these properties:
   - The OS key store is asked for **one** key instead of one Keychain item per secret, so there are far fewer macOS password prompts.
   - The same design works on Linux (Secret Service / libsecret) and on Windows (DPAPI / Credential Manager).
2. **Folders.** Folders can be nested to any depth, and each folder can take a colour from a palette. A connection inherits the colour of its nearest coloured ancestor, and the user can override that on the connection.
3. **Credential prompt.** When a connection needs a username and password (or a PSK) that is not stored, MacVPN asks for it in a modal before connecting. The user can choose to save it in the vault.
4. **Shared credentials.** A username and password can be defined once, centrally, and selected in any number of connections. Changing the password there updates every connection that uses it.
5. **Full backup and restore.** All data, secrets included, can be exported into one encrypted backup file and restored on a reinstalled or new Mac.
6. **Live system-VPN list.** Adding, changing or deleting a system VPN in macOS shows up in MacVPN at once, without reopening windows.

**Not goals:**
- syncing between machines
- several vaults or several users
- changing the update-signing model

## 2. Vault

### 2.1 Storage

- **File:** `~/Library/Application Support/MacVPN/vault.db`, mode 0600, in a 0700 directory. Elsewhere it goes in the platform's app-data directory.
- **Encryption:** SQLCipher 4 through `rusqlite`. The whole file is encrypted (AES-256, per-page HMAC-SHA512), so neither the schema nor the row counts are visible.
  - Plan task 1 is a spike that settles the crypto provider: CommonCrypto on macOS, vendored OpenSSL on Linux/Windows.
  - The spike also has to show that the universal (arm64 + x86_64) build works in `scripts/build-dmg.sh` and in CI.
  - If SQLCipher can't be built reliably, the fallback is plain SQLite with every payload column sealed by XChaCha20-Poly1305 (RustCrypto, pure Rust), with only random ids left in the clear. The key hierarchy below stays the same in both cases.
- **Database key (DEK):** 32 random bytes from `getentropy`, passed as a raw key (`PRAGMA key = "x'…'"`), so SQLCipher's own KDF is not used.

### 2.2 Key hierarchy

`vault.keys` is a small JSON file next to `vault.db`, mode 0600, written atomically. It holds two **wrapped copies** of the DEK:

- **Password slot:**
  - `KEK_pw = Argon2id(master password, salt₁, m=64 MiB, t=32, p=1)` (the spike raised t from 3 to 32, about 0.66 s on an M5)
  - `wrap = XChaCha20-Poly1305(KEK_pw, nonce, DEK, aad="macvpn-vault-v1|pw")`
- **Recovery slot:**
  - `KEK_rc = Argon2id(recovery key, salt₂, its own parameters, by default the same)`
  - the DEK wrapped the same way, with `aad="…|rc"`
- **Recovery key:** 120 random bits, shown as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` in base32 Crockford.
  - It is shown **once**, when the vault is created and whenever the user asks for a new one.
  - The user has to confirm that they saved it, by retyping one group.
- The file stores a version, and **each slot stores its own KDF parameters**, so the two slots can be raised independently.
  - Parameters read from the file must lie between a floor (64 MiB, t ≥ 3, p ≥ 1) and a ceiling (1 GiB, t ≤ 256, p ≤ 16); anything else makes the file corrupt. This stops a tampered file from downgrading the KDF or from making it allocate or run without limit.
  - Every new wrap (create, a new password, a new recovery key) uses the slot's parameters raised to at least the default (64 MiB, t = 32, p = 1); parameters are never lowered.

The slots make these operations cheap:
- **Changing the master password** only rewraps the password slot. The database is not re-encrypted.
- **A new recovery key** rewraps the recovery slot and invalidates the old one.
- **Resetting** the master password with the recovery key opens the recovery slot, then sets a new password slot.

The master password must be at least 10 characters. The setup shows a strength hint but does not block weak passwords beyond that minimum.

### 2.3 Unlocking

- **Auto-unlock** is on by default and can be turned off in the settings.
  - **On:** the DEK is stored as one item in the macOS Keychain: service `local.macvpn.vault`, account `dek`, data-protection class "when unlocked".
    - At launch the app reads it and opens the vault, with no password prompt.
    - After an update, macOS may ask **once** for Keychain access, because the ad-hoc signature changed.
  - **Off:** the Keychain item is deleted, and every launch asks for the master password.
- **The unlock window** appears when there is no Keychain item or it can't be read. It takes either the master password or a "Use recovery key" link. Wrong attempts are delayed, 1 s and growing; there is no lockout.
- **"Lock now" menu item:**
  - closes the database and wipes the DEK from memory (`zeroize`)
  - **does not** delete the Keychain item, so the next launch still auto-unlocks
  - leaves running VPNs up
  - shows the menu in a locked state: a "Unlock…" row, with connection names hidden

  The menu item is shown only when auto-unlock is off, or when the user turns on "Show Lock now".
- **While locked**, nothing that reads the vault works: connect, edit, import, export and the control API. The control API answers `locked`, a new error code added to API v1 in a compatible way.
- **Platform abstraction:** a `KeyStore` trait in `crates/core` with `get/set/delete`, implemented in `platform-mac` (Keychain). Linux (libsecret) and Windows (DPAPI) implementations come later. The vault logic itself is platform-independent in core.

### 2.4 Schema (SQLite inside SQLCipher)

```
meta(key TEXT PRIMARY KEY, value TEXT)                     -- schema_version, created
folders(id TEXT PK, parent_id TEXT NULL REFERENCES folders ON DELETE CASCADE,
        name TEXT NOT NULL, color TEXT NULL, position INTEGER NOT NULL, collapsed INTEGER NOT NULL DEFAULT 0)
connections(id TEXT PK, kind TEXT NOT NULL, meta_json TEXT NOT NULL,   -- today's meta.json contents
            config BLOB NOT NULL, folder_id TEXT NULL REFERENCES folders ON DELETE SET NULL,
            color TEXT NULL, position INTEGER NOT NULL)
secrets(connection_id TEXT, field TEXT, value BLOB, PRIMARY KEY(connection_id, field))
credentials(id TEXT PK, name TEXT NOT NULL UNIQUE, username TEXT NOT NULL, password BLOB NULL,
            created TEXT NOT NULL, updated TEXT NOT NULL)
credential_links(item_id TEXT PK,             -- managed connection UUID or system-VPN service ID
            credential_id TEXT NOT NULL REFERENCES credentials ON DELETE RESTRICT)
system_items(service_id TEXT PK, folder_id TEXT NULL, color TEXT NULL, position INTEGER NOT NULL)
system_otp(service_id TEXT PK, json TEXT NOT NULL)
ranking(id TEXT PK, json TEXT NOT NULL)
pins(id TEXT PK, position INTEGER NOT NULL)
control_clients(id TEXT PK, json TEXT NOT NULL)
```

- The `meta_json` format stays compatible with the export format and the Swift-era `meta.json`, so import and export don't change.
- Foreign keys are on. Each write runs in a transaction, with `journal_mode=WAL` and `secure_delete=ON`.
- Folder cycles are rejected in code: a folder can't move under its own descendant.

**Schema versioning.** `meta` holds `schema_version` (an integer) and `min_app_schema`, the lowest app schema that may write this database. On open, MacVPN compares them with the app's `CURRENT_SCHEMA`:

- **The database is older:** it is migrated automatically.
  1. First a byte copy of the still-encrypted file is made, after a WAL checkpoint: `vault.db.bak-v<old>`, mode 0600. Only the last 2 such backups are kept.
  2. Then each migration step v→v+1 runs in order, each in its own transaction (a savepoint inside one outer transaction).
  3. `schema_version` (and `min_app_schema`) are updated in the same transaction as the last step.
  4. If any step fails, everything is rolled back: the database stays at the old version, the backup is kept, and the app reports a clear error. A half-migrated database never exists.
- **Equal:** normal.
- **The database is newer than the app** (written by a newer MacVPN), or `min_app_schema` is above the app's schema: it is opened **read-only** (`SQLITE_OPEN_READONLY` plus `PRAGMA query_only=ON`), as long as every table and column the app knows can still be read. Connecting with the stored data still works. Every write path (save, delete, import, folder edits, ranking updates, backup restore, control-client changes) is refused with a typed `VaultError::NewerSchema { db, app }`, so the UI can say "This data was saved by a newer MacVPN — update the app to make changes". If the app cannot even read it, opening is refused with the same error.
- **Rule:** a migration must never be needed to *read* an older database, and an older app must never write to a newer database. Schema changes are therefore additive where possible.

### 2.5 Root-layer change (root VERSION 8)

- Today `mvpn` copies the config from the user's directory itself, with `sudo -u <user> cat`. Configs no longer exist as plain files, so **the app sends the config on stdin** together with the secrets:
  - The app sends a length-prefixed framing: `config <len>\n<bytes>`, then the existing secret lines.
  - `mvpn` reads it with the existing size limit (1 MB), writes it only into its root-only run directory (0700), and validates it exactly as it does today.
- `mvpn validate` takes the config on stdin too. The old `--config-path` form is removed.
- `scripts/test-root.sh` is updated for the stdin delivery. All existing cases must stay green, and new ones cover:
  - a truncated stream
  - a length mismatch
  - an oversize config
  - an embedded NUL
- The installer replaces VERSION 7 with 8, using the existing hash-checked install. The app requires root VERSION 8 and offers the reinstall through the existing "Update required" flow.

### 2.6 Native L2TP/Cisco profiles

- Plan task 1 checks where macOS keeps the secrets of the native VPN profiles that MacVPN installs. If macOS requires them in its own System Keychain (as part of the profile), they stay there, because macOS owns those profiles.
- MacVPN's own copies (for the editor and for start options) move into the vault. If the secrets can be passed at start through SCNetworkConnection options, MacVPN does that and keeps no other copy.

### 2.7 Migration (first launch of 1.2.0)

1. A first-run "Create vault" window: set the master password, then save the recovery key and confirm it. Auto-unlock is on by default.
2. MacVPN imports into the vault, inside one transaction:
   - every connection directory (meta and config)
   - every Keychain item `local.macvpn.secrets/<UUID>.<field>`
   - `connection-order.json`, `system-otp.json` and the control-API registry

   macOS may ask for Keychain access for each old item. The window shows this ahead of time ("macOS may ask several times — choose Always Allow — this happens only once").
3. A verification pass reads every record back and compares it with the source.
4. Only after verification succeeds:
   - the old files are deleted (overwritten first, then unlinked)
   - the old Keychain items are deleted
   - a `migrated-to-vault` marker is written

   If migration fails, nothing is deleted. The app reports the error and keeps working from the old storage in read-only mode until the user retries.
5. A backup reminder: the window offers "Export all" before deleting the old data.

## 3. Folders and colours

- **Nesting:** folders nest to any depth. Connections (managed ones and system VPNs) can be in a folder or at the root.
- **Colour palette:** 12 colours tuned to look good in light and dark mode, plus "none". The tokens are defined in the UI design system: red, orange, amber, yellow, lime, green, teal, cyan, blue, indigo, purple, pink.
- **Inheritance:** a connection's effective colour is its own colour, or else the nearest ancestor folder's colour, or else none. A folder with no colour of its own also inherits from its parent. The UI marks an explicit override, and offers "Use folder colour" to clear it.
- **Ordering:**
  - Within a folder: pinned items first, in pin order, then by the existing usage ranking (14-day half-life).
  - Subfolders come before connections and keep their manual order (`position`).
  - The root behaves the same way.
- **Menu window:**
  - Folders are collapsible rows with a coloured folder icon and a count of active connections. The collapsed state is persisted.
  - A connected item inside a collapsed folder still shows on the folder row as a green dot plus the count.
  - Nesting is shown with indentation, capped visually at 3 levels; deeper levels still work.
- **Manage window:**
  - A tree with drag and drop for moving and reordering, and for moving between folders.
  - Context menu: New folder, Rename, Colour, Delete.
  - "Delete folder" asks whether to move its contents to the parent (the default) or to delete the connections too, with an extra confirmation for that.
- **Export/import:**
  - Export writes the folder path in the exported metadata, as an optional field.
  - Import recreates missing folders.
  - Older exports without folders import to the root.

## 3a. Shared credentials

- **What a credential is:** a named username + password pair stored in the vault, for example "Company AD" or "Office L2TP user". The password is optional; if it is empty, the credential prompt (section 4) asks for it.
- **Where it is managed:** the Manage window gets a new **Credentials** section (HU: „Hitelesítő adatok”).
  - The list shows each credential's name, username, and how many connections use it.
  - Actions: add, edit, rename and delete.
  - The password field follows the existing secret-field pattern ("Saved — type to replace"). It is never sent to the webview.
- **Choosing one in a connection:** each connection editor that has username/password fields (OpenVPN `auth-user-pass`, L2TP, Cisco IPsec, IKEv2 EAP, SSTP, and system VPNs that MacVPN stores secrets for) gets a selector:
  - **Own username and password**, the default and today's behaviour, or
  - **Use credential: <name>**. The connection's own username and password fields are then hidden, and its own stored username and password are deleted after the user confirms.
  - A linked connection's editor never writes the username or password: saving it cannot change the shared credential that the other connections use. The credential is changed only in the Credentials section, or by "Save" in the credential prompt (below).
  - Other secrets (PSK, key password, OTP secret) stay per connection.
- **At connect time:**
  - The username and password are taken from the linked credential.
  - If the credential has no password, the credential prompt asks for it and names the credential ("Password for Company AD — used by 4 connections"). "Save" stores it in the credential.
  - A sign-in failure re-prompts once, the same as in section 4. A new password saved there updates the shared credential.
- **Deleting a credential that is in use:** a question lists the connections and offers two choices: "Copy into each connection", which turns them back into their own username and password, or Cancel. A credential is never deleted silently while it is linked (`ON DELETE RESTRICT`).
- **Export and import:**
  - Export never contains secrets. It writes `credentialName` in the exported metadata.
  - On import, nothing is linked automatically: an imported file chooses its own server, so a silent link would send the shared password to whatever host the file names. When a credential with the same name exists, the user is asked "Use the shared credential '<name>' for this connection to <server>?", where <server> is the remote host read from the config. The default answer is the connection's own fields. When no credential has that name, the user is asked to pick a credential or to use the connection's own fields.
  - The folder path in the metadata follows the folder-name rules; a line with an invalid name is ignored.
- **Control API:** no change. The API never sees credentials.
- **Migration from 1.1:** nothing is converted automatically. In the Credentials section, a **"Create from connection…"** helper turns an existing connection's username and password into a credential and offers to link the other connections that have the same username and password. The comparison is done in memory and the values are never shown.

## 3b. Full backup and restore

The per-connection export stays as it is: one connection, never any secrets. Next to it comes a **full backup** for reinstalling the system or moving to another Mac.

- **Backup:** "Back up everything…" in the menu's settings and in the Manage window writes a single file, `MacVPN-backup-<date>.macvpnbackup`, with mode 0600, to a path the user picks in the native save panel.
- **What the backup contains:**
  - every connection, with its config and secrets
  - folders, colours, order, pins and the ranking
  - shared credentials
  - system-VPN OTP settings, and the folder and colour placements of system VPNs
  - app preferences: auto-update, the 24 h delay, launch at login, the control-API on/off switch, and auto-unlock
- **What is left out:**
  - **Paired control-API clients.** Their tokens are bound to executable paths on this Mac, so clients pair again after a restore.
  - **The vault key and the recovery key.**
  - **Logs.**
- **Encryption:**
  - The user sets a **backup password** at least 10 characters long, with a strength hint. The master password is offered as a default only after explicit confirmation ("Use my master password").
  - The format is a versioned header holding the magic number, the format version, the Argon2id parameters and the salt, then an XChaCha20-Poly1305 sealed payload. The payload is a SQLite database image (`VACUUM INTO` of a temporary plain copy built in memory) or JSON. The plan decides which, but the plain copy must never touch the disk.
  - The header is authenticated as AAD.
  - The Argon2id parameters in the header have a backup-specific ceiling (256 MiB, 64 passes, 4 lanes). A header above it is refused before the key derivation runs.
  - A wrong password or a corrupted file produces one generic error.
- **A backup is untrusted input.** Anyone who knows its password can craft one. Before anything is written, a restore checks the payload with the same rules as the editors: credential names, usernames and passwords, folder names, item ids, no control characters in any secret, and caps on the size and on the number of entries. An invalid backup is refused as a whole. A restored link never leaves the connection with its own username and password. A merge drops the restored connections' acknowledged risky OpenVPN directives, unless the same connection already exists with the same config. "Replace everything" keeps them, and the restore window lists those connections first.
- **Restore on a fresh install:** the first-run "Create vault" window offers **"Restore from backup…"**.
  1. Pick the file and enter the backup password.
  2. Set a new master password and save a new recovery key.
  3. Everything is imported in one transaction.
- **Restore into an existing vault:** "Restore from backup…" in the settings offers:
  - **Merge:** adds items that are missing. When an id already exists, one question applies to all conflicts: overwrite with the backup, keep the existing item, or keep both. "Keep both" gives the backup copy a new id and a " (backup)" suffix.
  - **Replace everything:** clears the vault first, after a confirmation that names how many items will be lost. It suggests making a backup of the current state first.
- **After a restore:**
  - The backed-up preferences are never applied silently. The user confirms each one, and the control API is unticked by default.
  - Native L2TP/Cisco profiles are reinstalled from their stored data through the existing installer, which asks for the admin password once.
  - A missing brew tool or root layer shows up in System Status as usual.
  - System VPNs that don't exist on the new Mac keep their folder placement for 30 days (section 5), then they are dropped.
- **Version:** a backup from a newer MacVPN with an unknown format version is refused with a clear message. An older format is migrated on import.
- **Security:**
  - The backup is as sensitive as the vault, and the UI says so ("Anyone with this file and its password can read all your VPN credentials").
  - The password is never stored.
  - No plaintext is written to a temporary file.
  - The file is written atomically; if writing fails, the partial file is removed.
- **Not included:** automatic or scheduled backups, and cloud upload.

## 4. Credential prompt before connecting

- **Before connecting,** MacVPN computes the required fields for each kind:
  - **OpenVPN:** username and password when the config has `auth-user-pass` without inline credentials. A key password when the key is encrypted and none is stored.
  - **L2TP:** username, password and PSK.
  - **Cisco IPsec:** username, password, plus PSK or certificate.
  - **IKEv2:** EAP username and password when the auth method is EAP.
  - **SSTP:** username and password.
  - **WireGuard:** none.
- **Prompt window:** if any required field is empty, MacVPN opens a "Credentials needed" modal before calling the root layer.
  - **Contents:**
    - only the missing fields, with the username pre-filled when one is stored
    - a "Save in vault" checkbox, on by default
    - Connect and Cancel buttons
  - **Behaviour:**
    - Follows the MFA window rules: no focus steal, a 1 s input lock, no default button.
    - Cancel aborts the connect, with no error notification.
    - For the control API, `up` replies `waiting_for_credentials`, a new compatible state, while the modal is open, and `credentials_cancelled` if it is cancelled.
- **Secret handling:** typed secrets go straight to the root layer on stdin. They are kept in memory only as long as the connect needs them, then zeroized. They are written to the vault only when "Save in vault" is ticked.
- **Wrong credentials:** an authentication failure from the tool (OpenVPN `AUTH_FAILED`, pppd auth failure, charon EAP failure) offers a re-prompt once, with the message "Sign-in failed — check the username and password". It does not loop.

## 5. Live system-VPN list

- **Change notifications:** MacVPN watches for VPN configuration changes. It uses `SCPreferencesSetCallback` on the system preferences (or `SCDynamicStore` notifications for `Setup:/Network/Service/.*`, whichever reliably fires for VPN profile add/change/delete; plan task 1 checks this). On a change it reloads the system-service list, debounced by 500 ms.
- **Fallback:** if no notification source proves reliable, MacVPN polls `scutil --nc list` every 5 s while a MacVPN window is open, and every 30 s otherwise.
- **UI updates:** the menu, the Manage list and the folder placements (`system_items`) update live.
  - A deleted system VPN disappears.
  - Its folder placement is kept for 30 days, in case it comes back with the same service ID.
  - An open editor for a VPN that was just deleted shows "This VPN was removed from macOS" and becomes read-only.

## 6. Security notes

- The DEK and the KEKs live only in `zeroize` buffers.
- The master password and the recovery key never reach the webview's storage: they are typed into dedicated prompt windows and sent once over IPC, and the vault view model never contains them.
- The Keychain item holds the raw DEK.
  - Its access is limited to MacVPN's code identity, and macOS asks after an ad-hoc re-sign.
  - The 1.0 hardened runtime blocks `DYLD` injection into the trusted process.
  - Same-user malware that can drive the Keychain prompt UI is out of scope, as in the existing threat model.
- **Argon2id cost:** the parameters are tuned so unlocking takes about 0.5–1 s on Apple Silicon. They are stored in `vault.keys` so they can be raised later.
- **Backups:** `vault.db` and `vault.keys` are safe to back up, because they are encrypted. The recovery key is the user's way back on a new Mac.
- **Logging:** the log never contains secrets, configs or key material. The vault logs only events: unlocked, locked, migrated, wrong password, and the attempt counts.

## 7. Code layout

- **`crates/core/src/vault/`:** platform-independent.
  - key hierarchy: the Argon2id and XChaCha20-Poly1305 wrap and unwrap, `vault.keys` IO, the recovery-key format
  - schema and migrations
  - repositories for connections, secrets, folders, ordering, system items, OTP and control clients
  - the folder tree and colour inheritance
  - the `KeyStore` trait
- **`crates/platform-mac/`:**
  - the Keychain `KeyStore`
  - the SCPreferences / SCDynamicStore watcher
  - the legacy-store readers used by the migration
- **`crates/app-core/`:**
  - the vault lifecycle: locked/unlocked state, auto-unlock, lock now
  - the migration orchestrator
  - the required-fields computation and the credential-prompt flow
  - the store traits replaced by vault-backed implementations; `ConnectionStore`, `SecretStore` and the ranking store keep their interfaces where possible
- **`crates/mvpn/`:** config on stdin; VERSION 8.
- **Tauri / UI:**
  - the create-vault, unlock, recovery and change-password windows
  - the menu's lock state
  - the folder tree, colours, the colour picker and drag and drop, built on the 1.1 card design
  - the credential prompt
  - the live system list
- **l10n:** every new string in EN and HU.

## 8. Testing

- **Core:**
  - Backup: format round-trip; a wrong password and a tampered header or payload give the same generic error; merge conflict modes (overwrite, keep, keep both); replace; an unknown newer version is refused; no plaintext temp files (checked with a scratch-dir scan).
  - Shared credentials: link and unlink, the restricted delete, copy-into-connections, required fields when a linked credential has no password, and import matching by name.
  - Wrap and unwrap with known vectors.
  - A wrong password or recovery key fails without leaking which part was wrong.
  - Changing the password keeps the data; a new recovery key invalidates the old one.
  - Schema migrations.
  - Folder cycle rejection, cascade on delete, and colour inheritance (own, parent, grandparent, none).
  - Ordering within folders.
  - The required-fields computation for each kind, using the existing config fixtures.
- **Vault on disk:**
  - Without the key, the file reveals no plaintext: grep for a known connection name and config line.
  - Modes are 0600 and 0700.
  - A crash in the middle of a transaction leaves a consistent database.
- **Migration:**
  - Fixtures with a Swift-era and 1.0 data directory plus a fake Keychain.
  - Full import, the verification pass, and the deletion only after success.
  - A failure injected at every step leaves the old data intact.
- **mvpn:** `scripts/test-root.sh` with stdin config delivery, plus the new cases in section 2.5.
- **Smoke tests:** in the sandbox, in EN and HU:
  - create the vault, lock, unlock with the password, unlock with the recovery key
  - folders: create, nest, colour, drag, delete with move-up
  - the credential prompt for an OpenVPN config with `auth-user-pass`
  - a fake system-service list change shows up live
- **Manual checklist:**
  - the real migration from 1.1 on the maintainer's data, with a backup first
  - after the next update, check how many Keychain prompts appear (expected: at most one)
  - delete a system VPN in System Settings while the menu is open
- **Independent security review** before the release.

## 9. Sequencing

The parts ship in two releases:

- **1.1.0:** the control API, the card UI, **the live system-VPN list (section 5)** and **the credential prompt (section 4)**. These don't depend on the vault. Until 1.2, "Save" in the credential prompt writes to the existing secret store.
- **1.2.0:** the vault (section 2), the migration, folders and colours (section 3), shared credentials (section 3a), full backup and restore (section 3b), and root VERSION 8. The credential prompt's "Save" then writes to the vault, through the same `SecretStore` trait.
