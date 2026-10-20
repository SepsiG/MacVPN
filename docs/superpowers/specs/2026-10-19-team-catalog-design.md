# MacVPN – Team catalog (shared connections) – design

**Date:** 2026-10-19
**Status:** direction agreed in conversation (catalog rather than a shared database or a server; HTTPS URL **and** file path sources; signed **and** encrypted); this written spec awaits review.
**Release:** 1.3.0. It depends on the 1.2.0 vault, folders and shared credentials (`2026-10-19-vault-folders-design.md`).

## 1. Goal and non-goals

**Goal:** several people use the same VPN connections. An administrator publishes them once, and every subscribed MacVPN picks up additions, changes and removals automatically.

**Each user keeps their own:**
- usernames, passwords and OTP secrets
- pins, ranking and collapsed folders

**Not a goal:** sharing the vault database file itself.
- SQLite locking over SMB/NFS and synced folders is unreliable and can corrupt the file.
- Every user would need the same master password.
- There would be no per-user revocation.

A central server with per-user permissions is also not part of this design. It may come later.

## 2. Concepts

- **Catalog:** a single file, `<name>.macvpncatalog`. It holds the following, all signed and encrypted:
  - a set of connections (kind, meta and config)
  - their folder tree with colours
  - **credential slots**: named placeholders such as "Company AD" that each user fills in with their own username and password
  - optionally, shared secrets such as a team PSK, when the admin chooses to include them
- **Publisher:** a MacVPN with an **admin signing key** (Ed25519) in its vault. It publishes catalogs from the app.
- **Subscriber:** a MacVPN that has added a catalog source. It holds:
  - the source location
  - the pinned publisher public key (its fingerprint)
  - the team key
  
  All three are stored in the vault.

## 3. Catalog file format

```
magic "MVPNCAT1" | header JSON (len-prefixed) | sealed payload | Ed25519 signature
header: { catalog_id (uuid), name, version (monotonic u64), created, publisher_key_id,
          kdf: none, enc: "xchacha20poly1305", nonce }
payload (after decryption): JSON { folders[], connections[], credential_slots[], shared_secrets{} }
signature: Ed25519 over ("macvpn-catalog-v1\n" || header || sealed payload)
```

- **Encryption:** the payload is sealed with the **team key**.
  - The team key is 256 random bits, shared out of band as a string in the same 6×4 Crockford format as the recovery key, for example `TEAM-XXXX-…`.
  - A key rather than a password: no KDF is needed, and it can't be brute-forced.
- **Order of checks:**
  1. Signature against the pinned publisher key.
  2. Monotonic `version`: an older or equal version than the one last applied is ignored (rollback protection).
  3. Decrypt.
  4. Validate every config with the existing validators. Risky directives in a catalog connection require the subscriber's own acknowledgement, the same as an import.
- **Size limit:** 8 MB.

## 4. Sources

There are two kinds of source.

**HTTPS URL**
- `https://` only, with certificate checks through the system trust store.
- Optional `Authorization: Bearer <token>`, with the token stored in the vault.
- Conditional GET (ETag / If-Modified-Since). Redirects only to https.
- No URL globbing (`--globoff`; `[ ] { }` percent-encoded) and at most 5 redirects. The token and the conditional headers go only to the subscription URL's origin; a source moved to another origin drops the stored token.
- **No proxy:** curl runs with a cleared environment, so `https_proxy` / `all_proxy` and the system proxy settings are not used (as for the updater). A catalog host must be reachable directly. A validated proxy setting may come in a later version.

**File path**
- A path on a network share or in a synced folder (iCloud Drive, OneDrive, Dropbox).
- Read only: `O_NOFOLLOW` on the last component, a regular-file check, and the 8 MB cap.
- A missing share means "unavailable", not an error storm.

**Refresh schedule**
- At launch, and every 15 minutes.
- On wake from sleep.
- On demand through **Refresh now**.
- Exponential back-off while the source is failing.

## 5. Subscribing

"Add team catalog…" in the Manage window. The user enters:
- the source (URL or file),
- the **team key**,
- the **publisher fingerprint** (8 groups of 4 hex characters), compared with what the admin sent out of band.

The first download must match that fingerprint. Trust on first use without a fingerprint is not offered.

A one-line **subscription string** can carry all three at once: `macvpn-sub:<base64url JSON>`. The admin sends it in a secure channel and the user pastes it.

**Opening a catalog file from Finder** (added after 1.3.0 at the user's request; it reverses the 1.3.0 decision not to register document types). `.macvpncatalog` is a document type of MacVPN (exported UTI `local.macvpn.catalog`, `LSHandlerRank` Owner). Double-clicking such a file opens "Add team catalog…" with the file preselected as the file source, exactly as if it had been chosen with "Choose File…": the path stays in the backend, the dialog shows the file name. The user still enters or confirms the team key and the fingerprint, and nothing is subscribed without the verified preview and the "fingerprint matches" tick. While the vault is locked, the file waits (its path only, in memory) until the unlock; a cancelled unlock drops it. `.macvpnadminkey` and `.macvpnbackup` are not document types: they are opened from their panels only.

## 6. How catalog items behave on the subscriber

- **Placement:** catalog connections live in a root folder named after the catalog, with a "Team" badge. The catalog's own folder tree sits inside it, with the publisher's colours.
- **Read-only for the user:** config, name, folder and colour.
- **What the user can change:**
  - pin and ranking
  - collapse state
  - the colour override, which is local only
  - fill in credential slots
  - connect and disconnect
  - export their own copy: "Duplicate as personal connection", which makes an independent, editable copy
- **Credential slots:**
  - Each slot maps to a **shared credential** (1.2 section 3a) in the subscriber's vault, matched by slot id.
  - At first use, MacVPN asks: "Company AD — enter your username and password". This uses the credential prompt from 1.1 and is saved to the user's own vault.
  - The catalog never contains user credentials.
- **Updates:** a new catalog version is applied in one transaction: add, change, remove.
  - A connection that is **up** when it changes or disappears stays up until it disconnects. The new config takes effect on the next connect. A notification says "Team catalog updated: 2 changed, 1 removed".
  - A removed connection is deleted after it disconnects. The user's pins and ranking for it are dropped.
- **Unsubscribing** removes all items from that catalog after confirmation. Connections that are up are disconnected first. Credentials the user filled in are kept as normal shared credentials.
- **Several catalogs** are allowed. Item ids are namespaced by `catalog_id`, so they never collide.

## 7. Publishing (admin)

- **Generate admin key:** creates the Ed25519 signing key and stores it in the vault. It can also be exported as part of the encrypted full backup.
  - The app shows the fingerprint.
  - A **backup admin key** can be generated. The catalog header can announce a successor key, signed by the current key, so the key can be rotated without every user re-subscribing.
- **"Publish catalog…"** steps:
  1. Choose folders and connections.
  2. Choose which secrets to include: none by default; a team PSK is an explicit tick per secret.
  3. Choose the credential slots, mapped from the selected connections' shared credentials, without their values.
  4. Write the file to a chosen path. MacVPN does not upload anything. The admin puts the file on the web server or share.

  `version` increments automatically.
- **Team key:** generated on the first publish of a catalog and shown once.
  - **"Rotate team key"** makes a new key. Subscribers must enter the new key, which is how a departing member is cut off.
  - The UI says plainly that rotating is the only way to revoke access to a catalog someone already has.
- **Admin side:** the publisher's own MacVPN keeps the source connections as normal editable connections. A "published in catalog X (v12)" badge shows when they have changed since the last publish.

## 8. Security notes

- **What the team key protects against:** leaking the file. Anyone holding the team key can read the catalog, including any team secrets the admin chose to include.
- **What the signature protects against:** tampering, even by someone who has the team key or write access to the share or web server.
- **Rollback protection:** the monotonic version is stored per subscription. A version number that goes down is refused, and the UI shows a warning.
- **Validation:** catalog configs go through the same validators and risky-directive acknowledgement as imports. No new root-layer surface.
- **Sensitive values:** the subscription string and the team key are treated as secrets: vault only, never logged.
- **The control API** treats catalog connections like any other. The allowlist uses the namespaced ids.

## 9. Code layout

- **`crates/core/src/catalog/`:** the format (seal and open, signature, version check), the subscription string, credential-slot mapping, and the apply/diff planner as a pure function from (old state, new catalog) to operations.
- **`crates/platform-mac/`:** nothing new beyond the existing HTTP client (curl with pinned options). File-source reads reuse the import file reader.
- **`crates/app-core/`:** a catalog service for refresh scheduling, back-off, apply and notifications, plus the publishing flow.
- **UI:** a "Team catalogs" section (subscriptions, status, last refresh, errors), the publish wizard, the admin key page, the "Team" badges and the read-only editors.

## 10. Testing

- **Format:**
  - round-trip
  - a wrong team key, a wrong signature, a tampered header or payload, and a truncated file all fail with distinct but non-leaky errors
  - a version going down is refused
  - the size cap
- **Planner:** add, change and remove; a connection that is up when it changes or is removed; several catalogs; namespacing; unsubscribe.
- **Sources:** an HTTPS mock server (ETag, 304, a redirect to http refused, back-off), and a file source on a symlink, a FIFO or an oversized file.
- **Smoke:** publish a catalog in sandbox A, subscribe to it in sandbox B through a file source, see the items, publish v2, see the update.
- **Manual:** two real Macs, a share and an HTTPS host.
- **Independent security review** before the release.
