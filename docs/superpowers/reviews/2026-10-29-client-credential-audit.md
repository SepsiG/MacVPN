# Client credential audit: what a VPN client should generate, show, copy or import

- **Question (maintainer, 2026-10-29):** WireGuard had no key generation and no public-key copy. Do the other VPN kinds have certificate, key or password fields the client should be able to generate, or show and copy? This is a client, so server-side functions are out of scope.
- **Scope:** `develop` @ `a61e066`, which includes 2.0.6 (`crates/core/src/wireguard_keys.rs`, `app/ui/src/lib/manage/WireGuardKeys.svelte`). The code was read. Nothing was run, and no code was changed.
- **Files read (main ones):** `app/ui/src/lib/manage/{TextEditor,NativeForm,SstpForm,SystemDetail,Credentials,SecretField,WireGuardKeys,TrustCa}.svelte`, `secret.ts`, `wgkeys.ts`; `crates/core/src/{models,importer,exporter,credentials,wireguard_keys}.rs`, `catalog/{payload,selection}.rs`, `nm_plan/strongswan.rs`, `ras/ikev2.rs`, `validators/{openvpn,strongswan}.rs`; `crates/app-core/src/{editor,import_export}.rs`; `crates/helper/src/macos/{strongswan,openvpn}.rs`, `helper/src/shared/mask.rs`; `crates/platform-win/src/pure/ca_trust.rs`; `Cargo.lock`, `crates/core/Cargo.toml`.

## The two secret models in the editor today

There are two ways the editor holds a secret.

1. **Vault field, write-only.** The secret is held in `secrets(connection_id, field, value)` in the SQLCipher vault. The fields are `Username`, `Password`, `Psk` and `KeyPassword` (`models::SecretField`). The web view never receives a stored value. `SecretField.svelte` shows "Saved — type to replace": typing a value replaces it, and "Remove saved password" deletes it. There is no Show, no Copy and no reveal. This is deliberate (see the `Credentials.svelte` text: "Passwords are stored in the vault and never shown").
2. **Inline in the config text.** The secret is part of the config text, which is stored in the vault (`connections.config`, SQLCipher). Examples are the WireGuard `PrivateKey` and `PresharedKey`, the OpenVPN `<key>`, `<pkcs12>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<auth-user-pass>` and `<http-proxy-user-pass>` blocks, and a strongSwan `secrets { … }` section. All of it shows **in plain text in the config `<textarea>`**. It is entered by typing or pasting, or by import: `importer::inline_openvpn_files` inlines the referenced files of an `.ovpn` file, including PKCS#12 as base64.

WireGuard 2.0.6 put a third model on top of (2) for the WireGuard keys only. The key panel shows them masked, with Show and Hide. Copy goes through the backend's `SecretClipboard`, which is concealed and cleared after a minute. Keys are generated in Rust from `vault::Entropy`, the OS CSPRNG.

## Per kind

Columns: **Entry** is how the value gets in. **Show / Copy / Replace / Generate** describe what the UI offers today. **Client need** says whether a client legitimately creates this value or receives it from an admin.

### OpenVPN

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| User name | vault `Username` (or shared credential) | form field | yes (not secret) | no | yes | — | receive |
| Password | vault `Password` (or shared credential) | `SecretField`, connect prompt | no | no | yes (type) | no | receive / user-chosen elsewhere |
| Private key password (PEM / PKCS#12) | vault `KeyPassword` | `SecretField` (always shown for OpenVPN), prompt only for an encrypted **PEM** `<key>` | no | no | yes | no | receive (or chosen at CSR time) |
| Client certificate `<cert>` (public) | config text | paste, `.ovpn` import inlines `cert file` | plain text | select text in textarea | edit text | no | receive (signed by admin CA) |
| Client private key `<key>` | config text | paste, import inlines `key file` | **plain text** | select text | edit text | **no** | receive today; *could* be generated with a CSR (see G7) |
| PKCS#12 `<pkcs12>` | config text (base64) | import inlines `pkcs12 file` | plain base64 | select text | edit text | no | receive |
| CA `<ca>` (public) | config text | paste, import | plain | select | edit | no | receive |
| `<tls-auth>`, `<tls-crypt>`, `<secret>` | config text | paste, import | **plain** | select | edit | no | **receive**: these are shared with the server, and the server issues them |
| `<tls-crypt-v2>` | config text | paste, import | **plain** | select | edit | no | **receive**: the client key is wrapped by the server's key, so only the server side can mint it |
| `<auth-user-pass>`, `<http-proxy-user-pass>` inline | config text | paste | **plain** | select | edit | no | receive. Import moves an `auth-user-pass` *file* into the vault, but an inline block stays in the text |

Certificate details: none. There is no subject, issuer, validity or fingerprint, and no warning before expiry.

### WireGuard (done in 2.0.6, confirmed)

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| `[Interface] PrivateKey` | config text | config text, key panel | panel: masked + Show; **textarea: plain** | yes (`SecretClipboard`, cleared in 60 s) | yes (asks first) | yes (`wg genkey`, OS CSPRNG) | **generate**: yes, the client makes its own key pair |
| Public key (derived) | not stored | derived in Rust | yes | yes (web clipboard, not secret) | — | derived | the client sends it to the admin |
| `[Peer] PresharedKey` (one peer) | config text | config text, key panel | as private key | yes | yes | yes (`wg genpsk`) | either side may make it (symmetric) |
| `[Peer] PublicKey` (server) | config text | config text | plain | select | edit | no | receive |

The only open point is that the textarea still shows `PrivateKey` and `PresharedKey` in plain text (G1).

### IKEv2 (strongSwan `swanctl.conf`)

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| EAP user name | vault `Username` (or shared credential) | form field (`eap_id` in text too) | yes | no | yes | — | receive |
| EAP password | vault `Password` | `SecretField`, prompt (when `auth = eap*`) | no | no | yes | no | receive |
| PSK (`auth = psk`) | vault `Psk` | `SecretField` (always shown for IKEv2) | no | no | yes | **no** | receive (shared with the gateway) |
| Client certificate + private key (`auth = pubkey`) | **not in the app**: macOS reads Homebrew `etc/swanctl/{x509,private,pkcs12}` (copied into the run dir by `stage_creds`). Linux reads `$XDG_DATA_HOME/LinVPN/swanctl/{x509,private}` (`nm_plan/strongswan.rs`). Windows reads a **computer** certificate from LocalMachine\My (`Auth::MachineCertificate`) | manual file copy, or certmgr as admin on Windows | no | no | no | no | receive today; *could* be generated with a CSR |
| Private key passphrase | Linux NM: `KeyPassword` is the `password` secret for `method = key`. **No editor field and no prompt for IKEv2** (G2). macOS: only by hand, as a `secrets { private-… { secret = … } }` section in the config text, in plain text | — | — | — | — | — | receive / chosen |
| CA `cacerts` (public) | file in the swanctl folder. Windows: **Trust This CA in Windows…** with a picked PEM | file copy, picker (Windows) | Windows confirmation shows subject, validity and SHA-256 | no | — | — | receive |
| `secrets { … }` section typed into the config | config text | text | **plain** | select | edit | no | should never be needed (G1, G2) |

### L2TP/IPsec

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| Account name | `meta.json` `native.account` | form | yes | no | yes | — | receive |
| Password | vault `Password` (or shared credential) | `SecretField`, prompt | no | no | yes | no | receive |
| PSK ("Pre-shared key (PSK)") | vault `Psk` | `SecretField`, prompt | no | no | yes | **no** | receive: the gateway's group secret |
| Machine certificate (L2TP/IPsec with cert) | not supported (mobileconfig and RAS entry are PSK only) | — | — | — | — | — | rare |

### Cisco IPsec (IKEv1 XAuth)

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| Group name | `native.group_name` | form | yes | no | yes | — | receive |
| Account name, password | as L2TP | as L2TP | as L2TP | no | yes | no | receive |
| Group secret (PSK) | vault `Psk` | `SecretField` | no | no | yes | **no** | receive: the group secret is the same for every user |
| Hybrid / certificate auth | not supported | — | — | — | — | — | rare |

### SSTP

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| User (`user=`) | config (form) | form | yes | no | yes | — | receive |
| Password | vault `Password` (or shared credential, password only) | `SecretField`, prompt | no | no | yes | no | receive |
| Custom CA (public) | config | **Choose PEM File…** | count only ("Certificates loaded: N"). Windows: subject, validity, SHA-256 in the trust confirmation | no | yes (picker) | — | receive |
| Client certificate (EAP-TLS) | not supported | — | — | — | — | — | rare |

### System VPNs (not created by the app)

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| "Shared secret (PSK)" (L2TP / Cisco) | vault `Psk` | `SecretField` | no | no | yes | no | receive (the user retypes what the OS profile holds) |
| "Password (optional, if not saved in macOS)" | vault `Password` (or shared credential) | `SecretField` | no | no | yes | no | receive |

### Shared credentials

| Secret / credential | Held in | Entry | Show | Copy | Replace | Generate | Client need |
|---|---|---|---|---|---|---|---|
| User name | vault `credentials.username` | form | yes | no | yes | — | receive |
| Password | vault | `SecretField`; or "create from a connection" (the values are never shown) | no ("never shown") | no | yes | no | receive (directory account) |

## Candidates

| Candidate | Verdict | Reasoning | How common |
|---|---|---|---|
| **CSR generation** (OpenVPN, IKEv2): make the key pair and a PKCS#10 request on the device, then import the signed certificate | **Partial: not now, keep as an optional later feature** | This is a real client-side function: the private key never leaves the device. But the mainstream workflows don't use it. easy-rsa, OpenVPN Access Server, pfSense, OPNsense and most MSPs hand out an `.ovpn` (or `.p12`) with the key already inside. Enterprise IKEv2 uses MDM, SCEP or AD CS auto-enrollment. None of the reference clients (Tunnelblick, Viscosity, OpenVPN Connect, the strongSwan NM plugin, GNOME's VPN editor, the Windows built-in VPN) generates a CSR. It is size L, because it adds a new crypto dependency set and a two-step pending state (a key waiting for its certificate). Worth doing only if an admin actually asks for it | rare (security-conscious admins, some PKI-run companies) |
| **View stored certificate details** (subject, issuer, validity, SHA-256 fingerprint) and **warn before expiry** | **Yes** | An expired client certificate is a common, confusing failure: the TLS error is opaque. The Windows certificate UI and the GNOME and strongSwan certificate pickers let the user inspect a certificate. Whether Tunnelblick or Viscosity warn before expiry was not checked for this audit. A bounded DER reader already exists in `crates/platform-win/src/pure/ca_trust.rs` (subject, validity, SHA-256, strict lengths). It can move to `core` and be extended with issuer and serial. No new crate is needed | common (every certificate-based config expires) |
| **Copy the client certificate / public part** to send to the admin | **Partial: yes, as part of the details view** | Useful when an admin asks "which certificate do you have?" or needs to revoke one. The certificate is public: the fingerprint and the PEM can go through the normal clipboard. Exporting the *public key* alone has no use without CSR generation | occasional |
| **PSK / password show-copy parity** with the WireGuard private key | **Partial** | (a) A **Show toggle for the text being typed** (an eye button) is standard in GNOME, Windows and the WireGuard app, and costs nothing, because the typed value is in the web view already. **Do it.** (b) **Copy a stored PSK** through `SecretClipboard` is useful: users retype the L2TP or Cisco group PSK on a phone or another laptop, and the system-VPN view exists because macOS loses it. **Optional.** (c) **Reveal a stored password** would break the write-only design (the backend never sends one) for little gain, since the user knows their password. **Don't.** | (a) very common, (b) occasional, (c) — |
| **Masking consistency** | **Yes (small)** | Every `SecretField` is masked, so masking itself is consistent. The labels are not: PSK and key-password fields show "Remove saved password", and the PSK is "Pre-shared key (PSK)" in the editor but "Shared secret (PSK)" in the system VPN view. The only *unmasked* secrets are the inline ones in the config textarea (G1) | — |
| **"Generate PSK"** for L2TP, Cisco or IKEv2 PSK | **No** | An IPsec PSK is the gateway's secret. For Cisco and most L2TP servers it is a single group secret that every user shares. A client that generates one can only produce a value the server doesn't know. The admin sets it on the server and hands it out. WireGuard's `PresharedKey` is different: it is per peer and symmetric, so either side may make it, which is why 2.0.6 offers it there | — |
| **Generate `tls-auth` / `tls-crypt` / `secret` static keys** | **No** | These are shared HMAC or encryption keys that the server must already hold (`openvpn --genkey` on the server). A client-made key cannot work. `tls-crypt-v2` client keys are wrapped with the server's key, so they can only be minted on the server side | — |
| **Export a connection's public material** for the admin | **No as a separate feature** | WireGuard: the public key Copy covers it. OpenVPN and IKEv2: the certificate Copy in the details view covers it. A file export of "public material" would be a new format that no admin tool reads | — |
| **Generate passwords** (EAP, L2TP, SSTP, shared credentials) | **No** | VPN passwords are directory (AD, RADIUS) accounts that the server side owns. A password generator would only help on first-time account creation, which happens elsewhere | — |
| **Store a TOTP seed and compute codes** | **No** | It would turn the VPN client into the second factor, which defeats MFA. The app already asks for the code at connect time | — |

## Gaps, prioritized

Size: S is under a day, M is a few days, L is a week or more, or a new dependency set with a security review. P1 means do soon, P2 means do, P3 means optional.

| # | Prio | Gap | Recommendation | Size |
|---|---|---|---|---|
| G1 | P1 | **Inline secrets in plain text in the config textarea**: WireGuard `PrivateKey`/`PresharedKey` (the 2.0.6 panel masks them, the textarea next to it does not), OpenVPN `<key>`, `<pkcs12>`, `<tls-*>`, `<secret>`, inline `<auth-user-pass>`, and a typed strongSwan `secrets` section. This exposes them to screen sharing, screenshots and shoulder-surfing | **Do.** Mask the secret values in the textarea by default, with one "Show secrets in config" toggle. Either fold the OpenVPN key blocks to a one-line placeholder, or render the editor as text plus masked ranges. The backend keeps the real text; edits outside the masked ranges must round-trip exactly. Alternative (larger): move inline keys into the vault as fields and keep a reference in the text, which is how the 2.0.6 panel works for WireGuard. Start with WireGuard and the OpenVPN `<key>`/`<pkcs12>` blocks | M |
| G2 | P1 | **IKEv2 private key passphrase has no input.** On Linux, `nm_plan/strongswan.rs` sends `KeyPassword` as the NM `password` for `auth = pubkey` (`method = key`). But `TextEditor.svelte` shows "Private key password" only for OpenVPN, and `credentials::required_fields` asks nothing for a non-EAP IKEv2 connection. So an encrypted client key can't be used on Linux, unless NM's own agent asks for it (unverified). On macOS, the helper's `secrets_block` writes only `ike-` and `eap-` entries, so the only way is a hand-written `private-…` secret in the config text, in plain text | **Do.** Show "Private key password" for IKEv2 when `local auth = pubkey`, and ask for it at connect when the key is encrypted. On macOS, have the helper append a `private-mvpn-<id> { file = …; secret = … }` entry. Check that last part on a Mac lab first | S (UI + prompt) + S–M (macOS helper) |
| G3 | P2 | **No certificate details or expiry warning** (OpenVPN `<cert>`, `<ca>`, `<pkcs12>` certificates; SSTP CA; IKEv2 certificates) | **Do.** Move the DER reader from `platform-win/src/pure/ca_trust.rs` into `core` and add issuer, serial and SHA-1/SHA-256. Show a "Certificates" section in the editor (subject, issuer, valid from/to, fingerprint, Copy PEM/fingerprint through the normal clipboard). Show a yellow note within 30 days of expiry, and use the expiry as the failure reason after a TLS error. PKCS#12 needs a parser for the certificate bags. Start with PEM and treat PKCS#12 as a follow-up | M (PEM), +M (PKCS#12) |
| G4 | P2 | **IKEv2 client certificate cannot be imported in the app.** The user copies files into Homebrew `etc/swanctl` (macOS) or `~/.local/share/LinVPN/swanctl` (Linux), or uses certmgr as admin for the computer store (Windows). GNOME and the strongSwan NM plugin have file pickers. Windows has its own certificate import | **Do (per platform).** "Import Client Certificate…" (PKCS#12, or PEM cert + key) in the IKEv2 editor. The key goes into the vault, not into a world-readable folder. The helper stages it into the root-only run directory at connect, as `stage_creds` does now. Linux writes it to the NM-referenced 0600 file at connect. Windows needs a separate decision: a machine certificate import needs an admin step (an elevated step exists for the CA trust), and RAS user certificates (EAP-TLS) are not supported | L (all three platforms); M for macOS + Linux only |
| G5 | P2 | **Replacing an OpenVPN certificate or key means hand-editing PEM** in the textarea. Viscosity and GNOME have file pickers | **Optional.** "Replace Certificate / Key / PKCS#12…" buttons that reuse `importer` (format check, 1 MB limit) and rewrite the block in the draft, plus "Private key password" when the key is encrypted. This pairs naturally with G1 and G3 | M |
| G6 | P2 | **Secret field polish.** No Show toggle while typing. The "Remove saved password" label is used on PSK and key-password fields. The PSK is labelled "Pre-shared key (PSK)" in one view and "Shared secret (PSK)" in another. "Private key password" is shown for every OpenVPN config even without an encrypted key, and the connect prompt asks for it only for an encrypted PEM `<key>`, not for a password-protected `<pkcs12>` | **Do.** Add an eye toggle on the typed text only (never the stored value), per-field remove labels, one PSK term, show "Private key password" when the key or PKCS#12 needs it, and prompt for a PKCS#12 password (try an empty password first) | S |
| G7 | P3 | **CSR generation** (OpenVPN, IKEv2) | **Optional, not now.** If it is done: only ECDSA P-256, the key stored in the vault at once, a "waiting for certificate" state, then "Import Signed Certificate…" checks that the certificate's public key matches the key. See the security notes | L |
| G8 | P3 | **Copy a stored PSK** (L2TP, Cisco, IKEv2, system VPN) through `SecretClipboard` | **Optional.** The same backend copy as the WireGuard keys (a concealed clipboard, cleared in 60 s), with no reveal in the web view | S |
| G9 | P3 | **Team catalog subscribers cannot add a per-user key.** A catalog WireGuard or OpenVPN connection is read-only, so a subscriber cannot generate their own WireGuard key or import their own certificate. Today the publisher must tick `InlineSecret::WireGuardPrivateKey`/`OpenVpnKey`, which means everyone shares one key | **Optional, separate spec.** A per-subscriber "personal key overlay" kept in the subscriber's vault: WireGuard Generate Key Pair (shows the public key to send to the admin), or an OpenVPN or IKEv2 certificate import (G4, G5) | L |
| G10 | P3 | **OpenVPN export without keys also drops `<tls-auth>`/`<tls-crypt>`**, which are shared, not personal, so the recipient's copy cannot connect | **Optional.** Strip only `<key>`, `<pkcs12>`, `<secret>`, `<tls-crypt-v2>` (per-client) and the user/pass blocks, and keep `tls-auth`/`tls-crypt` with a note. This needs a product decision; today's behaviour is the safe default | S |
| — | — | OS keystore and smartcard identities (macOS Keychain identity like Tunnelblick or OpenVPN Connect, `cryptoapicert`, PKCS#11) | **Don't (now).** `pkcs11-*` is refused by policy (provider code loading), and `cryptoapicert` is Windows-only. Revisit only on demand | — |
| — | — | Generate a PSK, `tls-*` key, password or TOTP seed | **Don't** (see Candidates) | — |

## Exports and logs (checked, no finding)

- **Export** (`app-core/src/import_export.rs`). When key material is present, the export asks first (`export_warning` lists `<key>`, `PrivateKey`, `secrets`, and so on). "Without keys" strips OpenVPN key blocks, empties WireGuard key values and removes a strongSwan `secrets` section (`exporter::strip_secrets`). Vault passwords, PSKs and key passwords are never exported. A native `.mobileconfig` export has no PSK and an empty account name. The metadata line carries only names. Files are written 0600 through an atomic rename. See G10 for the `tls-*` remark.
- **Team catalogs** (`catalog/payload.rs`, `selection.rs`). Inline user names and passwords are refused, as is a strongSwan `secrets` section. Each inline key needs an explicit tick from the admin, and the publish review lists personal values.
- **Logs.** The helper's `shared/mask.rs` masks the password, PSK, key password and one-time code in every user-readable log, and WinVPN's RAS log does the same (`platform-win/src/pure/ras_log.rs`). `Secrets` and `nm_plan::SecretValue` have redacting `Debug` implementations. `wireguard_keys` never formats key material and returns `Zeroizing` buffers. The masker doesn't cover inline config keys. None was found reaching a log, since OpenVPN, `wg` and swanctl don't log key material, so this is not a finding. Any new code (G2, G4, G7) must add the key passphrase to the masker.
- **At connect.** The OpenVPN key password goes to a 0600 `askpass` file in the root-only run directory (macOS helper), or to the run directory with the data directory's protection (Windows). The strongSwan secrets go into the root-only config copy.

## Security notes for the "do" items

1. **Key generation stays in Rust, from the OS RNG.** Use `vault::Entropy` (SecRandomCopyBytes, BCryptGenRandom or getrandom through the platform crates), exactly as `wireguard_keys` does: a `fill` callback, where a failed fill is an error and never a weak key. Nothing is generated or derived in the web view. The web view gets the public parts (certificate, fingerprint, CSR PEM) and never a private key, unless the user explicitly presses Show.
2. **The private key goes into the vault.** It is stored as a vault value (or inline in the config, which is SQLCipher too), held in `Zeroizing`. It is never written to the user's folders: staging into the root-only run directory happens at connect, as today. A pending CSR's key (G7) is stored in the vault the moment it is created, so a crash cannot lose it or leave it on disk.
3. **Crate choice for a CSR (G7).** `Cargo.lock` has **none** of `rcgen`, `x509-cert`, `der`, `spki`, `pkcs8`, `p256`, `ecdsa` or `rsa`. The crypto already present is the RustCrypto family of the new generation: `sha2 0.11`, `digest 0.11`, `const-oid 0.10.2`, `chacha20poly1305 0.11`, `argon2 0.6`, `blake2 0.11`, `curve25519-dalek 5.0`, `ed25519-dalek 3.0`. OpenSSL is linked only as SQLCipher's vendored libcrypto (`openssl-sys` via `libsqlite3-sys`), with no safe Rust API, so it should not be used. A CSR therefore needs new crates. The recommendation is the pure-Rust RustCrypto stack, matching the existing generation (`const-oid 0.10` / `der 0.8`): `p256` (ECDSA, keygen from a seed filled by `Entropy`) + `x509-cert` with its `builder` feature (PKCS#10 `CertReq`) + `pkcs8` for the PEM key. Avoid:
   - `rcgen`: it pulls in `ring` or `aws-lc-rs` as a second crypto backend, unless used with an external signer, which gains little.
   - `rsa`: slow key generation, and RUSTSEC-2023-0071 (Marvin timing side channel on private-key operations, still no constant-time fix).
   - Ed25519 certificates (`ed25519-dalek` is already present): Windows RAS/IKEv2 and many OpenVPN or AD CS deployments don't accept EdDSA client certificates.
   P-256 is the interoperable choice for OpenVPN 2.5+ with OpenSSL, strongSwan and Windows. Pin exact versions, as the workspace does, and add them to the THIRD-PARTY-NOTICES files.
4. **Parsing certificates (G3, G4) treats input as untrusted.** Imported files and team catalogs supply it. Reuse or extend the strict, bounded DER reader in `ca_trust.rs` (definite lengths of at most four bytes, nested bounds, nothing trailing, control characters stripped from displayed text) rather than adding `x509-parser`. A PKCS#12 reader needs the same care, plus a cap on iterations and MAC work against decompression- and KDF-style abuse.
5. **Copy semantics.** Private keys and PSKs are copied only through the backend's `SecretClipboard` (concealed, cleared after a minute). Certificates, fingerprints, public keys and CSRs are public and may use the web view's clipboard.

## Summary for the maintainer

The WireGuard gap was a genuine client-side gap: a WireGuard client makes its own key. **For the other kinds there is no comparable "generate" gap.** Their PSKs, `tls-auth`/`tls-crypt`/static keys and passwords are server-side secrets that the client receives. CSR generation is the only legitimate client-side generator, and it is rare in practice (optional, L).

The real gaps are elsewhere:

1. Plain-text secrets in the config textarea, including the WireGuard `PrivateKey` (G1).
2. IKEv2 has no way to enter a private-key passphrase (G2, a functional bug on Linux).
3. No certificate details or expiry warning (G3).
4. IKEv2 client certificates can't be imported in the app (G4).
5. Small polish of the secret fields: a Show toggle while typing, labels, and the PKCS#12 password prompt (G6).
