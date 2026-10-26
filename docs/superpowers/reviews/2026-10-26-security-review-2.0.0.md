# Security review: joint 2.0.0 release (MacVPN + WinVPN)

- **Scope:** 2b Task 24 and 2c Task 18. Everything from `v1.5.0` to `winvpn-2b` @ `82ad56b`: 537 files, about 94k lines added.
- **Reviewer:** independent review. Only the code was read; nothing was run, and no VM or network was used. Code was not changed.
- **Date:** 2026-10-26.

## Method

I read both plans' security decisions and every "threat notes" paragraph first. The most important one is 2b Task 17's "As built (fix4)", with its threat notes for Task 24 (lines 25 and 4778 of the 2b plan).

I then traced the code along each privilege boundary:

- the WinVPN Service, running as LocalSystem;
- the app-initiated UAC steps;
- the macOS root helper;
- RAS in the user's context;
- the app and UI;
- the supply chain.

A finding is listed only when the attacker-controlled input could be followed to the privileged action. Where one link could not be confirmed without running Windows or macOS, the finding is marked **(unverified link)** and its severity is held down accordingly.

The plans already accept some risks: the WireGuard LLC name-only signer, and same-user malware hijacking a UAC prompt. These are noted where a finding changes their premise. They are not re-reported as new.

## Summary

| # | Severity | Area | Title |
|---|---|---|---|
| M-1 | Medium | WinVPN Service / RAS CA trust | The "Trust This CA" Root install, combined with the name-only signer pin, lets a VPN operator's CA run code as SYSTEM through the wireguard-nt update **(fixed in `a2a3ffa`)** |
| M-2 | Medium | macOS root helper, DNS | An oversized DNS owner entry makes the ledger unreadable: VPN DNS stays after disconnect and the originals are lost **(fixed in `0bc448e`)** |
| L-1 | Low | Elevation (OpenVPN step) | The elevated MSI step checks one file, then msiexec re-opens it by path (junction re-point TOCTOU) (fixed: `7d5e6b6`) |
| L-2 | Low | Elevation (OpenVPN step) | `msi-official` trusts the file name for the version: a renamed, older signed OpenVPN MSI installs on a fresh machine (fixed: `7d5e6b6`) |
| L-3 | Low | Elevation (OpenVPN step) | A UNC path is opened by the elevated process before it is refused (NTLM credential leak) (fixed: `7d5e6b6`) |
| L-4 | Low | WinVPN Service pipe | A silent client that does not set SQOS stalls the single accept loop for 2 s per connection (cross-user DoS) (fixed: `b7be177`) |
| L-5 | Low | App / elevation | `WinVPN.exe` never restricts the DLL search order, including when it runs elevated (unverified link) **(fixed in `c6fc1a0`)** |
| L-6 | Low | RAS CA trust UI | The CA confirmation shows invisible format characters (bidi, zero-width) unescaped **(fixed in `ef3d6a8`)** |
| L-7 | Low | macOS root helper, strongSwan | `stage_creds` follows symlinks in directory components and accepts hard links **(fixed in `ed95466`)** |
| L-8 | Low | RAS (user context) | The L2TP server field is not checked for CR/LF before `RasSetEntryPropertiesW` (unverified link) (fixed: `7ddec2f`) |
| L-9 | Low | Validator (OpenVPN, Windows) | `is_harmless_argument` lets a drive-relative argument (`C:name`) through for RISKY directives (unverified link) (fixed: `0fd43f7`) |
| I-1…I-9 | Info | various | See [Informational](#informational) |

I found nothing Critical or High.

---

## Medium

### M-1: "Trust This CA" plus the name-only signer pin lets a VPN operator's CA run code as SYSTEM through the wireguard-nt update

**Status: fixed in `a2a3ffa` (both minimal fixes).** (1) `trust::verify_signature` returns the signer chain's SPKI SHA-256s; `Signer::is_pinned` requires the pinned name and a pinned CA key above the leaf (`signer_ca_spki_sha256` in both pin files: Sectigo Public Code Signing CA EV R36 for wireguard-nt, DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 for OpenVPN), for every `wireguard.dll` load, `openvpn.exe` and the OpenVPN MSIs; a refused download is logged with its chain's keys and the bundled DLL stays in use; `docs/RELEASING.md` "Signer pins" says how to add a new CA key. (2) **Trust This CA in Windows…** runs the installed `WinVPN.exe --winvpn-trust-ca-step <file>` elevated, which adds the CA with `CERT_ENHKEY_USAGE_PROP_ID` = serverAuth + clientAuth (`cert_store::add_with_usage`: set before the add, read back, removed otherwise); the confirmation now says server and client certificates, not software.

**Where:**
- `crates/helper/src/windows/sys/wgdll.rs:113-117`: the signer check is `signer.subject == wg_pins::PINS.signer`. A downloaded DLL has no hash pin; only `Trust::Bundled` has one (`:104-109`).
- `crates/winsys/src/trust.rs:53-58`: `WINTRUST_ACTION_GENERIC_VERIFY_V2` with `WTD_REVOKE_NONE`. This accepts any chain to any root in the machine's store.
- `crates/winsys/src/trust.rs:110-137`: the "subject" is only `CERT_NAME_SIMPLE_DISPLAY_TYPE`, the CN.
- `crates/platform-win/src/win/admin_steps.rs:50-60` (`trust_ca`): `certutil -addstore Root <cer>`, which trusts the CA for every purpose, code signing included. It is reached from `app/src-tauri/src/ras.rs:65-111` (`ras_ca_summary` / `ras_trust_ca`).
- The download goes through System32 `curl.exe`, which uses Schannel and so trusts the same machine Root store (`crates/helper/src/windows/sys/fetch.rs`, `wg_update.rs` `curl_args`).

**Why this is new beyond the accepted fix4 risk:** the 2b threat note (1) accepts two cases: a public CA mis-issuing a "WireGuard LLC" code-signing certificate, or a stolen WireGuard key. 2c Task 12 then added a WinVPN button that puts a *VPN operator's own* CA into `LocalMachine\Root` with no restriction on what it may be used for. After an administrator approves that once, the same party can do both things the update path relies on: intercept TLS to `download.wireguard.com`, and issue an Authenticode certificate with CN "WireGuard LLC".

**Exploit path:**
1. A catalog, or a shared `.sstp` / IKEv2 config, carries the operator's CA.
2. The user clicks **Trust This CA in Windows…** and an administrator approves UAC. The confirmation warns about trusted *certificates* in general, not about trusted *software*.
3. Later, while the user's VPN to that operator is up (the operator is then on-path), any interactive user starts the WireGuard update, or the check followed by the update. `Service::wireguard_update` is open to every caller (`crates/helper/src/windows/service.rs:256, 531-544`).
4. The service fetches the listing and zip from the operator's TLS endpoint. The zip holds a DLL signed by "WireGuard LLC" under the operator's CA, with a higher version and the right PE machine.
5. `open_checked` accepts it, `Library::load` maps it into the LocalSystem service, and the attacker's code runs as SYSTEM.

A corporate TLS-inspection root whose usage is not restricted creates the same exposure without the button. `openvpn.exe` uses the same CN-only pin (`sys/detect.rs:203-206`). There, the admin-only folder check (`detect.rs:200`) keeps a user from planting the file, so that case stays Info.

**Minimal fix (either one closes the path):**
1. Pin the wireguard-nt signing chain, not just the CN. For example, require that the chain's issuing intermediate (or the leaf's SPKI SHA-256) is one of a set shipped in `wg_pins.rs`, read from `WTHelperProvDataFromStateData` → `CRYPT_PROVIDER_SGNR.pasCertChain`. The set is updated with app releases, and the downloaded DLL stays free of a release hash pin as the maintainer chose.
2. Restrict what the WinVPN-installed CA may be used for. Add it with `CERT_ENHKEY_USAGE_PROP_ID` = serverAuth (and clientAuth) only, using `CertAddEncodedCertificateToStore` and `CertSetCertificateContextProperty` in a small elevated step instead of a bare `certutil -addstore Root`. Also reword the confirmation.

(1) is the more robust fix, because it also covers TLS-inspection roots. Doing both is best.

### M-2: An oversized DNS owner entry makes the ledger unreadable; the VPN's DNS then stays after disconnect and the originals are lost

**Status: fixed in `0bc448e`.**
- Each owner is capped: 1 to 16 servers, at most 32 search domains, each at most 253 bytes (an IPv6 server at most 39 bytes). An owner over a limit is refused whole, with a log line; the list is not truncated. A shortened list would silently differ from what the VPN asked for, and an oversized list is a broken or hostile config. The originals stay in effect.
- `Manager::acquire` checks the limits before it touches the ledger. `wireguard::up` checks the same limits before it hands the stripped `DNS =` values over.
- `save` refuses a ledger over `LEDGER_MAX`, or one that does not parse back to the same value. The ledger on disk then stays as it was.
- `load` no longer drops an unreadable or oversized ledger. It sets the file aside as `ledger.bad`, recovers the originals and the owners within the limits (`Ledger::salvage`), and writes them back, so the originals survive.
- `hook_dns` now uses `is_search_domain`.
- Tests: unit tests in `dns.rs`, `hook_dns.rs` and `wireguard.rs`. In `scripts/test-root.sh`, a WireGuard config with 1040 domains of 253 bytes is refused and the originals are intact after down, and an oversized ledger still restores the originals.

**Where:**
- `crates/helper/src/macos/dns.rs:262-291` (`acquire`): it pushes an owner entry of any size and `save`s it.
- `dns.rs:513-522` (`save`): no size check.
- `dns.rs:31` (`LEDGER_MAX` = 256 KiB) and `dns.rs:491-510` (`load`): a ledger that cannot be read is renamed to `ledger.bad` and replaced with an empty one.
- `crates/helper/src/macos/wireguard.rs:46-53` (`strip_dns`): no limit on the number of servers or domains.

**Exploit path:**
1. An imported or catalog WireGuard config (the attacker is its author) has `DNS = <attacker-ip>, <≈1040 domains of 253 bytes each>`, about 262 KB. That is under the 1 MB config limit, and every value passes the format check (`crates/core/src/validators/wireguard.rs:164`).
2. At connect, root writes a ledger over 256 KiB and applies the attacker's resolver to every network service with `networksetup`. If `networksetup` refuses a list that long, only the denial of service below happens.
3. At disconnect, `release` → `load` → `read_private` fails on the size cap. The ledger is set aside, `release` returns `false`, and nothing is restored.
4. The attacker's resolver stays in the persistent SystemConfiguration preferences, across reboots too, with no connection up.
5. The next connection records the attacker's DNS as the "original" (`dns.rs:274-283`), so every later restore puts it back.

The same mismatch exists on the OpenVPN hook side: `hook_dns.rs:87-92` uses `is_domain` (no length limit), while the parser uses `is_search_domain` (≤ 253). OpenVPN's option-line limit probably keeps pushed domains shorter than that, but this was not confirmed.

**Minimal fix:**
- In `Manager::acquire`, cap the owner lists (for example 16 servers and 16 domains; the resolver uses at most 6 search domains). Refuse to `save` when `l.render().len() > LEDGER_MAX` or when `Ledger::parse(&l.render()) != Some(l)`, so a ledger is never written that `load` cannot read.
- Make `hook_dns::options` use `dns::is_search_domain`.

---

## Low

### L-1: The elevated MSI step checks one file, then msiexec re-opens the path

**Status: fixed in `7d5e6b6`.** The elevated step reads the named MSI through a deny-write handle, copies the bytes into a new folder `C:\ProgramData\WinVPN\installer\<random>` (owned by Administrators, SYSTEM + Administrators only), checks the copy (SHA-256 or the same bytes, signer, MSI database) and runs msiexec on the copy, which it deletes afterwards.

**Where:** `crates/platform-win/src/win/openvpn_install.rs:424-436` (`step_result`), `:324-353` (`open_verified` / `open_official`). The path comes from argv (`crates/platform-win/src/pure/openvpn_install.rs:467-479`, checked only by `quotable`, `:143-146`); it normally lies in the user-writable `%LOCALAPPDATA%\WinVPN\downloads` (`win/openvpn_install.rs:73-82`).

**Path:**
- The `FILE_SHARE_READ` handle stops anyone writing to, renaming or deleting *that file*, but not re-resolving the path. Same-user code passes a path through a directory junction it owns (`…\x\OpenVPN-….msi`, with `x` pointing at dirA, where the real MSI is).
- After the hash and signer checks, it re-points `x` (by rewriting the junction's reparse data) at dirB, which holds a malicious MSI with the same name.
- The elevated `msiexec /i "<path>"` installs dirB's MSI, and its custom actions run as SYSTEM.
- The re-point while a handle into the old target is open was not tested on the VM.

**Severity rationale:** the 2b threat model treats same-user malware that hijacks a UAC prompt as out of scope. The attacker still needs an administrator to approve the prompt, which shows WinVPN as a trusted, signed publisher. That is why this is Low, but it defeats the code's stated intent: "the unelevated app's checks are not trusted", `:425`.

**Minimal fix:**
- In the elevated process, copy the bytes from the held handle into a new admin-only directory, for example `C:\ProgramData\WinVPN\installer\<random>` with a protected DACL.
- Check the hash and signer again on the copy, and run msiexec on the copy.
- At the least, refuse a path with any reparse point in its ancestors (as `acl_check::is_admin_only` walks them).

### L-2: `msi-official` trusts the file name for the version

**Status: fixed in `7d5e6b6`.** The elevated step reads `ProductName`, `ProductVersion`, `UpgradeCode` and `Manufacturer` from the copy's `Property` table (`winsys::msi`) and requires OpenVPN Community of this architecture, not older than the pin (`msi_properties_ok`). The MSI steps no longer take `absent`/`present`: the elevated process looks itself before anything runs.

**Where:** `crates/platform-win/src/win/openvpn_install.rs:341-353` and `crates/platform-win/src/pure/openvpn_install.rs:171-175` (`official_msi_name_ok` parses the version from the *file name* only).

**Path:**
- Same-user code renames an older, validly signed OpenVPN Inc. MSI to `OpenVPN-<newer>-I001-amd64.msi` and starts the step.
- On a machine without OpenVPN, the old release installs, and its Interactive Service is treated per `absent_before`, which also comes from argv (`parse_before`).
- When OpenVPN is already installed, msiexec's Upgrade table refuses the downgrade (2b threat note 8). The service's `min_version` check on `openvpn.exe` still applies, but only to what WinVPN itself runs, not to the old Interactive Service.

**Severity rationale:** same preconditions as L-1.

**Minimal fix:**
- Read `ProductName` / `ProductVersion` / `UpgradeCode` from the MSI database (`MsiOpenDatabase` + `MsiDatabaseOpenView` on the held copy, see L-1) and require OpenVPN Community at or above the pin.
- Compute `absent_before` in the elevated process rather than taking it from argv.

### L-3: A UNC path is opened by the elevated process before it is refused

**Status: fixed in `7d5e6b6`.** `parse_step` (and `step_parameters`) accept only a plain local drive path (`is_plain_windows_path`, shared with the updater's msiexec parameters, which already refused UNC and now also refuse a stream `:`).

**Where:**
- `crates/platform-win/src/pure/openvpn_install.rs:143-146`: `quotable` accepts `\\host\share\…`, since `is_absolute` is true.
- `win/openvpn_install.rs:325-331` and `:342-346`: the file is opened and read *before* `verify_signature` → `plain_absolute` (`crates/winsys/src/util.rs:44`) refuses UNC paths.

**Path:** argv `--winvpn-openvpn-step msi "\\attacker\s\x.msi" absent` makes the elevated process, running with the approving administrator's token, authenticate to the attacker over SMB or WebDAV. The attacker gets a NetNTLMv2 response to crack or relay.

**Minimal fix:** in `parse_step`, require a `Prefix::Disk` path (call `plain_absolute`) before any open.

### L-4: A silent client that does not set SQOS stalls the service's single accept loop

**Status: fixed in `b7be177`.** The accept loop hands each client to its own thread (`Listener::accept_unidentified`), which identifies it; at most 16 clients are being identified at a time, more are closed unanswered.

**Where:**
- `crates/winsys/src/pipe.rs:413-449`: `Listener::accept` calls `stream.identify()` on the accept thread.
- `pipe.rs:688-708` (`identify`): a client that opened without `SECURITY_SQOS_PRESENT` and writes nothing makes it wait `FIRST_WRITE_WAIT` = 2 s (`:69`) in `first_write`.
- `crates/helper/src/windows/sys/server.rs:30-50`: one accept loop serves every user.

**Path:** any INTERACTIVE user loops `CreateFileW(\\.\pipe\WinVPN…)` without SQOS and closes after 2 s. The listener has only one pending instance, so the other users' requests (`down`, `status`, `up`) wait behind it. Kept up, this denies service to other users across sessions. Logoff tear-down is not affected; it runs on its own thread.

**Minimal fix:**
- Move `identify()` into the per-client thread: hand the stream out first, then identify, and drop the client when that fails.
- Optionally cap the number of unidentified clients pending at a time.

### L-5: `WinVPN.exe` never restricts the DLL search order, including when elevated (unverified link)

**Status: fixed in `c6fc1a0`:** `platform::harden_dll_search()` (Windows: `harden_process_search`) is the first statement of `main`, before every mode.

**Where:** `app/src-tauri/src/main.rs:521-531` enters `helper_mode` (the elevated `--winvpn-openvpn-step`) and the relauncher without calling `macvpn_winsys::dll::harden_process_search()`. Only the service calls it (`crates/helper/src/windows/sys/mod.rs:33`).

**Risk:** a DLL that is delay-loaded, or loaded at runtime by bare name and not found in the admin-only app folder or System32, falls through to `PATH`. For a split-token administrator, the elevated process inherits the user's `PATH`, which includes the user-writable `%LOCALAPPDATA%\Microsoft\WindowsApps`. I did not identify a specific DLL that is missing, so the link is unverified.

**Minimal fix:** call `harden_process_search()` as the first statement of `main`, before any mode dispatch.

### L-6: The CA confirmation shows invisible format characters unescaped

**Status: fixed in `ef3d6a8`:** Cf characters, U+2028/U+2029 and the Hangul fillers are shown as `\u{…}`.

**Where:** `crates/platform-win/src/pure/ca_trust.rs:347` replaces only `char::is_control`. Category Cf characters pass through: bidi overrides U+202A–U+202E and U+2066–U+2069, and zero-width characters U+200B–U+200F and U+FEFF.

**Path:** a catalog or SSTP `<ca>` whose subject *displays* as a familiar name is installed machine-wide as a Root CA after an administrator approves it. The SHA-256 is still shown, which limits the impact.

**Minimal fix:** map Cf (and U+2028/U+2029) to `?` or to `\u{…}`.

### L-7: strongSwan `stage_creds` follows symlinks in directory components and accepts hard links

**Status: fixed in `ed95466`.**
- `stage_creds` now takes the Homebrew prefix. It opens `<prefix>`, `etc`, `swanctl`, each credential directory and each file through the parent's descriptor (`openat` with `O_NOFOLLOW`), so a symlink in any component is not followed, and a swap after a check has no effect.
- A file must have `st_nlink == 1`.
- Every directory and file must be owned by root, by the prefix owner, or by the owner of `<prefix>/etc`. The last case covers Intel, where `/usr/local` belongs to root and its `etc` to the Homebrew user.
- A refused file is counted as skipped. The copy semantics are unchanged.
- Tests: unit tests in `strongswan.rs`, and cases in `scripts/test-root.sh` for a hard-linked file, a symlinked credential directory and a symlinked `etc`.

**Where:** `crates/helper/src/macos/strongswan.rs:215-241` with `fsx::read_private` (`crates/helper/src/macos/fsx.rs:30-39`). `O_NOFOLLOW` covers only the last component, and `is_real_dir(from)` is checked before the open (TOCTOU).

**Path:**
- The owner of the Homebrew prefix swaps `…/etc/swanctl/private` for a symlink to `/var/db`, or hard-links a root-only file into `x509/`.
- Root then copies any regular file it can read, up to 1 MB, into the root-only (0700) run directory.
- No way to read it back was found (`swanctl` logs only that parsing failed).
- The prefix owner can already get root through the Homebrew binaries that root runs (I-2). So the practical impact is nil today, but the primitive is unsafe.

**Minimal fix:**
- Open the source and each credential directory with `O_DIRECTORY|O_NOFOLLOW` and each file with `openat(dirfd, name, O_NOFOLLOW)`.
- After `fstat`, require `st_nlink == 1` and an owner of root or the prefix owner.

### L-8: The L2TP server field is not checked for CR/LF before `RasSetEntryPropertiesW` (unverified link)

**Status: fixed in `7ddec2f`.** Core refuses C0/C1 controls, DEL and U+2028/U+2029 in the server of every RAS kind; `Entry::encode` refuses them again.

**Where:**
- `crates/winsys/src/ras/entry.rs:332`: `fill(szLocalPhoneNumber, …, &self.server)` refuses only NUL.
- `crates/core/src/ras/l2tp.rs:24`: the server is only `trim()`-ed.
- The catalog path does check (`crates/core/src/catalog/payload.rs:273-275`). A backup restore or a local `meta.json` does not, and `install_all` (`crates/app-core/src/connections.rs:1111`) writes the entries when the vault unlocks.

**Unverified:** whether RAS writes `PhoneNumber=` verbatim. If it does, a `\r\n` injects extra keys into the user's own `[WinVPN-<UUID>]` section. That happens in the user's context only, but RasMan (SYSTEM) parses the phonebook too.

**Minimal fix:** refuse C0/C1 controls, DEL and U+2028/U+2029 in `Entry::encode` for `server`, and in the native-settings restore.

### L-9: Drive-relative arguments pass `is_harmless_argument` (unverified link)

**Status: fixed in `0fd43f7` (test follow-up `48b6f70`).** On Windows a RISKY argument with a `:` is refused unless it is an IPv6 address or prefix (`is_harmless_argument_for`); macOS is unchanged.

**Where:** `crates/core/src/validators/openvpn.rs:916-937`. It blocks `\`, `/` (except in a CIDR), `..` and `~`, but not `C:name`.

**Why it matters:** any interactive user can acknowledge an unknown directive with `--accept-risky`. The service re-validates the config (`crates/helper/src/windows/service.rs:325`) and runs `openvpn.exe` as SYSTEM, where `D:foo` resolves to `D:\foo`. No OpenVPN 2.6/2.7 directive was found that takes a path, is in no table and escapes `FORBIDDEN_PATTERN`, so the link is unverified.

**Minimal fix:** on Windows, also refuse `^[A-Za-z]:` and any `:` in RISKY arguments, except an IPv6 literal.

---

## Informational

- **I-1, any interactive user is a VPN operator for the whole PC.** The pipe grants INTERACTIVE `SERVICE_CLIENT_ACCESS` (`crates/winsys/src/pipe.rs:58, 209-220`). Any local user can bring up a full-tunnel OpenVPN or WireGuard as SYSTEM, which routes other users' traffic and DNS. The RISKY tier (server/listen directives, unknown names) can be acknowledged by any caller. This is documented ("carries the whole PC's traffic", 2b plan line 5255). Make it explicit for administrators of multi-user PCs, and consider an optional machine policy (an HKLM value) that limits `up` to members of a group.
- **I-2, macOS: the Homebrew prefix is the real root boundary.** Root runs `swanctl`, `charon`, `openvpn`, `sstpc`, `wg-quick` / `bash`, `wg` and `wireguard-go` from the user-owned Homebrew prefix (`crates/helper/src/macos/ctx.rs:117-127, 219-244`). This is unchanged since 1.5.0. The "root layer 9" bump (`crates/helper/VERSION`) is only an app-side reinstall prompt (`crates/platform-mac/src/setup_checker.rs:95-97`), not a security gate.
- **I-3, cross-user log take-over by UUID.** `Service::up` with another user's *past*, no-longer-owned ID re-records the log owner and `FileLogStore::open` truncates that log (`service.rs:342-356, 437-455`; `logs.rs:132-138`). This needs the other user's random connection UUID, which no answer reveals, so there is no practical path.
- **I-4, `curl --ssl-revoke-best-effort` and `WTD_REVOKE_NONE`.** Revocation is not enforced on downloads or signatures. Updates are acceptable because of the Ed25519 gate, but this adds to M-1.
- **I-5, the L2TP PSK stays in the user's RAS credential store** after disconnect and while the vault is locked (`crates/platform-win/src/win/ras_engine.rs:309, 622-625`). Anything running as the user can dial with it. Document this in the user guide.
- **I-6, connection toasts show the connection name**, which can appear on the lock screen. This is by design: no server, user or log text is shown, and the XML is escaped (`crates/platform-win/src/pure/toast.rs:4-24`).
- **I-7, OpenVPN management port squatting** gives at most a denial of service: the password is sent only after the peer-PID check (`crates/helper/src/windows/sys/mgmt.rs:48`, `sys/tcp_owner.rs:60-72`).
- **I-8, certutil staging (`admin_steps.rs:92-134`)** has the same path re-resolution pattern as L-1. It adds nothing, because whoever controls the unelevated process can already start an elevated certutil.
- **I-9, a macOS service with a scoped IPv6 DNS server (`fe80::1%en0`)** fails `is_ipv6` and is left unchanged while the VPN is up (`dns.rs:115-121, 276-282`). This is a possible DNS leak. Nobody controls it; it is logged.

---

## Checked and found sound

### WinVPN Service (LocalSystem)

- **Service pipe:**
  - SYSTEM owns it; the protected DACL denies NETWORK, allows SYSTEM, and gives INTERACTIVE read and write-data only (no `FILE_CREATE_PIPE_INSTANCE`, no `WRITE_DAC`).
  - It is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`. The endpoint refuses a non-SYSTEM process (`pipe.rs:209-249`).
  - The client checks that SYSTEM owns the pipe before sending (`pipe.rs:576-592`).
- **Client identity:**
  - Identification-level impersonation, with `OpenAsSelf`, and `RevertToSelf` or abort.
  - Anonymous or unidentifiable clients are closed without an answer.
  - For the client without SQOS, the first bytes are kept and impersonation is retried, never defaulted (`pipe.rs:483-511, 688-708`). The only issue there is L-4.
- **Ownership:**
  - Every ID-bearing command goes through `owned_kind`, which matches the SID.
  - Another user's ID answers exactly like an unknown one, including while it is busy connecting.
  - The engine recorded at `up` is the one used for `down`. Epochs handle a `down` that races a blocking `up`.
  - Limits are 8 connections per user and 32 total, and 32 logs per user and 256 total (`service.rs:262-556`).
- **Logoff:**
  - Sessions are read with `WTSQueryUserToken`; an unreadable list drops nothing.
  - The RAS safety net hangs up only entries named exactly `WinVPN-<UUID>` whose phonebook path, compared component by component without regard to case (no `.`/`..`, drive paths only), is the absent profile's `AppData\Local\WinVPN\ras\WinVPN.pbk`.
  - A phonebook that also belongs to a present user is kept, `.bak` profile keys are skipped, and the wait is bounded (`ras_logoff.rs`, `sys/session.rs`).
- **`C:\ProgramData\WinVPN`:**
  - Every level is checked: not a reparse point, owner SYSTEM or Administrators, exactly the protected inherited admin-only DACL. Anything else is never repaired; the service runs degraded instead.
  - Engine and run files are `create_new` with an explicit DACL, and names come only from UUIDs or fixed names.
  - `is_own_file` refuses files that inherited their ACL. Run-directory removal never follows links (`sys/data_dir.rs`).
- **wireguard-nt download:**
  - System32 curl, a bare environment, `-q`, `--proto =https`, `--max-redirs 0`, TLS 1.2 or later, fixed URLs, a version made only of digits and dots, size and time caps.
  - The zip parser: bounds-checked `get`, `checked_add`, the size cap before inflate, inflate output limited, CRC and size checked, duplicates refused, member names never become paths.
  - Version is monotonic: newer than the bundled DLL and than every kept version, and equal to the listed version. The handle is held deny-write with `OPEN_REPARSE_POINT` from the hash/PE/signature checks until `LoadLibraryExW` has mapped the DLL. The fallback goes to the hash-pinned bundled DLL, which must sit in an admin-only folder (`wg_update.rs`, `sys/wgdll.rs`, `sys/wireguard.rs`). The only gap is M-1.
- **DLL loading in the service:**
  - `SetDefaultDllDirectories(SYSTEM32)` and `SetDllDirectoryW("")`, with an abort on failure.
  - `Library::load` takes plain absolute paths with `DLL_LOAD_DIR|SYSTEM32`, and `wlanapi` is loaded by its full path (`crates/winsys/src/dll.rs`, `net.rs:330`).
- **OpenVPN start:**
  - `openvpn.exe` comes from the HKLM 64-bit view: a plain regular file, at least 2.6.0, the exact signer, and an admin-only file, folder and every ancestor with no reparse points (`sys/detect.rs`, `acl_check.rs:67-105`).
  - argv holds only fixed words, the UUID run directory and the port. `--script-security 1` and `--management` come after `--config`.
  - The validator forbids `up`/`down`/`*-verify`/`plugin`/`engine`/`providers`/`log`/`status`/`writepid`/`cd`/`config`/`tmp-dir`/`management*`. On Windows it also forbids `win-sys`, `service`, `msg-channel`, `allow-nonadmin`, `windows-driver`, `cryptoapicert` and `dev-node`. File directives must be inline.
  - The environment is cleared, and the working directory is the admin-only run directory.
  - Management: 127.0.0.1 only, a 256-bit password, and the peer-PID check (`ovpn_args.rs`, `sys/openvpn.rs`, `sys/mgmt.rs`).
- **Logs and diagnostics:**
  - Per-connection logs are masked line by line, capped at 8 MiB plus one rotated part, CR/LF flattened.
  - `service.log` lines are capped at 512 bytes and rotated.
  - The diagnostics have no key fields, bounded lists, and system strings with control characters removed (`logs.rs`, `sys/service_log.rs`, `diagnostics.rs`).

### Elevation paths

- **Updater:**
  - Canonical GitHub URLs.
  - The MSI is held deny-write and hashed through that handle.
  - The Ed25519 signature is checked with `verify_trusted_for(WINVPN.signature_domain, asset, …)` (`crates/platform-win/src/pure/update.rs:74-167`, `win/updater.rs`).
- **certutil and reg.exe:**
  - Both are found in System32 through the known folder.
  - The reg arguments are fixed words, and the certutil path must have the `ca-<hex>.cer` shape.
  - `parameters()` refuses `"`, control characters and a trailing `\` inside quotes.
  - The CA is staged `create_new` under a random name, re-opened `FILE_SHARE_READ` and compared byte for byte (`pure/admin_steps.rs`, `win/admin_steps.rs`).
- **`ca_trust.rs` DER/SHA-1:**
  - Length fields of at most 4 bytes in the shortest form, `checked_add`/`checked_mul`, slicing only through `get`.
  - `time()` checks the length first.
  - A single certificate with no trailing data is required, so the bytes shown are exactly the bytes installed.
  - No panic or overflow was found when reasoning through malformed input (truncated, over-long, indefinite-length or nested tags).
- **Quoting:** `msiexec_parameters` / `step_parameters` quote correctly. The step runs only when the running `WinVPN.exe` is in an admin-only location (`win/openvpn_install.rs:302-312`).

### macOS root helper

- **Entry checks:** `refuse_via_sudo` covers the internal modes. The hook paths require a root-owned 0700 `/var/run/macvpn/<uuid>`, and the kind and ID are allowlisted (`macos/mod.rs`, `shared/cli.rs`).
- **DNS ledger:**
  - The 0700 directory owned by the effective uid is not a symlink. The lock is opened with `O_NOFOLLOW` and taken with `flock`.
  - Writes go through an `O_EXCL|O_NOFOLLOW` temp file and a rename. Reads use `read_private` with a strict parser.
  - `networksetup` gets each value as a separate argument with `env_clear`; scutil stdin is never used and no shell is involved (`dns.rs:136-212, 448-522`). The only issue is M-2.
- **Hook environment:** only `script_type`, `dev`, `ifconfig_local` and `foreign_option_N` are read, and each is format-checked. Child processes get `env_clear` plus a fixed `PATH` and `LC_ALL` (`hook_dns.rs:32-47`, `exec.rs:96-121`).
- **`log.rs`:**
  - Logs live only in root-owned directories.
  - Opens use `O_NOFOLLOW|O_NONBLOCK` with an `fstat` check for a regular file.
  - `.1` and `.tmp<pid>` are created with `O_EXCL` and renamed, `lchown` is used, and flushed text is masked.
- **strongSwan F1/F2:**
  - In `load.conf`, values are escaped (`\` and `"`) and NUL and newline are refused by the framing.
  - Secret names are derived from the UUID and bound to the validated `remote_ids`.
  - `load.conf` is 0600, `O_EXCL`, inside the 0700 run directory, and removed after use.
  - `include` is forbidden by the validator, and the sudoers rule names a single user. The only issue is L-7.
- **Primitives:** `fsx.rs`, `run_dir.rs` and `lock.rs` use `O_NOFOLLOW`/`O_EXCL`, and `remove_rf` never follows links.

### Windows RAS (user context)

- **Private phonebook:** `ensure_private_dir` with an owner check and reparse points refused (`crates/platform-win/src/win/ras_paths.rs:35-53`).
- **Entry names:** only `WinVPN-<UUID>`, with an exact round trip (`crates/core/src/ras/names.rs:18-28`). The INI writer writes fixed keys and hex only (`crates/winsys/src/ras/ini.rs:188-217`).
- **Sweep:**
  - Only the private phonebook, only exact names, and only `<UUID>.ras/.log/.log.1` files.
  - Only with the vault unlocked (`crates/platform-win/src/pure/ras_sweep.rs`, `ras_engine.rs:609-631`).
  - The G-9 clean-up is limited to the same scope.
- **System VPNs:** `Phonebook::system()` refuses writes. A PSK is provided only when Windows has none, checked through the mask only (`system_vpns.rs:279-289`, `creds.rs:63-78`).
- **Secrets:** `RASCREDENTIALSW` / `RASDIALPARAMSW` are heap buffers wiped with volatile writes, the dial password is `Zeroizing`, and `Debug` redacts.

### App / UI

- **Control API:**
  - The pipe `\\.\pipe\WinVPN-control-<SID>` uses `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`, with a DACL that denies NETWORK and allows only the user and SYSTEM (OWNER RIGHTS gets `READ_CONTROL` only).
  - The client checks that the server is its own SID.
  - The token is 32 bytes from `BCryptGenRandom`, stored as SHA-256 only and compared in constant time (`crates/core/src/control/registry.rs:36-62, 237-264`).
- **Catalogs:** the token goes over curl stdin (`--config -`) in a `Zeroizing` buffer; System32 curl, a bare environment, and capped output (`crates/platform-api/src/curl/catalog.rs:135-161`, `curl_runner.rs`).
- **Import:** UNC, device and ADS paths are refused, as are junctions and symlinks. A canonical below-base check and no-follow `open_regular` are used, with size caps (`crates/core/src/importer.rs`).
- **Tauri:**
  - The new capability entries in `app/src-tauri/capabilities/main.json` are narrow.
  - The RAS commands take no paths or certificates from the UI, and the confirmed CA is used once (`PendingCa`).
  - The Windows CSP patch changes only `connect-src`. `assetProtocol` is off and `freezePrototype` is on.

### Supply chain

- **Workflows:**
  - Every action is pinned by full SHA. There is no `pull_request_target`, no self-hosted or `windows-admin` runner with secrets, and CI runs with `contents: read`.
  - Caches are saved only on push to main or develop, and release builds use no cache.
- **Release workflow:**
  - `permissions: {}`.
  - `ci-green` requires a successful main-push CI run, the tag must be on main and match `vX.Y.Z`, and builds run with `persist-credentials: false`.
  - The release is a draft, and signing is offline.
- **Pins:**
  - `scripts/pins/wireguard-nt.txt`: zip and DLL SHA-256, the URL prefix, Authenticode Valid plus the signer at build time.
  - `scripts/pins/openvpn.txt`: MSI SHA-256.
- **`scripts/build-msi.sh`:** WiX tool hashes are pinned, ICE validation is forced in CI, `cargo --locked` and `npm ci`, and binary marker/import gates.
- **VM scripts (`scripts/win-remote.sh`, `win-smoke.sh`):** a dedicated key and dedicated `known_hosts`, `BatchMode`, no `StrictHostKeyChecking=no`, no credentials in the scripts, inputs checked by regex, and the remote command base64-encoded.

## Not covered

- **Runtime behaviour:** nothing was executed on Windows or macOS. These need a VM run:
  - the junction re-point while a handle is open (L-1);
  - whether `RasSetEntryPropertiesW` writes CR/LF verbatim (L-8);
  - whether `networksetup` accepts very long lists (M-2);
  - which DLLs `WinVPN.exe` loads at runtime (L-5).
- **Core validators:** `crates/core/src/validators/*` was not fully audited. The Windows tier, the RISKY argument rule and the DNS/PostUp/`include` rules were checked. The SAFE-tier argument rules (for example `dhcp-option` values that reach netsh) were not.
- **Updater internals:** the core of the signature and downgrade logic (`crates/core/src/update.rs`) and the relauncher (`--relaunch-after`).
- **MSI:** the WiX fragments (the service's SCM ACL, the install directory ACLs) and the bootstrapper behaviour of the MSI's WebView2 (Task 15's note) were only skimmed via `build-msi.sh`.
- **Not reviewed:** the Svelte UI (XSS / `{@html}`), the vault crypto and backup format, `scripts/sign-release.sh`, `scripts/ras-spike.ps1` and the lab scripts.
- **`platform-mac` user-level changes:** `brew.rs`, `http.rs`, `catalog_http.rs`, `net_probe` and `net_watch` were skimmed only.
