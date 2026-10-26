# Security review, part 2: what the first 2.0.0 review could not cover

- **Scope:** the "Not covered" list of `2026-10-26-security-review-2.0.0.md`, on `winvpn-2b` @ `626094b`:
  1. the updaters (core, Windows, macOS) and `scripts/sign-release.sh`;
  2. the MSI: WiX fragments, the service's SCM ACL, the install directory, `build-msi.sh` and the WebView2 custom action;
  3. the Svelte UI, the Tauri capabilities, the CSP and the navigation guard;
  4. the vault crypto and the backup format;
  5. the SAFE tier of the OpenVPN, WireGuard, strongSwan and SSTP validators;
  6. the lab and spike scripts.
- **Reviewer:** independent review. The code was read; nothing in the repository was changed, and no VM or network was used. One finding (P2-M1) was confirmed with a throwaway harness outside the repository, which linked `macvpn-core` and called `OpenVPNValidator::validate_full`.
- **Date:** 2026-10-26.

## Method

As in part 1, a finding is listed only when an attacker-controlled input could be traced to the harmful action. **(unverified link)** marks a step that needs Windows or macOS at runtime to confirm. Those findings are rated lower.

The plans' accepted risks are not reported again. These are:

- same-user malware hijacking a UAC prompt;
- the name-only WireGuard LLC signer;
- any interactive user acting as the PC's VPN operator (part 1, I-1).

Where a finding depends on one of these premises, it says so.

## Summary

| # | Severity | Area | Title |
|---|---|---|---|
| P2-M1 | Medium | Validator (OpenVPN) | Nested `setenv opt` recurses without a limit. A config of about 110 KB overflows the stack, which aborts the WinVPN Service (cross-user, and permanent after the third crash in a day), the app (catalog refresh, opening a file) and the macOS helper. **(fixed in `7092d9c`)** |
| P2-M2 | Medium | MSI / service | The install folder is not forced admin-only, and the LocalSystem service runs from it unchecked. A non-default `INSTALLDIR` under `C:\` lets any local user become SYSTEM. **(fixed in `a4bcabb`)** |
| P2-L1 | Low | MSI | The WebView2 custom action downloads `MicrosoftEdgeWebview2Setup.exe` into the user's `%TEMP%` and runs it from there with the installing token (elevated on the updater path), with no signature check. **(fixed in `a4bcabb`)** |
| P2-L2 | Low | MSI | `allowDowngrades` is left at Tauri's default (`true`), so an older signed WinVPN MSI installs over a newer one. **(fixed in `a4bcabb`)** |
| P2-L3 | Low | Windows updater | The deny-write hold on the MSI ends when WinVPN quits, not when msiexec is done. The elevated msiexec also writes its log into the user-writable updates folder. **(fixed in `4d876c2`)** |
| P2-L4 | Low | Lab | The lab CA has name constraints but no EKU limit, and its key stays on disk. On a test PC that trusts it, the key can sign code, including a "WireGuard LLC" certificate (part 1, M-1). **(fixed in `112418b`)** |
| P2-L5 | Low | Release signing | `sign-release.sh` signs whatever the draft holds. The only link to the CI build is a manual hash comparison against a log on the same GitHub account. **(fixed in `a24b63b`)** |
| P2-I1…I6 | Info | various | See [Informational](#informational) |

I found nothing Critical or High. The UI, the vault crypto, the backup format and the WireGuard, strongSwan and SSTP validators had no findings (see [Checked and found sound](#checked-and-found-sound)).

---

## Medium

### P2-M1: Nested `setenv opt` recurses without a limit; a ~110 KB config aborts the WinVPN Service, the app or the macOS helper

**Where:** `crates/core/src/validators/openvpn.rs:1141-1149`:

```rust
if swift_str::eq(&ascii_lowercased(&tokens[1]), "opt") {
    ...
    let mut inner = Self::check_directive(os, &tokens[2..], false);
    inner.directive = Some(directive);
    return inner;
}
```

Each `setenv opt` costs one stack frame. The call is not in tail position, and nothing limits the depth or the number of tokens per line.

**Exploit path:**

1. A line made of `setenv opt ` repeated N times, followed by `verb 3`. The tokenizer accepts it, and every level passes the `setenv` branch.
2. The harness (outside the repository, linking this commit's `macvpn-core`) shows:
   - 1,000 levels validate;
   - 10,000 levels (11 KB per 1,000, so about 110 KB) give "thread has overflowed its stack" and abort the process on a 2 MiB thread;
   - 90,000 levels also abort on an 8 MiB thread.
   A Rust stack overflow aborts the whole process, not just the thread.
3. Where the input comes from:
   - **WinVPN Service (LocalSystem).** `Service::up` validates the framed config before anything else (`crates/helper/src/windows/service.rs:315-327`). `BODY_MAX` is about 1.1 MiB (`crates/core/src/service_proto.rs:27`).
     - Any interactive user can open the pipe (part 1, I-1) and send this body with a fresh UUID. No ownership or acknowledgement is needed, because the abort happens during validation.
     - Every user's tunnels are dropped.
     - Recovery restarts the service twice, then does nothing until the 24-hour reset (`crates/helper/src/windows/recovery.rs`: `ACTIONS = [5 s, 30 s, none]`). Three requests stop the service for everyone until an administrator restarts it.
   - **The app.** These all validate on the same code path, so the input aborts the app:
     - a team catalog: `crates/core/src/catalog/payload.rs:412`, where configs may be up to 1 MiB (`MAX_CATALOG_CONFIG_BYTES`);
     - an opened `.ovpn` file (file association);
     - the editor and import (`crates/app-core/src/editor.rs:339`, `manager.rs:222`).

     With a catalog that refreshes automatically, this is a crash loop that the user cannot remove from inside the app. Anyone who controls the catalog source and the publisher key can cause it, or a publisher by mistake.
   - **macOS root helper:** `validate_config` (`crates/helper/src/macos/validate.rs:41-53`). Only that connection's process aborts, so there is no cross-user effect.

**Fix (minimal):**

- Accept `setenv opt` exactly once. OpenVPN itself unwraps it only once (`options.c`, `add_option`: `p += 2`), so in `check_directive` refuse an inner directive that is again `setenv`.
- Better, check it in a loop instead of recursing.
- Also refuse a line with more than 16 parameters. That is OpenVPN's `MAX_PARMS`, so no valid config is lost.
- Add a regression test with 100,000 levels.

**Status: fixed in `7092d9c`.**
- `setenv opt` is unwrapped once (`check_directive` → `check_unwrapped`, which refuses a second `setenv opt` with "setenv not allowed: opt"); there is no recursion per level. OpenVPN 2.7.8 itself only warns about `setenv opt setenv opt verb 3` and ignores it, so nothing valid is lost.
- A line may have at most 16 tokens, the directive included (`MAX_PARMS`, "Wrong number of arguments").
- **Found while fixing, worse than the crash:** every line, in inline blocks and comments too, is now at most 255 bytes ("Line too long", `MAX_LINE_BYTES`). OpenVPN reads a line into a 256/257-byte buffer and reads the rest of a longer line as a new line. Confirmed with the installed openvpn 2.7.8: after `<ca>`, a line of 255 bytes followed by `</ca>` closes the block for OpenVPN, and the next lines are parsed as directives, while the validator still saw block content. That was a validator bypass (any FORBIDDEN directive) on every OS, not just a crash. At the top level OpenVPN 2.7 refuses such a line itself, but in an inline block it does not warn.
- Total size stays bounded by the callers (`BODY_MAX`, `MAX_CATALOG_CONFIG_BYTES`); the scan is linear, so no line-count cap was added.
- Other parsers: the strongSwan scanner keeps its sections on a heap `Vec` (no recursion; any section deeper than four levels is already "Section not allowed"); `swift_json` already stops at 512 levels; WireGuard and SSTP are line-based; serde_json keeps its default 128-level limit. No change was needed there; regression tests now pin it.
- Tests: `crates/core/tests/openvpn_tiers.rs` (100,000 `setenv opt` levels on a 512 KiB stack, in a `<connection>` block and on Windows too; the token cap; the inline-block smuggle and the CRLF/255-byte edge), a unit test in `openvpn.rs` (100,000 levels straight into `check_directive` and `check_unwrapped` on a 256 KiB stack), and `crates/core/tests/validators.rs` (strongSwan 100,000 nested sections, JSON 100,000 levels).

---

### P2-M2: The install folder is not forced admin-only, and the LocalSystem service runs from it unchecked

**Status: fixed in `a4bcabb`** (both options and the runtime check):
- Tauri 2.12.3's `main.wxs` (read from the CLI binary) does offer the choice: `WixUI_InstallDir` with `InstallDirDlg`, and `INSTALLDIR` is also read back from `HKCU\Software\<manufacturer>\WinVPN\InstallDir`.
- `service.wxs.in` pins `INSTALLDIR` to `[ProgramFiles64Folder]WinVPN\` (`SetINSTALLDIR`, type 51, unconditional, sequence 999 before `CostFinalize` 1000 in both sequences), so neither the command line, the HKCU value nor a dialog applies, and skips the folder dialog (`WelcomeDlg` Next → `VerifyReadyDlg` at Ordering 3; `WixUIValidatePath` stays in the table, unreachable).
- The folder gets an explicit protected ACL through core WiX `PermissionEx` (the `MsiLockPermissionsEx` table, SDDL by SID: the name-based `LockPermissions` fails with error 1609 on a localized Windows): `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;AU)(A;OICI;0x1200a9;;;AC)(A;OICI;0x1200a9;;;S-1-15-2-2)`.
- The service refuses to start (one `service.log` line, `SERVICE_STOPPED` with exit code 1) unless its exe and the bundled `wireguard.dll` pass `acl_check::is_admin_only` (`crates/helper/src/windows/install_dir.rs`). A copy run elsewhere therefore fails `ServiceControl`, and the install rolls back.
- `build-msi.sh` gates the custom actions, the pin's target and sequence positions, the dialog skip, the `MsiLockPermissionsEx` row and an empty `LockPermissions` (`--check-msi-rows`, tested on good and bad rows).
- Verified on the built x64 MSI (no ICE over SSH; CI validates). Not verified, needs an elevated install: the ACL that results (`icacls`), and the service's refusal on a writable folder (`docs/manual-test-checklist.md`).

**Where:**

- `app/src-tauri/wix/service.wxs.in:18-29`: `WinVPNService.exe`, run as LocalSystem with automatic start, and `wireguard.dll` are installed into `INSTALLDIR`. No `Permission` or `CreateFolder` ACL is set.
- `scripts/build-msi.sh:441-450`: the CustomAction gate lists `WixUIValidatePath`. This is the browse dialog's path check, so the installer UI offers a folder choice. **(unverified link:** Tauri's `main.wxs` template is compiled into the CLI and was not read.)
- The service never checks its own folder. Only the bundled-DLL fallback calls `acl_check::is_admin_only` (`crates/helper/src/windows/sys/wgdll.rs:82-88`).

**Exploit path:**

1. An administrator installs to a folder they chose: `msiexec /i WinVPN-….msi INSTALLDIR=C:\WinVPN`, or **Change…** in the UI, which is the common "tools in `C:\`" layout. `INSTALLDIR` is a public property, so the command-line route always works.
2. A folder created under `C:\` inherits `Authenticated Users:(OI)(CI)(IO)(M)` from the drive root. Every local user can therefore modify files in `C:\WinVPN`.
3. Any local user can take one of two routes:
   - rename the running `WinVPNService.exe`, which NTFS allows for a running image, and drop their own in its place;
   - or plant one of the service's non-KnownDLL static imports next to it. The pinned import list in `build-msi.sh` includes `version.dll`, `wintrust.dll`, `wtsapi32.dll`, `iphlpapi.dll` and `bcrypt.dll`. These load from the application folder before `main` runs, so `SetDefaultDllDirectories` comes too late.
4. At the next service start (a reboot, or recovery after a crash, for example P2-M1), that code runs as **SYSTEM**.

The wireguard-nt fallback check refuses the DLL in this layout, which shows the layout is already known to be unsafe. But the service exe itself is never covered.

**Fix (minimal):** do both at install time, because a runtime check cannot catch import-time DLL planting:

- **Option A:** give `INSTALLDIR` an explicit ACL with core WiX `<CreateFolder><Permission …/></CreateFolder>`, which writes the `LockPermissions` table. It *replaces* the inherited ACL:
  - SYSTEM and Administrators: full control;
  - Users: read and execute.
- **Option B:** pin `INSTALLDIR` to `[ProgramFiles64Folder]WinVPN` (a type-51 setter after `CostFinalize`), and drop the browse dialog (`WixUI_Minimal`).

As defence in depth, also make the service refuse to start (and log why) unless `is_admin_only(current_exe().parent())` holds. Add a `build-msi.sh` gate for the `LockPermissions` rows.

---

## Low

### P2-L1: The WebView2 custom action runs an unsigned-checked download from the user's `%TEMP%`, elevated on the updater path

**Status: fixed in `a4bcabb`.** `webviewInstallMode` is `embedBootstrapper`: the MSI has `InvokeBootstrapper` (type 1026: deferred, an exe from the Binary table, `/silent /install`, only when no WebView2 is installed) and no PowerShell action. `build-msi.sh` pins the new custom-action set and checks the embedded `MicrosoftEdgeWebview2Setup.exe` (unpacked by `dark.exe`) for a valid Authenticode signature by Microsoft Corporation. It is not pinned by hash, because the Tauri CLI downloads Microsoft's current bootstrapper at build time.

**Where:**

- `app/src-tauri/tauri.windows.conf.json:45`: `"webviewInstallMode": { "type": "downloadBootstrapper" }`.
- `build-msi.sh:441-450` accepts `DownloadAndInvokeBootstrapper` with type 1058: deferred (0x400), an exe with a working directory (34), and no `NoImpersonate`.

The action runs `powershell.exe` (an unqualified name) with `Invoke-WebRequest` to `$env:TEMP\MicrosoftEdgeWebview2Setup.exe`, then `Start-Process` on that file.

**Exploit path:**

1. The action runs only when no WebView2 Runtime is installed. In practice that means an older or stripped Windows 10.
2. The file has a fixed name in a folder the user owns. A process running as that user can win the race between the download and the start, or replace the file, and its exe then runs with the impersonated installing token.
3. On the updater path, `msiexec` is started with `runas` (`crates/platform-win/src/win/updater.rs:146`), so the client and the impersonated token are elevated. **(unverified link:** the token's elevation under impersonation.)
4. Nothing checks the downloaded file's Authenticode signature; only HTTPS to `go.microsoft.com` protects it.

This is the same-user premise (accepted), but it is a needless elevated execution of a user-writable file.

**Fix and recommendation:**

| Mode | What it does | Trade-off |
|---|---|---|
| **`embedBootstrapper`** (recommended) | The bootstrapper (~1.8 MB) goes into the MSI's Binary table. Windows Installer extracts it to its own admin-only temp folder; nothing runs from `%TEMP%` and no PowerShell is used. | The runtime itself still downloads on machines without one. Gate it in `build-msi.sh`: pin the bootstrapper's SHA-256, check Authenticode "Microsoft Corporation", and update the CustomAction-table gate. |
| `offlineInstaller` | Embeds the full runtime installer, so no network is needed. | Adds about 130–180 MB to each MSI and must be re-pinned with each runtime release. Only worth it for air-gapped sites. |
| `skip` | No custom action at all, so the smallest attack surface. | The app cannot start without WebView2. Windows 11 and serviced Windows 10 already have it. Pair it with a `LaunchCondition` on the Evergreen runtime's `pv` (`HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`) and a clear message. |

### P2-L2: `allowDowngrades` defaults to `true`, so an older signed MSI installs over a newer one

**Status: fixed in `a4bcabb`.** `"allowDowngrades": false`. Tauri's template then writes `MajorUpgrade DowngradeErrorMessage=… AllowSameVersionUpgrades="yes"`, so the same version still reinstalls (CP1/CP2). Gated in `build-msi.sh`: the `Upgrade` table is exactly `{UpgradeCode}, –, <version>, 513, WIX_UPGRADE_DETECTED` (up to this version, this one included, is upgraded) and `{UpgradeCode}, <version>, –, 2, WIX_DOWNGRADE_DETECTED` (newer: only detected), plus the launch condition `NOT WIX_DOWNGRADE_DETECTED` ("A newer version of WinVPN is already installed."). **Limit:** the refusal is carried by the package being installed, so the already-published 1.x MSIs (which still allow downgrades) can still install over 2.0.0. Only MSIs from 2.0.0 on are refused over a newer WinVPN.

**Where:** `app/src-tauri/tauri.windows.conf.json:44-51` does not set `bundle.windows.allowDowngrades`. Tauri's default is `true` (`tauri-utils` `WindowsConfig::default`, `allow_downgrades: true`), which writes `MajorUpgrade AllowDowngrades="yes"`.

**Exploit path:**

- The in-app updater refuses downgrades: `Release::is_newer`, and the signature binds the version.
- The MSI does not. Someone who gets an administrator to run an older, genuinely signed `WinVPN-x.y.z.msi` (an old download, a "repair" link) silently reinstalls a version with a fixed vulnerability, for example one still affected by part 1's M-1.
- This is the WinVPN counterpart of part 1's L-2 for OpenVPN.

**Fix:** set `"allowDowngrades": false`. Add a `build-msi.sh` gate that the `Upgrade` table has a row which detects newer versions and sets the downgrade-error property.

### P2-L3: The MSI hold ends when WinVPN quits, and the elevated msiexec logs into the user-writable folder

**Status: fixed in `4d876c2`.**
- WinVPN creates msiexec's log itself, new, in the private updates folder. A stale regular file is replaced; a folder, junction or link under the name stays and is refused. WinVPN holds the log for reading, without delete sharing.
- The relauncher (`--relaunch --target --msi --sha256 --log`) does two things before msiexec starts:
  - it re-opens the MSI deny-write and re-hashes it against the verified SHA-256;
  - it holds the log the same way, then answers `held`. Without that answer, nothing elevated runs.
- WinVPN then starts msiexec. The relauncher gets msiexec's PID on stdin, opens the process, answers `waiting`, and keeps both handles until msiexec has exited.
- While the files are held, neither of them, nor any folder above them, can be renamed or deleted. This was checked on the test VM, including that msiexec still writes a held log. So the elevated msiexec reads the verified package and writes only the file the user created.
- The module docs are corrected.

**Where:**

- `crates/platform-win/src/pure/update.rs:5-9` documents the MSI as held deny-write "until WinVPN exits (after msiexec has opened it)".
- `crates/platform-win/src/win/updater.rs:159-165` keeps the handle in `KEPT` and returns `HelperLaunched`, and the app then quits. Nothing waits for msiexec to open the package, and the relauncher holds nothing: Rust handles are not inherited.
- `msiexec_parameters` (`pure/update.rs:227-231`) passes `/l*v "<%LOCALAPPDATA%\WinVPN\updates\msiexec-<version>.log>"` to the **elevated** msiexec.

**Exploit path (same-user premise):**

- **The package:** once WinVPN has exited, the verified MSI in `%LOCALAPPDATA%\WinVPN\updates` can be replaced before the elevated client or service re-opens it. The re-open happens at startup, or again during `InstallFiles` for an embedded cabinet.
- **The log:** the user owns the updates folder, so it can be turned into a junction to `\RPC Control` with an object-manager symlink named like the log. The elevated msiexec then creates or appends its log at a path of the attacker's choosing, which is an arbitrary file write as Administrator.

Both need code already running as the user, which can also hijack the UAC prompt itself. So this is a gap against the documented guarantee rather than a new boundary.

**Fix (minimal):**

- Have the relauncher re-open the MSI with `FILE_SHARE_READ` and `FILE_FLAG_OPEN_REPARSE_POINT`, re-hash it against the verified SHA-256, and hold it until msiexec exits. (Pass the hash as a fourth relaunch argument.)
- Either drop `/l*v` for the elevated run, or point it at a freshly created, randomly named sub-folder that is checked not to be a reparse point. Better still, read the outcome from the exit code alone and write the log under `%WINDIR%\Temp`.
- Correct the module docs.

### P2-L4: The lab CA has no EKU limit, and its key stays on disk

**Where:** `scripts/vpn-lab/profiles.sh:118-121`. The CA has `basicConstraints=critical,CA:TRUE,pathlen:0` and `nameConstraints` limited to `DNS:lab.test`, the host's IP or DNS name and the bind IP. It has **no `extendedKeyUsage`**, and `ca.key` stays in `.state/pki` for 90 days.

The README tells testers to put the CA into the computer's Trusted Root store for SSTP and IKEv2 (README lines 106 and 179).

**Exploit path:**

1. Name constraints restrict only the dNSName and iPAddress name forms. A certificate with no SAN and a plain directory-name subject (the code-signing shape) is not constrained.
2. Whoever reads `ca.key` from the lab Mac can issue a code-signing certificate for `CN=WireGuard LLC`. That includes anyone with that user's access, and backups or sync of the repository folder.
3. On a Windows test PC that still trusts the lab CA, this certificate passes the service's name-only signer check. With part 1's M-1, that means SYSTEM on the test PC through the wireguard-nt update.

**Fix:**

- Add `extendedKeyUsage=serverAuth,clientAuth,1.3.6.1.5.5.8.2.2` to the CA certificate. Windows treats a CA's EKU as a limit on its whole chain.
- Optionally add `excluded;email:.` and a `permitted;dirName` matching `/O=MacVPN test lab`.
- Delete `ca.key` once the server and client certificates and the CRL exist; the CRL is already valid for 89 days, and `--renew` rebuilds everything.

**Status: fixed in `112418b`.** The lab CA carries `extendedKeyUsage=serverAuth,clientAuth,1.3.6.1.5.5.8.2.2`; the leaves keep their own EKUs (server: serverAuth + IKE intermediate, client: clientAuth). OpenSSL (`verify -purpose sslserver|sslclient`), strongSwan's `pki --verify` and macOS' trust evaluation (`security verify-cert`, ssl and IPSec policies, server and client) still accept the chain; macOS refuses it for code signing. On Windows (CryptoAPI chain on the test VM, the CA passed as an extra store, nothing installed) the server certificate is valid for server authentication and the IKE intermediate usage, and invalid for code signing; the full SSTP/IKEv2 connects are the lab checkpoints' (CP1/CP2). `ca.key`, its serial and the CRL database are deleted right after the CRL is made; the CRL is not re-signed (a new one means a new lab, `--renew`; README). The optional `dirName`/`email` constraints were not added. `scripts/test-vpn-lab.sh` checks the CA's EKUs and name constraints from the certificate, the deleted key, and a re-run without it.

### P2-L5: `sign-release.sh` signs whatever the draft holds

**Where:**

- `scripts/sign-release.sh:238-278` downloads each asset and its `.sha256` from the draft. It checks that they agree with each other, prints the hashes, and asks the maintainer to "compare these with the 'SHA-256' steps of the release workflow log". It then signs on `y`.
- The comment in `crates/core/src/update.rs:506-510` says "a compromised GitHub account (or CI) cannot publish an update".

**Exploit path:** a holder of a write token for the repository can replace a draft's MSI or DMG and its `.sha256` between the CI run and signing. The offline signature then covers the replaced bytes, unless the maintainer actually compares the hashes against the log. That log lives on the same compromised account, although job logs are hard to edit.

The guarantee therefore rests on a manual step the script does not enforce.

**Fix:** make the comparison automatic:

- Let `release.yml` record build provenance (`actions/attest-build-provenance`).
- In `sign-release.sh`, run `gh attestation verify --repo SepsiG/MacVPN --signer-workflow …/release.yml` for each asset, with the hash bound to the tag's commit. Refuse to sign on a mismatch.
- Alternatively, rebuild the DMG locally and compare.

Keep the manual prompt as a second check.

**Status: fixed in `a24b63b`.** The release job (no repository code; the only job with `id-token: write` and `attestations: write`) records build provenance for the DMG, the MSIs and their `.sha256` with `actions/attest-build-provenance` (GitHub-owned, pinned by full SHA, v4.2.2). `sign-release.sh` resolves the tag's commit and runs `gh attestation verify <asset> --repo SepsiG/MacVPN --signer-workflow SepsiG/MacVPN/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z --source-digest <commit> --deny-self-hosted-runners` for each downloaded asset, and refuses to sign on any failure; the manual hash prompt stays as the second check. `docs/RELEASING.md` describes it. Not yet exercised against a real release run (the first is 2.0.0).

---

## Informational

- **P2-I1: The Windows auto-unlock key is readable by any process of the user.**
  - The DEK is a generic Credential Manager credential (`crates/platform-win/src/win/keystore.rs:105-118`, `CRED_PERSIST_LOCAL_MACHINE`). DPAPI ties it to the user, not to WinVPN, so any program running as the user can call `CredReadW("local.winvpn.vault")` and open the vault without a prompt.
  - On macOS the Keychain item's ACL trusts only the app's cdhash.
  - This is inherent to auto-unlock on Windows. Say it in the user guide ("auto-unlock trusts every program you run").
- **P2-I2: One Tauri capability covers all four main windows.**
  - `capabilities/main.json` grants `menu`, `manage`, `setup` and `update` the same 100+ commands. These include `ras-trust-ca`, `setup-uninstall` (with `remove_user_data`), `admin-key-export`, `publish-catalog`, `control-*` and `update-install`.
  - `ras_trust_ca` (`app/src-tauri/src/ras.rs:103`) and `setup_uninstall` (`app/src-tauri/src/system.rs:218`) do not check the calling window's label, as the vault commands do.
  - No script injection was found (see below), so this is defence in depth. Split `main` per window, and check `window.label()` in the commands that change the machine or delete data.
  - **Status: fixed in `6890333`.** `main.json` is split into `menu.json`, `manage.json`, `setup.json` and `update.json`, each with only the commands its window's UI uses (`admin-key-export`, `publish-catalog`, `control-*` and the `ras-*` commands: Connections only; `setup-*`: System Status only; `update-install`: Update only). `guard.rs` checks the calling window's label for `ras_trust_ca`, `ras_allow_l2tp_nat`, `make_l2tp_copy`, `delete_connection`, `folder_delete`, `export_connection`, `control_set_enabled` / `_set_allowed` / `_revoke` (Connections), the `setup_install_*` commands, `setup_uninstall`, `setup_open_system_uninstall`, `quit_after_uninstall` (System Status) and `update_install` (Update); the catalog, publishing and shared-credential commands already checked it. The smoke run (debug builds only) adds its reporting commands at runtime.
- **P2-I3: The `setenv` denylist targets macOS.**
  - On Windows, `setenv NAME value` (SAFE) goes into OpenVPN's env set. With `route-method exe` or `ip-win32 netsh|exe` (both SAFE), that set is the environment of `route.exe` and `netsh.exe`, which OpenVPN runs as SYSTEM. OpenVPN forces `PATH`, and both programs come from System32.
  - I found no variable that turns this into code execution **(unverified link)**.
  - A Windows allowlist (for example `UV_*` and the special forms OpenVPN interprets itself) would close the question.
  - **Status: fixed in `7092d9c`.** On Windows `setenv` takes only `FORWARD_COMPATIBLE`, `PUSH_PEER_INFO`, `SERVER_POLL_TIMEOUT`, `REMOTE_RANDOM_HOSTNAME` (interpreted by OpenVPN), `CLIENT_CERT`, `CONFIG_VERSION` (informational, seen in provider profiles) and `UV_*` / `IV_*` (peer info), case-insensitive, also through `setenv opt setenv …`; the denylist still applies. A likely route existed: OpenVPN's env set holds `SystemRoot` and `setenv SystemRoot C:/…` replaced it for `route.exe` / `netsh.exe` as SYSTEM. macOS is unchanged (denylist only). Documented in `docs/openvpn-directives.md`.
- **P2-I4: `down.sh` deletes whatever `LAB_STATE` names.**
  - `scripts/vpn-lab/down.sh:31` runs `rm -rf "${LAB_STATE:?}"`, so a tester's stray `LAB_STATE=$HOME/…` is deleted.
  - Refuse unless `$LAB_STATE/secrets.env` exists and the path is neither `/` nor `$HOME`.
  - **Status: fixed in `112418b`.** `down.sh` deletes the state only when `LAB_STATE` is a folder (not a symbolic link) that resolves inside `scripts/vpn-lab/` (not the folder itself) and holds the `.vpn-lab-state` marker `profiles.sh` writes; otherwise it stops before removing anything. `scripts/test-vpn-lab.sh` covers each refusal and the delete.
- **P2-I5: The macOS signature does not name the asset.**
  - `macvpn-update-v1` signs `version` and `sha256` only (`update.rs:552`). This is fine while there is one DMG per version.
  - If a second macOS asset is ever added (for example, per architecture), introduce `macvpn-update-v2` with the asset name, as WinVPN's domain already has.
- **P2-I6: GitHub can freeze updates.** Whoever controls the repository can hide newer releases from `releases/latest`. This is inherent to the design; noted for the threat model only.

---

## Checked and found sound

### Updaters

- **Core (`crates/core/src/update.rs`):**
  - The JSON fields are strict.
  - Drafts and pre-releases are refused.
  - The tag must match `^v?[0-9]+(\.[0-9]+){0,2}$`.
  - The `.sha256` and `.sig` asset names derive from the product's package name.
  - Every asset URL must be exactly `https://github.com/<repo>/releases/download/<tag>/<name>` (with path segments, no `%`, no `.`/`..`, no query).
  - The repository is queried by its numeric ID (no repo-jacking).
  - The canonical download URL is rebuilt.
- **Signatures:**
  - `message_for` requires `X.Y.Z` (1–9 digits each) and lower-case hex.
  - The domains are disjoint (`macvpn-update-v1` and `winvpn-update-v1`, which also binds the asset name). A MacVPN signature, or one for the other architecture's MSI, therefore never verifies for WinVPN.
  - The check is `verify_strict` with two embedded keys, and the `.sig` is limited to 1 KB on one line.
  - No downgrade: `is_newer`, plus the signature binds the version.
- **Windows (`pure/update.rs`, `win/updater.rs`):**
  - The asset must be exactly `WINVPN.update_asset(version, ARCH)`, with the matching `.sha256` and `.sig`.
  - The file is held with `FILE_SHARE_READ` and `OPEN_REPARSE_POINT`, regular files only, and hashed through the handle (capped at 512 MB).
  - Hash mismatch or a bad signature deletes the file.
  - The msiexec arguments are plain drive paths (no `"`, `..`, control characters or `/`).
  - `parse_relaunch` accepts only its own shape: a PID without leading zeros, a plain absolute path to `WinVPN.exe` and a plain `msiexec-<version>.log`. Even so, the relauncher runs with the user's own token and gains nothing.
  - The notice parser is strict, and housekeeping touches only regular files.
- **macOS (`platform-mac/src/update_installer.rs`):**
  - Hash, then signature, then a re-hash right before `hdiutil attach -nobrowse -readonly -noautoopen`.
  - The attached image path is confirmed with `hdiutil info`.
  - Bundle ID, version and symlinks are checked, then `codesign --verify --strict`. No designated requirement is needed there, because the DMG's bytes are signed.
  - The helper script uses single-quoted paths, a fixed `PATH`, and a fresh 0700 directory created with `O_EXCL`.
- **`sign-release.sh`:**
  - The token goes only through a process-substitution header file, and curl drops it on cross-host redirects.
  - The asset URLs must be under `$REPO_API/releases/assets/`.
  - The keys are parsed from the Rust source, and each signature is verified against them before upload.
  - The private key never touches the disk.
  - The only issue is P2-L5.

### MSI

- **Service registration:** LocalSystem, `ownProcess`, with a quoted image path (`ServiceInstall`).
  - No custom SCM security descriptor is set. The service therefore gets Windows' default DACL: only SYSTEM and Administrators get START, STOP and CHANGE_CONFIG; interactive users get query and interrogate only.
  - Nothing in the code calls `SetServiceObjectSecurity` or `sdset`.
- **`ChangeServiceConfig2` for recovery** runs as the service itself.
- **`C:\ProgramData\WinVPN`** is deliberately never touched by the MSI.
- **`build-msi.sh`:**
  - WiX tool hashes are pinned before and after the build.
  - ICE validation is mandatory in CI.
  - Version and UpgradeCode are gated.
  - The service and DLL are copied, gated, packed and compared byte for byte after unpacking.
  - The service imports are pinned exactly.
  - The CustomAction, ServiceInstall and ServiceControl tables are gated row by row.
  - `.conf` is registered as "Open with" only.
  - The file list is compared against a baseline.
- **Not an issue:** `LaunchApplication` (type 210) belongs to the exit dialog, which `/qb!` does not show, so the updater never starts WinVPN elevated.

### UI and Tauri

- **No raw HTML:** there is no `{@html}`, `innerHTML`, `insertAdjacentHTML`, `eval`/`Function` or dynamic `href` anywhere in `app/ui/src`.
  - Release notes are parsed into text segments (`lib/notes.ts`) and render as text nodes, and their links are not opened.
  - Search highlighting renders text parts inside `<mark>`.
  - Server, log, catalog and toast text is always interpolated, which Svelte escapes.
- **URLs:**
  - Only `open_web_auth_url` (`WebAuthURL::validate`, https only, strict ASCII, a one-second arming delay) and `open_github_url` (`is_safe_github_url`) reach the shell.
  - The platform layer accepts `https://` only (`win/shell.rs`, `platform-mac/src/api/adapters.rs:232`).
  - Catalog data never becomes an opened URL.
- **CSP:** `default-src 'self'`, with `script-src`, `style-src`, `img-src` and `font-src` all `'self'`; `object-src`, `frame-src`, `frame-ancestors`, `base-uri` and `form-action` are `'none'`.
  - The Windows merge patch changes only `connect-src`.
  - `freezePrototype` is on, `assetProtocol` is off, `withGlobalTauri` is false.
- **Navigation guard:** `navigation.rs` allows only the exact app origin (scheme, host, no port, no userinfo), plus the dev origin in `cfg(dev)` builds.
- **Commands:**
  - No command takes a path or URL from the UI; files come from native panels in the backend.
  - The prompt, credential, pairing and vault windows each have a narrow capability of their own.
  - The new RAS commands take only a connection ID. `PendingCa` makes "Trust" install exactly the CA last summarised, and only once.

### Vault and backup

- **Key hierarchy:** a random 32-byte DEK (`BCryptGenRandom` or `getentropy`).
  - It is wrapped twice (password and recovery) with Argon2id and XChaCha20-Poly1305, using a fresh salt and nonce each time and per-slot AAD.
  - The KDF has a floor (64 MiB, t=3; new wraps use t=32) and a ceiling (1 GiB, 256 passes, 16 lanes), checked before the KDF runs.
  - Unwrap errors are uniform.
  - The recovery key has 120 bits.
- **SQLCipher:** a raw-key pragma built in a `Zeroizing` buffer, `cipher_compatibility = 4`, `cipher_memory_security`, `secure_delete`, `temp_store = MEMORY`.
- **Backup and admin-key container (`sealed.rs`):**
  - The whole header is the AAD.
  - A newer `format` is told apart before decryption.
  - The KDF ceiling is 256 MiB / 64 passes / 4 lanes, checked before derivation.
  - Opening has one generic error.
  - Files are read without following symlinks and without blocking, regular files only, and capped while reading.
- **Restore:**
  - A payload is limited to 64 MiB.
  - `validate` caps every collection at 10,000 items and checks names, usernames, passwords, secrets (no control characters, at most 64 KiB), the folder tree and catalog records.
  - Acknowledged risky OpenVPN directives are dropped on merge and listed on "Replace everything".
  - No value from a payload ever becomes a file path.

### Validators, SAFE tier

- **OpenVPN:**
  - The tokenizer mirrors `parse_line` and refuses backslashes, unterminated quotes and control characters.
  - Every `FILE_REFERENCING` directive must be `[inline]`, as must the third argument of `http-proxy` and `socks-proxy`.
  - Only the listed data blocks may open, and only `http-proxy-user-pass` inside `<connection>`.
  - A mismatched closing tag is an error.
  - The FORBIDDEN list covers all script hooks (`up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `auth-user-pass-verify`, `client-*`, `learn-address`, `dns-updown`, `iproute`), code loading (`plugin`, `providers`, `engine`, `pkcs11-*`), `config`, `cd`, `chroot`, `management*`, `log*`, `status`, `writepid`, `tmp-dir` and the file-writing directives.
  - `script-security` is allowed only as 0 or 1.
  - `setenv opt` re-checks the inner directive; the only issue is P2-M1 (fixed in `7092d9c`, which also adds the 255-byte line cap).
  - SAFE arguments use anchored character sets:
    - `dhcp-option` values never contain space, quote, backslash, `$` or `;`;
    - `http-proxy-option` and `verify-x509-name` are `Text` with no line break;
    - a leading `-` is never possible.
- **WireGuard:**
  - The keys `PreUp`, `PostUp`, `PreDown`, `PostDown` and `SaveConfig` are forbidden.
  - Each section has a key allowlist, and the value grammar is strict (base64 keys, CIDR lists, IP or host DNS, numeric ranges, no leading `-`).
  - `FwMark` and `Table` are refused on Windows.
- **strongSwan:**
  - `include`, `updown`, `file`, `crl_uris` and `ocsp_uris` are forbidden.
  - Each section has a key allowlist.
  - `certs`, `cacerts`, `pubkeys` and `cacert` take plain file names only (no `/`, `..` or leading `.`), and no value may be a `file:` URI.
  - Backslashes and unbalanced quotes are refused, and smuggled `=` or `{` are refused.
- **SSTP:** only the keys `server`, `port`, `user`, `cert`, `route_all` and `peer_dns`, each with a strict pattern, plus a PEM-only `<ca>` block.

### Lab and spike scripts

- **`up.sh`:**
  - Refuses `--bind 0.0.0.0`.
  - Every published port is bound to `LAB_BIND`.
  - `labnet` is `internal`, and the servers forward only into it.
- **Secrets:** all are random per lab (`openssl rand`), under `umask 077`.
- **Lab CA:** name-constrained, `pathlen:0`, valid for 90 days; the only issue is P2-L4.
- **CRL server:** serves only the CRL folder.
- **Weak test-only settings:** the IKE proposals include `modp1024`/`3des` for client coverage. They are reachable only on `LAB_BIND`, which is acceptable for a lab.
- **`scripts/ras-spike.ps1`:**
  - Runs as a standard user, writes no HKLM keys and installs nothing.
  - Uses dummy secrets only, and refuses to write a fixture that contains them.
  - Dials only TEST-NET-1 (`192.0.2.1`).
  - Removes its entries, and deletes the default phonebook only if this run created it.

## Not covered

- **Runtime behaviour:** nothing was run on Windows or macOS. These need a VM:
  - Tauri 2.12's `main.wxs` (whether the UI offers a folder choice; the default ACL of the resulting folder) for P2-M2;
  - the token the impersonated WebView2 action gets on the elevated updater path (P2-L1);
  - OpenVPN's `env_block` contents for `route.exe` and `netsh.exe` (P2-I3);
  - P2-M1 against the real service. The abort itself was reproduced with the same validator code on macOS.
- **`platform-mac` user-level modules:** `brew.rs`, `http.rs`, `catalog_http.rs`, `net_probe` and `net_watch` were still only skimmed.
- **`WebAuthURL::validate` and `is_safe_github_url`:** taken as reviewed in 1.x and not re-derived.
