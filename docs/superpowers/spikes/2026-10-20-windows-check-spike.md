# Windows check spike (1.5.0, Task 2) – findings

Date: 2026-10-20. Machine: macOS 27.0 on Apple silicon, Rust 1.99.1 (pinned), rustup 1.29.1, Apple clang 21.0.0
(Xcode), no Homebrew LLVM. Spec: `docs/superpowers/specs/2026-10-20-cross-platform-winvpn-design.md`. Plan:
`docs/superpowers/plans/2026-10-20-platform-neutral-refactor.md` Task 2.

The probes ran in a scratch clone of `develop` (`e6d7f2d`) outside the repository, with its own target directory. Only
this report and the windows-latest probe (`2026-10-20-windows-check-spike.workflow.yml`, an inactive copy, see
"windows-latest") are committed. Nothing system-wide was installed: only the two rustup targets (user level).
`cargo-xwin` was **not** installed and no MSVC CRT/SDK was downloaded, because the source of `openssl-src` and the
missing LLVM tools decide the local question without it (section 3); the Microsoft licence was therefore not
accepted on anyone's behalf.

## Summary of decisions

| Item | Decision |
|------|----------|
| **A** (local check) | **Replaced.** `cargo xwin` cannot build this workspace from macOS: `openssl-src` builds MSVC targets only with `nmake.exe` found through the Windows registry and a Windows Perl, so no cross toolchain helps; the Tauri resource step needs `llvm-rc`. `scripts/check-windows.sh` checks only the crates without C dependencies (`macvpn-core` without `vault`, `macvpn-helper`, `macvpn-control-client`) on both targets and says that CI's windows-latest job is the full check. It has no `cargo xwin` branch. `macvpn-platform-api` and `macvpn-platform-win` are **not** in the local list when they depend on core's `vault` (the re-exported `KeyStore`, `Entropy`, `LegacyKeychain`, `CatalogFetcher` are behind `vault`); they are CI-only. |
| **B** (SQLCipher on Windows) | **Default kept, pending the windows-latest run:** `[target.'cfg(windows)'.dependencies] rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher-vendored-openssl"], optional = true }`. It adds exactly `openssl-src 300.6.1+3.6.3` and `openssl-sys 0.9.117` to `Cargo.lock`; neither reaches a macOS target (`cargo tree`). **But** `node scripts/third-party-notices.mjs --check` fails with the line in place (it lists `openssl-sys`), because `cargo metadata --filter-platform` does not resolve features per target. Task 16 changes the script (section 5). The fallback (`features = ["sqlcipher"]`) was also probed: it builds no C code, so a `cargo check` of the vault code passes the dependency stage even from macOS. |
| **C** (NASM) | **None.** `openssl-src` enables assembly only when `nasm` is on the PATH (on a Windows host) and otherwise configures `no-asm`; it never fails for a missing NASM. The windows-latest run records which case the image hits. |
| Perl (new) | `openssl-src` refuses a non-Windows Perl ("This perl implementation doesn't produce Windows like paths"). In Git Bash (`shell: bash`) the first `perl` on the PATH is MSYS Perl, which is likely refused the same way. Task 17 sets `OPENSSL_SRC_PERL: C:\Strawberry\perl\bin\perl.exe` for the Windows job unless the windows-latest run shows the PATH Perl works. |
| Line endings (new) | Task 17's Windows job runs `git config --global core.autocrlf false` before the checkout (or the repo gets a `.gitattributes`): a CRLF checkout breaks the toolchain step's `sed` (a trailing `\r`) and every byte-compared Task 1 fixture. |
| Tauri resources | `tauri-build` refuses a Windows target without `app/src-tauri/icons/icon.ico` (the default path; the config's icon list need not change, so the macOS bundle is unaffected). It then compiles the resource with `rc.exe` (Windows SDK, on the image) or, off Windows, `llvm-rc` (absent here). The WebView2 loader needs nothing: `webview2-com-sys` ships prebuilt `WebView2Loader` libraries for x64, ARM64 and x86. |
| rustup cost | rustup 1.29 installs targets listed in `rust-toolchain.toml` automatically on the first `cargo` call in the repo. Listing the two Windows targets costs every macOS job (CI `rust`, `dmg`, and `release.yml`) about 45 MB of download (`rust-std` 23.6 MB + 23.7 MB xz) and about 235 MB on disk; about 6 s here. Task 17 lists all four targets in the macOS jobs' `-t` (and in `release.yml`) so the download happens in the toolchain step, visibly. |

## 1. Targets

`rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc`: 6.6 s, 118 MB + 117 MB under the toolchain.
Downloads: `rust-std-1.99.1-x86_64-pc-windows-msvc.tar.xz` 23 619 148 bytes, `…-aarch64-pc-windows-msvc.tar.xz`
23 729 852 bytes. With both targets removed and listed in a scratch `rust-toolchain.toml`, a plain `cargo --version`
in the repository downloaded the missing one (rustup prints "downloading component rust-std").

## 2. `cargo check` from macOS, today's code

Both targets give the same results; times are cold, with a warm registry. Disk: about 310 MB of target directory per
Windows target for a full workspace check.

### 2.1 `macvpn-core` without `vault` (to-do list for Task 4)

Fails in 6 s (x64) / 2 s (ARM64) with 26 errors, all Unix file APIs; the `libc` crate itself compiles on Windows (it
just lacks the `O_*` constants):

| File | Errors |
|------|--------|
| `store.rs` | `std::os::unix` import; `DirBuilder::mode` (109, 220); `Permissions::from_mode` (110); `OpenOptions::mode` (154); `custom_flags` (190); `libc::O_NOFOLLOW` (154, 190), `libc::O_NONBLOCK` (190) |
| `exporter.rs` | `std::os::unix` import (15, 128); `OpenOptions::mode` (137); `libc::O_NOFOLLOW` (138); `Permissions::from_mode` (146); `Metadata::dev`/`ino` (150) |
| `importer.rs` | `std::os::unix` import (13); `custom_flags` + `O_NOFOLLOW` + `O_NONBLOCK` (550) |
| `mfa.rs` | `std::os::unix` (623); `custom_flags` + `O_NOFOLLOW` + `O_NONBLOCK` (625) |
| `log.rs` | `std::os::unix` import (7); `Metadata::ino` (127) |

### 2.2 `macvpn-core --features vault`

With the scratch Windows rusqlite line (`bundled-sqlcipher-vendored-openssl`): **the build script of `openssl-sys`
fails** before any Rust code of core is checked:

```
"perl" "./Configure" … "no-asm" "VC-WIN64A"
This perl implementation doesn't produce Windows like paths (with backward slash directory separators).
This Perl version: 5.34.1 for darwin-thread-multi-2level
```

Even with a Windows-like Perl the next step could not work: for `*-msvc` targets `openssl-src` (300.6.1) runs
`cc::windows_registry::find(target, "nmake.exe")`, which finds nothing on a non-Windows host. So `cargo xwin` (which
supplies `clang-cl`, `lld-link`, `llvm-lib` and the CRT/SDK headers, but no `nmake` and no Windows Perl) cannot build
vendored OpenSSL for MSVC from macOS. It was not installed for that reason; besides, it needs Homebrew LLVM
(`clang-cl`, `lld-link`, `llvm-lib`, `llvm-rc` are not in Xcode's toolchain: `xcrun -f` finds none of them), and
installing that is a system change outside this spike.

With the **fallback** line (`features = ["sqlcipher"]`, no bundled C): `libsqlite3-sys` builds without a C compiler,
and core fails only in its own code: 52 errors, the 26 above plus the vault and catalog modules (Task 4's full list):
`catalog/source.rs` 8, `vault/db.rs` 10, `vault/keys.rs` 4, `vault/sealed.rs` 4, plus `store.rs` 9, `exporter.rs` 7,
`importer.rs` 4, `mfa.rs` 4, `log.rs` 2 (counted per error location).

### 2.3 The whole workspace (`--workspace --all-targets --keep-going`)

32 s (x64) / 28 s (ARM64). Failures:

| Unit | Cause | Owner |
|------|-------|-------|
| `openssl-sys` build script | as 2.2 (C build of OpenSSL needs a Windows host) | CI only |
| `objc2` | "`objc2` only works on Apple platforms" | Task 12: platform-mac's Apple crates under `cfg(target_os = "macos")` |
| `core-foundation` | `std::os::unix`, `libc::PATH_MAX` | Task 12 |
| `oslog` build script | `cc` compiles its `wrapper.c` for the Windows target and fails | Task 12 |
| `macvpn-app` build script | `icons/icon.ico` not found (with the icon: `NotAttempted("llvm-rc")`) | Task 16 (icon); CI only (resource compiler) |
| `macvpn-control-client` (lib, lib test) | `std::os::unix` at `lib.rs:44` and `lib.rs:612` | Task 16 |
| `mvpn`, `macvpn-app-core`, `macvpn-platform-mac`, the app's Rust code | not reached (they depend on core, which fails) | see below |

The only C code in the Windows dependency graph: `libsqlite3-sys` (SQLCipher), `openssl-src`, `oslog` (gone with
Task 12) and the Tauri resource (`tauri-winres` → `embed-resource`). `webview2-com-sys`'s build script only copies its
prebuilt loader libraries.

### 2.4 The crates not reached (inventory by source scan, the to-do list for Tasks 11, 14–16)

- `crates/mvpn/src` (Task 11): Unix APIs or `libc` in `fsx.rs`, `exec.rs`, `log.rs`, `main.rs`, `openvpn.rs`,
  `mgmt_bridge.rs`, `run_dir.rs`, `sstp.rs`, `sys.rs`. Free of them: `cli`, `hook_dns`, `mask`, `paths`, `procs`,
  `secrets`, `testmode`, `strongswan`, `wireguard`, `lock`, `validate`, `respond`, `ctx`, `status`, `updown` (some of
  these still call macOS-only paths or tools; the scan only covers compile errors). Its `libc` dependency is
  unconditional.
- `crates/app-core/src`: `import_export.rs`, `control.rs`, `vault.rs` (Tasks 4, 5); `libc` unconditional.
- `app/src-tauri/src`: `control.rs`, `smoke.rs`, plus every platform-mac call (Tasks 14, 15).
- Tests with Unix APIs: core `exporter.rs`, `vault_db.rs`, `importer.rs`, `mfa.rs`, `store.rs`, `catalog_source.rs`,
  `vault_keys.rs`, `control_registry.rs`, `catalog_admin_file.rs`, `common/mod.rs`, `vault_backup.rs`; app-core
  `control_server.rs`, `vault_lifecycle.rs`, `migration.rs`, `catalog_publish.rs`, `catalog_file.rs`,
  `control_support/mod.rs` (Task 16's `#[cfg(unix)]` list; the control ones move to the TCP test transport in Task 5).

## 3. Decision A in detail: why not `cargo xwin`

The plan's default kept `cargo xwin` for the full local check unless it "cannot build SQLCipher/OpenSSL or the Tauri
resources". It can build neither on this Mac: OpenSSL by construction (`nmake.exe` through the Windows registry, a
Windows Perl), the resource without `llvm-rc`. A workaround exists in principle (`OPENSSL_NO_VENDOR` plus prebuilt
OpenSSL headers and import libraries for both targets, Homebrew LLVM, the xwin SDK), but it would be a second build
setup that CI does not use, and it is not worth maintaining. So:

- `scripts/check-windows.sh`: checks `rustup target list --installed` for both targets; runs
  `cargo check --locked --all-targets --target <t> -p macvpn-core -p macvpn-helper -p macvpn-control-client`
  (`macvpn-core` without `vault`; verified with the scratch line in place: `--all-targets -p macvpn-core -p mvpn
  -p macvpn-control-client` builds no `openssl-sys`/`libsqlite3-sys`, only Rust errors remain) for both targets,
  debug and `--release`;
  then prints "the vault, platform-api, platform-win, app-core and the app are checked by CI (windows-latest)" and
  exits 0 when those passed.
- If Task 9 keeps `macvpn-platform-api` free of core's `vault` feature (for example by putting the re-exports of the
  vault traits behind a `vault` feature of platform-api), platform-api and platform-win join the local list. The plan
  does not require it; the default is CI-only.

Local timing of the always-on part once it compiles: about 6 s cold per target for core (measured on today's code up
to the error), seconds when warm.

## 4. Decision B in detail

- Lock file: `cargo update -w` with the scratch line adds only `openssl-src v300.6.1+3.6.3` and `openssl-sys
  v0.9.117`.
- macOS isolation: `cargo tree --locked --target aarch64-apple-darwin -e features -i openssl-sys` and the same for
  `x86_64-apple-darwin` print "nothing to print"; `libsqlite3-sys`'s features on macOS stay `bundled-sqlcipher`
  (no `bundled-sqlcipher-vendored-openssl`); a macOS `cargo check -p macvpn-core --features vault` builds no
  `openssl-sys`. The normal-dependency trees of `macvpn-app` + `mvpn` for both macOS targets are identical with and
  without the line (258/259 packages, no `openssl`).
- `scripts/third-party-notices.mjs --check` **fails** with the line: the regenerated file gains `openssl-sys 0.9.117
  (MIT)` and its licence file. Without the line it passes. Cause: the script walks `cargo metadata --filter-platform
  <macOS target>`, whose resolve unifies features across all targets (the optional `openssl-sys` edge of
  `libsqlite3-sys` is active because Windows turns it on); only `cargo build`/`cargo tree` apply resolver 3's
  per-target features.
- The fallback (`["sqlcipher"]`) passes the dependency stage of `cargo check` even from macOS, but would mean no
  Windows `cargo test` of the vault (no SQLCipher to link). Kept as the fallback only.

## 5. What later tasks must change

- **Task 4 (`fsx`)**: the error list of 2.1 and 2.2 (`catalog/source.rs`, `vault/{db,keys,sealed}.rs` too); core's
  `libc` → `[target.'cfg(unix)'.dependencies]`.
- **Task 9 (platform-api)**: depending on core with `vault` makes it CI-only for Windows (section 3). Optional: a
  `vault` feature for the re-exports to keep it locally checkable.
- **Task 10 (Tauri per-OS config)**: `icons/icon.ico` at the default path is enough for `tauri-build`; no icon-list
  change in `tauri.conf.json`. Without `bundle.publisher`, the Windows `CompanyName` resource is the identifier's
  second segment (`macvpn` / `winvpn`); set `bundle.publisher` in `tauri.windows.conf.json` if that matters (phase 2).
- **Task 11 (helper)**: the module list of 2.4; `libc` → `cfg(unix)`.
- **Task 12 (platform-mac)**: `objc2`, `core-foundation`, `oslog` (and the other Apple crates) under
  `[target.'cfg(target_os = "macos")'.dependencies]`; `oslog`'s build script otherwise runs `cc` for Windows.
- **Task 16**:
  - `scripts/check-windows.sh` as in section 3, without a `cargo xwin` branch.
  - `scripts/third-party-notices.mjs`: take the crate set per macOS target from
    `cargo tree --locked -e normal --target <t> -p macvpn-app -p mvpn --prefix none -f '{p}'` (verified: no
    `openssl-*` with the line, identical to today without it), keep `cargo metadata` only for licence and path
    lookup. Then `--check` passes and the committed notices file does not change.
  - Add the Windows rusqlite line (Decision B), update the comment in `crates/core/Cargo.toml`.
  - `icons/icon.ico` from `npx tauri icon` (verified: 36 090 bytes from `icons/icon.png`; only the `.ico` is kept).
  - `examples/macvpn-control-client`: `lib.rs:44`, `lib.rs:612` behind `cfg(unix)`.
- **Task 17 (CI)**:
  - Windows job: `git config --global core.autocrlf false` before the checkout (or `.gitattributes`); the
    `OPENSSL_SRC_PERL` env unless the probe shows the PATH Perl works; NASM: nothing unless the probe says otherwise.
  - macOS jobs (`rust`, `dmg`) **and `.github/workflows/release.yml`**: pass all four targets in `-t`, since rustup
    downloads the Windows `rust-std` anyway once `rust-toolchain.toml` lists them.
- **Resolved point "Checking Windows from macOS"**: the full check is CI-only; locally only the crates without C
  dependencies.
- **Phase 2**: the WebView2 loader (static or DLL) and its licence in the notices and the MSI.

## 6. windows-latest (pending: runs when the maintainer pushes the probe)

Not pushed by this spike. The probe is `docs/superpowers/spikes/2026-10-20-windows-check-spike.workflow.yml`: copy it
to `.github/workflows/windows-spike.yml` on a throwaway branch `spike/windows-check`, push, read the log, delete the
branch. Per target (x64 and ARM64, `fail-fast: false`) it records:

1. `core.autocrlf` of the image (then checks out with LF).
2. The Perl on the Git Bash PATH and Strawberry Perl, `where nasm`, the Visual Studio install with ARM64 tools.
3. A probe crate (`rusqlite =0.40.2` with `bundled-sqlcipher-vendored-openssl`, the same `libsqlite3-sys`,
   `openssl-sys`, `openssl-src` versions as the scratch lock): built cold with the PATH Perl, and on failure with
   `OPENSSL_SRC_PERL=C:\Strawberry\perl\bin\perl.exe`; then rebuilt with a warm registry and a cold target, then a
   no-op rebuild (the three times). Whether `openssl-src` enabled assembly or `no-asm`. On x64 it runs the binary:
   `cipher_version`, `cipher_provider` (expected `openssl`) and a keyed write/reopen/read round trip. ARM64 is
   cross-compiled with the image's MSVC ARM64 tools (not run).
4. The scratch Windows rusqlite line + `cargo update -w`, then `cargo check --workspace --all-targets --keep-going`
   on today's code: expected to fail in Rust code; the log gives the time and the list of failing build scripts and
   crates (the build scripts must be only `macvpn-app`'s icon check, or none once the icon exists).

What to write back here after the run: the Perl result (decides the `OPENSSL_SRC_PERL` line of Task 17), NASM/asm
(Decision C), the three build times per target, the ARM64 cross build (pass/fail), the probe's cipher provider, and
`core.autocrlf`. If the probe crate cannot be built on the image, Decision B falls back as the plan says (Windows
`cargo check` only, `["sqlcipher"]`, a phase 2 item) and Task 17's test step drops `-p macvpn-app-core`.
