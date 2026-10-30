# LinVPN L0 — the workspace on Linux (baseline)

**Date:** 2026-10-29 · **VM:** Ubuntu 26.04.1, amd64 (x86_64), rustc 1.99.1, OpenSSL 3.5.5 (`/usr/bin/openssl`) · **Commit:** `b24ea93` (develop with Tasks 1 and 8) plus the throwaway line below, run with `LINVPN_REMOTE_DIR=linvpn-work-t2`

## Method

The throwaway Linux SQLCipher line, in the worktree only (not committed), after the Windows `rusqlite` table of
`crates/core/Cargo.toml`:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher-vendored-openssl"], optional = true }
```

`cargo metadata --locked --format-version 1` accepted it on the Mac (exit 0): **`Cargo.lock` does not change**
(`openssl-src`/`openssl-sys` are already there through Windows). Then on the VM:

    scripts/lin-remote.sh run 'cargo check --locked --all-targets -p macvpn-core -p macvpn-app-core -p macvpn-platform-api -p macvpn-helper -p macvpn-control-client'
    scripts/lin-remote.sh run 'dbus-run-session -- cargo test --locked -p macvpn-core -p macvpn-app-core -p macvpn-platform-api -p macvpn-helper -p macvpn-control-client --lib --tests --no-fail-fast'

(The test command adds `-p macvpn-helper` to the plan's Step 3 list, so that class (c) is measured; doc tests are
not run, as in the plan.) `macvpn-app` was not built: its `platform/mod.rs` has the `compile_error!` for Linux by
design (Task 18).

## Compile results

| Crate | Result | Errors (file:line, cause) |
|---|---|---|
| `macvpn-core` (with `vault` through feature unification: SQLCipher + vendored OpenSSL built on Linux) | ok, no warnings | – |
| `macvpn-platform-api` | ok, no warnings | – |
| `macvpn-app-core` | ok, no warnings | – |
| `macvpn-helper` (lib + `mvpn`; on Linux `main.rs` runs `windows::main()`, whose non-Windows stub compiles) | ok, no warnings | – |
| `macvpn-control-client` | ok, no warnings | – |

All targets (`--all-targets`: lib, bins, tests) compile. `platform-mac`, `platform-win` and `winsys` are
OS-gated as a whole and were not asked for.

## Test results

1944 passed, 2 failed, 2 ignored (129 test binaries). The ignored ones are `write_compat_fixtures` (writes the
1.4.0 fixtures) and `default_parameters_timing` (slow Argon2id), the same as on macOS. Every vault test binary
(`vault_*`) ran and passed on Linux, and so did the helper's portable Windows-backend tests (`service_core`,
`bridge_state`, `wg_*`, …) and the `mvpn` unit tests.

| Test | Class (a/b/c/d) | Cause | Proposed fix (test or code) |
|---|---|---|---|
| `macvpn-core --test importer` `routeros_v6_wiki_with_files_imports_cleanly` (`crates/core/tests/importer.rs:739`) | (a) | `make_router_files` adds `-traditional` to `openssl rsa -aes256` only under `cfg!(windows)`, reading "Windows" as "OpenSSL 3". Linux's `/usr/bin/openssl` is OpenSSL 3.5.5, so the "legacy" key comes out as PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) and the assertion for `Proc-Type: 4,ENCRYPTED` fails. The importer itself is fine (it inlined the PKCS#8 key; issues and risky are empty). | Test only: pass `-traditional` whenever the tool is OpenSSL 3, i.e. `cfg!(not(target_os = "macos"))` (macOS' `/usr/bin/openssl` is LibreSSL 3.3.6, which has no `-traditional` and writes the legacy form anyway), with the comment updated. Tests are outside the cfg rule's scanned roots. |
| `macvpn-core --test openvpn_tiers` `every_option_name_in_the_source_is_classified_and_documented` (`crates/core/tests/openvpn_tiers.rs:489`) | (d) | `no explicit tier: setcon`. The test's `has_explicit_tier` uses `platform_reasons(TargetOs::host())`; on Linux that is the draft `PLATFORM_LINUX` table in `crates/core/src/validators/openvpn.rs:417–419`, which deliberately leaves `setcon` out ("phase 4 revisits `setcon`"). `setcon` is in no other table (on macOS it is in `NOT_ON_MACOS`, on Windows in `PLATFORM_WINDOWS`), so on Linux it falls to the default tier. | A decision, not a test fix: give `setcon` an explicit Linux tier. LinVPN connects through NM's OpenVPN plugin (decision 3), which cannot pass `setcon`, so the natural answer is a Linux platform reason, or `FORBIDDEN` everywhere (it changes the SELinux context of the daemon). Seen on the way: the draft table maps the other names to `REASON_PLATFORM` ("Not supported on macOS (Windows or Linux only)"), a text that is wrong on Linux; L-b's Linux tier needs its own reason text. The Linux tier is L-b's (spec 3.1), so Task 11 asks the coordinator: either the one-entry change now (and `docs/openvpn-directives.md` says so), or the test's Linux branch names `setcon` as the one pending entry until L-b. |

No class (b) (a macOS assumption in production code that Linux reaches) and no class (c) (the helper's backend on
Linux) failure was found.

## The desktop context (Task 1 Step 6)

From a `lin-remote.sh desktop` job with `linvpn-dev` logged in at the desktop (recorded in Task 1's commit
`86df1de`):

    display=wayland-0 bus=unix:path=/run/user/1001/bus
    org.freedesktop.NetworkManager.network-control       igen (yes)
    org.freedesktop.NetworkManager.settings.modify.own   igen (yes)

Polkit treats the user manager (`systemd-run --user`) as the graphical session: both NM permissions are `yes`, not
`auth` (as spikes L0-1 and L0-3 found). The job's locale is Hungarian (`igen`): tests and scripts that parse tool
output must set `LC_ALL=C` or parse the D-Bus values instead.

Also seen on the VM (for Task 18): the display device is `bochs-drm` (`/dev/dri/card1` only, no
`/dev/dri/renderD*`), so WebKitGTK renders in software; see Task 18's note on `WEBKIT_DISABLE_DMABUF_RENDERER`.

## Consequences for L-a

- **(a) Task 11:** one test fix in `crates/core/tests/importer.rs` (`-traditional` for OpenSSL 3 on every
  non-macOS host). CI's Ubuntu runners have OpenSSL 3 at `/usr/bin/openssl` too, so the same fix covers CI.
- **(b) Task 11:** nothing to fix today; `crates/core/src/fsx/unix.rs` and the vault behave on Linux as on macOS.
- **(c) Task 11:** nothing failing. Note for Tasks 9 and 12: on Linux `crates/helper/src/main.rs` still runs
  `windows::main()`; the helper's `windows` module is portable except its `#[cfg(windows)]` parts, and its tests
  run (and pass) on Linux, so they must keep running when `main.rs` gets its Linux branch.
- **(d) Task 11 with the coordinator:** `setcon`'s Linux tier (above). The rest of the draft `PLATFORM_LINUX` tier
  stays L-b's.
- **Task 9:** the SQLCipher line exactly as above compiles and passes every vault test on Linux, and needs no
  `Cargo.lock` change (`--locked` holds). Nothing else changes the plan.
