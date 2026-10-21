#!/bin/bash
# The Windows compile check that runs on a Mac (docs/superpowers/spikes/2026-10-20-windows-check-spike.md,
# decision A). It installs nothing: the two Windows targets come from rust-toolchain.toml through rustup.
#
# Checked here, for x86_64-pc-windows-msvc and aarch64-pc-windows-msvc, debug and release, with --all-targets:
#   macvpn-core (without `vault`), macvpn-helper, macvpn-control-client.
# Not checked here: the vault, platform-api, platform-win, app-core and the app. They need C code built for MSVC
# (SQLCipher with a vendored OpenSSL, whose build needs nmake and a Windows Perl; the app's Windows resource, which
# needs rc.exe or llvm-rc), so CI's windows-latest job checks them.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

TARGETS=(x86_64-pc-windows-msvc aarch64-pc-windows-msvc)
PACKAGES=(-p macvpn-core -p macvpn-helper -p macvpn-control-client)

installed=$(rustup target list --installed) || { echo "FAIL: rustup target list"; exit 1; }
for target in "${TARGETS[@]}"; do
    if ! grep -qx "$target" <<<"$installed"; then
        echo "FAIL: the Rust target $target is not installed (it is listed in rust-toolchain.toml; run any cargo"
        echo "      command in the repository, or: rustup target add $target)"
        exit 1
    fi
done

failed=()
for target in "${TARGETS[@]}"; do
    for profile in dev release; do
        echo "==> cargo check --locked --all-targets --profile $profile --target $target ${PACKAGES[*]}"
        if ! cargo check --locked --all-targets --profile "$profile" --target "$target" "${PACKAGES[@]}"; then
            failed+=("$target $profile")
        fi
    done
done

if [ ${#failed[@]} -gt 0 ]; then
    echo "FAIL: the Windows check failed for: ${failed[*]}"
    exit 1
fi
echo "OK: macvpn-core (without vault), macvpn-helper and macvpn-control-client compile for both Windows targets"
echo "The vault, platform-api, platform-win, app-core and the app are checked by CI (windows-latest)."
