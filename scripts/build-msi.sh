#!/bin/bash
# Builds the unsigned WinVPN MSIs on Windows (Git Bash), the counterpart of build-dmg.sh (spec 7):
#   1. the three version numbers agree; no build-changing variable leaks in; THIRD-PARTY-NOTICES.windows.txt current
#   2. the UI, then per architecture: `tauri build --bundles msi` for the target (WiX 3.14, which the Tauri CLI
#      downloads once into %LOCALAPPDATA%\tauri\WixTools314 and checks against the SHA-256 it pins; this script
#      checks candle.exe, light.exe and dark.exe against the hashes below before the build when the folder exists
#      already, so a replaced tool never runs, and again after it)
#   3. release gates on the WinVPN.exe inside the MSI (unpacked, see 4): its PE machine and GUI subsystem; no
#      debug-only code (MACVPN_SANDBOX_HOME, MACVPN_SMOKE, the updater's --test-install-msi); SQLCipher with the
#      vendored OpenSSL 3, statically linked (no crypto or SQLite DLL imported, no CommonCrypto provider)
#   3a. the WinVPN Service (2b plan, Task 15): the helper crate's release mvpn.exe, installed as WinVPNService.exe,
#      and the pinned wireguard-nt wireguard.dll (scripts/fetch-wireguard-nt.sh), both next to WinVPN.exe, through
#      the WiX fragment app/src-tauri/wix/service.wxs.in (generated into target/winvpn-wix/<arch>/). Gated before
#      `tauri build` (the built files) and again unpacked from the MSI (what ships, byte for byte the built ones):
#      the service exe's PE machine and console subsystem, no debug-only code (the test console's options, the
#      test pipe prefix, the fake engines), no SQLite, exactly the pinned DLL imports; wireguard.dll's pinned
#      SHA-256 and Authenticode signer. The MSI's ServiceInstall, ServiceControl and the components' folder are
#      checked row for row; the MSI has no failure actions (MsiServiceConfigFailureActions absent or empty: a restart
#      action fails the install with error 1939, the service sets its own recovery) and no custom action beyond
#      the pinned list
#   3b. the install folder (security review part 2, P2-M2): SetINSTALLDIR pins it to <Program Files>\WinVPN before
#      CostFinalize in both sequences, WelcomeDlg's Next skips the folder dialog, MsiLockPermissionsEx gives it
#      exactly INSTALLDIR_SDDL (protected, admins only can change it), LockPermissions is empty; no downgrade (P2-L2:
#      the Upgrade rows of allowDowngrades false, same version still upgraded, and the launch condition); the WebView2
#      bootstrapper embedded (P2-L1: InvokeBootstrapper from the Binary table, signed by Microsoft Corporation)
#   4. the MSI: renamed to the update asset name; its tables read without installing (scripts/msi-query.ps1):
#      ProductVersion, the fixed UpgradeCode, the Start-menu shortcut carrying the AppUserModelID local.winvpn (the
#      toasts need it), the file associations (.ovpn, .sstp and .macvpncatalog as default, .conf only under "Open
#      with"); its files exactly scripts/bundle-baseline/winvpn-msi-files.txt (unpacked with WiX's dark.exe -x and
#      placed by the File, Component and Directory tables: no Windows Installer service, nothing installed), the
#      notices inside equal to the committed file, the WinVPN.exe inside the built one but for Tauri's bundle-type
#      marker; .sha256 next to it
# Authenticode only when WINVPN_SIGN_THUMBPRINT (and WINVPN_SIGN_TIMESTAMP_URL) are set: off by default and in CI
# (the Tauri CLI then signs WinVPN.exe before bundling and the MSI after, with signtool).
#
#   scripts/build-msi.sh [--arch x64|arm64|both] [--write-baseline]
#   scripts/build-msi.sh --check-tools      only the check of the WiX tools before a build, then exit
#   scripts/build-msi.sh --check-msi-rows WHAT ROWS-FILE [ARGS]
#                                           only one MSI table gate (check_msi_rows) on rows in a file, then exit
#                                           (scripts/test-build-msi.sh; runs on any OS)
#   scripts/build-msi.sh --service-fragment TEMPLATE SERVICE_EXE WIREGUARD_DLL OUT
#                                           only the service fragment: writes OUT from TEMPLATE with the two
#                                           absolute Windows paths, prints the `tauri build --config` JSON that adds
#                                           it, then exits (scripts/test-build-msi.sh; runs on any OS)
#
# WINVPN_WIX_DIR (with --check-tools only; scripts/test-build-msi.sh): the folder to check instead of the Tauri
# CLI's.
#
# WINVPN_WIX_NO_ICE=1 (never in CI): where the Windows Installer service cannot be reached (an OpenSSH session with
# key authentication: msiexec fails with 1601), light.exe's ICE validation cannot run and the Tauri CLI fails; the
# script then links the MSI from the same objects again with light.exe -sval and says so. CI validates.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

ARCHES=(x64 arm64)
WRITE_BASELINE=0
CHECK_TOOLS=0
FRAGMENT_ONLY=()
CHECK_ROWS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --service-fragment) [ $# -ge 5 ] || die "--service-fragment needs TEMPLATE SERVICE_EXE WIREGUARD_DLL OUT"
                        FRAGMENT_ONLY=("$2" "$3" "$4" "$5"); shift 4 ;;
    --arch) [ $# -ge 2 ] || die "--arch needs x64, arm64 or both"
            case "$2" in x64|arm64) ARCHES=("$2") ;; both) ;; *) die "--arch needs x64, arm64 or both" ;; esac; shift ;;
    --write-baseline) WRITE_BASELINE=1 ;;
    --check-tools) CHECK_TOOLS=1 ;;
    --check-msi-rows) [ $# -ge 3 ] || die "--check-msi-rows needs WHAT ROWS-FILE [ARGS]"
                      shift; CHECK_ROWS=("$@"); break ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

# The service fragment: TEMPLATE with @SERVICE_EXE@ and @WIREGUARD_DLL@ replaced by absolute Windows paths (drive
# letter, then only letters, digits, space, backslash, '.', '_' and '-': nothing XML or sed would read), written to
# OUT; refused when a placeholder is left or a path did not land exactly once.
render_service_wxs() { # TEMPLATE, SERVICE_EXE, WIREGUARD_DLL, OUT
  local path re='^[A-Za-z]:[\\][A-Za-z0-9 ._\\-]+$' esc_exe esc_dll
  for path in "$2" "$3"; do
    [[ "$path" =~ $re ]] || die "service fragment: not an absolute Windows path of plain characters: $path"
  done
  [ -f "$1" ] || die "service fragment: $1 is missing"
  esc_exe="$(printf '%s' "$2" | sed 's/\\/\\\\/g')"
  esc_dll="$(printf '%s' "$3" | sed 's/\\/\\\\/g')"
  sed -e "s|@SERVICE_EXE@|$esc_exe|g" -e "s|@WIREGUARD_DLL@|$esc_dll|g" "$1" >"$4" || die "service fragment: cannot write $4"
  if grep -qE '@[A-Za-z0-9_]+@' "$4"; then die "service fragment: a placeholder is left in $4"; fi
  [ "$(grep -cF "Source=\"$2\"" "$4")" = 1 ] || die "service fragment: the service exe's Source is not in $4 exactly once"
  [ "$(grep -cF "Source=\"$3\"" "$4")" = 1 ] || die "service fragment: wireguard.dll's Source is not in $4 exactly once"
}
# The `tauri build --config` JSON (a JSON merge patch) that adds the fragment (a Windows path) and its component
# group; the patch replaces arrays whole, so tauri.windows.conf.json's own fragment paths come first.
wix_config() { # FRAGMENT
  node -e '
    const wix = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).bundle.windows.wix;
    if (wix.componentGroupRefs) throw new Error("tauri.windows.conf.json has componentGroupRefs: merge them here");
    console.log(JSON.stringify({ bundle: { windows: { wix: {
      fragmentPaths: [...wix.fragmentPaths, process.argv[2]],
      componentGroupRefs: ["WinVPNServiceComponents"],
    } } } }));
  ' app/src-tauri/tauri.windows.conf.json "$1"
}

# The install folder's ACL (security review part 2, P2-M2): app/src-tauri/wix/service.wxs.in's PermissionEx, which
# Windows Installer applies from the MsiLockPermissionsEx table. SDDL by SID (a localized Windows names the groups
# differently, and the name-based LockPermissions table would fail there with error 1609): protected (P: nothing
# inherited from the parent, whose "Users: modify" made C:\WinVPN writable), SYSTEM and Administrators full control,
# Users, Authenticated Users, ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES read and execute
# (0x1200a9), each inherited by files and folders (OICI).
INSTALLDIR_SDDL='D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;AU)(A;OICI;0x1200a9;;;AC)(A;OICI;0x1200a9;;;S-1-15-2-2)'

# The MSI table gates on rows as scripts/msi-query.ps1 prints them (one row per line, tab-separated, an empty field
# for NULL), read from ROWS-FILE; the build runs them on the MSI's tables, scripts/test-build-msi.sh on rows written
# by hand (--check-msi-rows, any OS).
#   upgrade VERSION UPGRADECODE  Upgrade (UpgradeCode, VersionMin, VersionMax, Attributes, ActionProperty): Tauri's
#        allowDowngrades false (P2-L2): every version up to this one, this one included, is upgraded (513: migrate
#        features + maximum inclusive: a same-version reinstall works, CP1/CP2), a newer one only detected (2: only
#        detect, minimum exclusive) into WIX_DOWNGRADE_DETECTED, which the launch condition refuses
#   launch     LaunchCondition (Condition, Description): NOT WIX_DOWNGRADE_DETECTED is one of them
#   lock       MsiLockPermissionsEx (LockObject, Table, SDDL, Condition): exactly INSTALLDIR's CreateFolder row with
#              INSTALLDIR_SDDL, unconditional
#   sequence   a sequence table (Action, Sequence, Condition): SetINSTALLDIR unconditional and before CostFinalize
#              (which resolves the folders); FindRelatedProducts before LaunchConditions
#   welcome    ControlEvent of WelcomeDlg's Next, NewDialog (Argument, Condition, Ordering): the last one, alone at
#              its Ordering, is VerifyReadyDlg with the condition 1 (no folder dialog)
check_msi_rows() { # WHAT, ROWS-FILE, [ARGS]
  local what="$1" text want got
  [ -f "$2" ] || die "$2 is missing"
  text="$(tr -d '\r' <"$2")"
  shift 2
  case "$what" in
    upgrade)
      [ $# = 2 ] || die "the upgrade gate needs VERSION UPGRADECODE"
      want="$(printf '%s\t\t%s\t513\tWIX_UPGRADE_DETECTED\n%s\t%s\t\t2\tWIX_DOWNGRADE_DETECTED\n' "$2" "$1" "$2" "$1" | LC_ALL=C sort)"
      got="$(LC_ALL=C sort <<<"$text")"
      [ "$got" = "$want" ] || die "the MSI's Upgrade table is '$got', expected '$want' (allowDowngrades false: a newer WinVPN is detected and refused, the same version is upgraded)"
      echo "  Upgrade: up to $1 inclusive upgraded (513), above $1 detected (2, WIX_DOWNGRADE_DETECTED)"
      ;;
    launch)
      awk -F'\t' '$1 == "NOT WIX_DOWNGRADE_DETECTED" { n++ } END { exit n == 1 ? 0 : 1 }' <<<"$text" \
        || die "the MSI has no launch condition NOT WIX_DOWNGRADE_DETECTED: an older WinVPN would install over a newer one"
      echo "  LaunchCondition: NOT WIX_DOWNGRADE_DETECTED"
      ;;
    lock)
      [ "$text" = "$(printf 'INSTALLDIR\tCreateFolder\t%s\t' "$INSTALLDIR_SDDL")" ] \
        || die "the MSI's MsiLockPermissionsEx is '$text', expected INSTALLDIR's CreateFolder row with $INSTALLDIR_SDDL"
      echo "  MsiLockPermissionsEx: INSTALLDIR $INSTALLDIR_SDDL"
      ;;
    sequence)
      got="$(awk -F'\t' '
        { seq[$1] = $2; cond[$1] = $3 }
        END {
          if (!("SetINSTALLDIR" in seq) || !("CostFinalize" in seq)) { print "SetINSTALLDIR or CostFinalize is missing"; exit 1 }
          if (cond["SetINSTALLDIR"] != "") { print "SetINSTALLDIR has the condition " cond["SetINSTALLDIR"]; exit 1 }
          if (seq["SetINSTALLDIR"] + 0 >= seq["CostFinalize"] + 0) { print "SetINSTALLDIR is not before CostFinalize"; exit 1 }
          if (!("FindRelatedProducts" in seq) || !("LaunchConditions" in seq)) { print "FindRelatedProducts or LaunchConditions is missing"; exit 1 }
          if (seq["FindRelatedProducts"] + 0 >= seq["LaunchConditions"] + 0) { print "FindRelatedProducts is not before LaunchConditions"; exit 1 }
        }' <<<"$text")" || die "the MSI's sequence: $got"
      echo "  SetINSTALLDIR unconditional before CostFinalize; FindRelatedProducts before LaunchConditions"
      ;;
    welcome)
      got="$(LC_ALL=C sort -t$'\t' -k3,3n <<<"$text")"
      # The last row by Ordering, and no other row at its Ordering.
      [ "$(tail -n 1 <<<"$got" | cut -f1,2)" = "$(printf 'VerifyReadyDlg\t1')" ] \
        && [ "$(cut -f3 <<<"$got" | grep -cx "$(tail -n 1 <<<"$got" | cut -f3)")" = 1 ] \
        || die "WelcomeDlg's Next does not end in VerifyReadyDlg: $(tr '\t\n' ' ;' <<<"$text") (the folder dialog must not be offered)"
      echo "  WelcomeDlg Next: VerifyReadyDlg (no folder dialog)"
      ;;
    *) die "unknown MSI table check: $what" ;;
  esac
}
if [ ${#CHECK_ROWS[@]} -gt 0 ]; then
  check_msi_rows "${CHECK_ROWS[@]}"
  exit 0
fi

if [ ${#FRAGMENT_ONLY[@]} -gt 0 ]; then
  render_service_wxs "${FRAGMENT_ONLY[@]}"
  wix_config "${FRAGMENT_ONLY[3]}"
  exit 0
fi

if [ -n "${WINVPN_WIX_DIR:-}" ] && [ "$CHECK_TOOLS" != 1 ]; then
  die "WINVPN_WIX_DIR is only for --check-tools: a build checks the folder the Tauri CLI runs the tools from"
fi
[ -n "${WINVPN_WIX_DIR:-}" ] || [ "$(uname -o 2>/dev/null)" = Msys ] || die "run this in Git Bash on Windows"
NO_ICE="${WINVPN_WIX_NO_ICE:-}"
if [ -n "${CI:-}" ] && [ -n "$NO_ICE" ]; then
  die "WINVPN_WIX_NO_ICE is not allowed in CI: the MSI is validated there"
fi

# The WiX 3.14.1.8722 tools the Tauri CLI (@tauri-apps/cli 2.12.3) downloads and runs (wix314-binaries.zip).
if [ -n "${WINVPN_WIX_DIR:-}" ]; then
  WIX="$WINVPN_WIX_DIR"
else
  WIX="$(cygpath -u "${LOCALAPPDATA:?}")/tauri/WixTools314"
fi
WIX_SHA256=(
  "candle.exe a464676e2a2191d58e6ca643e89505bfb9628d3e721873a14994d3f4667987e5"
  "light.exe 8ee3d7fa5592511152a4d1fc605780eae1b27ac7b41d75d518c958515de39529"
  "dark.exe a5717db404e5b7cf10c40272d3a206bbe39a579fdb1dd378ba20a0c7419078e7"
)
# candle.exe, light.exe and dark.exe must have exactly the pinned SHA-256s.
check_wix_tools() {
  local entry tool expected got
  for entry in "${WIX_SHA256[@]}"; do
    read -r tool expected <<<"$entry"
    [ -f "$WIX/$tool" ] || die "$WIX/$tool is missing"
    got="$(sha256sum "$WIX/$tool" | cut -d' ' -f1)"
    [ "$got" = "$expected" ] || die "$WIX/$tool has SHA-256 $got, expected $expected (delete the folder and build again)"
    echo "  $tool: $got"
  done
}

# Before anything runs: tools that are there already (an earlier build downloaded them) are checked now, so a
# replaced tool is never run by the Tauri CLI. A first build has none yet: the Tauri CLI downloads the zip and checks
# its SHA-256 itself, and the tools are checked after the build below.
step "WiX tools (before the build)"
if [ -d "$WIX" ]; then
  check_wix_tools
else
  echo "  not downloaded yet: the Tauri CLI downloads and checks them; checked after the build"
fi
[ "$CHECK_TOOLS" = 0 ] || exit 0

step "versions"
VERSION="$(node -p "require('./app/src-tauri/tauri.conf.json').version")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version in tauri.conf.json: $VERSION"
CARGO_VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
UI_VERSION="$(node -p "require('./app/ui/package.json').version")"
[ "$VERSION" = "$CARGO_VERSION" ] && [ "$VERSION" = "$UI_VERSION" ] \
  || die "versions differ: tauri.conf.json $VERSION, Cargo.toml $CARGO_VERSION, app/ui/package.json $UI_VERSION"
UPGRADE="$(node -p "require('./app/src-tauri/tauri.windows.conf.json').bundle.windows.wix.upgradeCode")"
[[ "$UPGRADE" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]] || die "invalid upgradeCode: $UPGRADE"
echo "  WinVPN $VERSION, UpgradeCode {$UPGRADE}, ${ARCHES[*]}"

step "environment"
# The vault's SQLCipher (libsqlite3-sys, bundled-sqlcipher-vendored-openssl on Windows) builds OpenSSL from
# openssl-src; an OPENSSL_* variable would make openssl-sys link a system OpenSSL instead (a DLL next to the exe).
for v in MACVPN_SANDBOX_HOME MACVPN_SMOKE_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS OPENSSL_DIR OPENSSL_LIB_DIR \
         OPENSSL_INCLUDE_DIR OPENSSL_STATIC OPENSSL_LIBS OPENSSL_NO_VENDOR SQLCIPHER_LIB_DIR SQLCIPHER_INCLUDE_DIR \
         X86_64_PC_WINDOWS_MSVC_OPENSSL_DIR AARCH64_PC_WINDOWS_MSVC_OPENSSL_DIR; do
  [ -z "${!v:-}" ] || die "$v is set: unset it for a release build"
done
export OPENSSL_SRC_PERL="${OPENSSL_SRC_PERL:-C:\\Strawberry\\perl\\bin\\perl.exe}"
for arch in "${ARCHES[@]}"; do
  case "$arch" in x64) t=x86_64-pc-windows-msvc ;; arm64) t=aarch64-pc-windows-msvc ;; esac
  rustup target list --installed | tr -d '\r' | grep -qx "$t" || die "missing Rust target $t (rustup target add $t)"
done

step "THIRD-PARTY-NOTICES.windows.txt"
[ -d app/ui/node_modules ] || (cd app/ui && npm ci --no-audit --no-fund)
node scripts/third-party-notices.mjs --os windows --check \
  || die "THIRD-PARTY-NOTICES.windows.txt is out of date (node scripts/third-party-notices.mjs --os windows)"

SIGN_CONFIG=()
if [ -n "${WINVPN_SIGN_THUMBPRINT:-}" ]; then
  [[ "$WINVPN_SIGN_THUMBPRINT" =~ ^[0-9A-Fa-f]{40}$ ]] || die "WINVPN_SIGN_THUMBPRINT: 40 hex digits"
  [[ "${WINVPN_SIGN_TIMESTAMP_URL:-}" =~ ^https?://[A-Za-z0-9./_-]+$ ]] || die "WINVPN_SIGN_TIMESTAMP_URL is needed for signing"
  SIGN_CONFIG=(--config "{\"bundle\":{\"windows\":{\"certificateThumbprint\":\"$WINVPN_SIGN_THUMBPRINT\",\"digestAlgorithm\":\"sha256\",\"timestampUrl\":\"$WINVPN_SIGN_TIMESTAMP_URL\"}}}")
  echo "  Authenticode: on ($WINVPN_SIGN_THUMBPRINT)"
else
  echo "  Authenticode: off (unsigned build)"
fi

step "UI (npm ci, npm run build)"
(cd app/ui && npm ci --no-audit --no-fund && npm run build)
[ -s app/ui/dist/index.html ] || die "app/ui/dist/index.html is missing"

# One SQL query on an MSI's tables (tab-separated rows).
msi_query() { # MSI, SQL
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w scripts/msi-query.ps1)" \
    "$(cygpath -w "$1")" "$2" | tr -d '\r'
}
# The value the query returns must be exactly the expected text.
msi_expect() { # MSI, what, SQL, expected
  local got
  got="$(msi_query "$1" "$3")" || die "the MSI's $2 could not be read"
  [ "$got" = "$4" ] || die "the MSI's $2 is '$got', expected '$4'"
  echo "  $2: $got"
}

# Strings only a debug WinVPN.exe has: the sandbox, the smoke run, the updater's local-MSI hook (2b plan, Task 18).
APP_DEBUG_MARKERS=(MACVPN_SANDBOX_HOME MACVPN_SMOKE --test-install-msi)

# The release gates on a WinVPN.exe: the one inside the MSI, as unpacked from it (what ships). Arguments: the exe,
# the architecture.
gate_exe() { # EXE, arch
  local arch="$2" MACHINE SUBSYSTEM marker OPENSSL_TEXT
  # The binary is built for this architecture (the COFF machine field: 0x8664 x64, 0xaa64 ARM64).
  MACHINE="$(node scripts/pe-imports.mjs --machine "$1")"
  case "$arch:$MACHINE" in x64:8664|arm64:aa64) ;; *) die "$1 is not an $arch binary (machine 0x$MACHINE)" ;; esac
  # A GUI program (subsystem 2, `windows_subsystem = "windows"` in main.rs): no console window opens with WinVPN.
  SUBSYSTEM="$(node scripts/pe-imports.mjs --subsystem "$1")"
  [ "$SUBSYSTEM" = 2 ] || die "$1 is not a Windows GUI program (PE subsystem $SUBSYSTEM, expected 2)"

  step "release gate: no debug-only code ($arch)"
  for marker in "${APP_DEBUG_MARKERS[@]}"; do
    if LC_ALL=C grep -a -q -F -e "$marker" "$1"; then die "the release binary contains '$marker'"; fi
  done

  step "release gate: SQLCipher with the vendored OpenSSL, linked statically ($arch)"
  # "SQLite format" marks the linked SQLite; the OpenSSL version text is compiled into libcrypto; SQLCipher names
  # its provider ("openssl", never "commoncrypto" on Windows); no DLL of a crypto library or of SQLite is imported.
  LC_ALL=C grep -a -q -F 'SQLite format' "$1" || die "$1 contains no SQLCipher"
  OPENSSL_TEXT="$(LC_ALL=C grep -a -o -m 1 -E 'OpenSSL 3\.[0-9]+\.[0-9]+' "$1" | head -n 1)" \
    || die "$1 contains no vendored OpenSSL 3"
  if LC_ALL=C grep -a -q -F commoncrypto "$1"; then die "$1 names the CommonCrypto provider"; fi
  node scripts/pe-imports.mjs "$1" >"$OUT/imports-$arch.txt"
  if grep -E '^(libcrypto|libssl|ssleay|libeay|sqlite|sqlcipher)' "$OUT/imports-$arch.txt"; then
    die "$1 imports a crypto or SQLite DLL"
  fi
  grep -qx kernel32.dll "$OUT/imports-$arch.txt" || die "$1: the import table could not be read"
  echo "  SQLCipher with $OPENSSL_TEXT, imports: $(tr '\n' ' ' <"$OUT/imports-$arch.txt")"
}

# The DLLs WinVPNService.exe imports (pe-imports.mjs: normal and delay-loaded, lower case), exactly, for both
# architectures: pinned from the first 2b build (Task 15, 2026-10-22). A new import is a review question, not a
# silent change. Beyond the system DLLs of the plan's list: Rust std's bcryptprimitives.dll (ProcessPrng),
# combase.dll (CoTaskMemFree for SHGetKnownFolderPath) and the Universal CRT (api-ms-win-crt-*, part of Windows),
# as WinVPN.exe has them; never vcruntime140.dll (Windows does not ship it: crates/helper/build.rs links the VC
# runtime statically, as tauri-build does for WinVPN.exe), no crypto library, no SQLite, nothing WinVPN ships.
SERVICE_IMPORTS=(
  advapi32.dll
  api-ms-win-core-synch-l1-2-0.dll
  api-ms-win-crt-heap-l1-1-0.dll
  api-ms-win-crt-locale-l1-1-0.dll
  api-ms-win-crt-math-l1-1-0.dll
  api-ms-win-crt-runtime-l1-1-0.dll
  api-ms-win-crt-stdio-l1-1-0.dll
  api-ms-win-crt-string-l1-1-0.dll
  bcrypt.dll
  bcryptprimitives.dll
  combase.dll
  crypt32.dll
  iphlpapi.dll
  kernel32.dll
  ntdll.dll
  rasapi32.dll
  shell32.dll
  version.dll
  wintrust.dll
  ws2_32.dll
  wtsapi32.dll
)
# Strings only the debug build of the service has (the test console, its options and pipe prefix, the fake
# engines, the installed-OpenVPN probe) and the app's debug-only variables: none may be in a release service.
SERVICE_DEBUG_MARKERS=(MACVPN_SANDBOX_HOME MACVPN_SMOKE --fake-engine --fake-openvpn --existing-data --wireguard-dll
  --wireguard-updates --wireguard-floor WinVPN-test- console-detect winvpn-fake)

# The release gates on a WinVPNService.exe (the built one, then the one unpacked from the MSI). Arguments: the
# exe, the architecture.
gate_service_exe() { # EXE, arch
  local arch="$2" MACHINE SUBSYSTEM marker got want
  MACHINE="$(node scripts/pe-imports.mjs --machine "$1")"
  case "$arch:$MACHINE" in x64:8664|arm64:aa64) ;; *) die "$1 is not an $arch binary (machine 0x$MACHINE)" ;; esac
  # A console program (subsystem 3): a service has no window, and the SCM starts it without a console.
  SUBSYSTEM="$(node scripts/pe-imports.mjs --subsystem "$1")"
  [ "$SUBSYSTEM" = 3 ] || die "$1 is not a console program (PE subsystem $SUBSYSTEM, expected 3)"
  for marker in "${SERVICE_DEBUG_MARKERS[@]}"; do
    if LC_ALL=C grep -a -q -F -e "$marker" "$1"; then die "the service binary $1 contains '$marker' (debug-only)"; fi
  done
  # The helper never links core's vault (SQLite); no crypto or SQLite DLL either.
  if LC_ALL=C grep -a -q -F 'SQLite format' "$1"; then die "the service binary $1 contains SQLite"; fi
  got="$(node scripts/pe-imports.mjs "$1" | tr -d '\r')"
  [ -n "$got" ] || die "$1: the import table could not be read"
  want="$(printf '%s\n' "${SERVICE_IMPORTS[@]}")"
  [ "$got" = "$want" ] || die "$1 imports $(tr '\n' ' ' <<<"$got"), pinned: $(tr '\n' ' ' <<<"$want")"
  echo "  WinVPNService.exe ($arch): machine 0x$MACHINE, console subsystem, no debug-only code, no SQLite, imports: $(tr '\n' ' ' <<<"$got")"
}

# wireguard.dll: the pinned SHA-256 of its architecture and a valid Authenticode signature by the pinned signer.
WG_PINS=scripts/pins/wireguard-nt.txt
wg_pin() { # key
  awk -F'\t' -v k="$1" '$1 == k { print $2; n++ } END { if (n != 1) exit 1 }' "$WG_PINS" \
    || die "$WG_PINS: $1 must be there exactly once"
}
gate_wireguard_dll() { # DLL, arch
  local key want got sig
  case "$2" in x64) key=dll_amd64_sha256 ;; arm64) key=dll_arm64_sha256 ;; esac
  want="$(wg_pin "$key")"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "$WG_PINS: $key is not a SHA-256"
  [ -f "$1" ] || die "$1 is missing"
  got="$(sha256sum "$1" | cut -d' ' -f1)"
  [ "$got" = "$want" ] || die "$1 has SHA-256 $got, the pin ($key) is $want"
  sig="$(powershell.exe -NoProfile -NonInteractive -Command \
    "\$s = Get-AuthenticodeSignature -LiteralPath '$(cygpath -w "$1")'; \$s.Status; \$s.SignerCertificate.GetNameInfo('SimpleName', \$false)" |
    tr -d '\r')" || die "cannot read the signature of $1"
  [ "$(sed -n 1p <<<"$sig")" = Valid ] || die "$1: the Authenticode signature is not valid ($(sed -n 1p <<<"$sig"))"
  [ "$(sed -n 2p <<<"$sig")" = "$(wg_pin signer)" ] || die "$1 is signed by '$(sed -n 2p <<<"$sig")', the pin is '$(wg_pin signer)'"
  echo "  wireguard.dll ($2): SHA-256 $got (pinned), Authenticode Valid, $(wg_pin signer)"
}

# The WebView2 bootstrapper the MSI carries (its Binary table, as dark.exe unpacks it; P2-L1): Microsoft's, by a
# valid Authenticode signature whose signer is Microsoft Corporation. Not pinned by hash: the Tauri CLI downloads
# Microsoft's current one at build time (go.microsoft.com/fwlink/p/?LinkId=2124703), and Microsoft re-signs it.
gate_webview2_bootstrapper() { # EXE
  local sig
  [ -f "$1" ] || die "the MSI has no WebView2 bootstrapper ($1)"
  [ "$(head -c 2 "$1")" = MZ ] || die "$1 is not a Windows program"
  sig="$(powershell.exe -NoProfile -NonInteractive -Command \
    "\$s = Get-AuthenticodeSignature -LiteralPath '$(cygpath -w "$1")'; \$s.Status; \$s.SignerCertificate.GetNameInfo('SimpleName', \$false)" |
    tr -d '\r')" || die "cannot read the signature of $1"
  [ "$(sed -n 1p <<<"$sig")" = Valid ] || die "$1: the Authenticode signature is not valid ($(sed -n 1p <<<"$sig"))"
  [ "$(sed -n 2p <<<"$sig")" = "Microsoft Corporation" ] || die "$1 is signed by '$(sed -n 2p <<<"$sig")', not Microsoft Corporation"
  echo "  MicrosoftEdgeWebview2Setup.exe: Authenticode Valid, Microsoft Corporation, SHA-256 $(sha256sum "$1" | cut -d' ' -f1)"
}

step "wireguard-nt $(wg_pin version) (scripts/fetch-wireguard-nt.sh)"
scripts/fetch-wireguard-nt.sh || die "wireguard-nt does not match its pins"

OUT=dist/windows
rm -rf "$OUT"
mkdir -p "$OUT"
for arch in "${ARCHES[@]}"; do
  case "$arch" in
    x64) TARGET=x86_64-pc-windows-msvc ;;
    arm64) TARGET=aarch64-pc-windows-msvc ;;
  esac
  step "build $arch ($TARGET)"
  BUNDLE="target/$TARGET/release/bundle/msi"
  WIXOBJ="target/$TARGET/release/wix/$arch"
  rm -rf "$BUNDLE" "$WIXOBJ"

  step "the WinVPN Service ($arch)"
  cargo build --release --locked -p macvpn-helper --bin mvpn --target "$TARGET"
  SERVICE_EXE="target/$TARGET/release/mvpn.exe"
  [ -f "$SERVICE_EXE" ] || die "$SERVICE_EXE is missing"
  case "$arch" in x64) WG_DLL=target/wireguard-nt/bin/amd64/wireguard.dll ;; arm64) WG_DLL=target/wireguard-nt/bin/arm64/wireguard.dll ;; esac
  # The fragment's sources are copies made here and gated here: what the MSI packs is what passed.
  FRAG_DIR="target/winvpn-wix/$arch"
  rm -rf "$FRAG_DIR"
  mkdir -p "$FRAG_DIR/files"
  cp "$SERVICE_EXE" "$FRAG_DIR/files/WinVPNService.exe"
  cp "$WG_DLL" "$FRAG_DIR/files/wireguard.dll"
  gate_service_exe "$FRAG_DIR/files/WinVPNService.exe" "$arch"
  gate_wireguard_dll "$FRAG_DIR/files/wireguard.dll" "$arch"
  render_service_wxs app/src-tauri/wix/service.wxs.in "$(cygpath -w "$PWD/$FRAG_DIR/files/WinVPNService.exe")" \
    "$(cygpath -w "$PWD/$FRAG_DIR/files/wireguard.dll")" "$FRAG_DIR/service.wxs"
  WIX_CONFIG="$(wix_config "$(cygpath -w "$PWD/$FRAG_DIR/service.wxs")")"
  echo "  $FRAG_DIR/service.wxs; --config $WIX_CONFIG"
  # The UI is built above; the Tauri CLI must not build it again. The npm script `tauri` sets its paths with the
  # POSIX `VAR=value` syntax, which npm's cmd.exe does not understand: the same variables are set here.
  status=0
  (cd app/ui && TAURI_APP_PATH=../src-tauri TAURI_FRONTEND_PATH=. npx --no-install tauri build --ci \
    --target "$TARGET" --bundles msi --features custom-protocol \
    --config '{"build":{"beforeBuildCommand":""}}' --config "$WIX_CONFIG" "${SIGN_CONFIG[@]}") || status=$?
  # The Tauri CLI writes the binary under mainBinaryName next to cargo's macvpn-app.exe.
  EXE="target/$TARGET/release/WinVPN.exe"
  [ -f "$EXE" ] || die "$EXE is missing"

  step "WiX tools (after the build)"
  check_wix_tools

  if [ "$status" != 0 ]; then
    [ -n "$NO_ICE" ] || die "tauri build failed ($status)"
    # Only the link step may have failed: both objects of this run are there (the folder was emptied above).
    [ -f "$WIXOBJ/main.wixobj" ] && [ -f "$WIXOBJ/file-associations.wixobj" ] && [ -f "$WIXOBJ/service.wixobj" ] \
      && [ -f "$WIXOBJ/locale.wxl" ] \
      || die "tauri build failed ($status) before WiX's link step"
    step "MSI link without ICE validation ($arch, WINVPN_WIX_NO_ICE=1)"
    echo "  SKIPPED: ICE validation (the Windows Installer service cannot be reached here; CI validates)"
    mkdir -p "$BUNDLE"
    # The arguments of the Tauri CLI's own light.exe call, plus -sval.
    (cd "$WIXOBJ" && MSYS2_ARG_CONV_EXCL='*' "$WIX/light.exe" -nologo -sval -ext WixUIExtension -ext WixUtilExtension \
      -o "$(cygpath -w "$OLDPWD/$BUNDLE")\\WinVPN_${VERSION}_${arch}_en-US.msi" -cultures:en-us -loc locale.wxl \
      main.wixobj file-associations.wixobj service.wixobj) || die "light.exe failed"
  fi

  step "MSI ($arch)"
  shopt -s nullglob
  BUILT=(target/"$TARGET"/release/bundle/msi/WinVPN_"$VERSION"_*.msi)
  shopt -u nullglob
  [ ${#BUILT[@]} -eq 1 ] || die "expected one MSI for $arch, found ${#BUILT[@]}"
  MSI="$OUT/WinVPN-$VERSION-$arch.msi"
  cp "${BUILT[0]}" "$MSI"
  msi_expect "$MSI" ProductName "SELECT \`Value\` FROM \`Property\` WHERE \`Property\`='ProductName'" WinVPN
  msi_expect "$MSI" ProductVersion "SELECT \`Value\` FROM \`Property\` WHERE \`Property\`='ProductVersion'" "$VERSION"
  msi_expect "$MSI" UpgradeCode "SELECT \`Value\` FROM \`Property\` WHERE \`Property\`='UpgradeCode'" "{$UPGRADE}"
  # The Start-menu shortcut: WinVPN.exe, with the AppUserModelID that WinVPN's toasts are sent under.
  msi_expect "$MSI" "Start-menu shortcut" \
    "SELECT \`Shortcut\`.\`Name\`, \`Shortcut\`.\`Target\` FROM \`Shortcut\`, \`Directory\` WHERE \`Shortcut\`.\`Directory_\`=\`Directory\`.\`Directory\` AND \`Directory\`.\`Directory_Parent\`='ProgramMenuFolder'" \
    "$(printf 'WinVPN\t[!Path]')"
  msi_expect "$MSI" "the shortcut's AppUserModelID" \
    "SELECT \`PropVariantValue\` FROM \`MsiShortcutProperty\` WHERE \`PropertyKey\`='System.AppUserModel.ID'" local.winvpn
  # Default handler (advertised): the extension's ProgId WinVPN.<ext>, served by WinVPN.exe's component, whose
  # open verb passes the file. No other extension.
  msi_expect "$MSI" "default associations" \
    "SELECT \`Extension\`.\`Extension\`, \`Extension\`.\`ProgId_\`, \`File\`.\`FileName\`, \`Verb\`.\`Verb\`, \`Verb\`.\`Argument\` FROM \`Extension\`, \`File\`, \`Verb\` WHERE \`Extension\`.\`Component_\`=\`File\`.\`Component_\` AND \`Verb\`.\`Extension_\`=\`Extension\`.\`Extension\`" \
    "$(printf '%s\t%s\tWinVPN.exe\topen\t"%%1"\n' ovpn WinVPN.ovpn sstp WinVPN.sstp macvpncatalog WinVPN.macvpncatalog)"
  msi_expect "$MSI" "extensions" "SELECT \`Extension\` FROM \`Extension\`" "$(printf 'ovpn\nsstp\nmacvpncatalog')"
  # .conf: listed under "Open with" only (HKLM\Software\Classes\.conf\OpenWithProgids, value WinVPN.conf, its ProgId
  # opening WinVPN.exe "%1"); never the default value of .conf (another app's file type), in no root.
  REGISTRY="$(msi_query "$MSI" "SELECT \`Root\`, \`Key\`, \`Name\`, \`Value\` FROM \`Registry\`")" || die "the MSI's Registry table could not be read"
  conf="$(awk -F'\t' 'tolower($2) ~ /(^|\\)\.conf(\\|$)/' <<<"$REGISTRY")"
  [ "$conf" = "$(printf '2\tSoftware\\Classes\\.conf\\OpenWithProgids\tWinVPN.conf\t')" ] \
    || die "the MSI's .conf entries are not exactly the Open with entry: $conf"
  [ "$(awk -F'\t' '$2 == "Software\\Classes\\WinVPN.conf\\shell\\open\\command" { print $1 "\t" $4 }' <<<"$REGISTRY")" \
    = "$(printf '2\t"[INSTALLDIR]WinVPN.exe" "%%1"')" ] || die "the MSI's WinVPN.conf ProgId does not open WinVPN.exe"
  echo "  .conf: Open with only"
  # Admin key files, backups and .mobileconfig profiles are opened from their panels only.
  if grep -Eiq 'macvpnadminkey|macvpnbackup|mobileconfig' <<<"$REGISTRY"; then
    die "the MSI claims an admin key file, a backup or a .mobileconfig profile"
  fi

  step "MSI: the WinVPN Service ($arch)"
  # Own process (16), automatic start (2), error control normal (1) marked vital (0x8000: a failed install of the
  # service fails the whole install), LocalSystem without a password, the argument `service` (Windows Installer
  # registers the image path as the quoted path of the component's key file, WinVPNService.exe, then the
  # arguments).
  msi_expect "$MSI" "ServiceInstall" \
    "SELECT \`Name\`, \`DisplayName\`, \`ServiceType\`, \`StartType\`, \`ErrorControl\`, \`StartName\`, \`Password\`, \`Arguments\`, \`Component_\`, \`Dependencies\` FROM \`ServiceInstall\`" \
    "$(printf 'WinVPN\tWinVPN Service\t16\t2\t32769\tLocalSystem\t\tservice\tWinVPNServiceExe\t')"
  # Start on install (1), stop on install (2: an upgrade or repair replaces the running exe), stop (32) and delete
  # (128) on uninstall = 163; wait for each.
  msi_expect "$MSI" "ServiceControl" \
    "SELECT \`Name\`, \`Event\`, \`Arguments\`, \`Wait\`, \`Component_\` FROM \`ServiceControl\`" \
    "$(printf 'WinVPN\t163\t\t1\tWinVPNServiceExe')"
  # No failure actions in the MSI: Windows Installer's MsiServiceConfigFailureActions opens the service without
  # SERVICE_START, which ChangeServiceConfig2 needs for a restart action, so the install fails and rolls back with
  # error 1939 ("could not be configured", access denied). The service sets its own recovery at every start
  # (crates/helper/src/windows/recovery.rs). The table may exist only empty.
  fa_table="$(msi_query "$MSI" "SELECT \`Name\` FROM \`_Tables\` WHERE \`Name\`='MsiServiceConfigFailureActions'")" \
    || die "the MSI's table list could not be read"
  if [ -n "$fa_table" ]; then
    fa_rows="$(msi_query "$MSI" "SELECT \`Name\`, \`Actions\` FROM \`MsiServiceConfigFailureActions\`")" \
      || die "the MSI's MsiServiceConfigFailureActions table could not be read"
    [ -z "$fa_rows" ] || die "the MSI has failure actions (MsiServiceConfigFailureActions: '$fa_rows'): a restart action makes the install fail with error 1939; the service sets its own recovery (remove ServiceConfigFailureActions from app/src-tauri/wix/service.wxs.in)"
  fi
  echo "  failure actions: none in the MSI (the service sets its own)"
  # Both files in the install directory (admin-only, next to WinVPN.exe), each the key path of its own component
  # (the long file names; WiX makes up the short ones).
  got="$(msi_query "$MSI" "SELECT \`Component\`.\`Component\`, \`Component\`.\`Directory_\`, \`Component\`.\`KeyPath\`, \`File\`.\`FileName\` FROM \`Component\`, \`File\` WHERE \`File\`.\`Component_\`=\`Component\`.\`Component\` AND (\`Component\`.\`Component\`='WinVPNServiceExe' OR \`Component\`.\`Component\`='WireGuardDll')" \
    | awk -F'\t' '{ n = $4; sub(/^[^|]*\|/, "", n); print $1 "\t" $2 "\t" $3 "\t" n }' | LC_ALL=C sort)" \
    || die "the MSI's service components could not be read"
  [ "$got" = "$(printf 'WinVPNServiceExe\tINSTALLDIR\tWinVPNServiceExe\tWinVPNService.exe\nWireGuardDll\tINSTALLDIR\tWireGuardDll\twireguard.dll')" ] \
    || die "the MSI's service components are '$got'"
  echo "  WinVPNService.exe and wireguard.dll: INSTALLDIR, each its component's key path"
  # Custom actions: exactly the ones the Tauri template brings with this configuration, plus the service fragment's
  # SetINSTALLDIR (51: the install folder pinned to Program Files, P2-M2). LaunchApplication (210: the installed
  # WinVPN.exe, file key Path, after the install when the user ticks it); WixUIValidatePath and WixUIPrintEula (65:
  # WiX's UI DLL from the MSI's Binary table; WixUI_InstallDir's, the folder dialog itself is never shown, see the
  # welcome gate below); Tauri's two property setters (51); InvokeBootstrapper (1026: deferred, an exe from the
  # Binary table, which Windows Installer extracts into its own folder; webviewInstallMode embedBootstrapper, P2-L1:
  # nothing is downloaded into the user's %TEMP% and run from there, no PowerShell; it runs only when no WebView2 is
  # installed).
  got="$(msi_query "$MSI" "SELECT \`Action\`, \`Type\`, \`Source\` FROM \`CustomAction\`" | LC_ALL=C sort)" \
    || die "the MSI's CustomAction table could not be read"
  want="$(printf '%s\t%s\t%s\n' LaunchApplication 210 Path WixUIValidatePath 65 WixUIWixca WixUIPrintEula 65 WixUIWixca \
    SetARPNOMODIFY 51 ARPNOMODIFY InvokeBootstrapper 1026 MicrosoftEdgeWebview2Setup.exe \
    SetARPINSTALLLOCATION 51 ARPINSTALLLOCATION SetINSTALLDIR 51 INSTALLDIR | LC_ALL=C sort)"
  [ "$got" = "$want" ] || die "the MSI's custom actions are '$got', expected '$want'"
  echo "  custom actions: $(cut -f1 <<<"$got" | tr '\n' ' ')"
  msi_expect "$MSI" "the install folder's pin" \
    "SELECT \`Target\` FROM \`CustomAction\` WHERE \`Action\`='SetINSTALLDIR'" "[ProgramFiles64Folder]WinVPN\\"
  msi_expect "$MSI" "the WebView2 bootstrapper's command" \
    "SELECT \`Target\` FROM \`CustomAction\` WHERE \`Action\`='InvokeBootstrapper'" '/silent /install'

  step "MSI: the install folder ($arch)"
  # Pinned to <Program Files>\WinVPN before the folders are resolved, in both sequences; no folder dialog; the
  # folder's protected ACL; never the name-based LockPermissions (error 1609 on a localized Windows).
  for table in InstallUISequence InstallExecuteSequence; do
    msi_query "$MSI" "SELECT \`Action\`, \`Sequence\`, \`Condition\` FROM \`$table\`" >"$OUT/rows-$arch.txt" \
      || die "the MSI's $table could not be read"
    echo "  $table:"
    check_msi_rows sequence "$OUT/rows-$arch.txt"
  done
  msi_query "$MSI" "SELECT \`Argument\`, \`Condition\`, \`Ordering\` FROM \`ControlEvent\` WHERE \`Dialog_\`='WelcomeDlg' AND \`Control_\`='Next' AND \`Event\`='NewDialog'" \
    >"$OUT/rows-$arch.txt" || die "the MSI's ControlEvent table could not be read"
  check_msi_rows welcome "$OUT/rows-$arch.txt"
  # SELECT * (Windows Installer refuses the column list here): the key column dropped.
  msi_query "$MSI" "SELECT * FROM \`MsiLockPermissionsEx\`" | cut -f2- >"$OUT/rows-$arch.txt" \
    || die "the MSI's MsiLockPermissionsEx table could not be read"
  check_msi_rows lock "$OUT/rows-$arch.txt"
  lp_table="$(msi_query "$MSI" "SELECT \`Name\` FROM \`_Tables\` WHERE \`Name\`='LockPermissions'")" \
    || die "the MSI's table list could not be read"
  if [ -n "$lp_table" ]; then
    [ -z "$(msi_query "$MSI" "SELECT \`LockObject\` FROM \`LockPermissions\`")" ] \
      || die "the MSI has LockPermissions rows: account names fail on a localized Windows (use PermissionEx's SDDL)"
  fi
  echo "  LockPermissions: none"

  step "MSI: no downgrade ($arch)"
  msi_query "$MSI" "SELECT \`UpgradeCode\`, \`VersionMin\`, \`VersionMax\`, \`Attributes\`, \`ActionProperty\` FROM \`Upgrade\`" \
    >"$OUT/rows-$arch.txt" || die "the MSI's Upgrade table could not be read"
  check_msi_rows upgrade "$OUT/rows-$arch.txt" "$VERSION" "{$UPGRADE}"
  msi_query "$MSI" "SELECT \`Condition\`, \`Description\` FROM \`LaunchCondition\`" >"$OUT/rows-$arch.txt" \
    || die "the MSI's LaunchCondition table could not be read"
  check_msi_rows launch "$OUT/rows-$arch.txt"
  rm -f "$OUT/rows-$arch.txt"

  step "MSI contents ($arch)"
  # dark.exe -x unpacks every file stream as File/<File key>; the File, Component and Directory tables say where it
  # installs (the long target names, as an administrative image lays them out: PFiles/WinVPN/WinVPN.exe).
  DARK="$OUT/dark-$arch"
  EXTRACT="$OUT/extract-$arch"
  rm -rf "$DARK" "$EXTRACT"
  mkdir -p "$DARK" "$EXTRACT"
  MSYS2_ARG_CONV_EXCL='*' "$WIX/dark.exe" -nologo -sw1059 -x "$(cygpath -w "$DARK")" "$(cygpath -w "$MSI")" \
    "$(cygpath -w "$DARK/decompiled.wxs")" >/dev/null || die "dark.exe could not unpack the $arch MSI"
  declare -A PARENT=() DIRNAME=() COMPDIR=()
  long_name() { local n="${1%%:*}"; echo "${n##*|}"; }
  while IFS=$'\t' read -r dir parent default; do
    PARENT[$dir]="$parent"
    DIRNAME[$dir]="$(long_name "$default")"
  done < <(msi_query "$MSI" "SELECT \`Directory\`, \`Directory_Parent\`, \`DefaultDir\` FROM \`Directory\`")
  while IFS=$'\t' read -r component dir; do COMPDIR[$component]="$dir"; done \
    < <(msi_query "$MSI" "SELECT \`Component\`, \`Directory_\` FROM \`Component\`")
  dir_path() { # Directory key → its path below TARGETDIR (SourceDir and "." add nothing)
    local d="$1" path=""
    while [ -n "$d" ] && [ "$d" != TARGETDIR ]; do
      [ -n "${DIRNAME[$d]+x}" ] || die "the MSI's Directory table has no $d"
      case "${DIRNAME[$d]}" in .|SourceDir) ;; *) path="${DIRNAME[$d]}/$path" ;; esac
      d="${PARENT[$d]}"
    done
    echo "$path"
  }
  while IFS=$'\t' read -r key name component; do
    [ -f "$DARK/File/$key" ] || die "the MSI's file $key was not unpacked"
    dest="$EXTRACT/$(dir_path "${COMPDIR[$component]}")$(long_name "$name")"
    mkdir -p "$(dirname "$dest")"
    cp "$DARK/File/$key" "$dest"
  done < <(msi_query "$MSI" "SELECT \`File\`, \`FileName\`, \`Component_\` FROM \`File\`")
  (cd "$EXTRACT" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) >"$OUT/files-$arch.txt"
  if [ "$WRITE_BASELINE" = 1 ] && [ "$arch" = x64 ]; then
    cp "$OUT/files-$arch.txt" scripts/bundle-baseline/winvpn-msi-files.txt
    echo "  wrote scripts/bundle-baseline/winvpn-msi-files.txt: review it before committing"
  fi
  diff -u scripts/bundle-baseline/winvpn-msi-files.txt "$OUT/files-$arch.txt" || die "unexpected files in the $arch MSI"
  NOTICES="$(grep -m 1 '/THIRD-PARTY-NOTICES.txt$' "$OUT/files-$arch.txt")" || die "the MSI has no THIRD-PARTY-NOTICES.txt"
  cmp -s "$EXTRACT/$NOTICES" THIRD-PARTY-NOTICES.windows.txt || die "the MSI's notices differ from THIRD-PARTY-NOTICES.windows.txt"
  EXE_IN_MSI="$(grep -m 1 '/WinVPN.exe$' "$OUT/files-$arch.txt")" || die "the MSI has no WinVPN.exe"
  # The service and the DLL that ship: the gates again, and byte for byte the files gated before the build (Tauri
  # does not patch fragment files), which are cargo's mvpn.exe and the pinned DLL.
  SERVICE_IN_MSI="$(grep -m 1 '/WinVPNService.exe$' "$OUT/files-$arch.txt")" || die "the MSI has no WinVPNService.exe"
  DLL_IN_MSI="$(grep -m 1 '/wireguard.dll$' "$OUT/files-$arch.txt")" || die "the MSI has no wireguard.dll"
  [ "$(dirname "$SERVICE_IN_MSI")" = "$(dirname "$EXE_IN_MSI")" ] && [ "$(dirname "$DLL_IN_MSI")" = "$(dirname "$EXE_IN_MSI")" ] \
    || die "WinVPNService.exe and wireguard.dll are not next to WinVPN.exe"
  gate_service_exe "$EXTRACT/$SERVICE_IN_MSI" "$arch"
  gate_wireguard_dll "$EXTRACT/$DLL_IN_MSI" "$arch"
  cmp -s "$EXTRACT/$SERVICE_IN_MSI" "$SERVICE_EXE" || die "the MSI's WinVPNService.exe is not the built $SERVICE_EXE"
  cmp -s "$EXTRACT/$SERVICE_IN_MSI" "$FRAG_DIR/files/WinVPNService.exe" || die "the MSI's WinVPNService.exe is not the gated copy"
  cmp -s "$EXTRACT/$DLL_IN_MSI" "$WG_DLL" || die "the MSI's wireguard.dll is not the pinned $WG_DLL"
  echo "  WinVPNService.exe: the built $SERVICE_EXE; wireguard.dll: the pinned one"
  gate_webview2_bootstrapper "$DARK/Binary/MicrosoftEdgeWebview2Setup.exe"
  gate_exe "$EXTRACT/$EXE_IN_MSI" "$arch"
  # The exe in the MSI is the one cargo built but for the bundle-type marker: before bundling, the Tauri bundler
  # patches the target exe in place (tauri-utils' static __TAURI_BUNDLE_TYPE, read by
  # tauri::utils::platform::bundle_type(): "__TAURI_BUNDLE_TYPE_VAR_UNK" becomes "__TAURI_BUNDLE_TYPE_VAR_MSI"), and
  # after a successful bundle copies the unpatched original back (tauri-bundler's bundle_project). So with ICE
  # validation (CI) the target exe has the UNK marker and the MSI's the MSI one; without (WINVPN_WIX_NO_ICE: the
  # Tauri CLI failed at the link, before the restore) both are patched and equal. Strict: the same length, the
  # MSI's exe without the UNK marker, and equal to the target exe once its one UNK marker (if any) reads MSI.
  # A signed build is not compared byte for byte: Tauri signs only the patched copy it bundles and restores the
  # unsigned original; the gates above ran on the exe that ships.
  if [ -z "${WINVPN_SIGN_THUMBPRINT:-}" ]; then
    node -e '
      const fs = require("fs");
      const [shipped, built] = process.argv.slice(1).map((f) => fs.readFileSync(f));
      const unk = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_UNK"), msi = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_MSI");
      const fail = (m) => { console.error(m); process.exit(1); };
      if (shipped.length !== built.length) fail(`${shipped.length} bytes in the MSI, ${built.length} built`);
      if (shipped.includes(unk)) fail("the exe in the MSI is not marked as an MSI bundle");
      const at = built.indexOf(unk);
      if (at >= 0 && built.lastIndexOf(unk) !== at) fail("the built exe has more than one bundle-type marker");
      const patched = Buffer.from(built);
      if (at >= 0) msi.copy(patched, at);
      if (!patched.equals(shipped)) fail("bytes other than the bundle-type marker differ");
      console.log(`  WinVPN.exe: the built exe${at >= 0 ? " with the MSI bundle-type marker" : " (already marked)"}`);
    ' "$EXTRACT/$EXE_IN_MSI" "$EXE" || die "the MSI's WinVPN.exe is not the built $EXE (but for Tauri's bundle-type marker)"
  else
    echo "  signed build: the MSI's WinVPN.exe is not compared byte for byte with $EXE (Tauri signs only its copy)"
  fi
  echo "  $(tr '\n' ' ' <"$OUT/files-$arch.txt")"
  rm -rf "$DARK" "$EXTRACT"

  (cd "$OUT" && sha256sum "WinVPN-$VERSION-$arch.msi" >"WinVPN-$VERSION-$arch.msi.sha256")
  cat "$OUT/WinVPN-$VERSION-$arch.msi.sha256"
done
echo
echo "OK: $(ls "$OUT"/*.msi | tr '\n' ' ')"
