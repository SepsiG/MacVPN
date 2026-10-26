#!/bin/bash
# Tests the WiX tool check of scripts/build-msi.sh without building (runs on macOS and in Git Bash): with
# --check-tools and WINVPN_WIX_DIR pointing at a copy, a replaced or missing tool fails before anything runs, and a
# folder that does not exist yet (a first build) passes. Also checks that a build checks the tools before
# `tauri build` runs and again after it; the WinVPN Service's fragment (--service-fragment: the rendering, its
# refusals, the config JSON), the committed template's service settings (no failure actions), the gate that keeps
# MsiServiceConfigFailureActions out of the MSI, pe-imports.mjs' --machine and --subsystem, that the service exe and
# wireguard.dll are gated before and after `tauri build`, and the app gate's debug markers (the updater's
# --test-install-msi). Security review part 2: the template's install-folder pin, dialog skip and SDDL (P2-M2), and
# the MSI table gates (--check-msi-rows: Upgrade and LaunchCondition for P2-L2, MsiLockPermissionsEx, the sequences
# and WelcomeDlg's NewDialog for P2-M2) on good and bad rows; the custom-action pin of the embedded WebView2
# bootstrapper and its signature gate (P2-L1).
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/build-msi.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks_step() { ! grep -qE "==> ($2)" <<<"$1"; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
  # build-msi.sh's own findings are not this test's subject (its node -e snippets are single-quoted on purpose).
  check "shellcheck" shellcheck "$0"
else
  echo "skip - shellcheck is not installed"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/test-build-msi.XXXXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT
run() { WINVPN_WIX_DIR="$1" "$SCRIPT" --check-tools 2>&1; }

# A tool that is not the pinned one (a modified copy): refused, nothing else runs.
mkdir "$WORK/wix"
for tool in candle.exe light.exe dark.exe; do printf 'not %s\n' "$tool" >"$WORK/wix/$tool"; done
status=0; out="$(run "$WORK/wix")" || status=$?
check "a modified tool fails" test "$status" != 0
check "it names the tool and its hash" has "$out" "candle.exe has SHA-256 $(sha256sum "$WORK/wix/candle.exe" | cut -d' ' -f1)"
check "it fails before the build" lacks_step "$out" "versions|build"

# A folder with a tool missing: refused.
rm "$WORK/wix/candle.exe"
status=0; out="$(run "$WORK/wix")" || status=$?
check "a missing tool fails" test "$status" != 0
check "it says which" has "$out" "candle.exe is missing"

# No folder yet (a first build): the Tauri CLI downloads and checks the zip; passes.
status=0; out="$(run "$WORK/none")" || status=$?
check "no folder yet passes" test "$status" = 0
check "it says the tools are checked after the build" has "$out" "checked after the build"

# WINVPN_WIX_DIR is refused for a real build (it would check a folder the Tauri CLI does not use).
status=0; out="$(WINVPN_WIX_DIR="$WORK/wix" "$SCRIPT" --arch x64 2>&1)" || status=$?
check "WINVPN_WIX_DIR without --check-tools fails" test "$status" != 0
check "it says why" has "$out" "WINVPN_WIX_DIR is only for --check-tools"

# In a build the check before `tauri build` comes first, and the check after it stays.
before="$(grep -n '^  check_wix_tools$' "$SCRIPT" | head -1 | cut -d: -f1)"
tauri="$(grep -n 'npx --no-install tauri build' "$SCRIPT" | head -1 | cut -d: -f1)"
after="$(grep -n '^  check_wix_tools$' "$SCRIPT" | tail -1 | cut -d: -f1)"
check "the tools are checked before tauri build" test "$before" -lt "$tauri"
check "and again after it" test "$after" -gt "$tauri"

# The service fragment (Task 15 of the 2b plan): rendered from the template with two absolute Windows paths, the
# `tauri build --config` JSON valid and adding it after tauri.windows.conf.json's fragment.
TEMPLATE="$PWD/app/src-tauri/wix/service.wxs.in"
EXE_W='C:\Users\dev\work\target\winvpn-wix\x64\files\WinVPNService.exe'
DLL_W='C:\Users\dev\work\target\winvpn-wix\x64\files\wireguard.dll'
frag() { "$SCRIPT" --service-fragment "$1" "$2" "$3" "$WORK/service.wxs" 2>&1; }
status=0; out="$(frag "$TEMPLATE" "$EXE_W" "$DLL_W")" || status=$?
check "the fragment renders" test "$status" = 0
check "the service exe is its source" grep -qF "Source=\"$EXE_W\"" "$WORK/service.wxs"
check "wireguard.dll is its source" grep -qF "Source=\"$DLL_W\"" "$WORK/service.wxs"
no_placeholder() { ! grep -qE '@[A-Za-z0-9_]+@' "$1"; }
check "no placeholder is left" no_placeholder "$WORK/service.wxs"
json="$(tail -n 1 <<<"$out")"
check "the config JSON is valid" node -e 'JSON.parse(process.argv[1])' "$json"
check "it keeps the file associations' fragment first and adds the service's" node -e '
  const w = JSON.parse(process.argv[1]).bundle.windows.wix;
  const ok = JSON.stringify(w.fragmentPaths) === JSON.stringify(["wix/file-associations.wxs", process.argv[2]])
    && JSON.stringify(w.componentGroupRefs) === JSON.stringify(["WinVPNServiceComponents"]) && !("componentRefs" in w);
  process.exit(ok ? 0 : 1);' "$json" "$WORK/service.wxs"

# A template with a placeholder build-msi.sh does not know: refused.
sed 's|Name="wireguard.dll"|Name="@OTHER@"|' "$TEMPLATE" >"$WORK/other.wxs.in"
status=0; out="$(frag "$WORK/other.wxs.in" "$EXE_W" "$DLL_W")" || status=$?
check "a template with a placeholder left fails" test "$status" != 0
check "it says so" has "$out" "a placeholder is left"
# A template that uses a path twice: refused (each source exactly once).
sed 's|@WIREGUARD_DLL@|@SERVICE_EXE@|' "$TEMPLATE" >"$WORK/twice.wxs.in"
status=0; out="$(frag "$WORK/twice.wxs.in" "$EXE_W" "$DLL_W")" || status=$?
check "a path used twice fails" test "$status" != 0
# Paths that are not absolute Windows paths of plain characters: refused (XML, sed and JSON never see them).
for bad in 'target\mvpn.exe' '/c/Users/dev/mvpn.exe' 'C:\a"b\mvpn.exe' 'C:\a&b\mvpn.exe' 'C:\a|b\mvpn.exe' 'C:\a<b\mvpn.exe'; do
  status=0; out="$(frag "$TEMPLATE" "$bad" "$DLL_W")" || status=$?
  check "the path $bad is refused" test "$status" != 0
  check "  with the reason" has "$out" "not an absolute Windows path of plain characters"
done

# The committed template: the service as the plan fixes it (LocalSystem, automatic, own process, `service`, start on
# install, stop on install and uninstall, delete on uninstall) and fixed component GUIDs.
t="$(cat "$TEMPLATE")"
check "the template installs the service as LocalSystem" has "$t" 'Name="WinVPN" DisplayName="WinVPN Service"'
check "  own process, automatic, LocalSystem" has "$t" 'Type="ownProcess" Start="auto" Account="LocalSystem"'
check "  with the argument service" has "$t" 'Arguments="service" Vital="yes"'
check "  controlled on install and uninstall" has "$t" 'Start="install" Stop="both" Remove="uninstall" Wait="yes"'
check "  each placeholder once" test "$(grep -c '@SERVICE_EXE@' "$TEMPLATE"):$(grep -c '@WIREGUARD_DLL@' "$TEMPLATE")" = 1:1
check "  three fixed GUIDs" test "$(grep -cE 'Guid="\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"' "$TEMPLATE")" = 3
no_custom_action() { ! perl -0pe 's/<!--.*?-->//gs' "$1" | grep -qiE 'CustomAction|ProgramData|CommonAppData|RemoveFolder|util:'; }
check "  no custom action element, no ProgramData (outside comments)" no_custom_action "$TEMPLATE"
# The install folder (security review part 2, P2-M2): pinned to Program Files in both sequences, the folder dialog
# skipped, an explicit protected ACL by SID (MsiLockPermissionsEx), never the name-based LockPermissions.
uncommented="$(perl -0pe 's/<!--.*?-->//gs' "$TEMPLATE")"
check "  INSTALLDIR is pinned to Program Files before CostFinalize, in both sequences" has "$uncommented" \
  '<SetProperty Id="INSTALLDIR" Value="[ProgramFiles64Folder]WinVPN\" Before="CostFinalize" Sequence="both" />'
check "  the only SetProperty" test "$(grep -c '<SetProperty' <<<"$uncommented")" = 1
check "  WelcomeDlg skips the folder dialog" has "$uncommented" \
  '<Publish Dialog="WelcomeDlg" Control="Next" Event="NewDialog" Value="VerifyReadyDlg" Order="3">1</Publish>'
check "  VerifyReadyDlg goes back to WelcomeDlg" has "$uncommented" \
  '<Publish Dialog="VerifyReadyDlg" Control="Back" Event="NewDialog" Value="WelcomeDlg" Order="3">NOT Installed</Publish>'
sddl_line="$(grep -E '^INSTALLDIR_SDDL=' "$SCRIPT" || true)"
eval "$sddl_line"
check "  the folder's ACL is build-msi.sh's SDDL" has "$uncommented" "Sddl=\"${INSTALLDIR_SDDL:-none}\""
check "  protected, SYSTEM and Administrators full control" has "${INSTALLDIR_SDDL:-}" 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
check "  in the InstallDirAcl component's CreateFolder" \
  perl -0ne 'exit(/<Component Id="InstallDirAcl"[^>]*>\s*<CreateFolder>\s*<PermissionEx Id="InstallDirSddl"/ ? 0 : 1)' <<<"$uncommented"
check "  the component is in the service's group" has "$uncommented" '<ComponentRef Id="InstallDirAcl" />'
no_lock_permissions() { ! grep -qE '<Permission[ >]' <<<"$1"; }
check "  no name-based Permission (LockPermissions)" no_lock_permissions "$uncommented"
# No failure actions (CP1: Windows Installer's MsiServiceConfigFailureActions fails a restart action with error 1939;
# the service sets its own recovery), and the build fails if the table comes back with a row.
no_failure_actions() { ! perl -0pe 's/<!--.*?-->//gs' "$1" | grep -qiE 'ServiceConfigFailureActions|<Failure'; }
check "  no failure actions (outside comments)" no_failure_actions "$TEMPLATE"
check "the build looks for the failure-actions table" \
  grep -qF "FROM \\\`_Tables\\\` WHERE \\\`Name\\\`='MsiServiceConfigFailureActions'" "$SCRIPT"
check "  and fails on a row, naming error 1939" grep -qF 'die "the MSI has failure actions (MsiServiceConfigFailureActions:' "$SCRIPT"
check "  no longer expects failure-action rows" test "$(grep -c 'msi_expect.*failure actions' "$SCRIPT")" = 0

# The MSI table gates (build-msi.sh --check-msi-rows WHAT FILE [ARGS]: the same checks the build runs on the tables
# msi-query.ps1 reads, here on rows written by hand).
rows() { printf '%b' "$1" >"$WORK/rows.txt"; "$SCRIPT" --check-msi-rows "$2" "$WORK/rows.txt" "${@:3}" 2>&1; }
gate_ok() { local status=0 out; out="$(rows "$@")" || status=$?; [ "$status" = 0 ] || { echo "$out" >&2; return 1; }; }
gate_fails() { local status=0; rows "$@" >/dev/null || status=$?; [ "$status" != 0 ]; }
UC='{72446277-03C5-4DBB-AC44-49785F029CF8}'
# Upgrade (P2-L2): an older or the same version is upgraded (513: migrate features + maximum inclusive), a newer one
# only detected (2) and refused through WIX_DOWNGRADE_DETECTED; never AllowDowngrades' single row.
good_upgrade="$UC\t\t2.0.0\t513\tWIX_UPGRADE_DETECTED\n$UC\t2.0.0\t\t2\tWIX_DOWNGRADE_DETECTED\n"
check "upgrade gate: the downgrade-refusing rows pass" gate_ok "$good_upgrade" upgrade 2.0.0 "$UC"
check "  in either order" gate_ok "$UC\t2.0.0\t\t2\tWIX_DOWNGRADE_DETECTED\n$UC\t\t2.0.0\t513\tWIX_UPGRADE_DETECTED\n" upgrade 2.0.0 "$UC"
check "  AllowDowngrades (one row, any version) fails" gate_fails "$UC\t0.0.0\t\t257\tWIX_UPGRADE_DETECTED\n" upgrade 2.0.0 "$UC"
check "  no downgrade row fails" gate_fails "$UC\t\t2.0.0\t513\tWIX_UPGRADE_DETECTED\n" upgrade 2.0.0 "$UC"
check "  a same-version reinstall refused (258) fails" \
  gate_fails "$UC\t\t2.0.0\t1\tWIX_UPGRADE_DETECTED\n$UC\t2.0.0\t\t258\tWIX_DOWNGRADE_DETECTED\n" upgrade 2.0.0 "$UC"
check "  another version fails" gate_fails "$good_upgrade" upgrade 2.0.1 "$UC"
check "  another UpgradeCode fails" gate_fails "$good_upgrade" upgrade 2.0.0 '{00000000-0000-0000-0000-000000000000}'
check "launch condition gate: the downgrade refusal passes" gate_ok 'NOT WIX_DOWNGRADE_DETECTED\tA newer version of WinVPN is already installed.\n' launch
check "  none fails" gate_fails '' launch
# MsiLockPermissionsEx (P2-M2): exactly the install folder's row with build-msi.sh's SDDL, unconditional.
check "lock gate: the install folder's row passes" gate_ok "INSTALLDIR\tCreateFolder\t${INSTALLDIR_SDDL:-}\t\n" lock
check "  another SDDL fails" gate_fails 'INSTALLDIR\tCreateFolder\tD:(A;OICI;FA;;;WD)\t\n' lock
check "  a condition fails" gate_fails "INSTALLDIR\tCreateFolder\t${INSTALLDIR_SDDL:-}\tNOT Installed\n" lock
check "  another folder fails" gate_fails "ApplicationProgramsFolder\tCreateFolder\t${INSTALLDIR_SDDL:-}\t\n" lock
check "  no row fails" gate_fails '' lock
check "  a second row fails" \
  gate_fails "INSTALLDIR\tCreateFolder\t${INSTALLDIR_SDDL:-}\t\nINSTALLDIR\tCreateFolder\tD:(A;;FA;;;WD)\t\n" lock
# A sequence (InstallUISequence, InstallExecuteSequence): SetINSTALLDIR unconditional and before CostFinalize;
# FindRelatedProducts before LaunchConditions (the downgrade refusal sees what it found).
seq="AppSearch\t50\t\nFindRelatedProducts\t25\t\nLaunchConditions\t100\t\nSetINSTALLDIR\t998\t\nCostFinalize\t1000\t\n"
check "sequence gate: the pin before CostFinalize passes" gate_ok "$seq" sequence
check "  after CostFinalize fails" gate_fails "${seq/SetINSTALLDIR\\t998/SetINSTALLDIR\\t1001}" sequence
check "  with a condition fails" gate_fails "${seq/SetINSTALLDIR\\t998\\t/SetINSTALLDIR\\t998\\tNOT Installed}" sequence
check "  missing fails" gate_fails "${seq/SetINSTALLDIR\\t998\\t\\n/}" sequence
check "  FindRelatedProducts after LaunchConditions fails" gate_fails "${seq/FindRelatedProducts\\t25/FindRelatedProducts\\t101}" sequence
# The folder dialog (P2-M2): WelcomeDlg's Next ends in VerifyReadyDlg (the last true NewDialog wins).
welcome="InstallDirDlg\tNOT Installed\t1\nVerifyReadyDlg\tInstalled AND PATCH\t1\nInstallDirDlg\t1\t2\nVerifyReadyDlg\t1\t3\n"
check "dialog gate: WelcomeDlg straight to VerifyReadyDlg passes" gate_ok "$welcome" welcome
check "  the folder dialog last fails" gate_fails "InstallDirDlg\t1\t2\nVerifyReadyDlg\t1\t3\nInstallDirDlg\t1\t4\n" welcome
check "  a condition on the skip fails" gate_fails "InstallDirDlg\t1\t2\nVerifyReadyDlg\tNOT Installed\t3\n" welcome
check "an unknown table check fails" gate_fails '' other

# The build runs them all on the MSI.
for what in upgrade launch lock sequence welcome; do
  check "  the build runs the $what gate" grep -qE "check_msi_rows $what " "$SCRIPT"
done
check "  LockPermissions must stay empty" grep -qF "'LockPermissions'" "$SCRIPT"
# The WebView2 bootstrapper (P2-L1): embedded, run from the Binary table, Microsoft's signature checked at build.
check "the custom actions include the embedded bootstrapper" grep -qF 'InvokeBootstrapper 1026 MicrosoftEdgeWebview2Setup.exe' "$SCRIPT"
check "  and never the downloading one" test "$(grep -c 'DownloadAndInvokeBootstrapper 1058' "$SCRIPT")" = 0
check "  and the pin of INSTALLDIR" grep -qF 'SetINSTALLDIR 51 INSTALLDIR' "$SCRIPT"
# shellcheck disable=SC2016 # the script's text, not an expansion
check "  its Authenticode signer is checked" grep -qF 'gate_webview2_bootstrapper "$DARK/Binary/MicrosoftEdgeWebview2Setup.exe"' "$SCRIPT"

# pe-imports.mjs --machine and --subsystem on a minimal PE header.
node -e '
  const b = Buffer.alloc(0x200); b.write("MZ", 0, "latin1"); b.writeUInt32LE(0x80, 0x3c);
  b.write("PE\0\0", 0x80, "latin1"); b.writeUInt16LE(0xaa64, 0x84); b.writeUInt16LE(0xf0, 0x84 + 16);
  b.writeUInt16LE(0x20b, 0x98); b.writeUInt16LE(3, 0x98 + 68);
  require("fs").writeFileSync(process.argv[1], b);' "$WORK/pe.bin"
check "pe-imports.mjs --machine" test "$(node scripts/pe-imports.mjs --machine "$WORK/pe.bin")" = aa64
check "pe-imports.mjs --subsystem" test "$(node scripts/pe-imports.mjs --subsystem "$WORK/pe.bin")" = 3

# In a build the service and wireguard.dll are gated before `tauri build` and again unpacked from the MSI.
first_gate="$(grep -n '^  gate_service_exe ' "$SCRIPT" | head -1 | cut -d: -f1)"
last_gate="$(grep -n '^  gate_service_exe ' "$SCRIPT" | tail -1 | cut -d: -f1)"
first_dll="$(grep -n '^  gate_wireguard_dll ' "$SCRIPT" | head -1 | cut -d: -f1)"
last_dll="$(grep -n '^  gate_wireguard_dll ' "$SCRIPT" | tail -1 | cut -d: -f1)"
check "the service exe is gated before tauri build" test "$first_gate" -lt "$tauri"
check "  and after it" test "$last_gate" -gt "$tauri"
check "wireguard.dll is gated before tauri build" test "$first_dll" -lt "$tauri"
check "  and after it" test "$last_dll" -gt "$tauri"
# shellcheck disable=SC2016 # the script's text, not an expansion
check "tauri build gets the service's config" grep -qF -- '--config "$WIX_CONFIG"' "$SCRIPT"

# The app's release gate refuses the updater's debug-only local-MSI hook (2b plan, Task 18); every marker is a
# pattern, never an option (`grep -e`: "--test-install-msi" starts with dashes).
markers_line="$(grep -E '^APP_DEBUG_MARKERS=\(' "$SCRIPT")"
check "the app's debug markers include the updater's hook" has "$markers_line" "--test-install-msi"
# shellcheck disable=SC2016 # the script's text, not an expansion
check "  the gate loops over them with grep -e" grep -qF 'grep -a -q -F -e "$marker" "$1"' "$SCRIPT"
eval "$markers_line"
printf 'xx--test-install-msiyy' >"$WORK/app.bin"
caught=""
for marker in "${APP_DEBUG_MARKERS[@]}"; do
  if LC_ALL=C grep -a -q -F -e "$marker" "$WORK/app.bin"; then caught="$marker"; fi
done
check "  a binary with the hook is caught" test "$caught" = "--test-install-msi"
printf 'a release binary' >"$WORK/app.bin"
caught=""
for marker in "${APP_DEBUG_MARKERS[@]}"; do
  if LC_ALL=C grep -a -q -F -e "$marker" "$WORK/app.bin"; then caught="$marker"; fi
done
check "  a binary without debug markers passes" test -z "$caught"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
