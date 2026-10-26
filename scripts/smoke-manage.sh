#!/bin/bash
# Sandboxed smoke test of the app's windows (Tauri app, debug build with the embedded UI). Seeds 1.1 data
# (connections, a pin, an old Keychain item in the sandbox's in-memory Keychain) in a throwaway MACVPN_SANDBOX_HOME
# and starts the app with MACVPN_SMOKE_DIR=scripts/smoke, which runs, through the real UI:
#   vault-create.js – the create window in migration mode: the master password twice, the recovery key read and
#               one group retyped; the seeded data moves into the vault and the old files are deleted;
#   manage.js – the Connections window (risky panel, acknowledgement, unsaved-changes question, Log tab, SSTP and
#               native forms, stored secrets never shown, the New menu, a context menu at the window's corners and
#               its colour picker inside the window, the search – typed without the accents' care, by an OpenVPN
#               and a native server and by type, Up / Down and Return, the empty result and its Clear, Escape bringing every row back, Cmd+F –,
#               New and Delete, a navigation away cancelled);
#   setup.js  – System Status over a mock report (rows, the reinstall notice, the simulated brew output, the root
#               installer and the uninstaller answering "cancelled" in the sandbox);
#   update.js – the Update window over a mock release (notes stay text), Download and Install up to the quit
#               questions, cancelled at "Unsaved Changes";
#   (the Dock icon: shown while those windows are open, a Dock click, hidden after they close)
#   prompt.js – a mock MFA code prompt and web sign-in in their prompt windows (no Dock icon meanwhile);
#   credentials.js – the credential prompt of a seeded OpenVPN connection with a bare auth-user-pass and nothing
#               stored: the user name and password typed, saved (in memory) once connected, no prompt on the
#               second connect; then the one re-prompt after a sign-in failure, cancelled without a failure;
#   backup.js, restore.js – the full backup: "Back up everything" into the sandbox tmp (no save panel in the smoke
#               run), the file 0600 with no seeded text in clear; "Restore from backup" with a wrong password (the
#               generic message), then Merge with Overwrite, then Replace everything (its confirmation names the
#               count) with the preferences step (the control API unticked) – each brings the renamed canary back;
#   control.js, pairing.js, control-client.mjs – the control API: the Paired apps switch turns the socket on, the
#               test client (Node) pairs (approved in the pairing window), says hello, lists, brings a seeded
#               connection up (the smoke's stand-in root helper: nothing runs) and closes its socket, which takes
#               the connection down; then the switch turns it off and the socket is gone;
#   live.js, live-menu.js – the live system VPN list: the run's system VPNs are a stand-in list the app's smoke
#               driver changes (no scutil, no real VPN); with the Connections window open, a fake system VPN's
#               detail turns read-only with the "removed from macOS" banner when the driver removes it, and a VPN
#               the driver adds appears in the window and in the menu popover without reopening either;
#   folders.js – folders and colours in the Connections window (kept in the vault): New Folder named
#               in place, a subfolder, a colour the subfolder inherits, a connection dragged into it, collapse, and
#               the subfolder deleted with its contents moved up;
#   appearance.js, engines.js, notices.js, reconnect.js – the 2.0 features (their connections are created in the vault
#               for the step and deleted after it): Settings' Appearance (Dark, Light, Match System) switches the
#               popover and the Connections window (prefers-color-scheme); with one engine missing (macOS: sstpc,
#               Windows: OpenVPN) its row is greyed with "Not installed: … – System Status" (the switch disabled, the
#               link opens System Status), the New menu leaves the kind out and a file of that kind opened from
#               Finder is refused; installed "outside the app", the popover's background check brings the row back
#               within 2 s; a connect and a drop are notified (recorded: the sandbox posts no notification), nothing
#               with "Connection Notifications" off; auto-reconnect over a scripted network and the sleep / wake hooks
#               (reconnected at home, not on another network, not with the detail's switch off; a tunnel still up
#               after waking on the network it routes is disconnected, at a café it stays);
#   ras.js   – Windows only (WinVPN 2c; its connections are created in the vault for the step and deleted after it):
#               the New menu without Cisco IPsec, an IKEv2 PSK connection greyed with the Windows reason, a Cisco
#               IPsec connection with option A's text and "Make an L2TP/IPsec Copy", IKEv2 (EAP) and SSTP connected and
#               disconnected through the stand-in helper, an L2TP connection saved (the sandbox engine's entry, then
#               listed), connected and disconnected through the stand-in native layer – never a dial;
#   (the menu popover shown: its rounded corners as AppKit holds them; SMOKE_SHOTS=<dir> takes screenshots)
#   (every prompt, pairing and credential window must fit its content: no scrolling, checked in the real window;
#               the largest credential window – retry line, four fields, a refused answer's error – too)
#   shared.js, shared-prompt.js – shared credentials (in the vault): the Credentials section adds one
#               without a password, two seeded connections are linked to it through their editors' selector, the
#               first connect asks for the password once (naming the credential, "used by 2") and saves it into
#               the credential, the second connects without a prompt; Delete with "Copy into each connection";
#               an import naming a credential asks first (with the server) and links only after "Use";
#   catalog.js – a team catalog as a subscriber (plan Task 16): the driver seals a fixture catalog with the core's
#               functions into the sandbox (its own keys: publish.js runs after it); "Add team catalog…" with the file source (no open
#               panel in the smoke run), the team key and the fingerprint typed, the preview, Subscribe; the Team badges,
#               the read-only editor, the context menu and a refused drag; version 2 through "Refresh now"; Unsubscribe;
#   open.js   – files opened from Finder: the driver simulates the open event (`open_files::receive`, what
#               `RunEvent::Opened` calls) with sandbox fixtures – one .ovpn (the Connections window opens with the
#               import's report), two at once, the catalog fixture (the add dialog with the file source; cancelled),
#               one while locked (the unlock window, imported after it) and one whose unlock is cancelled (dropped);
#   publish.js – publishing a team catalog (in the vault): the Publishing section generates the admin key and the
#               backup key, the wizard publishes a seeded folder to the sandbox tmp (no save panel in the smoke run:
#               the file is 0644, opens with the stored team key and the admin key's fingerprint, holds no seeded
#               text in clear) and shows the team key once (read, "I Saved It", one group retyped); Publish New
#               Version (v2); Rotate Team Key after its revoke text and the review (v3: the old team key no longer
#               opens the file); Export Backup Key with "remove after" (offline, the key file 0600) and Import it again;
#   quit.js   – the quit flows' edge cases: a selection while the quit's "Unsaved Changes" is shown, the Update
#               window closed during an install and while its quit question is shown (the update is cancelled);
#   vault-menu.js, vault-unlock.js, vault-password.js – "Show “Lock Now”" turned on and "Lock Now" clicked in the
#               menu (the locked menu shows no name, no switch and no setting), its "Unlock…" opens the unlock window:
#               a wrong password (the delay's countdown) and the right one; then the recovery key and a new master
#               password, the new password, "Change Master Password…" in the menu's settings, and the changed one;
#   system.js – an unsaved change; the shell then quits the app the way logout does (a quit Apple Event) and
#               checks that the Connections window asked first and the app then quit.
# Then it checks the vault's files, the connections the app wrote out for the checks (<home>/smoke-dump: the vault
# itself is encrypted) and the log.
# On Windows (Git Bash, WinVPN's debug build: scripts/win-smoke.sh runs it in winvpn-dev's desktop session) every
# section runs except what is AppKit's: the Dock icon, the screenshots and the appearance print "skipped on Windows";
# the popover's corners are DWM's round-corner preference (round=true on Windows 11, false on Windows 10); the
# system's quit request is logout's WM_QUERYENDSESSION, which the app's smoke driver sends to its own lifecycle window;
# there is no old Keychain item (Windows has none), no staged native profile (saving an L2TP connection writes the
# sandbox RAS engine's entry in its private phonebook under the sandbox; System Status shows the Windows VPN client
# row and the account clean-up, whose confirmation is cancelled) and no Unix mode check (the Windows ACLs are checked by the app's own tests). SMOKE_LANG is passed as
# MACVPN_SMOKE_LANG (Windows' UI languages cannot be set for one process).
# SMOKE_LANG=en|hu forces the app's language the way macOS selects it (the AppleLanguages preference, here in the
# app's argument domain: -AppleLanguages '(hu)'); the run checks that the core picked it and the windows show it. Never touches the real Application Support, Keychain, preferences or
# system (the sandbox's vault is in its own home, its auto-unlock key in memory; preferences in memory; it
# opens nothing, runs no installer).
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -s)" in
  MINGW*|MSYS*) SMOKE_OS=windows ;;
  *) SMOKE_OS=macos ;;
esac
if [ "$SMOKE_OS" = windows ]; then
  # scripts/win-smoke.sh builds it for the CI target (the remote checkout's warm build directory).
  APP=${APP:-target/x86_64-pc-windows-msvc/debug/macvpn-app.exe}
  BUILD_HINT="build first: (cd app/ui && npm run build) && cargo build --target x86_64-pc-windows-msvc -p macvpn-app --features custom-protocol"
else
  APP=${APP:-target/debug/macvpn-app}
  BUILD_HINT="build first: (cd app/ui && npm run build) && cargo build -p macvpn-app --features custom-protocol"
fi
[ -x "$APP" ] || { echo "$BUILD_HINT" >&2; exit 2; }
# The binary must embed the current UI build. `cargo test`/`clippy` rebuild target/debug/macvpn-app without
# custom-protocol (the app crate has integration tests); such a binary loads the dev server and every flow stalls.
# (Git Bash has no `strings`: the asset's name is plain text in the binary.)
UI_JS=$(cd app/ui/dist/assets 2>/dev/null && ls index-*.js 2>/dev/null | head -1 || true)
embeds_ui() {
  if [ "$SMOKE_OS" = windows ]; then grep -aqF "assets/$UI_JS" "$APP"; else strings "$APP" | grep -F "assets/$UI_JS" >/dev/null; fi
}
if [ -z "$UI_JS" ] || ! embeds_ui; then
  echo "$APP does not embed the current UI build (app/ui/dist/assets/${UI_JS:-?}); $BUILD_HINT" >&2
  exit 2
fi
if [ "$SMOKE_OS" = windows ]; then
  # A fresh directory under the user's temp folder; the app gets its Windows path.
  HOME_DIR=$(mktemp -d "${TEMP:-/tmp}/winvpn-smoke.XXXXXX")
  # Long names (-l): the user's temp folder is often given in 8.3 form (C:\Users\WINVPN~1\…), and the app refuses a
  # file source path with `~` ("The file path contains an invalid character").
  APP_HOME=$(cygpath -l -w "$HOME_DIR")
  APP_SMOKE_DIR=$(cygpath -l -w "$PWD/scripts/smoke")
  NODE=$(command -v node || true)
  SUPPORT="$HOME_DIR/AppData/Local/WinVPN"
else
  # A short path: the control socket (<home>/Library/Application Support/MacVPN/control/macvpn.sock) must fit a
  # Unix socket address (104 bytes), which $TMPDIR (/var/folders/…) would not leave room for.
  HOME_DIR=$(mktemp -d /tmp/macvpn-smoke.XXXXXX)
  APP_HOME=$HOME_DIR
  APP_SMOKE_DIR="$PWD/scripts/smoke"
  NODE=$(command -v node || echo /opt/homebrew/bin/node)
  SUPPORT="$HOME_DIR/Library/Application Support/MacVPN"
fi
[ -n "$NODE" ] && [ -x "$NODE" ] || { echo "the control API test client needs node" >&2; exit 2; }
# SMOKE_LOG=<file>: keep the app's log.
# The app is stopped and gone before its sandbox is removed (Windows keeps the files of a running process busy).
stop_app() {
  [ -n "${PID:-}" ] || return 0
  if [ "$SMOKE_OS" = windows ] && [ -r "/proc/$PID/winpid" ]; then
    taskkill //F //PID "$(cat "/proc/$PID/winpid")" >/dev/null 2>&1 || true
  fi
  kill "$PID" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
}
trap 'stop_app; [ -z "${SMOKE_LOG:-}" ] || cp "$LOG" "$SMOKE_LOG"; rm -rf "$HOME_DIR"' EXIT
STORE="$SUPPORT/connections"
# The connections as the app had them at the end (written by its smoke driver; the vault is encrypted).
DUMP="$HOME_DIR/smoke-dump/connections"
LOG="$HOME_DIR/app.log"
seed() { # id kind name config [extra meta JSON]
  mkdir -p "$STORE/$1"
  chmod 700 "$STORE/$1"
  printf '{"acknowledgedRiskyDirectives":[],"createdAt":"2026-10-18T10:00:00Z","id":"%s","kind":"%s","name":"%s","otp":{"enabled":false,"separator":"none"}%s}' \
    "$1" "$2" "$3" "${5:-}" > "$STORE/$1/meta.json"
  [ -z "$4" ] || printf '%b' "$4" > "$STORE/$1/config"
  chmod 600 "$STORE/$1"/*
}
A=11111111-2222-4333-8444-555555555555
S=21111111-2222-4333-8444-555555555555
L=31111111-2222-4333-8444-555555555555
SETUP=41111111-2222-4333-8444-555555555555
UPDATE=51111111-2222-4333-8444-555555555555
QUIT=71111111-2222-4333-8444-555555555555
CONTROL=81111111-2222-4333-8444-555555555555
CONTROL_VPN=91111111-2222-4333-8444-555555555555
LIVE=C1111111-2222-4333-8444-555555555555
LIVE_MENU=C2111111-2222-4333-8444-555555555555
FOLDERS=E1111111-2222-4333-8444-555555555555
CRED=A1111111-2222-4333-8444-555555555555
CRED_RETRY=B1111111-2222-4333-8444-555555555555
SHARED_ONE=E3111111-2222-4333-8444-555555555555
SHARED_TWO=E4111111-2222-4333-8444-555555555555
OVPN='client\ndev tun\nremote vpn.example.com 1194\n'
seed "$A" openvpn "Seeded A" "$OVPN"
# Its own server: manage.js finds it by its OpenVPN `remote` host (the port and the rest of the line are not searched).
seed 66666666-7777-4888-9999-AAAAAAAAAAAA openvpn "Seeded B" 'client\ndev tun\nremote b-gateway.example.net 1194 udp\n'
seed "$S" sstp "Seeded S" 'server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n'
seed "$L" l2tp "Seeded L" '' ',"native":{"server":"l2tp.example.com","account":"bob","groupName":"","sendAllTraffic":true}'
seed "$SETUP" openvpn "Zz Setup result" "$OVPN"
seed "$UPDATE" openvpn "Zz Update result" "$OVPN"
seed "$QUIT" openvpn "Zz Quit result" "$OVPN"
seed "$CONTROL" openvpn "Zz Control result" "$OVPN"
seed "$CONTROL_VPN" openvpn "Zz Control VPN" "$OVPN"
seed "$LIVE" openvpn "Zz Live result" "$OVPN"
seed "$LIVE_MENU" openvpn "Zz Live menu result" "$OVPN"
# First among the top-level rows, so folders.js can drag it next to the folders it creates.
seed "$FOLDERS" openvpn "Aa Folders result" "$OVPN"
seed "$CRED" openvpn "Zz Credentials" "${OVPN}auth-user-pass\n"
seed "$CRED_RETRY" openvpn "Zz Credentials retry" "${OVPN}auth-user-pass\n"
# A pin: migrated with the ranking.
printf '{"pinned":["%s"],"usage":{}}' "$S" > "$SUPPORT/connection-order.json"
chmod 600 "$SUPPORT/connection-order.json"
seed "$SHARED_ONE" openvpn "Zz Shared one" "${OVPN}auth-user-pass\n"
seed "$SHARED_TWO" openvpn "Zz Shared two" "${OVPN}auth-user-pass\n"

LANG_ARGS=()
LANG_ENV=()
case "${SMOKE_LANG:-}" in
  '') ;;
  en|hu) if [ "$SMOKE_OS" = windows ]; then LANG_ENV=(MACVPN_SMOKE_LANG="$SMOKE_LANG"); else LANG_ARGS=(-AppleLanguages "(${SMOKE_LANG})"); fi ;;
  *) echo "SMOKE_LANG: en or hu" >&2; exit 2 ;;
esac
# SMOKE_SHOTS=<dir>: screenshots (with the shadow) of the real windows, <dir>/<name>-<lang>[-dark|-light].png: the menu
# popover, the MFA code and web sign-in prompts, the pairing window, the smallest and the largest credential window,
# the Connections window with the New menu open, with a context menu at its right edge, and its search with results
# and with none (popover-shots.js).
# SMOKE_DARK=1: the app in dark mode, SMOKE_LIGHT=1: in light mode (NSApp.appearance in the debug build; the system's
# own setting is not touched).
SHOTS_ENV=()
if [ "$SMOKE_OS" = windows ] && [ -n "${SMOKE_SHOTS:-}${SMOKE_DARK:-}${SMOKE_LIGHT:-}" ]; then
  echo "SMOKE_SHOTS, SMOKE_DARK and SMOKE_LIGHT are macOS only: ignored" >&2
  unset SMOKE_SHOTS SMOKE_DARK SMOKE_LIGHT
fi
[ -z "${SMOKE_SHOTS:-}" ] || { mkdir -p "$SMOKE_SHOTS"; rm -f "$SMOKE_SHOTS"/*.done; SHOTS_ENV=(MACVPN_SMOKE_SHOTS="$SMOKE_SHOTS"); }
[ -z "${SMOKE_DARK:-}" ] || SHOTS_ENV+=(MACVPN_SMOKE_DARK=1)
[ -z "${SMOKE_LIGHT:-}" ] || SHOTS_ENV+=(MACVPN_SMOKE_LIGHT=1)
env ${SHOTS_ENV[@]+"${SHOTS_ENV[@]}"} ${LANG_ENV[@]+"${LANG_ENV[@]}"} MACVPN_SANDBOX_HOME="$APP_HOME" MACVPN_SMOKE_DIR="$APP_SMOKE_DIR" "$APP" ${LANG_ARGS[@]+"${LANG_ARGS[@]}"} > "$LOG" 2>&1 &
PID=$!
CLIENT_PID=
# The console's screen lock, sampled through the run (the session's CGSSessionScreenIsLocked, as ioreg shows it):
# while it is locked, the windows are not drawn and their measured geometry is not what a user sees, so the popover
# placement checks are not trustworthy. Only those checks, and only when the lock was seen, are reported as not
# verified instead of failed (with a ⚠ line and in the final line); every other failure still fails.
SCREEN_LOCKED="$HOME_DIR/screen-locked"
# The output is read whole first: piped into `grep -q`, ioreg (about 87 KB, more than a pipe holds) was killed by
# SIGPIPE once grep had its match, and with `pipefail` that made every sample "not locked".
screen_locked() {
  [ "$SMOKE_OS" = macos ] || return 1
  local registry
  registry=$(ioreg -n Root -d1 2>/dev/null) || return 1
  [[ $registry == *'"CGSSessionScreenIsLocked"=Yes'* ]]
}
# The whole run's limit (seconds): WebView2 and the debug build are slower than macOS' WebKit.
if [ "$SMOKE_OS" = windows ]; then RUN_LIMIT=1200; else RUN_LIMIT=600; fi
for _ in $(seq 1 "$RUN_LIMIT"); do
  sleep 1
  ! screen_locked || touch "$SCREEN_LOCKED"
  if grep -q '^MacVPN smoke: done' "$LOG" 2>/dev/null; then break; fi
  # The control API's test client, once the app listens.
  if [ -z "$CLIENT_PID" ] && grep -q '^MacVPN smoke: control: listening ' "$LOG" 2>/dev/null; then
    SOCKET=$(sed -n 's/^MacVPN smoke: control: listening //p' "$LOG" | head -1)
    "$NODE" scripts/smoke/control-client.mjs "$SOCKET" "$CONTROL_VPN" "$HOME_DIR/client.json" > "$HOME_DIR/client.log" 2>&1 &
    CLIENT_PID=$!
  fi
  # The driver holds a window still (`MacVPN smoke: shot <name> window=<number>`) until its screenshot is taken.
  if [ -n "${SMOKE_SHOTS:-}" ]; then
    while read -r SHOT WINDOW; do
      [ -e "$SMOKE_SHOTS/$SHOT.done" ] && continue
      screencapture -x -l "$WINDOW" "$SMOKE_SHOTS/$SHOT-${SMOKE_LANG:-default}${SMOKE_DARK:+-dark}${SMOKE_LIGHT:+-light}.png" 2>/dev/null || true
      touch "$SMOKE_SHOTS/$SHOT.done"
    done < <(sed -n 's/^MacVPN smoke: shot \([a-z-]*\) window=\([0-9]*\)$/\1 \2/p' "$LOG" 2>/dev/null)
  fi
done
[ -z "$CLIENT_PID" ] || wait "$CLIENT_PID" || true
name() { sed -n 's/.*"name" : "\(.*\)",*/\1/p' "$DUMP/$1/meta.json" 2>/dev/null; }
echo "manage: $(name "$A")"
echo "setup:  $(name "$SETUP")"
echo "update: $(name "$UPDATE")"
echo "quit:   $(name "$QUIT")"
echo "control: $(name "$CONTROL")"
echo "live:   $(name "$LIVE") / $(name "$LIVE_MENU")"
echo "folders: $(name "$FOLDERS")"
grep '^MacVPN smoke: prompt' "$LOG" || true
grep '^MacVPN smoke: control' "$LOG" || true
grep '^MacVPN smoke: live' "$LOG" || true
grep '^MacVPN smoke: credentials' "$LOG" || true
grep '^MacVPN smoke: vault' "$LOG" || true
grep '^MacVPN smoke: folders' "$LOG" || true
grep '^MacVPN smoke: shared' "$LOG" || true
grep '^MacVPN smoke: backup' "$LOG" || true
grep '^MacVPN smoke: catalog' "$LOG" || true
grep '^MacVPN smoke: open' "$LOG" || true
grep '^MacVPN smoke: publish' "$LOG" || true
grep -E '^MacVPN smoke: (appearance|engines|notices|reconnect)' "$LOG" || true
fail() { echo "✗ $1"; sed 's/^/  app: /' "$LOG"; exit 1; }
grep -q '^MacVPN smoke: done' "$LOG" || fail "the smoke run did not finish"
LANGUAGE=$(sed -n 's/^MacVPN smoke: language //p' "$LOG")
echo "language: ${LANGUAGE}"
[ -z "${SMOKE_LANG:-}" ] || [ "$LANGUAGE" = "$SMOKE_LANG" ] || fail "the app picked ${LANGUAGE}, not ${SMOKE_LANG}"

# The vault: created in migration mode, the seeded connections, the old Keychain item and the pin moved in, the
# old files deleted, the marker written; the files are private.
# Windows has no old Keychain: no item, so no secret moves.
if [ "$SMOKE_OS" = windows ]; then KEYCHAIN_ITEMS=0 SECRET=no SECRETS=0; else KEYCHAIN_ITEMS=1 SECRET=yes SECRETS=1; fi
grep -q "^MacVPN smoke: vault: create window migrating=true keychain_items=$KEYCHAIN_ITEMS\$" "$LOG" || fail "the create window was not in migration mode"
grep -q "^MacVPN smoke: vault: created done=true connections=16 secret=$SECRET pinned=true files_gone=true marker=true key=true\$" "$LOG" \
  || fail "the vault was not created and migrated"
grep -q "^MacVPN: Vault: migrated: 16 connections, $SECRETS secrets" "$LOG" || fail "no migration line"
[ ! -e "$STORE" ] && [ ! -e "$SUPPORT/connection-order.json" ] || fail "the old files are still there"
[ -e "$SUPPORT/migrated-to-vault" ] || fail "no migration marker"
if [ "$SMOKE_OS" = macos ]; then
  for f in vault.db vault.keys migrated-to-vault; do
    [ "$(stat -f %Lp "$SUPPORT/$f")" = 600 ] || fail "$f is not 0600"
  done
fi
! grep -aq 'Seeded A\|Zz Credentials\|vpn.example.com' "$SUPPORT/vault.db" || fail "a name or a config is readable in vault.db"
# Locked: no name in the view model; unlocked with the password (after a wrong one and its delay), with the recovery
# key and a new master password, and with the new password.
grep -q '^MacVPN smoke: vault: menu lock_now=true names_hidden=true unlock_window=true$' "$LOG" || fail "Lock Now and the locked menu"
grep -q '^MacVPN smoke: vault: locked state="locked" names_hidden=true$' "$LOG" || fail "the locked view model"
grep -q '^MacVPN: Vault: wrong password (attempt 1)$' "$LOG" || fail "the wrong password was not refused"
grep -q '^MacVPN smoke: vault: unlocked password=true names_back=true$' "$LOG" || fail "unlock with the password"
grep -q '^MacVPN smoke: vault: unlocked recovery=true names_back=true$' "$LOG" || fail "unlock with the recovery key"
grep -q '^MacVPN: Vault: master password reset with the recovery key$' "$LOG" || fail "no reset line"
grep -q '^MacVPN smoke: vault: unlocked new_password=true names_back=true$' "$LOG" || fail "unlock with the new password"
grep -q '^MacVPN smoke: vault: password window closed=true$' "$LOG" || fail "the password window"
grep -q '^MacVPN: Vault: master password changed$' "$LOG" || fail "no password change line"
grep -q '^MacVPN smoke: vault: unlocked changed_password=true names_back=true$' "$LOG" || fail "unlock with the changed password"
! grep -q 'smoke-master-4711\|smoke-reset-0815\|smoke-changed-2024\|seeded-psk-0815' "$LOG" || fail "the log shows a vault password or a secret"
! grep -Eq '[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}' "$LOG" || fail "the log shows a recovery key"
! grep -q '^MacVPN smoke: vault: ERROR' "$LOG" || fail "the vault smoke"

# The Connections window.
grep -q '"user"' "$DUMP/$A/meta.json" || fail "the acknowledgement was not stored"
grep -q '^user nobody$' "$DUMP/$A/config" || fail "the config was not saved"
PLACEMENT_SKIPPED=
if [ "$(name "$A")" != "SMOKE OK" ]; then
  # `SMOKE FAILED <checks> <geometry>`: skipped only when every failed check is a placement check and the screen
  # was locked during the run; anything else (or an unlocked screen) fails.
  FAILED_CHECKS=$(name "$A" | sed -n 's/^SMOKE FAILED \([^ ]*\).*/\1/p')
  OTHER=$(printf '%s' "$FAILED_CHECKS" | tr ',' '\n' | grep -Ev '^(contextBottomRight|contextTopRight|contextBottomLeft|pickerInside|newMenuInside)$' || true)
  if [ -n "$FAILED_CHECKS" ] && [ -z "$OTHER" ] && [ -e "$SCREEN_LOCKED" ]; then
    echo "⚠ display locked during the run: the popover placement checks ($FAILED_CHECKS) were not verified – unlock the display and run again"
    PLACEMENT_SKIPPED=" – popover placement NOT verified: display locked"
  else
    fail "Connections window: $(name "$A")"
  fi
fi
grep -q '^port=8443$' "$DUMP/$S/config" || fail "the SSTP form was not saved"
if [ "$SMOKE_OS" = macos ]; then
  PROFILE=$(find "$HOME_DIR/tmp" -path '*/macvpn-profile.*/Seeded L2.mobileconfig' | head -1)
  [ -n "$PROFILE" ] || fail "the native profile was not staged"
  [ "$(stat -f %Lp "$PROFILE")" = 600 ] || fail "the staged profile is not 0600"
fi
! grep -rq native-secret "$HOME_DIR/tmp" || fail "the password is in a staged profile"
# 16 seeded, one created and deleted, the backup step's canary (in the backup, so restored), one imported by the
# shared credential step, one published by the publishing step.
[ "$(ls "$DUMP" | wc -l | tr -d ' ')" = 19 ] || fail "create / delete left $(ls "$DUMP" | wc -l | tr -d ' ') connections"

# System Status and Update.
[ "$(name "$SETUP")" = "SETUP OK" ] || fail "System Status window: $(name "$SETUP")"
[ "$(name "$UPDATE")" = "UPDATE OK" ] || fail "Update window: $(name "$UPDATE")"
! find "$HOME_DIR/tmp" -maxdepth 1 \( -name 'macvpn-download.*' -o -name 'macvpn-mount.*' -o -name 'macvpn-update.*' \) | grep -q . \
  || fail "the cancelled update left files behind"

# The quit flows' edge cases (the cancelled update's files are checked above).
[ "$(name "$QUIT")" = "QUIT OK" ] || fail "quit flows: $(name "$QUIT")"

# The Dock icon (NSApp.activationPolicy): shown while a window is open, a Dock click brings back
# a minimized window and opens none, hidden once the windows are closed and while only an MFA prompt is open.
if [ "$SMOKE_OS" = macos ]; then
  grep -q '^MacVPN smoke: dock: windows open regular=true$' "$LOG" || fail "no Dock icon with the windows open"
  grep -Eq '^MacVPN smoke: dock: reopen minimized=true restored=true windows=([0-9])->\1$' "$LOG" || fail "the Dock click"
  grep -q '^MacVPN smoke: dock: closed=true regular=false$' "$LOG" || fail "the Dock icon stayed after the windows closed"
  grep -q '^MacVPN smoke: dock: prompt only regular=false$' "$LOG" || fail "a Dock icon for an MFA prompt"
else
  grep -q '^MacVPN smoke: dock: skipped on Windows$' "$LOG" || fail "the Dock step was not skipped"
  grep -q '^MacVPN smoke: windows: closed=true$' "$LOG" || fail "the windows did not close"
fi

# The MFA prompts.
grep -q '^MacVPN smoke: prompt: code ok closed=true$' "$LOG" || fail "the code prompt"
grep -q '^MacVPN smoke: prompt: OpenedUrl closed=true$' "$LOG" || fail "the web sign-in"
grep -q 'web sign-in not opened: sso.example.com$' "$LOG" || fail "the web sign-in URL"

# The credential prompt: only the missing fields asked, the values on "stdin" (never logged), saved after the
# connect succeeded, nothing asked the second time; the re-prompt after a sign-in failure, cancelled silently.
grep -q '^MacVPN smoke: credentials: first fields=username+password retry=false$' "$LOG" || fail "the credential prompt's fields"
grep -q "^MacVPN smoke: fake root: up $CRED username=set password=set$" "$LOG" || fail "the typed credentials did not reach up"
grep -q '^MacVPN smoke: credentials: first connected=true saved=yes closed=true$' "$LOG" || fail "the credential prompt's connect and save"
grep -q '^MacVPN smoke: credentials: second prompt=false connected=true$' "$LOG" || fail "a prompt for stored credentials"
grep -q '^MacVPN smoke: credentials: retry fields=username+password message=true prefilled=true$' "$LOG" || fail "the re-prompt"
[ "$(grep -c "^MacVPN smoke: fake root: up $CRED_RETRY" "$LOG")" = 1 ] || fail "the cancelled re-prompt connected again"
grep -q '^MacVPN smoke: credentials: retry state=disconnected closed=true$' "$LOG" || fail "the cancelled re-prompt"
! grep -q 'smoke-pass-4711\|stored-pass' "$LOG" || fail "the log shows a password"
grep -q '^MacVPN smoke: credentials: largest fields=username+password+psk+keyPassword answer=cancelled closed=true$' "$LOG" \
  || fail "the largest credential window (retry line, four fields, error) does not fit its content"
! grep -q '^MacVPN smoke: credentials: ERROR' "$LOG" || fail "the credential prompt smoke"

# Shared credentials (in the vault): added and linked in the window, the prompt asks once for the password
# and saves it into the credential, the second linked connection asks nothing, Delete copies into each, the
# import asks (with the server) before it links.
grep -q '^MacVPN smoke: shared: linked=true used_by=2 user=true$' "$LOG" || fail "shared credential: add and link"
grep -q '^MacVPN smoke: shared: prompt fields=password credential=Smoke Cred used_by=2$' "$LOG" || fail "shared credential: the prompt"
grep -q "^MacVPN smoke: fake root: up $SHARED_ONE username=set password=set$" "$LOG" || fail "shared credential: the first up"
grep -q '^MacVPN smoke: shared: first connected=true saved_in_credential=true$' "$LOG" || fail "shared credential: saved into the credential"
grep -q '^MacVPN smoke: shared: second prompt=false connected=true$' "$LOG" || fail "shared credential: a prompt for the second connection"
grep -q "^MacVPN smoke: fake root: up $SHARED_TWO username=set password=set$" "$LOG" || fail "shared credential: the second up"
grep -q '^MacVPN smoke: shared: deleted copied=true$' "$LOG" || fail "shared credential: copy into each connection"
grep -q '^MacVPN smoke: shared: import asked=true unlinked_before_answer=true$' "$LOG" || fail "shared credential: the import's question"
grep -q '^MacVPN smoke: shared: import linked=true meta_stripped=true$' "$LOG" || fail "shared credential: the import's link"
! grep -q 'smoke-shared-pass' "$LOG" || fail "the log shows the shared password"
! grep -q '^MacVPN smoke: shared: ERROR' "$LOG" || fail "the shared credential smoke"
# The full backup: the file in the sandbox tmp, 0600, nothing seeded in clear; a wrong password gives the generic
# message, then Merge with Overwrite and Replace everything bring the canary's name back (replace also removes the
# connection added later); the backed-up control API switch is not applied by itself; no password in the log.
grep -q '^MacVPN smoke: backup: saved mode=600 clear=no$' "$LOG" || fail "the backup file (mode, plaintext)"
grep -q '^MacVPN smoke: backup: merge restored=yes$' "$LOG" || fail "the restore with Merge"
grep -q '^MacVPN smoke: backup: replace restored=yes extra-gone=yes control-api=off$' "$LOG" || fail "the restore with Replace everything"
! grep -q 'smoke backup pw\|smoke-canary-secret\|smoke-master-4711' "$LOG" || fail "the log shows a backup secret"
! grep -q '^MacVPN smoke: backup: ERROR' "$LOG" || fail "the backup smoke"
[ ! -e "$HOME_DIR/tmp/smoke.macvpnbackup" ] || fail "the smoke backup file was left behind"
# Publishing: the admin keys, v1 (0644, opens, nothing in clear), v2, the rotation (the old team key refused), the
# backup key exported (offline, 0600) and imported again; no key file password or team key (of either step) in the log.
grep -q '^MacVPN smoke: publish: keys generated=true$' "$LOG" || fail "publishing: the admin keys"
grep -q '^MacVPN smoke: publish: v1 mode=644 opens=v1 clear=no$' "$LOG" || fail "publishing: the first version (mode, opening, plaintext)"
grep -q '^MacVPN smoke: publish: again version=2$' "$LOG" || fail "publishing: the new version"
grep -q '^MacVPN smoke: publish: rotate version=3 old_key_refused=true new_key_opens=v3$' "$LOG" || fail "publishing: the team key rotation"
grep -q '^MacVPN smoke: publish: export offline=true mode=600$' "$LOG" || fail "publishing: the backup key export"
grep -q '^MacVPN smoke: publish: import online=true$' "$LOG" || fail "publishing: the backup key import"
grep -q 'published v3' "$LOG" || fail "publishing: no publish line in the log"
! grep -q 'smoke key file 4711' "$LOG" || fail "the log shows the admin key file password"
! grep -Eq 'TEAM-[0-9A-Z]{4}-' "$LOG" || fail "the log shows a team key"
! grep -q '^MacVPN smoke: publish: ERROR' "$LOG" || fail "the publishing smoke"

# Team catalogs (the subscriber): the fixture is sealed (no name or config line in clear), every UI phase passed, the
# backend agrees after each step, and no team key reached the log.
grep -q '^MacVPN smoke: catalog: fixture written clear=no$' "$LOG" || fail "team catalog: the fixture file"
for p in preview subscribe readonly update ask unsubscribe; do
  grep -q "^MacVPN smoke: catalog: $p: CATALOG $p OK$" "$LOG" || fail "team catalog: the $p phase"
done
grep -Eq '^MacVPN smoke: catalog: subscribed catalogs=1 version=1 items=Smoke Team A\+Smoke Team B read_only=true team_folders=[0-9]+$' "$LOG" \
  || fail "team catalog: the subscription in the backend"
grep -q '^MacVPN smoke: catalog: updated version=2 items=Smoke Team A2+Smoke Team B+Smoke Team C$' "$LOG" || fail "team catalog: version 2"
grep -q '^MacVPN smoke: catalog: unsubscribed catalogs=0 items=0$' "$LOG" || fail "team catalog: unsubscribe"
! grep -q '^MacVPN smoke: catalog: ERROR' "$LOG" || fail "the team catalog smoke"
[ ! -e "$HOME_DIR/tmp/smoke-share" ] || fail "the team catalog files were left behind (the subscriber's fixture or the published files)"

# Files opened from Finder (the open event simulated with sandbox fixtures): the Connections window opens with the
# import's report (one file, two at once), the team catalog file opens the add dialog with the file source (nothing
# subscribed), a file opened while locked waits for the unlock window and is imported after it, a cancelled unlock
# drops it; nothing connects and no path reaches the view model.
grep -q '^MacVPN smoke: open: one window=true imported=true connected=false$' "$LOG" || fail "open: one file"
grep -q '^MacVPN smoke: open: two imported=true connected=false$' "$LOG" || fail "open: two files at once"
for p in one two catalog locked; do
  grep -q "^MacVPN smoke: open: $p: OPEN $p OK$" "$LOG" || fail "open: the $p phase"
done
grep -q '^MacVPN smoke: open: catalog subscribed=0$' "$LOG" || fail "open: the catalog file subscribed something"
grep -q '^MacVPN smoke: open: view_model_paths=no$' "$LOG" || fail "open: a path reached the view model"
grep -q '^MacVPN smoke: open: locked unlock_window=true imported_before_unlock=false$' "$LOG" || fail "open: locked"
grep -q '^MacVPN smoke: open: locked unlocked=true imported=true connected=false$' "$LOG" || fail "open: after the unlock"
grep -q '^MacVPN smoke: open: cancelled closed=true unlocked=true imported=false$' "$LOG" || fail "open: the cancelled unlock"
! grep -q '^MacVPN smoke: open: ERROR' "$LOG" || fail "the open smoke"
! grep -q 'macvpn-smoke-open' "$LOG" || fail "open: the log shows a path of an opened file"

# The control API: the switch, the pairing window, the test client's session, the lease's end, the switch off.
CONTROL_SOCKET="$SUPPORT/control/macvpn.sock"
grep -q '^MacVPN smoke: control: on running=true socket=true$' "$LOG" || fail "the control API did not start"
[ -f "$HOME_DIR/client.json" ] || fail "the test client did not run: $(cat "$HOME_DIR/client.log" 2>/dev/null)"
for s in pair hello list up closed; do
  grep -A1 "\"name\": \"$s\"" "$HOME_DIR/client.json" | grep -q '"ok": true' || fail "test client step $s: $(cat "$HOME_DIR/client.json")"
done
grep -q '"connecting"' "$HOME_DIR/client.json" && grep -q '"connected"' "$HOME_DIR/client.json" || fail "the client got no progress events"
grep -q "^MacVPN smoke: control: paired \[smoke-client:$CONTROL_VPN\] window_closed=true$" "$LOG" || fail "the pairing window"
grep -q '^MacVPN smoke: control: held_by=smoke-client$' "$LOG" || fail "the connection was not held by the client"
[ "$(grep -c "^MacVPN smoke: fake root: up $CONTROL_VPN$" "$LOG")" = 1 ] || fail "the client's up did not connect once"
[ "$(grep -c "^MacVPN smoke: fake root: down $CONTROL_VPN$" "$LOG")" = 1 ] || fail "closing the client's socket did not disconnect once"
grep -q '^MacVPN smoke: control: released disconnected=true$' "$LOG" || fail "the lease's end"
[ "$(name "$CONTROL")" = "CONTROL OK" ] || fail "Paired apps: $(name "$CONTROL")"
grep -q '^MacVPN smoke: control: off running=false socket=false$' "$LOG" || fail "the socket stayed after the switch was turned off"
[ "$SMOKE_OS" = windows ] || [ ! -e "$CONTROL_SOCKET" ] || fail "the control socket is still there"
grep -q 'MacVPN (Control API): paired “smoke-client”' "$LOG" || fail "no audit line for the pairing"
AUDIT="$SUPPORT/control/audit.log"
[ -f "$AUDIT" ] || fail "the audit file is missing"
[ "$SMOKE_OS" = windows ] || [ "$(stat -f %Lp "$AUDIT" 2>/dev/null)" = 600 ] || fail "the audit file is not 0600"
grep -q 'paired “smoke-client”' "$AUDIT" || fail "no pairing in the audit file"
grep -q 'lease on .* ended' "$AUDIT" || fail "no lease end in the audit file"
! grep -qi 'token' "$AUDIT" || fail "the audit file mentions a token"
! grep -qi 'token' "$LOG" || fail "the log mentions a token"
[ ! -e "$SUPPORT/control-clients.json" ] || fail "the paired apps are in control-clients.json, not in the vault"

# The live system VPN list: the debounced reload shows a removed and an added VPN (well before the 5 s poll
# fallback), the open editor turns read-only, the window and the menu follow without being reopened.
grep -q '^MacVPN smoke: live: editor open=true$' "$LOG" || fail "live list: the system VPN's editor did not open"
REMOVED_MS=$(sed -n 's/^MacVPN smoke: live: removed listed=\([0-9]*\) selected_removed=true$/\1/p' "$LOG")
[ -n "$REMOVED_MS" ] && [ "$REMOVED_MS" -lt 2500 ] || fail "live list: the removed VPN was not reloaded in time (${REMOVED_MS:-never} ms)"
ADDED_MS=$(sed -n 's/^MacVPN smoke: live: added listed=\([0-9]*\)$/\1/p' "$LOG")
[ -n "$ADDED_MS" ] && [ "$ADDED_MS" -lt 2500 ] || fail "live list: the added VPN was not reloaded in time (${ADDED_MS:-never} ms)"
[ "$(name "$LIVE")" = "LIVE OK" ] || fail "live list, Connections window: $(name "$LIVE")"
[ "$(name "$LIVE_MENU")" = "MENU OK" ] || fail "live list, menu: $(name "$LIVE_MENU")"
# (Windows: the native step's own L2TP entry, `WinVPN-<UUID>`, is started on purpose.)
! grep '^MacVPN smoke: fake native: start ' "$LOG" | grep -qv '^MacVPN smoke: fake native: start WinVPN-' \
  || fail "live list: a fake system VPN was started"

# Folders and colours: created (named in place, the default name in the run's language), nested, coloured (the
# subfolder inherits), a connection dragged into the subfolder, collapsed, the subfolder deleted with its contents
# moved up into the folder.
[ "$(name "$FOLDERS")" = "FOLDERS OK" ] || fail "folders: $(name "$FOLDERS")"
grep -q '^MacVPN smoke: folders: store work=true colour=teal subfolders=0 item_in_work=true$' "$LOG" || fail "folders: the stored tree"

# The 2.0 features: the Appearance setting in the popover and the Connections window; a missing engine's row, New
# menu and import, and the row back once installed; the connection notices and their switch; auto-reconnect.
for SECTION in appearance engines notices reconnect; do
  grep -q "^MacVPN smoke: $SECTION: ok$" "$LOG" || fail "$SECTION: $(grep "^MacVPN smoke: $SECTION: " "$LOG" | tail -1)"
done
grep -q '^MacVPN smoke: notice: Zz Notices' "$LOG" || fail "notices: nothing was recorded"
! grep -q '^MacVPN smoke: features: ERROR' "$LOG" || fail "the 2.0 features' connections"

# WinVPN 2c's native VPNs (Windows only): the step's verdict, and no secret of it in the log.
if [ "$SMOKE_OS" = windows ]; then
  grep '^MacVPN smoke: ras: ' "$LOG" || true
  grep -q '^MacVPN smoke: ras: ok$' "$LOG" || fail "native VPNs: $(grep '^MacVPN smoke: ras: ' "$LOG" | tail -1)"
  ! grep -q 'smoke-ras-pass\|smoke-ras-psk\|smoke-ras-helper-pass' "$LOG" || fail "the log shows a native VPN secret"
fi

# The menu popover's rounded corners (borderless window: non-opaque, its content layer masked, with a shadow).
if [ "$SMOKE_OS" = macos ]; then
  grep -Eq '^MacVPN smoke: menu: shape radius=12 masks=true opaque=false shadow=true window=[0-9]+$' "$LOG" || fail "the menu's rounded corners"
else
  # Windows 11 (build 22000 and later) rounds the popover through DWM; Windows 10 has no round corners.
  WIN_BUILD=$(cmd //c ver 2>/dev/null | sed -n 's/.*Version [0-9]*\.[0-9]*\.\([0-9]*\).*/\1/p')
  if [ "${WIN_BUILD:-0}" -ge 22000 ]; then CORNERS=true; else CORNERS=false; fi
  grep -q "^MacVPN smoke: menu: corners round=$CORNERS\$" "$LOG" \
    || fail "the menu's corners (build ${WIN_BUILD:-?}): $(grep '^MacVPN smoke: menu: ' "$LOG" | tail -1)"
fi

# Quitting the way logout does (macOS: a quit Apple Event; Windows: WM_QUERYENDSESSION, sent by the app's driver to
# its own lifecycle window): the system's request is answered "later" (blocked for now), the Connections window asks
# about the unsaved change (system.js answers Discard), then the app quits.
grep -q '^MacVPN smoke: system: unsaved change ready$' "$LOG" || fail "no unsaved change for the quit test"
if [ "$SMOKE_OS" = windows ]; then
  grep -q '^MacVPN smoke: system: quit request blocked=true$' "$LOG" \
    || fail "the quit request: $(grep '^MacVPN smoke: system: quit' "$LOG" | tail -1)"
else
  cat > "$HOME_DIR/terminate.swift" <<SWIFT
import AppKit
exit(NSRunningApplication(processIdentifier: $PID)?.terminate() == true ? 0 : 1)
SWIFT
  swift "$HOME_DIR/terminate.swift" || fail "could not send the quit request"
fi
for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
! kill -0 "$PID" 2>/dev/null || fail "the app did not quit after the quit question"
[ "$(name 66666666-7777-4888-9999-AAAAAAAAAAAA)" = "SYSTEM ASKED" ] || fail "the system's quit request did not ask"
[ "$(name "$A")" = "SMOKE OK" ] || fail "the discarded change was saved"
if [ "$SMOKE_OS" = windows ]; then
  echo "✓ smoke test passed on Windows (${LANGUAGE}; vault create, migration, Lock Now, locked menu, unlock, recovery, password change, Connections, System Status, Update, MFA prompts, credential prompt, control API, live system list, folders, shared credentials, full backup and restore, team catalog subscription, files opened from Explorer, publishing, appearance, missing engines, notices, auto-reconnect, native VPNs (L2TP, IKEv2, SSTP, Cisco copy), menu corners (round=$CORNERS), quit flows, quit request; skipped: Dock, screenshots)${PLACEMENT_SKIPPED}"
  exit 0
fi
echo "✓ smoke test passed (${LANGUAGE}; vault create, migration, Lock Now, locked menu, unlock, recovery, password change, Connections, System Status, Update, Dock icon, MFA prompts, credential prompt, control API, live system list, folders, shared credentials, full backup and restore, team catalog subscription, files opened from Finder, publishing, appearance, missing engines, notices, auto-reconnect, menu shape, quit flows, quit request)${PLACEMENT_SKIPPED}"
