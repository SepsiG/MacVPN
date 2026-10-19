#!/bin/bash
# Sandboxed smoke test of the app's windows (Tauri app, debug build with the embedded UI). Seeds connections in a
# throwaway MACVPN_SANDBOX_HOME and starts the app with MACVPN_SMOKE_DIR=scripts/smoke, which runs, through the
# real UI:
#   manage.js – the Connections window (risky panel, acknowledgement, unsaved-changes question, Log tab, SSTP and
#               native forms, stored secrets never shown, New and Delete, a navigation away cancelled);
#   setup.js  – System Status over a mock report (rows, the reinstall notice, the simulated brew output, the root
#               installer and the uninstaller answering "cancelled" in the sandbox);
#   update.js – the Update window over a mock release (notes stay text), Download and Install up to the quit
#               questions, cancelled at "Unsaved Changes";
#   (the Dock icon: shown while those windows are open, a Dock click, hidden after they close)
#   prompt.js – a mock MFA code prompt and web sign-in in their prompt windows (no Dock icon meanwhile);
#   credentials.js – the credential prompt of a seeded OpenVPN connection with a bare auth-user-pass and nothing
#               stored: the user name and password typed, saved (in memory) once connected, no prompt on the
#               second connect; then the one re-prompt after a sign-in failure, cancelled without a failure;
#   control.js, pairing.js, control-client.mjs – the control API: the Paired apps switch turns the socket on, the
#               test client (Node) pairs (approved in the pairing window), says hello, lists, brings a seeded
#               connection up (the smoke's stand-in root helper: nothing runs) and closes its socket, which takes
#               the connection down; then the switch turns it off and the socket is gone;
#   live.js, live-menu.js – the live system VPN list: the run's system VPNs are a stand-in list the app's smoke
#               driver changes (no scutil, no real VPN); with the Connections window open, a fake system VPN's
#               detail turns read-only with the "removed from macOS" banner when the driver removes it, and a VPN
#               the driver adds appears in the window and in the menu popover without reopening either;
#   quit.js   – the quit flows' edge cases: a selection while the quit's "Unsaved Changes" is shown, the Update
#               window closed during an install and while its quit question is shown (the update is cancelled);
#   system.js – an unsaved change; the shell then quits the app the way logout does (a quit Apple Event) and
#               checks that the Connections window asked first and the app then quit.
# Then it checks the store and the log.
# SMOKE_LANG=en|hu forces the app's language the way macOS selects it (the AppleLanguages preference, here in the
# app's argument domain: -AppleLanguages '(hu)'); the run checks that the core picked it and the windows show it. Never touches the real Application Support, Keychain, preferences or
# system (the sandbox keeps secrets and preferences in memory, opens nothing, runs no installer).
set -euo pipefail
cd "$(dirname "$0")/.."

APP=${APP:-target/debug/macvpn-app}
[ -x "$APP" ] || { echo "build first: (cd app/ui && npm run build) && cargo build -p macvpn-app --features custom-protocol" >&2; exit 2; }
# A short path: the control socket (<home>/Library/Application Support/MacVPN/control/macvpn.sock) must fit a
# Unix socket address (104 bytes), which $TMPDIR (/var/folders/…) would not leave room for.
HOME_DIR=$(mktemp -d /tmp/macvpn-smoke.XXXXXX)
NODE=$(command -v node || echo /opt/homebrew/bin/node)
[ -x "$NODE" ] || { echo "the control API test client needs node" >&2; exit 2; }
# SMOKE_LOG=<file>: keep the app's log.
trap 'kill "$PID" 2>/dev/null || true; [ -z "${SMOKE_LOG:-}" ] || cp "$LOG" "$SMOKE_LOG"; rm -rf "$HOME_DIR"' EXIT
STORE="$HOME_DIR/Library/Application Support/MacVPN/connections"
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
CRED=A1111111-2222-4333-8444-555555555555
CRED_RETRY=B1111111-2222-4333-8444-555555555555
OVPN='client\ndev tun\nremote vpn.example.com 1194\n'
seed "$A" openvpn "Seeded A" "$OVPN"
seed 66666666-7777-4888-9999-AAAAAAAAAAAA openvpn "Seeded B" "$OVPN"
seed "$S" sstp "Seeded S" 'server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n'
seed "$L" l2tp "Seeded L" '' ',"native":{"server":"l2tp.example.com","account":"bob","groupName":"","sendAllTraffic":true}'
seed "$SETUP" openvpn "Zz Setup result" "$OVPN"
seed "$UPDATE" openvpn "Zz Update result" "$OVPN"
seed "$QUIT" openvpn "Zz Quit result" "$OVPN"
seed "$CONTROL" openvpn "Zz Control result" "$OVPN"
seed "$CONTROL_VPN" openvpn "Zz Control VPN" "$OVPN"
seed "$LIVE" openvpn "Zz Live result" "$OVPN"
seed "$LIVE_MENU" openvpn "Zz Live menu result" "$OVPN"
seed "$CRED" openvpn "Zz Credentials" "${OVPN}auth-user-pass\n"
seed "$CRED_RETRY" openvpn "Zz Credentials retry" "${OVPN}auth-user-pass\n"

LANG_ARGS=()
case "${SMOKE_LANG:-}" in
  '') ;;
  en|hu) LANG_ARGS=(-AppleLanguages "(${SMOKE_LANG})") ;;
  *) echo "SMOKE_LANG: en or hu" >&2; exit 2 ;;
esac
MACVPN_SANDBOX_HOME="$HOME_DIR" MACVPN_SMOKE_DIR="$PWD/scripts/smoke" "$APP" ${LANG_ARGS[@]+"${LANG_ARGS[@]}"} > "$LOG" 2>&1 &
PID=$!
CLIENT_PID=
for _ in $(seq 1 300); do
  sleep 1
  if grep -q '^MacVPN smoke: done' "$LOG" 2>/dev/null; then break; fi
  # The control API's test client, once the app listens.
  if [ -z "$CLIENT_PID" ] && grep -q '^MacVPN smoke: control: listening ' "$LOG" 2>/dev/null; then
    SOCKET=$(sed -n 's/^MacVPN smoke: control: listening //p' "$LOG" | head -1)
    "$NODE" scripts/smoke/control-client.mjs "$SOCKET" "$CONTROL_VPN" "$HOME_DIR/client.json" > "$HOME_DIR/client.log" 2>&1 &
    CLIENT_PID=$!
  fi
done
[ -z "$CLIENT_PID" ] || wait "$CLIENT_PID" || true
name() { sed -n 's/.*"name" : "\(.*\)",*/\1/p' "$STORE/$1/meta.json"; }
echo "manage: $(name "$A")"
echo "setup:  $(name "$SETUP")"
echo "update: $(name "$UPDATE")"
echo "quit:   $(name "$QUIT")"
echo "control: $(name "$CONTROL")"
echo "live:   $(name "$LIVE") / $(name "$LIVE_MENU")"
grep '^MacVPN smoke: prompt' "$LOG" || true
grep '^MacVPN smoke: control' "$LOG" || true
grep '^MacVPN smoke: live' "$LOG" || true
grep '^MacVPN smoke: credentials' "$LOG" || true
fail() { echo "✗ $1"; sed 's/^/  app: /' "$LOG"; exit 1; }
grep -q '^MacVPN smoke: done' "$LOG" || fail "the smoke run did not finish"
LANGUAGE=$(sed -n 's/^MacVPN smoke: language //p' "$LOG")
echo "language: ${LANGUAGE}"
[ -z "${SMOKE_LANG:-}" ] || [ "$LANGUAGE" = "$SMOKE_LANG" ] || fail "the app picked ${LANGUAGE}, not ${SMOKE_LANG}"

# The Connections window.
grep -q '"user"' "$STORE/$A/meta.json" || fail "the acknowledgement was not stored"
grep -q '^user nobody$' "$STORE/$A/config" || fail "the config was not saved"
[ "$(name "$A")" = "SMOKE OK" ] || fail "Connections window: $(name "$A")"
grep -q '^port=8443$' "$STORE/$S/config" || fail "the SSTP form was not saved"
PROFILE=$(find "$HOME_DIR/tmp" -path '*/macvpn-profile.*/Seeded L2.mobileconfig' | head -1)
[ -n "$PROFILE" ] || fail "the native profile was not staged"
[ "$(stat -f %Lp "$PROFILE")" = 600 ] || fail "the staged profile is not 0600"
! grep -rq native-secret "$HOME_DIR/tmp" || fail "the password is in a staged profile"
[ "$(ls "$STORE" | wc -l | tr -d ' ')" = 13 ] || fail "create / delete left $(ls "$STORE" | wc -l | tr -d ' ') connections"
[ "$(stat -f %Lp "$STORE/$A/meta.json")" = 600 ] || fail "meta.json is not 0600"

# System Status and Update.
[ "$(name "$SETUP")" = "SETUP OK" ] || fail "System Status window: $(name "$SETUP")"
[ "$(name "$UPDATE")" = "UPDATE OK" ] || fail "Update window: $(name "$UPDATE")"
! find "$HOME_DIR/tmp" -maxdepth 1 \( -name 'macvpn-download.*' -o -name 'macvpn-mount.*' -o -name 'macvpn-update.*' \) | grep -q . \
  || fail "the cancelled update left files behind"

# The quit flows' edge cases (the cancelled update's files are checked above).
[ "$(name "$QUIT")" = "QUIT OK" ] || fail "quit flows: $(name "$QUIT")"

# The Dock icon (NSApp.activationPolicy): shown while a window is open, a Dock click brings back
# a minimized window and opens none, hidden once the windows are closed and while only an MFA prompt is open.
grep -q '^MacVPN smoke: dock: windows open regular=true$' "$LOG" || fail "no Dock icon with the windows open"
grep -Eq '^MacVPN smoke: dock: reopen minimized=true restored=true windows=([0-9])->\1$' "$LOG" || fail "the Dock click"
grep -q '^MacVPN smoke: dock: closed=true regular=false$' "$LOG" || fail "the Dock icon stayed after the windows closed"
grep -q '^MacVPN smoke: dock: prompt only regular=false$' "$LOG" || fail "a Dock icon for an MFA prompt"

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
! grep -q '^MacVPN smoke: credentials: ERROR' "$LOG" || fail "the credential prompt smoke"

# The control API: the switch, the pairing window, the test client's session, the lease's end, the switch off.
CONTROL_SOCKET="$HOME_DIR/Library/Application Support/MacVPN/control/macvpn.sock"
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
[ ! -e "$CONTROL_SOCKET" ] || fail "the control socket is still there"
grep -q 'MacVPN (Control API): paired “smoke-client”' "$LOG" || fail "no audit line for the pairing"
AUDIT="$HOME_DIR/Library/Application Support/MacVPN/control/audit.log"
[ "$(stat -f %Lp "$AUDIT" 2>/dev/null)" = 600 ] || fail "the audit file is missing or not 0600"
grep -q 'paired “smoke-client”' "$AUDIT" || fail "no pairing in the audit file"
grep -q 'lease on .* ended' "$AUDIT" || fail "no lease end in the audit file"
! grep -qi 'token' "$AUDIT" || fail "the audit file mentions a token"
! grep -qi 'token' "$LOG" || fail "the log mentions a token"
[ "$(stat -f %Lp "$HOME_DIR/Library/Application Support/MacVPN/control-clients.json")" = 600 ] || fail "control-clients.json is not 0600"

# The live system VPN list: the debounced reload shows a removed and an added VPN (well before the 5 s poll
# fallback), the open editor turns read-only, the window and the menu follow without being reopened.
grep -q '^MacVPN smoke: live: editor open=true$' "$LOG" || fail "live list: the system VPN's editor did not open"
REMOVED_MS=$(sed -n 's/^MacVPN smoke: live: removed listed=\([0-9]*\) selected_removed=true$/\1/p' "$LOG")
[ -n "$REMOVED_MS" ] && [ "$REMOVED_MS" -lt 2500 ] || fail "live list: the removed VPN was not reloaded in time (${REMOVED_MS:-never} ms)"
ADDED_MS=$(sed -n 's/^MacVPN smoke: live: added listed=\([0-9]*\)$/\1/p' "$LOG")
[ -n "$ADDED_MS" ] && [ "$ADDED_MS" -lt 2500 ] || fail "live list: the added VPN was not reloaded in time (${ADDED_MS:-never} ms)"
[ "$(name "$LIVE")" = "LIVE OK" ] || fail "live list, Connections window: $(name "$LIVE")"
[ "$(name "$LIVE_MENU")" = "MENU OK" ] || fail "live list, menu: $(name "$LIVE_MENU")"
! grep -q '^MacVPN smoke: fake native: start ' "$LOG" || fail "live list: a fake system VPN was started"

# Quitting the way logout does (a quit Apple Event): applicationShouldTerminate answers "later", the Connections
# window asks about the unsaved change (system.js answers Discard), then the app quits.
grep -q '^MacVPN smoke: system: unsaved change ready$' "$LOG" || fail "no unsaved change for the quit test"
cat > "$HOME_DIR/terminate.swift" <<SWIFT
import AppKit
exit(NSRunningApplication(processIdentifier: $PID)?.terminate() == true ? 0 : 1)
SWIFT
swift "$HOME_DIR/terminate.swift" || fail "could not send the quit request"
for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
! kill -0 "$PID" 2>/dev/null || fail "the app did not quit after the quit question"
[ "$(name 66666666-7777-4888-9999-AAAAAAAAAAAA)" = "SYSTEM ASKED" ] || fail "the system's quit request did not ask"
[ "$(name "$A")" = "SMOKE OK" ] || fail "the discarded change was saved"
echo "✓ smoke test passed (${LANGUAGE}; Connections, System Status, Update, Dock icon, MFA prompts, credential prompt, control API, live system list, quit flows, quit request)"
