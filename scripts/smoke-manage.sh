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
#   prompt.js – a mock MFA code prompt and web sign-in in their prompt windows;
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
HOME_DIR=$(mktemp -d "${TMPDIR:-/tmp}/macvpn-smoke.XXXXXX")
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
OVPN='client\ndev tun\nremote vpn.example.com 1194\n'
seed "$A" openvpn "Seeded A" "$OVPN"
seed 66666666-7777-4888-9999-AAAAAAAAAAAA openvpn "Seeded B" "$OVPN"
seed "$S" sstp "Seeded S" 'server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n'
seed "$L" l2tp "Seeded L" '' ',"native":{"server":"l2tp.example.com","account":"bob","groupName":"","sendAllTraffic":true}'
seed "$SETUP" openvpn "Zz Setup result" "$OVPN"
seed "$UPDATE" openvpn "Zz Update result" "$OVPN"
seed "$QUIT" openvpn "Zz Quit result" "$OVPN"

LANG_ARGS=()
case "${SMOKE_LANG:-}" in
  '') ;;
  en|hu) LANG_ARGS=(-AppleLanguages "(${SMOKE_LANG})") ;;
  *) echo "SMOKE_LANG: en or hu" >&2; exit 2 ;;
esac
MACVPN_SANDBOX_HOME="$HOME_DIR" MACVPN_SMOKE_DIR="$PWD/scripts/smoke" "$APP" ${LANG_ARGS[@]+"${LANG_ARGS[@]}"} > "$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 180); do
  sleep 1
  if grep -q '^MacVPN smoke: done' "$LOG" 2>/dev/null; then break; fi
done
name() { sed -n 's/.*"name" : "\(.*\)",*/\1/p' "$STORE/$1/meta.json"; }
echo "manage: $(name "$A")"
echo "setup:  $(name "$SETUP")"
echo "update: $(name "$UPDATE")"
echo "quit:   $(name "$QUIT")"
grep '^MacVPN smoke: prompt' "$LOG" || true
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
[ "$(ls "$STORE" | wc -l | tr -d ' ')" = 7 ] || fail "create / delete left $(ls "$STORE" | wc -l | tr -d ' ') connections"
[ "$(stat -f %Lp "$STORE/$A/meta.json")" = 600 ] || fail "meta.json is not 0600"

# System Status and Update.
[ "$(name "$SETUP")" = "SETUP OK" ] || fail "System Status window: $(name "$SETUP")"
[ "$(name "$UPDATE")" = "UPDATE OK" ] || fail "Update window: $(name "$UPDATE")"
! find "$HOME_DIR/tmp" -maxdepth 1 \( -name 'macvpn-download.*' -o -name 'macvpn-mount.*' -o -name 'macvpn-update.*' \) | grep -q . \
  || fail "the cancelled update left files behind"

# The quit flows' edge cases (the cancelled update's files are checked above).
[ "$(name "$QUIT")" = "QUIT OK" ] || fail "quit flows: $(name "$QUIT")"

# The MFA prompts.
grep -q '^MacVPN smoke: prompt: code ok closed=true$' "$LOG" || fail "the code prompt"
grep -q '^MacVPN smoke: prompt: OpenedUrl closed=true$' "$LOG" || fail "the web sign-in"
grep -q 'web sign-in not opened: sso.example.com$' "$LOG" || fail "the web sign-in URL"

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
echo "✓ smoke test passed (${LANGUAGE}; Connections, System Status, Update, MFA prompts, quit flows, quit request)"
