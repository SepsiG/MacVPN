#!/bin/sh
# OpenVPN auth-user-pass-verify (via-file): $1 holds the user name and the password.
# - LAB_USER and LAB_FULL_USER (the server pushes redirect-gateway to it: ccd/): the password.
# - LAB_OTP_USER: the password with the code appended (separator none, "," or ":"), a static challenge response
#   (SCRV1:base64(password):base64(code)), or the password alone, answered with a dynamic challenge (CRV1); the
#   CRV1 response (CRV1::<state>::<code>) then completes it.
set -eu
# shellcheck source=/dev/null
. /state/server/openvpn-users.env
user="$(sed -n 1p "$1")"
pass="$(sed -n 2p "$1")"
state_file="/tmp/crv1-state"
b64d() { printf '%s' "$1" | base64 -d 2>/dev/null || true; }

if [ "$user" = "$LAB_USER" ] || [ "$user" = "${LAB_FULL_USER:-}" ]; then
  [ "$pass" = "$LAB_PASSWORD" ] && exit 0
  exit 1
fi
[ "$user" = "$LAB_OTP_USER" ] || exit 1
case "$pass" in
  SCRV1:*:*)
    p="$(b64d "$(printf '%s' "$pass" | cut -d: -f2)")"
    c="$(b64d "$(printf '%s' "$pass" | cut -d: -f3)")"
    [ "$p" = "$LAB_PASSWORD" ] && [ "$c" = "$LAB_OTP_CODE" ] && exit 0
    exit 1 ;;
  CRV1::*::*)
    state="$(printf '%s' "$pass" | cut -d: -f3)"
    code="$(printf '%s' "$pass" | cut -d: -f5)"
    if [ -s "$state_file" ] && [ "$state" = "$(cat "$state_file")" ] && [ "$code" = "$LAB_OTP_CODE" ]; then
      rm -f "$state_file"; exit 0
    fi
    exit 1 ;;
  "$LAB_PASSWORD$LAB_OTP_CODE"|"$LAB_PASSWORD,$LAB_OTP_CODE"|"$LAB_PASSWORD:$LAB_OTP_CODE")
    exit 0 ;;
  "$LAB_PASSWORD")
    state="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
    printf '%s' "$state" >"$state_file"
    if [ -n "${auth_failed_reason_file:-}" ]; then
      printf 'CRV1:R,E:%s:%s:%s' "$state" "$(printf '%s' "$user" | base64)" "Enter the lab one-time code" \
        >"$auth_failed_reason_file"
    fi
    exit 1 ;;
esac
exit 1
