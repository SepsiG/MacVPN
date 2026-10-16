#!/bin/bash
# A Resources/root/mvpn tesztje nem-root, dry-run módban.
set -u
cd "$(dirname "$0")/.."
MVPN="$PWD/Resources/root/mvpn"
SH=/bin/bash   # a rendszer bash 3.2-vel kell működnie (root alatt ez fut)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
swift build --product mvpn-validate >/dev/null || { echo "mvpn-validate build sikertelen"; exit 1; }
export MVPN_VALIDATOR="$PWD/.build/debug/mvpn-validate"
export MVPN_SRC_BASE="$T/src" MVPN_RUN_BASE="$T/run" MVPN_LOG_BASE="$T/log"
mkdir -p "$MVPN_SRC_BASE"
# Hamis "openvpn" folyamat: symlink a /bin/sleep-re (a másolatot az aláírás-ellenőrzés megölné),
# így a ps comm neve openvpn-re végződik.
mkdir -p "$T/bin"; ln -s /bin/sleep "$T/bin/openvpn"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "ok   - $1"; }
nok()  { FAIL=$((FAIL+1)); echo "FAIL - $1"; }

new_conn() { # $1=config tartalom → id kiírva
  local id; id=$(uuidgen)
  mkdir -p "$MVPN_SRC_BASE/$id"
  printf '%s\n' "$1" > "$MVPN_SRC_BASE/$id/config"
  echo "$id"
}
expect_ok()   { if "$@" </dev/null >"$T/out" 2>&1; then ok "$DESC"; else nok "$DESC"; cat "$T/out"; fi; }
expect_fail() { if "$@" </dev/null >"$T/out" 2>&1; then nok "$DESC"; cat "$T/out"; else ok "$DESC"; fi; }

GOOD_OVPN=$'client\ndev tun\nremote vpn.example.com 1194\nauth-user-pass\n<ca>\nup /x\n</ca>'
GOOD_WG=$'[Interface]\nPrivateKey = aGVsbG8=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = d29ybGQ=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820'
NL=$'\n'
GOOD_SWAN=$'connections {\n  office {\n    remote_addrs = vpn.example.com\n    children {\n      office-net {\n        remote_ts = 0.0.0.0/0\n      }\n    }\n  }\n}'

DESC="version";              expect_ok "$SH" "$MVPN" version
DESC="status üres";          expect_ok "$SH" "$MVPN" status
[ "$("$SH" "$MVPN" status)" = "[]" ] && ok "status = []" || nok "status = []"

DESC="jó openvpn dry-run";   expect_ok "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")" --dry-run
DESC="jó wireguard dry-run"; expect_ok "$SH" "$MVPN" up wireguard "$(new_conn "$GOOD_WG")" --dry-run
DESC="jó strongswan dry-run";expect_ok "$SH" "$MVPN" up strongswan "$(new_conn "$GOOD_SWAN")" --dry-run

for d in up down route-up plugin script-security config daemon log-append management user group pkcs11-providers; do
  DESC="openvpn tiltott: $d"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\n'"$d /tmp/x")" --dry-run
done
DESC="openvpn --up forma";   expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\n--up /tmp/x')" --dry-run
DESC="openvpn külső ca";     expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nca /etc/ca.crt')" --dry-run
DESC="openvpn setenv BASH_ENV"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nsetenv BASH_ENV /tmp/x')" --dry-run
DESC="openvpn setenv opt up";  expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nsetenv opt up /tmp/x')" --dry-run
DESC="openvpn remote nélkül";expect_fail "$SH" "$MVPN" up openvpn "$(new_conn $'client\ndev tun')" --dry-run
for k in PreUp PostUp PreDown PostDown SaveConfig; do
  DESC="wireguard tiltott: $k"; expect_fail "$SH" "$MVPN" up wireguard "$(new_conn "${GOOD_WG/Address/$k = echo hi${NL}Address}")" --dry-run
done
DESC="strongswan updown";    expect_fail "$SH" "$MVPN" up strongswan "$(new_conn "${GOOD_SWAN/remote_ts/updown = x${NL}remote_ts}")" --dry-run
DESC="strongswan include";   expect_fail "$SH" "$MVPN" up strongswan "$(new_conn "include /etc/x"$'\n'"$GOOD_SWAN")" --dry-run

DESC="validátor hiányzik";   expect_fail env MVPN_VALIDATOR=/nonexistent "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")" --dry-run
DESC="nem UUID id";          expect_fail "$SH" "$MVPN" up openvpn "../../etc" --dry-run
DESC="ismeretlen kind";      expect_fail "$SH" "$MVPN" up pptp "$(uuidgen)" --dry-run
DESC="hiányzó config";       expect_fail "$SH" "$MVPN" up openvpn "$(uuidgen)" --dry-run
SID=$(uuidgen); mkdir -p "$MVPN_SRC_BASE/$SID"; ln -s /etc/hosts "$MVPN_SRC_BASE/$SID/config"
DESC="symlink config";       expect_fail "$SH" "$MVPN" up openvpn "$SID" --dry-run
SID=$(uuidgen); mkdir -p "$T/elsewhere"; printf '%s\n' "$GOOD_OVPN" >"$T/elsewhere/config"; ln -s "$T/elsewhere" "$MVPN_SRC_BASE/$SID"
DESC="symlink kapcsolat-könyvtár"; expect_fail "$SH" "$MVPN" up openvpn "$SID" --dry-run
SID=$(new_conn "$GOOD_OVPN"); ln "$MVPN_SRC_BASE/$SID/config" "$T/hardlink"
DESC="hardlinkelt config";   expect_fail "$SH" "$MVPN" up openvpn "$SID" --dry-run
DESC="up dry-run nélkül nem-rootként"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")"
DESC="dry-run nem hagy futási könyvtárat"
[ -z "$(ls "$MVPN_RUN_BASE" 2>/dev/null)" ] && ok "$DESC" || { nok "$DESC"; ls -la "$MVPN_RUN_BASE"; }

# Jelszó maszkolás és naplóformátum
MID=$(new_conn "$GOOD_OVPN")
printf 'username=bob\npassword=Sup3rTitok\n' | "$SH" "$MVPN" up openvpn "$MID" --dry-run --debug >/dev/null 2>&1
LOG="$MVPN_LOG_BASE/$MID.log"
grep -q '^═══ ' "$LOG" && ok "napló fejléc" || nok "napló fejléc"
grep -q '^\$ ' "$LOG" && ok "napló parancssor" || nok "napló parancssor"
grep -q '^▶ \[mvpn\]' "$LOG" && ok "napló lépés" || nok "napló lépés"
grep -q 'Sup3rTitok' "$LOG" && nok "jelszó nem kerülhet a naplóba" || ok "jelszó nem kerül a naplóba"
grep -q 'export MVPN_MASK' "$MVPN" && nok "titkok nincsenek exportálva" || ok "titkok nincsenek exportálva"
SWID=$(new_conn "$GOOD_SWAN")
printf 'username=alice\npassword=EapTitok42\npsk=PskTitok99\n' | "$SH" "$MVPN" up strongswan "$SWID" --dry-run --debug >"$T/sw.out" 2>&1
grep -q 'EapTitok42\|PskTitok99' "$MVPN_LOG_BASE/$SWID.log" "$T/sw.out" && nok "strongswan titok nem kerül a naplóba" || ok "strongswan titok nem kerül a naplóba"
grep -q 'DRY: .*charon' "$T/sw.out" && grep -q 'DRY: .*--initiate --child office-net' "$T/sw.out" && ok "strongswan dry-run parancsok" || { nok "strongswan dry-run parancsok"; cat "$T/sw.out"; }
OUT=$(printf 'a Sup3rTitok b\n' | MVPN_MASK_1=Sup3rTitok "$SH" "$MVPN" __mask)
[ "$OUT" = "a *** b" ] && ok "mask függvény" || nok "mask függvény ($OUT)"
OUT=$(printf 'x.*y [a] x.*y\n' | MVPN_MASK_2='x.*y' "$SH" "$MVPN" __mask)
[ "$OUT" = "*** [a] ***" ] && ok "mask literális" || nok "mask literális ($OUT)"

# Kapcsolatonkénti zár. Tesztmódban a dry-run is a valódi zár-útvonalon megy (a futási könyvtár itt
# a teszt temp könyvtára); az MVPN_LOCK_TRIES csak tesztmódban rövidíti a várakozást.
mkdir -p "$MVPN_RUN_BASE"
dead_pid() { sh -c 'exit 0' & local p=$!; wait "$p"; echo "$p"; }
LID=$(new_conn "$GOOD_OVPN")
DESC="zár feloldva sikeres futás után"; expect_ok "$SH" "$MVPN" up openvpn "$LID" --dry-run
[ ! -e "$MVPN_RUN_BASE/.$LID.lock" ] && ok "zár könyvtár törölve" || nok "zár könyvtár törölve"

mkdir "$MVPN_RUN_BASE/.$LID.lock"; dead_pid >"$MVPN_RUN_BASE/.$LID.lock/pid"
DESC="elárvult zár (halott pid) nem blokkol"; expect_ok env MVPN_LOCK_TRIES=2 "$SH" "$MVPN" up openvpn "$LID" --dry-run
[ ! -e "$MVPN_RUN_BASE/.$LID.lock" ] && ok "elárvult zár eltávolítva" || nok "elárvult zár eltávolítva"

mkdir "$MVPN_RUN_BASE/.$LID.lock"; touch -t 202001010000 "$MVPN_RUN_BASE/.$LID.lock"
DESC="régi, pid nélküli zár nem blokkol"; expect_ok env MVPN_LOCK_TRIES=2 "$SH" "$MVPN" up openvpn "$LID" --dry-run

mkdir "$MVPN_RUN_BASE/.$LID.lock"
DESC="friss, pid nélküli zár blokkol"; expect_fail env MVPN_LOCK_TRIES=2 "$SH" "$MVPN" down openvpn "$LID" --dry-run
rm -rf "$MVPN_RUN_BASE/.$LID.lock"

sleep 60 & HOLDER=$!
mkdir "$MVPN_RUN_BASE/.$LID.lock"; echo "$HOLDER" >"$MVPN_RUN_BASE/.$LID.lock/pid"
DESC="élő zár blokkol";      expect_fail env MVPN_LOCK_TRIES=2 "$SH" "$MVPN" down openvpn "$LID" --dry-run
[ "$(cat "$MVPN_RUN_BASE/.$LID.lock/pid" 2>/dev/null)" = "$HOLDER" ] && ok "idegen zár érintetlen" || nok "idegen zár érintetlen"

# SIGTERM a zárra várakozás közben: 143-mal lép ki, az idegen zárat nem bántja.
MVPN_LOCK_TRIES=40 "$SH" "$MVPN" down openvpn "$LID" --dry-run </dev/null >/dev/null 2>&1 & W=$!
sleep 1; kill -TERM "$W"; wait "$W"; RC=$?
[ "$RC" = 143 ] && ok "SIGTERM → 143" || nok "SIGTERM → 143 ($RC)"
[ "$(cat "$MVPN_RUN_BASE/.$LID.lock/pid" 2>/dev/null)" = "$HOLDER" ] && ok "SIGTERM után idegen zár érintetlen" || nok "SIGTERM után idegen zár érintetlen"
kill "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null
rm -rf "$MVPN_RUN_BASE/.$LID.lock"

# ovpn-dns: csak a networksetup-ot nem érintő ágak (DNS nélkül / érvénytelen DNS-sel).
OD="$PWD/Resources/root/ovpn-dns"; ODR="$T/odrun"; mkdir -p "$ODR"
env -i script_type=up dev=utun9 ifconfig_local=10.8.0.2 "$SH" "$OD" "$ODR" "$T/od.log"
[ "$(cat "$ODR/iface" 2>/dev/null)" = utun9 ] && [ "$(cat "$ODR/ip" 2>/dev/null)" = 10.8.0.2 ] && ok "ovpn-dns iface/ip" || nok "ovpn-dns iface/ip"
grep -q 'the server sent no DNS' "$T/od.log" && ok "ovpn-dns DNS nélkül (lang fájl nélkül angol)" || nok "ovpn-dns DNS nélkül (lang fájl nélkül angol)"
printf 'hu\n' >"$ODR/lang"
env -i script_type=up dev=utun9 "$SH" "$OD" "$ODR" "$T/od-hu.log"
grep -q 'a szerver nem küldött DNS-t' "$T/od-hu.log" && ok "ovpn-dns magyarul (lang=hu)" || nok "ovpn-dns magyarul (lang=hu)"
rm -f "$ODR/lang"
env -i script_type=up dev=utun9 'foreign_option_1=dhcp-option DNS 1.1.1.1;touch /tmp/x' "$SH" "$OD" "$ODR" "$T/od2.log"
grep -q 'the server sent no DNS' "$T/od2.log" && [ ! -f "$ODR/dns-backup" ] && ok "ovpn-dns érvénytelen DNS elutasítva" || nok "ovpn-dns érvénytelen DNS elutasítva"
DESC="ovpn-dns down mentés nélkül"; expect_ok env -i script_type=down "$SH" "$OD" "$ODR" "$T/od.log"

OUT=$(env -i script_type=check \
  'foreign_option_1=dhcp-option DNS 10.0.0.1' 'foreign_option_2=dhcp-option DNS 1.2.3' \
  'foreign_option_3=dhcp-option DNS ::' 'foreign_option_4=dhcp-option DNS fd00::53' \
  'foreign_option_5=dhcp-option DNS 1:2' 'foreign_option_6=dhcp-option DNS 1.1.1.1.1' \
  'foreign_option_7=dhcp-option DOMAIN corp.example' 'foreign_option_8=dhcp-option DOMAIN -evil' \
  'foreign_option_9=dhcp-option DOMAIN .x' 'foreign_option_10=dhcp-option DOMAIN a b' \
  "$SH" "$OD" "$ODR" "$T/od3.log" | tr '\n' '|')
[ "$OUT" = "DNS 10.0.0.1|DNS fd00::53|DOMAIN corp.example|" ] && ok "ovpn-dns szigorú DNS/DOMAIN" || nok "ovpn-dns szigorú DNS/DOMAIN ($OUT)"
ODR2="$T/odrun2"; mkdir -p "$ODR2"
env -i script_type=up 'dev=utun1;x' 'ifconfig_local=10.0.0.2/24' "$SH" "$OD" "$ODR2" "$T/od4.log"
[ ! -e "$ODR2/iface" ] && [ ! -e "$ODR2/ip" ] && ok "ovpn-dns érvénytelen dev/ip nem íródik" || nok "ovpn-dns érvénytelen dev/ip nem íródik"
grep -q '^    set -f$' "$OD" && ok "ovpn-dns down set -f" || nok "ovpn-dns down set -f"

# down: a típus a futási könyvtárból jön
DID=$(uuidgen); mkdir -p "$MVPN_RUN_BASE/$DID"; echo wireguard >"$MVPN_RUN_BASE/$DID/kind"; echo mv12345678 >"$MVPN_RUN_BASE/$DID/iface"
"$SH" "$MVPN" down openvpn "$DID" --dry-run --lang hu </dev/null >"$T/out" 2>&1
grep -q 'DRY: .*wg-quick down' "$T/out" && grep -q 'típuseltérés' "$MVPN_LOG_BASE/$DID.log" && [ -d "$MVPN_RUN_BASE/$DID" ] \
  && ok "down rossz típussal: a futó típust bontja (dry-run)" || { nok "down rossz típussal: a futó típust bontja (dry-run)"; cat "$T/out"; }
rm -rf "$MVPN_RUN_BASE/$DID"

DID=$(uuidgen); mkdir -p "$MVPN_RUN_BASE/$DID"; echo openvpn >"$MVPN_RUN_BASE/$DID/kind"
"$T/bin/openvpn" 60 & OP=$!; echo "$OP" >"$MVPN_RUN_BASE/$DID/pid"; sleep 0.2
kill -0 "$OP" 2>/dev/null && ok "hamis openvpn fut" || nok "hamis openvpn fut"
DESC="down rossz típussal: openvpn leállítva"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 "$SH" "$MVPN" down strongswan "$DID"
sleep 0.2
! kill -0 "$OP" 2>/dev/null && [ ! -e "$MVPN_RUN_BASE/$DID" ] && ok "down: folyamat leállt, futási könyvtár törölve" || nok "down: folyamat leállt, futási könyvtár törölve"
kill "$OP" 2>/dev/null; wait "$OP" 2>/dev/null

DID=$(uuidgen); mkdir -p "$MVPN_RUN_BASE/$DID"; echo pptp >"$MVPN_RUN_BASE/$DID/kind"
DESC="down érvénytelen kind fájllal: takarítás"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 "$SH" "$MVPN" down openvpn "$DID"
[ ! -e "$MVPN_RUN_BASE/$DID" ] && ok "érvénytelen kind: futási könyvtár törölve" || nok "érvénytelen kind: futási könyvtár törölve"

UT=$(ifconfig -l | tr ' ' '\n' | grep -E '^utun[0-9]+$' | head -1)
if [ -n "$UT" ]; then
  DID=$(uuidgen); WGR="$T/wgrun"; mkdir -p "$MVPN_RUN_BASE/$DID" "$WGR"
  echo wireguard >"$MVPN_RUN_BASE/$DID/kind"; echo mv12345678 >"$MVPN_RUN_BASE/$DID/iface"; echo "$UT" >"$WGR/mv12345678.name"
  DESC="down sikertelen + élő interfész: hibával lép ki"; expect_fail env MVPN_TEST_ALLOW_DOWN=1 MVPN_WG_RUN="$WGR" "$SH" "$MVPN" down wireguard "$DID"
  [ -d "$MVPN_RUN_BASE/$DID" ] && ok "down sikertelen: futási könyvtár megmarad" || nok "down sikertelen: futási könyvtár megmarad"
  rm -rf "$MVPN_RUN_BASE/$DID"
else
  ok "down sikertelen + élő interfész (kihagyva: nincs utun interfész)"
fi
DESC="up nem-rootként dry-run nélkül továbbra is tiltott"; expect_fail env MVPN_TEST_ALLOW_DOWN=1 "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")"

# Dry-run nem nyúl az élő futási könyvtárhoz
LIVE=$(new_conn "$GOOD_OVPN"); mkdir -p "$MVPN_RUN_BASE/$LIVE"; echo marker >"$MVPN_RUN_BASE/$LIVE/pid"
DESC="dry-run up élő futási könyvtár mellett"; expect_ok "$SH" "$MVPN" up openvpn "$LIVE" --dry-run
[ "$(cat "$MVPN_RUN_BASE/$LIVE/pid" 2>/dev/null)" = marker ] && ok "élő futási könyvtár érintetlen" || nok "élő futási könyvtár érintetlen"
ls -d "$MVPN_RUN_BASE/$LIVE".dryrun.* >/dev/null 2>&1 && nok "dry-run könyvtár törölve" || ok "dry-run könyvtár törölve"
rm -rf "$MVPN_RUN_BASE/$LIVE"

# Túl nagy forrás config
BIG=$(new_conn "$GOOD_OVPN"); head -c 1100000 /dev/zero | tr '\0' '#' >>"$MVPN_SRC_BASE/$BIG/config"
DESC="1 MB-nál nagyobb config elutasítva"; expect_fail "$SH" "$MVPN" up openvpn "$BIG" --dry-run

# Napló forgatás (5 MB fölött, up-nál), symlink-biztosan
RID=$(new_conn "$GOOD_OVPN"); RL="$MVPN_LOG_BASE/$RID.log"
{ echo OLDMARKER; head -c 5300000 /dev/zero | tr '\0' x; } >"$RL"
echo victim >"$T/victim"; ln -s "$T/victim" "$RL.1"
DESC="up forgatással"; expect_ok "$SH" "$MVPN" up openvpn "$RID" --dry-run
[ ! -L "$RL.1" ] && head -1 "$RL.1" | grep -q OLDMARKER && ok "napló .1 a régi tartalommal" || nok "napló .1 a régi tartalommal"
[ "$(cat "$T/victim")" = victim ] && ok "symlink cél érintetlen" || nok "symlink cél érintetlen"
[ "$(stat -f %z "$RL")" -lt 100000 ] && ! grep -q OLDMARKER "$RL" && ok "új napló kicsi" || nok "új napló kicsi"
[ "$(stat -f %Lp "$RL.1")" = 600 ] && [ "$(stat -f %Lp "$RL")" = 600 ] && ok "napló jogosultság 600" || nok "napló jogosultság 600"
{ echo NEWMARKER; head -c 5300000 /dev/zero | tr '\0' y; } >"$RL"
"$SH" "$MVPN" up openvpn "$RID" --dry-run </dev/null >/dev/null 2>&1
head -1 "$RL.1" | grep -q NEWMARKER && [ ! -e "$RL.2" ] && ok "csak egy .1 marad" || nok "csak egy .1 marad"
SZ=$(stat -f %z "$RL"); "$SH" "$MVPN" down openvpn "$RID" --dry-run </dev/null >/dev/null 2>&1
head -1 "$RL.1" | grep -q NEWMARKER && [ "$(stat -f %z "$RL")" -ge "$SZ" ] && ok "down nem forgat" || nok "down nem forgat"

# status JSON hamis futási könyvtárakkal (élő openvpn pid → connected, wireguard interfész nélkül → failed)
SB="$T/statusrun"; mkdir -p "$SB/x-not-uuid"; echo openvpn >"$SB/x-not-uuid/kind"
S1=$(uuidgen); S2=$(uuidgen); mkdir -p "$SB/$S1" "$SB/$S2"
"$T/bin/openvpn" 30 & SP=$!
sleep 30 & NP=$!   # nem openvpn nevű folyamat: pid-újrahasznosítás esete, nem számít élőnek
S3=$(uuidgen); mkdir -p "$SB/$S3"; echo openvpn >"$SB/$S3/kind"; echo "$NP" >"$SB/$S3/pid"; echo utun8 >"$SB/$S3/iface"
echo openvpn >"$SB/$S1/kind"; echo "$SP" >"$SB/$S1/pid"; echo utun7 >"$SB/$S1/iface"; echo 10.8.0.2 >"$SB/$S1/ip"; echo 1700000000 >"$SB/$S1/started"
echo wireguard >"$SB/$S2/kind"; echo mv12345678 >"$SB/$S2/iface"
SJ=$(MVPN_RUN_BASE="$SB" "$SH" "$MVPN" status)
kill "$SP" "$NP" 2>/dev/null; wait "$SP" "$NP" 2>/dev/null
printf '%s' "$SJ" | python3 -c '
import json, sys
d = {e["id"]: e for e in json.load(sys.stdin)}
a, b, c = d[sys.argv[1]], d[sys.argv[2]], d[sys.argv[3]]
assert len(d) == 3
assert c["state"] == "failed", c
assert (a["state"], a["iface"], a["ip"], a["since"]) == ("connected", "utun7", "10.8.0.2", 1700000000), a
assert (b["state"], b["iface"], b["ip"], b["since"]) == ("failed", "mv12345678", None, None), b
' "$S1" "$S2" "$S3" && ok "status JSON" || { nok "status JSON"; echo "$SJ"; }

# Nyelv (--lang): a hibaüzenet angol alapból és --lang en mellett, magyar --lang hu mellett; ismeretlen érték: angol.
LANG_ID=$(new_conn "$GOOD_OVPN"$'\nup /tmp/x')
lang_out() { "$SH" "$MVPN" up openvpn "$LANG_ID" --dry-run "$@" </dev/null 2>&1; }
OUT=$(lang_out)
case "$OUT" in *"Invalid config:"*"Line 8: Forbidden directive: up"*) ok "nyelv: alapból angol" ;; *) nok "nyelv: alapból angol"; echo "$OUT" ;; esac
OUT=$(lang_out --lang en)
case "$OUT" in *"Invalid config:"*"Line 8: Forbidden directive: up"*) ok "nyelv: --lang en" ;; *) nok "nyelv: --lang en"; echo "$OUT" ;; esac
OUT=$(lang_out --lang hu)
case "$OUT" in *"Érvénytelen config:"*"8. sor: Tiltott direktíva: up"*) ok "nyelv: --lang hu" ;; *) nok "nyelv: --lang hu"; echo "$OUT" ;; esac
OUT=$(lang_out --lang=hu)
case "$OUT" in *"8. sor: Tiltott direktíva: up"*) ok "nyelv: --lang=hu" ;; *) nok "nyelv: --lang=hu"; echo "$OUT" ;; esac
OUT=$(lang_out --lang de)
case "$OUT" in *"Line 8: Forbidden directive: up"*) ok "nyelv: ismeretlen --lang = angol" ;; *) nok "nyelv: ismeretlen --lang = angol"; echo "$OUT" ;; esac
OUT=$("$SH" "$MVPN" up openvpn "../../etc" --dry-run --lang hu 2>&1 </dev/null)
[ "$OUT" = "Érvénytelen azonosító" ] && ok "nyelv: mvpn saját hibája magyarul" || nok "nyelv: mvpn saját hibája magyarul ($OUT)"
OUT=$("$SH" "$MVPN" up openvpn "../../etc" --dry-run 2>&1 </dev/null)
[ "$OUT" = "Invalid ID" ] && ok "nyelv: mvpn saját hibája angolul" || nok "nyelv: mvpn saját hibája angolul ($OUT)"
[ "$("$SH" "$MVPN" version --lang hu)" = "$(cat Resources/root/VERSION)" ] && ok "version --lang mellett is" || nok "version --lang mellett is"
LANG_ID2=$(new_conn "$GOOD_OVPN")
"$SH" "$MVPN" up openvpn "$LANG_ID2" --dry-run --lang hu </dev/null >/dev/null 2>&1
grep -q '^▶ \[mvpn\] config érvényes' "$MVPN_LOG_BASE/$LANG_ID2.log" && ok "nyelv: napló lépés magyarul" || nok "nyelv: napló lépés magyarul"
"$SH" "$MVPN" up openvpn "$LANG_ID2" --dry-run </dev/null >/dev/null 2>&1
grep -q '^▶ \[mvpn\] config is valid' "$MVPN_LOG_BASE/$LANG_ID2.log" && ok "nyelv: napló lépés angolul" || nok "nyelv: napló lépés angolul"
OUT=$("$MVPN_VALIDATOR" --lang hu wireguard /nonexistent 2>&1)
[ "$OUT" = "A fájl nem olvasható: /nonexistent" ] && ok "mvpn-validate --lang hu" || nok "mvpn-validate --lang hu ($OUT)"
OUT=$("$MVPN_VALIDATOR" wireguard /nonexistent 2>&1)
[ "$OUT" = "Cannot read the file: /nonexistent" ] && ok "mvpn-validate alapból angol" || nok "mvpn-validate alapból angol ($OUT)"

# Valódi (nem dry-run) up tesztmódban: csak hamis brew könyvtárral (MVPN_BREW), hamis ovpn-dns-sel (MVPN_LIBEXEC),
# így valódi VPN eszköz és networksetup nem fut. A sikertelen up nem hagyhat futási könyvtárat.
FB="$T/fakebrew"; mkdir -p "$FB/bin"
FL="$T/fakelibexec"; mkdir -p "$FL"
printf '#!/bin/bash\nprintf "%%s %%s\\n" "$script_type" "$1" >>"%s"\nrm -f "$1/dns-backup"\n' "$T/dns-restore.log" >"$FL/ovpn-dns"
chmod 755 "$FL/ovpn-dns"
upt() { env MVPN_TEST_ALLOW_UP=1 MVPN_LIBEXEC="$FL" "$@"; }

DESC="valódi up hamis brew nélkül tesztmódban tiltott"; expect_fail env MVPN_TEST_ALLOW_UP=1 "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")"

UID1=$(new_conn "$GOOD_OVPN")
DESC="up: hiányzó openvpn → hiba"; expect_fail upt MVPN_BREW="$T/emptybrew" "$SH" "$MVPN" up openvpn "$UID1"
[ ! -e "$MVPN_RUN_BASE/$UID1" ] && ok "up: hiányzó eszköz után nincs futási könyvtár" || { nok "up: hiányzó eszköz után nincs futási könyvtár"; ls -la "$MVPN_RUN_BASE/$UID1"; }
grep -q 'cleaning up after the failed connection attempt' "$MVPN_LOG_BASE/$UID1.log" && ok "up: takarítás naplózva" || nok "up: takarítás naplózva"
[ ! -e "$MVPN_RUN_BASE/.$UID1.lock" ] && ok "up hiba után a zár feloldva" || nok "up hiba után a zár feloldva"

# wg-quick megvan, bash 4 nincs: a die a prepare_run után jön.
WB="$T/wgbrew"; mkdir -p "$WB/bin"; printf '#!/bin/bash\nexit 0\n' >"$WB/bin/wg-quick"; chmod 755 "$WB/bin/wg-quick"
UID2=$(new_conn "$GOOD_WG")
DESC="up: hiányzó bash 4 (wireguard) → hiba"; expect_fail upt MVPN_BREW="$WB" "$SH" "$MVPN" up wireguard "$UID2"
[ ! -e "$MVPN_RUN_BASE/$UID2" ] && ok "up wireguard: nincs futási könyvtár" || nok "up wireguard: nincs futási könyvtár"

# Hamis openvpn: DNS-mentést hagy maga után (mintha az up hook lefutott volna), majd hibával kilép.
OB="$T/ovpnfail"; mkdir -p "$OB/bin"
cat >"$OB/bin/openvpn" <<'FAKE'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in --writepid) R=$(dirname "$2"); shift ;; esac; shift; done
printf 'svc\t1.1.1.1\tEmpty\n' >"$R/dns-backup"
exit 1
FAKE
chmod 755 "$OB/bin/openvpn"
UID3=$(new_conn "$GOOD_OVPN"); : >"$T/dns-restore.log"
DESC="up: openvpn hibával kilép → hiba"; expect_fail upt MVPN_BREW="$OB" "$SH" "$MVPN" up openvpn "$UID3"
[ ! -e "$MVPN_RUN_BASE/$UID3" ] && ok "up openvpn hiba: nincs futási könyvtár" || nok "up openvpn hiba: nincs futási könyvtár"
grep -q "^down $MVPN_RUN_BASE/$UID3\$" "$T/dns-restore.log" && ok "up openvpn hiba: DNS visszaállítva" || { nok "up openvpn hiba: DNS visszaállítva"; cat "$T/dns-restore.log"; }

# Hamis openvpn, ami "felépül": a jelszófájl a down-ig megmarad (600, a futási könyvtár 700).
SB2="$T/ovpnok"; mkdir -p "$SB2/bin"
cat >"$SB2/bin/openvpn" <<'FAKE'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in --log-append) L="$2"; shift ;; esac; shift; done
echo "Initialization Sequence Completed" >>"$L"
exit 0
FAKE
chmod 755 "$SB2/bin/openvpn"
UID4=$(new_conn "$GOOD_OVPN")
printf 'username=bob\npassword=Sup3rTitok\n' | upt MVPN_BREW="$SB2" "$SH" "$MVPN" up openvpn "$UID4" >"$T/out" 2>&1 \
  && ok "up openvpn (hamis) sikeres" || { nok "up openvpn (hamis) sikeres"; cat "$T/out"; }
[ -f "$MVPN_RUN_BASE/$UID4/auth" ] && [ "$(stat -f %Lp "$MVPN_RUN_BASE/$UID4/auth")" = 600 ] && [ "$(stat -f %Lp "$MVPN_RUN_BASE/$UID4")" = 700 ] \
  && ok "auth fájl megmarad a felépülés után (600, könyvtár 700)" || { nok "auth fájl megmarad a felépülés után (600, könyvtár 700)"; ls -la "$MVPN_RUN_BASE/$UID4"; }
[ "$(sed -n 2p "$MVPN_RUN_BASE/$UID4/auth" 2>/dev/null)" = Sup3rTitok ] && ok "auth fájl tartalma" || nok "auth fájl tartalma"
grep -q 'Sup3rTitok' "$MVPN_LOG_BASE/$UID4.log" && nok "jelszó nem kerül a naplóba (valódi up)" || ok "jelszó nem kerül a naplóba (valódi up)"
DESC="down a felépült kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$UID4"
[ ! -e "$MVPN_RUN_BASE/$UID4" ] && ok "down után az auth fájl és a futási könyvtár törölve" || nok "down után az auth fájl és a futási könyvtár törölve"

# Összeomlott openvpn maradéka (halott pid, dns-backup): az up előbb visszaállítja a DNS-t, aztán törli.
UID5=$(new_conn "$GOOD_OVPN"); mkdir -m 700 "$MVPN_RUN_BASE/$UID5"
echo openvpn >"$MVPN_RUN_BASE/$UID5/kind"; dead_pid >"$MVPN_RUN_BASE/$UID5/pid"
printf 'svc\t1.1.1.1\tEmpty\n' >"$MVPN_RUN_BASE/$UID5/dns-backup"; : >"$T/dns-restore.log"
DESC="up összeomlott maradék mellett (eszköz nélkül hibázik)"; expect_fail upt MVPN_BREW="$T/emptybrew" "$SH" "$MVPN" up openvpn "$UID5"
grep -q "^down $MVPN_RUN_BASE/$UID5\$" "$T/dns-restore.log" && ok "maradék: DNS visszaállítva a dns-backup-ból" || { nok "maradék: DNS visszaállítva a dns-backup-ból"; cat "$T/dns-restore.log"; }
grep -q 'closing the previous run' "$MVPN_LOG_BASE/$UID5.log" && ok "maradék: korábbi futás lebontva" || nok "maradék: korábbi futás lebontva"
[ ! -e "$MVPN_RUN_BASE/$UID5" ] && ok "maradék: nincs futási könyvtár" || nok "maradék: nincs futási könyvtár"

# SIGTERM a kapcsolódás közben (hamis openvpn, ami nem épül fel): 143, takarítás, nincs futási könyvtár.
HB="$T/ovpnhang"; mkdir -p "$HB/bin"; printf '#!/bin/bash\nexit 0\n' >"$HB/bin/openvpn"; chmod 755 "$HB/bin/openvpn"
UID6=$(new_conn "$GOOD_OVPN")
MVPN_TEST_ALLOW_UP=1 MVPN_LIBEXEC="$FL" MVPN_BREW="$HB" "$SH" "$MVPN" up openvpn "$UID6" </dev/null >/dev/null 2>&1 & W=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -d "$MVPN_RUN_BASE/$UID6" ] && break; sleep 0.2; done
sleep 0.5; kill -TERM "$W"; wait "$W"; RC=$?
[ "$RC" = 143 ] && [ ! -e "$MVPN_RUN_BASE/$UID6" ] && ok "up SIGTERM: 143, nincs futási könyvtár" || { nok "up SIGTERM: 143, nincs futási könyvtár ($RC)"; ls -la "$MVPN_RUN_BASE/$UID6" 2>&1; }

echo "---"; echo "pass: $PASS  fail: $FAIL"
[ "$FAIL" -eq 0 ]
