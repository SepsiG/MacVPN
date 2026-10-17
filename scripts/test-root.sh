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
mkdir -p "$T/emptybrew"
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
GOOD_WG=$'[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820'
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

# Argumentum-/értékszintű validálás a root oldalon is (mvpn-validate): eszköz-fájl, útvonal, rossz formátum.
for bad in 'dev /dev/disk0' 'dev-type /dev/x' 'remote -x 1194' 'cipher /etc/passwd' 'verb 99'; do
  DESC="openvpn argumentum: $bad"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\n'"$bad")" --dry-run
done
DESC="openvpn <connection> blokk (remote csak benne)"
expect_ok "$SH" "$MVPN" up openvpn "$(new_conn $'client\ndev tun\n<connection>\nremote vpn.example.com 1194 udp\n</connection>')" --dry-run
DESC="openvpn <connection> belső sora is validált"
expect_fail "$SH" "$MVPN" up openvpn "$(new_conn $'client\n<connection>\nremote a 1194\nup /tmp/x\n</connection>')" --dry-run
for k in 'Address = -x' 'Address = 10.0.0.2/33' 'DNS = /etc/x' 'MTU = 99999'; do
  DESC="wireguard érték: $k"; expect_fail "$SH" "$MVPN" up wireguard "$(new_conn "${GOOD_WG/Address = 10.0.0.2\/32/$k}")" --dry-run
done
CB='}'
swan_local() { printf '%s' "${GOOD_SWAN/remote_addrs = vpn.example.com/remote_addrs = vpn.example.com${NL}    local {${NL}      $1${NL}    $CB}"; }
DESC="strongswan local blokk (kontroll)"; expect_ok "$SH" "$MVPN" up strongswan "$(new_conn "$(swan_local 'certs = client.pem')")" --dry-run
for k in 'certs = /etc/master.passwd' 'certs = ../../x.pem' 'pubkeys = .hidden'; do
  DESC="strongswan fájlútvonal: $k"; expect_fail "$SH" "$MVPN" up strongswan "$(new_conn "$(swan_local "$k")")" --dry-run
done
DESC="strongswan crl_uris"; expect_fail "$SH" "$MVPN" up strongswan "$(new_conn "$GOOD_SWAN"$'\nauthorities {\n  a {\n    crl_uris = file:///etc/x\n  }\n}')" --dry-run
DESC="strongswan: értékben álló 'file' szó nem tiltott"
expect_ok "$SH" "$MVPN" up strongswan "$(new_conn "$(swan_local 'id = file')")" --dry-run

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
# 1–2 karakteres titok: csak önálló tokenként maszkolódik (különben a napló minden szava szétesne).
OUT=$(printf 'ab cab ab. abc (ab)\n' | MVPN_MASK_1=ab "$SH" "$MVPN" __mask)
[ "$OUT" = "*** cab ***. abc (***)" ] && ok "mask 2 karakteres titok, önálló tokenként" || nok "mask 2 karakteres titok, önálló tokenként ($OUT)"
OUT=$(printf 'x y xx x\n' | MVPN_MASK_2=x "$SH" "$MVPN" __mask)
[ "$OUT" = "*** y xx ***" ] && ok "mask 1 karakteres titok" || nok "mask 1 karakteres titok ($OUT)"
OUT=$(printf 'pw=%%s! end\n' | MVPN_MASK_1='%s!' "$SH" "$MVPN" __mask)
[ "$OUT" = "pw=*** end" ] && ok "mask 3+ karakter bárhol" || nok "mask 3+ karakter bárhol ($OUT)"

# Locale, verzió, charon: statikus ellenőrzések
grep -q '^export LC_ALL=C' "$MVPN" && grep -q '^export LC_ALL=C' Resources/root/ovpn-dns && ok "LC_ALL=C a mvpn-ben és az ovpn-dns-ben" || nok "LC_ALL=C a mvpn-ben és az ovpn-dns-ben"
[ "$("$SH" "$MVPN" version)" = 4 ] && [ "$(cat Resources/root/VERSION)" = 4 ] && ok "root verzió: 4" || nok "root verzió: 4"
OUT=$(printf 'Szép ÁRVÍZTŰRŐ\n' | env LC_ALL=hu_HU.UTF-8 LANG=hu_HU.UTF-8 MVPN_MASK_1=ŰR "$SH" "$MVPN" __mask)
[ "$OUT" = "Szép ÁRVÍZT***Ő" ] && ok "mask felhasználói locale mellett is bájt-alapú" || nok "mask felhasználói locale mellett is bájt-alapú ($OUT)"
grep -q 'pgrep -U 0 -x charon' "$MVPN" && ! grep -qE 'p(grep|kill) -x charon' "$MVPN" && ok "charon: csak root folyamat (pgrep -U 0)" || nok "charon: csak root folyamat (pgrep -U 0)"

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
DESC="down rossz típussal: openvpn leállítva"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" "$SH" "$MVPN" down strongswan "$DID"
sleep 0.2
! kill -0 "$OP" 2>/dev/null && [ ! -e "$MVPN_RUN_BASE/$DID" ] && ok "down: folyamat leállt, futási könyvtár törölve" || nok "down: folyamat leállt, futási könyvtár törölve"
kill "$OP" 2>/dev/null; wait "$OP" 2>/dev/null

DID=$(uuidgen); mkdir -p "$MVPN_RUN_BASE/$DID"; echo pptp >"$MVPN_RUN_BASE/$DID/kind"
DESC="down érvénytelen kind fájllal: takarítás"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" "$SH" "$MVPN" down openvpn "$DID"
[ ! -e "$MVPN_RUN_BASE/$DID" ] && ok "érvénytelen kind: futási könyvtár törölve" || nok "érvénytelen kind: futási könyvtár törölve"

UT=$(ifconfig -l | tr ' ' '\n' | grep -E '^utun[0-9]+$' | head -1)
if [ -n "$UT" ]; then
  DID=$(uuidgen); WGR="$T/wgrun"; mkdir -p "$MVPN_RUN_BASE/$DID" "$WGR"
  echo wireguard >"$MVPN_RUN_BASE/$DID/kind"; echo mv12345678 >"$MVPN_RUN_BASE/$DID/iface"; echo "$UT" >"$WGR/mv12345678.name"
  DESC="down sikertelen + élő interfész: hibával lép ki"; expect_fail env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_WG_RUN="$WGR" "$SH" "$MVPN" down wireguard "$DID"
  [ -d "$MVPN_RUN_BASE/$DID" ] && ok "down sikertelen: futási könyvtár megmarad" || nok "down sikertelen: futási könyvtár megmarad"
  rm -rf "$MVPN_RUN_BASE/$DID"
else
  ok "down sikertelen + élő interfész (kihagyva: nincs utun interfész)"
fi
DESC="up nem-rootként dry-run nélkül továbbra is tiltott"; expect_fail env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")"

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
echo "2026-10-17 00:00:00 Initialization Sequence Completed" >"$SB/$S1/openvpn.log"
# Élő openvpn, van interfész, de a root-only openvpn.log szerint még nem kész: connecting (a felhasználói napló nem számít).
S4=$(uuidgen); mkdir -p "$SB/$S4"; echo openvpn >"$SB/$S4/kind"; echo "$SP" >"$SB/$S4/pid"; echo utun6 >"$SB/$S4/iface"; : >"$SB/$S4/openvpn.log"
mkdir -p "$T/statuslog"; echo "Initialization Sequence Completed" >"$T/statuslog/$S4.log"
echo wireguard >"$SB/$S2/kind"; echo mv12345678 >"$SB/$S2/iface"
echo "2026-10-17 00:00:01 FLUSHMARKER" >>"$SB/$S1/openvpn.log"; : >"$T/statuslog/$S1.log"
SJ=$(MVPN_RUN_BASE="$SB" MVPN_LOG_BASE="$T/statuslog" "$SH" "$MVPN" status)
kill "$SP" "$NP" 2>/dev/null; wait "$SP" "$NP" 2>/dev/null
grep -q FLUSHMARKER "$T/statuslog/$S1.log" && ok "status: a felépült openvpn root-only naplója átmásolva" || nok "status: a felépült openvpn root-only naplója átmásolva"
printf '%s' "$SJ" | python3 -c '
import json, sys
d = {e["id"]: e for e in json.load(sys.stdin)}
a, b, c, e = d[sys.argv[1]], d[sys.argv[2]], d[sys.argv[3]], d[sys.argv[4]]
assert len(d) == 4
assert e["state"] == "connecting", e
assert c["state"] == "failed", c
assert (a["state"], a["iface"], a["ip"], a["since"]) == ("connected", "utun7", "10.8.0.2", 1700000000), a
assert (b["state"], b["iface"], b["ip"], b["since"]) == ("failed", "mv12345678", None, None), b
' "$S1" "$S2" "$S3" "$S4" && ok "status JSON" || { nok "status JSON"; echo "$SJ"; }

# v3 → v4 frissítés: a v3 által indított openvpn-nek nincs $RUN/openvpn.log-ja. Élő, ellenőrzött pid + iface → connected
# (a korábbi viselkedés); iface nélkül connecting; halott pid → failed.
LB="$T/legacyrun"; mkdir -p "$LB"
"$T/bin/openvpn" 30 & LP=$!
L1=$(uuidgen); mkdir -p "$LB/$L1"; echo openvpn >"$LB/$L1/kind"; echo "$LP" >"$LB/$L1/pid"; echo utun9 >"$LB/$L1/iface"; echo 10.8.0.9 >"$LB/$L1/ip"
L2=$(uuidgen); mkdir -p "$LB/$L2"; echo openvpn >"$LB/$L2/kind"; echo "$LP" >"$LB/$L2/pid"
L3=$(uuidgen); mkdir -p "$LB/$L3"; echo openvpn >"$LB/$L3/kind"; echo 999999 >"$LB/$L3/pid"; echo utun10 >"$LB/$L3/iface"
SJ=$(MVPN_RUN_BASE="$LB" MVPN_LOG_BASE="$T/legacylog" "$SH" "$MVPN" status)
kill "$LP" 2>/dev/null; wait "$LP" 2>/dev/null
printf '%s' "$SJ" | python3 -c '
import json, sys
d = {e["id"]: e for e in json.load(sys.stdin)}
assert (d[sys.argv[1]]["state"], d[sys.argv[1]]["iface"], d[sys.argv[1]]["ip"]) == ("connected", "utun9", "10.8.0.9"), d[sys.argv[1]]
assert d[sys.argv[2]]["state"] == "connecting", d[sys.argv[2]]
assert d[sys.argv[3]]["state"] == "failed", d[sys.argv[3]]
' "$L1" "$L2" "$L3" && ok "status: v3-ból maradt openvpn (nincs openvpn.log) → connected" || { nok "status: v3-ból maradt openvpn (nincs openvpn.log) → connected"; echo "$SJ"; }

# status-kori napló-átmásolás: csak ha a zár szabad (nem blokkolva megszerzi, majd elengedi), és titok nélkül maszkol:
# a jelszó / auth sorok kimaradnak.
FB="$T/flushrun"; FLG="$T/flushlog"; mkdir -p "$FB" "$FLG"
"$T/bin/openvpn" 30 & FP=$!
F1=$(uuidgen); mkdir -p "$FB/$F1"; echo openvpn >"$FB/$F1/kind"; echo "$FP" >"$FB/$F1/pid"; echo utun7 >"$FB/$F1/iface"
printf '%s\n' "x Initialization Sequence Completed" "x KEEPMARKER" "x Password: LEAKPW1" "x AUTH: Received control message LEAKAUTH2" "x passwd LEAKPW3" >"$FB/$F1/openvpn.log"
: >"$FLG/$F1.log"
mkdir "$FB/.$F1.lock"; echo "$FP" >"$FB/.$F1.lock/pid"
MVPN_RUN_BASE="$FB" MVPN_LOG_BASE="$FLG" "$SH" "$MVPN" status >/dev/null
[ ! -s "$FLG/$F1.log" ] && [ "$(cat "$FB/.$F1.lock/pid")" = "$FP" ] && ok "status: foglalt zárnál nincs átmásolás, a zár érintetlen" || nok "status: foglalt zárnál nincs átmásolás, a zár érintetlen"
rm -rf "$FB/.$F1.lock"
MVPN_RUN_BASE="$FB" MVPN_LOG_BASE="$FLG" "$SH" "$MVPN" status >/dev/null
grep -q KEEPMARKER "$FLG/$F1.log" && ! grep -q LEAK "$FLG/$F1.log" && ok "status: átmásolás jelszó/auth sorok nélkül" || { nok "status: átmásolás jelszó/auth sorok nélkül"; cat "$FLG/$F1.log"; }
[ ! -e "$FB/.$F1.lock" ] && ok "status: a zár elengedve" || nok "status: a zár elengedve"
kill "$FP" 2>/dev/null; wait "$FP" 2>/dev/null

# Inline hitelesítő blokkok (<auth-user-pass>, <http-proxy-user-pass>) tartalma nem kerül a naplóba (debug pillanatkép).
IAID=$(new_conn $'client\ndev tun\n<auth-user-pass>\nremote INLINELEAK1\nremote INLINELEAK2\n</auth-user-pass>\nremote vpn.example.com 1194\n<connection>\nremote alt.example.com 443\nhttp-proxy proxy.example.com 8080 [inline]\n<http-proxy-user-pass>\nremote INLINELEAK3\nremote INLINELEAK4\n</http-proxy-user-pass>\n</connection>\n<ca>\nx\n</ca>')
"$SH" "$MVPN" up openvpn "$IAID" --dry-run --debug </dev/null >"$T/ia.out" 2>&1
grep -q 'dscacheutil -q host -a name vpn.example.com' "$MVPN_LOG_BASE/$IAID.log" && ! grep -q INLINELEAK "$MVPN_LOG_BASE/$IAID.log" "$T/ia.out" \
  && ok "debug pillanatkép: inline hitelesítő blokk tartalma nem kerül a naplóba" || { nok "debug pillanatkép: inline hitelesítő blokk tartalma nem kerül a naplóba"; cat "$T/ia.out" "$MVPN_LOG_BASE/$IAID.log"; }

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
DESC="down a felépült kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$UID4"
[ ! -e "$MVPN_RUN_BASE/$UID4" ] && ok "down után az auth fájl és a futási könyvtár törölve" || nok "down után az auth fájl és a futási könyvtár törölve"

# OpenVPN: a felépülésről/hibáról csak a root-only $RUN/openvpn.log dönt; a felhasználói naplóba injektált sor nem számít.
DID=$(new_conn "$GOOD_OVPN")
"$SH" "$MVPN" up openvpn "$DID" --dry-run </dev/null >"$T/out" 2>&1
grep -q -- "--log-append $MVPN_RUN_BASE/$DID.dryrun.[A-Za-z0-9]*/openvpn.log --daemon" "$T/out" \
  && ok "openvpn: --log-append a root-only futási könyvtárba" || { nok "openvpn: --log-append a root-only futási könyvtárba"; cat "$T/out"; }
OI="$T/ovpninject"; mkdir -p "$OI/bin"
cat >"$OI/bin/openvpn" <<FAKE
#!/bin/bash
while [ \$# -gt 0 ]; do case "\$1" in --log-append) L="\$2"; shift ;; --writepid) P="\$2"; shift ;; esac; shift; done
echo "\$L" >"$T/ovpn-logpath"
"$T/bin/openvpn" 60 </dev/null >/dev/null 2>&1 &
echo \$! >"\$P"
case "\$FAKE_OVPN_MODE" in
  inject)     printf 'Initialization Sequence Completed\n' >>"\$INJECT_LOG" ;;
  authinject) printf 'AUTH_FAILED\n' >>"\$INJECT_LOG"; printf '2026-10-17 00:00:00 Initialization Sequence Completed\n' >>"\$L" ;;
  auth)       printf '2026-10-17 00:00:00 AUTH: Received control message: AUTH_FAILED\n' >>"\$L" ;;
esac
exit 0
FAKE
chmod 755 "$OI/bin/openvpn"
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" MVPN_UP_TIMEOUT=3 FAKE_OVPN_MODE=inject INJECT_LOG="$MVPN_LOG_BASE/$OID.log" "$SH" "$MVPN" up openvpn "$OID" 2>&1 </dev/null); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Timed out: the connection was not established within 3 s"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$OID" ] \
  && ok "openvpn: injektált 'Initialization Sequence Completed' a felhasználói naplóban nem számít" || { nok "openvpn: injektált 'Initialization Sequence Completed' a felhasználói naplóban nem számít"; echo "$OUT"; }
[ "$(cat "$T/ovpn-logpath")" = "$MVPN_RUN_BASE/$OID/openvpn.log" ] && ok "openvpn: a napló a futási könyvtárban" || nok "openvpn: a napló a futási könyvtárban ($(cat "$T/ovpn-logpath"))"
pgrep -f "$T/bin/openvpn 60" >/dev/null && sleep 1
OID=$(new_conn "$GOOD_OVPN")
OUT=$(printf 'username=bob\npassword=Sup3rTitok\n' | upt MVPN_BREW="$OI" FAKE_OVPN_MODE=authinject INJECT_LOG="$MVPN_LOG_BASE/$OID.log" "$SH" "$MVPN" up openvpn "$OID" 2>&1); RC=$?
[ "$RC" = 0 ] && ok "openvpn: injektált AUTH_FAILED a felhasználói naplóban nem számít" || { nok "openvpn: injektált AUTH_FAILED a felhasználói naplóban nem számít"; echo "$OUT"; }
[ "$(stat -f %Lp "$MVPN_RUN_BASE/$OID/openvpn.log" 2>/dev/null)" = 600 ] && grep -q '^2026-10-17 00:00:00 Initialization Sequence Completed$' "$MVPN_LOG_BASE/$OID.log" \
  && ok "openvpn: openvpn.log 600, tartalma a kapcsolat naplójába másolva" || { nok "openvpn: openvpn.log 600, tartalma a kapcsolat naplójába másolva"; cat "$MVPN_LOG_BASE/$OID.log"; }
DESC="openvpn: down a felépült (hamis) kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$OID"
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" FAKE_OVPN_MODE=auth "$SH" "$MVPN" up openvpn "$OID" 2>&1 </dev/null); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Authentication failed (AUTH_FAILED)"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$OID" ] \
  && grep -q 'AUTH: Received control message: AUTH_FAILED' "$MVPN_LOG_BASE/$OID.log" \
  && ok "openvpn: AUTH_FAILED a root-only naplóból → hiba, takarítás, napló átmásolva" || { nok "openvpn: AUTH_FAILED a root-only naplóból → hiba, takarítás, napló átmásolva"; echo "$OUT"; }
pgrep -f "$T/bin/openvpn 60" >/dev/null && nok "openvpn: nem maradt futó hamis openvpn" || ok "openvpn: nem maradt futó hamis openvpn"

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

# ---------- SSTP ----------
# A jelszó a sstpc parancssorába kerül (a brew sstpc csak így indul, lásd mvpn), de a naplóba és a dry-run
# kimenetbe soha: ott ***. Valódi sstpc/pppd a teszt alatt nem indul (dry-run, illetve hamis brew könyvtár).
SPW='Sup3rSstp!pw'
PEM=$'-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2E+/=\n-----END CERTIFICATE-----'
GOOD_SSTP=$'server=vpn.example.com\nport=443\nuser=bob@corp.example\ncert=system\nroute_all=yes\npeer_dns=yes'
CA_SSTP=$'server=vpn.example.com\nport=4443\nuser=bob\ncert=ca\nroute_all=yes\npeer_dns=yes\n<ca>\n'"$PEM"$'\n</ca>'
export MVPN_PPP_OPTIONS="$T/ppp/options"
export MVPN_SSTP_TMP="$T/sstptmp"   # a sstp-pppd.* takarítás tesztmódban csak ide nyúlhat
mkdir -p "$MVPN_SSTP_TMP"
sstp_dry() { # $1=config, többi: extra argumentumok → stdout+stderr a $T/sd.out-ba, az id a $SDID-be
  SDID=$(new_conn "$1"); shift
  printf 'password=%s\n' "$SPW" | "$SH" "$MVPN" up sstp "$SDID" --dry-run "$@" >"$T/sd.out" 2>&1
}
if sstp_dry "$GOOD_SSTP"; then ok "sstp dry-run"; else nok "sstp dry-run"; cat "$T/sd.out"; fi
SLOG="$MVPN_LOG_BASE/$SDID.log"
EXP1="DRY: /opt/homebrew/sbin/sstpc --log-stderr --log-level 2 --tls-ext --save-server-route --user bob@corp.example --password *** vpn.example.com:443 -- logfile $MVPN_RUN_BASE/$SDID.dryrun."
EXP2="/pppd.log require-mschap-v2 refuse-pap refuse-chap refuse-mschap refuse-eap noauth nodetach usepeerdns defaultroute"
DL=$(grep -F -- "$EXP1" "$T/sd.out")
case "$DL" in *"$EXP2") ok "sstp: várt sstpc parancssor (sbin, ***, root-only pppd.log)" ;;
  *) nok "sstp: várt sstpc parancssor (sbin, ***, root-only pppd.log)"; cat "$T/sd.out" ;; esac
grep -qF -- "logfile $SLOG" "$T/sd.out" && nok "sstp: a pppd nem a felhasználói naplóba ír" || ok "sstp: a pppd nem a felhasználói naplóba ír"
grep -qF -- "/opt/homebrew/sbin/sstpc --log-stderr" "$SLOG" && grep -qF -- "--password *** vpn.example.com:443" "$SLOG" \
  && ok "sstp: naplózott parancssor (dry-run)" || nok "sstp: naplózott parancssor (dry-run)"
grep -qF "$SPW" "$T/sd.out" "$SLOG" && nok "sstp: jelszó nincs a dry-run kimenetben és a naplóban" || ok "sstp: jelszó nincs a dry-run kimenetben és a naplóban"
grep -q "DRY: touch $MVPN_PPP_OPTIONS" "$T/sd.out" && [ ! -e "$MVPN_PPP_OPTIONS" ] && grep -q "creating $MVPN_PPP_OPTIONS" "$SLOG" \
  && ok "sstp: hiányzó /etc/ppp/options (dry-run: csak naplóz)" || nok "sstp: hiányzó /etc/ppp/options (dry-run: csak naplóz)"
grep -q -- '--cert-warn\|--ca-cert' "$T/sd.out" && nok "sstp system mód: nincs --ca-cert/--cert-warn" || ok "sstp system mód: nincs --ca-cert/--cert-warn"

sstp_dry "$GOOD_SSTP" --debug
grep -q -- '--log-level 4 .* refuse-pap .*usepeerdns defaultroute debug$' "$T/sd.out" \
  && ok "sstp debug: --log-level 4, pppd debug, refuse-pap marad" || { nok "sstp debug: --log-level 4, pppd debug, refuse-pap marad"; cat "$T/sd.out"; }
sstp_dry "${GOOD_SSTP/cert=system/cert=insecure}"
grep -q -- 'DRY: .*--save-server-route --cert-warn --user' "$T/sd.out" && grep -q 'WARNING: server certificate verification is off' "$MVPN_LOG_BASE/$SDID.log" \
  && ok "sstp insecure: --cert-warn + figyelmeztetés" || { nok "sstp insecure: --cert-warn + figyelmeztetés"; cat "$T/sd.out"; }
sstp_dry "$CA_SSTP"
grep -q -- "DRY: .*--ca-cert $MVPN_RUN_BASE/$SDID.dryrun.[A-Za-z0-9]*/ca.pem --user bob --password \*\*\* vpn.example.com:4443 " "$T/sd.out" \
  && grep -q 'CA certificate written' "$MVPN_LOG_BASE/$SDID.log" && ok "sstp ca: --ca-cert <run>/ca.pem" || { nok "sstp ca: --ca-cert <run>/ca.pem"; cat "$T/sd.out"; }
sstp_dry $'server=fd00::1\nuser=bob\nroute_all=no\npeer_dns=no'
grep -q -- 'DRY: .* \[fd00::1\]:443 -- logfile .* nodetach$' "$T/sd.out" \
  && ok "sstp: IPv6 cél, route_all/peer_dns=no" || { nok "sstp: IPv6 cél, route_all/peer_dns=no"; cat "$T/sd.out"; }
for bpw in 'a"b' 'a\b' "$(printf 'a\tb')" '"
plugin /tmp/x.so'; do
  DESC="sstp: tiltott karakter a jelszóban ($(printf '%s' "$bpw" | head -1 | tr -d '\t'))"
  BID=$(new_conn "$GOOD_SSTP")
  OUT=$(printf 'password=%s\n' "$bpw" | "$SH" "$MVPN" up sstp "$BID" --dry-run 2>&1); RC=$?
  if [ "$RC" != 0 ] && case "$OUT" in *"must not contain quotation marks, backslashes or control characters"*) true ;; *) false ;; esac \
     && ! printf '%s' "$OUT" | grep -q 'DRY: .*sstpc'; then ok "$DESC"; else nok "$DESC"; echo "$OUT"; fi
done
OUT=$(printf 'password=a"b\n' | "$SH" "$MVPN" up sstp "$(new_conn "$GOOD_SSTP")" --dry-run --lang hu 2>&1)
case "$OUT" in *"Az SSTP jelszóban nem lehet idézőjel"*) ok "sstp: jelszó-szabály magyarul" ;; *) nok "sstp: jelszó-szabály magyarul"; echo "$OUT" ;; esac
EVIL_SSTP=$'<ca>\nserver=evil\n'"$PEM"$'\n</ca>\nserver=vpn.example.com\nuser=bob\ncert=ca'
sstp_dry "$EVIL_SSTP" --debug
grep -q 'dscacheutil -q host -a name vpn.example.com$' "$MVPN_LOG_BASE/$SDID.log" && ! grep -q 'name evil' "$MVPN_LOG_BASE/$SDID.log" \
  && ok "sstp debug: a diagnosztika a validált hosztot használja (nem a <ca> blokkot)" || { nok "sstp debug: a diagnosztika a validált hosztot használja (nem a <ca> blokkot)"; cat "$MVPN_LOG_BASE/$SDID.log"; }
DESC="sstp: jelszó nélkül hiba"; expect_fail "$SH" "$MVPN" up sstp "$(new_conn "$GOOD_SSTP")" --dry-run
DESC="sstp: hiányzó pppd"; expect_fail env MVPN_PPPD=/nonexistent "$SH" "$MVPN" up sstp "$(new_conn "$GOOD_SSTP")" --dry-run

for bad in $'server=vpn example.com\nuser=bob' $'server=-x.example\nuser=bob' $'server=a.example:443\nuser=bob' \
           $'server=a.example\nuser=DOMAIN\\bob' $'server=a.example\nuser=bob smith' $'server=a.example\nuser="bob"' \
           $'server=a.example\nuser=bob\npassword=x' $'server=a.example\nuser=bob\npppd_opts=plugin x.so' \
           $'server=a.example\nuser=bob\ncert=ca' $'server=a.example\nuser=bob\nport=0' $'server=a.example\nuser=bob\nroute_all=1' \
           $'server=a.example\nuser=bob\n<ca>\n$(touch /tmp/x)\n</ca>' $'user=bob' $'server=a.example\nuser=bob\nserver=b.example'; do
  DESC="sstp érvénytelen: $(printf '%s' "$bad" | tr '\n' '|')"
  SBID=$(new_conn "$bad")
  if printf 'password=%s\n' "$SPW" | "$SH" "$MVPN" up sstp "$SBID" --dry-run >"$T/out" 2>&1; then nok "$DESC"; cat "$T/out"
  elif grep -q 'DRY: .*sstpc' "$T/out"; then nok "$DESC (sstpc parancs mégis megjelent)"
  else ok "$DESC"; fi
done
DESC="sstp: vezérlőkarakter"; expect_fail "$SH" "$MVPN" up sstp "$(new_conn $'server=a.example\nuser=bo\001b')" --dry-run
OUT=$(printf 'password=%s\n' "$SPW" | "$SH" "$MVPN" up sstp "$(new_conn $'server=a b\nuser=bob')" --dry-run --lang hu 2>&1)
case "$OUT" in *"Érvénytelen config:"*"1. sor: Érvénytelen szerver"*) ok "sstp: magyar validátor-üzenet, érték idézése nélkül" ;;
  *) nok "sstp: magyar validátor-üzenet, érték idézése nélkül"; echo "$OUT" ;; esac
printf '%s\n' "$CA_SSTP" >"$T/ca.sstp"
OUT=$("$MVPN_VALIDATOR" --sstp-params "$T/ca.sstp" | tr '\n' '|')
[ "$OUT" = "vpn.example.com|4443|bob|ca|yes|yes|" ] && ok "mvpn-validate --sstp-params" || nok "mvpn-validate --sstp-params ($OUT)"
"$MVPN_VALIDATOR" --sstp-ca "$T/ca.sstp" | diff -q - <(printf '%s\n' "$PEM") >/dev/null && ok "mvpn-validate --sstp-ca" || nok "mvpn-validate --sstp-ca"

# Valódi up tesztmódban, hamis sstpc-vel ($BREW/sbin). A hamis sstpc rögzíti az argv-t, a jelszót a stderr-re is
# kiírja (mint a sstpc PAP dumpja), pppd-szerű sorokat ír a logfile-ba, majd sstpc nevű sleep-pé válik.
SPB="$T/sstpbrew"; mkdir -p "$SPB/sbin" "$T/sstpsleep"; ln -s /bin/sleep "$T/sstpsleep/sstpc"
REC="$T/sstprec"
cat >"$SPB/sbin/sstpc" <<FAKE
#!/bin/bash
: >"$REC.argv"; L=""; CA=""; PW=""
while [ \$# -gt 0 ]; do
  printf '%s\n' "\$1" >>"$REC.argv"
  case "\$1" in logfile) L="\$2" ;; --ca-cert) CA="\$2" ;; --password) PW="\$2" ;; esac
  shift
done
[ -n "\$CA" ] && { stat -f %Lp "\$CA"; head -1 "\$CA"; } >"$REC.ca"
echo "PPP NAME=\"bob\", PASSWORD: \"\$PW\"" >&2
# Injektálási kísérlet: a sstpc kimenetében és a felhasználói naplóban lévő pppd-szerű sorok nem számíthatnak.
INJ='Using interface ppp6\nlocal  IP address 6.6.6.6\nprimary   DNS address 6.6.6.6\n'
printf "\$INJ" >&2
[ -n "\$INJECT_LOG" ] && printf "\$INJ" >>"\$INJECT_LOG"
case "\$FAKE_SSTP_MODE" in
  ok)   printf 'Fri Oct 16 22:58:59 2026 : evil Using interface ppp7\nFri Oct 16 22:58:59 2026 : Using interface ppp9\nFri Oct 16 22:58:59 2026 : local  IP address 10.0.0.7\nFri Oct 16 22:58:59 2026 : remote IP address 10.0.0.1\nFri Oct 16 22:58:59 2026 : primary   DNS address 10.0.0.53\nsecondary DNS address 10.0.0.54\nprimary   DNS address 6.6.6.7 x\n' >>"\$L" ;;
  hang) ;;
  auth) printf 'MS-CHAP authentication failed: E=691 Authentication failure\n' >>"\$L" ;;
  cert) echo "SSL certificate verification failed: self signed certificate (18)" >&2; exit 1 ;;
esac
exec "$T/sstpsleep/sstpc" 60
FAKE
chmod 755 "$SPB/sbin/sstpc"
FL2="$T/sstplibexec"; mkdir -p "$FL2"
cat >"$FL2/ovpn-dns" <<FAKE
#!/bin/bash
printf '%s %s %s %s\n' "\$script_type" "\$dev" "\$foreign_option_1" "\$foreign_option_2" >>"$T/sstp-dns.log"
case "\$script_type" in up) : >"\$1/dns-backup" ;; down) rm -f "\$1/dns-backup" ;; esac
FAKE
printf '#!/bin/bash\necho "$*" >>"%s"\ncase "$*" in *"add -net 128.0.0.0/1"*) [ "$FAKE_ROUTE_FAIL" = 1 ] && exit 1 ;; esac\nexit 0\n' "$T/sstp-route.log" >"$T/fakeroute"
chmod 755 "$FL2/ovpn-dns" "$T/fakeroute"
sstp_up() { env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$SPB" MVPN_LIBEXEC="$FL2" MVPN_ROUTE="$T/fakeroute" MVPN_TEST_IFACE_OK=1 "$@"; }
sstp_alive_t() { ps -p "$1" -o comm= 2>/dev/null | grep -q 'sstpc$'; }

SUID=$(new_conn "$CA_SSTP"); : >"$T/sstp-dns.log"; : >"$T/sstp-route.log"
# Régi és új sstp-pppd.* fájlok a takarítás teszteléséhez (csak a régi, szabályos, pontos nevű törlődhet).
ST="$MVPN_SSTP_TMP"; echo x >"$T/sweep-victim"
echo old >"$ST/sstp-pppd.AAAAAA"; echo old >"$ST/sstp-pppd.AB"; ln -s "$T/sweep-victim" "$ST/sstp-pppd.SYMSYM"
mkdir "$ST/sstp-pppd.DIRDIR"; echo new >"$ST/sstp-pppd.NEWNEW"
touch -h -t 202001010000 "$ST/sstp-pppd.AAAAAA" "$ST/sstp-pppd.AB" "$ST/sstp-pppd.SYMSYM" "$ST/sstp-pppd.DIRDIR"
touch -t 209901010000 "$ST/sstp-pppd.NEWNEW"
printf 'username=ignored\npassword=%s\n' "$SPW" | sstp_up FAKE_SSTP_MODE=ok INJECT_LOG="$MVPN_LOG_BASE/$SUID.log" "$SH" "$MVPN" up sstp "$SUID" >"$T/out" 2>&1 \
  && ok "sstp up (hamis sstpc) sikeres" || { nok "sstp up (hamis sstpc) sikeres"; cat "$T/out"; }
SR="$MVPN_RUN_BASE/$SUID"; SLOG="$MVPN_LOG_BASE/$SUID.log"
[ "$(cat "$SR/iface" 2>/dev/null)" = ppp9 ] && [ "$(cat "$SR/ip" 2>/dev/null)" = 10.0.0.7 ] && sstp_alive_t "$(cat "$SR/pid" 2>/dev/null)" \
  && ok "sstp: pid, iface (ppp9), ip rögzítve" || { nok "sstp: pid, iface (ppp9), ip rögzítve"; ls -la "$SR"; }
grep -qxF -- "--password" "$REC.argv" && grep -qxF -- "$SPW" "$REC.argv" && ok "sstp: a jelszó a sstpc-hez eljut" || nok "sstp: a jelszó a sstpc-hez eljut"
grep -qF "$SPW" "$SLOG" && nok "sstp: jelszó nincs a naplóban (valódi up)" || ok "sstp: jelszó nincs a naplóban (valódi up)"
grep -qF 'PASSWORD: "***"' "$SLOG" && ok "sstp: a sstpc kimenete maszkolva" || { nok "sstp: a sstpc kimenete maszkolva"; cat "$SLOG"; }
grep -qF -- '--password *** vpn.example.com:4443' "$SLOG" && ok "sstp: naplózott parancssor ***-gal" || nok "sstp: naplózott parancssor ***-gal"
[ ! -e "$SR/mask" ] && ok "sstp: a maszk-fájl törölve az up végén" || nok "sstp: a maszk-fájl törölve az up végén"
[ "$(sed -n 1p "$REC.ca" 2>/dev/null)" = 600 ] && [ "$(sed -n 2p "$REC.ca" 2>/dev/null)" = "-----BEGIN CERTIFICATE-----" ] \
  && ok "sstp ca: ca.pem (600) a configból" || { nok "sstp ca: ca.pem (600) a configból"; cat "$REC.ca"; }
[ -f "$MVPN_PPP_OPTIONS" ] && [ "$(stat -f %Lp "$MVPN_PPP_OPTIONS")" = 644 ] && ok "sstp: /etc/ppp/options létrehozva (644)" || nok "sstp: /etc/ppp/options létrehozva (644)"
[ -f "$FL2/.created-ppp-options" ] && ok "sstp: jelölő a létrehozott /etc/ppp/options-ről" || nok "sstp: jelölő a létrehozott /etc/ppp/options-ről"
rm -f "$FL2/.created-ppp-options"
grep -qx -- '-n add -net 0.0.0.0/1 -interface ppp9' "$T/sstp-route.log" && grep -qx -- '-n add -net 128.0.0.0/1 -interface ppp9' "$T/sstp-route.log" \
  && ok "sstp route_all: két /1 útvonal a ppp-re" || { nok "sstp route_all: két /1 útvonal a ppp-re"; cat "$T/sstp-route.log"; }
grep -qx 'up ppp9 dhcp-option DNS 10.0.0.53 dhcp-option DNS 10.0.0.54' "$T/sstp-dns.log" \
  && ok "sstp peer_dns: a közös DNS-hook kapja a szerver DNS-eit" || { nok "sstp peer_dns: a közös DNS-hook kapja a szerver DNS-eit"; cat "$T/sstp-dns.log"; }
grep -q 'ppp6\|ppp7' "$T/sstp-route.log" "$SR/iface" || grep -q '6\.6\.6' "$T/sstp-dns.log" "$SR/ip" \
  && nok "sstp: injektált sorok (naplóban, stderr-en, horgonyzatlan) nem hatnak" || ok "sstp: injektált sorok (naplóban, stderr-en, horgonyzatlan) nem hatnak"
[ "$(wc -l <"$T/sstp-route.log" | tr -d ' ')" = 2 ] && [ "$(wc -l <"$T/sstp-dns.log" | tr -d ' ')" = 1 ] && ok "sstp: pontosan 2 útvonal, 1 DNS-hívás" || nok "sstp: pontosan 2 útvonal, 1 DNS-hívás"
[ "$(stat -f %Lp "$SR/pppd.log" 2>/dev/null)" = 600 ] && grep -q '^\[pppd\] Fri Oct 16 22:58:59 2026 : Using interface ppp9$' "$SLOG" \
  && ok "sstp: pppd.log root-only (600), a naplóba [pppd] előtaggal átmásolva" || { nok "sstp: pppd.log root-only (600), a naplóba [pppd] előtaggal átmásolva"; ls -la "$SR"; }
sed -n '/^start_sstpc()/,/^}/p;/^up_sstp()/,/^}/p' "$MVPN" | grep -q 'export' && nok "sstp: nincs export az indításban" || ok "sstp: nincs export az indításban"
SJ=$(env MVPN_TEST_IFACE_OK=1 "$SH" "$MVPN" status)
printf '%s' "$SJ" | python3 -c '
import json, sys
e = {x["id"]: x for x in json.load(sys.stdin)}[sys.argv[1]]
assert (e["kind"], e["state"], e["iface"], e["ip"]) == ("sstp", "connected", "ppp9", "10.0.0.7"), e
' "$SUID" && ok "sstp status JSON: connected" || { nok "sstp status JSON: connected"; echo "$SJ"; }
SPID=$(cat "$SR/pid" 2>/dev/null)
DESC="sstp down"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL2" MVPN_ROUTE="$T/fakeroute" "$SH" "$MVPN" down sstp "$SUID"
sleep 0.3
! kill -0 "$SPID" 2>/dev/null && [ ! -e "$SR" ] && ok "sstp down: sstpc leállt, futási könyvtár törölve" || { nok "sstp down: sstpc leállt, futási könyvtár törölve"; kill "$SPID" 2>/dev/null; }
grep -q '^down ' "$T/sstp-dns.log" && ok "sstp down: DNS visszaállítva" || nok "sstp down: DNS visszaállítva"
grep -qx -- '-n delete -net 0.0.0.0/1 -interface ppp9' "$T/sstp-route.log" && grep -qx -- '-n delete -net 128.0.0.0/1 -interface ppp9' "$T/sstp-route.log" \
  && ok "sstp down: /1 útvonalak törölve" || { nok "sstp down: /1 útvonalak törölve"; cat "$T/sstp-route.log"; }
[ ! -e "$ST/sstp-pppd.AAAAAA" ] && [ -e "$ST/sstp-pppd.AB" ] && [ -L "$ST/sstp-pppd.SYMSYM" ] && [ -d "$ST/sstp-pppd.DIRDIR" ] \
  && [ -e "$ST/sstp-pppd.NEWNEW" ] && [ "$(cat "$T/sweep-victim")" = x ] \
  && ok "sstp: régi sstp-pppd.XXXXXX takarítva, más (név, symlink, könyvtár, újabb) érintetlen" || { nok "sstp: régi sstp-pppd.XXXXXX takarítva, más (név, symlink, könyvtár, újabb) érintetlen"; ls -la "$ST"; }

# Részleges hiba: a második útvonal nem áll be → hiba, a már felvett útvonal törölve, nincs futási könyvtár.
SUID=$(new_conn "$GOOD_SSTP"); : >"$T/sstp-route.log"
OUT=$(printf 'password=%s\n' "$SPW" | sstp_up FAKE_SSTP_MODE=ok FAKE_ROUTE_FAIL=1 "$SH" "$MVPN" up sstp "$SUID" 2>&1); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Setting the routes failed"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$SUID" ] \
  && grep -qx -- '-n delete -net 0.0.0.0/1 -interface ppp9' "$T/sstp-route.log" && grep -qx -- '-n delete -net 128.0.0.0/1 -interface ppp9' "$T/sstp-route.log" \
  && ok "sstp: útvonal-hiba → takarítás az útvonalakkal együtt" || { nok "sstp: útvonal-hiba → takarítás az útvonalakkal együtt"; echo "$OUT"; cat "$T/sstp-route.log"; }

[ ! -e "$FL2/.created-ppp-options" ] && ok "sstp: meglévő /etc/ppp/options mellett nincs jelölő" || nok "sstp: meglévő /etc/ppp/options mellett nincs jelölő"

# A maszk-fájlt az awk beolvasás után azonnal törli (kapcsolódás közben sincs meg, SIGKILL után sem maradna).
SUID=$(new_conn "$GOOD_SSTP")
printf 'password=%s\n' "$SPW" | sstp_up FAKE_SSTP_MODE=hang MVPN_UP_TIMEOUT=4 "$SH" "$MVPN" up sstp "$SUID" >"$T/hang.out" 2>&1 & W=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -f "$MVPN_RUN_BASE/$SUID/pid" ] && break; sleep 0.2; done
sleep 1
[ -d "$MVPN_RUN_BASE/$SUID" ] && [ ! -e "$MVPN_RUN_BASE/$SUID/mask" ] && ok "sstp: maszk-fájl törölve már kapcsolódás közben" || { nok "sstp: maszk-fájl törölve már kapcsolódás közben"; ls -la "$MVPN_RUN_BASE/$SUID"; }
wait "$W"; RC=$?
[ "$RC" != 0 ] && grep -q 'Timed out' "$T/hang.out" && [ ! -e "$MVPN_RUN_BASE/$SUID" ] && ok "sstp: időtúllépés → takarítás" || { nok "sstp: időtúllépés → takarítás"; cat "$T/hang.out"; }

SUID=$(new_conn "$GOOD_SSTP")
OUT=$(printf 'password=%s\n' "$SPW" | sstp_up FAKE_SSTP_MODE=auth "$SH" "$MVPN" up sstp "$SUID" 2>&1); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Authentication failed"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$SUID" ] \
  && ok "sstp: hitelesítési hiba → hiba, takarítás" || { nok "sstp: hitelesítési hiba → hiba, takarítás"; echo "$OUT"; }
pgrep -f "$T/sstpsleep/sstpc" >/dev/null && nok "sstp: hitelesítési hiba után nem fut sstpc" || ok "sstp: hitelesítési hiba után nem fut sstpc"
SUID=$(new_conn "$GOOD_SSTP")
OUT=$(printf 'password=%s\n' "$SPW" | sstp_up FAKE_SSTP_MODE=cert "$SH" "$MVPN" up sstp "$SUID" 2>&1); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Server certificate error"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$SUID" ] \
  && ok "sstp: tanúsítványhiba → hiba, takarítás" || { nok "sstp: tanúsítványhiba → hiba, takarítás"; echo "$OUT"; }
grep -qF "$SPW" "$MVPN_LOG_BASE/$SUID.log" && nok "sstp: jelszó nincs a naplóban (hiba után)" || ok "sstp: jelszó nincs a naplóban (hiba után)"
SUID=$(new_conn "$GOOD_SSTP")
DESC="sstp: hiányzó sstpc → hiba"; expect_fail sstp_up MVPN_BREW="$T/emptybrew" "$SH" "$MVPN" up sstp "$SUID"
[ ! -e "$MVPN_RUN_BASE/$SUID" ] && ok "sstp: hiányzó sstpc után nincs futási könyvtár" || nok "sstp: hiányzó sstpc után nincs futási könyvtár"

# status / down hamis pid-ekkel és interfészekkel
SB3="$T/sstpstatus"
"$T/sstpsleep/sstpc" 30 & SP1=$!
A=$(uuidgen); B=$(uuidgen); C=$(uuidgen); mkdir -p "$SB3/$A" "$SB3/$B" "$SB3/$C"
echo sstp >"$SB3/$A/kind"; echo "$SP1" >"$SB3/$A/pid"
echo sstp >"$SB3/$B/kind"; dead_pid >"$SB3/$B/pid"; echo ppp3 >"$SB3/$B/iface"
echo sstp >"$SB3/$C/kind"; echo "$SP1" >"$SB3/$C/pid"; echo ppp99 >"$SB3/$C/iface"
D=$(uuidgen); mkdir -p "$SB3/$D"; echo sstp >"$SB3/$D/kind"; echo "$SP1" >"$SB3/$D/pid"; echo $(( $(date +%s) - 100 )) >"$SB3/$D/started"
E=$(uuidgen); mkdir -p "$SB3/$E"; echo sstp >"$SB3/$E/kind"; echo "$SP1" >"$SB3/$E/pid"; date +%s >"$SB3/$E/started"
SJ=$(MVPN_RUN_BASE="$SB3" "$SH" "$MVPN" status)
printf '%s' "$SJ" | python3 -c '
import json, sys
d = {e["id"]: e["state"] for e in json.load(sys.stdin)}
assert d == {sys.argv[1]: "connecting", sys.argv[2]: "failed", sys.argv[3]: "failed", sys.argv[4]: "failed", sys.argv[5]: "connecting"}, d
' "$A" "$B" "$C" "$D" "$E" && ok "sstp status: connecting / halott pid / eltűnt interfész / elavult connecting" || { nok "sstp status: connecting / halott pid / eltűnt interfész / elavult connecting"; echo "$SJ"; }
DID=$(uuidgen); mkdir -p "$MVPN_RUN_BASE/$DID"; echo sstp >"$MVPN_RUN_BASE/$DID/kind"; echo "$SP1" >"$MVPN_RUN_BASE/$DID/pid"
echo secret >"$MVPN_RUN_BASE/$DID/mask"
# Idegen (nem a sstpc gyermeke) pppd nevű folyamat a pppd-pid fájlban: nem szabad leállítani.
mkdir -p "$T/pppdsleep"; ln -s /bin/sleep "$T/pppdsleep/pppd"; "$T/pppdsleep/pppd" 30 & FP=$!
echo "$FP" >"$MVPN_RUN_BASE/$DID/pppd-pid"
DESC="sstp down hamis pid-del"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL2" MVPN_ROUTE="$T/fakeroute" "$SH" "$MVPN" down sstp "$DID"
sleep 0.2
! kill -0 "$SP1" 2>/dev/null && [ ! -e "$MVPN_RUN_BASE/$DID" ] && ok "sstp down: folyamat leállt, takarítva" || nok "sstp down: folyamat leállt, takarítva"
kill -0 "$FP" 2>/dev/null && ok "sstp down: a sstpc-hez nem köthető pppd érintetlen" || nok "sstp down: a sstpc-hez nem köthető pppd érintetlen"
kill "$FP" 2>/dev/null; wait "$FP" 2>/dev/null
kill "$SP1" 2>/dev/null; wait "$SP1" 2>/dev/null
DID=$(uuidgen); mkdir -p "$MVPN_RUN_BASE/$DID"; echo sstp >"$MVPN_RUN_BASE/$DID/kind"
"$SH" "$MVPN" down openvpn "$DID" --dry-run </dev/null >"$T/out" 2>&1
grep -q 'kind mismatch: command line openvpn, running connection sstp' "$MVPN_LOG_BASE/$DID.log" && ok "sstp: down a futó típust (sstp) bontja" || nok "sstp: down a futó típust (sstp) bontja"
rm -rf "${MVPN_RUN_BASE:?}/${DID:?}"

echo "---"; echo "pass: $PASS  fail: $FAIL"
[ "$FAIL" -eq 0 ]
