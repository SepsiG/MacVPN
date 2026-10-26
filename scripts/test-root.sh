#!/bin/bash
# A root réteg (crates/helper) fekete dobozos tesztje nem-root, dry-run / tesztmódban: mvpn, mvpn validate,
# mvpn hook ovpn-dns, mvpn-mgmt / mvpn mgmt-bridge. MVPN_BIN=<abszolút útvonal> egy kész binárist tesztel (pl. a
# dist/MacVPN.app/Contents/Resources/root/mvpn-t); enélkül a crates/helper debug buildjét.
#
# Root réteg 8: az mvpn semmilyen felhasználói fájlt nem nyit meg. A config a standard bemeneten jön, hosszal
# keretezve, utána a titok-sorok (lásd crates/helper/src/shared/framing.rs):
#   config <hossz>\n<pontosan hossz bájt config>username=…\npassword=…\n…
# A tesztkonfigok a $T/cfg/<id> alatt vannak (csak tesztadat, az mvpn sosem olvassa); a `feed <id>` írja ki a keretet.
# Az expect_ok / expect_fail az `up <kind> <id>` hívásnak automatikusan a feed-et adja (ha van ilyen config),
# a titkos up-ok: { feed "$ID"; printf 'username=…'; } | … up …
#
# A 0.x bash root réteg statikus ellenőrzései helyett viselkedés-ellenőrzés fut:
#   - "$SH" "$MVPN" …: SH=/usr/bin/env, így a bináris közvetlenül fut (az env exec-kel cseréli magát, a pid azonos).
#   - A DNS hook: "$MVPN" hook ovpn-dns (OD_* tömbök); a hamis ovpn-dns elé a tesztkönyvtárakba ($FL, $FL2) egy `mvpn`
#     átirányító kerül, mert a réteg a hookot `$LIBEXEC/mvpn hook ovpn-dns`-ként hívja.
#   - A validátor: "$MVPN" validate (VALIDATE tömb); a közvetítő: MVPN_MGMT=$MVPN (argv[0] = mvpn-mgmt).
#   - ovpn-dns `#!/bin/bash -p` → a hook ellenséges környezet (PATH, IFS, locale, BASH_ENV, …) mellett is ugyanazt adja;
#     környezet-allowlist → a hook check-env kimenete pontosan az engedélyezett nevek (+ PATH, LC_ALL);
#     ovpn-dns down `set -f` → a macos::hook_dns::tests::backup_lines_never_glob egységteszt fut;
#     `export MVPN_MASK` hiánya, `export LC_ALL=C`, sstp indítás export nélkül → a gyermekfolyamatok környezete
#       (hamis openvpn / sstpc env-mentéssel): nincs benne titok, PATH és LC_ALL=C rögzített;
#     `pgrep -U 0 -x charon` → ugyanez a Rust forrásban (crates/helper/src/macos/strongswan.rs);
#     OVPN_DONE_RE → a sorok a "$MVPN" __ovpn-done (csak tesztmódú) parancson át;
#     do_respond here-string nélkül → a respond nem ír ideiglenes fájlt (üres TMPDIR marad), a kód csak a
#       futási könyvtár mgmt-resp fájljában van;
#     "validátor hiányzik" (MVPN_VALIDATOR=/nonexistent → hiba) → a validátor beépített, a változó hatástalan.
set -u
cd "$(dirname "$0")/.."
T=$(mktemp -d)
# MFA tesztek: rövid útvonal, mert a unix socket útvonala legfeljebb 104 bájt (a $TMPDIR alatti túl hosszú lenne).
MR=$(mktemp -d /tmp/mvmfa.XXXXXX)
trap 'rm -rf "$T" "$MR"' EXIT
# MVPN_BIN=<abszolút útvonal>: egy kész bináris (pl. a DMG-be került, hardened runtime-mal aláírt universal mvpn).
if [ -n "${MVPN_BIN:-}" ]; then
  case "$MVPN_BIN" in /*) ;; *) echo "MVPN_BIN: abszolút útvonal kell"; exit 2 ;; esac
  MVPN="$MVPN_BIN"
else
  PATH="$HOME/.cargo/bin:$PATH" cargo build -q -p macvpn-helper --locked || { echo "mvpn build sikertelen"; exit 1; }
  MVPN="$PWD/target/debug/mvpn"
fi
SH=/usr/bin/env   # "$SH" "$MVPN" … = a bináris közvetlen futtatása
export MVPN_MGMT="$MVPN"
VALIDATE=("$MVPN" validate)
OD_SH=("$MVPN" hook ovpn-dns); OD_SELF=("$MVPN" hook ovpn-dns); OD_P=("$MVPN" hook ovpn-dns)
VERSION_FILE="$PWD/crates/helper/VERSION"; EXPECT_VERSION=9
# A hamis ovpn-dns elé: `mvpn hook ovpn-dns <run> <log>` → <könyvtár>/ovpn-dns <run> <log>.
hook_shim() {
  printf '#!/bin/bash\n[ "$1 $2" = "hook ovpn-dns" ] || exit 99\nshift 2\nexec "$(dirname "$0")/ovpn-dns" "$@"\n' >"$1/mvpn"
  chmod 755 "$1/mvpn"
}
export MVPN_UI_BASE="$T/ui"
export MVPN_RUN_BASE="$T/run" MVPN_LOG_BASE="$T/log"
CFG="$T/cfg"
mkdir -p "$T/emptybrew" "$CFG"
# Hamis "openvpn" folyamat: symlink a /bin/sleep-re (a másolatot az aláírás-ellenőrzés megölné),
# így a ps comm neve openvpn-re végződik.
mkdir -p "$T/bin"; ln -s /bin/sleep "$T/bin/openvpn"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "ok   - $1"; }
nok()  { FAIL=$((FAIL+1)); echo "FAIL - $1"; }

new_conn() { # $1=config tartalom → id kiírva; a config a $CFG/<id> fájlba (sorvéggel)
  local id; id=$(uuidgen)
  printf '%s\n' "$1" > "$CFG/$id"
  echo "$id"
}
# feed <id>: a keretezett config (`config <bájtszám>\n` + a fájl). A bájtszám wc -c-vel, LC_ALL=C mellett (nem ${#var}).
feed() {
  local n; n=$(LC_ALL=C wc -c <"$CFG/$1" | tr -d ' ')
  printf 'config %s\n' "$n"; cat "$CFG/$1"
}
# auto_feed <parancs…>: ha a parancsban `up <kind> <id>` áll és van $CFG/<id>, a feed-je; különben üres bemenet.
auto_feed() {
  local prev2="" prev1="" a
  for a in "$@"; do
    if [ "$prev2" = up ] && [ -f "$CFG/$a" ]; then feed "$a"; return; fi
    prev2=$prev1; prev1=$a
  done
}
expect_ok()   { if "$@" < <(auto_feed "$@") >"$T/out" 2>&1; then ok "$DESC"; else nok "$DESC"; cat "$T/out"; fi; }
expect_fail() { if "$@" < <(auto_feed "$@") >"$T/out" 2>&1; then nok "$DESC"; cat "$T/out"; else ok "$DESC"; fi; }

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

for d in up down route-up plugin script-security config daemon log-append management user group pkcs11-providers chroot echo; do
  DESC="openvpn tiltott/kockázatos jelzés nélkül: $d"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\n'"$d /tmp/x")" --dry-run
done

# Kockázatos (RISKY) direktívák: csak a kapcsolatnál tudomásul vett nevek (--accept-risky) mellett mennek át;
# a FORBIDDEN szintet a jelzés nem oldja fel; a jelzés értéke szigorú formátumú.
RISKY_OVPN="$GOOD_OVPN"$'\nuser nobody\ngroup nogroup\nremap-usr1 SIGTERM\nsetenv CONFIG_VERSION "2.0.4"'
DESC="kockázatos jelzés nélkül → elutasítva"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$RISKY_OVPN")" --dry-run
DESC="kockázatos, csak részben tudomásul véve → elutasítva"
expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$RISKY_OVPN")" --dry-run --accept-risky user
DESC="kockázatos --accept-risky mellett → elfogadva"
expect_ok "$SH" "$MVPN" up openvpn "$(new_conn "$RISKY_OVPN")" --dry-run --accept-risky group,user --lang en
grep -q 'acknowledged risky directives: group,user' "$MVPN_LOG_BASE"/*.log && ok "kockázatos lista a naplóban" || nok "kockázatos lista a naplóban"
DESC="ismeretlen direktíva --accept-risky mellett → elfogadva"
expect_ok "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nfuture-option 3 abc')" --dry-run --accept-risky future-option
DESC="ismeretlen direktíva útvonal-argumentummal → elutasítva jelzéssel is"
expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nfuture-option /etc/master.passwd')" --dry-run --accept-risky future-option
for d in up chroot plugin script-security echo; do
  DESC="tiltott név az --accept-risky-ben is tiltott: $d"
  expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\n'"$d x")" --dry-run --accept-risky "$d"
done
for v in 'User' 'a,,b' ',a' 'a;b' 'a b' '../x' ''; do
  DESC="érvénytelen --accept-risky érték: '$v'"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")" --dry-run --accept-risky "$v"
done
DESC="--accept-risky érték nélkül (utolsó argumentum)"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")" --dry-run --accept-risky
DESC="tiltott setenv név: LD_PRELOAD"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nsetenv LD_PRELOAD x')" --dry-run --accept-risky ld-preload
# A `-p` shebang helyett: ellenséges környezet (PATH, IFS, locale, BASH_ENV, GREP_OPTIONS) nem hat a hookra.
OUT=$(env PATH=/nonexistent IFS=x LC_ALL=hu_HU.UTF-8 LANG=hu_HU.UTF-8 BASH_ENV="$T/evil-env" GREP_OPTIONS=-v \
  script_type=check foreign_option_1='dhcp-option DNS 10.0.0.53' "${OD_SELF[@]}" "$T" "$T/od-env.log" 2>&1)
[ "$OUT" = "DNS 10.0.0.53" ] && ok "hook: ellenséges környezet nem hat" || nok "hook: ellenséges környezet nem hat ($OUT)"
# Az allowlist-sor helyett: a hook pontosan az engedélyezett változókat olvassa (a többi nem is látszik).
OUT=$(env -i FOO=bar DYLD_FAKE=1 script_type=check-env dev=utun3 ifconfig_local=10.8.0.2 foreign_option_1=x foreign_option_3=y \
  "${OD_SELF[@]}" "$T" "$T/od-env.log" 2>&1 | tr '\n' ' ')
[ "$OUT" = "LC_ALL PATH dev foreign_option_1 ifconfig_local script_type " ] && ok "hook: környezet-allowlist" || nok "hook: környezet-allowlist ($OUT)"
OUT=$(env BASH_ENV="$T/evil-env" ENV="$T/evil-env" script_type=check foreign_option_1='dhcp-option DNS 10.0.0.53' \
  "${OD_SELF[@]}" "$T" "$T/od-env.log" 2>&1)
[ "$OUT" = "DNS 10.0.0.53" ] && ok "ovpn-dns: BASH_ENV mellett is csak a saját kimenete" || nok "ovpn-dns: BASH_ENV mellett is csak a saját kimenete ($OUT)"
# Környezet-allowlist: csak az OpenVPN által adott, a hook által olvasott változók (és a fix PATH/LC_ALL) maradnak.
OUT=$(env -i TMOUT=1 POSIXLY_CORRECT=1 CDPATH=/tmp GLOBIGNORE='*' BASH_ENV="$T/evil-env" SHELLOPTS=xtrace FOO=bar \
  OPENSSL_CONF=/x GREP_OPTIONS=-v script_type=check-env dev=utun3 ifconfig_local=10.8.0.2 foreign_option_1='dhcp-option DNS 1.1.1.1' \
  "${OD_P[@]}" "$T" "$T/od-env.log" 2>&1)
# A SHELLOPTS readonly: a bash a saját (a -p miatt a környezetből nem átvett) értékével exportálja; xtrace nincs.
BADVARS=$(printf '%s\n' "$OUT" | grep -E '^(TMOUT|POSIXLY_CORRECT|CDPATH|GLOBIGNORE|BASH_ENV|FOO|OPENSSL_CONF|GREP_OPTIONS|[+].*)$')
[ -z "$BADVARS" ] && printf '%s\n' "$OUT" | grep -qx script_type \
  && printf '%s\n' "$OUT" | grep -qx foreign_option_1 && printf '%s\n' "$OUT" | grep -qx LC_ALL \
  && ok "ovpn-dns: környezet-allowlist (TMOUT, POSIXLY_CORRECT, CDPATH, … törölve, posix mód ki)" || { nok "ovpn-dns: környezet-allowlist"; echo "$OUT"; }
OUT=$(env TMOUT=1 POSIXLY_CORRECT=1 script_type=check foreign_option_1='dhcp-option DNS 10.0.0.53' "${OD_SELF[@]}" "$T" "$T/od-env.log" 2>&1)
[ "$OUT" = "DNS 10.0.0.53" ] && ok "ovpn-dns: TMOUT/POSIXLY_CORRECT mellett is ugyanaz a kimenet" || nok "ovpn-dns: TMOUT/POSIXLY_CORRECT mellett is ugyanaz a kimenet ($OUT)"

# MikroTik RouterOS által exportált / a wiki szerinti configok: tudomásulvétel nélkül, rootként is átmennek.
for f in Tests/Fixtures/mikrotik/routeros-v7-export-udp.ovpn Tests/Fixtures/mikrotik/routeros-v7-export-tcp.ovpn \
         Tests/Fixtures/mikrotik/routeros-v7-export-tls-crypt.ovpn Tests/Fixtures/mikrotik/routeros-wiki-extras.ovpn \
         Tests/Fixtures/mikrotik/routeros-v6-imported.ovpn; do
  DESC="MikroTik fixture, jelzés nélkül: ${f##*/}"; expect_ok "$SH" "$MVPN" up openvpn "$(new_conn "$(cat "$f")")" --dry-run
done
DESC="MikroTik v6 import előtt (külső fájlok) rootként elutasítva"
expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$(cat Tests/Fixtures/mikrotik/routeros-v6-wiki.ovpn)")" --dry-run
DESC="script-security 1 (SAFE)"; expect_ok "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nscript-security 1')" --dry-run
DESC="script-security 2 jelzéssel is tiltott"
expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nscript-security 2')" --dry-run --accept-risky script-security

# Privát kulcs jelszava: --askpass $RUN/askpass, a jelszó soha nem látszik.
KID=$(new_conn "$GOOD_OVPN")
{ feed "$KID"; printf 'username=bob\npassword=Sup3rTitok\nkeypass=K3yP4ssTitok\n'; } | "$SH" "$MVPN" up openvpn "$KID" --dry-run --debug >"$T/kp.out" 2>&1
grep -q 'DRY: .*--askpass [^ ]*/askpass' "$T/kp.out" && ok "dry-run: --askpass \$RUN/askpass" || { nok "dry-run: --askpass \$RUN/askpass"; cat "$T/kp.out"; }
grep -q 'K3yP4ssTitok' "$T/kp.out" "$MVPN_LOG_BASE/$KID.log" && nok "kulcsjelszó nem látszik" || ok "kulcsjelszó nem látszik"
KID2=$(new_conn "$GOOD_OVPN")
{ feed "$KID2"; printf 'username=bob\npassword=x1\n'; } | "$SH" "$MVPN" up openvpn "$KID2" --dry-run >"$T/kp2.out" 2>&1
grep -q -- '--askpass' "$T/kp2.out" && nok "kulcsjelszó nélkül nincs --askpass" || ok "kulcsjelszó nélkül nincs --askpass"
OUT=$(printf 'k K3yP4ss\n' | MVPN_MASK_3=K3yP4ss "$SH" "$MVPN" __mask)
[ "$OUT" = "k ***" ] && ok "mask: kulcsjelszó" || nok "mask: kulcsjelszó ($OUT)"
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

# A validátor beépített (a core validátorai), az MVPN_VALIDATOR nem hook: hatástalan.
DESC="validátor beépített (MVPN_VALIDATOR hatástalan)"; expect_ok env MVPN_VALIDATOR=/nonexistent "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")" --dry-run
DESC="nem UUID id";          expect_fail "$SH" "$MVPN" up openvpn "../../etc" --dry-run
DESC="ismeretlen kind";      expect_fail "$SH" "$MVPN" up pptp "$(uuidgen)" --dry-run
DESC="hiányzó config";       expect_fail "$SH" "$MVPN" up openvpn "$(uuidgen)" --dry-run

# ---------- Root réteg 8: a config a standard bemeneten (keretezve) ----------
# Minden elutasításnál: kilépés 1, pontosan az üzenet a stderr-en (és ✗-gel a naplóban), nincs futási könyvtár, és
# a naplóba nem kerül titok (FrameS3cret) vagy config-sor (FRAMEMARK, a config utolsó sora).
FR="$T/frames"; mkdir -p "$FR"
FRAME_CFG="$GOOD_OVPN"$'\n# FRAMEMARK'
printf '%s\n' "$FRAME_CFG" >"$FR/cfg"
FRAME_LEN=$(LC_ALL=C wc -c <"$FR/cfg" | tr -d ' ')
frame_case() { # $1=leírás $2=várt üzenet $3=bemenet-fájl, a többi: extra up argumentum
  local desc=$1 msg=$2 in=$3 id out rc; shift 3
  id=$(uuidgen)
  out=$("$SH" "$MVPN" up openvpn "$id" --dry-run "$@" <"$in" 2>&1); rc=$?
  if [ "$rc" = 1 ] && [ "$out" = "$msg" ] && [ -z "$(ls "$MVPN_RUN_BASE" 2>/dev/null)" ] \
     && grep -qxF "✗ $msg" "$MVPN_LOG_BASE/$id.log" && ! grep -q 'FrameS3cret\|FRAMEMARK\|remote vpn' "$MVPN_LOG_BASE/$id.log"; then
    ok "$desc"
  else
    nok "$desc"; echo "rc=$rc out=$out"; ls -la "$MVPN_RUN_BASE" 2>/dev/null; cat "$MVPN_LOG_BASE/$id.log"
  fi
}
SECRETS_IN=$'username=bob\npassword=FrameS3cret\n'
{ printf 'config %s\n' "$FRAME_LEN"; cat "$FR/cfg"; printf '%s' "$SECRETS_IN"; } >"$FR/good"
DESC="stdin: jó keret titkokkal (kontroll)"; expect_ok "$SH" "$MVPN" up openvpn "$(new_conn "$FRAME_CFG")" --dry-run
OUT=$("$SH" "$MVPN" up openvpn "$(uuidgen)" --dry-run <"$FR/good" 2>&1) && ! grep -q 'FrameS3cret\|FRAMEMARK' "$MVPN_LOG_BASE"/*.log \
  && ok "stdin: jó keret a fájlból, a titok és a config nincs a naplóban" || { nok "stdin: jó keret a fájlból, a titok és a config nincs a naplóban"; echo "$OUT"; }
{ printf 'config 100\n'; head -c 50 "$FR/cfg"; } >"$FR/trunc"
frame_case "stdin: csonka folyam (len 100, 50 bájt)" "The config is incomplete" "$FR/trunc"
frame_case "stdin: csonka folyam magyarul" "A config hiányos" "$FR/trunc" --lang hu
{ printf 'config %s\n' "$((FRAME_LEN - 12))"; cat "$FR/cfg"; printf '%s' "$SECRETS_IN"; } >"$FR/short"
frame_case "stdin: hosszeltérés (len rövidebb: config-sorok titok-sorként)" "Invalid input" "$FR/short"
{ printf 'config %s\n' "$((FRAME_LEN + 5))"; cat "$FR/cfg"; printf '%s' "$SECRETS_IN"; } >"$FR/long"
frame_case "stdin: hosszeltérés (len hosszabb: titok-sor csonkja marad)" "Invalid input" "$FR/long"
{ printf 'config %s\n' "$((FRAME_LEN + 500))"; cat "$FR/cfg"; printf '%s' "$SECRETS_IN"; } >"$FR/longer"
frame_case "stdin: hosszeltérés (len hosszabb a folyamnál)" "The config is incomplete" "$FR/longer"
{ printf 'config 1048577\n'; head -c 1048577 /dev/zero | tr '\0' '#'; } >"$FR/over"
frame_case "stdin: túl nagy config (len 1048577)" "The config is too large (1 MB at most)" "$FR/over"
{ printf 'config 1048576\n'; head -c 1048576 /dev/zero | tr '\0' '#'; } >"$FR/max"
OUT=$("$SH" "$MVPN" up openvpn "$(uuidgen)" --dry-run <"$FR/max" 2>&1); RC=$?
[ "$RC" = 1 ] && case "$OUT" in "Invalid config:"*) true ;; *) false ;; esac && [ -z "$(ls "$MVPN_RUN_BASE" 2>/dev/null)" ] \
  && ok "stdin: pontosan 1 MB átmegy a kereten (a validátor dönt)" || { nok "stdin: pontosan 1 MB átmegy a kereten (a validátor dönt)"; echo "$RC ${OUT:0:200}"; }
{ printf 'client\n\0dev tun\n'; cat "$FR/cfg"; } >"$FR/nulcfg"
{ printf 'config %s\n' "$(LC_ALL=C wc -c <"$FR/nulcfg" | tr -d ' ')"; cat "$FR/nulcfg"; printf '%s' "$SECRETS_IN"; } >"$FR/nul"
frame_case "stdin: NUL bájt a configban" "The config must not contain NUL bytes" "$FR/nul"
for h in 'config -1' 'config 01' 'config 1x' 'config +5' 'config  5' 'config'; do
  { printf '%s\n' "$h"; cat "$FR/cfg"; } >"$FR/badhdr"
  frame_case "stdin: rossz fejléc: '$h'" "Invalid input" "$FR/badhdr"
done
printf 'config %s' "$FRAME_LEN" >"$FR/nonl"
frame_case "stdin: fejléc sorvég nélkül" "Invalid input" "$FR/nonl"
{ printf '%s' "$SECRETS_IN"; printf 'config %s\n' "$FRAME_LEN"; cat "$FR/cfg"; } >"$FR/secfirst"
frame_case "stdin: titok-sor a fejléc előtt" "Config not provided" "$FR/secfirst"
{ printf 'xx'; cat "$FR/good"; } >"$FR/garbage"
frame_case "stdin: szemét a keret előtt" "Config not provided" "$FR/garbage"
{ printf 'config %s\n' "$FRAME_LEN"; cat "$FR/cfg"; printf 'username=bob\nFrameS3cret\n'; } >"$FR/badsecret"
frame_case "stdin: ismeretlen sor a titkok között" "Invalid input" "$FR/badsecret"
{ printf 'config %s\n' "$FRAME_LEN"; cat "$FR/cfg"; printf 'password=FrameS3cret'; } >"$FR/unterminated"
frame_case "stdin: lezáratlan utolsó titok-sor" "Invalid input" "$FR/unterminated"
: >"$FR/empty"
frame_case "stdin: üres bemenet" "Config not provided" "$FR/empty"
frame_case "stdin: üres bemenet magyarul" "Nincs megadva config" "$FR/empty" --lang hu
# A régi útvonalon hagyott config hatástalan: a root réteg nem nyit meg felhasználói fájlt (MVPN_SRC_BASE sincs már).
OLD_ID=$(uuidgen); mkdir -p "$T/src/$OLD_ID"; printf '%s\n' "$GOOD_OVPN" >"$T/src/$OLD_ID/config"
OUT=$(printf '%s' "$SECRETS_IN" | env MVPN_SRC_BASE="$T/src" "$SH" "$MVPN" up openvpn "$OLD_ID" --dry-run 2>&1); RC=$?
[ "$RC" = 1 ] && [ "$OUT" = "Config not provided" ] && [ -z "$(ls "$MVPN_RUN_BASE" 2>/dev/null)" ] \
  && ok "stdin: a régi útvonalon hagyott config hatástalan (fejléc nélkül: Config not provided)" || { nok "stdin: a régi útvonalon hagyott config hatástalan (fejléc nélkül: Config not provided)"; echo "$RC $OUT"; }
# Valódi (nem dry-run) up is ugyanígy utasít el, futási könyvtár nélkül.
OUT=$(env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$T/emptybrew" "$SH" "$MVPN" up openvpn "$(uuidgen)" <"$FR/short" 2>&1); RC=$?
[ "$RC" = 1 ] && [ "$OUT" = "Invalid input" ] && [ -z "$(ls "$MVPN_RUN_BASE" 2>/dev/null)" ] \
  && ok "stdin: valódi up hosszeltéréssel → Invalid input, nincs futási könyvtár" || { nok "stdin: valódi up hosszeltéréssel → Invalid input, nincs futási könyvtár"; echo "$RC $OUT"; }
# A config `password=` sorai configként maradnak (a hossz dönt), nem titokként: az SSTP validátor elutasítja a sort.
PWC_ID=$(new_conn $'server=vpn.example.com\nuser=bob\npassword=CfgLineXYZ')
OUT=$({ feed "$PWC_ID"; printf 'password=RealS3cretPw\n'; } | "$SH" "$MVPN" up sstp "$PWC_ID" --dry-run 2>&1); RC=$?
[ "$RC" = 1 ] && case "$OUT" in *"Invalid config:"*"Line 3: Key not allowed: password"*) true ;; *) false ;; esac \
  && ! grep -q 'RealS3cretPw\|CfgLineXYZ' "$MVPN_LOG_BASE/$PWC_ID.log" \
  && ok "stdin: a config password= sora config marad, nem titok" || { nok "stdin: a config password= sora config marad, nem titok"; echo "$OUT"; }
DESC="up dry-run nélkül nem-rootként"; expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")"
DESC="dry-run nem hagy futási könyvtárat"
[ -z "$(ls "$MVPN_RUN_BASE" 2>/dev/null)" ] && ok "$DESC" || { nok "$DESC"; ls -la "$MVPN_RUN_BASE"; }

# Jelszó maszkolás és naplóformátum
MID=$(new_conn "$GOOD_OVPN")
{ feed "$MID"; printf 'username=bob\npassword=Sup3rTitok\n'; } | "$SH" "$MVPN" up openvpn "$MID" --dry-run --debug >/dev/null 2>&1
LOG="$MVPN_LOG_BASE/$MID.log"
grep -q '^═══ ' "$LOG" && ok "napló fejléc" || nok "napló fejléc"
grep -q '^\$ ' "$LOG" && ok "napló parancssor" || nok "napló parancssor"
grep -q '^▶ \[mvpn\]' "$LOG" && ok "napló lépés" || nok "napló lépés"
grep -q 'Sup3rTitok' "$LOG" && nok "jelszó nem kerülhet a naplóba" || ok "jelszó nem kerül a naplóba"
# Az `export` keresése helyett a gyermekfolyamatok tényleges környezete: hamis openvpn / sstpc, ami a
# környezetét elmenti és hibával kilép. Nincs benne titok; PATH és LC_ALL=C rögzített.
EB="$T/envbrew"; mkdir -p "$EB/bin" "$EB/sbin" "$T/envlibexec"
printf '#!/bin/bash\n/usr/bin/env >"%s"\nexit 1\n' "$T/child-env.openvpn" >"$EB/bin/openvpn"
printf '#!/bin/bash\n/usr/bin/env >"%s"\nexit 1\n' "$T/child-env.sstpc" >"$EB/sbin/sstpc"
chmod 755 "$EB/bin/openvpn" "$EB/sbin/sstpc"
ENVID=$(new_conn "$GOOD_OVPN")
{ feed "$ENVID"; printf 'username=bob\npassword=EnvS3cretPw\nkeypass=EnvK3yPw77\n'; } | env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$EB" MVPN_LIBEXEC="$T/envlibexec" \
  "$MVPN" up openvpn "$ENVID" >/dev/null 2>&1
ENVID=$(new_conn $'server=vpn.example.com\nuser=bob')
{ feed "$ENVID"; printf 'password=EnvS3cretPw\notp=EnvOtp4242\n'; } | env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$EB" MVPN_LIBEXEC="$T/envlibexec" \
  MVPN_PPP_OPTIONS="$T/envppp/options" MVPN_UP_TIMEOUT=3 "$MVPN" up sstp "$ENVID" >/dev/null 2>&1
[ -s "$T/child-env.openvpn" ] && [ -s "$T/child-env.sstpc" ] && ! grep -q 'EnvS3cretPw\|EnvK3yPw77\|EnvOtp4242\|MVPN_MASK' "$T/child-env.openvpn" "$T/child-env.sstpc" \
  && ok "titkok nincsenek a gyermekfolyamatok környezetében (openvpn, sstpc)" || { nok "titkok nincsenek a gyermekfolyamatok környezetében (openvpn, sstpc)"; cat "$T/child-env.openvpn" "$T/child-env.sstpc"; }
SWID=$(new_conn "$GOOD_SWAN")
{ feed "$SWID"; printf 'username=alice\npassword=EapTitok42\npsk=PskTitok99\n'; } | "$SH" "$MVPN" up strongswan "$SWID" --dry-run --debug >"$T/sw.out" 2>&1
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
# `export LC_ALL=C` helyett: a gyermekfolyamatok LC_ALL=C-t és a rögzített PATH-t kapják.
grep -qx 'LC_ALL=C' "$T/child-env.openvpn" && grep -qx 'PATH=/usr/bin:/bin:/usr/sbin:/sbin' "$T/child-env.openvpn" \
  && grep -qx 'LC_ALL=C' "$T/child-env.sstpc" && grep -qx 'PATH=/usr/bin:/bin:/usr/sbin:/sbin' "$T/child-env.sstpc" \
  && ok "LC_ALL=C és rögzített PATH a gyermekfolyamatokban" || nok "LC_ALL=C és rögzített PATH a gyermekfolyamatokban"
[ "$("$SH" "$MVPN" version)" = "$EXPECT_VERSION" ] && [ "$(cat "$VERSION_FILE")" = "$EXPECT_VERSION" ] && ok "root verzió: $EXPECT_VERSION" || nok "root verzió: $EXPECT_VERSION"
# Az 1.4.0 kompatibilitási fixture-ök (platformsemleges refaktor, Task 1): az mvpn argumentum nélkül és a `version`
# kimenete (stdout és stderr együtt, az utolsó sorban `exit <kód>`) bájtra azonos az 1.4.0-éval.
COMPAT=crates/app-core/tests/fixtures/compat-1.4.0
compat_out() { "$SH" "$MVPN" "$@" </dev/null 2>&1; echo "exit $?"; }
compat_out | cmp -s - "$COMPAT/mvpn-usage.txt" && ok "1.4.0 fixture: mvpn (argumentum nélkül)" \
  || { nok "1.4.0 fixture: mvpn (argumentum nélkül)"; compat_out | diff "$COMPAT/mvpn-usage.txt" - ; }
# The output's form is 1.4.0's; the number is the current root layer's (1.4.0 shipped 8).
compat_out version | cmp -s - <(sed "1s/.*/$EXPECT_VERSION/" "$COMPAT/mvpn-version.txt") && ok "1.4.0 fixture: mvpn version" \
  || { nok "1.4.0 fixture: mvpn version"; compat_out version | diff <(sed "1s/.*/$EXPECT_VERSION/" "$COMPAT/mvpn-version.txt") - ; }
OUT=$(printf 'Szép ÁRVÍZTŰRŐ\n' | env LC_ALL=hu_HU.UTF-8 LANG=hu_HU.UTF-8 MVPN_MASK_1=ŰR "$SH" "$MVPN" __mask)
[ "$OUT" = "Szép ÁRVÍZT***Ő" ] && ok "mask felhasználói locale mellett is bájt-alapú" || nok "mask felhasználói locale mellett is bájt-alapú ($OUT)"
# Ugyanez a Rust forrásban: a charon pid-ek csak a `pgrep -U 0 -x charon` (root) találatai lehetnek.
SW_SRC=crates/helper/src/macos/strongswan.rs
grep -qF '"-U", "0", "-x", "charon"' "$SW_SRC" && [ "$(grep -c '"charon"' "$SW_SRC")" = 1 ] && ! grep -rq --include='*.rs' 'pkill' crates/helper/src \
  && ok "charon: csak root folyamat (pgrep -U 0)" || nok "charon: csak root folyamat (pgrep -U 0)"

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
ODR="$T/odrun"; mkdir -p "$ODR"
env -i script_type=up dev=utun9 ifconfig_local=10.8.0.2 "${OD_SH[@]}" "$ODR" "$T/od.log"
[ "$(cat "$ODR/iface" 2>/dev/null)" = utun9 ] && [ "$(cat "$ODR/ip" 2>/dev/null)" = 10.8.0.2 ] && ok "ovpn-dns iface/ip" || nok "ovpn-dns iface/ip"
grep -q 'the server sent no DNS' "$T/od.log" && ok "ovpn-dns DNS nélkül (lang fájl nélkül angol)" || nok "ovpn-dns DNS nélkül (lang fájl nélkül angol)"
printf 'hu\n' >"$ODR/lang"
env -i script_type=up dev=utun9 "${OD_SH[@]}" "$ODR" "$T/od-hu.log"
grep -q 'a szerver nem küldött DNS-t' "$T/od-hu.log" && ok "ovpn-dns magyarul (lang=hu)" || nok "ovpn-dns magyarul (lang=hu)"
rm -f "$ODR/lang"
env -i script_type=up dev=utun9 'foreign_option_1=dhcp-option DNS 1.1.1.1;touch /tmp/x' "${OD_SH[@]}" "$ODR" "$T/od2.log"
grep -q 'the server sent no DNS' "$T/od2.log" && [ ! -f "$ODR/dns-backup" ] && ok "ovpn-dns érvénytelen DNS elutasítva" || nok "ovpn-dns érvénytelen DNS elutasítva"
DESC="ovpn-dns down mentés nélkül"; expect_ok env -i script_type=down "${OD_SH[@]}" "$ODR" "$T/od.log"

OUT=$(env -i script_type=check \
  'foreign_option_1=dhcp-option DNS 10.0.0.1' 'foreign_option_2=dhcp-option DNS 1.2.3' \
  'foreign_option_3=dhcp-option DNS ::' 'foreign_option_4=dhcp-option DNS fd00::53' \
  'foreign_option_5=dhcp-option DNS 1:2' 'foreign_option_6=dhcp-option DNS 1.1.1.1.1' \
  'foreign_option_7=dhcp-option DOMAIN corp.example' 'foreign_option_8=dhcp-option DOMAIN -evil' \
  'foreign_option_9=dhcp-option DOMAIN .x' 'foreign_option_10=dhcp-option DOMAIN a b' \
  "${OD_SH[@]}" "$ODR" "$T/od3.log" | tr '\n' '|')
[ "$OUT" = "DNS 10.0.0.1|DNS fd00::53|DOMAIN corp.example|" ] && ok "ovpn-dns szigorú DNS/DOMAIN" || nok "ovpn-dns szigorú DNS/DOMAIN ($OUT)"
ODR2="$T/odrun2"; mkdir -p "$ODR2"
env -i script_type=up 'dev=utun1;x' 'ifconfig_local=10.0.0.2/24' "${OD_SH[@]}" "$ODR2" "$T/od4.log"
[ ! -e "$ODR2/iface" ] && [ ! -e "$ODR2/ip" ] && ok "ovpn-dns érvénytelen dev/ip nem íródik" || nok "ovpn-dns érvénytelen dev/ip nem íródik"
# `set -f` helyett: a dns-backup sorainak bontása soha nem glob-kifejt (egységteszt).
PATH="$HOME/.cargo/bin:$PATH" cargo test -q -p macvpn-helper --locked -- macos::hook_dns::tests::backup_lines_never_glob >"$T/glob.out" 2>&1 \
  && grep -q '1 passed' "$T/glob.out" && ok "hook down: nincs glob-kifejtés" || { nok "hook down: nincs glob-kifejtés"; cat "$T/glob.out"; }

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

# Túl nagy config (valódi tartalommal, helyes hosszal keretezve)
BIG=$(new_conn "$GOOD_OVPN"); head -c 1100000 /dev/zero | tr '\0' '#' >>"$CFG/$BIG"
DESC="1 MB-nál nagyobb config elutasítva"; expect_fail "$SH" "$MVPN" up openvpn "$BIG" --dry-run

# Napló forgatás (5 MB fölött), symlink-biztosan: a .1 a legújabb teljes sorokat tartja, legfeljebb 5 MiB-ot
RID=$(new_conn "$GOOD_OVPN"); RL="$MVPN_LOG_BASE/$RID.log"
{ head -c 5300000 /dev/zero | tr '\0' x; echo; echo OLDMARKER; } >"$RL"
echo victim >"$T/victim"; ln -s "$T/victim" "$RL.1"
DESC="up forgatással"; expect_ok "$SH" "$MVPN" up openvpn "$RID" --dry-run
[ ! -L "$RL.1" ] && grep -q OLDMARKER "$RL.1" && [ "$(stat -f %z "$RL.1")" -le 5242880 ] && ok "napló .1 a régi tartalommal" || nok "napló .1 a régi tartalommal"
[ "$(cat "$T/victim")" = victim ] && ok "symlink cél érintetlen" || nok "symlink cél érintetlen"
[ "$(stat -f %z "$RL")" -lt 100000 ] && ! grep -q OLDMARKER "$RL" && ok "új napló kicsi" || nok "új napló kicsi"
[ "$(stat -f %Lp "$RL.1")" = 600 ] && [ "$(stat -f %Lp "$RL")" = 600 ] && ok "napló jogosultság 600" || nok "napló jogosultság 600"
{ head -c 5300000 /dev/zero | tr '\0' y; echo; echo NEWMARKER; } >"$RL"
"$SH" "$MVPN" up openvpn "$RID" --dry-run < <(feed "$RID") >/dev/null 2>&1
grep -q NEWMARKER "$RL.1" && ! grep -q OLDMARKER "$RL.1" && [ ! -e "$RL.2" ] && ok "csak egy .1 marad" || nok "csak egy .1 marad"
SZ=$(stat -f %z "$RL"); "$SH" "$MVPN" down openvpn "$RID" --dry-run </dev/null >/dev/null 2>&1
grep -q NEWMARKER "$RL.1" && [ "$(stat -f %z "$RL")" -ge "$SZ" ] && ok "down nem forgat" || nok "down nem forgat"

# A "kapcsolódva" minta minden valódi OpenVPN 2.7 naplóformátumra illeszkedik, és a hamisítványokra nem.
# A minta a Rust forrásban van: a sorokat a tesztmódú `__ovpn-done` parancs ítéli meg.
done_match() { printf '%s\n' "$1" | "$MVPN" __ovpn-done; }
for line in "2026-10-18 15:22:48 Initialization Sequence Completed" \
            "2026-10-18 15:42:51 us=411817 Initialization Sequence Completed" \
            "Initialization Sequence Completed" \
            "1792330971.453131 32000004 Initialization Sequence Completed" \
            "2026-10-18 15:42:51 us=5 Initialization Sequence Completed With Errors ( see http://openvpn.net/faq.html#dhcpclientserv )"; do
  done_match "$line" && ok "completion minta illeszkedik: ${line:0:40}" || nok "completion minta illeszkedik: $line"
done
for line in "2026-10-18 15:22:48 ECHO:msg x Initialization Sequence Completed" \
            "2026-10-18 15:22:48 PUSH: Received control message: 'PUSH_REPLY,echo msg Initialization Sequence Completed'" \
            "2026-10-18 15:22:48 us=abc Initialization Sequence Completed"; do
  done_match "$line" && nok "completion minta nem illeszkedik: $line" || ok "completion minta nem illeszkedik: ${line:0:40}"
done

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
printf '%s\n' "2026-10-17 00:00:00 Initialization Sequence Completed" "x KEEPMARKER" "x Password: LEAKPW1" "x AUTH: Received control message LEAKAUTH2" "x passwd LEAKPW3" >"$FB/$F1/openvpn.log"
: >"$FLG/$F1.log"
mkdir "$FB/.$F1.lock"; echo "$FP" >"$FB/.$F1.lock/pid"
MVPN_RUN_BASE="$FB" MVPN_LOG_BASE="$FLG" "$SH" "$MVPN" status >/dev/null
[ ! -s "$FLG/$F1.log" ] && [ "$(cat "$FB/.$F1.lock/pid")" = "$FP" ] && ok "status: foglalt zárnál nincs átmásolás, a zár érintetlen" || nok "status: foglalt zárnál nincs átmásolás, a zár érintetlen"
rm -rf "$FB/.$F1.lock"
MVPN_RUN_BASE="$FB" MVPN_LOG_BASE="$FLG" "$SH" "$MVPN" status >/dev/null
grep -q KEEPMARKER "$FLG/$F1.log" && ! grep -q LEAK "$FLG/$F1.log" && ok "status: átmásolás jelszó/auth sorok nélkül" || { nok "status: átmásolás jelszó/auth sorok nélkül"; cat "$FLG/$F1.log"; }
[ ! -e "$FB/.$F1.lock" ] && ok "status: a zár elengedve" || nok "status: a zár elengedve"
kill "$FP" 2>/dev/null; wait "$FP" 2>/dev/null

# DNS-kezelő (tartós nyilvántartás): a status / dns-reconcile visszaállítja a már nem futó kapcsolat DNS-ét (összeomlás,
# újraindítás). Tesztmódban csak hamis networksetup-pal (MVPN_NETWORKSETUP) és saját nyilvántartással (MVPN_DNS_BASE).
NSD="$T/ns"; mkdir -p "$NSD"; DNSDB="$T/dnsdb"; mkdir -m 700 "$DNSDB"
cat >"$NSD/networksetup" <<FAKE
#!/bin/bash
echo "\$*" >>"$NSD/calls"
case "\$1" in
  -listallnetworkservices) echo "An asterisk (*) denotes that a network service is disabled."; echo "Wi-Fi" ;;
  -getdnsservers) if [ -s "$NSD/srv" ]; then cat "$NSD/srv"; else echo "There aren't any DNS Servers set on \$2."; fi ;;
  -getsearchdomains) if [ -s "$NSD/dom" ]; then cat "$NSD/dom"; else echo "There aren't any Search Domains set on \$2."; fi ;;
  -setdnsservers) shift 2; if [ "\$1" = Empty ]; then : >"$NSD/srv"; else printf '%s\\n' "\$@" >"$NSD/srv"; fi ;;
  -setsearchdomains) shift 2; if [ "\$1" = Empty ]; then : >"$NSD/dom"; else printf '%s\\n' "\$@" >"$NSD/dom"; fi ;;
esac
FAKE
chmod 755 "$NSD/networksetup"
DNSID=$(uuidgen); DNSRUN="$T/dnsrun"; DNSLOG="$T/dnslog"; mkdir -p "$DNSRUN" "$DNSLOG"; : >"$DNSLOG/$DNSID.log"
dns_ledger() {
  printf 'macvpn-dns-ledger 1\norig\tWi-Fi\t192.168.1.1\tlan.example.com\nowner\t%s\t10.8.0.1\tcorp.example\n' "$DNSID" >"$DNSDB/ledger"
  printf '10.8.0.1\n' >"$NSD/srv"; printf 'corp.example\n' >"$NSD/dom"
}
dns_ledger
MVPN_RUN_BASE="$DNSRUN" MVPN_LOG_BASE="$DNSLOG" MVPN_DNS_BASE="$DNSDB" "$SH" "$MVPN" status >/dev/null
[ "$(cat "$NSD/srv")" = 10.8.0.1 ] && [ -f "$DNSDB/ledger" ] && [ ! -e "$NSD/calls" ] \
  && ok "dns: tesztmódban hamis networksetup nélkül a DNS-hez nem nyúl" || nok "dns: tesztmódban hamis networksetup nélkül a DNS-hez nem nyúl"
MVPN_RUN_BASE="$DNSRUN" MVPN_LOG_BASE="$DNSLOG" MVPN_DNS_BASE="$DNSDB" MVPN_NETWORKSETUP="$NSD/networksetup" "$SH" "$MVPN" status >/dev/null
[ "$(cat "$NSD/srv")" = 192.168.1.1 ] && [ "$(cat "$NSD/dom")" = lan.example.com ] && [ ! -e "$DNSDB/ledger" ] \
  && grep -q 'original DNS restored and verified on 1 network service' "$DNSLOG/$DNSID.log" \
  && ok "dns: status a halott kapcsolat DNS-ét visszaállítja (ellenőrizve, naplózva)" || { nok "dns: status a halott kapcsolat DNS-ét visszaállítja"; cat "$DNSLOG/$DNSID.log" "$NSD/calls"; }
dns_ledger
MVPN_RUN_BASE="$DNSRUN" MVPN_LOG_BASE="$DNSLOG" MVPN_DNS_BASE="$DNSDB" MVPN_NETWORKSETUP="$NSD/networksetup" "$SH" "$MVPN" dns-reconcile
[ "$(cat "$NSD/srv")" = 192.168.1.1 ] && [ ! -e "$DNSDB/ledger" ] && ok "dns: dns-reconcile ugyanígy" || nok "dns: dns-reconcile ugyanígy"
# Élő tulajdonos (futó openvpn, kész openvpn.log) DNS-e marad.
dns_ledger; "$T/bin/openvpn" 30 & DP=$!
mkdir -p "$DNSRUN/$DNSID"; echo openvpn >"$DNSRUN/$DNSID/kind"; echo "$DP" >"$DNSRUN/$DNSID/pid"; echo utun7 >"$DNSRUN/$DNSID/iface"
echo "2026-10-17 00:00:00 Initialization Sequence Completed" >"$DNSRUN/$DNSID/openvpn.log"
MVPN_RUN_BASE="$DNSRUN" MVPN_LOG_BASE="$DNSLOG" MVPN_DNS_BASE="$DNSDB" MVPN_NETWORKSETUP="$NSD/networksetup" "$SH" "$MVPN" dns-reconcile
[ "$(cat "$NSD/srv")" = 10.8.0.1 ] && [ -f "$DNSDB/ledger" ] && ok "dns: futó kapcsolat DNS-e marad" || nok "dns: futó kapcsolat DNS-e marad"
kill "$DP" 2>/dev/null; wait "$DP" 2>/dev/null

# M-2: túl hosszú DNS-lista (WireGuard `DNS =`, ~1040 db 253 bájtos tartomány, a nyilvántartás korlátja fölött).
# A DNS-kezelő az egészet elutasítja (nem csonkít), az eredeti DNS marad, és a bontás után is az eredeti van érvényben;
# egy korlát fölötti (régi / sérült) nyilvántartásból az eredeti értékek visszanyerhetők.
WGB="$T/wgdnsbrew"; mkdir -p "$WGB/bin"
for t in wg-quick bash wireguard-go; do printf '#!/bin/bash\nexit 0\n' >"$WGB/bin/$t"; chmod 755 "$WGB/bin/$t"; done
dns_orig() { rm -f "$DNSDB/ledger" "$DNSDB/ledger.bad" "$NSD/calls"; printf '192.168.1.1\n' >"$NSD/srv"; printf 'lan.example.com\n' >"$NSD/dom"; }
wgd() { env MVPN_TEST_ALLOW_UP=1 MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="$WGB" MVPN_RUN_BASE="$DNSRUN" MVPN_LOG_BASE="$DNSLOG" \
  MVPN_DNS_BASE="$DNSDB" MVPN_NETWORKSETUP="$NSD/networksetup" "$SH" "$MVPN" "$@"; }
dns_orig; WGOK=$(new_conn "${GOOD_WG/Address/DNS = 10.8.0.1, corp.example${NL}Address}")
wgd up wireguard "$WGOK" < <(feed "$WGOK") >"$T/wgd.out" 2>&1
[ "$(cat "$NSD/srv")" = 10.8.0.1 ] && [ "$(cat "$NSD/dom")" = corp.example ] && ok "dns M-2: wireguard DNS a korláton belül beáll (kontroll)" \
  || { nok "dns M-2: wireguard DNS a korláton belül beáll (kontroll)"; cat "$T/wgd.out" "$DNSLOG/$WGOK.log"; }
wgd down wireguard "$WGOK" </dev/null >/dev/null 2>&1
[ "$(cat "$NSD/srv")" = 192.168.1.1 ] && [ "$(cat "$NSD/dom")" = lan.example.com ] && [ ! -e "$DNSDB/ledger" ] \
  && ok "dns M-2: kontroll bontás után az eredeti DNS" || { nok "dns M-2: kontroll bontás után az eredeti DNS"; cat "$DNSLOG/$WGOK.log"; }
D253="a$(printf '.b%.0s' $(seq 126))"; HUGE="10.8.0.1"
for i in $(seq 1040); do HUGE="$HUGE, $(printf 'd%04d' "$i")${D253:5}"; done
dns_orig; WGBIG=$(new_conn "${GOOD_WG/Address/DNS = $HUGE${NL}Address}")
wgd up wireguard "$WGBIG" < <(feed "$WGBIG") >"$T/wgd.out" 2>&1
[ "$(cat "$NSD/srv")" = 192.168.1.1 ] && [ "$(cat "$NSD/dom")" = lan.example.com ] && [ ! -e "$DNSDB/ledger" ] && ! grep -q -- '-set' "$NSD/calls" 2>/dev/null \
  && grep -q "the VPN's DNS settings exceed the limits (1 servers, 1040 search domains; at most 16 and 32): DNS not changed" "$DNSLOG/$WGBIG.log" \
  && ok "dns M-2: túl hosszú DNS-lista elutasítva, az eredeti DNS marad (naplózva)" || { nok "dns M-2: túl hosszú DNS-lista elutasítva"; cat "$T/wgd.out" "$DNSLOG/$WGBIG.log"; }
wgd down wireguard "$WGBIG" </dev/null >/dev/null 2>&1
[ "$(cat "$NSD/srv")" = 192.168.1.1 ] && [ "$(cat "$NSD/dom")" = lan.example.com ] && [ ! -e "$DNSDB/ledger" ] \
  && ok "dns M-2: túl hosszú DNS-lista: bontás után is az eredeti DNS" || { nok "dns M-2: túl hosszú DNS-lista: bontás után is az eredeti DNS"; cat "$DNSLOG/$WGBIG.log"; }
dns_orig; { printf 'macvpn-dns-ledger 1\norig\tWi-Fi\t192.168.1.1\tlan.example.com\nowner\t%s\t10.8.0.1\t' "$DNSID"
  for i in $(seq 1100); do printf 'd%04d%s ' "$i" "${D253:5}"; done; printf '\n'; } >"$DNSDB/ledger"
printf '10.8.0.1\n' >"$NSD/srv"; printf 'd0001\n' >"$NSD/dom"
[ "$(wc -c <"$DNSDB/ledger")" -gt 262144 ] || nok "dns M-2: a teszt-nyilvántartás nem lépi túl a korlátot"
MVPN_RUN_BASE="$DNSRUN" MVPN_LOG_BASE="$DNSLOG" MVPN_DNS_BASE="$DNSDB" MVPN_NETWORKSETUP="$NSD/networksetup" "$SH" "$MVPN" dns-reconcile
[ "$(cat "$NSD/srv")" = 192.168.1.1 ] && [ "$(cat "$NSD/dom")" = lan.example.com ] && [ ! -e "$DNSDB/ledger" ] && [ -f "$DNSDB/ledger.bad" ] \
  && ok "dns M-2: korlát fölötti nyilvántartásból az eredeti DNS visszaáll" || { nok "dns M-2: korlát fölötti nyilvántartásból az eredeti DNS visszaáll"; cat "$NSD/srv" "$NSD/dom"; ls -la "$DNSDB"; }

# Inline hitelesítő blokkok (<auth-user-pass>, <http-proxy-user-pass>) tartalma nem kerül a naplóba (debug pillanatkép).
IAID=$(new_conn $'client\ndev tun\n<auth-user-pass>\nremote INLINELEAK1\nremote INLINELEAK2\n</auth-user-pass>\nremote vpn.example.com 1194\n<connection>\nremote alt.example.com 443\nhttp-proxy proxy.example.com 8080 [inline]\n<http-proxy-user-pass>\nremote INLINELEAK3\nremote INLINELEAK4\n</http-proxy-user-pass>\n</connection>\n<ca>\nx\n</ca>')
"$SH" "$MVPN" up openvpn "$IAID" --dry-run --debug < <(feed "$IAID") >"$T/ia.out" 2>&1
grep -q 'dscacheutil -q host -a name vpn.example.com' "$MVPN_LOG_BASE/$IAID.log" && ! grep -q INLINELEAK "$MVPN_LOG_BASE/$IAID.log" "$T/ia.out" \
  && ok "debug pillanatkép: inline hitelesítő blokk tartalma nem kerül a naplóba" || { nok "debug pillanatkép: inline hitelesítő blokk tartalma nem kerül a naplóba"; cat "$T/ia.out" "$MVPN_LOG_BASE/$IAID.log"; }

# Nyelv (--lang): a hibaüzenet angol alapból és --lang en mellett, magyar --lang hu mellett; ismeretlen érték: angol.
LANG_ID=$(new_conn "$GOOD_OVPN"$'\nup /tmp/x')
lang_out() { "$SH" "$MVPN" up openvpn "$LANG_ID" --dry-run "$@" < <(feed "$LANG_ID") 2>&1; }
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
[ "$("$SH" "$MVPN" version --lang hu)" = "$(cat "$VERSION_FILE")" ] && ok "version --lang mellett is" || nok "version --lang mellett is"
LANG_ID2=$(new_conn "$GOOD_OVPN")
"$SH" "$MVPN" up openvpn "$LANG_ID2" --dry-run --lang hu < <(feed "$LANG_ID2") >/dev/null 2>&1
grep -q '^▶ \[mvpn\] config érvényes' "$MVPN_LOG_BASE/$LANG_ID2.log" && ok "nyelv: napló lépés magyarul" || nok "nyelv: napló lépés magyarul"
"$SH" "$MVPN" up openvpn "$LANG_ID2" --dry-run < <(feed "$LANG_ID2") >/dev/null 2>&1
grep -q '^▶ \[mvpn\] config is valid' "$MVPN_LOG_BASE/$LANG_ID2.log" && ok "nyelv: napló lépés angolul" || nok "nyelv: napló lépés angolul"
OUT=$("${VALIDATE[@]}" --lang hu wireguard </dev/null 2>&1)
[ "$OUT" = "Nincs megadva config" ] && ok "mvpn-validate --lang hu" || nok "mvpn-validate --lang hu ($OUT)"
OUT=$("${VALIDATE[@]}" wireguard </dev/null 2>&1)
[ "$OUT" = "Config not provided" ] && ok "mvpn-validate alapból angol" || nok "mvpn-validate alapból angol ($OUT)"
# mvpn validate: a config a standard bemeneten, ugyanabban a keretben, titok-sor nélkül; a régi <fájl> argumentum megszűnt.
vfeed() { local n; n=$(printf '%s\n' "$1" | LC_ALL=C wc -c | tr -d ' '); printf 'config %s\n%s\n' "$n" "$1"; }
V_SSTP=$'server=vpn.example.com\nuser=bob'
for kc in "openvpn|$GOOD_OVPN|up /tmp/x" "wireguard|$GOOD_WG|PostUp = x" "strongswan|$GOOD_SWAN|include /etc/x" "sstp|$V_SSTP|pppd_opts=x"; do
  k=${kc%%|*}; rest=${kc#*|}; cfg=${rest%|*}; bad=${rest##*|}
  OUT=$(vfeed "$cfg" | "${VALIDATE[@]}" "$k" 2>&1); RC=$?
  [ "$RC" = 0 ] && [ -z "$OUT" ] && ok "mvpn validate $k (stdin): jó config" || { nok "mvpn validate $k (stdin): jó config"; echo "$RC $OUT"; }
  OUT=$(vfeed "$cfg"$'\n'"$bad" | "${VALIDATE[@]}" "$k" 2>&1); RC=$?
  [ "$RC" = 1 ] && [ -n "$OUT" ] && ok "mvpn validate $k (stdin): hibás config" || { nok "mvpn validate $k (stdin): hibás config"; echo "$RC $OUT"; }
done
OUT=$(vfeed "$GOOD_SWAN" | "${VALIDATE[@]}" --swan-names | tr '\n' '|')
[ "$OUT" = "office|office-net|" ] && ok "mvpn validate --swan-names (stdin)" || nok "mvpn validate --swan-names (stdin) ($OUT)"
OUT=$(vfeed "$GOOD_OVPN" | "${VALIDATE[@]}" --sstp-params 2>&1); RC=$?
[ "$RC" = 1 ] && [ -z "$OUT" ] && ok "mvpn validate --sstp-params: nem SSTP config → 1" || nok "mvpn validate --sstp-params: nem SSTP config → 1 ($RC $OUT)"
OUT=$({ vfeed "$GOOD_WG"; printf 'password=VS3cret\n'; } | "${VALIDATE[@]}" wireguard 2>&1); RC=$?
[ "$RC" = 2 ] && [ "$OUT" = "Invalid input" ] && ok "mvpn validate: titok-sor a config után → Invalid input" || nok "mvpn validate: titok-sor a config után → Invalid input ($RC $OUT)"
OUT=$(printf 'config 100\nclient\n' | "${VALIDATE[@]}" openvpn 2>&1); RC=$?
[ "$RC" = 2 ] && [ "$OUT" = "The config is incomplete" ] && ok "mvpn validate: csonka folyam" || nok "mvpn validate: csonka folyam ($RC $OUT)"
printf '%s\n' "$GOOD_WG" >"$T/wg.conf"
OUT=$(vfeed "$GOOD_WG" | "${VALIDATE[@]}" wireguard "$T/wg.conf" 2>&1); RC=$?
[ "$RC" = 2 ] && case "$OUT" in "Usage: mvpn validate"*) true ;; *) false ;; esac && ok "mvpn validate: a <fájl> argumentum megszűnt (használati hiba)" || nok "mvpn validate: a <fájl> argumentum megszűnt (használati hiba) ($RC $OUT)"

# Valódi (nem dry-run) up tesztmódban: csak hamis brew könyvtárral (MVPN_BREW), hamis ovpn-dns-sel (MVPN_LIBEXEC),
# így valódi VPN eszköz és networksetup nem fut. A sikertelen up nem hagyhat futási könyvtárat.
FB="$T/fakebrew"; mkdir -p "$FB/bin"
FL="$T/fakelibexec"; mkdir -p "$FL"
printf '#!/bin/bash\nprintf "%%s %%s\\n" "$script_type" "$1" >>"%s"\nrm -f "$1/dns-backup"\n' "$T/dns-restore.log" >"$FL/ovpn-dns"
chmod 755 "$FL/ovpn-dns"
hook_shim "$FL"
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

# Hamis openvpn, ami "felépül". A felhasználónév és a jelszó a közvetítőn (mvpn-mgmt) át megy: a mgmt-creds fájlt a
# közvetítő azonnal beolvassa és törli, jelszófájl (auth) nem marad; a kulcsjelszó (askpass) a down-ig megmarad.
SB2="$T/ovpnok"; mkdir -p "$SB2/bin"
cat >"$SB2/bin/openvpn" <<'FAKE'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in --log-append) L="$2"; shift ;; esac; shift; done
echo "Initialization Sequence Completed" >>"$L"
exit 0
FAKE
chmod 755 "$SB2/bin/openvpn"
UID4=$(new_conn "$GOOD_OVPN")
{ feed "$UID4"; printf 'username=bob\npassword=Sup3rTitok\nkeypass=K3yTitok77\n'; } | upt MVPN_BREW="$SB2" "$SH" "$MVPN" up openvpn "$UID4" >"$T/out" 2>&1 \
  && ok "up openvpn (hamis) sikeres" || { nok "up openvpn (hamis) sikeres"; cat "$T/out"; }
for i in 1 2 3 4 5 6 7 8 9 10; do [ -e "$MVPN_RUN_BASE/$UID4/mgmt-creds" ] || break; sleep 0.2; done
[ ! -e "$MVPN_RUN_BASE/$UID4/auth" ] && [ ! -e "$MVPN_RUN_BASE/$UID4/mgmt-creds" ] && [ "$(stat -f %Lp "$MVPN_RUN_BASE/$UID4")" = 700 ] \
  && ok "nincs jelszófájl: a közvetítő beolvasta és törölte a mgmt-creds-et (könyvtár 700)" || { nok "nincs jelszófájl: a közvetítő beolvasta és törölte a mgmt-creds-et (könyvtár 700)"; ls -la "$MVPN_RUN_BASE/$UID4"; }
ps -p "$(cat "$MVPN_RUN_BASE/$UID4/mgmt.pid" 2>/dev/null)" -o comm= 2>/dev/null | grep -q 'mvpn-mgmt$' && ok "a közvetítő fut a felépülés után" || nok "a közvetítő fut a felépülés után"
UID4_MGMT=$(cat "$MVPN_RUN_BASE/$UID4/mgmt.pid" 2>/dev/null)
grep -q 'Sup3rTitok' "$MVPN_LOG_BASE/$UID4.log" && nok "jelszó nem kerül a naplóba (valódi up)" || ok "jelszó nem kerül a naplóba (valódi up)"
[ -f "$MVPN_RUN_BASE/$UID4/askpass" ] && [ "$(stat -f %Lp "$MVPN_RUN_BASE/$UID4/askpass")" = 600 ] \
  && [ "$(cat "$MVPN_RUN_BASE/$UID4/askpass")" = K3yTitok77 ] && ok "askpass fájl (600) a felépülés után" || nok "askpass fájl (600) a felépülés után"
grep -q 'K3yTitok77' "$MVPN_LOG_BASE/$UID4.log" && nok "kulcsjelszó nem kerül a naplóba (valódi up)" || ok "kulcsjelszó nem kerül a naplóba (valódi up)"
DESC="down a felépült kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$UID4"
[ ! -e "$MVPN_RUN_BASE/$UID4" ] && ok "down után a futási könyvtár törölve" || nok "down után a futási könyvtár törölve"
ps -p "$UID4_MGMT" -o comm= 2>/dev/null | grep -q 'mvpn-mgmt$' && nok "down után a közvetítő leállt" || ok "down után a közvetítő leállt"

# OpenVPN: a felépülésről/hibáról csak a root-only $RUN/openvpn.log dönt; a felhasználói naplóba injektált sor nem számít.
DID=$(new_conn "$GOOD_OVPN")
"$SH" "$MVPN" up openvpn "$DID" --dry-run < <(feed "$DID") >"$T/out" 2>&1
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
  echo)       printf '2026-10-17 00:00:00 ECHO:msg Initialization Sequence Completed\n' >>"\$L"
              printf "2026-10-17 00:00:01 PUSH: Received control message: 'PUSH_REPLY,echo msg Initialization Sequence Completed'\\n" >>"\$L"
              printf '2026-10-17 00:00:02 ECHO-PULL:msg Initialization Sequence Completed\n' >>"\$L" ;;
  echoauth)   printf '2026-10-17 00:00:00 ECHO:msg AUTH_FAILED\n' >>"\$L"
              ( sleep 2; printf '2026-10-17 00:00:01 Initialization Sequence Completed\n' >>"\$L" ) </dev/null >/dev/null 2>&1 & ;;
  mgmtlog)    printf '%s\n' "2026-10-17 00:00:00 MANAGEMENT: CMD 'state on'" "2026-10-17 00:00:00 MANAGEMENT: CMD 'hold release'" \
                "2026-10-17 00:00:01 MANAGEMENT: CMD 'username \"Auth\" bob'" "2026-10-17 00:00:01 MANAGEMENT: CMD 'password [...]'" \
                "2026-10-17 00:00:02 MANAGEMENT: CMD 'cr-response MTEyMjMz'" \
                "2026-10-17 00:00:02 us=123456 SENT CONTROL [vpn.example.com]: 'CR_RESPONSE,MTEyMjMz' (status=1)" \
                "2026-10-17 00:00:02 MANAGEMENT: CMD 'signal SIGUSR1'" "2026-10-17 00:00:02 MANAGEMENT: CMD 'version 3'" \
                "2026-10-17 00:00:03 Initialization Sequence Completed" >>"\$L" ;;
  mgmtexit)   printf '%s\n' "2026-10-17 00:00:00 KEEPLINE" "2026-10-17 00:00:01 MANAGEMENT: CMD 'cr-response MTEyMjMz'" >>"\$L"
              kill \$! ;;
  temp)       printf '2026-10-17 00:00:00 AUTH: Received control message: AUTH_FAILED,TEMP[backoff 2]:busy\n' >>"\$L"
              ( sleep 2; printf '2026-10-17 00:00:03 Initialization Sequence Completed\n' >>"\$L" ) </dev/null >/dev/null 2>&1 & ;;
esac
exit 0
FAKE
chmod 755 "$OI/bin/openvpn"
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" MVPN_UP_TIMEOUT=3 FAKE_OVPN_MODE=inject INJECT_LOG="$MVPN_LOG_BASE/$OID.log" "$SH" "$MVPN" up openvpn "$OID" 2>&1 < <(feed "$OID")); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Timed out: the connection was not established within 3 s"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$OID" ] \
  && ok "openvpn: injektált 'Initialization Sequence Completed' a felhasználói naplóban nem számít" || { nok "openvpn: injektált 'Initialization Sequence Completed' a felhasználói naplóban nem számít"; echo "$OUT"; }
[ "$(cat "$T/ovpn-logpath")" = "$MVPN_RUN_BASE/$OID/openvpn.log" ] && ok "openvpn: a napló a futási könyvtárban" || nok "openvpn: a napló a futási könyvtárban ($(cat "$T/ovpn-logpath"))"
pgrep -f "$T/bin/openvpn 60" >/dev/null && sleep 1
OID=$(new_conn "$GOOD_OVPN")
OUT=$({ feed "$OID"; printf 'username=bob\npassword=Sup3rTitok\n'; } | upt MVPN_BREW="$OI" FAKE_OVPN_MODE=authinject INJECT_LOG="$MVPN_LOG_BASE/$OID.log" "$SH" "$MVPN" up openvpn "$OID" 2>&1); RC=$?
[ "$RC" = 0 ] && ok "openvpn: injektált AUTH_FAILED a felhasználói naplóban nem számít" || { nok "openvpn: injektált AUTH_FAILED a felhasználói naplóban nem számít"; echo "$OUT"; }
[ "$(stat -f %Lp "$MVPN_RUN_BASE/$OID/openvpn.log" 2>/dev/null)" = 600 ] && grep -q '^2026-10-17 00:00:00 Initialization Sequence Completed$' "$MVPN_LOG_BASE/$OID.log" \
  && ok "openvpn: openvpn.log 600, tartalma a kapcsolat naplójába másolva" || { nok "openvpn: openvpn.log 600, tartalma a kapcsolat naplójába másolva"; cat "$MVPN_LOG_BASE/$OID.log"; }
DESC="openvpn: down a felépült (hamis) kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$OID"
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" FAKE_OVPN_MODE=auth "$SH" "$MVPN" up openvpn "$OID" 2>&1 < <(feed "$OID")); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Authentication failed (AUTH_FAILED)"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$OID" ] \
  && grep -q 'AUTH: Received control message: AUTH_FAILED' "$MVPN_LOG_BASE/$OID.log" \
  && ok "openvpn: AUTH_FAILED a root-only naplóból → hiba, takarítás, napló átmásolva" || { nok "openvpn: AUTH_FAILED a root-only naplóból → hiba, takarítás, napló átmásolva"; echo "$OUT"; }
pgrep -f "$T/bin/openvpn 60" >/dev/null && nok "openvpn: nem maradt futó hamis openvpn" || ok "openvpn: nem maradt futó hamis openvpn"
# ECHO / ECHO-PULL / PUSH_REPLY sor a root-only naplóban (config `echo`/`parameter`, vagy a szerver által küldött echo)
# nem jelent felépülést és nem jelent AUTH_FAILED-et: csak az OpenVPN saját, horgonyzott sora számít.
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" MVPN_UP_TIMEOUT=3 FAKE_OVPN_MODE=echo "$SH" "$MVPN" up openvpn "$OID" 2>&1 < <(feed "$OID")); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Timed out: the connection was not established within 3 s"*) true ;; *) false ;; esac \
  && ok "openvpn: 'ECHO:msg Initialization Sequence Completed' nem számít felépülésnek" || { nok "openvpn: 'ECHO:msg Initialization Sequence Completed' nem számít felépülésnek"; echo "$OUT"; }
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" FAKE_OVPN_MODE=echoauth "$SH" "$MVPN" up openvpn "$OID" 2>&1 < <(feed "$OID")); RC=$?
[ "$RC" = 0 ] && ok "openvpn: 'ECHO:msg AUTH_FAILED' nem hitelesítési hiba" || { nok "openvpn: 'ECHO:msg AUTH_FAILED' nem hitelesítési hiba"; echo "$OUT"; }
DESC="openvpn: down az echoauth kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$OID"
# A management parancsok naplósorai (OpenVPN 2.7: `MANAGEMENT: CMD '…'`, verb >= 4-nél `SENT CONTROL …: 'CR_RESPONSE,…'`)
# a válaszkódot base64-ben hordozzák: egyik másolási úton sem kerülhetnek a felhasználói naplóba. Csak a state / hold /
# version parancs sora marad.
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" FAKE_OVPN_MODE=mgmtlog "$SH" "$MVPN" up openvpn "$OID" 2>&1 < <(feed "$OID")); RC=$?
UL="$MVPN_LOG_BASE/$OID.log"
[ "$RC" = 0 ] && ! grep -q "MTEyMjMz\|CMD 'username\|CMD 'password\|CMD 'signal" "$UL" \
  && grep -q "CMD 'state on'" "$UL" && grep -q "CMD 'hold release'" "$UL" && grep -q "CMD 'version 3'" "$UL" \
  && ok "napló: a management parancsok (cr-response, CR_RESPONSE, username) nem kerülnek a felhasználói naplóba" \
  || { nok "napló: a management parancsok (cr-response, CR_RESPONSE, username) nem kerülnek a felhasználói naplóba"; echo "$OUT"; cat "$UL"; }
printf '%s\n' "2026-10-17 00:00:09 MANAGEMENT: CMD 'cr-response OTk5OTk5'" "2026-10-17 00:00:09 SENT CONTROL [vpn]: 'CR_RESPONSE,OTk5OTk5' (status=1)" \
  "2026-10-17 00:00:09 STATUSMARK" >>"$MVPN_RUN_BASE/$OID/openvpn.log"
"$SH" "$MVPN" status >/dev/null 2>&1
grep -q STATUSMARK "$UL" && ! grep -q OTk5OTk5 "$UL" && ok "napló: a status-kori átmásolás is szűr" || { nok "napló: a status-kori átmásolás is szűr"; cat "$UL"; }
DESC="openvpn: down a mgmtlog kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$OID"
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" FAKE_OVPN_MODE=mgmtexit "$SH" "$MVPN" up openvpn "$OID" 2>&1 < <(feed "$OID")); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"openvpn exited: 2026-10-17 00:00:00 KEEPLINE"*) true ;; *) false ;; esac && ! grep -q MTEyMjMz "$MVPN_LOG_BASE/$OID.log" \
  && ok "napló: az \"openvpn exited\" üzenet sem idéz management parancsot" || { nok "napló: az \"openvpn exited\" üzenet sem idéz management parancsot"; echo "$OUT"; }
# AUTH_FAILED,TEMP: átmeneti szerverhiba, az OpenVPN újrapróbál (mint a közvetítőben): nem végleges.
OID=$(new_conn "$GOOD_OVPN")
OUT=$(upt MVPN_BREW="$OI" FAKE_OVPN_MODE=temp "$SH" "$MVPN" up openvpn "$OID" 2>&1 < <(feed "$OID")); RC=$?
[ "$RC" = 0 ] && ok "openvpn: AUTH_FAILED,TEMP nem végleges hiba" || { nok "openvpn: AUTH_FAILED,TEMP nem végleges hiba"; echo "$OUT"; }
DESC="openvpn: down a temp kapcsolatra"; expect_ok env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="${MVPN_BREW:-$T/emptybrew}" MVPN_LIBEXEC="$FL" "$SH" "$MVPN" down openvpn "$OID"
# status: csak ECHO sorral a kapcsolat nem "connected".
EB="$T/echostatus"; mkdir -p "$EB"; "$T/bin/openvpn" 30 & EP=$!
E1=$(uuidgen); mkdir -p "$EB/$E1"; echo openvpn >"$EB/$E1/kind"; echo "$EP" >"$EB/$E1/pid"; echo utun5 >"$EB/$E1/iface"
printf '%s\n' "2026-10-17 00:00:00 ECHO:msg Initialization Sequence Completed" >"$EB/$E1/openvpn.log"
E2=$(uuidgen); mkdir -p "$EB/$E2"; echo openvpn >"$EB/$E2/kind"; echo "$EP" >"$EB/$E2/pid"; echo utun6 >"$EB/$E2/iface"
printf '%s\n' "1760000000.123456 1 Initialization Sequence Completed" >"$EB/$E2/openvpn.log"
SJ=$(MVPN_RUN_BASE="$EB" "$SH" "$MVPN" status)
python3 -c 'import json,sys; d={x["id"]:x["state"] for x in json.loads(sys.argv[1])}; sys.exit(0 if d[sys.argv[2]]=="connecting" and d[sys.argv[3]]=="connected" else 1)' "$SJ" "$E1" "$E2" \
  && ok "status: ECHO sor nem 'connected', machine-readable sor igen" || { nok "status: ECHO sor nem 'connected', machine-readable sor igen"; echo "$SJ"; }
kill "$EP" 2>/dev/null; wait "$EP" 2>/dev/null

# Összeomlott openvpn maradéka (halott pid, dns-backup): az up előbb visszaállítja a DNS-t, aztán törli.
UID5=$(new_conn "$GOOD_OVPN"); mkdir -m 700 "$MVPN_RUN_BASE/$UID5"
echo openvpn >"$MVPN_RUN_BASE/$UID5/kind"; dead_pid >"$MVPN_RUN_BASE/$UID5/pid"
printf 'svc\t1.1.1.1\tEmpty\n' >"$MVPN_RUN_BASE/$UID5/dns-backup"; : >"$T/dns-restore.log"
DESC="up összeomlott maradék mellett (eszköz nélkül hibázik)"; expect_fail upt MVPN_BREW="$T/emptybrew" "$SH" "$MVPN" up openvpn "$UID5"
grep -q "^down $MVPN_RUN_BASE/$UID5\$" "$T/dns-restore.log" && ok "maradék: DNS visszaállítva a dns-backup-ból" || { nok "maradék: DNS visszaállítva a dns-backup-ból"; cat "$T/dns-restore.log"; }
grep -q 'closing the previous run' "$MVPN_LOG_BASE/$UID5.log" && ok "maradék: korábbi futás lebontva" || nok "maradék: korábbi futás lebontva"
[ ! -e "$MVPN_RUN_BASE/$UID5" ] && ok "maradék: nincs futási könyvtár" || nok "maradék: nincs futási könyvtár"

# Hibás új config nem bontja le a futó kapcsolatot: a validálás a korábbi futás lezárása előtt történik.
LVID=$(new_conn "$GOOD_OVPN"$'\nup /tmp/x'); mkdir -m 700 "$MVPN_RUN_BASE/$LVID"; echo openvpn >"$MVPN_RUN_BASE/$LVID/kind"
"$T/bin/openvpn" 60 & LVP=$!; echo "$LVP" >"$MVPN_RUN_BASE/$LVID/pid"; sleep 0.2
OUT=$(upt MVPN_BREW="$T/emptybrew" "$SH" "$MVPN" up openvpn "$LVID" 2>&1 < <(feed "$LVID")); RC=$?
[ "$RC" = 1 ] && case "$OUT" in "Invalid config:"*) true ;; *) false ;; esac && kill -0 "$LVP" 2>/dev/null \
  && [ "$(cat "$MVPN_RUN_BASE/$LVID/pid" 2>/dev/null)" = "$LVP" ] && ! grep -q 'closing the previous run' "$MVPN_LOG_BASE/$LVID.log" \
  && ok "hibás új config: a futó kapcsolat és a futási könyvtár érintetlen" || { nok "hibás új config: a futó kapcsolat és a futási könyvtár érintetlen"; echo "$RC $OUT"; }
kill "$LVP" 2>/dev/null; wait "$LVP" 2>/dev/null; rm -rf "${MVPN_RUN_BASE:?}/$LVID"

# SIGTERM a kapcsolódás közben (hamis openvpn, ami nem épül fel): 143, takarítás, nincs futási könyvtár.
HB="$T/ovpnhang"; mkdir -p "$HB/bin"; printf '#!/bin/bash\nexit 0\n' >"$HB/bin/openvpn"; chmod 755 "$HB/bin/openvpn"
UID6=$(new_conn "$GOOD_OVPN")
MVPN_TEST_ALLOW_UP=1 MVPN_LIBEXEC="$FL" MVPN_BREW="$HB" "$SH" "$MVPN" up openvpn "$UID6" < <(feed "$UID6") >/dev/null 2>&1 & W=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -d "$MVPN_RUN_BASE/$UID6" ] && break; sleep 0.2; done
sleep 0.5; kill -TERM "$W"; wait "$W"; RC=$?
[ "$RC" = 143 ] && [ ! -e "$MVPN_RUN_BASE/$UID6" ] && ok "up SIGTERM: 143, nincs futási könyvtár" || { nok "up SIGTERM: 143, nincs futási könyvtár ($RC)"; ls -la "$MVPN_RUN_BASE/$UID6" 2>&1; }

# strongSwan EAP hitelesítési hiba: hamis swanctl (eapfail módban az --initiate EAP_FAILURE-t ír és hibával kilép)
# → "Authentication failed (EAP)"; más IKE hiba (ikefail) → a régi üzenet. Takarítás, a jelszó nincs a naplóban.
SWB="$T/swanbrew"; mkdir -p "$SWB/bin" "$SWB/opt/strongswan/libexec/ipsec"
printf '#!/bin/bash\nexit 0\n' >"$SWB/opt/strongswan/libexec/ipsec/charon"
cat >"$SWB/bin/swanctl" <<'FAKE'
#!/bin/bash
case " $* " in
  *" --initiate "*)
    case "$FAKE_SWAN_MODE" in
      eapfail) echo "[IKE] received EAP_FAILURE, EAP authentication failed"; echo "[IKE] EAP method EAP_MSCHAPV2 failed for peer 10.0.0.1"; exit 1 ;;
      ikefail) echo "[IKE] establishing CHILD_SA office-net failed"; exit 1 ;;
      # Más folyamat írja a felhasználói naplóba (nem a swanctl kimenete): nem dönthet.
      ikeinject) echo "[IKE] received EAP_FAILURE (injected)" >>"$INJECT_LOG"; echo "[IKE] establishing CHILD_SA office-net failed"; exit 1 ;;
    esac ;;
esac
exit 0
FAKE
chmod 755 "$SWB/bin/swanctl" "$SWB/opt/strongswan/libexec/ipsec/charon"
for mode in eapfail ikefail; do
  EID=$(new_conn "$GOOD_SWAN")
  OUT=$({ feed "$EID"; printf 'username=alice\npassword=EapFailS3cret\n'; } | env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$SWB" FAKE_SWAN_MODE=$mode "$SH" "$MVPN" up strongswan "$EID" 2>&1); RC=$?
  if [ "$mode" = eapfail ]; then WANT="Authentication failed (EAP)"; else WANT="IKE negotiation failed (details in the log)"; fi
  [ "$RC" = 1 ] && [ "$OUT" = "$WANT" ] && [ ! -e "$MVPN_RUN_BASE/$EID" ] && ! grep -q EapFailS3cret "$MVPN_LOG_BASE/$EID.log" \
    && ok "strongswan $mode: \"$WANT\", takarítás, jelszó nincs a naplóban" || { nok "strongswan $mode: \"$WANT\""; echo "$RC $OUT"; cat "$MVPN_LOG_BASE/$EID.log"; }
done
EID=$(new_conn "$GOOD_SWAN")
OUT=$({ feed "$EID"; printf 'password=EapFailS3cret\n'; } | env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$SWB" FAKE_SWAN_MODE=ikeinject INJECT_LOG="$MVPN_LOG_BASE/$EID.log" "$SH" "$MVPN" up strongswan "$EID" 2>&1)
[ "$OUT" = "IKE negotiation failed (details in the log)" ] && grep -q 'EAP_FAILURE (injected)' "$MVPN_LOG_BASE/$EID.log" \
  && ok "strongswan: a felhasználói naplóba injektált EAP_FAILURE nem dönt (csak a swanctl kimenete)" || { nok "strongswan: a felhasználói naplóba injektált EAP_FAILURE nem dönt (csak a swanctl kimenete)"; echo "$OUT"; }
EID=$(new_conn "$GOOD_SWAN")
OUT=$({ feed "$EID"; printf 'password=EapFailS3cret\n'; } | env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$SWB" FAKE_SWAN_MODE=eapfail "$SH" "$MVPN" up strongswan "$EID" --lang hu 2>&1)
[ "$OUT" = "Hitelesítési hiba (EAP)" ] && ok "strongswan eapfail magyarul" || nok "strongswan eapfail magyarul ($OUT)"

# F1: a `swanctl --load-all --file <run>/config` a hitelesítő adatokat (x509ca/, x509/, private/, …) a <config> mellől
# olvassa (strongSwan swanctl.c: swanctl_dir = dirname(--file)), a Homebrew etc/swanctl-t nem; amit ott nem talál
# (kulcs, közös titok), azt a charonból ki is tölti. Az mvpn ezért a <brew>/etc/swanctl/<könyvtár>/ sima fájljait
# a futási könyvtárba másolja (könyvtár 0700, fájl 0600; symlink, rejtett fájl, más könyvtár nem), a bontás törli.
CRB="$T/credbrew"; SC="$CRB/etc/swanctl"; CRO="$T/credout"
mkdir -p "$CRB/bin" "$CRB/opt/strongswan/libexec/ipsec" "$SC/x509ca" "$SC/x509" "$SC/private" "$SC/pkcs12" "$SC/other" "$CRO"
printf '#!/bin/bash\nexit 0\n' >"$CRB/opt/strongswan/libexec/ipsec/charon"
printf 'LAB-CA\n' >"$SC/x509ca/lab-ca.pem"; printf 'LAB-CLIENT\n' >"$SC/x509/lab-client.pem"
printf 'KeyMaterialS3cret\n' >"$SC/private/lab-client.key"; printf 'P12\n' >"$SC/pkcs12/c.p12"
printf 'outside\n' >"$T/outside.key"; ln -s "$T/outside.key" "$SC/private/link.key"; printf 'h\n' >"$SC/private/.hidden.key"
printf 'o\n' >"$SC/other/o.pem"; printf 'connections {\n}\n' >"$SC/swanctl.conf"
# L-7: kemény link (máshol lévő fájl) és symlinkelt hitelesítő könyvtár: nem másolódik.
mkdir -p "$T/credoutside"; printf 'RootOnlyS3cret\n' >"$T/credoutside/root-only"; ln "$T/credoutside/root-only" "$SC/x509/hard.pem"
printf 'crl\n' >"$T/credoutside/crl.pem"; ln -s "$T/credoutside" "$SC/x509crl"
cat >"$CRB/bin/swanctl" <<'FAKE'
#!/bin/bash
case " $* " in
  *" --load-all "*)
    printf '%s\n' "$*" >"$CRED_OUT/argv"
    f=""; prev=""; for a in "$@"; do [ "$prev" = --file ] && f=$a; prev=$a; done
    d=$(dirname "$f")
    (cd "$d" && find . -mindepth 1 -exec stat -f '%Lp %N' {} \; | LC_ALL=C sort) >"$CRED_OUT/tree"
    cat "$d/x509ca/lab-ca.pem" >"$CRED_OUT/ca" 2>/dev/null ;;
esac
exit 0
FAKE
chmod 755 "$CRB/bin/swanctl" "$CRB/opt/strongswan/libexec/ipsec/charon"
CRID=$(new_conn "$(swan_local 'certs = lab-client.pem')")
OUT=$({ feed "$CRID"; printf 'psk=PskCredS3cret\n'; } | env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$CRB" CRED_OUT="$CRO" "$SH" "$MVPN" up strongswan "$CRID" 2>&1); RC=$?
[ "$RC" = 0 ] || { nok "strongswan tanúsítvány: up ($RC)"; echo "$OUT"; cat "$MVPN_LOG_BASE/$CRID.log"; }
TREE=$(cat "$CRO/tree" 2>/dev/null)
for want in "700 ./x509ca" "600 ./x509ca/lab-ca.pem" "700 ./x509" "600 ./x509/lab-client.pem" "700 ./private" \
  "600 ./private/lab-client.key" "700 ./pkcs12" "600 ./pkcs12/c.p12"; do
  grep -qxF "$want" <<<"$TREE" && ok "strongswan hitelesítő adat a futási könyvtárban: $want" || { nok "strongswan hitelesítő adat a futási könyvtárban: $want"; echo "$TREE"; }
done
! grep -q 'link.key\|hidden\|other\|swanctl.conf' <<<"$TREE" && ok "strongswan: symlink, rejtett fájl, más könyvtár, swanctl.conf nem másolódik" \
  || { nok "strongswan: symlink, rejtett fájl, más könyvtár, swanctl.conf nem másolódik"; echo "$TREE"; }
! grep -q 'hard.pem\|x509crl\|crl.pem' <<<"$TREE" && ok "strongswan L-7: kemény link és symlinkelt könyvtár nem másolódik" \
  || { nok "strongswan L-7: kemény link és symlinkelt könyvtár nem másolódik"; echo "$TREE"; }
[ "$(cat "$CRO/ca" 2>/dev/null)" = "LAB-CA" ] && ok "strongswan: a CA tartalma a másolatban" || nok "strongswan: a CA tartalma a másolatban"
grep -q -- '--load-all --noprompt --file ' "$CRO/argv" && ! grep -q 'S3cret' "$CRO/argv" && ok "strongswan --load-all --noprompt, titok nincs az argv-ben" \
  || { nok "strongswan --load-all --noprompt, titok nincs az argv-ben"; cat "$CRO/argv"; }
grep -qF "strongSwan credentials copied from $SC: 4 (skipped: 3)" "$MVPN_LOG_BASE/$CRID.log" && ok "strongswan: a másolás a naplóban (darabszám)" \
  || { nok "strongswan: a másolás a naplóban (darabszám)"; cat "$MVPN_LOG_BASE/$CRID.log"; }
! grep -q 'S3cret' "$MVPN_LOG_BASE/$CRID.log" && ok "strongswan: kulcs és PSK nincs a naplóban" || nok "strongswan: kulcs és PSK nincs a naplóban"
env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="$CRB" CRED_OUT="$CRO" "$SH" "$MVPN" down strongswan "$CRID" >/dev/null 2>&1
[ ! -e "$MVPN_RUN_BASE/$CRID" ] && ok "strongswan down: a futási könyvtár (kulcsmásolat) törölve" || { nok "strongswan down: a futási könyvtár (kulcsmásolat) törölve"; ls -laR "$MVPN_RUN_BASE/$CRID"; }
# L-7: ha a prefix `etc` könyvtára symlink (pl. /var/db felé), semmi sem másolódik.
CRL="$T/credbrewlink"; mkdir -p "$CRL"; cp -R "$CRB/bin" "$CRB/opt" "$CRL/"; ln -s "$CRB/etc" "$CRL/etc"; rm -f "$CRO/tree"
CRID2=$(new_conn "$(swan_local 'certs = lab-client.pem')")
{ feed "$CRID2"; printf 'psk=PskCredS3cret\n'; } | env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$CRL" CRED_OUT="$CRO" "$SH" "$MVPN" up strongswan "$CRID2" >/dev/null 2>&1
grep -qF "strongSwan credentials copied from $CRL/etc/swanctl: 0 (skipped: 0)" "$MVPN_LOG_BASE/$CRID2.log" && ! grep -q 'pem\|key\|p12' "$CRO/tree" 2>/dev/null \
  && ok "strongswan L-7: symlinkelt etc könyvtáron át nem másol" || { nok "strongswan L-7: symlinkelt etc könyvtáron át nem másol"; cat "$MVPN_LOG_BASE/$CRID2.log" "$CRO/tree"; }
env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="$CRL" CRED_OUT="$CRO" "$SH" "$MVPN" down strongswan "$CRID2" >/dev/null 2>&1

# F2: két strongSwan kapcsolat egyszerre. A `swanctl --load-all --file F` (strongSwan 6.1 load_conns.c,
# load_creds.c) mindent kitölt a charonból, ami nincs az F-ben: kapcsolatot, privát kulcsot, közös titkot. A hamis
# swanctl ezt utánozza: a betöltés után a "charon" pontosan az F-ben álló connections.<név> / secrets.<név>
# szakaszokat tartja ($SWS/loaded). Az mvpn ezért minden betöltésnél az összes aktív (betöltött) strongSwan
# kapcsolat configját együtt tölti be, egyedi (azonosítós) titoknevekkel; a bontás a többit újratölti.
TWB="$T/twobrew"; SWS="$T/twostate"; mkdir -p "$TWB/bin" "$TWB/opt/strongswan/libexec/ipsec" "$SWS"
printf '#!/bin/bash\nexit 0\n' >"$TWB/opt/strongswan/libexec/ipsec/charon"
cat >"$TWB/bin/swanctl" <<'FAKE'
#!/bin/bash
printf '%s\n' "$*" >>"$SWAN_STATE/argv"
case " $* " in
  *" --load-all "*)
    f=""; prev=""; for a in "$@"; do [ "$prev" = --file ] && f=$a; prev=$a; done
    awk '{ l=$0; sub(/#.*/, "", l)
           if (match(l, /^[ \t]*[A-Za-z0-9_.-]+[ \t]*\{/)) { n=l; sub(/^[ \t]*/, "", n); sub(/[ \t]*\{.*/, "", n)
             if (d == 0) top=n; else if (d == 1) print top "." n; d++ ; sub(/\{/, "", l) }
           d -= gsub(/\}/, "", l) }' "$f" | LC_ALL=C sort >"$SWAN_STATE/loaded" ;;
  *" --terminate "*) printf '%s\n' "$*" >>"$SWAN_STATE/terminated" ;;
esac
exit 0
FAKE
chmod 755 "$TWB/bin/swanctl" "$TWB/opt/strongswan/libexec/ipsec/charon"
swan_conf() { # $1 = kapcsolatnév, $2 = local auth, $3 = remote id (üres: nincs)
  printf 'connections {\n  %s {\n    remote_addrs = 192.0.2.10\n    local {\n      auth = %s\n    }\n    remote {\n      auth = %s\n%s    }\n    children {\n      %s {\n        remote_ts = 10.99.0.0/24\n      }\n    }\n  }\n}\n' \
    "$1" "$2" "$([ "$2" = psk ] && echo psk || echo pubkey)" "${3:+      id = $3$NL}" "$1"
}
swup() { env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$TWB" SWAN_STATE="$SWS" "$SH" "$MVPN" up strongswan "$@"; }
swdown() { env MVPN_TEST_ALLOW_DOWN=1 MVPN_BREW="$TWB" SWAN_STATE="$SWS" "$SH" "$MVPN" down strongswan "$1"; }
PA=$(new_conn "$(swan_conf lab-psk psk lab.example)")
OUT=$({ feed "$PA"; printf 'psk=TwoPskS3cret\n'; } | swup "$PA" 2>&1) || { nok "F2: első (PSK) up"; echo "$OUT"; cat "$MVPN_LOG_BASE/$PA.log"; }
EB=$(new_conn "$(swan_conf lab-eap eap-mschapv2 lab.example)")
OUT=$({ feed "$EB"; printf 'username=labuser\npassword=TwoEapS3cret\n'; } | swup "$EB" 2>&1) || { nok "F2: második (EAP) up"; echo "$OUT"; cat "$MVPN_LOG_BASE/$EB.log"; }
LOADED=$(cat "$SWS/loaded" 2>/dev/null)
for want in connections.lab-psk connections.lab-eap "secrets.ike-mvpn-$PA" "secrets.eap-mvpn-$EB"; do
  grep -qxF "$want" <<<"$LOADED" && ok "F2: két kapcsolat után is betöltve: $want" || { nok "F2: két kapcsolat után is betöltve: $want"; echo "$LOADED"; }
done
grep -q -- "--initiate --child lab-eap --ike lab-eap " "$SWS/argv" && ok "F2: az --initiate a saját IKE-configot nevezi meg (--ike)" \
  || { nok "F2: az --initiate a saját IKE-configot nevezi meg (--ike)"; cat "$SWS/argv"; }
! grep -q 'S3cret' "$SWS/argv" "$MVPN_LOG_BASE/$PA.log" "$MVPN_LOG_BASE/$EB.log" && ok "F2: titok nincs az argv-ben és a naplóban" || nok "F2: titok nincs az argv-ben és a naplóban"
[ -z "$(find "$MVPN_RUN_BASE" -name 'load*.conf' 2>/dev/null)" ] && ok "F2: az összefűzött betöltőfájl nem marad meg" || { nok "F2: az összefűzött betöltőfájl nem marad meg"; find "$MVPN_RUN_BASE"; }
# Ugyanaz a kapcsolatnév egy harmadikban: érthető hiba, az első kettő betöltve marad.
DUP=$(new_conn "$(swan_conf lab-psk psk other.example)")
OUT=$({ feed "$DUP"; printf 'psk=DupS3cret\n'; } | swup "$DUP" 2>&1); RC=$?
[ "$RC" = 1 ] && [ "$OUT" = "Another active strongSwan connection already defines connections.lab-psk" ] && [ ! -e "$MVPN_RUN_BASE/$DUP" ] \
  && [ "$(cat "$SWS/loaded")" = "$LOADED" ] && ok "F2: azonos kapcsolatnév: érthető hiba, a többi érintetlen" \
  || { nok "F2: azonos kapcsolatnév: érthető hiba, a többi érintetlen"; echo "$RC $OUT"; cat "$SWS/loaded"; }
# Két PSK ugyanarra a távoli azonosítóra: a charon nem tudná, melyiket használja → érthető hiba.
AMB=$(new_conn "$(swan_conf lab-psk2 psk lab.example)")
OUT=$({ feed "$AMB"; printf 'psk=AmbS3cret\n'; } | swup "$AMB" --lang hu 2>&1); RC=$?
[ "$RC" = 1 ] && [ "$OUT" = "Egy másik aktív strongSwan-kapcsolat már tart titkot ugyanezekhez az azonosítókhoz (adj meg eltérő remote id-t)" ] \
  && [ "$(cat "$SWS/loaded")" = "$LOADED" ] && ok "F2: két PSK ugyanarra a remote id-re: érthető hiba (magyarul)" \
  || { nok "F2: két PSK ugyanarra a remote id-re: érthető hiba (magyarul)"; echo "$RC $OUT"; }
# Az egyik bontása a másikat betöltve hagyja (és csak a sajátját bontja).
: >"$SWS/terminated"
swdown "$EB" >/dev/null 2>&1
LOADED=$(cat "$SWS/loaded" 2>/dev/null)
grep -qxF connections.lab-psk <<<"$LOADED" && grep -qxF "secrets.ike-mvpn-$PA" <<<"$LOADED" && ! grep -q 'lab-eap\|eap-mvpn' <<<"$LOADED" \
  && ok "F2: a második bontása után az első betöltve marad, a második kitöltve" || { nok "F2: a második bontása után az első betöltve marad, a második kitöltve"; echo "$LOADED"; }
[ "$(cat "$SWS/terminated")" = "--terminate --ike lab-eap --timeout 10" ] && ok "F2: a bontás csak a saját IKE SA-t bontja" \
  || { nok "F2: a bontás csak a saját IKE SA-t bontja"; cat "$SWS/terminated"; }
[ ! -e "$MVPN_RUN_BASE/$EB" ] && [ -d "$MVPN_RUN_BASE/$PA" ] && ok "F2: csak a bontott futási mappája törlődik" || nok "F2: csak a bontott futási mappája törlődik"
swdown "$PA" >/dev/null 2>&1
[ ! -e "$MVPN_RUN_BASE/$PA" ] && ok "F2: az első bontása" || nok "F2: az első bontása"

# ---------- MFA: management közvetítő (mvpn-mgmt) ----------
# Hamis openvpn + hamis management szerver (perl, unix socket a futási könyvtárban): a valódi közvetítő a valódi
# protokollt beszéli vele. A szerver minden kapott parancsot átiratba ír, így az engedélyezőlista ellenőrizhető.
# A futási könyvtár itt rövid útvonalon ($MR) van (unix socket: legfeljebb 104 bájt).
MB="$T/mfabrew"; mkdir -p "$MB/bin"
cat >"$T/fakemgmt.pl" <<'PL'
use strict; use warnings;
use IO::Socket::UNIX; use IO::Select;
my ($path, $log, $pid, $mode, $tr) = @ARGV;
$SIG{ALRM} = sub { exit 3 }; alarm 120;
unlink $path;
my $srv = IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => $path, Listen => 1) or die "listen: $!";
open(my $L, '>>', $log) or die; my $o = select($L); $| = 1; select($o);
open(my $T, '>>', $tr) or die; $o = select($T); $| = 1; select($o);
my $c = $srv->accept or die "accept: $!";
$c->autoflush(1);
my $sel = IO::Select->new($c);
sub alive { kill 0, $pid }
sub wr { print $c "$_[0]\r\n" }
sub logl { print $L "2026-10-18 12:00:00 $_[0]\n" }
# A közvetítő következő parancsa (átiratba írva, SUCCESS válasszal). Ha az openvpn (a sleep) leállt: kilépés.
# sysread + saját puffer (a select és a pufferelt <$c> keverése elnyelné az egy csomagban érkező második sort).
my $buf = '';
sub nextline {
  while (1) {
    if ($buf =~ s/\A([^\n]*)\n//) { my $l = $1; $l =~ s/\r\z//; print $T "$l\n"; return $l }
    return undef unless alive();
    if ($sel->can_read(0.5)) { my $n = sysread($c, $buf, 4096, length $buf); return undef unless $n }
  }
}
sub rd { my $l = nextline(); exit 0 unless defined $l; wr("SUCCESS: ok"); return $l }
sub expect { my $want = shift; my $l = rd(); die "expected $want, got '$l'" unless $l =~ $want; return $l }
sub hold { wr(">HOLD:Waiting for hold release:0"); expect(qr/^hold release$/) }
sub creds { wr(">PASSWORD:Need 'Auth' username/password"); expect(qr/^username "Auth" /); expect(qr/^password "Auth" /) }
sub done { logl("Initialization Sequence Completed"); wr(">STATE:1760000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,") }
wr(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info");
expect(qr/^state on$/);
# Titkos token és ECHO: a közvetítő nem adhatja tovább, és nem jelenthet felépülést.
wr(">PASSWORD:Auth-Token:T0kenS3cretXYZ");
wr(">ECHO:1760000000,Initialization Sequence Completed");
hold();
if ($mode eq 'plain') { creds(); done() }
elsif ($mode eq 'crv1') {
  creds();
  logl("AUTH: Received control message: AUTH_FAILED,CRV1:R:st4te-ID:Ym9i:Enter PIN");
  wr(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:st4te-ID:Ym9i:Enter PIN']");
  hold(); creds(); done();
}
elsif ($mode eq 'inject') {
  creds();
  wr(">INFOMSG:OPEN_URL:javascript:alert(1)");
  wr(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:stLONG:Ym9i:" . ('A' x 5000) . "']");
  wr(">PASSWORD:Verification Failed: 'Auth' ['CRV1:E,R:st2:Ym9i:Enter\x1b[31m PIN\",\"state\":\"done\\n" . ('x' x 300) . "']");
  wr("\",\"state\":\"done\",\"url\":\"https://evil.example.com\"}");
  hold(); creds(); done();
}
elsif ($mode eq 'web') {
  creds();
  wr(">STATE:1760000000,AUTH_PENDING,timeout 30,,,,,");
  wr(">INFOMSG:OPEN_URL:http://evil.example.com/login");
  sleep 3;
  wr(">INFOMSG:WEB_AUTH::https://sso.example.com/auth?session=abc");
  sleep 3; done();
}
elsif ($mode eq 'crtext') {
  creds(); wr(">INFOMSG:CR_TEXT:R,E:Enter the code from your app");
  expect(qr/^cr-response [A-Za-z0-9+\/=]+$/); done();
}
elsif ($mode eq 'static') {
  wr(">PASSWORD:Need 'Auth' username/password SC:1,Enter OTP");
  expect(qr/^username "Auth" /); expect(qr/^password "Auth" /); done();
}
elsif ($mode eq 'authfail') {
  creds(); logl("AUTH: Received control message: AUTH_FAILED");
  wr(">PASSWORD:Verification Failed: 'Auth'");
  wr(">HOLD:Waiting for hold release:5");
  wr(">PASSWORD:Need 'Auth' username/password");
  rd();
}
elsif ($mode eq 'cancel') {
  creds(); wr(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:st:Ym9i:Enter PIN']"); hold();
  wr(">PASSWORD:Need 'Auth' username/password"); rd();
}
elsif ($mode eq 'webloop') {
  creds();
  while (alive()) { wr(">INFOMSG:WEB_AUTH::https://sso.example.com/again"); sleep 1 }
}
elsif ($mode eq 'postconnect') { creds(); done(); sleep 1; wr(">INFOMSG:CR_TEXT:R:Enter the code again") }
elsif ($mode eq 'wait') { creds(); wr(">STATE:1760000000,AUTH_PENDING,timeout 120,,,,,") }
while (defined(nextline())) { }
PL
cat >"$MB/bin/openvpn" <<FAKE
#!/bin/bash
printf '%s\n' "\$@" >"$T/mfa-argv"
while [ \$# -gt 0 ]; do
  case "\$1" in
    --log-append) L="\$2"; shift ;;
    --writepid) P="\$2"; shift ;;
    --management) S="\$2"; shift ;;
  esac
  shift
done
"$T/bin/openvpn" 120 </dev/null >/dev/null 2>&1 &
echo \$! >"\$P"
/usr/bin/perl "$T/fakemgmt.pl" "\$S" "\$L" "\$(cat "\$P")" "\$FAKE_MGMT_MODE" "$T/mgmt-transcript.\$FAKE_MGMT_MODE" </dev/null >>"$T/fakemgmt.err" 2>&1 &
exit 0
FAKE
chmod 755 "$MB/bin/openvpn"
MUI="$MR/ui"; MRUN="$MR/run"
mfa_env() { env MVPN_TEST_ALLOW_UP=1 MVPN_TEST_ALLOW_DOWN=1 MVPN_LIBEXEC="$FL" MVPN_BREW="$MB" MVPN_RUN_BASE="$MRUN" MVPN_UI_BASE="$MUI" "$@"; }
mfa_down() { mfa_env "$SH" "$MVPN" down openvpn "$1" </dev/null >"$T/out" 2>&1; }
mfa_respond() { printf '%s' "$2" | env MVPN_RUN_BASE="$MRUN" MVPN_UI_BASE="$MUI" "$SH" "$MVPN" respond openvpn "$1" >"$T/out" 2>&1; }
# ui <id> <mező>: az állapotfájl egy mezője (python json; hibás JSON: kilépés 1).
ui() { python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
v=d.get(sys.argv[2])
print("" if v is None else v)' "$MUI/$1.json" "$2" 2>/dev/null; }
wait_ui() { local i; for i in $(seq 1 100); do [ "$(ui "$1" state)" = "$2" ] && return 0; sleep 0.2; done; return 1; }
wait_gone() { local i; for i in $(seq 1 25); do [ -e "$1" ] || return 0; sleep 0.2; done; return 1; }
ALLOWED='^(state on|hold release|username "Auth" ".*"|password "Auth" ".*"|cr-response [A-Za-z0-9+/=]+)$'
allowlisted() { [ -s "$1" ] && ! grep -vE "$ALLOWED" "$1" >/dev/null; }

# Dry-run: a management opciók a config után, puszta --auth-user-pass, a közvetítő argv-jében nincs titok.
MD=$(new_conn "$GOOD_OVPN")
{ feed "$MD"; printf 'username=bob\npassword=Sup3rTitok\n'; } | "$SH" "$MVPN" up openvpn "$MD" --dry-run >"$T/mfa-dry.out" 2>&1
grep -q -- "--verb 3 --management $MVPN_RUN_BASE/$MD.dryrun.[A-Za-z0-9]*/mgmt.sock unix --management-client-user root --management-hold --management-query-passwords --auth-retry interact --setenv IV_SSO openurl,webauth,crtext --auth-user-pass\$" "$T/mfa-dry.out" \
  && ok "mfa dry-run: management opciók a config után, puszta --auth-user-pass" || { nok "mfa dry-run: management opciók a config után, puszta --auth-user-pass"; cat "$T/mfa-dry.out"; }
grep -qF -- "mvpn-mgmt --id $MD --run $MVPN_RUN_BASE/$MD.dryrun." "$T/mfa-dry.out" && grep -qF -- "--ui $MVPN_UI_BASE --uid $(id -u) --gid $(id -g)" "$T/mfa-dry.out" \
  && ok "mfa dry-run: a közvetítő indítása (argv-ben nincs titok)" || { nok "mfa dry-run: a közvetítő indítása (argv-ben nincs titok)"; cat "$T/mfa-dry.out"; }
grep -q 'Sup3rTitok' "$T/mfa-dry.out" "$MVPN_LOG_BASE/$MD.log" && nok "mfa dry-run: a jelszó nem látszik" || ok "mfa dry-run: a jelszó nem látszik"
for d in "management /tmp/s unix" "management-hold" "management-query-passwords" "management-client-user root"; do
  DESC="management a configban tiltott (jelzéssel is): ${d%% *}"
  expect_fail "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\n'"$d")" --dry-run --accept-risky "${d%% *}"
done
DESC="static-challenge a configban engedett"
expect_ok "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN"$'\nstatic-challenge "Enter OTP" 1')" --dry-run
DESC="hiányzó mvpn-mgmt → hiba (valódi up)"
expect_fail mfa_env MVPN_MGMT=/nonexistent FAKE_MGMT_MODE=plain "$SH" "$MVPN" up openvpn "$(new_conn "$GOOD_OVPN")"

# Sima felhasználónév/jelszó a managementen át; hold release; a jelszó-válasz; a UI könyvtár symlink-biztos.
mkdir -p "$MR/uitarget"; ln -s "$MR/uitarget" "$MUI"
P1=$(new_conn "$GOOD_OVPN")
{ feed "$P1"; printf 'username=bob\npassword=Pl4in"S3c\\ret\n'; } | mfa_env FAKE_MGMT_MODE=plain "$SH" "$MVPN" up openvpn "$P1" >"$T/out" 2>&1 \
  && ok "mfa: sima hitelesítés a közvetítőn át" || { nok "mfa: sima hitelesítés a közvetítőn át"; cat "$T/out" "$T/fakemgmt.err"; }
TR="$T/mgmt-transcript.plain"
grep -qx 'hold release' "$TR" && ok "mfa: hold release" || { nok "mfa: hold release"; cat "$TR"; }
grep -qx 'username "Auth" "bob"' "$TR" && grep -qxF 'password "Auth" "Pl4in\"S3c\\ret"' "$TR" \
  && ok "mfa: username/password \"Auth\" válasz (idézve, escape-elve)" || { nok "mfa: username/password \"Auth\" válasz (idézve, escape-elve)"; cat "$TR"; }
allowlisted "$TR" && ok "mfa: csak engedélyezőlistás parancsok (sima)" || { nok "mfa: csak engedélyezőlistás parancsok (sima)"; cat "$TR"; }
[ ! -L "$MUI" ] && [ -d "$MUI" ] && [ "$(stat -f %Lp "$MUI")" = 755 ] && [ -z "$(ls -A "$MR/uitarget")" ] \
  && ok "mfa: a UI könyvtár symlink helyén valódi 755-ös könyvtár" || { nok "mfa: a UI könyvtár symlink helyén valódi 755-ös könyvtár"; ls -la "$MR"; }
wait_gone "$MUI/$P1.json" && ok "mfa: felépülés után nincs állapotfájl" || nok "mfa: felépülés után nincs állapotfájl"
grep -q 'S3c' "$MVPN_LOG_BASE/$P1.log" && nok "mfa: a jelszó nincs a naplóban" || ok "mfa: a jelszó nincs a naplóban"
grep -q 'T0kenS3cretXYZ' "$MVPN_LOG_BASE/$P1.log" && nok "mfa: az Auth-Token nincs a naplóban" || ok "mfa: az Auth-Token nincs a naplóban"
grep -q '\[mgmt\] hold released' "$MVPN_LOG_BASE/$P1.log" && grep -q '\[mgmt\] credentials sent' "$MVPN_LOG_BASE/$P1.log" \
  && ok "mfa: a közvetítő eseményei a naplóban (érték nélkül)" || { nok "mfa: a közvetítő eseményei a naplóban (érték nélkül)"; cat "$MVPN_LOG_BASE/$P1.log"; }
P1M=$(cat "$MRUN/$P1/mgmt.pid" 2>/dev/null)
mfa_down "$P1" && ok "mfa: down" || { nok "mfa: down"; cat "$T/out"; }
[ ! -e "$MRUN/$P1" ] && [ ! -e "$MUI/$P1.json" ] && ! ps -p "$P1M" >/dev/null 2>&1 \
  && ok "mfa: down után nincs futási könyvtár, állapotfájl és közvetítő" || nok "mfa: down után nincs futási könyvtár, állapotfájl és közvetítő"

# CRV1 (dinamikus challenge): AUTH_FAILED,CRV1 nem hiba; a challenge az állapotfájlba kerül; a válasz a respond-dal.
C1=$(new_conn "$GOOD_OVPN")
{ feed "$C1"; printf 'username=bob\npassword=CrvS3cret\n'; } | mfa_env FAKE_MGMT_MODE=crv1 "$SH" "$MVPN" up openvpn "$C1" >"$T/c1.out" 2>&1 & W=$!
if wait_ui "$C1" challenge; then ok "crv1: challenge az állapotfájlban"; else nok "crv1: challenge az állapotfájlban"; cat "$T/c1.out"; fi
[ "$(ui "$C1" method)" = crv1 ] && [ "$(ui "$C1" text)" = "Enter PIN" ] && [ "$(ui "$C1" echo)" = False ] \
  && ok "crv1: szöveg és echo" || nok "crv1: szöveg és echo ($(cat "$MUI/$C1.json" 2>/dev/null))"
[ "$(stat -f '%Lp %Su' "$MUI/$C1.json" 2>/dev/null)" = "600 $(id -un)" ] && ok "crv1: állapotfájl 600, a felhasználóé" || nok "crv1: állapotfájl 600, a felhasználóé"
mfa_respond "$C1" $'kind=crv1\nresponse=987654\n' && ok "crv1: respond" || { nok "crv1: respond"; cat "$T/out"; }
wait "$W" && ok "crv1: felépült a válasz után" || { nok "crv1: felépült a válasz után"; cat "$T/c1.out"; }
TR="$T/mgmt-transcript.crv1"
grep -qx 'password "Auth" "CRV1::st4te-ID::987654"' "$TR" && [ "$(grep -c '^username "Auth" "bob"$' "$TR")" = 2 ] \
  && ok "crv1: CRV1::<state>::<válasz> a dekódolt felhasználónévvel" || { nok "crv1: CRV1::<state>::<válasz> a dekódolt felhasználónévvel"; cat "$TR"; }
[ "$(grep -c '^hold release$' "$TR")" = 2 ] && ok "crv1: hold release az újraindítás után is" || nok "crv1: hold release az újraindítás után is"
allowlisted "$TR" && ok "crv1: csak engedélyezőlistás parancsok" || { nok "crv1: csak engedélyezőlistás parancsok"; cat "$TR"; }
grep -q '987654\|CrvS3cret' "$MVPN_LOG_BASE/$C1.log" && nok "crv1: kód és jelszó nincs a naplóban" || ok "crv1: kód és jelszó nincs a naplóban"
grep -q 'kind: crv1' "$MVPN_LOG_BASE/$C1.log" && ok "crv1: a respond naplózva (érték nélkül)" || nok "crv1: a respond naplózva (érték nélkül)"
mfa_down "$C1"

# Injektálás a challenge szövegében: túl hosszú sor eldobva, vezérlőkarakter és JSON-szerű szöveg ártalmatlan,
# a hosszú szöveg csonkolva, a "sortörés utáni" sor (nem > kezdetű) figyelmen kívül, javascript: URL eldobva.
I1=$(new_conn "$GOOD_OVPN")
{ feed "$I1"; printf 'username=bob\npassword=InjS3cret\n'; } | mfa_env FAKE_MGMT_MODE=inject "$SH" "$MVPN" up openvpn "$I1" >"$T/i1.out" 2>&1 & W=$!
wait_ui "$I1" challenge
python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); t=d["text"]
assert d["state"]=="challenge" and d.get("url") is None, d
assert t.startswith("Enter") and len(t)<=201 and all(ord(c)>=32 for c in t), t
assert "\x1b" not in t and "AAAA" not in t, t' "$MUI/$I1.json" 2>"$T/out" \
  && ok "injektálás: tisztított, csonkolt szöveg, érvényes JSON, nincs URL" || { nok "injektálás: tisztított, csonkolt szöveg, érvényes JSON, nincs URL"; cat "$T/out" "$MUI/$I1.json"; }
mfa_respond "$I1" $'kind=crv1\nresponse=111222\n'
wait "$W" && grep -qx 'password "Auth" "CRV1::st2::111222"' "$T/mgmt-transcript.inject" \
  && ok "injektálás: a túl hosszú sor eldobva, a válasz a második challenge-re ment" || { nok "injektálás: a túl hosszú sor eldobva, a válasz a második challenge-re ment"; cat "$T/i1.out" "$T/mgmt-transcript.inject"; }
allowlisted "$T/mgmt-transcript.inject" && ok "injektálás: csak engedélyezőlistás parancsok" || nok "injektálás: csak engedélyezőlistás parancsok"
mfa_down "$I1"

# Webes hitelesítés: az http URL eldobva (pending, URL nélkül), a https URL megmarad; a naplóba csak a hoszt kerül.
W1=$(new_conn "$GOOD_OVPN")
{ feed "$W1"; printf 'username=bob\npassword=WebS3cret\n'; } | mfa_env FAKE_MGMT_MODE=web "$SH" "$MVPN" up openvpn "$W1" >"$T/w1.out" 2>&1 & W=$!
wait_ui "$W1" pending && [ -z "$(ui "$W1" url)" ] && ok "web: http URL eldobva (pending, URL nélkül)" || { nok "web: http URL eldobva (pending, URL nélkül)"; cat "$MUI/$W1.json"; }
wait_ui "$W1" webauth && [ "$(ui "$W1" url)" = "https://sso.example.com/auth?session=abc" ] && [ -n "$(ui "$W1" deadline)" ] \
  && ok "web: https URL az állapotfájlban, határidővel" || { nok "web: https URL az állapotfájlban, határidővel"; cat "$MUI/$W1.json"; }
mfa_respond "$W1" $'kind=webauth-ack\nresponse=\n' && ok "web: webauth-ack" || { nok "web: webauth-ack"; cat "$T/out"; }
wait "$W" && ok "web: felépült" || { nok "web: felépült"; cat "$T/w1.out"; }
grep -q 'web authentication requested: sso.example.com' "$MVPN_LOG_BASE/$W1.log" && ! grep -q 'session=abc\|evil.example.com' "$MVPN_LOG_BASE/$W1.log" \
  && ok "web: a naplóban csak a hoszt" || { nok "web: a naplóban csak a hoszt"; cat "$MVPN_LOG_BASE/$W1.log"; }
mfa_down "$W1"

# CR_TEXT: a válasz cr-response <base64> formában.
X1=$(new_conn "$GOOD_OVPN")
{ feed "$X1"; printf 'username=bob\npassword=CrtS3cret\n'; } | mfa_env FAKE_MGMT_MODE=crtext "$SH" "$MVPN" up openvpn "$X1" >"$T/x1.out" 2>&1 & W=$!
wait_ui "$X1" challenge && [ "$(ui "$X1" method)" = crtext ] && [ "$(ui "$X1" echo)" = True ] \
  && ok "crtext: challenge (echo)" || nok "crtext: challenge (echo)"
mfa_respond "$X1" $'kind=crv1\nresponse=112233\n'
wait "$W" && grep -qx 'cr-response MTEyMjMz' "$T/mgmt-transcript.crtext" && ok "crtext: cr-response base64" || { nok "crtext: cr-response base64"; cat "$T/x1.out" "$T/mgmt-transcript.crtext"; }
mfa_down "$X1"

# Statikus challenge: az app SCRV1-be csomagolja (challenge=packed), a közvetítő változatlanul adja át; a kód maszkolva.
S1=$(new_conn "$GOOD_OVPN"$'\nstatic-challenge "Enter OTP" 1')
SCRV="SCRV1:$(printf StatPass | base64):$(printf 246810 | base64)"
{ feed "$S1"; printf 'username=bob\npassword=%s\notp=246810\nchallenge=packed\n' "$SCRV"; } | mfa_env FAKE_MGMT_MODE=static "$SH" "$MVPN" up openvpn "$S1" >"$T/out" 2>&1 \
  && grep -qx "password \"Auth\" \"$SCRV\"" "$T/mgmt-transcript.static" \
  && ok "static: SCRV1 jelszó változatlanul" || { nok "static: SCRV1 jelszó változatlanul"; cat "$T/out" "$T/mgmt-transcript.static"; }
[ "$SCRV" = "SCRV1:U3RhdFBhc3M=:MjQ2ODEw" ] && ok "static: SCRV1 formátum" || nok "static: SCRV1 formátum ($SCRV)"
grep -q '246810\|U3RhdFBhc3M' "$MVPN_LOG_BASE/$S1.log" && nok "static: a kód és a jelszó nincs a naplóban" || ok "static: a kód és a jelszó nincs a naplóban"
mfa_down "$S1"
# Tartalék: csomagolatlan jelszó → a közvetítő kéri a kódot (static), és ő csomagol.
S2=$(new_conn "$GOOD_OVPN")
: >"$T/mgmt-transcript.static"
{ feed "$S2"; printf 'username=bob\npassword=FallPass\n'; } | mfa_env FAKE_MGMT_MODE=static "$SH" "$MVPN" up openvpn "$S2" >"$T/s2.out" 2>&1 & W=$!
wait_ui "$S2" challenge && [ "$(ui "$S2" method)" = static ] && [ "$(ui "$S2" text)" = "Enter OTP" ] && [ "$(ui "$S2" echo)" = True ] \
  && ok "static tartalék: challenge az állapotfájlban" || nok "static tartalék: challenge az állapotfájlban"
mfa_respond "$S2" $'kind=static\nresponse=135790\n'
wait "$W" && grep -qx "password \"Auth\" \"SCRV1:$(printf FallPass | base64):$(printf 135790 | base64)\"" "$T/mgmt-transcript.static" \
  && ok "static tartalék: a közvetítő SCRV1-be csomagolt" || { nok "static tartalék: a közvetítő SCRV1-be csomagolt"; cat "$T/s2.out" "$T/mgmt-transcript.static"; }
mfa_down "$S2"

# Végleges hitelesítési hiba: a közvetítő nem küld újra, leállítja az openvpn-t; az up takarít.
A1=$(new_conn "$GOOD_OVPN")
OUT=$({ feed "$A1"; printf 'username=bob\npassword=BadS3cret\n'; } | mfa_env FAKE_MGMT_MODE=authfail "$SH" "$MVPN" up openvpn "$A1" 2>&1); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Authentication failed"*) true ;; *) false ;; esac \
  && ok "authfail: hiba" || { nok "authfail: hiba"; echo "$OUT"; }
[ "$(grep -c '^password "Auth"' "$T/mgmt-transcript.authfail")" = 1 ] && allowlisted "$T/mgmt-transcript.authfail" \
  && ok "authfail: a jelszót nem küldte újra" || { nok "authfail: a jelszót nem küldte újra"; cat "$T/mgmt-transcript.authfail"; }
[ ! -e "$MRUN/$A1" ] && [ ! -e "$MUI/$A1.json" ] && ! pgrep -f "mvpn-mgmt --id $A1" >/dev/null \
  && ok "authfail: takarítás (futási könyvtár, állapotfájl, közvetítő)" || nok "authfail: takarítás (futási könyvtár, állapotfájl, közvetítő)"

# Megszakítás a kódbekérőből (kind=cancel): az up "megszakítva" hibával és takarítással ér véget.
K1=$(new_conn "$GOOD_OVPN")
{ feed "$K1"; printf 'username=bob\npassword=CanS3cret\n'; } | mfa_env FAKE_MGMT_MODE=cancel "$SH" "$MVPN" up openvpn "$K1" >"$T/k1.out" 2>&1 & W=$!
wait_ui "$K1" challenge
mfa_respond "$K1" $'kind=cancel\nresponse=\n'
wait "$W"; RC=$?
[ "$RC" != 0 ] && grep -q 'Authentication cancelled' "$T/k1.out" && [ ! -e "$MRUN/$K1" ] && [ ! -e "$MUI/$K1.json" ] \
  && ok "cancel: megszakítva, takarítva" || { nok "cancel: megszakítva, takarítva ($RC)"; cat "$T/k1.out"; }
pgrep -f "$T/bin/openvpn 120" >/dev/null && nok "mfa: nem maradt futó hamis openvpn" || ok "mfa: nem maradt futó hamis openvpn"
for f in "$MVPN_LOG_BASE"/*.log "$MUI"/*; do [ -e "$f" ] || continue; cat "$f"; done >"$T/all-mfa"
grep -q 'S3cret\|S3c\\ret\|987654\|111222\|112233\|246810\|135790\|T0kenS3cretXYZ' "$T/all-mfa" \
  && nok "mfa: nincs titok vagy kód a naplókban és az állapotfájlokban" || ok "mfa: nincs titok vagy kód a naplókban és az állapotfájlokban"

# mvpn respond validálás (hamis futási könyvtár + "mvpn-mgmt" nevű élő folyamat): csak a négy típus, ≤ 256 bájt,
# vezérlőkarakter nélkül, legfeljebb két sor; a válaszfájl root (itt: a felhasználó) 0600, atomikus.
RB="$MR/rrun"; RID=$(uuidgen); mkdir -p "$RB/$RID"; chmod 700 "$RB/$RID"; echo openvpn >"$RB/$RID/kind"
mkdir -p "$T/mgmtsleep"; ln -s /bin/sleep "$T/mgmtsleep/mvpn-mgmt"; "$T/mgmtsleep/mvpn-mgmt" 60 & FMP=$!
echo "$FMP" >"$RB/$RID/mgmt.pid"; sleep 0.2
resp() { printf '%s' "$1" | env MVPN_RUN_BASE="$RB" "$SH" "$MVPN" respond "${2:-openvpn}" "${3:-$RID}" >"$T/out" 2>&1; }
resp $'kind=crv1\nresponse=123456\n' && [ "$(cat "$RB/$RID/mgmt-resp")" = $'kind=crv1\nresponse=123456' ] && [ "$(stat -f %Lp "$RB/$RID/mgmt-resp")" = 600 ] \
  && ok "respond: érvényes válasz átadva (0600)" || { nok "respond: érvényes válasz átadva (0600)"; cat "$T/out"; }
grep -q '123456' "$MVPN_LOG_BASE/$RID.log" && nok "respond: az érték nincs a naplóban" || ok "respond: az érték nincs a naplóban"
rm -f "$RB/$RID/mgmt-resp"
resp $'kind=webauth-ack\nresponse=ignored\n' && [ "$(cat "$RB/$RID/mgmt-resp")" = $'kind=webauth-ack\nresponse=' ] \
  && ok "respond: webauth-ack érték nélkül" || nok "respond: webauth-ack érték nélkül"
rm -f "$RB/$RID/mgmt-resp"
LONG=$(printf 'x%.0s' $(seq 1 257))
for bad in $'kind=password\nresponse=x\n' $'kind=hold\nresponse=release\n' $'kind=raw\nresponse=signal SIGTERM\n' \
           $'kind=CRV1\nresponse=1\n' $'kind=crv1\nresponse=12\x013\n' $'kind=crv1\nresponse=12\x7f3\n' "kind=crv1"$'\n'"response=$LONG"$'\n' \
           $'kind=crv1\nresponse=1\nextra=1\n' $'kind=crv1\nresponse=1\nkind=crv1\n' $'response=1\n' '' $'kind=crv1 \nresponse=1\n'; do
  if resp "$bad" || [ -e "$RB/$RID/mgmt-resp" ]; then nok "respond elutasítja: $(printf '%q' "$bad")"; rm -f "$RB/$RID/mgmt-resp"; else ok "respond elutasítja: $(printf '%q' "$bad" | cut -c1-60)"; fi
done
resp $'kind=crv1\nresponse=1\n' wireguard && nok "respond: csak openvpn" || ok "respond: csak openvpn"
resp $'kind=crv1\nresponse=1\n' openvpn "../../etc" && nok "respond: érvénytelen id" || ok "respond: érvénytelen id"
resp $'kind=crv1\nresponse=1\n' openvpn "$(uuidgen)" && nok "respond: nincs futó kapcsolat" || ok "respond: nincs futó kapcsolat"
kill "$FMP" 2>/dev/null; wait "$FMP" 2>/dev/null
resp $'kind=crv1\nresponse=1\n' && nok "respond: a közvetítő nem fut" || ok "respond: a közvetítő nem fut"
[ ! -e "$RB/$RID/mgmt-resp" ] && ok "respond: hibás esetekben nincs válaszfájl" || nok "respond: hibás esetekben nincs válaszfájl"
# A here-string keresése helyett: a respond nem ír ideiglenes fájlt (az üres TMPDIR üres marad), és a kód
# csak a futási könyvtár mgmt-resp fájljában van (a naplóban és máshol a futási könyvtárban nincs).
"$T/mgmtsleep/mvpn-mgmt" 60 & FMP=$!; echo "$FMP" >"$RB/$RID/mgmt.pid"; sleep 0.2; mkdir -p "$T/rtmp"
printf 'kind=crv1\nresponse=DISKC0DE77\n' | env TMPDIR="$T/rtmp" MVPN_RUN_BASE="$RB" "$SH" "$MVPN" respond openvpn "$RID" >"$T/out" 2>&1
[ -z "$(ls -A "$T/rtmp")" ] && [ "$(grep -rl DISKC0DE77 "$RB/$RID" "$MVPN_LOG_BASE" 2>/dev/null)" = "$RB/$RID/mgmt-resp" ] \
  && ok "respond: a kód nem kerül lemezre (csak a mgmt-resp-be)" || { nok "respond: a kód nem kerül lemezre (csak a mgmt-resp-be)"; cat "$T/out"; ls -la "$T/rtmp" "$RB/$RID"; }
rm -f "$RB/$RID/mgmt-resp"; kill "$FMP" 2>/dev/null; wait "$FMP" 2>/dev/null

# Összesített várakozási korlát: az ismétlődő WEB_AUTH nem nyújtja a határidőt MFA_MAX fölé.
WL=$(new_conn "$GOOD_OVPN"); START=$(date +%s)
OUT=$({ feed "$WL"; printf 'username=bob\npassword=LoopS3cret\n'; } | mfa_env MVPN_MFA_MAX=4 MVPN_UP_TIMEOUT=3 FAKE_MGMT_MODE=webloop "$SH" "$MVPN" up openvpn "$WL" 2>&1); RC=$?
EL=$(( $(date +%s) - START ))
[ "$RC" != 0 ] && [ "$EL" -le 20 ] && case "$OUT" in *"Timed out waiting for authentication"*) true ;; *) false ;; esac && [ ! -e "$MRUN/$WL" ] \
  && ok "mfa: ismétlődő WEB_AUTH mellett is lejár a korlát ($EL mp)" || { nok "mfa: ismétlődő WEB_AUTH mellett is lejár a korlát ($EL mp)"; echo "$OUT"; }
# Felépülés utáni challenge (újracsatlakozás, nincs figyelő app): a korlát után a közvetítő leállítja az openvpn-t.
PC=$(new_conn "$GOOD_OVPN")
{ feed "$PC"; printf 'username=bob\npassword=PostS3cret\n'; } | mfa_env MVPN_MFA_MAX=3 FAKE_MGMT_MODE=postconnect "$SH" "$MVPN" up openvpn "$PC" >"$T/out" 2>&1 \
  && ok "mfa: postconnect felépült" || { nok "mfa: postconnect felépült"; cat "$T/out"; }
PCP=$(cat "$MRUN/$PC/pid" 2>/dev/null)
for i in $(seq 1 75); do ps -p "$PCP" >/dev/null 2>&1 || break; sleep 0.2; done
! ps -p "$PCP" >/dev/null 2>&1 && grep -q "timed out waiting for authentication" "$MVPN_LOG_BASE/$PC.log" \
  && ok "mfa: felépülés utáni challenge a korlát után leállítja az openvpn-t" || { nok "mfa: felépülés utáni challenge a korlát után leállítja az openvpn-t"; cat "$MVPN_LOG_BASE/$PC.log"; }
mfa_down "$PC"
# A közvetítő leáll hitelesítés közben: az up nem vár a végtelenségig, hibával takarít.
BK=$(new_conn "$GOOD_OVPN")
{ feed "$BK"; printf 'username=bob\npassword=DeadS3cret\n'; } | mfa_env FAKE_MGMT_MODE=wait "$SH" "$MVPN" up openvpn "$BK" >"$T/bk.out" 2>&1 & W=$!
wait_ui "$BK" pending
kill -9 "$(cat "$MRUN/$BK/mgmt.pid")" 2>/dev/null
wait "$W"; RC=$?
[ "$RC" != 0 ] && grep -q 'The management bridge stopped' "$T/bk.out" && [ ! -e "$MRUN/$BK" ] \
  && ok "mfa: leállt közvetítő → hiba és takarítás" || { nok "mfa: leállt közvetítő → hiba és takarítás ($RC)"; cat "$T/bk.out"; }
# status: élő, még nem felépült openvpn halott közvetítővel → failed; közvetítő nélküli (régebbi réteg) futás → connecting.
IB="$T/i2run"; mkdir -p "$IB"; "$T/bin/openvpn" 30 & IP=$!
I2A=$(uuidgen); mkdir -p "$IB/$I2A"; echo openvpn >"$IB/$I2A/kind"; echo "$IP" >"$IB/$I2A/pid"; : >"$IB/$I2A/openvpn.log"; dead_pid >"$IB/$I2A/mgmt.pid"
I2B=$(uuidgen); mkdir -p "$IB/$I2B"; echo openvpn >"$IB/$I2B/kind"; echo "$IP" >"$IB/$I2B/pid"; : >"$IB/$I2B/openvpn.log"
SJ=$(MVPN_RUN_BASE="$IB" "$SH" "$MVPN" status)
python3 -c 'import json,sys; d={x["id"]:x["state"] for x in json.loads(sys.argv[1])}; sys.exit(0 if d[sys.argv[2]]=="failed" and d[sys.argv[3]]=="connecting" else 1)' "$SJ" "$I2A" "$I2B" \
  && ok "status: halott közvetítő mellett a még nem felépült openvpn failed" || { nok "status: halott közvetítő mellett a még nem felépült openvpn failed"; echo "$SJ"; }
kill "$IP" 2>/dev/null; wait "$IP" 2>/dev/null

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
  { feed "$SDID"; printf 'password=%s\n' "$SPW"; } | "$SH" "$MVPN" up sstp "$SDID" --dry-run "$@" >"$T/sd.out" 2>&1
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
# A sortöréssel injektált sor (`"` + új sor + `plugin …`) már a szigorú titok-sorokon elakad: Invalid input.
for bpw in 'a"b' 'a\b' "$(printf 'a\tb')" '"
plugin /tmp/x.so'; do
  DESC="sstp: tiltott karakter a jelszóban ($(printf '%s' "$bpw" | head -1 | tr -d '\t'))"
  WANT="must not contain quotation marks, backslashes or control characters"
  case "$bpw" in *"$NL"*) WANT="Invalid input"; DESC="$DESC + sortöréssel injektált sor" ;; esac
  BID=$(new_conn "$GOOD_SSTP")
  OUT=$({ feed "$BID"; printf 'password=%s\n' "$bpw"; } | "$SH" "$MVPN" up sstp "$BID" --dry-run 2>&1); RC=$?
  if [ "$RC" != 0 ] && case "$OUT" in *"$WANT"*) true ;; *) false ;; esac \
     && ! printf '%s' "$OUT" | grep -q 'DRY: .*sstpc'; then ok "$DESC"; else nok "$DESC"; echo "$OUT"; fi
done
QID=$(new_conn "$GOOD_SSTP")
OUT=$({ feed "$QID"; printf 'password=a"b\n'; } | "$SH" "$MVPN" up sstp "$QID" --dry-run --lang hu 2>&1)
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
  if { feed "$SBID"; printf 'password=%s\n' "$SPW"; } | "$SH" "$MVPN" up sstp "$SBID" --dry-run >"$T/out" 2>&1; then nok "$DESC"; cat "$T/out"
  elif grep -q 'DRY: .*sstpc' "$T/out"; then nok "$DESC (sstpc parancs mégis megjelent)"
  else ok "$DESC"; fi
done
DESC="sstp: vezérlőkarakter"; expect_fail "$SH" "$MVPN" up sstp "$(new_conn $'server=a.example\nuser=bo\001b')" --dry-run
QID=$(new_conn $'server=a b\nuser=bob')
OUT=$({ feed "$QID"; printf 'password=%s\n' "$SPW"; } | "$SH" "$MVPN" up sstp "$QID" --dry-run --lang hu 2>&1)
case "$OUT" in *"Érvénytelen config:"*"1. sor: Érvénytelen szerver"*) ok "sstp: magyar validátor-üzenet, érték idézése nélkül" ;;
  *) nok "sstp: magyar validátor-üzenet, érték idézése nélkül"; echo "$OUT" ;; esac
CAID=$(new_conn "$CA_SSTP")
OUT=$(feed "$CAID" | "${VALIDATE[@]}" --sstp-params | tr '\n' '|')
[ "$OUT" = "vpn.example.com|4443|bob|ca|yes|yes|" ] && ok "mvpn-validate --sstp-params" || nok "mvpn-validate --sstp-params ($OUT)"
feed "$CAID" | "${VALIDATE[@]}" --sstp-ca | diff -q - <(printf '%s\n' "$PEM") >/dev/null && ok "mvpn-validate --sstp-ca" || nok "mvpn-validate --sstp-ca"

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
hook_shim "$FL2"
sstp_up() { env MVPN_TEST_ALLOW_UP=1 MVPN_BREW="$SPB" MVPN_LIBEXEC="$FL2" MVPN_ROUTE="$T/fakeroute" MVPN_TEST_IFACE_OK=1 "$@"; }
sstp_alive_t() { ps -p "$1" -o comm= 2>/dev/null | grep -q 'sstpc$'; }

SUID=$(new_conn "$CA_SSTP"); : >"$T/sstp-dns.log"; : >"$T/sstp-route.log"
# Régi és új sstp-pppd.* fájlok a takarítás teszteléséhez (csak a régi, szabályos, pontos nevű törlődhet).
ST="$MVPN_SSTP_TMP"; echo x >"$T/sweep-victim"
echo old >"$ST/sstp-pppd.AAAAAA"; echo old >"$ST/sstp-pppd.AB"; ln -s "$T/sweep-victim" "$ST/sstp-pppd.SYMSYM"
mkdir "$ST/sstp-pppd.DIRDIR"; echo new >"$ST/sstp-pppd.NEWNEW"
touch -h -t 202001010000 "$ST/sstp-pppd.AAAAAA" "$ST/sstp-pppd.AB" "$ST/sstp-pppd.SYMSYM" "$ST/sstp-pppd.DIRDIR"
touch -t 209901010000 "$ST/sstp-pppd.NEWNEW"
{ feed "$SUID"; printf 'username=ignored\npassword=%s\n' "$SPW"; } | sstp_up FAKE_SSTP_MODE=ok INJECT_LOG="$MVPN_LOG_BASE/$SUID.log" "$SH" "$MVPN" up sstp "$SUID" >"$T/out" 2>&1 \
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
# Az export keresése helyett: a sstpc környezetében nincs jelszó (lásd a gyermek-környezet ellenőrzést fent).
[ -s "$T/child-env.sstpc" ] && ! grep -q 'EnvS3cretPw' "$T/child-env.sstpc" && ok "sstp: nincs titok az indítás környezetében" || nok "sstp: nincs titok az indítás környezetében"
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
OUT=$({ feed "$SUID"; printf 'password=%s\n' "$SPW"; } | sstp_up FAKE_SSTP_MODE=ok FAKE_ROUTE_FAIL=1 "$SH" "$MVPN" up sstp "$SUID" 2>&1); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Setting the routes failed"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$SUID" ] \
  && grep -qx -- '-n delete -net 0.0.0.0/1 -interface ppp9' "$T/sstp-route.log" && grep -qx -- '-n delete -net 128.0.0.0/1 -interface ppp9' "$T/sstp-route.log" \
  && ok "sstp: útvonal-hiba → takarítás az útvonalakkal együtt" || { nok "sstp: útvonal-hiba → takarítás az útvonalakkal együtt"; echo "$OUT"; cat "$T/sstp-route.log"; }

[ ! -e "$FL2/.created-ppp-options" ] && ok "sstp: meglévő /etc/ppp/options mellett nincs jelölő" || nok "sstp: meglévő /etc/ppp/options mellett nincs jelölő"

# A maszk-fájlt az awk beolvasás után azonnal törli (kapcsolódás közben sincs meg, SIGKILL után sem maradna).
SUID=$(new_conn "$GOOD_SSTP")
{ feed "$SUID"; printf 'password=%s\n' "$SPW"; } | sstp_up FAKE_SSTP_MODE=hang MVPN_UP_TIMEOUT=4 "$SH" "$MVPN" up sstp "$SUID" >"$T/hang.out" 2>&1 & W=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -f "$MVPN_RUN_BASE/$SUID/pid" ] && break; sleep 0.2; done
sleep 1
[ -d "$MVPN_RUN_BASE/$SUID" ] && [ ! -e "$MVPN_RUN_BASE/$SUID/mask" ] && ok "sstp: maszk-fájl törölve már kapcsolódás közben" || { nok "sstp: maszk-fájl törölve már kapcsolódás közben"; ls -la "$MVPN_RUN_BASE/$SUID"; }
wait "$W"; RC=$?
[ "$RC" != 0 ] && grep -q 'Timed out' "$T/hang.out" && [ ! -e "$MVPN_RUN_BASE/$SUID" ] && ok "sstp: időtúllépés → takarítás" || { nok "sstp: időtúllépés → takarítás"; cat "$T/hang.out"; }

SUID=$(new_conn "$GOOD_SSTP")
OUT=$({ feed "$SUID"; printf 'password=%s\n' "$SPW"; } | sstp_up FAKE_SSTP_MODE=auth "$SH" "$MVPN" up sstp "$SUID" 2>&1); RC=$?
[ "$RC" != 0 ] && case "$OUT" in *"Authentication failed"*) true ;; *) false ;; esac && [ ! -e "$MVPN_RUN_BASE/$SUID" ] \
  && ok "sstp: hitelesítési hiba → hiba, takarítás" || { nok "sstp: hitelesítési hiba → hiba, takarítás"; echo "$OUT"; }
pgrep -f "$T/sstpsleep/sstpc" >/dev/null && nok "sstp: hitelesítési hiba után nem fut sstpc" || ok "sstp: hitelesítési hiba után nem fut sstpc"
SUID=$(new_conn "$GOOD_SSTP")
OUT=$({ feed "$SUID"; printf 'password=%s\n' "$SPW"; } | sstp_up FAKE_SSTP_MODE=cert "$SH" "$MVPN" up sstp "$SUID" 2>&1); RC=$?
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
