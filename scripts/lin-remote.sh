#!/bin/bash
# Runs the working tree on the Linux test VM over SSH (docs/architecture.md, "The Linux test machine").
#
#   scripts/lin-remote.sh sync                         copy HEAD + uncommitted changes of tracked files there
#   scripts/lin-remote.sh run 'COMMAND'                sync, then COMMAND in the remote checkout (a logged job)
#   scripts/lin-remote.sh run-nosync 'COMMAND'         COMMAND in the remote checkout as it is (no sync)
#   scripts/lin-remote.sh desktop 'COMMAND'            sync, then COMMAND in linvpn-dev's desktop session
#   scripts/lin-remote.sh test [EXTRA CARGO ARGS]      sync, then the CI linux job's test set
#   scripts/lin-remote.sh ignored                      sync, then list the ignored tests
#   scripts/lin-remote.sh attach JOB                   follow a job started earlier (its log, then its exit code)
#   scripts/lin-remote.sh put LOCAL NAME               copy a local file or folder to <checkout>/.linvpn-put/NAME
#   scripts/lin-remote.sh fetch REMOTE_PATH LOCAL_DIR  copy a build product back (relative to the checkout)
#
# Environment: LINVPN_SSH (ssh destination linvpn-dev@host, required), LINVPN_REMOTE_DIR (default "linvpn-work",
# one folder name in the remote home; one per concurrent agent), LINVPN_JOB_WAIT (seconds a job may take, default 5400),
# LINVPN_REMOTE_PRINT=1 prints the remote scripts instead of running them (scripts/test-lin-remote.sh).
#
# Every command runs as a job: a script in <checkout>/.lin-jobs/<id>.sh, started detached (setsid) with its output in
# <id>.log and its exit code in <id>.rc; this script polls the log over short SSH calls, so a hanging SSH session
# never loses the command or its result (`attach <id>` picks it up again). `test` and `run` run with CI=1 under a
# login shell (rustup's ~/.cargo/env); `test` wraps cargo in dbus-run-session (a private session bus: no test sees
# the desktop's keyring or notifications). `desktop` checks that linvpn-dev is logged in at the VM's desktop and starts
# the job with `systemd-run --user` in the user's systemd instance, which has the desktop's WAYLAND_DISPLAY, DISPLAY and
# session bus, and which polkit counts as the graphical session. The remote account has no administrator rights;
# nothing here needs any. Nothing secret is sent: the bundle holds only the repository's tracked content.
set -euo pipefail
cd "$(dirname "$0")/.."

SSH_DEST="${LINVPN_SSH:-}"
# No forwarding whatever ~/.ssh/config says: the VM runs unreviewed builds, which must never reach this Mac's agent.
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes -o LogLevel=ERROR -o ForwardAgent=no -o ForwardX11=no
  -o ClearAllForwardings=yes -o ConnectTimeout=20
  -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -i "$HOME/.ssh/linvpn_dev"
  -o UserKnownHostsFile="$HOME/.ssh/linvpn_known_hosts" -o StrictHostKeyChecking=yes)
REMOTE_DIR="${LINVPN_REMOTE_DIR-linvpn-work}"
WAIT="${LINVPN_JOB_WAIT:-5400}"
PRINT="${LINVPN_REMOTE_PRINT:-}"
# Refs are shared by every worktree of the repository: one ref per run.
REF="refs/linvpn/sync-$$"

die() { echo "error: $*" >&2; exit 1; }

[ $# -ge 1 ] || { sed -n '4,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[ -n "$SSH_DEST" ] || die "set LINVPN_SSH=linvpn-dev@<VM address>"
# One folder name directly in the remote home: never empty, absolute, nested, `.`, `..` or hidden (`git clean -fdx`
# runs in it, so `.` would wipe the home and `.ssh` the harness's own key).
[[ "$REMOTE_DIR" =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]*$ ]] || die "LINVPN_REMOTE_DIR: one folder name (letters, digits, . _ -; not starting with .)"
[[ "$WAIT" =~ ^[0-9]+$ ]] || die "LINVPN_JOB_WAIT: seconds"

# The CI linux job's packages; a package whose crate does not exist yet is left out.
PACKAGES=()
for pkg_dir in macvpn-core:crates/core macvpn-app-core:crates/app-core macvpn-platform-api:crates/platform-api \
  macvpn-platform-linux:crates/platform-linux macvpn-unixsys:crates/unixsys macvpn-helper:crates/helper \
  macvpn-control-client:examples/macvpn-control-client macvpn-app:app/src-tauri; do
  if [ -f "${pkg_dir#*:}/Cargo.toml" ]; then PACKAGES+=(-p "${pkg_dir%%:*}"); fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lin-remote.XXXXXXXX")"
cleanup() { rm -rf "${WORK:?}"; git update-ref -d "$REF" 2>/dev/null || true; }
trap cleanup EXIT

# One short SSH call: the script text goes base64-encoded (no re-quoting) into bash's stdin, as one `{ …; }` group
# that bash reads whole before running it, with the group's own stdin from /dev/null (scripts/win-remote.sh).
remote() {
  local b64
  if [ -n "$PRINT" ]; then
    printf '%s\n' "$1"
    return
  fi
  b64="$(printf '{\n%s\n} </dev/null\n' "$1" | base64 | tr -d '\n')"
  # shellcheck disable=SC2029 # expanded locally on purpose: the base64 text is the whole command
  ssh -n "${SSH_OPTS[@]}" "$SSH_DEST" "echo $b64 | base64 -d | bash"
}

sync() {
  local rev tree
  # A snapshot commit of the tracked files as they are on disk, made in a copy of the index (scripts/win-remote.sh).
  cp "$(git rev-parse --git-path index)" "$WORK/index"
  tree="$(GIT_INDEX_FILE="$WORK/index" git add -u && GIT_INDEX_FILE="$WORK/index" git write-tree)" \
    || die "could not snapshot the working tree"
  if [ "$tree" = "$(git rev-parse 'HEAD^{tree}')" ]; then
    rev="$(git rev-parse HEAD)"
  else
    rev="$(git commit-tree --no-gpg-sign "$tree" -p HEAD -m "lin-remote: uncommitted changes on $(git rev-parse --short HEAD)")"
  fi
  git update-ref "$REF" "$rev"
  git bundle create "$WORK/sync.bundle" "$REF" >/dev/null 2>&1 || die "git bundle failed"
  if [ -n "$PRINT" ]; then
    echo "(print only: nothing is synced)"
    return
  fi
  remote "mkdir -p ~/'$REMOTE_DIR' && cd ~/'$REMOTE_DIR' && { [ -d .git ] || git init -q; }"
  scp -q "${SSH_OPTS[@]}" "$WORK/sync.bundle" "$SSH_DEST:$REMOTE_DIR/.sync.bundle"
  # The build products stay: the UI build (app/ui/dist) too, which scripts/lin-smoke.sh builds in one job and the
  # smoke run of the next (synced again) checks against the binary.
  remote "set -e; cd ~/'$REMOTE_DIR'; git fetch -q .sync.bundle '$REF'; git checkout -q --force --detach FETCH_HEAD
git clean -q -fdx -e /target -e node_modules -e /dist -e /app/ui/dist -e /.lin-jobs -e /.linvpn-put -e '/spikes/*/target'
rm -f .sync.bundle; git log -1 --format='synced %h %s'"
}

# The job script: the command in the checkout, its exit code written last (atomically: .rc.tmp, then mv). The command
# runs in a subshell, so an `exit` in it ends only the command and its exit code is still recorded.
job_script() {
  local id="$1" command="$2"
  cat <<SCRIPT
#!/bin/bash
set -o pipefail
cd "\$HOME/$REMOTE_DIR" || { echo 97 > ".lin-jobs/$id.rc"; exit 97; }
export CI=1
(
$command
)
rc=\$?
echo "\$rc" > "\$HOME/$REMOTE_DIR/.lin-jobs/$id.rc.tmp" && mv "\$HOME/$REMOTE_DIR/.lin-jobs/$id.rc.tmp" "\$HOME/$REMOTE_DIR/.lin-jobs/$id.rc"
SCRIPT
}

new_id() { echo "j$(date +%Y%m%d%H%M%S)-$$"; }

# Writes the job script remotely and starts it detached in the SSH user's own session (`plain`) or, after the
# desktop-session check, in the user manager (`desktop`).
start_job() {
  local mode="$1" id="$2" command="$3" b64 launch
  b64="$(job_script "$id" "$command" | base64 | tr -d '\n')"
  if [ "$mode" = desktop ]; then
    launch="session=\$(loginctl show-user \"\$USER\" -p Display --value 2>/dev/null)
type=\$(loginctl show-session \"\$session\" -p Type --value 2>/dev/null)
case \"\$type\" in wayland|x11) ;; *) echo 'no desktop session of '\"\$USER\"': log in as '\"\$USER\"' at the VM desktop (it may be locked), then run again' >&2; exit 3 ;; esac
systemd-run --user --quiet --collect --unit='linvpn-$id' -p StandardOutput=append:\"\$HOME/$REMOTE_DIR/.lin-jobs/$id.log\" -p StandardError=append:\"\$HOME/$REMOTE_DIR/.lin-jobs/$id.log\" /bin/bash -l \"\$HOME/$REMOTE_DIR/.lin-jobs/$id.sh\""
  else
    launch="setsid --fork /bin/bash -l \"\$HOME/$REMOTE_DIR/.lin-jobs/$id.sh\" > \"\$HOME/$REMOTE_DIR/.lin-jobs/$id.log\" 2>&1 < /dev/null"
  fi
  remote "set -e; mkdir -p ~/'$REMOTE_DIR'/.lin-jobs; cd ~/'$REMOTE_DIR'/.lin-jobs
rm -f '$id.log' '$id.rc' '$id.rc.tmp'; : > '$id.log'
echo $b64 | base64 -d > '$id.sh'
$launch
echo 'job $id started (scripts/lin-remote.sh attach $id)' >&2"
  [ -n "$PRINT" ] && job_script "$id" "$command"
  return 0
}

# Polls the job's log (new bytes only) and its exit code; a failed poll is retried, 12 in a row end the wait.
follow() {
  local id="$1" offset=0 waited=0 misses=0 rc n
  [ -n "$PRINT" ] && return 0
  while :; do
    if remote "tail -c +$((offset + 1)) ~/'$REMOTE_DIR'/.lin-jobs/'$id'.log 2>/dev/null; true" > "$WORK/chunk"; then
      misses=0
      n=$(wc -c < "$WORK/chunk" | tr -d ' ')
      offset=$((offset + n))
      cat "$WORK/chunk"
    else
      misses=$((misses + 1))
      [ "$misses" -lt 12 ] || die "lost the VM while following job $id (scripts/lin-remote.sh attach $id)"
    fi
    rc="$(remote "cat ~/'$REMOTE_DIR'/.lin-jobs/'$id'.rc 2>/dev/null; true" 2>/dev/null || true)"
    if [[ "$rc" =~ ^[0-9]+$ ]]; then
      remote "tail -c +$((offset + 1)) ~/'$REMOTE_DIR'/.lin-jobs/'$id'.log 2>/dev/null; true" || true
      return "$rc"
    fi
    [ "$waited" -lt "$WAIT" ] || die "job $id: no exit code after $WAIT s (scripts/lin-remote.sh attach $id)"
    sleep 5
    waited=$((waited + 5))
  done
}

job() {
  local mode="$1" command="$2" id
  id="$(new_id)"
  start_job "$mode" "$id" "$command"
  follow "$id"
}

case "$1" in
  sync) sync ;;
  run)
    [ $# -eq 2 ] || die "run needs exactly one quoted command"
    sync
    job plain "$2"
    ;;
  run-nosync)
    [ $# -eq 2 ] || die "run-nosync needs exactly one quoted command"
    job plain "$2"
    ;;
  desktop)
    [ $# -eq 2 ] || die "desktop needs exactly one quoted command"
    sync
    job desktop "$2"
    ;;
  test)
    shift
    sync
    job plain "dbus-run-session -- cargo test --locked ${PACKAGES[*]} --lib --tests --no-fail-fast $*"
    ;;
  ignored)
    sync
    job plain "cargo test --locked ${PACKAGES[*]} --lib --tests -- --list --ignored 2>/dev/null | grep ': test\$' | sort"
    ;;
  attach)
    [ $# -eq 2 ] && [[ "$2" =~ ^j[0-9]{14}-[0-9]+$ ]] || die "attach needs a job id (j<timestamp>-<pid>)"
    follow "$2"
    ;;
  put)
    [ $# -eq 3 ] || die "put needs LOCAL NAME"
    [[ "$3" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ && ! "$3" =~ (^|/)\.\.(/|$) ]] || die "NAME: letters, digits, . _ - and /, no .."
    [ -e "$2" ] || die "not found: $2"
    if [ -n "$PRINT" ]; then echo "scp -r $2 -> $REMOTE_DIR/.linvpn-put/$3"; exit 0; fi
    remote "mkdir -p ~/'$REMOTE_DIR'/.linvpn-put/'$(dirname "$3")'"
    scp -q -r "${SSH_OPTS[@]}" "$2" "$SSH_DEST:$REMOTE_DIR/.linvpn-put/$3"
    ;;
  fetch)
    [ $# -eq 3 ] || die "fetch needs REMOTE_PATH LOCAL_DIR"
    [[ "$2" =~ ^[A-Za-z0-9._/-]+$ && ! "$2" =~ (^|/)\.\.(/|$) ]] || die "REMOTE_PATH: letters, digits, . _ / - only, no .."
    if [ -n "$PRINT" ]; then echo "scp -r $REMOTE_DIR/$2 -> $3"; exit 0; fi
    mkdir -p "$3"
    scp -q -r "${SSH_OPTS[@]}" "$SSH_DEST:$REMOTE_DIR/$2" "$3/"
    ;;
  *) die "unknown command: $1" ;;
esac
