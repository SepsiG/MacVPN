#!/bin/bash
# Runs the working tree on the Windows test machine over SSH (docs/architecture.md, "The Windows test machine").
#
#   scripts/win-remote.sh sync                       copy HEAD + uncommitted changes of tracked files there
#   scripts/win-remote.sh run 'COMMAND'              sync, then COMMAND in the remote checkout (Git Bash)
#   scripts/win-remote.sh run-nosync 'COMMAND'       COMMAND in the remote checkout as it is (no sync; polling)
#   scripts/win-remote.sh test [EXTRA CARGO ARGS]    sync, then the CI windows job's test set
#   scripts/win-remote.sh ignored                    sync, then list the tests ignored on Windows
#   scripts/win-remote.sh msi [BUILD-MSI ARGS]       sync, then scripts/build-msi.sh without ICE validation
#   scripts/win-remote.sh fetch REMOTE_PATH LOCAL_DIR   copy a build product back (relative to the checkout)
#
# Environment: WINVPN_SSH (ssh destination user@host, required), WINVPN_REMOTE_DIR (default "winvpn-work",
# one folder name in the remote home). The remote account is a standard user: nothing here needs administrator rights.
# Commands run with CI=1 (as the CI windows job), except `msi`: an SSH session cannot reach the Windows Installer
# service, so it runs build-msi.sh with WINVPN_WIX_NO_ICE=1, which build-msi.sh refuses whenever CI is set (CI
# validates the MSI). WINVPN_REMOTE_PRINT=1 prints the remote commands instead of running them (scripts/test-win-remote.sh).
# Nothing secret is sent: the bundle holds only the repository's tracked content.
set -euo pipefail
cd "$(dirname "$0")/.."

SSH_DEST="${WINVPN_SSH:-}"
# No forwarding whatever ~/.ssh/config says: the VM runs unreviewed builds, which must never reach this Mac's agent.
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes -o LogLevel=ERROR -o ForwardAgent=no -o ForwardX11=no
  -o ClearAllForwardings=yes -i "$HOME/.ssh/winvpn_dev"
  -o UserKnownHostsFile="$HOME/.ssh/winvpn_known_hosts")
GIT_BASH='"C:\Program Files\Git\bin\bash.exe"'
REMOTE_DIR="${WINVPN_REMOTE_DIR-winvpn-work}"
# Refs are shared by every worktree of the repository: one ref per run, so parallel runs never clobber each other.
REF="refs/winvpn/sync-$$"

die() { echo "error: $*" >&2; exit 1; }

[ $# -ge 1 ] || { sed -n '4,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[ -n "$SSH_DEST" ] || die "set WINVPN_SSH=user@host of the Windows test machine"
# One folder name directly in the remote home: never empty, absolute, nested, `.`, `..` or hidden (`git clean -fdx`
# runs in it, so `.` would wipe the home and `.ssh` the harness's own key).
[[ "$REMOTE_DIR" =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]*$ ]] || die "WINVPN_REMOTE_DIR: one folder name (letters, digits, . _ -; not starting with .)"

# The CI windows job's packages plus the ones phase 2 adds; a package whose crate does not exist yet is left out.
PACKAGES=()
for pkg_dir in macvpn-core:crates/core macvpn-app-core:crates/app-core macvpn-platform-api:crates/platform-api \
  macvpn-platform-win:crates/platform-win macvpn-helper:crates/helper macvpn-winsys:crates/winsys \
  macvpn-control-client:examples/macvpn-control-client; do
  if [ -f "${pkg_dir#*:}/Cargo.toml" ]; then PACKAGES+=(-p "${pkg_dir%%:*}"); fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/winvpn-remote.XXXXXXXX")"
cleanup() { rm -rf "${WORK:?}"; git update-ref -d "$REF" 2>/dev/null || true; }
trap cleanup EXIT

# The remote default shell is cmd.exe (OpenSSH's default; not changed): every command runs in Git Bash explicitly.
# The command is passed base64-encoded so neither cmd.exe nor bash re-quotes it. It is one `{ …; }` group read whole
# before it runs, with stdin from /dev/null: a remote program that reads stdin never eats the rest of the script.
remote() {
  local b64
  if [ -n "${WINVPN_REMOTE_PRINT:-}" ]; then
    printf '%s\n' "$*"
    return
  fi
  b64="$(printf '{ %s\n} </dev/null\n' "$*" | base64 | tr -d '\n')"
  # shellcheck disable=SC2029 # expanded locally on purpose: the base64 text is the whole command
  ssh -n "${SSH_OPTS[@]}" "$SSH_DEST" "$GIT_BASH -lc \"echo $b64 | base64 -d | bash\""
}
# The remote shell is Git Bash: one login shell per command, the checkout as the working directory, the Perl that
# openssl-src needs (the CI job's OPENSSL_SRC_PERL).
in_checkout() {
  remote "set -o pipefail && cd ~/'$REMOTE_DIR' && export OPENSSL_SRC_PERL='C:\\Strawberry\\perl\\bin\\perl.exe' CI=1 && $1"
}
# The same without CI (only for `msi`).
in_checkout_without_ci() {
  remote "set -o pipefail && cd ~/'$REMOTE_DIR' && unset CI && export OPENSSL_SRC_PERL='C:\\Strawberry\\perl\\bin\\perl.exe' && $1"
}

sync() {
  local rev tree
  # A snapshot commit of the tracked files as they are on disk, made in a copy of the index (the real index and the
  # stash stay untouched). Not `git stash create`: it refuses a file added with `git add -N`.
  cp "$(git rev-parse --git-path index)" "$WORK/index"
  tree="$(GIT_INDEX_FILE="$WORK/index" git add -u && GIT_INDEX_FILE="$WORK/index" git write-tree)" \
    || die "could not snapshot the working tree"
  if [ "$tree" = "$(git rev-parse 'HEAD^{tree}')" ]; then
    rev="$(git rev-parse HEAD)"
  else
    rev="$(git commit-tree --no-gpg-sign "$tree" -p HEAD -m "win-remote: uncommitted changes on $(git rev-parse --short HEAD)")"
  fi
  git update-ref "$REF" "$rev"
  git bundle create "$WORK/sync.bundle" "$REF" >/dev/null 2>&1 || die "git bundle failed"
  if [ -n "${WINVPN_REMOTE_PRINT:-}" ]; then
    echo "(print only: nothing is synced)"
    return
  fi
  remote "mkdir -p ~/'$REMOTE_DIR' && cd ~/'$REMOTE_DIR' && { [ -d .git ] || git init -q; } && git config core.autocrlf false"
  scp -q "${SSH_OPTS[@]}" "$WORK/sync.bundle" "$SSH_DEST:$REMOTE_DIR/.sync.bundle"
  # MSYS_NO_PATHCONV: Git Bash would turn `/target` into `C:/Program Files/Git/target` and the build cache would go.
  in_checkout "git fetch -q .sync.bundle '$REF' && git checkout -q --force --detach FETCH_HEAD \
    && MSYS_NO_PATHCONV=1 git clean -q -fdx -e /target -e node_modules -e /dist && rm -f .sync.bundle && git log -1 --format='synced %h %s'"
}

case "$1" in
  sync) sync ;;
  run)
    [ $# -eq 2 ] || die "run needs exactly one quoted command"
    sync
    in_checkout "$2"
    ;;
  run-nosync)
    [ $# -eq 2 ] || die "run-nosync needs exactly one quoted command"
    in_checkout "$2"
    ;;
  test)
    shift
    sync
    in_checkout "cargo test --locked --target x86_64-pc-windows-msvc ${PACKAGES[*]} --lib --tests --no-fail-fast $*"
    ;;
  msi)
    shift
    for arg in "$@"; do
      [[ "$arg" =~ ^[A-Za-z0-9-]+$ ]] || die "msi: build-msi.sh options are letters, digits and - only: $arg"
    done
    sync
    echo "msi: WINVPN_WIX_NO_ICE=1 without CI: ICE validation is skipped here (the Windows Installer service cannot be reached over SSH); CI validates the MSI"
    in_checkout_without_ci "WINVPN_WIX_NO_ICE=1 scripts/build-msi.sh $*"
    ;;
  ignored)
    sync
    in_checkout "cargo test --locked --target x86_64-pc-windows-msvc ${PACKAGES[*]} --lib --tests -- --list --ignored 2>/dev/null | grep ': test\$' | sort"
    ;;
  fetch)
    [ $# -eq 3 ] || die "fetch needs REMOTE_PATH LOCAL_DIR"
    [[ "$2" =~ ^[A-Za-z0-9._/-]+$ && ! "$2" =~ (^|/)\.\.(/|$) ]] || die "REMOTE_PATH: letters, digits, . _ / - only, no .."
    mkdir -p "$3"
    scp -q -r "${SSH_OPTS[@]}" "$SSH_DEST:$REMOTE_DIR/$2" "$3/"
    ;;
  *) die "unknown command: $1" ;;
esac
