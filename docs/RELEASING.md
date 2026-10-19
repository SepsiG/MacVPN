# Releasing MacVPN

This is the maintainer's procedure for publishing a release, and the repository settings the in-app updater relies on.

## How the updater finds releases

- The app asks `https://api.github.com/repositories/1422472799/releases/latest`. `1422472799` is the immutable numeric ID of `SepsiG/MacVPN`, stored as `MacVPNUpdateRepoID` in `app/src-tauri/Info.plist`, which the Tauri bundler merges into `MacVPN.app/Contents/Info.plist` (`scripts/build-dmg.sh` checks the result). A renamed, deleted and re-created, or transferred repository with the same name cannot serve updates (repo-jacking). Without a valid ID the app does not check for updates.
- `MacVPNUpdateRepo` (`SepsiG/MacVPN`) is used for the Help links and to check asset URLs: the DMG, its `.sha256` and its `.sig` are accepted only from `https://github.com/SepsiG/MacVPN/releases/download/<tag>/<file name>`.
- Both values are set statically in `app/src-tauri/Info.plist`. The release workflow does not rewrite them; it fails if they do not match `github.repository_id` and `github.repository`. If the repository is ever moved, update both keys in a normal commit.
- The release must contain `MacVPN-X.Y.Z.dmg`, `MacVPN-X.Y.Z.dmg.sha256` and `MacVPN-X.Y.Z.dmg.sig`, and the tag must be `vX.Y.Z`. Users can opt in to a 24-hour delay, so a broken release can still be pulled before it reaches them.

## Offline signing (from 0.2.2)

Goal: even if the maintainer's GitHub account (or CI) is compromised, no update can be pushed to apps running 0.2.2 or later. Every update must carry an Ed25519 signature made with an offline key that only the maintainer holds.

- **Signed message** (exact bytes): `"macvpn-update-v1\n" + X.Y.Z + "\n" + sha256hex + "\n"`, where the version has no `v` and the SHA-256 of the DMG is lowercase hex. Pure Ed25519 (OpenSSL 3 `pkeyutl -sign -rawin`).
- **Asset:** `MacVPN-X.Y.Z.dmg.sig`, one line: the base64 of the 64-byte signature and a newline (max 1 KB).
- **In the app** (`crates/core/src/update.rs`, `UpdateSignature::PRIMARY_PUBLIC_KEY_BASE64` / `BACKUP_PUBLIC_KEY_BASE64`; the same keys as in 0.2.2–0.4.0): two raw 32-byte public keys, base64: primary `KfHXY5gQkjMA3e8bx8rIuPQ4x3zCuSJoMo3PYcMgbFk=` and backup `QUFfsn9koh06k4EX9lNPognIvQ84/Ox6lgZhShvVrmI=`. A signature by either is accepted. The updater verifies it against the SHA-256 it computes itself from the downloaded DMG (not just the `.sha256` file). A newer release without a `.sig` asset is not offered (**Check for Updates Now** says "Update waiting for signature"); a missing or invalid signature at install time stops the update with "The update is not signed by the MacVPN maintainer".
- **Older apps:** 0.2.1 and older do not check signatures. They install 0.2.2+ releases as before (the extra asset does not matter to them), but they are only protected by HTTPS and the SHA-256 from the same release.
- `scripts/sign-release.sh` reads the public keys from the Rust core source (`crates/core/src/update.rs`), so there is a single copy; `scripts/test-sign-release.sh` and the unit tests (`cargo test`, `sign_release_uses_the_embedded_keys`) check that both sides agree, and that the keys are still the ones the released 0.4.0 app embeds (`git show v0.4.0:…`).

### Key storage

- **Primary private key:** in the maintainer's login Keychain, as a generic password: service `MacVPN release signing`, account `primary`; the value is the base64 of the PEM. It was added with `-T /usr/bin/security`, so only `security` can read it without a prompt. `sign-release.sh` reads it through a process substitution (`-inkey <(security find-generic-password … -w | base64 -d)`): the PEM never touches the disk and is never printed.
- **Backup private key:** a PEM file kept offline in the password manager, **not** on the Mac. Use it only with `--backup-key <file>` (from a temporary location that you delete afterwards), e.g. if the Mac with the primary key is lost.
- Neither key is ever given to GitHub, CI or any other service. CI only creates a draft.

### If a key is lost or compromised

- **Primary lost** (Mac lost or wiped, Keychain item gone), not compromised: sign releases with `--backup-key` from the password manager. In the next release, generate a new primary key pair offline, put its public key in place of the old primary in `crates/core/src/update.rs`, and sign that release with the backup key (every app that has the old key set accepts it). From then on sign with the new primary.
- **Primary compromised** (someone else may have the private key): act at once. Generate a new primary key pair offline, replace the compromised public key in `crates/core/src/update.rs`, and publish a new release signed with the **backup** key. Until users install it, the attacker can sign updates for them, so also secure the GitHub account (a compromised key alone is not enough: the attacker also needs to publish a release on GitHub). Announce the incident.
- **Backup lost or compromised:** generate a new backup key pair, replace the backup public key in `crates/core/src/update.rs`, and sign that release with the primary key. If it was compromised, treat it like a compromised primary.
- **Both keys lost:** apps 0.2.2+ can no longer be updated in-app. Publish a release with new keys and tell users to install it manually from the DMG (after verifying it through another channel).
- Never generate keys in CI, and never commit a private key. Generate key pairs with OpenSSL 3: `openssl genpkey -algorithm ed25519 -out key.pem`, raw public key for the app: `openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64`.

## Release procedure

The flow is: **tag → CI builds a draft → `scripts/sign-release.sh vX.Y.Z` on the maintainer's Mac → published.**

1. Merge everything for the release into `main`. CI (`.github/workflows/ci.yml`) must be green.
2. If the root layer (`crates/mvpn`) changed, bump `crates/mvpn/VERSION`. Set the version (`X.Y.Z`) in `app/src-tauri/tauri.conf.json`, in `[workspace.package]` of `Cargo.toml` (then `cargo check` to update `Cargo.lock`) and in `app/ui/package.json` (`npm install --package-lock-only` updates the lock file). The three must agree (`scripts/build-dmg.sh` fails otherwise) and equal the tag (the workflow fails otherwise; it no longer rewrites the version). Before tagging, run the local-only checks: the smoke test in both languages (`SMOKE_LANG=en scripts/smoke-manage.sh`, `SMOKE_LANG=hu scripts/smoke-manage.sh`, see `app/README.md`) and `docs/manual-test-checklist.md`.
3. Tag the commit on `main` and push the tag:
   ```
   git checkout main && git pull
   git tag -s vX.Y.Z -m "MacVPN vX.Y.Z"   # or -a if you do not sign tags
   git push origin vX.Y.Z
   ```
4. `.github/workflows/release.yml` runs:
   - **build** job (`contents: read`, no persisted credentials): checks the tag format (`vX.Y.Z`), checks that the tagged commit is an ancestor of `origin/main`, checks the update source keys, checks that the version in `tauri.conf.json` equals the tag, runs `cargo test` (debug and release), `MVPN_IMPL=rust scripts/test-root.sh` and the UI tests (`npm ci`, `npm test`), builds the universal DMG with `scripts/build-dmg.sh` (UI build, `tauri build`, the release gate against debug-only code, the app and `mvpn` signed ad-hoc with the hardened runtime and no entitlements, Info.plist checks), checks the finished bundle again (repository ID, version, bundle ID, `codesign --verify --strict`), writes the `.sha256` (printed in the "SHA-256" step log), and uploads both as a workflow artifact.
   - **release** job (`contents: write`): downloads the artifact, re-checks the checksum, and runs `gh release create --draft --repo "$GITHUB_REPOSITORY" --verify-tag`. It does not check out or run repository code, and it never creates the `.sig`: CI must never hold the signing key.
   The result is a **draft** release with the DMG and the `.sha256`. Users do not see it yet.
5. On the maintainer's Mac (needs OpenSSL 3: `brew install openssl@3`; `jq` and `curl` ship with macOS; a GitHub credential for `github.com` in the git credential helper, with write access to releases):
   **Before you sign**, compare the draft's DMG with a local build of the same tag, so that a tampered CI build is not signed:
   ```
   git checkout vX.Y.Z && scripts/build-dmg.sh          # local: dist/MacVPN.app
   # download MacVPN-X.Y.Z.dmg from the draft into a temporary directory, then:
   hdiutil attach -nobrowse -readonly -mountpoint /tmp/macvpn-draft MacVPN-X.Y.Z.dmg
   D=/tmp/macvpn-draft/MacVPN.app; L=dist/MacVPN.app
   codesign -dv "$D" 2>&1 | grep -E 'Identifier|flags'    # local.macvpn, flags=0x10002(adhoc,runtime)
   codesign -d --entitlements - --xml "$D" 2>/dev/null     # empty: no entitlements
   codesign --verify --strict --deep --verbose=2 "$D"
   diff <(plutil -convert xml1 -o - "$D/Contents/Info.plist") <(plutil -convert xml1 -o - "$L/Contents/Info.plist")
   for a in arm64 x86_64; do
     for app in "$D" "$L"; do lipo -thin $a "$app/Contents/Resources/root/mvpn" -output /tmp/mvpn-$a && shasum -a 256 /tmp/mvpn-$a; done
   done
   cmp "$D/Contents/Resources/root/VERSION" "$L/Contents/Resources/root/VERSION"
   hdiutil detach /tmp/macvpn-draft
   ```
   The Info.plist must be identical, both bundles signed with the hardened runtime (`runtime` in the flags) and no entitlements, and the root binary `mvpn` (the part that runs as root) must have the same SHA-256 per architecture. The builds are not bit-for-bit reproducible across machines when the toolchain or the build paths differ (they are embedded in the binaries), so build locally with the pinned toolchain (`rust-toolchain.toml`) and the Node version of the workflows (26.8.2); if a hash still differs, do not sign until the difference is explained.
   Then sign and publish:
   ```
   scripts/sign-release.sh vX.Y.Z
   ```
   It validates the tag, gets the token from `git credential fill` (never printed, only used in curl `Authorization` headers), finds the draft release for the tag (refuses a published one), downloads the DMG and `.sha256` into a temporary directory, computes the SHA-256 locally and compares it with the `.sha256` asset, and **prints the hash: compare it with the "SHA-256" step of the workflow log**. After you answer `y` to "Sign and publish vX.Y.Z? [y/N]", it signs with the primary key from the Keychain (macOS may ask for the login Keychain password), verifies the signature against the embedded public keys, uploads `MacVPN-X.Y.Z.dmg.sig`, publishes the release (`draft=false`, `make_latest=true`) and prints its URL.
   - With the backup key: `scripts/sign-release.sh --backup-key /path/to/backup.pem vX.Y.Z`.
   - To fix the signature of an already published release: `--republish-sig` (deletes and re-uploads the `.sig`). With immutable releases on, published assets cannot be changed; publish a new patch release instead.
   - To test the setup without network: `scripts/sign-release.sh --dry-run --dmg some-file vX.Y.Z` signs the file with the Keychain key and verifies it against the embedded keys (add `--backup-key file` to test a key file). `scripts/test-sign-release.sh` runs the same with a throwaway key.
6. Check the release page: the three assets are present, and the notes mention offline signing and the Gatekeeper and Keychain steps. Optionally run **Check for Updates Now** in an older 0.2.2+ app.
7. If a release turns out to be broken or suspicious, delete it (or mark a newer fixed one as latest) quickly; users with the 24-hour delay will not have been offered it yet. A draft that should not be released can simply be deleted.

All actions are pinned to full commit SHAs with a `# vX.Y.Z` comment. Dependabot (`.github/dependabot.yml`) proposes updates weekly; review the upstream diff before merging such a PR.

## Repository settings (not code)

These protect the release channel and must be set in the GitHub UI by the account owner:

- **Two-factor authentication with a hardware security key** (passkey / FIDO2) on the owner account; remove SMS as a fallback. Whoever controls this account can publish an update to users of 0.2.1 and older (0.2.2 and later also require the offline signature, see above).
- **Immutable releases** (Settings → General → Releases): published release assets and their tags cannot be changed or replaced afterwards.
- **Tag protection ruleset** (Settings → Rules → Rulesets) for `refs/tags/v*`: restrict creation, update and deletion to the maintainer, and block force pushes. Optionally require signed tags.
- **Branch protection / ruleset for `main`**: no force pushes or deletion, require the CI check, since the release job only accepts tags on `main`.
- **Actions settings**: default `GITHUB_TOKEN` permissions set to read-only; allow only GitHub-owned actions (the workflows use nothing else).
