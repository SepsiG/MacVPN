# Releasing MacVPN

This is the maintainer's procedure for publishing a release, and the repository settings the in-app updater relies on.

## How the updater finds releases

- The app asks `https://api.github.com/repositories/1422472799/releases/latest`. `1422472799` is the immutable numeric ID of `SepsiG/MacVPN`, stored in `Resources/Info.plist` as `MacVPNUpdateRepoID`. A renamed, deleted and re-created, or transferred repository with the same name cannot serve updates (repo-jacking). Without a valid ID the app does not check for updates.
- `MacVPNUpdateRepo` (`SepsiG/MacVPN`) is used for the Help links and to check asset URLs: the DMG and its `.sha256` are accepted only from `https://github.com/SepsiG/MacVPN/releases/download/<tag>/<file name>`.
- Both values are set statically in `Info.plist`. The release workflow does not rewrite them; it fails if they do not match `github.repository_id` and `github.repository`. If the repository is ever moved, update both keys in a normal commit.
- The release must contain `MacVPN-X.Y.Z.dmg` and `MacVPN-X.Y.Z.dmg.sha256`, and the tag must be `vX.Y.Z`. Users can opt in to a 24-hour delay, so a broken release can still be pulled before it reaches them.

## Release procedure

1. Merge everything for the release into `main`. CI (`.github/workflows/ci.yml`) must be green.
2. If the root scripts changed, bump `Resources/root/VERSION`.
3. Tag the commit on `main` and push the tag:
   ```
   git checkout main && git pull
   git tag -s vX.Y.Z -m "MacVPN vX.Y.Z"   # or -a if you do not sign tags
   git push origin vX.Y.Z
   ```
4. `.github/workflows/release.yml` runs:
   - **build** job (`contents: read`, no persisted credentials): checks the tag format (`vX.Y.Z`), checks that the tagged commit is an ancestor of `origin/main`, checks the update source keys, sets the version from the tag, runs `swift test` and `scripts/test-root.sh`, builds the DMG with `scripts/build-dmg.sh`, writes the `.sha256`, and uploads both as a workflow artifact.
   - **release** job (`contents: write`): downloads the artifact, re-checks the checksum, and runs `gh release create --repo "$GITHUB_REPOSITORY" --verify-tag`. It does not check out or run repository code.
   The release is published immediately (not a draft).
5. Check the release page: both assets are present, and the notes mention the Gatekeeper and Keychain steps.
6. If a release turns out to be broken or suspicious, delete it (or mark a newer fixed one as latest) quickly; users with the 24-hour delay will not have been offered it yet.

All actions are pinned to full commit SHAs with a `# vX.Y.Z` comment. Dependabot (`.github/dependabot.yml`) proposes updates weekly; review the upstream diff before merging such a PR.

## Repository settings (not code)

These protect the release channel and must be set in the GitHub UI by the account owner:

- **Two-factor authentication with a hardware security key** (passkey / FIDO2) on the owner account; remove SMS as a fallback. Whoever controls this account can publish an update to every user.
- **Immutable releases** (Settings → General → Releases): published release assets and their tags cannot be changed or replaced afterwards.
- **Tag protection ruleset** (Settings → Rules → Rulesets) for `refs/tags/v*`: restrict creation, update and deletion to the maintainer, and block force pushes. Optionally require signed tags.
- **Branch protection / ruleset for `main`**: no force pushes or deletion, require the CI check, since the release job only accepts tags on `main`.
- **Actions settings**: default `GITHUB_TOKEN` permissions set to read-only; allow only GitHub-owned actions (the workflows use nothing else).

## Possible future step: offline signing key

Today a release is trusted because it comes from this repository over HTTPS with a matching SHA-256, so a compromised GitHub account could still publish a malicious update. A stronger option is to sign each release (for example the `.sha256` file with a minisign or Ed25519 key kept offline) and embed the public key in the app, so the updater rejects anything not signed with that key. This is not implemented yet; the maintainer will decide on it separately.
