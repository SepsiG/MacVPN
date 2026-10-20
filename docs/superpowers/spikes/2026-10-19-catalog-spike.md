# Team catalog spike (1.3.0, Task 1) – findings

Date: 2026-10-19. Machine: macOS 27.0.1, `/usr/bin/curl` 8.7.1 (`SecureTransport` + LibreSSL 3.3.6 multi-SSL build),
OpenSSL 3.5.9 (Homebrew `openssl@3`, the one `scripts/sign-release.sh` uses), Rust 1.99.1, `ed25519-dalek 3.0.0`.
The probes lived outside the repository (a scratch directory: a Python HTTPS test server, shell and Python probes,
a scratch crate); only this report is committed. Spec: `docs/superpowers/specs/2026-10-19-team-catalog-design.md`.
Plan: `docs/superpowers/plans/2026-10-19-team-catalog.md` Task 1.

**No external host was contacted.** Every HTTP probe ran against a local HTTPS server on `127.0.0.1:8443` with a
throwaway test CA passed to curl through `--cacert` (no keychain was changed). Parts B and D were decided from
documentation, the code and local APFS tests; the checks that need real shares, cloud providers or two running
apps are listed at the end for the maintainer.

## Summary of decisions

| Part | Decision |
|------|----------|
| A1 | **Our own conditional headers** (`If-None-Match` / `If-Modified-Since` from the validators in the vault) plus `--dump-header`; curl's `--etag-compare/--etag-save` files are not used. Confirmed working with `--max-redirs 0`. `--max-filesize 8388608` gives exit 63 in both cases (see A.4). |
| A2 | **The bearer token goes on stdin via `--config -`** with `-q` still the first argument. No conflict; the fallback (a 0600 config file) is not needed. The token never appears in `ps -ww -o args`. |
| B1 | **Always read the file and compare its SHA-256** with the last applied content hash. The `fstat` shortcut is **not used at all**: it cannot be verified on every provider here, and the local APFS test shows a case it misses (B.1). |
| B2 | Read timeout of `FileCatalogFetcher` **20 s** (on a worker thread, Task 10). "Unavailable" errnos: `ENOENT`, `ENOTDIR`, `ENXIO`, `EIO`, `EHOSTDOWN`, `EHOSTUNREACH`, `ENETDOWN`, `ENETUNREACH`, `ENETRESET`, `ECONNABORTED`, `ECONNRESET`, `ECONNREFUSED`, `ENOTCONN`, `ETIMEDOUT`, `ESTALE`, `EDEADLK`, `EAGAIN`. `ELOOP` and a non-regular file are `Io("not a regular file")`; everything else (`EACCES`, `EPERM`, …) is `Io`. |
| C | **Confirmed:** `SigningKey::from_bytes` from 32 `Entropy` bytes, no `rand` crate, `SigningKey` is `ZeroizeOnDrop`, OpenSSL 3 signatures verify. **One correction:** `VerifyingKey::from_bytes` accepts small-order keys, so `PublisherKey::from_bytes` must also refuse `is_weak()` keys. The successor-key header field is kept, with the rules in C.4. |
| D | **Sequential sandboxes** for the Task 19 smoke run (A publishes, quits; B subscribes, quits; A publishes v2; B refreshes). Two side-by-side instances share the webview data store of the bundle identifier (see D). |

## A. curl

Arguments used for every probe: the exact `CurlHttpClient::base_arguments` shape with the catalog user agent:

```
/usr/bin/curl -q --silent --show-error --proto =https --max-redirs 0 --connect-timeout 20 --max-time 60
              --user-agent MacVPN-Catalog/1.3.0 [--cacert <test CA>] … --write-out '%{http_code} %{redirect_url}' -- <url>
```

### A.1 Trust

- Without `--cacert`, the test server's certificate is refused with **exit 60** ("unable to get local issuer
  certificate"). That is the "certificate not trusted" mapping of Task 9.
- With `--cacert <test CA>` the same request succeeds (only for the probes; production never passes `--cacert`).

### A.2 The bearer token on stdin (`--config -`)

- `printf 'header = "Authorization: Bearer <token>"\n' | curl -q … --config - …` with `-q` first: the server
  received `Authorization: Bearer <token>` exactly (the test token used `.~+/=` characters of the `b64token` rule).
- `ps -ww -o args= -p <curl pid>` during a request held open for 3 s: the argument list ends in `--config -`, the
  token occurs **0 times**.
- `--config -` also works before `-q`, but `-q` must stay first (curl only honours it as the first argument), so
  the fetcher keeps `-q` first and puts `--config -` after the base arguments.
- `CommandRunner::run(…, stdin: Some(&line))` already writes stdin through the non-blocking runner; the line must be
  built in a `Zeroizing<String>`. The `b64token` rule (no `"` or `\`) means the line needs no escaping.

**Decision A2:** stdin via `--config -`. The 0600 config-file fallback is not needed.

### A.3 `--dump-header` and conditional GET

- With `--max-redirs 0`, the dump file holds **exactly one** response block per request (one status line), also
  for a 302 hop. Lines end in CRLF; the header names arrive as the server wrote them (`eTaG`, `last-modified` in the
  probe), so the parser must compare names case-insensitively and strip `\r`.
- `If-None-Match: "cat-v1"` → `304`, exit 0. `If-Modified-Since: <the Last-Modified value>` → `304`, exit 0. A
  stale `If-None-Match` → `200` with the body.
- **A `304` creates no `--output` file at all**; a `302` with `Content-Length: 0` creates an empty one. The fetcher
  must not use the existence of the body file as a signal: the status from `--write-out` decides, and a missing body
  file reads as empty.
- `--write-out '%{http_code} %{redirect_url}'` gives `304 ` and `302 https://127.0.0.1:8443/cat` (curl resolves the
  relative `Location` itself); our own `HttpsUrl::redirect_target` re-checks it anyway.

**Decision A1:** our own `If-None-Match` / `If-Modified-Since` headers from the vault's `SourceValidators` and
`--dump-header`. `--etag-save/--etag-compare` would put the validators in files and is not used.

### A.4 `--max-filesize 8388608`

- `Content-Length` above the cap (8 MiB + 1): **exit 63** ("Maximum file size exceeded") before any body is written;
  no output file exists.
- A chunked body that grows past the cap (the server tried to send 16 MiB): **exit 63** ("Exceeded the maximum
  allowed file size (8388608) with 8388608 bytes"); curl 8.7.1 aborts mid-transfer, and the output file holds
  exactly 8 388 608 bytes (the server had pushed about 10 MB into the socket by then). So the file never exceeds the
  cap; the reader's `take(cap + 1)` stays as a second guard.
- Mapping: exit 63 → `TooLarge`, whatever the body file holds.

### A.5 Redirects to `http://`

- `301 Location: http://…` with `--max-redirs 0`: curl does **not** follow; exit 0, `--write-out` reports `301
  http://127.0.0.1:8443/cat`. Our hop check (`redirect_target`) is what refuses it, before any request.
- The same with `-L --max-redirs 5`: exit 1, "Protocol "http" disabled (in redirect)".
- A direct `http://` URL: exit 1, "Protocol "http" disabled". So `--proto =https` is a second line of defence even
  if our own check were bypassed.

## B. File sources

### B.1 Local tests (APFS, the probe used the exact `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` open of Task 5)

| Case | Result |
|---|---|
| atomic replace (temp file + `rename`, as `exporter::write`) | inode and `mtime` change |
| in-place rewrite with the same size, then the old `mtime` restored (what a sync client that preserves the server time can do) | `(dev, ino, size, mtime_ns)` **unchanged** although the content differs |
| in-place rewrite with the same size | `mtime` changes (ns resolution on APFS) |
| symlink as the last component | `ELOOP` |
| FIFO | the open returns at once (0.000 s); `fstat` says not a regular file |
| directory | the open succeeds; `fstat` says not a regular file (so the regular-file check is required) |
| `/Volumes/<missing share>/x.macvpncatalog` | `ENOENT` |
| missing parent directory | `ENOENT` |
| a regular file used as a directory | `ENOTDIR` |
| symlink in a middle component | allowed (only the last component is `O_NOFOLLOW`) |

### B.2 Providers (documentation; manual checks below)

- **SMB / NFS / AFP:** a mounted share whose server goes away keeps the mount; `open`/`read` block until the
  client times out (SMB: tens of seconds and more; a hard NFS mount can hang indefinitely). The errors seen after the
  time-out are typically `ETIMEDOUT`, `EHOSTDOWN`, `ENOTCONN`, `EIO`, or `ESTALE` for NFS. An unmounted share is just a
  missing directory under `/Volumes` (`ENOENT`). Server-side `mtime` granularity and caching differ per server, so
  `fstat` stamps are not trustworthy there.
- **iCloud Drive, OneDrive, Dropbox** (all on the File Provider framework on current macOS): an evicted or
  online-only file is a *dataless* file. Opening it for reading materializes it: the `open`/`read` blocks while it
  downloads, and fails when it cannot be downloaded (offline). A process whose materialization policy is off gets
  `EDEADLK`. During a download the provider replaces the file, and the provider may set `mtime` to the server time,
  so a stamp can stay equal across a content change or change without one.

**Decision B1:** always read (≤ 8 MB) and compare the SHA-256 with the last applied `content_hash`. The `fstat`
shortcut is **not** used on any provider: it could not be verified on every provider, and the local test already
shows a content change it misses.

**Decision B2:** the read runs on a worker thread with a **20 s** timeout (Task 10; at most one hung read per
path). The errnos listed in the summary table mean `Unavailable(<file name>)` (shown as "unavailable", no error
notification). `EIO` is counted as unavailable because network file systems report a lost server that way; on a
local disk it is rare and the status line still shows it. `EAGAIN` covers a non-blocking open of a file whose
provider is busy.

## C. Ed25519 signing and rotation

### C.1 Signing without `rand`

- `SigningKey::from_bytes(&[u8; 32])` from 32 `FixedEntropy` bytes; `sign` (the `Signer` trait re-exported by
  `ed25519-dalek`) and `verify_strict` work; a flipped message byte fails.
- Known-answer from `FixedEntropy::new(7)`: seed `e8dd943d…c31bdf2eec1`, public key `95e19a2555f7f773…3e7bfed68e`.
- `Cargo.lock` has no `rand*` package; `cargo tree -i rand_core` for `macvpn-core --features vault` finds none. The
  default features are `fast` and `zeroize`; `rand_core` is only pulled in by the `batch`/`rand_core` features, which
  the workspace does not enable.

### C.2 Zeroization

- `SigningKey` implements `Drop` and `ZeroizeOnDrop` with the default `zeroize` feature (checked at compile time
  with a `T: ZeroizeOnDrop` bound). `AdminKey` wraps it without `Clone`; `seed()` returns a `Zeroizing<[u8; 32]>`.
- `SigningKey`'s own `Debug` prints only the verifying key; `AdminKey` gets a fully redacted `Debug` anyway.

### C.3 Small-order public keys

- `VerifyingKey::from_bytes` **accepts** the identity point (`01 00 … 00`); `is_weak()` is true and `verify_strict`
  refuses every signature. `PublisherKey::from_bytes` therefore also refuses `is_weak()` keys (Task 2), so such a key
  can never be pinned or announced as a successor.

### C.4 OpenSSL interop and the successor scheme

- The seed wrapped as PKCS#8 (`302e020100300506032b657004220420 ‖ seed`) imports into OpenSSL 3; the derived public
  key equals dalek's, `pkeyutl -sign -rawin` gives a **byte-identical** signature (Ed25519 is deterministic), it
  passes `verify_strict`, and OpenSSL verifies dalek's signature. A catalog can later be signed offline the same way
  as `scripts/sign-release.sh` signs releases.
- **Decision C:** the header field `successor_key` (covered by the catalog signature, so the current key signs the
  announcement) is kept. Review notes for Tasks 4, 11 and 14:
  - The announcement is stored only from a catalog that passed every check (signature, catalog id, newer version,
    decryption, validation), never from a refused one.
  - Once a catalog signed by the successor has been applied, the subscriber re-pins: the successor becomes the
    pinned key and the old key is no longer accepted. Without this, a leaked old key (the usual reason to rotate)
    could still sign newer versions.
  - A later catalog signed by the current key may announce a different successor (the admin replaced the backup
    key); the stored successor is replaced. This is inherent to any scheme signed by the current key: a leaked
    current key can announce an attacker's successor, and a separately signed announcement would not change that.
  - The successor must differ from the header key and pass the small-order check.
  - The catalog signature domain (`macvpn-catalog-v1\n`) differs from the update signature domain
    (`macvpn-update-v1\n`), so a catalog signature can never be replayed as an update signature or back.

## D. Two sandboxes (code reading)

- `MACVPN_SANDBOX_HOME` moves the store, ranking, system OTP file and staging directory under the sandbox, with an
  in-memory keychain and in-memory preferences (`app/src-tauri/src/platform.rs`, `main.rs`). So data, Keychain and
  preferences do not collide.
- There is no single-instance lock in the app (no plugin, no lock file).
- This branch has no control API socket yet (the 1.2 `control-api` merge is not in the `catalog` base used here); when
  it arrives, its socket path under the sandbox home must be checked.
- Both instances use the bundle identifier `local.macvpn`, so the WKWebView data store (local storage of the UI) is
  shared, and both put an icon in the menu bar. Side-by-side runs would therefore share UI state.

**Decision D:** the Task 19 smoke run uses the two sandboxes **sequentially**.

## Manual checks for the maintainer

Run these on the maintainer's Mac and add the results here; none of them changes a decision unless noted.

1. **SMB:** put a catalog file on an SMB share, mount it, note `stat -f '%d %i %z %m' <file>`; replace it from
   another Mac (atomic rename) and note again; then unplug the server's network and time
   `python3 -c 'import os;os.open("<file>", os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)'` and a `cat`. Record the errno
   and the time. If it exceeds 20 s, the timeout in Task 10 does its job; if the errno is not in the B2 list, add it.
2. **NFS or AFP** if available: as 1.
3. **iCloud Drive:** a catalog file, "Remove Download" in Finder, then the same `open` online (blocks while it
   downloads? how long?) and offline (which errno?).
4. **OneDrive and Dropbox:** an online-only file, the same as 3.
5. **Two apps side by side** (only if a parallel smoke run is wanted later): two debug builds with different
   `MACVPN_SANDBOX_HOME` values; check the menu-bar icons, the webview state and, once the control API is merged, the
   socket path.
6. **Live HTTPS:** the `#[ignore]` test of Task 9 against `MACVPN_CATALOG_TEST_URL` (an HTTPS host the maintainer
   controls), once with a valid certificate and once with an `http://` redirect configured on the server.
