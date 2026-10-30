#!/usr/bin/env node
// Generates THIRD-PARTY-NOTICES.txt (repo root) from what the release bundles: the SQLCipher notice and the SQLite
// public-domain note, then every Rust crate linked into the app or mvpn (normal dependencies, both macOS targets,
// from `cargo metadata --locked`, without the crates only a Windows build brings in) and every JS package bundled into the web view (the UI's runtime dependencies and
// the Svelte runtime), each with its licence expression and the licence files it ships (LICENSE*, LICENCE*, COPYING*,
// NOTICE*), read from ~/.cargo/registry and app/ui/node_modules. Identical texts are printed once, after the list of
// the packages that ship them. Sorted throughout and free of local paths, so every machine produces the same file.
//
//   node scripts/third-party-notices.mjs           writes THIRD-PARTY-NOTICES.txt
//   node scripts/third-party-notices.mjs --check   exits 1 when the committed file is not what it would write
//   --os windows                                    THIRD-PARTY-NOTICES.windows.txt instead (WinVPN's MSI installs it
//                                                   as THIRD-PARTY-NOTICES.txt): the app and the WinVPN Service (the
//                                                   helper crate), the two Windows targets, OpenSSL's licence too (the
//                                                   vendored OpenSSL 3 under SQLCipher is linked into WinVPN.exe), and
//                                                   wireguard-nt's prebuilt-binaries licence (wireguard.dll ships in the
//                                                   MSI; scripts/notices/wireguard-nt-LICENSE.txt, the LICENSE.txt of
//                                                   the zip pinned in scripts/pins/wireguard-nt.txt)
//   --os linux                                      THIRD-PARTY-NOTICES.linux.txt instead (LinVPN's .deb installs it as
//                                                   /usr/share/doc/linvpn/THIRD-PARTY-NOTICES.txt): the app and the
//                                                   helper crate's binaries (linvpn-install-update, linvpn-logd), the
//                                                   two Linux targets, OpenSSL's licence too (the vendored OpenSSL 3
//                                                   under SQLCipher is linked into linvpn), LinVPN's NetworkManager
//                                                   OpenVPN service (GPL-2.0-or-later, its source in the .deb), no
//                                                   wireguard-nt
//
// Each OS's list leaves out only the crates that just the other OSes' builds bring in (`cargo tree` per target). It is
// not filtered further by per-target features: `cargo metadata` unifies features across targets, so a list may name a
// crate that only another OS's features pull in (the Windows list names tracing-attributes, which zbus' tracing brings
// on Linux). Listing a notice too many is harmless; `cargo tree` alone is no better list (it also shows what proc
// macros use on the build host, such as swift-rs for Windows), and filtering by it would rewrite the shipped MacVPN and
// WinVPN files.
//
// Needs the crate sources (`cargo fetch --locked`) and app/ui/node_modules (`npm ci`).
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const UI = join(ROOT, 'app', 'ui');
const MACOS_TARGETS = ['aarch64-apple-darwin', 'x86_64-apple-darwin'];
const WINDOWS_TARGETS = ['x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc'];
const LINUX_TARGETS = ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'];

function usage(message) {
  console.error(`${message} (usage: third-party-notices.mjs [--os macos|windows|linux] [--check])`);
  process.exit(2);
}
let OS = 'macos';
let CHECK = false;
for (let args = process.argv.slice(2); args.length > 0; args = args.slice(1)) {
  if (args[0] === '--check') CHECK = true;
  else if (args[0] === '--os') {
    if (!['macos', 'windows', 'linux'].includes(args[1])) usage('--os needs macos, windows or linux');
    OS = args[1];
    args = args.slice(1);
  } else usage(`unknown option: ${args[0]}`);
}
const WINDOWS = OS === 'windows';
const LINUX = OS === 'linux';
// SQLCipher's crypto provider is the vendored OpenSSL 3 on Windows and Linux (CommonCrypto on macOS).
const VENDORED_OPENSSL = WINDOWS || LINUX;
const PRODUCT = WINDOWS ? 'WinVPN' : LINUX ? 'LinVPN' : 'MacVPN';
const OUT_NAME = WINDOWS ? 'THIRD-PARTY-NOTICES.windows.txt' : LINUX ? 'THIRD-PARTY-NOTICES.linux.txt' : 'THIRD-PARTY-NOTICES.txt';
const OUT = join(ROOT, OUT_NAME);
const ROOT_PACKAGES = ['macvpn-app', 'macvpn-helper'];
const TARGETS = WINDOWS ? WINDOWS_TARGETS : LINUX ? LINUX_TARGETS : MACOS_TARGETS;
// macOS and Windows keep their earlier comparison (each against the other), so their files stay as shipped.
const OTHER_TARGETS = WINDOWS ? MACOS_TARGETS : LINUX ? [...MACOS_TARGETS, ...WINDOWS_TARGETS] : WINDOWS_TARGETS;
const LICENSE_FILE = /^(licen[cs]e|copying|notice)([-._].*)?$/i;
const RULE = '='.repeat(100);

/// The licence files at the top of a package directory, sorted by name: [name, normalized text].
function licenseFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => LICENSE_FILE.test(name) && statSync(join(dir, name)).isFile())
    .sort()
    .map((name) => [name, normalize(readFileSync(join(dir, name), 'utf8'))]);
}

function normalize(text) {
  return text.replace(/\r\n?/g, '\n').replace(/[ \t]+$/gm, '').replace(/^\n+|\n+$/g, '') + '\n';
}

/// `name version` of every crate in the normal dependency tree of the root packages for `target`, from `cargo tree`,
/// which applies resolver 3's per-target features.
function treeCrates(target) {
  const roots = ROOT_PACKAGES.flatMap((name) => ['-p', name]);
  const tree = execFileSync(
    'cargo',
    ['tree', '--locked', '-e', 'normal', '--target', target, ...roots, '--prefix', 'none', '-f', '{p}'],
    { cwd: ROOT, maxBuffer: 256 * 1024 * 1024, encoding: 'utf8' },
  );
  const set = new Set();
  for (const line of tree.split('\n')) {
    // `name vX.Y.Z`, then `(path)` for a workspace member, `(proc-macro)`, `(*)` for a repeated subtree.
    const [name, version] = line.trim().split(/\s+/);
    if (name && version?.startsWith('v')) set.add(`${name} ${version.slice(1)}`);
  }
  return set;
}

/// The crates that only another OS's build links (`openssl-sys`, which SQLCipher uses on Windows and Linux only).
/// `cargo metadata --filter-platform` unifies features across all targets, so the walk below would list them; they are
/// taken out by name and version.
function otherTargetsOnly() {
  const macos = new Set(TARGETS.flatMap((t) => [...treeCrates(t)]));
  return new Set(OTHER_TARGETS.flatMap((t) => [...treeCrates(t)]).filter((c) => !macos.has(c)));
}

/// The crates linked into the shipped binaries: normal dependencies from the root packages, for both targets.
function crates() {
  const excluded = otherTargetsOnly();
  const found = new Map();
  for (const target of TARGETS) {
    const meta = JSON.parse(
      execFileSync('cargo', ['metadata', '--format-version', '1', '--locked', '--filter-platform', target], {
        cwd: ROOT,
        maxBuffer: 256 * 1024 * 1024,
      }),
    );
    const packages = new Map(meta.packages.map((p) => [p.id, p]));
    const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
    const members = new Set(meta.workspace_members);
    const queue = meta.packages.filter((p) => members.has(p.id) && ROOT_PACKAGES.includes(p.name)).map((p) => p.id);
    const seen = new Set(queue);
    while (queue.length > 0) {
      const node = nodes.get(queue.shift());
      for (const dep of node?.deps ?? []) {
        // A build dependency is a tool, not linked; except openssl-src on Windows and Linux, whose OpenSSL sources it
        // builds into a static library that ends up in WinVPN.exe and linvpn.
        const linked = dep.dep_kinds.some(
          (k) => k.kind === null || (VENDORED_OPENSSL && k.kind === 'build' && dep.name === 'openssl_src'),
        );
        if (!linked) continue;
        if (seen.has(dep.pkg)) continue;
        seen.add(dep.pkg);
        queue.push(dep.pkg);
      }
    }
    for (const id of seen) {
      const p = packages.get(id);
      if (members.has(id) || excluded.has(`${p.name} ${p.version}`)) continue;
      found.set(`${p.name} ${p.version}`, {
        name: p.name,
        version: p.version,
        license: p.license ?? (p.license_file ? `see ${p.license_file}` : 'not stated'),
        files: licenseFiles(dirname(p.manifest_path)),
      });
    }
  }
  return [...found.values()];
}

/// The JS packages in the web view's bundle: the UI's runtime dependencies and Svelte (its runtime is compiled in),
/// with their own runtime dependencies.
function jsPackages() {
  const ui = JSON.parse(readFileSync(join(UI, 'package.json'), 'utf8'));
  const queue = [...Object.keys(ui.dependencies ?? {}), 'svelte'];
  const found = new Map();
  while (queue.length > 0) {
    const name = queue.shift();
    if (found.has(name)) continue;
    const dir = join(UI, 'node_modules', name);
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    found.set(name, {
      name,
      version: pkg.version,
      license: typeof pkg.license === 'string' ? pkg.license : (pkg.license?.type ?? 'not stated'),
      files: licenseFiles(dir),
    });
    queue.push(...Object.keys(pkg.dependencies ?? {}));
  }
  return [...found.values()];
}

/// The packages grouped by identical licence texts; packages without a licence file listed on their own.
function section(title, list) {
  const sorted = [...list].sort((a, b) => (a.name === b.name ? a.version.localeCompare(b.version) : a.name < b.name ? -1 : 1));
  const lines = [RULE, title, RULE, ''];
  for (const p of sorted) lines.push(`${p.name} ${p.version} (${p.license})`);
  lines.push('');
  const groups = new Map();
  const bare = [];
  for (const p of sorted) {
    if (p.files.length === 0) {
      bare.push(p);
      continue;
    }
    for (const [file, text] of p.files) {
      const entry = groups.get(text) ?? { text, users: [] };
      entry.users.push(`${p.name} ${p.version} (${file})`);
      groups.set(text, entry);
    }
  }
  const ordered = [...groups.values()].sort((a, b) => (a.users[0] < b.users[0] ? -1 : a.users[0] > b.users[0] ? 1 : 0));
  for (const g of ordered) {
    lines.push('-'.repeat(100), ...g.users.map((u) => `  ${u}`), '-'.repeat(100), '', g.text);
  }
  if (bare.length > 0) {
    lines.push('-'.repeat(100));
    lines.push('Packages that ship no licence file; they are used under the licence named in their manifest:');
    for (const p of bare) lines.push(`  ${p.name} ${p.version}: ${p.license}`);
    lines.push('');
  }
  return lines.join('\n');
}

/// A licence file inside a crate's registry source (`relative`, '/'-separated), normalized.
function registryFile(rust, crate, relative, what) {
  const found = rust.find((c) => c.name === crate);
  if (!found) throw new Error(`${crate} is not a dependency`);
  const home = process.env.CARGO_HOME ?? join(process.env.HOME ?? process.env.USERPROFILE, '.cargo');
  const registry = join(home, 'registry', 'src');
  for (const index of readdirSync(registry).sort()) {
    const file = join(registry, index, `${crate}-${found.version}`, ...relative.split('/'));
    if (existsSync(file)) return normalize(readFileSync(file, 'utf8'));
  }
  throw new Error(`the ${what} licence of ${crate} ${found.version} was not found (cargo fetch --locked)`);
}

function sqlcipherNotice(rust) {
  return registryFile(rust, 'libsqlite3-sys', 'sqlcipher/LICENSE', 'SQLCipher');
}

/// Windows and Linux: SQLCipher's crypto provider there is OpenSSL 3, built from openssl-src and linked statically.
function opensslNotice(rust) {
  const src = rust.find((c) => c.name === 'openssl-src');
  const version = src?.version.split('+')[1] ?? 'unknown';
  return [
    RULE,
    `OpenSSL ${version} (vendored through openssl-src, SQLCipher's crypto provider, linked into ${LINUX ? 'linvpn' : 'WinVPN.exe'})`,
    RULE,
    '',
    registryFile(rust, 'openssl-src', 'openssl/LICENSE.txt', 'OpenSSL'),
  ];
}

/// Windows only: wireguard.dll, the prebuilt wireguard-nt DLL of the pinned zip, under its own licence.
function wireguardNtNotice() {
  const pins = readFileSync(join(ROOT, 'scripts', 'pins', 'wireguard-nt.txt'), 'utf8');
  const version = pins.split('\n').filter((l) => l.startsWith('version\t')).map((l) => l.slice('version\t'.length));
  if (version.length !== 1 || !/^[0-9][0-9.]*$/.test(version[0])) throw new Error('scripts/pins/wireguard-nt.txt: no version');
  return [
    RULE,
    `wireguard-nt ${version[0]} (wireguard.dll, the prebuilt signed DLL of WireGuard LLC, used by the WinVPN Service)`,
    RULE,
    '',
    normalize(readFileSync(join(ROOT, 'scripts', 'notices', 'wireguard-nt-LICENSE.txt'), 'utf8')),
  ];
}

/// Linux only: LinVPN's NetworkManager OpenVPN service, upstream NetworkManager-openvpn with LinVPN's patch, built by
/// scripts/build-nm-linvpn-openvpn.sh and shipped in the .deb with its source (GPL-2.0-or-later).
function nmOpenvpnNotice() {
  const pin = readFileSync(join(ROOT, 'scripts', 'pins', 'nm-openvpn.sha256'), 'utf8').trim();
  const tarball = pin.split(/\s+/)[1] ?? '';
  const version = /^NetworkManager-openvpn-([0-9.]+)\.tar\.xz$/.exec(tarball)?.[1];
  if (!version) throw new Error('scripts/pins/nm-openvpn.sha256: no NetworkManager-openvpn tarball');
  return [
    RULE,
    `NetworkManager-openvpn ${version} (LinVPN's NetworkManager OpenVPN service, /usr/lib/linvpn/nm-openvpn-service*)`,
    RULE,
    '',
    `LinVPN ships its own build of NetworkManager-openvpn ${version}`,
    '(https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) with linvpn-nm-openvpn.patch: the programs',
    '/usr/lib/linvpn/nm-openvpn-service and /usr/lib/linvpn/nm-openvpn-service-openvpn-helper, which NetworkManager',
    'starts, and the D-Bus policy /usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf. They are separate',
    'programs from LinVPN and are licensed under the GNU General Public License, version 2 or (at your option) any',
    'later version (GPL-2.0-or-later); so is the patch.',
    '',
    'Copyright (C) 2005 - 2010 Tim Niemueller',
    'Copyright (C) 2005 - 2010 Dan Williams',
    'Copyright (C) 2005 - 2018 Red Hat, Inc.',
    '',
    'The corresponding source is in /usr/share/linvpn/source/: the unmodified upstream tarball',
    `${tarball}, linvpn-nm-openvpn.patch and a README with the build command. The full text`,
    'of the GNU General Public License version 2 is in /usr/share/common-licenses/GPL-2.',
    '',
  ];
}

function render() {
  const rust = crates();
  const js = jsPackages();
  return [
    `${PRODUCT} — third-party notices`,
    '',
    `${PRODUCT} includes the software listed below. Each part is used under its own licence, reproduced here.`,
    'This file is generated by scripts/third-party-notices.mjs; do not edit it by hand.',
    '',
    RULE,
    'SQLCipher (bundled through libsqlite3-sys, the encrypted vault database)',
    RULE,
    '',
    sqlcipherNotice(rust),
    RULE,
    'SQLite',
    RULE,
    '',
    'SQLCipher is based on SQLite. The SQLite source code is in the public domain: its authors disclaim copyright',
    'to it (https://sqlite.org/copyright.html).',
    '',
    ...(VENDORED_OPENSSL ? opensslNotice(rust) : []),
    ...(WINDOWS ? wireguardNtNotice() : []),
    ...(LINUX ? nmOpenvpnNotice() : []),
    section(
      WINDOWS
        ? 'Rust crates (the WinVPN app and the WinVPN Service)'
        : LINUX
          ? 'Rust crates (the LinVPN app, its update step and its log reader)'
          : 'Rust crates (the MacVPN app and the mvpn helper)',
      rust,
    ),
    section('JavaScript packages (the app’s web view)', js),
  ].join('\n');
}

const text = render();
if (CHECK) {
  const current = existsSync(OUT) ? readFileSync(OUT, 'utf8') : '';
  if (current !== text) {
    const option = OS === 'macos' ? '' : ` --os ${OS}`;
    console.error(`${OUT_NAME} is not up to date: run node scripts/third-party-notices.mjs${option}`);
    process.exit(1);
  }
  console.log(`${OUT_NAME} is up to date`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}`);
}
