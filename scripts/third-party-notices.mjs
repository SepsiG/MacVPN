#!/usr/bin/env node
// Generates THIRD-PARTY-NOTICES.txt (repo root) from what the release bundles: the SQLCipher notice and the SQLite
// public-domain note, then every Rust crate linked into the app or mvpn (normal dependencies, both macOS targets,
// from `cargo metadata --locked`) and every JS package bundled into the web view (the UI's runtime dependencies and
// the Svelte runtime), each with its licence expression and the licence files it ships (LICENSE*, LICENCE*, COPYING*,
// NOTICE*), read from ~/.cargo/registry and app/ui/node_modules. Identical texts are printed once, after the list of
// the packages that ship them. Sorted throughout and free of local paths, so every machine produces the same file.
//
//   node scripts/third-party-notices.mjs           writes THIRD-PARTY-NOTICES.txt
//   node scripts/third-party-notices.mjs --check   exits 1 when the committed file is not what it would write
//
// Needs the crate sources (`cargo fetch --locked`) and app/ui/node_modules (`npm ci`).
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'THIRD-PARTY-NOTICES.txt');
const UI = join(ROOT, 'app', 'ui');
const ROOT_PACKAGES = ['macvpn-app', 'mvpn'];
const TARGETS = ['aarch64-apple-darwin', 'x86_64-apple-darwin'];
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

/// The crates linked into the shipped binaries: normal dependencies from the root packages, for both targets.
function crates() {
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
        if (!dep.dep_kinds.some((k) => k.kind === null)) continue;
        if (seen.has(dep.pkg)) continue;
        seen.add(dep.pkg);
        queue.push(dep.pkg);
      }
    }
    for (const id of seen) {
      const p = packages.get(id);
      if (members.has(id)) continue;
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

function sqlcipherNotice(rust) {
  const sys = rust.find((c) => c.name === 'libsqlite3-sys');
  if (!sys) throw new Error('libsqlite3-sys is not a dependency');
  const home = process.env.CARGO_HOME ?? join(process.env.HOME, '.cargo');
  const registry = join(home, 'registry', 'src');
  for (const index of readdirSync(registry).sort()) {
    const file = join(registry, index, `libsqlite3-sys-${sys.version}`, 'sqlcipher', 'LICENSE');
    if (existsSync(file)) return normalize(readFileSync(file, 'utf8'));
  }
  throw new Error(`the SQLCipher licence of libsqlite3-sys ${sys.version} was not found (cargo fetch --locked)`);
}

function render() {
  const rust = crates();
  const js = jsPackages();
  return [
    'MacVPN — third-party notices',
    '',
    'MacVPN includes the software listed below. Each part is used under its own licence, reproduced here.',
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
    section('Rust crates (the MacVPN app and the mvpn helper)', rust),
    section('JavaScript packages (the app’s web view)', js),
  ].join('\n');
}

const text = render();
if (process.argv.includes('--check')) {
  const current = existsSync(OUT) ? readFileSync(OUT, 'utf8') : '';
  if (current !== text) {
    console.error('THIRD-PARTY-NOTICES.txt is not up to date: run node scripts/third-party-notices.mjs');
    process.exit(1);
  }
  console.log('THIRD-PARTY-NOTICES.txt is up to date');
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}`);
}
