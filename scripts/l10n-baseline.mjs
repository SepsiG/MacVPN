#!/usr/bin/env node
// The macOS wording baseline (platform-neutral refactor, Task 1): the resolved English and Hungarian text of every
// key of crates/core/l10n/strings.json as the macOS app shows it, in
// scripts/bundle-baseline/1.4.0/l10n-macos.json. Frozen on 1.4.0: per-OS l10n variants must leave every macOS text
// byte-identical.
//
//   node scripts/l10n-baseline.mjs           writes the baseline
//   node scripts/l10n-baseline.mjs --check   exits 1 when the table no longer resolves to the baseline
//
// Keys added after 1.4.0 (new texts) are not in the baseline: --check counts them but does not compare them.
//
// 1.4.0: EN = the key, HU = the entry's `hu`. From Task 6 on, `resolve` goes through the per-OS lookup with
// os = "macos" (and must give identical output); only `resolve` changes, never the baseline file.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TABLE = join(ROOT, 'crates', 'core', 'l10n', 'strings.json');
const OUT = join(ROOT, 'scripts', 'bundle-baseline', '1.4.0', 'l10n-macos.json');
const OS = 'macos';

/// The text the app on `os` shows for `key` in `language` (`en` or `hu`): the OS's variant if the entry has one,
/// else the base text (core `l10n::tr_for`). The product name is MacVPN on macOS, so nothing is replaced here.
function resolve(entry, key, language, os) {
  const variant = entry.variants?.[os];
  if (variant !== undefined) return language === 'hu' ? variant.hu : variant.en;
  return language === 'hu' ? entry.hu : key;
}

function baseline() {
  const table = JSON.parse(readFileSync(TABLE, 'utf8'));
  const out = {};
  // Sorted by UTF-16 code units, so the file never depends on the table's own key order.
  for (const key of Object.keys(table.strings).sort()) {
    const entry = table.strings[key];
    out[key] = { en: resolve(entry, key, 'en', OS), hu: resolve(entry, key, 'hu', OS) };
  }
  return JSON.stringify(out, null, 2) + '\n';
}

const text = baseline();
if (process.argv.includes('--check')) {
  let current;
  try {
    current = readFileSync(OUT, 'utf8');
  } catch {
    console.error(`missing: ${OUT} (run node scripts/l10n-baseline.mjs once on 1.4.0)`);
    process.exit(1);
  }
  const was = JSON.parse(current);
  const now = JSON.parse(text);
  const added = Object.keys(now).filter((key) => !(key in was)).length;
  if (current !== text) {
    let shown = 0;
    for (const key of Object.keys(was).sort()) {
      if (JSON.stringify(was[key]) === JSON.stringify(now[key])) continue;
      if (shown++ < 20) console.error(`changed: ${JSON.stringify(key)}\n  was ${JSON.stringify(was[key])}\n  now ${JSON.stringify(now[key])}`);
    }
    if (shown > 0) {
      console.error(`the macOS texts differ from the 1.4.0 baseline (${shown} keys)`);
      process.exit(1);
    }
  }
  console.log(`l10n baseline: ${Object.keys(was).length} keys identical, ${added} new`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}`);
}
