#!/usr/bin/env node
// Merges the L-b string fragments (crates/core/l10n/lb/<task>.json) into crates/core/l10n/strings.json: entries
// appended in numeric fragment order, an identical existing entry accepted, a different one refused (nothing is
// written then). The fragments are deleted after a successful write. Usage: node scripts/l10n-merge.mjs
import { readFileSync, writeFileSync, readdirSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

export function merge(tablePath, fragmentDir) {
  const table = JSON.parse(readFileSync(tablePath, 'utf8'));
  const files = readdirSync(fragmentDir).filter((f) => /^\d+\.json$/.test(f)).sort((a, b) => parseInt(a) - parseInt(b));
  for (const f of files) {
    const { strings } = JSON.parse(readFileSync(join(fragmentDir, f), 'utf8'));
    for (const [key, entry] of Object.entries(strings)) {
      const old = table.strings[key];
      if (old !== undefined && !isDeepStrictEqual(old, entry)) throw new Error(`${f}: "${key}" already exists with another entry`);
      table.strings[key] = entry;
    }
  }
  writeFileSync(tablePath, JSON.stringify(table, null, 2) + '\n');
  for (const f of files) unlinkSync(join(fragmentDir, f));
  return files.length;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const n = merge(join(root, 'crates/core/l10n/strings.json'), join(root, 'crates/core/l10n/lb'));
  console.log(`merged ${n} fragment(s)`);
}
