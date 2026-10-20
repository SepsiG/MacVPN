#!/bin/bash
# EN/HU coverage of every text (the Swift-era String Catalog check's successor). The single table is
# crates/core/l10n/strings.json (the English text is the key, every entry has a Hungarian text):
#   - the web UI (app/ui, `node --test`, l10n.test.ts): every tr('…') key is an `app` entry with a Hungarian text,
#     tr only gets literal keys, no hard-coded text in the Svelte markup or in TypeScript objects;
#   - the Rust side (cargo test): every key translated anywhere in the workspace has a Hungarian text
#     (crates/app-core/tests/l10n_coverage.rs), the table itself (crates/core/tests/l10n.rs), the root helper's
#     messages (mvpn's own unit tests).
# Needs `npm ci` in app/ui first (Node runs the TypeScript tests directly).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> UI texts (app/ui: node --test src/lib/l10n.test.ts)"
(cd app/ui && node --test src/lib/l10n.test.ts)
echo "==> Rust texts (cargo test)"
cargo test --locked -q -p macvpn-app-core --test l10n_coverage
cargo test --locked -q -p macvpn-core --test l10n
cargo test --locked -q -p mvpn -- call_site
echo "OK: every text has an English key and a Hungarian translation"
