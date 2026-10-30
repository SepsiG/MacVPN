# L-b string fragments

Each L-b task writes its new user-facing strings into `<task number>.json` here, with exactly the entry schema of
`../strings.json` (`{"strings": {"<English key>": {"hu": "…", "scope": "…", "only": ["linux"]}}}`). The wave's
wiring task runs `node scripts/l10n-merge.mjs`, which appends the entries to `strings.json` (refusing a key that
already exists with a different entry) and deletes the fragments. Until then a task's tests check the English text
(the key) only.
