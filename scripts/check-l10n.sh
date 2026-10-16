#!/bin/bash
# Az app String Catalogjának lefedettsége: a MacVPN target fordításakor a Swift fordító kigyűjti a lokalizálható
# kulcsokat (.stringsdata: SwiftUI Text/Button/…, String(localized:)); hiba, ha bármelyik hiányzik a
# Sources/MacVPN/Resources/Localizable.xcstrings-ből, vagy nincs lefordított magyar változata.
# A native build system a -emit-localized-strings-path könyvtárba ír, az újabb (swiftbuild) a köztes
# könyvtárakba: mindkettőt összegyűjtjük, és csak a Sources/MacVPN alatti forrásokat nézzük.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/strings"
echo "▶ MacVPN fordítása kulcs-kigyűjtéssel"
swift build --product MacVPN --scratch-path "$WORK/build" \
  -Xswiftc -emit-localized-strings -Xswiftc -emit-localized-strings-path -Xswiftc "$WORK/strings" >/dev/null

python3 - "$WORK" "$PWD/Sources/MacVPN/" Sources/MacVPN/Resources/Localizable.xcstrings <<'PY'
import glob, json, os, sys
work, src_dir, catalog_path = sys.argv[1], os.path.realpath(sys.argv[2]), sys.argv[3]
files = set(glob.glob(f"{work}/strings/**/*.stringsdata", recursive=True))
files |= set(glob.glob(f"{work}/build/**/*.stringsdata", recursive=True))
used = {}
for f in files:
    data = json.load(open(f, encoding="utf-8"))
    source = os.path.realpath(data.get("source", ""))
    if not source.startswith(src_dir):
        continue
    for table, entries in data.get("tables", {}).items():
        for e in entries:
            if e["key"]:
                used.setdefault((table, e["key"]), f"{os.path.basename(source)}:{e['location']['startingLine']}")
if not used:
    sys.exit("✗ nem sikerült kulcsokat kigyűjteni (nincs .stringsdata)")
strings = json.load(open(catalog_path, encoding="utf-8"))["strings"]
errors = []
for (table, key), where in sorted(used.items(), key=lambda x: x[1]):
    if table != "Localizable":
        errors.append(f"{where}: nem a Localizable táblában ({table}): {key!r}")
        continue
    hu = (strings.get(key) or {}).get("localizations", {}).get("hu", {}).get("stringUnit", {})
    if key not in strings:
        errors.append(f"{where}: hiányzik a catalogból: {key!r}")
    elif hu.get("state") != "translated" or not hu.get("value"):
        errors.append(f"{where}: nincs magyar fordítás: {key!r}")
unused = sorted(set(strings) - {k for _, k in used})
for e in errors:
    print("✗", e)
if unused:
    print(f"(figyelmeztetés) a catalogban, de a kódban nem használt kulcsok: {unused}")
if errors:
    sys.exit(1)
print(f"✓ {len(used)} kulcs, mind szerepel a catalogban magyar fordítással")
PY
