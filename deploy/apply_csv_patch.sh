#!/usr/bin/env bash
# INPV-21 persistent remediation: produce a patched ExportDataGenerator.php
# that wires league/csv EscapeFormula into every CSV writer, so exported
# transaction descriptions beginning with =,+,-,@ are neutralised.
# The patched file is bind-mounted into the app container by docker-compose,
# so the fix survives container recreation (unlike an in-container edit).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-/home/kali/firefly-iii-src-cache/app/Support/Export/ExportDataGenerator.php}"
OUT="${HERE}/patch/ExportDataGenerator.php"
mkdir -p "${HERE}/patch"

if [ ! -f "$SRC" ]; then
  echo "Source not found at $SRC -- downloading v6.6.2 copy."
  SRC=/tmp/ExportDataGenerator.orig.php
  curl -fsSL -o "$SRC" \
    https://raw.githubusercontent.com/firefly-iii/firefly-iii/v6.6.2/app/Support/Export/ExportDataGenerator.php
fi

python3 - "$SRC" "$OUT" <<'PY'
import sys
src, out = sys.argv[1], sys.argv[2]
code = open(src).read()
if 'EscapeFormula' not in code:
    code = code.replace("use League\\Csv\\Writer;",
                        "use League\\Csv\\EscapeFormula;\nuse League\\Csv\\Writer;", 1)
new = []
for ln in code.splitlines():
    new.append(ln)
    if 'Writer::fromString();' in ln:
        indent = ln[:len(ln) - len(ln.lstrip())]
        new.append(f"{indent}$csv->addFormatter(new EscapeFormula()); // INPV-21: neutralise CSV formula injection")
open(out, 'w').write("\n".join(new) + "\n")
n = sum(1 for l in new if 'addFormatter(new EscapeFormula' in l)
print(f"Patched {n} CSV writer(s) -> {out}")
PY
