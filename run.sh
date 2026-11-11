#!/bin/bash
# ESDA Protocol — one-command run for macOS Terminal
# Picks the first python3 that actually runs (a broken Homebrew python3 can be an empty file).
set -euo pipefail
cd "$(dirname "$0")"
PY=""
for c in python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if command -v "$c" >/dev/null 2>&1 && [ "$("$c" -c 'print(42)' 2>/dev/null)" = "42" ]; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then echo "No working python3 found." >&2; exit 1; fi
echo "Using $PY ($("$PY" --version 2>&1))"
chmod +x esda_protocol.py
"$PY" esda_protocol.py
echo
# Companion check: rebuild 7 mainnet genesis blocks from raw fields and prove their hashes.
# Dash needs X11 (dash_hash); a venv at ~/.venvs/esda-genesis is used if present.
GPY="${ESDA_GENESIS_PY:-}"
if [ -z "$GPY" ] && [ -x "$HOME/.venvs/esda-genesis/bin/python" ]; then GPY="$HOME/.venvs/esda-genesis/bin/python"; fi
GPY="${GPY:-$PY}"
echo "Genesis proof using $GPY"
"$GPY" tools/genesis_proof.py --json-out genesis_results.json | tee genesis_output.txt
echo
echo "Saved: esda_output.txt, esda_results.json, genesis_output.txt, genesis_results.json"
