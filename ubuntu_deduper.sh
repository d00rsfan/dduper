#!/usr/bin/env bash
# Run from the checkout; the Python driver uses only the standard library.
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/scripts/ubuntu_deduper.py" "$@"
