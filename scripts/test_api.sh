#!/usr/bin/env bash
# Run the standard-library end-to-end differential test against a live panel.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PANEL_URL="${PANEL_URL:-http://127.0.0.1:8000}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to run the API tests." >&2
  exit 1
fi

exec python3 "${SCRIPT_DIR}/differential_test.py" "${PANEL_URL}"
