#!/usr/bin/env bash
# PostToolUse hook: after an edit to anything that decides whose rows a caller
# sees, run the isolation tests and put a failure in front of Claude.
#
# Two earlier versions of this hook failed silently, which is the one thing a
# guard must not do: it called the system `python`, which has no pytest, so the
# tests never ran; and it watched only security/ and db.py, missing the tool
# schemas and the API that CLAUDE.md itself calls security-relevant.

set -uo pipefail

root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$root" || exit 0

changed=$(python3 -c 'import json, sys; print(json.load(sys.stdin).get("tool_input", {}).get("file_path", ""))')

case "$changed" in
  */secure_rls/security/*|*/secure_rls/tools/*|*/db.py|*/api.py|*/secure_rls/auth.py|*/secure_rls/oracle.py|*/secure_rls/redteam.py) ;;
  *) exit 0 ;;
esac

python="$root/.venv/bin/python"
if [ ! -x "$python" ]; then
  # Refuse to pretend. Exit 2 shows this to Claude rather than passing quietly.
  echo "isolation hook: $python not found, so the isolation tests did NOT run." >&2
  echo "Create the venv (python -m venv .venv && pip install -r requirements-dev.txt)." >&2
  exit 2
fi

echo "Security-relevant file touched ($changed) - running the isolation tests"
if ! output=$("$python" -m pytest -o addopts="" -q -m "not slow" -p no:cacheprovider -W ignore \
    tests/test_isolation.py tests/test_sql_guard.py tests/test_egress.py \
    tests/test_tools.py tests/test_auth.py tests/test_api.py tests/test_verdict.py 2>&1); then
  echo "$output" | tail -40 >&2
  echo "Isolation tests FAILED after editing $changed. Fix the layer; do not relax the test." >&2
  exit 2
fi
echo "$output" | tail -1
