---
description: Run the full isolation gate exactly as CI does, and explain any failure in terms of the five layers
---

Run the checks that decide whether this project still does what it claims.

```bash
python scripts/gen_data.py
python -m pytest -m "not slow" tests/test_isolation.py tests/test_sql_guard.py \
  tests/test_egress.py tests/test_tools.py tests/test_auth.py
python -m ruff check . && python -m mypy
```

If everything passes, say so in one line and stop.

If something fails, do not fix it yet. First say **which layer** the failing
test belongs to and what the failure means:

| Failing tests | Layer | What a failure means |
| --- | --- | --- |
| `test_isolation.py` | L2 / L3 | the database itself can be made to show foreign rows |
| `test_sql_guard.py` | L4 | generated SQL is no longer validated as expected |
| `test_egress.py` | L5 | the tripwire, or the untrusted-text handling, has changed |
| `test_tools.py` | L1 | a tool may now be told whose data to fetch |
| `test_auth.py` | L1 | the tenant is no longer decided where it should be |

Then propose the smallest fix that restores the guarantee. Never propose
relaxing an assertion: these tests exist because the behaviour they pin is the
product.

$ARGUMENTS
