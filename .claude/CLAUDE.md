# Secure multi-tenant RLS agent

A conversational data analyst over a multi-tenant HR dataset. The product is
ordinary; the point of the project is that **the language model is outside the
trust boundary**. A compromised, jailbroken or simply badly-behaved model must
not be able to reach another tenant's rows.

## The rule that governs everything here

Isolation is enforced by five layers, none of which is the prompt:

| Layer | Where | What it does |
| --- | --- | --- |
| L1 identity | `secure_rls/security/context.py` | tenant comes from the session; tools take no tenant argument |
| L2 physical | `db.py` | read-only connection whose only visible relation is a per-tenant view |
| L3 kernel | `secure_rls/security/authorizer.py` | SQLite authorizer: base table readable only *through* that view |
| L4 validation | `secure_rls/security/sql_guard.py` | sqlglot AST checks and tenant-predicate injection |
| L5 egress | `secure_rls/security/egress.py` | refuses any result carrying a foreign tenant id |

`agent.py`, `app.py` and everything in `secure_rls/tools/` sit **above** this
line and are not security-critical. The prompt is defence in depth, never a
control.

## Working in this repository

- Changing anything under `secure_rls/security/` or `db.py` requires the
  isolation tests to pass, and normally requires a new test. A change that
  makes them pass by weakening an assertion is a change in the wrong direction.
- Never add a tenant, user, scope or database argument to a tool schema. If a
  tool needs to know who is asking, it takes a `SecurityContext` in Python and
  the LLM never sees it.
- Validate SQL on the parsed AST, never by inspecting the string. Comments,
  literals and quoting defeat string inspection.
- Tool argument schemas forbid unknown fields. An ignored argument means the
  tool silently answers a different question.
- Prefer failing loudly to failing open. Several bugs found in this project
  were silent: a renamed sqlglot argument key that skipped a rewrite, a dropped
  tool argument that removed a filter. Both returned plausible answers.

## Commands

```bash
python scripts/gen_data.py           # regenerate employees.csv (seeded)
python -m pytest -m "not slow"       # fast suite, no model needed
python -m pytest -m slow             # retrieval tests (downloads embeddings)
python -m ruff check . && python -m mypy
streamlit run app.py                 # the app, needs Ollama on :11434
python -m evals --limit 4            # evaluation smoke run
python -m evals --models all         # full suite across three models (slow)
```

## Style

Comments explain *why*, especially where the code looks over-cautious -- most
of it is deliberate. Docstrings on security modules should say what attack the
code exists to stop. Keep line length at 100 and let `ruff` settle the rest.
