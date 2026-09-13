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

`agent.py`, the React front end in `web/` and the tool *implementations* sit
**above** this line and are not security-critical. The prompt is defence in
depth, never a control.

Three places above the line still carry a security claim, and are treated as if
they were below it:

- **`api.py` and `secure_rls/auth.py` decide who the caller is.** The API must
  build the `SecurityContext` from the signed session and nothing else. An
  endpoint that constructs a context for a *different* tenant and returns what
  it produced hands that tenant's data to the caller -- every layer below then
  holds perfectly and the data leaks anyway. `/api/compare` and the Streamlit
  side-by-side tab once did exactly this; the second side is now a separate
  sign-in with its own password and cookie (`secure_rls_peer`, different salt).
  `tests/test_api.py` pins that the old request shape is refused.
- **Tool schemas in `secure_rls/tools/__init__.py`** are the model's whole
  interface. No tenant, user, scope or database argument, ever.
- **`secure_rls/oracle.py` and `verdict()` in `secure_rls/redteam.py`** are the
  measurement behind the leak rate. They must not trust the layers they measure:
  a verdict that only looked for a `tenant_id` column once scored
  `SELECT name, salary` over foreign rows as contained.

## Working in this repository

- Changing anything under `secure_rls/security/`, `db.py`, `api.py`,
  `secure_rls/auth.py` or the tool schemas requires the isolation tests to pass,
  and normally requires a new test. A hook (`.claude/hooks/isolation-tests.sh`)
  runs them after every such edit and reports a failure back. A change that
  makes them pass by weakening an assertion is a change in the wrong direction.
- Never add a tenant, user, scope or database argument to a tool schema. If a
  tool needs to know who is asking, it takes a `SecurityContext` in Python and
  the LLM never sees it.
- Validate SQL on the parsed AST, never by inspecting the string. Comments,
  literals and quoting defeat string inspection.
- Tool argument schemas forbid unknown fields. An ignored argument means the
  tool silently answers a different question.
- The authorizer (L3) trusts the name of the view a read came through, and a
  CTE can borrow that name: `WITH employees AS (SELECT * FROM employees_all)`
  passes L3 alone and is stopped only by L4. Do not reason that "L3 would catch
  it" for anything that can be spelled as a CTE.
- Tests must pass on a clean checkout with no model running: create the
  database through the code path under test, and replace the agent rather than
  calling Ollama. Three CI failures came from tests that only passed because a
  local `secure_rls.db` or a local model happened to exist.
- Answer-quality checks (secure_rls/grounding.py) must act only on unambiguous
  signs, and every fault or false alarm seen in a demo goes into
  tests/fixtures/answers.json before the check is changed. Tenant names and two
  tool names are ordinary English words; bare-word matching has already been
  tried and flagged normal answers.
- Prefer failing loudly to failing open. Several bugs found in this project
  were silent: a renamed sqlglot argument key that skipped a rewrite, a dropped
  tool argument that removed a filter. Both returned plausible answers.

## Commands

```bash
source .venv/bin/activate            # every command below assumes the venv
python scripts/gen_data.py           # regenerate employees.csv (seeded)
python -m pytest -m "not slow"       # fast suite, no model needed
python -m pytest -m slow             # retrieval tests (downloads embeddings)
python -m ruff check . && python -m mypy
npm --prefix web run build           # type-check and bundle the front end
uvicorn api:app --port 8000          # API (serves web/dist when built); needs Ollama
npm --prefix web run dev             # React dev server on :5173, proxies /api to :8000
streamlit run app.py                 # the fallback UI on :8501
python -m evals --limit 4            # evaluation smoke run
python -m evals.benchmark --models all   # compare the three models (about an hour)
python -m evals.retrieval            # note search quality, no language model needed
```

Supported Python is 3.10 and 3.12, both in CI. sqlite3 differs between them:
before 3.12 a multi-statement payload raises `sqlite3.Warning`, which is not a
subclass of `sqlite3.Error`.

## Style

Comments explain *why*, especially where the code looks over-cautious -- most
of it is deliberate. Docstrings on security modules should say what attack the
code exists to stop. Keep line length at 100 and let `ruff` settle the rest.
