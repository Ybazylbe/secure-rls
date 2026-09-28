# What was hard

The interesting failures were all silent. None would have been found by reading
the code, and none had anything to do with the parts that look dangerous.

**A leak above every layer.** The side-by-side view built another tenant's
context on the server and returned its answer to the caller. The five layers
held perfectly — each query really was scoped — and the data still reached the
wrong user. Nothing in `security/` could have caught it, because the mistake was
about *who* was asking, not *what* was asked.

**A measurement that failed open.** The leak verdict looked for a `tenant_id`
column and skipped rows without one. `SELECT name, salary` over another tenant
would have scored as contained. It never happened only because the layers held,
and a measurement that is right only while the thing it measures is working is
not a measurement. The verdict now replays each step against a database that
holds only the caller's tenant.

**A security control that failed open on a library upgrade.** The SQL guard
located the `FROM` clause by argument name. `sqlglot` renamed that key in v30,
the lookup started returning `None`, and the tenant-predicate rewrite was
skipped — with no error, and with the guard reporting success. L2 and L3 meant
nothing leaked, which is precisely what defence in depth is for, but the lesson
was about the test: it now counts predicates per scope rather than trusting that
the code ran.

**`AND` is a function.** In `sqlglot`, `exp.And` subclasses `exp.Func`, so the
function allowlist read `WHERE a IN (...) AND b = 1` as a call to something
named `tenant_id in` and refused it. Any query mixing `AND` with parentheses
would have been rejected live on the demo.

**An ignored argument is a different query.** Pydantic drops unknown fields by
default. The model kept sending a nested `{"filter": {...}}` object instead of
the flat arguments the schema declared; the key was silently dropped, the tool
ran unfiltered, and the agent answered "450 employees scored below 3.0" — a
real number, from a real tool call, answering a question nobody asked. Schemas
now forbid extra fields.

**Tests that passed for the wrong reason.** The first CI run on a clean machine
failed three ways that no local run could show: API tests that relied on a
database already on disk, one that quietly called the local model, and one that
never presented the tampered cookie it claimed to test — on Python 3.10 the
cookie jar sent the valid one first. The same run found that `sqlite3` before
3.12 raises `sqlite3.Warning`, outside the `sqlite3.Error` hierarchy, for a
stacked statement.

**The benchmark overturned a claim.** The default model was chosen partly for
"best tool selection", on a three-question smoke test. The full run put it last
of three on that measure. The documentation now says what the full run says.

## Time spent

Roughly 20 hours for the first complete version:

| | |
| --- | --- |
| Data, storage, the five security layers | ~6 h |
| Tools, agent, retrieval | ~5 h |
| First UI, in Streamlit (since replaced by React) | ~3 h |
| Evaluation, and the six defects it found | ~5 h |
| CI, container, documentation | ~2 h |

Building the agent took an afternoon; finding out that it was quietly wrong took
considerably longer, and was the part worth doing.
