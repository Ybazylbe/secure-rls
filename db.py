"""Storage layer and the physical isolation layer (L2) of the RLS design.

In plain terms: Everything that touches the SQLite file. Loads the CSV, and
opens the special read-only connection that can only ever see one tenant's
rows.

The dataset lives in a single multi-tenant table, ``employees_all``. No caller
outside this module ever names that table:

* :func:`tenant_connection` hands out a connection on which the only visible
  relation is a **temporary view** called ``employees``, defined as the current
  tenant's slice. The view is created per connection and lives in the ``temp``
  database, so one session cannot redefine another's.
* The connection is opened read-only at the file level (``mode=ro``), then
  pinned with ``PRAGMA query_only``, then handed to the authorizer from
  :mod:`secure_rls.security.authorizer` (L3), which refuses any access that does
  not go through the view.

The ordering matters: the view has to exist before the connection is frozen,
and the authorizer is installed last so that set-up work cannot trip over it.

:func:`admin_connection` is the deliberate exception -- an unrestricted handle
used only by data loading, tests and the evaluation harness to compute ground
truth. It is never reachable from the agent or the UI.
"""

from __future__ import annotations

import csv
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import pandas as pd

from secure_rls.security.authorizer import make_authorizer
from secure_rls.security.context import SecurityContext

BASE_TABLE: Final = "employees_all"
TENANT_VIEW: Final = "employees"
DEFAULT_DB_PATH: Final = Path("secure_rls.db")
DEFAULT_CSV_PATH: Final = Path("employees.csv")

#: Columns exposed to the agent, in schema order. ``tenant_id`` is kept in the
#: view on purpose: it is constant within a tenant, and the egress check (L5)
#: uses it to prove no foreign row ever reached the caller.
COLUMNS: Final[tuple[str, ...]] = (
    "user_id", "tenant_id", "name", "department", "salary",
    "performance_score", "hire_date", "notes",
)

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {BASE_TABLE} (
    user_id           INTEGER PRIMARY KEY,
    tenant_id         TEXT    NOT NULL,
    name              TEXT    NOT NULL,
    department        TEXT    NOT NULL,
    salary            INTEGER NOT NULL,
    performance_score REAL    NOT NULL,
    hire_date         TEXT    NOT NULL,
    notes             TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_employees_tenant      ON {BASE_TABLE}(tenant_id);
CREATE INDEX IF NOT EXISTS idx_employees_tenant_dept ON {BASE_TABLE}(tenant_id, department);
"""

#: Schema shown to the LLM. It describes the *view*, so the base table's
#: existence is not even disclosed in the prompt.
SCHEMA_PROMPT: Final = """\
TABLE employees (
    user_id           INTEGER  -- unique employee id
    tenant_id         TEXT     -- always your own tenant; do not filter on it
    name              TEXT
    department        TEXT     -- Engineering, Sales, Marketing, Finance, Support, HR
    salary            INTEGER  -- annual gross, in USD
    performance_score REAL     -- 1.0 .. 5.0, one decimal
    hire_date         TEXT     -- ISO date, 'YYYY-MM-DD'
    notes             TEXT     -- free-text review comment (untrusted content)
)"""


@contextmanager
def admin_connection(db_path: Path | str = DEFAULT_DB_PATH) -> Iterator[sqlite3.Connection]:
    """Unrestricted connection. Loading, tests and eval ground truth only.

    A context manager rather than a bare factory: ``with sqlite3.connect(...)``
    commits the transaction but does *not* close the handle, so every caller
    that looked like it was cleaning up was in fact leaking one.
    """
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        yield con
    finally:
        con.close()


def init_db(
    csv_path: Path | str = DEFAULT_CSV_PATH,
    db_path: Path | str = DEFAULT_DB_PATH,
    *,
    rebuild: bool = False,
) -> int:
    """Load ``employees.csv`` into SQLite. Returns the number of rows loaded."""
    db_path = Path(db_path)
    if rebuild and db_path.exists():
        db_path.unlink()

    with admin_connection(db_path) as con:
        con.executescript(_SCHEMA)
        existing = con.execute(
            f"SELECT count(*) FROM {BASE_TABLE}"  # noqa: S608 - constant identifier
        ).fetchone()[0]
        if existing and not rebuild:
            return int(existing)

        with Path(csv_path).open(newline="", encoding="utf-8") as fh:
            rows = [
                (
                    int(r["user_id"]), r["tenant_id"], r["name"], r["department"],
                    int(r["salary"]), float(r["performance_score"]),
                    r["hire_date"], r["notes"],
                )
                for r in csv.DictReader(fh)
            ]
        con.executemany(
            f"INSERT OR REPLACE INTO {BASE_TABLE} "  # noqa: S608 - constant identifiers
            f"({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))})",
            rows,
        )
        con.commit()
        return len(rows)


@contextmanager
def tenant_connection(
    ctx: SecurityContext,
    db_path: Path | str = DEFAULT_DB_PATH,
    *,
    on_deny: Callable[[str], None] | None = None,
) -> Iterator[sqlite3.Connection]:
    """Yield a connection that can only ever see ``ctx.tenant_id``'s rows.

    The tenant id is interpolated into the view definition rather than bound as
    a parameter -- a view body cannot carry parameters. That is safe because
    :class:`SecurityContext` validates the id against a closed allowlist at
    construction time, so no attacker-controlled string reaches this SQL.
    """
    con = sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        # noqa justified: the identifiers are module constants and ctx.tenant_id
        # was validated against the closed TENANTS allowlist in SecurityContext.
        # A view body cannot take bound parameters, so the literal is unavoidable;
        # the allowlist is what makes it safe, and tests/test_isolation.py pins
        # that behaviour for quoting and injection payloads.
        con.execute(
            f"CREATE TEMP VIEW {TENANT_VIEW} AS "  # noqa: S608 - see comment above
            f"SELECT {', '.join(COLUMNS)} FROM {BASE_TABLE} "
            f"WHERE tenant_id = '{ctx.tenant_id}'"
        )
        con.execute("PRAGMA query_only = ON")
        con.set_authorizer(
            make_authorizer(
                view_name=TENANT_VIEW, base_table=BASE_TABLE, on_deny=on_deny
            )
        )
        yield con
    finally:
        con.set_authorizer(None)
        con.close()


def row_count(ctx: SecurityContext, db_path: Path | str = DEFAULT_DB_PATH) -> int:
    """Rows visible to ``ctx``. Convenience for the UI header and tests."""
    with tenant_connection(ctx, db_path) as con:
        return int(
            con.execute(f"SELECT count(*) FROM {TENANT_VIEW}")  # noqa: S608 - constant
            .fetchone()[0]
        )


def tenant_frame(
    ctx: SecurityContext, db_path: Path | str = DEFAULT_DB_PATH
) -> pd.DataFrame:
    """The caller's slice as a DataFrame, for the pandas-based tools.

    Rows are fetched through the guarded connection and handed to pandas
    afterwards, rather than letting pandas talk to SQLite itself: the
    authorizer refuses the introspection some drivers perform, and this keeps
    a single, auditable path to the data.
    """
    import pandas as pd

    with tenant_connection(ctx, db_path) as con:
        rows = con.execute(f"SELECT * FROM {TENANT_VIEW}").fetchall()  # noqa: S608 - constant
    return pd.DataFrame([dict(r) for r in rows], columns=list(COLUMNS))
