"""Layer L4 tests: model-generated SQL is vetted and rewritten before execution."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlglot import exp, parse_one

from db import TENANT_VIEW, tenant_connection
from secure_rls.security.context import SecurityContext
from secure_rls.security.sql_guard import MAX_ROWS, GuardedQuery, SqlGuardError, guard


def ctx_for(tenant: str) -> SecurityContext:
    return SecurityContext(user_id=1, username=f"{tenant}_analyst", tenant_id=tenant)


# --------------------------------------------------------------------------
# Queries an analyst would actually write must not be refused. A guard with
# false positives gets switched off, so this list is as load-bearing as the
# attack list below.
# --------------------------------------------------------------------------

ANALYTICAL_QUERIES = [
    "SELECT avg(salary) FROM employees WHERE department = 'Engineering'",
    "SELECT department, round(avg(salary), 2) AS avg_sal, count(*) AS n "
    "FROM employees GROUP BY department ORDER BY avg_sal DESC",
    "SELECT name, salary FROM employees ORDER BY salary DESC LIMIT 5",
    "SELECT strftime('%Y', hire_date) AS yr, count(*) AS hires "
    "FROM employees GROUP BY yr ORDER BY yr",
    "WITH top AS (SELECT * FROM employees WHERE performance_score >= 4.5) "
    "SELECT department, count(*) FROM top GROUP BY department",
    "SELECT e.name, e.salary FROM employees e "
    "WHERE e.salary > (SELECT avg(salary) FROM employees)",
    "SELECT department, sum(CASE WHEN performance_score >= 4 THEN 1 ELSE 0 END) AS strong "
    "FROM employees GROUP BY department",
    "SELECT name, CAST(salary AS REAL) / 12 AS monthly FROM employees "
    "WHERE department LIKE 'Eng%'",
    "SELECT max(salary) - min(salary) AS spread FROM employees",
    "SELECT e.name FROM employees e JOIN employees f ON e.user_id = f.user_id",
]


@pytest.mark.parametrize("sql", ANALYTICAL_QUERIES)
def test_ordinary_analytics_is_allowed(sql: str) -> None:
    assert isinstance(guard(sql, ctx_for("acme")), GuardedQuery)


@pytest.mark.parametrize("sql", ANALYTICAL_QUERIES)
def test_every_scope_reading_employees_gets_a_tenant_predicate(sql: str) -> None:
    """Regression guard for a silent failure.

    An earlier version located the FROM clause by argument name. sqlglot renamed
    that key, the lookup started returning None, and the rewrite was skipped
    without any error -- the worst possible outcome for a security control. This
    test counts scopes instead of trusting the code path.
    """
    guarded = guard(sql, ctx_for("acme"))
    tree = parse_one(guarded.sql, dialect="sqlite")

    for select in tree.find_all(exp.Select):
        reads_employees = any(
            table.name.lower() == "employees"
            for child in select.iter_expressions()
            if isinstance(child, exp.From | exp.Join)
            for table in child.find_all(exp.Table)
        )
        if not reads_employees:
            continue
        where = select.args.get("where")
        assert where is not None, f"scope without WHERE: {select.sql('sqlite')}"
        assert "tenant_id = 'acme'" in where.sql("sqlite")


# --------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------

REFUSED = [
    pytest.param("SELECT * FROM employees_all", "table", id="base-table"),
    pytest.param("SELECT * FROM main.employees_all", "table", id="qualified-base-table"),
    pytest.param(
        "SELECT * FROM employees UNION ALL SELECT * FROM employees_all", "table", id="union"
    ),
    pytest.param("SELECT name FROM sqlite_master", "table", id="schema-introspection"),
    pytest.param(
        "SELECT * FROM employees; DROP TABLE employees_all", "one statement", id="stacked"
    ),
    pytest.param("DELETE FROM employees", "read-only", id="delete"),
    pytest.param("UPDATE employees SET salary = 0", "read-only", id="update"),
    pytest.param("DROP TABLE employees", "read-only", id="drop"),
    pytest.param("PRAGMA table_list", "read-only", id="pragma"),
    pytest.param("ATTACH DATABASE 'exfil.db' AS x", "read-only", id="attach"),
    pytest.param("SELECT load_extension('evil.so')", "function", id="load-extension"),
    pytest.param("SELECT readfile('/etc/passwd')", "function", id="readfile"),
    pytest.param("SELECT ssn FROM employees", "column", id="unknown-column"),
    pytest.param("", "empty", id="empty"),
    pytest.param("this is not sql at all", "parse", id="garbage"),
]


@pytest.mark.parametrize(("sql", "expected_reason"), REFUSED)
def test_hostile_or_invalid_sql_is_refused(sql: str, expected_reason: str) -> None:
    with pytest.raises(SqlGuardError) as excinfo:
        guard(sql, ctx_for("acme"))
    assert expected_reason in excinfo.value.reason, excinfo.value.reason


# --------------------------------------------------------------------------
# Asking for another tenant by name
# --------------------------------------------------------------------------

FOREIGN_TENANT_FILTERS = [
    pytest.param("SELECT salary FROM employees WHERE tenant_id = 'beta'", id="equals"),
    pytest.param("SELECT salary FROM employees WHERE 'gamma' = tenant_id", id="equals-reversed"),
    pytest.param(
        "SELECT salary FROM employees WHERE tenant_id IN ('beta', 'gamma')", id="in-list"
    ),
    pytest.param(
        "SELECT salary FROM employees WHERE tenant_id IN ('acme', 'beta')", id="in-list-mixed"
    ),
    pytest.param(
        "SELECT * FROM (SELECT * FROM employees WHERE tenant_id = 'beta') AS t", id="subquery"
    ),
    pytest.param("SELECT * FROM employees WHERE tenant_id = 'xyz'", id="unknown-tenant"),
    pytest.param("SELECT * FROM employees WHERE TENANT_ID = 'BETA'", id="case"),
]


@pytest.mark.parametrize("sql", FOREIGN_TENANT_FILTERS)
def test_selecting_another_tenant_is_refused_with_a_reason_that_cannot_be_misread(
    sql: str,
) -> None:
    """Refused, rather than rewritten into an empty result.

    The rewrite alone turned ``tenant_id IN ('beta', 'gamma')`` into
    ``... AND tenant_id = 'acme'``, which returned nothing -- and the model
    reported that beta and gamma "have no employees". An empty result looks like
    an answer; a refusal that says only acme is visible does not.
    """
    with pytest.raises(SqlGuardError) as excinfo:
        guard(sql, ctx_for("acme"))
    reason = excinfo.value.reason
    assert "only query acme" in reason, reason
    assert "says nothing about" in reason, reason


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM employees WHERE tenant_id = 'acme'",
        "SELECT * FROM employees WHERE tenant_id IN ('acme')",
        "SELECT * FROM employees WHERE tenant_id <> 'beta'",
        "SELECT * FROM employees WHERE notes LIKE '%beta%'",
        "SELECT * FROM employees WHERE name = 'beta'",
    ],
    ids=["own-equals", "own-in", "not-equal", "text-mentions-beta", "other-column"],
)
def test_filters_that_do_not_select_another_tenant_are_left_alone(sql: str) -> None:
    guard(sql, ctx_for("acme"))


# --------------------------------------------------------------------------
# Rewrites
# --------------------------------------------------------------------------


def test_unbounded_queries_are_capped() -> None:
    guarded = guard("SELECT * FROM employees", ctx_for("acme"))
    assert f"LIMIT {MAX_ROWS}" in guarded.sql
    assert any("capped" in note for note in guarded.rewrites)


def test_an_oversized_limit_is_lowered() -> None:
    guarded = guard("SELECT * FROM employees LIMIT 99999", ctx_for("acme"))
    assert f"LIMIT {MAX_ROWS}" in guarded.sql


def test_a_modest_limit_is_left_alone() -> None:
    guarded = guard("SELECT * FROM employees LIMIT 5", ctx_for("acme"))
    assert "LIMIT 5" in guarded.sql


def test_comments_cannot_disguise_the_rewrite() -> None:
    """A trailing comment must not survive into the SQL shown to the user."""
    guarded = guard(
        "SELECT * FROM employees WHERE 1=1 -- AND tenant_id='beta'", ctx_for("acme")
    )
    assert "--" not in guarded.sql
    assert "beta" not in guarded.sql
    assert "tenant_id = 'acme'" in guarded.sql


# --------------------------------------------------------------------------
# The guard and the database agree
# --------------------------------------------------------------------------


@pytest.mark.parametrize("sql", ANALYTICAL_QUERIES)
def test_guarded_queries_execute_and_stay_in_tenant(db_path: Path, tenant: str, sql: str) -> None:
    ctx = ctx_for(tenant)
    guarded = guard(sql, ctx)
    with tenant_connection(ctx, db_path) as con:
        rows = con.execute(guarded.sql).fetchall()
    for row in rows:
        # sqlite3.Row membership tests values, not column names, so `.keys()`
        # is required here rather than stylistic.
        if "tenant_id" in row.keys():  # noqa: SIM118
            assert row["tenant_id"] == tenant


def test_a_refused_query_is_also_refused_by_the_database(db_path: Path) -> None:
    """L4 and L3 must not disagree: what the guard blocks, SQLite blocks too."""
    import sqlite3

    ctx = ctx_for("acme")
    sql = f"SELECT * FROM {TENANT_VIEW} UNION ALL SELECT * FROM employees_all"
    with pytest.raises(SqlGuardError):
        guard(sql, ctx)
    with tenant_connection(ctx, db_path) as con, pytest.raises(sqlite3.Error):
        con.execute(sql).fetchall()
