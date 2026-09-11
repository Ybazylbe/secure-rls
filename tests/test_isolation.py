"""Layer L2/L3 tests: no statement may observe another tenant's rows.

These are the tests that define the product. They run against real SQL sent to
a real connection -- not against a mocked helper -- because the guarantee being
asserted is a property of the connection, not of our Python wrappers.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from db import BASE_TABLE, TENANT_VIEW, admin_connection, row_count, tenant_connection
from secure_rls.security.context import TENANTS, SecurityContext, TenantError


def ctx_for(tenant: str) -> SecurityContext:
    return SecurityContext(user_id=1, username=f"{tenant}_analyst", tenant_id=tenant)


# --------------------------------------------------------------------------
# The dataset is actually partitioned
# --------------------------------------------------------------------------


def test_tenant_slices_are_disjoint_and_complete(db_path: Path) -> None:
    with admin_connection(db_path) as con:
        total = con.execute(f"SELECT count(*) FROM {BASE_TABLE}").fetchone()[0]

    seen: set[int] = set()
    per_tenant = {}
    for tenant in TENANTS:
        with tenant_connection(ctx_for(tenant), db_path) as con:
            ids = {r[0] for r in con.execute(f"SELECT user_id FROM {TENANT_VIEW}")}
        assert not (ids & seen), f"{tenant} overlaps another tenant"
        seen |= ids
        per_tenant[tenant] = len(ids)

    assert sum(per_tenant.values()) == total
    assert all(count > 0 for count in per_tenant.values())


def test_view_never_exposes_a_foreign_tenant_id(db_path: Path, tenant: str) -> None:
    with tenant_connection(ctx_for(tenant), db_path) as con:
        tenants = {r[0] for r in con.execute(f"SELECT DISTINCT tenant_id FROM {TENANT_VIEW}")}
    assert tenants == {tenant}


# --------------------------------------------------------------------------
# Attempts to break out
# --------------------------------------------------------------------------

#: Statements that must not raise but must also not widen the result set.
#: Every one of these is a real bypass against a string-concatenated
#: "... AND tenant_id = ?" implementation.
PREDICATE_BYPASSES = [
    f"SELECT * FROM {TENANT_VIEW} WHERE 1=1 OR tenant_id <> 'acme'",
    f"SELECT * FROM {TENANT_VIEW} WHERE tenant_id IS NOT NULL",
    f"SELECT * FROM {TENANT_VIEW} WHERE salary > 0 OR 1=1",
    f"SELECT * FROM {TENANT_VIEW} WHERE tenant_id LIKE '%'",
    f"SELECT * FROM {TENANT_VIEW} WHERE tenant_id IN ('acme','beta','gamma')",
    f"WITH everyone AS (SELECT * FROM {TENANT_VIEW}) SELECT * FROM everyone",
    f"SELECT * FROM {TENANT_VIEW} UNION ALL SELECT * FROM {TENANT_VIEW}",
]


@pytest.mark.parametrize("sql", PREDICATE_BYPASSES)
def test_predicate_tricks_cannot_widen_the_slice(db_path: Path, tenant: str, sql: str) -> None:
    with tenant_connection(ctx_for(tenant), db_path) as con:
        rows = con.execute(sql).fetchall()
    assert rows, "query should still return the tenant's own data"
    assert {r["tenant_id"] for r in rows} == {tenant}


#: Statements that must be refused outright by the authorizer (L3).
BLOCKED_STATEMENTS = [
    pytest.param(f"SELECT * FROM {BASE_TABLE}", id="direct-base-table"),
    pytest.param(f"SELECT count(*) FROM {BASE_TABLE}", id="aggregate-base-table"),
    pytest.param(
        f"SELECT * FROM {TENANT_VIEW} UNION ALL SELECT * FROM {BASE_TABLE}",
        id="union-with-base-table",
    ),
    pytest.param(
        f"SELECT (SELECT count(*) FROM {BASE_TABLE}) AS n FROM {TENANT_VIEW}",
        id="subquery-base-table",
    ),
    pytest.param("SELECT name FROM sqlite_master", id="schema-introspection"),
    pytest.param("PRAGMA table_list", id="pragma"),
    pytest.param("ATTACH DATABASE 'exfil.db' AS x", id="attach"),
    pytest.param(f"DELETE FROM {BASE_TABLE}", id="delete"),
    pytest.param(f"UPDATE {BASE_TABLE} SET salary = 0", id="update"),
    pytest.param(f"DROP VIEW {TENANT_VIEW}", id="drop-view"),
    pytest.param(f"CREATE TEMP VIEW leak AS SELECT * FROM {BASE_TABLE}", id="redefine-view"),
    pytest.param("SELECT load_extension('evil.so')", id="load-extension"),
]


@pytest.mark.parametrize("sql", BLOCKED_STATEMENTS)
def test_authorizer_blocks_escape_attempts(db_path: Path, sql: str) -> None:
    denials: list[str] = []
    with tenant_connection(ctx_for("acme"), db_path, on_deny=denials.append) as con:
        with pytest.raises(sqlite3.Error):
            con.execute(sql).fetchall()
    assert denials, "a refusal should always be recorded for the audit log"


def test_multi_statement_payload_is_rejected(db_path: Path) -> None:
    """``sqlite3`` refuses multiple statements in one ``execute`` call."""
    with tenant_connection(ctx_for("acme"), db_path) as con:
        with pytest.raises(sqlite3.Error):
            con.execute(f"SELECT 1; SELECT * FROM {BASE_TABLE}")


def test_connection_is_read_only(db_path: Path) -> None:
    with tenant_connection(ctx_for("acme"), db_path) as con:
        with pytest.raises(sqlite3.Error):
            con.execute("CREATE TABLE scratch(x INT)")


# --------------------------------------------------------------------------
# Session hygiene
# --------------------------------------------------------------------------


def test_views_do_not_leak_between_concurrent_sessions(db_path: Path) -> None:
    """Two open sessions each keep their own temp view."""
    with tenant_connection(ctx_for("acme"), db_path) as acme_con:
        with tenant_connection(ctx_for("beta"), db_path) as beta_con:
            acme = {r[0] for r in acme_con.execute(f"SELECT tenant_id FROM {TENANT_VIEW}")}
            beta = {r[0] for r in beta_con.execute(f"SELECT tenant_id FROM {TENANT_VIEW}")}
    assert acme == {"acme"}
    assert beta == {"beta"}


def test_row_count_matches_the_view(db_path: Path, tenant: str) -> None:
    with tenant_connection(ctx_for(tenant), db_path) as con:
        expected = con.execute(f"SELECT count(*) FROM {TENANT_VIEW}").fetchone()[0]
    assert row_count(ctx_for(tenant), db_path) == expected


@pytest.mark.parametrize(
    "bad_tenant",
    ["", "ACME", "delta", "acme' OR '1'='1", "acme; DROP TABLE employees_all", "%"],
)
def test_unknown_tenants_are_refused_at_construction(bad_tenant: str) -> None:
    """The tenant id reaches SQL as a literal, so the allowlist is load-bearing."""
    with pytest.raises(TenantError):
        SecurityContext(user_id=1, username="mallory", tenant_id=bad_tenant)
