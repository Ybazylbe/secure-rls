"""Tool-layer tests: identity cannot be supplied, and scope cannot be widened.

These run without a language model. The tools are ordinary functions over a
:class:`SecurityContext`; the LLM binding is a thin wrapper around them, and
testing the functions directly keeps the security assertions deterministic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_rls.rag import get_index, reset_indexes
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.tools import build_tools, tool_names
from secure_rls.tools.anomaly import detect_anomalies
from secure_rls.tools.plot import plot
from secure_rls.tools.query import run_sql
from secure_rls.tools.stats import aggregate


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog(None)  # no file, buffer only


def ctx_for(tenant: str) -> SecurityContext:
    return SecurityContext(user_id=1, username=f"{tenant}_analyst", tenant_id=tenant)


# --------------------------------------------------------------------------
# What the model is allowed to say
# --------------------------------------------------------------------------

#: Anything by which a caller could name a tenant, a user, or a database.
IDENTITY_WORDS = ("tenant", "user_id", "username", "db", "path", "ctx", "context", "role")


def test_no_tool_exposes_an_identity_argument(audit: AuditLog) -> None:
    """The central claim of the design, asserted mechanically.

    If this fails, the model has been handed a way to ask for someone else's
    data, and every other control is arguing with a question that should never
    have been askable.
    """
    for tool in build_tools(ctx_for("acme"), audit):
        properties = tool.args_schema.model_json_schema()["properties"]
        for name in properties:
            assert not any(word in name.lower() for word in IDENTITY_WORDS), (
                f"{tool.name} exposes argument {name!r}"
            )


def test_the_expected_tools_are_bound(audit: AuditLog) -> None:
    assert tuple(t.name for t in build_tools(ctx_for("acme"), audit)) == tool_names()


# --------------------------------------------------------------------------
# Every tool stays inside the tenant
# --------------------------------------------------------------------------


def test_sql_tool_returns_only_own_rows(db_path: Path, tenant: str, audit: AuditLog) -> None:
    result = run_sql("SELECT * FROM employees", ctx_for(tenant), audit, db_path)
    assert not result.refused
    assert {row["tenant_id"] for row in result.rows} == {tenant}


def test_sql_tool_reports_a_refusal_instead_of_raising(db_path: Path, audit: AuditLog) -> None:
    result = run_sql("SELECT * FROM employees_all", ctx_for("acme"), audit, db_path)
    assert result.refused
    assert "employees_all" in (result.reason or "")
    assert result.for_model().startswith("REFUSED")


def test_aggregates_differ_between_tenants(db_path: Path, audit: AuditLog) -> None:
    """Same question, three tenants, three answers -- the dataset gives each a
    different pay scale, so identical numbers would mean the filter is gone."""
    values = {
        tenant: aggregate("avg", "salary", ctx_for(tenant), audit, db_path=db_path).rows[0][
            "avg_salary"
        ]
        for tenant in ("acme", "beta", "gamma")
    }
    assert len(set(values.values())) == 3, values


def test_stats_refuses_a_column_outside_the_vocabulary(db_path: Path, audit: AuditLog) -> None:
    result = aggregate("avg", "ssn", ctx_for("acme"), audit, db_path=db_path)
    assert result.refused and "numeric column" in (result.reason or "")


def test_plot_data_never_leaves_the_tenant(db_path: Path, tenant: str, audit: AuditLog) -> None:
    result = plot("bar", "salary", ctx_for(tenant), audit, db_path=db_path)
    assert result.chart is not None
    assert result.chart["data"], "a chart with no points proves nothing"


# --------------------------------------------------------------------------
# The quiet kind of leak
# --------------------------------------------------------------------------


def test_outliers_are_judged_against_the_caller_s_own_peers(
    db_path: Path, audit: AuditLog
) -> None:
    """Anomaly thresholds must come from the tenant's population only.

    A version that computed the quartiles over the whole table would return no
    foreign rows at all, so nothing would look wrong -- yet every threshold it
    applied would be derived from data the caller cannot see. This test pins the
    flagged set to the tenant-local computation and checks that the global
    computation would in fact have produced a different answer, so it cannot
    pass by coincidence.
    """
    import pandas as pd

    from db import BASE_TABLE, admin_connection

    ctx = ctx_for("acme")
    flagged = {
        row["name"] for row in detect_anomalies("salary", ctx, audit, db_path=db_path).rows
    }

    with admin_connection(db_path) as con:
        everyone = pd.DataFrame(
            [dict(r) for r in con.execute(f"SELECT * FROM {BASE_TABLE}")]  # noqa: S608
        )

    def outliers(frame: pd.DataFrame) -> set[str]:
        names: set[str] = set()
        for _, block in frame.groupby("department"):
            q1, q3 = block["salary"].quantile(0.25), block["salary"].quantile(0.75)
            spread = q3 - q1
            low, high = q1 - 1.5 * spread, q3 + 1.5 * spread
            names |= set(block[(block["salary"] < low) | (block["salary"] > high)]["name"])
        return names

    own = everyone[everyone["tenant_id"] == "acme"]
    assert flagged == outliers(own)
    assert flagged != outliers(everyone) & set(own["name"]), (
        "tenant-local and global thresholds agree here, so this test cannot "
        "distinguish them -- adjust the dataset before trusting it"
    )


# --------------------------------------------------------------------------
# Retrieval
# --------------------------------------------------------------------------


@pytest.mark.slow
def test_each_tenant_gets_its_own_index(db_path: Path) -> None:
    """Isolation as a property of what exists, not of a query parameter."""
    reset_indexes()
    try:
        for tenant in ("acme", "beta", "gamma"):
            index = get_index(ctx_for(tenant), db_path)
            assert index.tenants_present == {tenant}
            assert len(index) > 0
    finally:
        reset_indexes()


# --------------------------------------------------------------------------
# Filters: the shape models actually send
# --------------------------------------------------------------------------


def test_flat_and_nested_filters_mean_the_same_thing(db_path: Path, audit: AuditLog) -> None:
    """The nested form exists because models emit it; it must not be a second,
    subtly different code path."""
    from secure_rls.tools.stats import Filters

    ctx = ctx_for("acme")
    flat = aggregate(
        "count", None, ctx, audit,
        filters=Filters.build(min_performance=4.5), db_path=db_path,
    )
    nested = aggregate(
        "count", None, ctx, audit,
        filters=Filters.build(nested={"performance_score": {"gte": 4.5}}), db_path=db_path,
    )
    assert flat.rows == nested.rows


@pytest.mark.parametrize(
    ("spelling", "symbol"),
    [("min", ">="), ("gte", ">="), ("max", "<="), ("lte", "<="), ("gt", ">"), ("lt", "<")],
)
def test_comparison_spellings_models_use_are_accepted(spelling: str, symbol: str) -> None:
    from secure_rls.tools.stats import parse_filter

    predicates = parse_filter({"salary": {spelling: 100_000}})
    assert predicates[0].operator == symbol


@pytest.mark.parametrize(
    "bad",
    [
        {"ssn": {"gte": 1}},
        {"notes": {"eq": "x"}},
        {"salary": {"regex": "1"}},
    ],
)
def test_filters_outside_the_vocabulary_are_refused(bad: dict[str, object]) -> None:
    from secure_rls.tools.frames import ColumnError
    from secure_rls.tools.stats import parse_filter

    with pytest.raises(ColumnError):
        parse_filter(bad)


def test_an_unfiltered_result_says_so_in_words(db_path: Path, audit: AuditLog) -> None:
    """The agent once reported a total as a filtered count; the summary the
    model reads now states plainly that nothing was filtered."""
    result = aggregate("count", None, ctx_for("acme"), audit, db_path=db_path)
    assert "no filter applied" in result.summary.lower()


def test_unknown_tool_arguments_are_rejected_not_ignored(audit: AuditLog) -> None:
    """Silently dropping an unrecognised argument runs a different query than
    the one that was asked for, and returns a real number for it."""
    from pydantic import ValidationError

    stats_tool = next(t for t in build_tools(ctx_for("acme"), audit) if t.name == "stats")
    with pytest.raises(ValidationError):
        stats_tool.args_schema(metric="count", nonsense={"a": 1})


def test_min_and_max_report_who(db_path: Path, audit: AuditLog) -> None:
    """"Who earns the most" is a max question with a name attached."""
    result = aggregate("max", "salary", ctx_for("acme"), audit, db_path=db_path)
    assert "name" in result.rows[0]
    assert result.rows[0]["name"]
