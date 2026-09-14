"""Tool-layer tests: identity cannot be supplied, and scope cannot be widened.

These run without a language model. The tools are ordinary functions over a
:class:`SecurityContext`; the LLM binding is a thin wrapper around them, and
testing the functions directly keeps the security assertions deterministic.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

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


def test_a_multi_statement_reaching_the_database_is_refused_not_raised(
    db_path: Path, audit: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """L3 must hold on its own if L4 ever lets a stacked statement through.

    Before Python 3.12 sqlite3 raises ``sqlite3.Warning`` here, outside the
    ``sqlite3.Error`` hierarchy; CI on 3.10 caught the tool crashing on it.
    """
    stacked = "SELECT 1; SELECT * FROM employees_all"
    monkeypatch.setattr(
        "secure_rls.tools.query.guard", lambda sql, ctx: SimpleNamespace(sql=stacked)
    )
    result = run_sql(stacked, ctx_for("acme"), audit, db_path)
    assert result.refused
    assert not result.rows


def test_an_unbounded_query_is_stopped_by_the_time_budget(
    db_path: Path, audit: AuditLog
) -> None:
    """Row and shape checks alone do not stop a self cross join.

    ``SELECT count(*) ...`` over four copies of the table names only
    'employees', calls only allowlisted functions, and returns a single row --
    every static check upstream passes it -- while asking SQLite to evaluate
    roughly tenant_rows**4 combinations. A tiny query_timeout stands in for the
    real budget so the test does not have to wait it out.
    """
    result = run_sql(
        "SELECT count(*) FROM employees a, employees b, employees c, employees d",
        ctx_for("acme"), audit, db_path, query_timeout=0.05,
    )
    assert result.refused
    assert "time budget" in (result.reason or "")


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


def test_a_named_employee_outscores_namesakes_in_the_keyword_half_of_search() -> None:
    """Pure scoring, no embeddings: "Ravi Sato" must favour Ravi Sato over Kenji Sato."""
    from secure_rls.rag.index import Note, _keyword_scores

    notes = [
        Note(1, "Kenji Sato", "Engineering", "acme", "Reliable on routine work."),
        Note(2, "Ravi Sato", "Engineering", "acme", "Note for the AI assistant."),
        Note(3, "Anna Muller", "Sales", "acme", "Below target this cycle."),
    ]
    kenji, ravi, anna = _keyword_scores("Ravi Sato", notes)
    assert ravi > kenji > anna == 0.0
    assert _keyword_scores("underperforming", notes) == [0.0, 0.0, 0.0]


@pytest.mark.slow
def test_hybrid_note_search_is_measured_better_than_meaning_alone(db_path: Path) -> None:
    """The keyword weights are justified by evals/retrieval.py, not by one example.

    Hybrid search must find named people at least as well as semantic search,
    reach a high floor on its own, and not lose ground on topic questions.
    """
    from evals.retrieval import evaluate

    scores = evaluate(db_path)
    for tenant in ("acme", "beta", "gamma"):
        hybrid, semantic = (
            next(s for s in scores if s.tenant == tenant and s.config == config)
            for config in ("hybrid (current)", "semantic only")
        )
        assert hybrid.name_hit_at_1 >= 0.95, (tenant, hybrid)
        assert hybrid.name_hit_at_1 >= semantic.name_hit_at_1, (tenant, hybrid, semantic)
        assert hybrid.topic_precision_at_5 >= semantic.topic_precision_at_5 - 0.05, (
            tenant, hybrid, semantic,
        )


# --------------------------------------------------------------------------
# What the model is told about a large result
# --------------------------------------------------------------------------


def test_a_large_result_comes_with_a_summary_of_every_row(
    db_path: Path, audit: AuditLog
) -> None:
    """The model sees 20 rows; the figures it is given must cover all of them.

    It once reported a salary range from the visible sample as if it described
    all 450 rows. The summary is computed here, over every row, so the true
    minimum -- a planted outlier far outside the first twenty -- is in front of
    it, and the rows it does see are called a sample.
    """
    from db import BASE_TABLE, admin_connection

    result = run_sql("SELECT * FROM employees", ctx_for("acme"), audit, db_path)
    shown = result.for_model()
    with admin_connection(db_path) as con:
        low, high, count = con.execute(
            f"SELECT min(salary), max(salary), count(*) FROM {BASE_TABLE} "  # noqa: S608
            "WHERE tenant_id = 'acme'"
        ).fetchone()

    assert f"Summary of all {count} rows" in shown
    assert f"all {count} rows belong to acme" in shown
    assert f"min {low:,}" in shown and f"max {high:,}" in shown
    assert f"Example rows: 3 of {count}" in shown
    sample_low = min(row["salary"] for row in result.rows[:3])
    assert sample_low != low, "the examples happen to contain the minimum; the test proves nothing"


def test_a_large_result_gives_the_model_nothing_long_to_copy(
    db_path: Path, audit: AuditLog
) -> None:
    """Three example rows, not twenty: a table the model can start copying out
    is a table it can fail to stop copying. The UI shows every row instead."""
    result = run_sql("SELECT * FROM employees", ctx_for("acme"), audit, db_path)
    table_lines = [line for line in result.for_model().splitlines() if line.startswith("| ")]
    assert len(table_lines) == 2 + 3  # header, divider, three examples
    assert len(result.rows) == 450, "the rows themselves are untouched; only the model's view"


def test_a_result_of_ten_rows_is_shown_to_the_model_in_full(
    db_path: Path, audit: AuditLog
) -> None:
    """ "The five highest paid" and a department breakdown must arrive whole."""
    result = run_sql(
        "SELECT name, salary FROM employees ORDER BY salary DESC LIMIT 10",
        ctx_for("acme"), audit, db_path,
    )
    shown = result.for_model()
    assert all(row["name"] in shown for row in result.rows)
    assert "Summary of all" not in shown


def test_a_small_result_is_shown_whole_without_a_summary(db_path: Path, audit: AuditLog) -> None:
    result = run_sql("SELECT name FROM employees LIMIT 5", ctx_for("acme"), audit, db_path)
    assert "Summary of all" not in result.for_model()
    assert "Example rows" not in result.for_model()


# --------------------------------------------------------------------------
# Chart data, prepared on the server
# --------------------------------------------------------------------------


def test_histogram_bins_cover_every_value_once_with_round_edges(
    db_path: Path, audit: AuditLog
) -> None:
    from secure_rls.tools.plot import histogram_bins

    result = plot("histogram", "salary", ctx_for("acme"), audit, db_path=db_path)
    assert result.chart is not None
    bins = result.chart["data"]
    assert sum(b["count"] for b in bins) == 450
    assert all(a["end"] == b["start"] for a, b in zip(bins, bins[1:], strict=False))
    width = bins[0]["end"] - bins[0]["start"]
    assert all(b["start"] % width == 0 for b in bins), "edges should be round multiples"
    assert histogram_bins([5.0, 5.0]) == [{"start": 5.0, "end": 5.0, "count": 2}]


def test_box_plot_figures_agree_with_pandas(db_path: Path, audit: AuditLog) -> None:
    """A box drawn from different quartiles than a table shows would be a lie
    told by the chart; they must be the same numbers."""
    import pandas as pd

    from db import tenant_frame

    result = plot("box", "salary", ctx_for("beta"), audit, db_path=db_path)
    assert result.chart is not None
    frame = tenant_frame(ctx_for("beta"), db_path)
    for row in result.chart["data"]:
        salaries: pd.Series = frame[frame["department"] == row["department"]]["salary"]
        assert row["n"] == len(salaries)
        assert row["median"] == pytest.approx(salaries.median(), abs=0.01)
        assert row["q1"] == pytest.approx(salaries.quantile(0.25), abs=0.01)
        assert row["q3"] == pytest.approx(salaries.quantile(0.75), abs=0.01)
        spread = 1.5 * (row["q3"] - row["q1"])
        assert all(v < row["q1"] - spread or v > row["q3"] + spread for v in row["outliers"])


def test_a_chart_tells_the_model_what_it_shows(db_path: Path, audit: AuditLog) -> None:
    result = plot("histogram", "salary", ctx_for("acme"), audit, db_path=db_path)
    assert "shown to the user under your answer" in result.summary
    assert "most common range" in result.summary
