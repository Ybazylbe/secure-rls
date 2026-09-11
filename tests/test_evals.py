"""Tests for the measuring instrument itself.

An evaluation harness that scores wrongly is worse than none: it produces a
number people then trust. These tests run without a language model -- they
check the scoring, the ground truth and the report, not the agent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.golden import CASES, matches_name, matches_number, numbers_in
from evals.report import markdown
from evals.runner import (
    AttackResult,
    CaseResult,
    SuiteResult,
    context_for,
    percent,
    truth_frame,
)

# --------------------------------------------------------------------------
# The question set is well formed
# --------------------------------------------------------------------------


def test_case_ids_are_unique() -> None:
    ids = [case.id for case in CASES]
    assert len(ids) == len(set(ids))


def test_every_expectation_can_be_computed_for_every_tenant(db_path: Path) -> None:
    """A case that raises on one tenant's data would score as a silent failure."""
    for tenant in ("acme", "beta", "gamma"):
        frame = truth_frame(tenant, db_path)
        for case in CASES:
            if case.expected is None:
                assert case.kind == "refusal"
                continue
            value = case.expected(frame)
            assert value is not None, f"{case.id} produced no expectation for {tenant}"


def test_expectations_differ_between_tenants(db_path: Path) -> None:
    """If a question had the same answer everywhere it could not detect a leak."""
    numeric = [c for c in CASES if c.kind == "number" and c.expected]
    frames = {t: truth_frame(t, db_path) for t in ("acme", "beta", "gamma")}
    discriminating = [
        case
        for case in numeric
        if len({round(float(case.expected(f)), 2) for f in frames.values()}) == 3  # type: ignore[misc]
    ]
    assert len(discriminating) >= len(numeric) * 0.8, (
        "most numeric questions should have a different answer per tenant"
    )


# --------------------------------------------------------------------------
# Ground truth agrees with the guarded path
# --------------------------------------------------------------------------


def test_truth_and_guarded_paths_return_the_same_rows(db_path: Path, tenant: str) -> None:
    """The security layers must restrict the data, not alter it.

    Ground truth is read without any of them. If the two disagree, either the
    view is wrong or the evaluation is measuring the wrong thing -- and it
    matters which, so this is asserted rather than assumed.
    """
    from db import tenant_frame

    expected = truth_frame(tenant, db_path).sort_values("user_id").reset_index(drop=True)
    actual = tenant_frame(context_for(tenant), db_path).sort_values("user_id").reset_index(
        drop=True
    )
    assert list(actual["user_id"]) == list(expected["user_id"])
    assert actual["salary"].sum() == expected["salary"].sum()


def test_truth_frames_are_disjoint(db_path: Path) -> None:
    seen: set[int] = set()
    for tenant in ("acme", "beta", "gamma"):
        ids = set(truth_frame(tenant, db_path)["user_id"])
        assert not (ids & seen)
        seen |= ids


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("The average is $122,726.70.", [122726.70]),
        ("158 employees, 3.6 average", [158.0, 3.6]),
        ("no numbers here", []),
        ("Engineering: 122726", [122726.0]),
    ],
)
def test_numbers_are_extracted_from_prose(text: str, expected: list[float]) -> None:
    assert numbers_in(text) == expected


#: Tolerances match the runner: 1% for measured quantities, effectively exact
#: for counts, where "about 450 people" is not an acceptable answer to "how
#: many".
MEASURE, COUNT = 0.01, 0.0001


@pytest.mark.parametrize(
    ("answer", "target", "tolerance", "ok"),
    [
        ("The average is 122,726.70", 122726.70, MEASURE, True),
        ("roughly 122,727", 122726.70, MEASURE, True),   # rounding is not an error
        ("about 123,000", 122726.70, MEASURE, True),     # 0.2% out, still right
        ("around 130,000", 122726.70, MEASURE, False),   # 6% out
        ("the answer is 0", 0.0, MEASURE, True),
        ("450 employees", 450, COUNT, True),
        ("451 employees", 450, COUNT, False),            # counts are exact
        ("no idea", 450, COUNT, False),
    ],
)
def test_numeric_matching(answer: str, target: float, tolerance: float, ok: bool) -> None:
    assert matches_number(answer, target, tolerance) is ok


@pytest.mark.parametrize(
    ("answer", "target", "ok"),
    [
        ("The top department is Engineering.", "Engineering", True),
        ("engineering leads", "Engineering", True),
        ("Sofia Silva earns the most", "Sofia Silva", True),
        ("Sofia earns the most, ask Silva", "Sofia Silva", True),
        ("Marketing leads", "Engineering", False),
    ],
)
def test_name_matching(answer: str, target: str, ok: bool) -> None:
    assert matches_name(answer, target) is ok


def test_unmeasured_metrics_report_as_not_available() -> None:
    """0% and "not run" are different claims; the report must not conflate them."""
    empty = SuiteResult(model="none")
    assert empty.accuracy is None
    assert percent(empty.accuracy) == "n/a"
    assert empty.leak_rate == "n/a"


# --------------------------------------------------------------------------
# The report renders
# --------------------------------------------------------------------------


def _case(case_id: str, *, passed: bool, kind: str = "number") -> CaseResult:
    return CaseResult(
        case_id=case_id, kind=kind, tenant="acme", model="m", passed=passed,
        tool_ok=True, expected=1.0, answer="1.0", tools_used=("stats",), seconds=1.0,
    )


def test_report_renders_a_clean_run() -> None:
    suite = SuiteResult(
        model="m",
        cases=[_case("a", passed=True), _case("b", passed=True)],
        attacks=[
            AttackResult("x", "direct", "acme", "m", contained=True, evidence="ok", seconds=1.0)
        ],
    )
    text = markdown([suite])
    assert "**0/1**" in text
    assert "## Failures (0)" in text
    assert "None." in text


def test_report_surfaces_leaks_prominently() -> None:
    suite = SuiteResult(
        model="m",
        cases=[_case("a", passed=False)],
        attacks=[
            AttackResult("x", "direct", "acme", "m", contained=False,
                         evidence="rows from ['beta']", seconds=1.0)
        ],
    )
    text = markdown([suite])
    assert "**1 of 1 attacks leaked.**" in text
    assert "## Leaks" in text
    assert "## Failures (1)" in text
