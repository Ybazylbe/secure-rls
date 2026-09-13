"""Tests for the model benchmark's reasoning.

The benchmark ends in a recommendation, and a recommendation is a claim. These
check the claim is derived from the numbers rather than from the order the
models happened to run in -- without needing a model, so they run in CI.
"""

from __future__ import annotations

import pytest

from evals.benchmark import decide, markdown
from evals.runner import AttackResult, CaseResult, SuiteResult


def suite(
    model: str, *, passed: int, total: int = 10, seconds: float = 3.0, leaks: int = 0
) -> SuiteResult:
    cases = [
        CaseResult(
            case_id=f"c{i}", kind="number", tenant="acme", model=model,
            passed=i < passed, tool_ok=True, expected=1.0, answer="1.0",
            tools_used=("stats",), seconds=seconds,
        )
        for i in range(total)
    ]
    attacks = [
        AttackResult(
            attack_id=f"a{i}", category="direct", tenant="acme", model=model,
            contained=i >= leaks, evidence="", seconds=1.0,
        )
        for i in range(5)
    ]
    return SuiteResult(model=model, cases=cases, attacks=attacks)


def test_the_most_accurate_safe_model_wins() -> None:
    verdict = decide([suite("slow-but-right", passed=9), suite("fast-but-wrong", passed=5)])
    assert verdict.winner == "slow-but-right"


def test_a_leaking_model_cannot_win_however_good_it_is() -> None:
    """The rule that overrides every other number."""
    verdict = decide(
        [suite("leaky", passed=10, seconds=1.0, leaks=1), suite("honest", passed=6)]
    )
    assert verdict.winner == "honest"


def test_if_everything_leaks_nothing_is_recommended() -> None:
    verdict = decide([suite("a", passed=10, leaks=1), suite("b", passed=9, leaks=2)])
    assert verdict.winner == "none"
    assert "leaked" in verdict.reason


def test_latency_breaks_a_tie_on_accuracy() -> None:
    verdict = decide(
        [suite("slower", passed=8, seconds=9.0), suite("quicker", passed=8, seconds=2.0)]
    )
    assert verdict.winner == "quicker"


def test_a_near_tie_is_reported_as_a_trade_off_not_a_verdict() -> None:
    """Two points of accuracy is noise on one run of a hundred questions, and
    the report should say so rather than crown a winner by a hair.

    Scored over a hundred questions on purpose: the same two-point gap over ten
    questions is twenty points, which is not a tie at all.
    """
    verdict = decide(
        [
            suite("a", passed=88, total=100, seconds=9.0),
            suite("b", passed=86, total=100, seconds=2.0),
        ]
    )
    assert verdict.winner == "a"
    assert "licence and latency" in verdict.reason


def test_the_report_states_what_it_cannot_measure() -> None:
    text = markdown([suite("m", passed=9)], {"m": 12.0})
    assert "leak rate" in text.lower()
    assert "not theirs to affect" in text


@pytest.mark.parametrize("pct,expected", [(50, 3.0), (95, 3.0)])
def test_percentiles_on_a_flat_distribution(pct: int, expected: float) -> None:
    result = suite("m", passed=5, seconds=3.0)
    assert result._percentile(pct) == expected
