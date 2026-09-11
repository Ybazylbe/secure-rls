"""Tests for the grounding check.

The check exists because the evaluation suite caught the agent inventing a
department and a headcount after receiving an ungrouped total. These tests pin
the two things that matter: an invented figure is caught, and a legitimate
answer is not second-guessed. The second is the harder half -- a grounding
check that fires on correct answers would train everyone to ignore it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from secure_rls.grounding import correction_for, numbers_in, ungrounded_numbers


@dataclass
class _Result:
    rows: tuple[dict[str, Any], ...] = ()
    summary: str = ""


@dataclass
class _Step:
    result: _Result | None


def steps_with(*, rows: tuple[dict[str, Any], ...] = (), summary: str = "") -> list[Any]:
    return [_Step(_Result(rows=rows, summary=summary))]


DEPARTMENT_ROWS = (
    {"department": "Engineering", "employees": 158},
    {"department": "Sales", "employees": 82},
    {"department": "Support", "employees": 75},
)


def test_figures_taken_from_a_tool_result_are_grounded() -> None:
    steps = steps_with(rows=DEPARTMENT_ROWS, summary="headcount by department, 3 groups.")
    assert ungrounded_numbers("Engineering leads with 158, then Sales at 82.", steps) == []


def test_an_invented_figure_is_caught() -> None:
    """The exact failure the evaluation suite found."""
    steps = steps_with(rows=({"employees": 450},), summary="450 employee(s) in all departments.")
    assert ungrounded_numbers("Sales has the most, with 150 employees.", steps) == [150.0]


def test_rounding_is_not_treated_as_invention() -> None:
    steps = steps_with(rows=({"avg_salary": 122726.70},))
    assert ungrounded_numbers("about 122,727", steps) == []


def test_list_markers_are_not_claims() -> None:
    steps = steps_with(rows=DEPARTMENT_ROWS)
    assert ungrounded_numbers("1. Engineering 158\n2. Sales 82\n3. Support 75", steps) == []


def test_numbers_quoted_from_the_question_are_allowed() -> None:
    """Echoing the threshold back is not a claim about the data."""
    steps = steps_with(rows=({"employees": 12},))
    question = "How many employees score 4.5 or above?"
    assert ungrounded_numbers("12 employees score 4.5 or above.", steps, question) == []


def test_figures_inside_returned_text_count_as_support() -> None:
    steps = steps_with(rows=({"notes": "Salary reviewed at 98,500 last cycle."},))
    assert ungrounded_numbers("Their note mentions 98,500.", steps) == []


def test_an_answer_with_no_tools_and_no_numbers_is_fine() -> None:
    assert ungrounded_numbers("I cannot answer that.", []) == []


def test_an_answer_with_no_tools_but_hard_figures_is_not() -> None:
    assert ungrounded_numbers("The average salary is 98,110.", []) == [98110.0]


@pytest.mark.parametrize(
    ("text", "expected"),
    [("$122,726.70", [122726.70]), ("no digits", []), ("-3.5 and 2020", [-3.5, 2020.0])],
)
def test_number_parsing(text: str, expected: list[float]) -> None:
    assert numbers_in(text) == expected


def test_the_correction_names_the_offending_figures_and_the_likely_cause() -> None:
    message = correction_for([150.0, 85000.0])
    assert "150" in message
    assert "85,000" in message
    assert "group_by" in message
