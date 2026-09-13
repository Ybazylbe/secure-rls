"""Regression tests built from real answers.

In plain terms: every answer-quality fault seen in a demo, and every false
alarm an earlier check raised on an ordinary sentence, is kept in
``fixtures/answers.json`` with the verdict the checks must reach. Changing a
check so that it catches a new fault cannot silently break an old one, or
start flagging normal answers again.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent import Step
from secure_rls.grounding import (
    TABLE_OMITTED,
    claimed_tenants,
    remove_model_tables,
    scope_correction,
    written_tool_call,
)
from secure_rls.tools.base import ToolResult

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "answers.json").read_text())["cases"]


def steps_for(case: dict[str, Any]) -> list[Step]:
    if case["rows_from"] is None:
        return []
    rows = ({"tenant_id": case["rows_from"], "name": "someone"},)
    return [Step("query_db", {}, ToolResult(summary="", rows=rows), executed=True)]


@pytest.mark.parametrize("case", FIXTURES, ids=lambda c: c["id"])
def test_answer_quality_checks_agree_with_the_recorded_verdict(case: dict[str, Any]) -> None:
    steps = steps_for(case)
    expect = case["expect"]
    tenant = case["tenant"]

    misattributed = scope_correction(case["question"], case["answer"], steps, tenant) is not None
    assert misattributed is expect["misattributed"], "scope check disagrees"

    written = not steps and written_tool_call(case["answer"]) is not None
    assert written is expect["written_call"], "written-call check disagrees"

    returned = {case["rows_from"]} if case["rows_from"] else set()
    labelled = [t for t in claimed_tenants(case["answer"], tenant) if t not in returned]
    assert labelled == expect["labelled_tenants"], "table/label check disagrees"

    if "tables_removed" in expect:
        shown = remove_model_tables(case["answer"], tools_returned_rows=bool(steps))
        assert shown.count(TABLE_OMITTED) == expect["tables_removed"]
        assert "|" not in shown, "a model-written table survived"
