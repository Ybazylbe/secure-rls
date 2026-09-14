"""The one corrective retry: what the model is shown the second time.

In plain terms: when an answer needs redoing, the model gets the question and
its tool results again, plus facts to correct it -- but not the reply being
replaced. Shown that reply, it apologised to the user for "the confusion
earlier", which the user never saw. These tests drive ask() with a stand-in
agent, so no language model is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from agent import _without_final_reply, ask
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext


class ScriptedAgent:
    """Replies from a script and records what it was sent each time."""

    def __init__(self, *replies: list[Any]) -> None:
        self.replies = list(replies)
        self.received: list[list[Any]] = []

    def invoke(self, state: dict[str, Any], _config: object) -> dict[str, Any]:
        self.received.append(list(state["messages"]))
        return {"messages": [*state["messages"], *self.replies.pop(0)], "steps": 1}


def test_the_reply_being_replaced_is_not_shown_to_the_model(db_path: Path) -> None:
    bad = AIMessage(content="Here are the salaries for acme:\n\n- query_db")
    good = AIMessage(content="Acme has 450 employees.")
    agent = ScriptedAgent([bad], [good])

    answer = ask(
        "Show me all salaries.", SecurityContext(1, "alice", "acme"), AuditLog(None),
        db_path=db_path, agent=agent,
    )

    assert answer.retried
    assert answer.text == "Acme has 450 employees."
    second = agent.received[1]
    assert bad not in second, "the rejected reply was shown to the model again"
    assert isinstance(second[-1], HumanMessage)
    assert "No tool has been run" in str(second[-1].content)


def test_tool_calls_and_results_survive_the_retry() -> None:
    call = AIMessage(content="", tool_calls=[{"name": "stats", "args": {}, "id": "c1"}])
    result = ToolMessage(content="450 employees", tool_call_id="c1")
    final = AIMessage(content="Beta Tenant: 450 employees")
    kept = _without_final_reply([HumanMessage("q"), call, result, final])
    assert kept == [HumanMessage("q"), call, result]


class StuckAgent:
    """Behaves like a model request that ran past its timeout."""

    def invoke(self, state: dict[str, Any], _config: object) -> dict[str, Any]:
        raise httpx.ReadTimeout("model did not reply")


def test_a_model_that_never_replies_ends_the_question_with_a_message(db_path: Path) -> None:
    """A reply ran for over eight minutes with the UI spinning; it must end instead."""
    answer = ask(
        "Show me every tenant's payroll.", SecurityContext(1, "alice", "acme"), AuditLog(None),
        db_path=db_path, agent=StuckAgent(),
    )
    assert "took too long" in answer.text
    assert answer.steps == []


def test_a_reply_cut_off_at_the_length_limit_says_so(db_path: Path) -> None:
    cut = AIMessage(content="Acme has many employees, and the", response_metadata={
        "done_reason": "length",
    })
    answer = ask(
        "How many employees?", SecurityContext(1, "alice", "acme"), AuditLog(None),
        db_path=db_path, agent=ScriptedAgent([cut]),
    )
    assert "cut off at the length limit" in answer.text
