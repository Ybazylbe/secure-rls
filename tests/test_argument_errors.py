"""What the model is told when a tool call fails validation.

The message is the only thing the model has to correct itself with. A wrong one
is worse than a vague one: search_notes(k=10) used to be told it had used
"arguments it does not have", when both arguments existed and only the value was
out of range, and the model repeated the identical call until it gave up.

These run the calls through a real ToolNode, the way the agent does, so the
exception shape LangChain produces is the one under test. No model is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from agent import _explain_arguments
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.tools import build_tools


class _State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


def message_for(tool: str, arguments: dict[str, Any], db_path: Path) -> str:
    tools = build_tools(SecurityContext(1, "gita", "gamma"), AuditLog(None), db_path)
    graph = StateGraph(_State)
    graph.add_node("tools", ToolNode(tools, handle_tool_errors=_explain_arguments(tools)))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    call = AIMessage(content="", tool_calls=[{"name": tool, "args": arguments, "id": "t1"}])
    result = graph.compile().invoke({"messages": [call]})
    return str(result["messages"][-1].content)


def test_an_out_of_range_value_is_reported_as_a_value_not_a_missing_argument(
    db_path: Path,
) -> None:
    message = message_for("search_notes", {"query": "administrator", "k": 10}, db_path)
    assert "`k`" in message
    assert "less than or equal to 5" in message
    assert "has no argument" not in message


def test_an_unknown_argument_is_named(db_path: Path) -> None:
    message = message_for("search_notes", {"query": "x", "tenant": "beta"}, db_path)
    assert "no argument named `tenant`" in message
    assert "query, k" in message


def test_a_value_outside_a_closed_set_says_what_is_allowed(db_path: Path) -> None:
    message = message_for("stats", {"metric": "avg", "column": "password"}, db_path)
    assert "`column`" in message
    assert "salary" in message


def test_a_missing_required_argument_is_named(db_path: Path) -> None:
    message = message_for("search_notes", {"k": 2}, db_path)
    assert "`query`" in message
    assert "required" in message.lower()
