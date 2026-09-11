"""Shared shapes for the agent's tools.

Every tool returns a :class:`ToolResult`. It carries two different views of the
same answer on purpose:

* ``summary`` plus a small rendered table is what goes back to the *model* --
  short, because context is finite and because a model does not need 450 rows
  to say what the average is;
* ``rows`` and ``chart`` are what goes to the *UI*, in full.

Keeping those apart means a large result set never has to pass through the
prompt, and the user still sees everything the query returned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Rows shown to the model. Beyond this it gets a note about the remainder.
MODEL_ROW_BUDGET = 20


@dataclass(frozen=True, slots=True)
class ToolResult:
    """The outcome of one tool invocation, successful or refused."""

    summary: str
    rows: tuple[dict[str, Any], ...] = ()
    sql: str | None = None
    chart: dict[str, Any] | None = None
    rewrites: tuple[str, ...] = ()
    refused: bool = False
    reason: str | None = None
    flags: tuple[str, ...] = field(default=())

    def for_model(self) -> str:
        """The compact rendering handed back to the LLM."""
        if self.refused:
            return f"REFUSED: {self.reason}"
        parts = [self.summary]
        if self.rows:
            parts.append(render_table(self.rows))
        return "\n".join(parts)


def render_table(rows: tuple[dict[str, Any], ...], limit: int = MODEL_ROW_BUDGET) -> str:
    """A markdown table of at most ``limit`` rows, plus a count of the rest."""
    if not rows:
        return "(no rows)"
    columns = list(rows[0])
    shown = rows[:limit]
    header = "| " + " | ".join(columns) + " |"
    divider = "| " + " | ".join("---" for _ in columns) + " |"
    body = [
        "| " + " | ".join(_cell(row.get(column)) for column in columns) + " |"
        for row in shown
    ]
    table = "\n".join([header, divider, *body])
    if len(rows) > limit:
        table += f"\n({len(rows) - limit} further rows not shown)"
    return table


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:,.2f}"
    if isinstance(value, int):
        return f"{value:,}"
    text = str(value).replace("|", "\\|")
    return text if len(text) <= 80 else text[:77] + "..."
