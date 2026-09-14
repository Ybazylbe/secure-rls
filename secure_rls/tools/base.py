"""Shared shapes for the agent's tools.

In plain terms: ToolResult, the common return type of every tool: a short
version for the model and the full rows for the screen.

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

import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Final

#: A result this small is shown to the model in full: enough for "the top five",
#: a list of notes, or one row per department.
MODEL_ROW_BUDGET = 10

#: For anything larger the model gets a summary of every row and only this many
#: example rows. Twenty rows were once enough for a model asked for "every
#: tenant's payroll" to start copying them out and never stop: each row looks
#: like the last, so under greedy decoding the likeliest next token is always
#: another row. With three there is nothing to copy. The user still sees every
#: row, shown by the server under the answer, and the model can ask for
#: particular rows with a narrower query.
PREVIEW_ROWS = 3

#: A text column with at most this many distinct values is summarised as counts.
_CATEGORY_LIMIT: Final = 12
_ISO_DATE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
    #: A short id for this result within the conversation, such as "r7". Each
    #: row the model sees is labelled with it ("r7.3" is the third row), so the
    #: final answer can point at rows instead of retyping them. Set by the tool
    #: binding in secure_rls/tools/__init__.py.
    ref: str | None = None

    def for_model(self) -> str:
        """The compact rendering handed back to the LLM."""
        if self.refused:
            return f"REFUSED: {self.reason}"
        parts = [self.summary]
        if len(self.rows) > MODEL_ROW_BUDGET:
            # A large result: the facts, not the table. The summary gives the
            # right figures for every row, so the model has no reason to work
            # them out from the examples -- it once reported a salary range from
            # the rows it could see as if they described all 450.
            parts.append(profile_rows(self.rows))
            parts.append(render_table(self.rows, limit=PREVIEW_ROWS, ref=self.ref))
        elif self.rows:
            parts.append(render_table(self.rows, ref=self.ref))
        return "\n".join(parts)


def render_table(
    rows: tuple[dict[str, Any], ...], limit: int = MODEL_ROW_BUDGET, ref: str | None = None
) -> str:
    """A markdown table of at most ``limit`` rows, plus a count of the rest.

    With ``ref`` set, the first column labels each row ("r7.1", "r7.2", ...) so
    the model can name the rows its answer is about.
    """
    if not rows:
        return "(no rows)"
    columns = list(rows[0])
    shown = rows[:limit]
    labels = ["row"] if ref else []
    header = "| " + " | ".join([*labels, *columns]) + " |"
    divider = "| " + " | ".join("---" for _ in [*labels, *columns]) + " |"
    body = [
        "| "
        + " | ".join(
            [*([f"{ref}.{index}"] if ref else []), *(_cell(row.get(c)) for c in columns)]
        )
        + " |"
        for index, row in enumerate(shown, start=1)
    ]
    table = "\n".join([header, divider, *body])
    if len(rows) > limit:
        # Said to the model, not the user: what these rows are, where the rest
        # are, and how to get particular ones.
        table += (
            f"\n(Example rows: {limit} of {len(rows)}. The user sees all {len(rows)} rows "
            f"in a table under your answer, so do not list rows yourself; use the summary "
            f"above for figures about all of them. If the question needs particular rows, "
            f"run a narrower query with WHERE, ORDER BY or LIMIT.)"
        )
    return table


def _cell(value: Any) -> str:
    """Format one table cell for the model: thousands separators, and long text cut short."""
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:,.2f}"
    if isinstance(value, int):
        return f"{value:,}"
    text = str(value).replace("|", "\\|")
    return text if len(text) <= 80 else text[:77] + "..."


def profile_rows(rows: tuple[dict[str, Any], ...]) -> str:
    """A summary of every row, computed here rather than left to the model.

    In plain terms: when a result is too big to show the model in full, this
    works out the figures people ask about -- how many rows, whose they are,
    the range and average of each number, the spread of each short category,
    the first and last date -- over all of the rows. It looks only at the
    values, so it works for any query's columns.
    """
    count = len(rows)
    lines = [f"Summary of all {count} rows, computed by the system:"]
    columns = list(rows[0]) if rows else []
    for column in columns:
        values = [row.get(column) for row in rows if row.get(column) is not None]
        if not values:
            continue
        if column == "tenant_id":
            owners = Counter(str(value) for value in values)
            if len(owners) == 1:
                lines.append(f"- tenant_id: all {count} rows belong to {next(iter(owners))}")
            else:
                lines.append(f"- tenant_id: {_counts(owners)}")
            continue
        if column.endswith("_id"):
            continue  # identifiers have no meaningful range or average
        numbers = [
            float(v) for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)
        ]
        texts = [v for v in values if isinstance(v, str)]
        if len(numbers) == len(values):
            lines.append(
                f"- {column}: min {_number(min(numbers))}, max {_number(max(numbers))}, "
                f"mean {_number(statistics.fmean(numbers))}, "
                f"median {_number(statistics.median(numbers))}"
            )
        elif len(texts) == len(values) and all(_ISO_DATE.match(v) for v in texts):
            lines.append(f"- {column}: earliest {min(texts)}, latest {max(texts)}")
        elif len(texts) == len(values):
            distinct = Counter(texts)
            if len(distinct) <= _CATEGORY_LIMIT:
                lines.append(f"- {column}: {_counts(distinct)}")
    return "\n".join(lines)


def _counts(counter: Counter[str]) -> str:
    """'Engineering 158, Sales 82, ...', most common first."""
    return ", ".join(f"{name} {n}" for name, n in counter.most_common())


def _number(value: float) -> str:
    """A number for the summary: whole numbers without decimals, others to 2 places."""
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.2f}"


_ROW_REF: Final = re.compile(r"^(r\d+)\.(\d+)$")


def resolve_row_refs(
    refs: list[str], results: list[ToolResult]
) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    """Turn row labels chosen by the model into the real rows, and list the rest.

    In plain terms: the model answers by pointing at rows ("r7.3"), and this
    looks each label up in the results the tools actually returned. A label
    that matches nothing -- a result that does not exist, or a row number past
    the end -- is not guessed at; it is returned separately so it can be
    reported. The rows handed back are the tools' own dictionaries, so nothing
    the model wrote can change a value or the tenant a row belongs to.
    """
    by_ref = {result.ref: result for result in results if result.ref and not result.refused}
    rows: list[dict[str, Any]] = []
    ignored: list[str] = []
    seen: set[str] = set()
    for raw in refs:
        label = str(raw).strip()
        if label in seen:
            continue
        seen.add(label)
        match = _ROW_REF.match(label)
        result = by_ref.get(match.group(1)) if match else None
        index = int(match.group(2)) if match else 0
        if result is None or not 1 <= index <= len(result.rows):
            ignored.append(label)
            continue
        rows.append(dict(result.rows[index - 1]))
    return tuple(rows), tuple(ignored)
