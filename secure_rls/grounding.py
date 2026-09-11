"""Checking that the numbers in an answer came from somewhere.

The evaluation suite turned up a failure mode worse than a refusal: asked
"which department has the most employees?", the agent called the stats tool
without a grouping, received a single total, and then *invented* a department
and a headcount to answer with. Fluent, plausible, and wrong -- and nothing in
the security layers has any opinion about it, because no data left the tenant.

So this module asks a narrow question with a checkable answer: **does every
figure in the answer appear in something a tool actually returned?** Numbers
are the part of an analytics answer that can be verified mechanically, and they
are the part a reader will act on.

What counts as supported:

* any number in a tool result -- its rows, or its summary line;
* any number in the user's own question, since echoing it back is not a claim;
* small integers, which are ordinals ("1.", "2.") far more often than data.

This is a grounding check, not a fact checker. It cannot tell whether the
*right* number was chosen, only whether the number was seen at all. That is a
low bar, and the point is that a hallucinated figure does not clear even that.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from agent import Step

_NUMBER: Final = re.compile(r"[-+]?\d[\d,]*(?:\.\d+)?")

#: Integers this small are almost always list markers, ranks or small counts
#: the model is entitled to state ("the top 3 are..."), so they are not treated
#: as claims about the data.
_ORDINAL_CEILING: Final = 10

#: Relative slack when matching an answer's number against a source number, so
#: that reporting 122,727 for 122,726.70 counts as grounded.
_TOLERANCE: Final = 0.005


def numbers_in(text: str) -> list[float]:
    """Every number mentioned in a piece of text, commas stripped."""
    values: list[float] = []
    for match in _NUMBER.finditer(text):
        try:
            values.append(float(match.group().replace(",", "")))
        except ValueError:  # pragma: no cover - the regex already constrains this
            continue
    return values


def _supported_values(steps: list[Step], question: str) -> set[float]:
    known: set[float] = set(numbers_in(question))
    for step in steps:
        result = step.result
        if result is None:
            continue
        known.update(numbers_in(result.summary))
        for row in result.rows:
            for value in row.values():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    known.add(float(value))
                elif isinstance(value, str):
                    known.update(numbers_in(value))
    return known


def ungrounded_numbers(answer: str, steps: list[Step], question: str = "") -> list[float]:
    """Figures stated in ``answer`` that no tool result supports."""
    known = _supported_values(steps, question)
    missing: list[float] = []
    for value in numbers_in(answer):
        if abs(value) <= _ORDINAL_CEILING and float(value).is_integer():
            continue
        margin = max(abs(value) * _TOLERANCE, 0.01)
        if not any(abs(value - source) <= margin for source in known):
            missing.append(value)
    return missing


CORRECTION: Final = (
    "Your answer contained figures that none of the tool results support: {values}. "
    "Do not state numbers you have not been given. Call the tools again with the "
    "arguments needed to answer the question properly -- if the question compares "
    "or ranks groups, you must pass group_by -- and then answer using only what "
    "they return."
)


def correction_for(values: list[float]) -> str:
    rendered = ", ".join(f"{v:,.2f}".rstrip("0").rstrip(".") for v in values[:5])
    return CORRECTION.format(values=rendered)
