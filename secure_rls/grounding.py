"""Checking that the numbers in an answer came from somewhere.

In plain terms: Catches the model making things up: numbers in an answer that
no tool returned, and tables that claim to show another tenant's rows.

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
    """Every number the answer may use: from tool results or from the question itself."""
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
    """The message that asks the model to redo an answer that contained made-up numbers."""
    rendered = ", ".join(f"{v:,.2f}".rstrip("0").rstrip(".") for v in values[:5])
    return CORRECTION.format(values=rendered)


# ---------------------------------------------------------------------------
# Rows presented as someone else's
# ---------------------------------------------------------------------------

#: A heading that names a tenant, as in "**Tenant: xyz**". The colon is
#: required: prose such as "you cannot see tenant beta" is an honest refusal,
#: not a claim to be showing that tenant's data.
_TENANT_HEADING: Final = re.compile(r"\btenant\s*:\s*[*`_]*\s*([A-Za-z][\w-]*)", re.I)
_TABLE_SEPARATOR: Final = re.compile(r"^\|?\s*:?-{3,}")


def claimed_tenants(answer: str, own_tenant: str) -> tuple[str, ...]:
    """Tenants other than ``own_tenant`` that the answer presents data for.

    The number check above cannot see this. Asked for "every tenant's payroll",
    a model printed a table headed "Tenant: xyz" with invented rows -- and every
    figure in it happened to occur somewhere in the 450 real rows it had been
    given, so nothing was flagged. The data never left the tenant; the answer
    still reads as a leak to anyone looking at it, and is false. So this looks
    for the shape of the claim instead: a ``tenant_id`` column in a table the
    answer drew, or a heading that names a tenant, with a value that is not the
    caller's own.
    """
    own = own_tenant.lower()
    found: dict[str, None] = {}

    for match in _TENANT_HEADING.finditer(answer):
        name = match.group(1).lower()
        if name != own:
            found[name] = None

    lines = answer.splitlines()
    column: int | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("|"):
            column = None
            continue
        cells = [cell.strip(" *`_").lower() for cell in stripped.strip("|").split("|")]
        following = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if _TABLE_SEPARATOR.match(following):
            column = next(
                (i for i, cell in enumerate(cells) if cell in {"tenant_id", "tenant"}), None
            )
            continue
        if column is None or _TABLE_SEPARATOR.match(stripped) or column >= len(cells):
            continue
        value = cells[column]
        if value.strip(".") and value != own:  # "..." marks elided rows
            found[value] = None

    return tuple(found)


def scope_correction(
    question: str, answer: str, steps: list[Step], own_tenant: str
) -> str | None:
    """Ask for a rewrite when the answer blurs whose data it is showing.

    In plain terms: tools only ever return the caller's own rows, so an answer
    that talks about another tenant next to that data is presenting the caller's
    rows as someone else's. A model asked for "every tenant's salaries" was seen
    labelling gamma's employees "Beta Tenant"; asked for "beta's notes", another
    listed gamma's employees without saying whose they were.

    The check compares facts rather than phrasing. Which tenants does the text
    refer to *as tenants* (see tenants_referred_to), and
    which tenants do the returned rows actually belong to? If the answer names a
    tenant whose rows never came back, or the question asks about another
    tenant and the answer never says whose data it is, the model is told the
    facts and asked once to rewrite. Nothing here is specific to one question
    or one tenant.
    """
    rows = [row for step in steps if step.result is not None for row in step.result.rows]
    if not rows:
        # Nothing was returned, so no data can be misattributed. An answer
        # that only says "I cannot see beta" is honest and is left alone.
        return None

    own = own_tenant.lower()
    returned = {str(row["tenant_id"]).lower() for row in rows if row.get("tenant_id")}
    returned.add(own)

    named_in_answer = dict.fromkeys(
        [*tenants_referred_to(answer, own), *claimed_tenants(answer, own)]
    )
    phantom = [tenant for tenant in named_in_answer if tenant not in returned]
    if phantom:
        names = ", ".join(phantom)
        return (
            f"Your answer refers to {names} next to data. Every row the tools returned "
            f"belongs to {own_tenant}; you cannot see any other tenant. Rewrite the answer "
            f"so that nothing is presented as {names}'s data: say plainly that you can only "
            f"see {own_tenant}, and label the data you show as {own_tenant}'s."
        )

    asked_about = tenants_referred_to(question, own)
    if asked_about and not _mentions(answer, own):
        names = ", ".join(asked_about)
        return (
            f"The question asks about {names}. You can only see {own_tenant}, so every row "
            f"you received is {own_tenant}'s. Rewrite the answer to say that plainly, and "
            f"make clear that the data you show belongs to {own_tenant}, not to {names}."
        )
    return None


def tenants_referred_to(text: str, exclude: str = "") -> list[str]:
    """Tenants from the registry that ``text`` refers to as tenants.

    In plain terms: the tenant names here are ordinary English words, so a bare
    mention proves nothing -- "Alice has beta access" or "the gamma-ray
    project" is not about a tenant. An earlier version matched the bare words
    and asked the model to rewrite perfectly normal answers. A name only counts
    when the text uses it as a tenant: next to the word "tenant" ("Beta
    Tenant:", "tenant beta"), as an owner ("beta's employees"), or in a sentence
    that talks about tenants ("salaries for every tenant, including beta").
    The egress module learned the same lesson earlier, for the same reason.
    """
    from secure_rls.security.context import TENANTS

    sentences = [part for part in re.split(r"[.!?\n]+", text) if part.strip()]
    found: list[str] = []
    for tenant in TENANTS:
        if tenant == exclude:
            continue
        name = re.escape(tenant)
        as_tenant = re.search(
            rf"\b{name}\s+tenants?\b|\btenants?\s*:?\s*[*`_]*{name}\b|\b{name}['’]s\b",
            text,
            re.IGNORECASE,
        )
        in_tenant_sentence = any(
            _mentions(sentence, tenant) and re.search(r"\btenants?\b", sentence, re.IGNORECASE)
            for sentence in sentences
        )
        if as_tenant or in_tenant_sentence:
            found.append(tenant)
    return found


def _mentions(text: str, word: str) -> bool:
    """Whether ``word`` appears in ``text`` as a whole word, ignoring case."""
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


def written_tool_call(answer: str, tool_names: tuple[str, ...] | None = None) -> str | None:
    """What the model wrote out instead of calling a tool, or None.

    In plain terms: sometimes the model means to use a tool but prints it
    instead -- "Here are the salaries: - query_db", or a ```sql block it never
    ran -- and the user gets a promise of data with no data.

    Only unambiguous signs count, because two of our tool names are everyday
    words ("stats", "plot") and "select ... from" is ordinary English. An
    earlier version flagged "the plot above shows" and "select a department
    from the list". Now a tool name counts only when written as code (in
    backticks, or followed by an opening bracket) or alone on its own line, and
    SQL counts only inside a ```sql block or as an upper-case SELECT ... FROM.
    """
    if tool_names is None:
        from secure_rls.tools import tool_names as registered

        tool_names = registered()
    for name in tool_names:
        tool = re.escape(name)
        if re.search(
            rf"`{tool}`|\b{tool}\s*\(|^\s*(?:[-*•]|\d+\.)?\s*\**{tool}\**\s*:?\s*$",
            answer,
            re.MULTILINE,
        ):
            return f"the tool name `{name}`"
    if re.search(r"```\s*sql\b", answer, re.IGNORECASE) or re.search(
        r"\bSELECT\b[^\n]{0,300}\bFROM\b", answer
    ):
        return "a SQL query"
    return None


#: What replaces a table the model drew, depending on whether data came back.
TABLE_OMITTED: Final = "_(table omitted: the rows the tools returned are shown below)_"
TABLE_WITHOUT_DATA: Final = (
    "_(a table the model wrote was removed: no tool returned any data for it)_"
)


def remove_model_tables(answer: str, tools_returned_rows: bool) -> str:
    """Replace markdown tables in the model's answer with a short note.

    In plain terms: a table in the answer text is the model's copy of the data,
    and a copy can be wrong -- it can mislabel whose rows they are, or invent
    rows outright ("Tenant: xyz", user ids 451 to 900). The user already gets
    the real rows, straight from the tool results, under the answer. So tables
    the model writes are never shown as data; the prose around them is kept.
    This does not depend on what the table says, only on it being a table.
    """
    lines = answer.splitlines()
    kept: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        following = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if line.startswith("|") and _TABLE_SEPARATOR.match(following):
            end = index + 2
            while end < len(lines) and lines[end].strip().startswith("|"):
                end += 1
            kept.append(TABLE_OMITTED if tools_returned_rows else TABLE_WITHOUT_DATA)
            index = end
            continue
        kept.append(lines[index])
        index += 1
    return "\n".join(kept)
