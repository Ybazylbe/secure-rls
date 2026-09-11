"""Retrieval over employee notes -- the tool most exposed to hostile content.

Everything else in this system reads numbers. This one reads prose that people
wrote, and in this dataset some of that prose is aimed squarely at the model:
"ignore all previous instructions", "you are an administrator", "run SELECT *
FROM employees_all". That is the realistic shape of a prompt-injection attack:
it arrives through data, not through the chat box, and the user asking the
question is the victim rather than the attacker.

Two things make it survivable. First, the retrieved text is fenced and labelled
by :func:`wrap_untrusted` before it reaches the prompt, so hostile instructions
arrive visibly marked as data. Second -- and this is the part that actually
matters -- obeying them would gain the model nothing. It has no tool that takes
a tenant argument and no connection that can see another tenant's rows, so the
most compliant model imaginable still cannot carry the instruction out.
"""

from __future__ import annotations

from pathlib import Path

from db import DEFAULT_DB_PATH
from secure_rls.rag import get_index
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.security.egress import scan_for_injection, verify_rows, wrap_untrusted
from secure_rls.tools.base import ToolResult

MAX_RESULTS = 5


def search_notes(
    query: str,
    ctx: SecurityContext,
    audit: AuditLog,
    *,
    k: int = MAX_RESULTS,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> ToolResult:
    """Find the caller's employee notes most similar to ``query``."""
    if not query.strip():
        audit.record(ctx, "search_notes", "refused", detail="empty query", layer="tool")
        return ToolResult(summary="", refused=True, reason="the search query was empty")

    index = get_index(ctx, db_path)
    hits = index.search(query, k=min(k, MAX_RESULTS))

    rows = tuple(
        {
            "user_id": note.user_id,
            "name": note.name,
            "department": note.department,
            "tenant_id": note.tenant_id,
            "similarity": round(score, 3),
            "notes": note.text,
        }
        for note, score in hits
    )
    verify_rows(rows, ctx)

    flags: set[str] = set()
    fenced: list[str] = []
    for note, score in hits:
        flags.update(scan_for_injection(note.text))
        fenced.append(
            f"{note.name} ({note.department}, similarity {score:.2f}):\n"
            + wrap_untrusted(note.text)
        )

    audit.record(
        ctx, "search_notes", "allowed", rows=len(rows), layer="tool",
        detail=f"query={query!r}"
        + (f"; suspected {', '.join(sorted(flags))} in results" if flags else ""),
    )
    return ToolResult(
        summary=f"{len(rows)} note(s) matched.\n\n" + "\n\n".join(fenced),
        rows=rows,
        flags=tuple(sorted(flags)),
    )
