"""The SQL tool: the only path from a model-written query to the database.

In plain terms: The query_db tool: runs one model-written SQL query through the
guard, the locked-down connection and the egress check, in that order.

The sequence is fixed and every step is recorded:

    guard (L4) -> tenant connection (L2/L3) -> egress check (L5) -> audit

There is no variant that skips a step, and no parameter that relaxes one. A
refusal is returned to the model as an ordinary result, not raised: the agent
should be able to read "that table is not available" and try a different
question, which is exactly what a well-behaved analyst would do.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from db import DEFAULT_DB_PATH, QUERY_TIMEOUT_SECONDS, tenant_connection
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.security.egress import EgressViolation, scan_for_injection, verify_rows
from secure_rls.security.sql_guard import SqlGuardError, guard
from secure_rls.tools.base import ToolResult


def run_sql(
    sql: str,
    ctx: SecurityContext,
    audit: AuditLog,
    db_path: Path | str = DEFAULT_DB_PATH,
    *,
    query_timeout: float = QUERY_TIMEOUT_SECONDS,
) -> ToolResult:
    """Validate, execute and vet one read-only query on behalf of ``ctx``.

    ``query_timeout`` is forwarded to :func:`db.tenant_connection`, which
    interrupts the statement if it runs past that budget -- see the constant's
    docstring in :mod:`db` for why row and shape checks alone are not enough.
    """
    try:
        guarded = guard(sql, ctx)
    except SqlGuardError as err:
        audit.record(ctx, "query_db", "refused", detail=err.reason, sql=sql, layer="L4")
        return ToolResult(
            summary="", refused=True, reason=err.reason, sql=sql,
        )

    denials: list[str] = []
    try:
        with tenant_connection(
            ctx, db_path, on_deny=denials.append, query_timeout=query_timeout
        ) as con:
            cursor = con.execute(guarded.sql)
            rows = tuple(dict(r) for r in cursor.fetchall())
    # Before Python 3.12, sqlite3 reports a multi-statement payload as
    # sqlite3.Warning, which is not a subclass of sqlite3.Error. Catching only
    # Error would turn that refusal into an unhandled crash on 3.10 and 3.11.
    except (sqlite3.Error, sqlite3.Warning) as err:
        if denials:
            detail = denials[0]
        elif "interrupted" in str(err).lower():
            # Raised by the progress handler installed in tenant_connection,
            # not by the authorizer, so it never reaches `denials`.
            detail = (
                f"this query ran longer than the {query_timeout:g}s time budget and was "
                "stopped; narrow it with a filter, a smaller LIMIT, or fewer joined copies "
                "of the table"
            )
        else:
            detail = str(err)
        audit.record(
            ctx, "query_db", "refused", detail=detail, sql=guarded.sql, layer="L3"
        )
        return ToolResult(summary="", refused=True, reason=detail, sql=guarded.sql)

    try:
        verify_rows(rows, ctx)
    except EgressViolation as err:
        # Unreachable unless a preventive layer has regressed. Fail closed and
        # make as much noise as possible.
        audit.record(
            ctx, "query_db", "error", detail=err.reason, sql=guarded.sql, layer="L5"
        )
        return ToolResult(summary="", refused=True, reason=err.reason, sql=guarded.sql)

    flags = _flag_untrusted(rows)
    audit.record(
        ctx, "query_db", "allowed", sql=guarded.sql, rows=len(rows),
        detail="; ".join(guarded.rewrites), layer="L4",
    )
    return ToolResult(
        summary=f"{len(rows)} row(s) returned.",
        rows=rows,
        sql=guarded.sql,
        rewrites=guarded.rewrites,
        flags=flags,
    )


def _flag_untrusted(rows: tuple[dict[str, object], ...]) -> tuple[str, ...]:
    """Note any injection shapes present in returned free text.

    The text is still returned -- it is the tenant's own data and the user
    asked for it -- but the finding is surfaced so the UI can mark it and the
    evaluation suite can count it.
    """
    found: set[str] = set()
    for row in rows:
        for value in row.values():
            if isinstance(value, str):
                found.update(scan_for_injection(value))
    return tuple(sorted(found))
