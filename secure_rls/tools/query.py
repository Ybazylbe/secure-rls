"""The SQL tool: the only path from a model-written query to the database.

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

from db import DEFAULT_DB_PATH, tenant_connection
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
) -> ToolResult:
    """Validate, execute and vet one read-only query on behalf of ``ctx``."""
    try:
        guarded = guard(sql, ctx)
    except SqlGuardError as err:
        audit.record(ctx, "query_db", "refused", detail=err.reason, sql=sql, layer="L4")
        return ToolResult(
            summary="", refused=True, reason=err.reason, sql=sql,
        )

    denials: list[str] = []
    try:
        with tenant_connection(ctx, db_path, on_deny=denials.append) as con:
            cursor = con.execute(guarded.sql)
            rows = tuple(dict(r) for r in cursor.fetchall())
    except sqlite3.Error as err:
        detail = denials[0] if denials else str(err)
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
