"""Aggregates without SQL.

Most questions an analyst asks -- average salary by department, headcount,
the spread of performance scores -- do not need a generated query at all.
Serving them from a structured tool removes a whole class of failure: there is
no SQL to get wrong, and no SQL to attack. The model picks a metric and a
column from a fixed vocabulary; it does not write code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from db import DEFAULT_DB_PATH, tenant_frame
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.tools.base import ToolResult
from secure_rls.tools.frames import ColumnError, check_groupable, check_numeric

Metric = Literal["avg", "sum", "min", "max", "count", "median"]

_PANDAS_METRIC = {
    "avg": "mean", "sum": "sum", "min": "min",
    "max": "max", "count": "count", "median": "median",
}


def aggregate(
    metric: Metric,
    column: str,
    ctx: SecurityContext,
    audit: AuditLog,
    *,
    group_by: str | None = None,
    department: str | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> ToolResult:
    """Compute one aggregate over the caller's employees."""
    try:
        check_numeric(column)
        if group_by:
            check_groupable(group_by)
        if metric not in _PANDAS_METRIC:
            raise ColumnError(
                f"unknown metric {metric!r}; choose one of {sorted(_PANDAS_METRIC)}"
            )
    except ColumnError as err:
        audit.record(ctx, "stats", "refused", detail=str(err), layer="tool")
        return ToolResult(summary="", refused=True, reason=str(err))

    frame = tenant_frame(ctx, db_path)
    scope = "all departments"
    if department:
        frame = frame[frame["department"].str.lower() == department.lower()]
        scope = department
        if frame.empty:
            audit.record(ctx, "stats", "allowed", detail=f"no rows for {department}", rows=0)
            return ToolResult(summary=f"No employees found in {department}.")

    operation = _PANDAS_METRIC[metric]
    if group_by:
        series = getattr(frame.groupby(group_by)[column], operation)()
        rows = tuple(
            {group_by: str(key), f"{metric}_{column}": _round(value)}
            for key, value in series.sort_values(ascending=False).items()
        )
        summary = f"{metric} of {column} by {group_by} ({scope}), {len(rows)} group(s)."
    else:
        value = _round(getattr(frame[column], operation)())
        rows = ({f"{metric}_{column}": value, "employees": int(len(frame))},)
        summary = f"{metric} of {column} across {scope}: {value}"

    audit.record(
        ctx, "stats", "allowed", rows=len(rows), layer="tool",
        detail=f"{metric}({column})" + (f" by {group_by}" if group_by else ""),
    )
    return ToolResult(summary=summary, rows=rows)


def _round(value: object) -> float | int:
    number = float(value)  # type: ignore[arg-type]
    return int(number) if number.is_integer() else round(number, 2)
