"""Charts as data, not as pictures.

In plain terms: The plot tool: turns the tenant's rows into chart data (bar,
histogram, box) that the front end draws.

The tool returns a chart *specification* plus the aggregated points. The UI
renders it. Two reasons: the model never handles an image it cannot check, and
the numbers behind a chart stay inspectable -- during the demo the same figures
appear in the table beside the plot, which is how you show that a chart is not
hiding a wider query than it claims.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from db import DEFAULT_DB_PATH, tenant_frame
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.tools.base import ToolResult
from secure_rls.tools.frames import ColumnError, check_groupable, check_numeric

ChartType = Literal["bar", "histogram", "box"]


def plot(
    chart_type: ChartType,
    column: str,
    ctx: SecurityContext,
    audit: AuditLog,
    *,
    group_by: str | None = "department",
    db_path: Path | str = DEFAULT_DB_PATH,
) -> ToolResult:
    """Build a chart spec over the caller's employees."""
    try:
        check_numeric(column)
        if chart_type not in ("bar", "histogram", "box"):
            raise ColumnError(f"unknown chart type {chart_type!r}")
        if chart_type in ("bar", "box"):
            check_groupable(group_by or "")
    except ColumnError as err:
        audit.record(ctx, "plot", "refused", detail=str(err), layer="tool")
        return ToolResult(summary="", refused=True, reason=str(err))

    frame = tenant_frame(ctx, db_path)

    if chart_type == "bar":
        series = frame.groupby(group_by)[column].mean().sort_values(ascending=False)
        rows = tuple(
            {str(group_by): str(k), f"mean_{column}": round(float(v), 2)}
            for k, v in series.items()
        )
        spec: dict[str, Any] = {
            "type": "bar", "x": group_by, "y": f"mean_{column}",
            "title": f"Mean {column} by {group_by}",
        }
    elif chart_type == "histogram":
        rows = tuple({column: float(v)} for v in frame[column])
        spec = {"type": "histogram", "x": column, "title": f"Distribution of {column}"}
    else:
        rows = tuple(
            {str(group_by): str(g), column: float(v)}
            for g, v in zip(frame[group_by], frame[column], strict=True)
        )
        spec = {"type": "box", "x": group_by, "y": column,
                "title": f"{column} by {group_by}"}

    audit.record(ctx, "plot", "allowed", rows=len(rows), layer="tool", detail=spec["title"])
    return ToolResult(
        summary=f"Chart ready: {spec['title']} ({len(rows)} points).",
        rows=rows if chart_type == "bar" else (),
        chart={**spec, "data": [dict(r) for r in rows]},
    )
