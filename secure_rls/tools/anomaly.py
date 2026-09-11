"""Outlier detection, scoped to the caller's own population.

The scoping is the interesting part. "Who is paid unusually?" is only
meaningful relative to a peer group, and the peer group here must be the
caller's tenant -- the dataset gives each tenant a different pay scale on
purpose. An implementation that computed the thresholds over the whole table
would not return foreign rows, so nothing would look wrong, yet every number
it reported would be derived from data the caller cannot see. That is a
quieter kind of leak, and the tests check for it explicitly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from db import DEFAULT_DB_PATH, tenant_frame
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.tools.base import ToolResult
from secure_rls.tools.frames import ColumnError, check_groupable, check_numeric

Method = Literal["iqr", "zscore"]


def detect_anomalies(
    column: str,
    ctx: SecurityContext,
    audit: AuditLog,
    *,
    method: Method = "iqr",
    group_by: str | None = "department",
    db_path: Path | str = DEFAULT_DB_PATH,
) -> ToolResult:
    """Flag values that sit far outside their peer group."""
    try:
        check_numeric(column)
        if group_by:
            check_groupable(group_by)
        if method not in ("iqr", "zscore"):
            raise ColumnError(f"unknown method {method!r}; use 'iqr' or 'zscore'")
    except ColumnError as err:
        audit.record(ctx, "anomaly", "refused", detail=str(err), layer="tool")
        return ToolResult(summary="", refused=True, reason=str(err))

    frame = tenant_frame(ctx, db_path)
    groups = frame.groupby(group_by) if group_by else [("all", frame)]

    flagged: list[dict[str, object]] = []
    for label, block in groups:
        values = block[column]
        if len(values) < 4:
            continue
        if method == "iqr":
            q1, q3 = values.quantile(0.25), values.quantile(0.75)
            spread = q3 - q1
            low, high = q1 - 1.5 * spread, q3 + 1.5 * spread
        else:
            mean, deviation = values.mean(), values.std()
            if not deviation:
                continue
            low, high = mean - 3 * deviation, mean + 3 * deviation

        outliers = block[(values < low) | (values > high)]
        for _, row in outliers.iterrows():
            flagged.append(
                {
                    "name": row["name"],
                    "department": row["department"],
                    column: _number(row[column]),
                    "direction": "above" if row[column] > high else "below",
                    "peer_group": str(label),
                    "tenant_id": row["tenant_id"],
                }
            )

    flagged.sort(key=lambda r: float(r[column]), reverse=True)  # type: ignore[arg-type]
    scope = f"within each {group_by}" if group_by else "across the tenant"
    audit.record(
        ctx, "anomaly", "allowed", rows=len(flagged), layer="tool",
        detail=f"{method} on {column} {scope}",
    )
    return ToolResult(
        summary=(
            f"{len(flagged)} outlier(s) in {column} by {method.upper()} {scope}, "
            f"out of {len(frame)} employees."
        ),
        rows=tuple(flagged),
    )


def _number(value: object) -> float | int:
    number = float(value)  # type: ignore[arg-type]
    return int(number) if number.is_integer() else round(number, 2)
