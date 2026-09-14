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

import math
import statistics
from pathlib import Path
from typing import Any, Final, Literal

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
    values = frame[column].astype(float)

    # The chart's data is prepared here, ready to draw: means per group, bin
    # counts, or five-number summaries. The front end only draws it, so every
    # figure on a chart is computed in one tested place, and the model gets a
    # one-line description of what the chart shows rather than an image or a
    # pile of raw points it would have to summarise itself.
    if chart_type == "bar":
        series = frame.groupby(group_by)[column].mean().sort_values(ascending=False)
        data: list[dict[str, Any]] = [
            {str(group_by): str(key), f"mean_{column}": round(float(value), 2)}
            for key, value in series.items()
        ]
        spec: dict[str, Any] = {
            "type": "bar", "x": group_by, "y": f"mean_{column}",
            "title": f"Mean {column} by {group_by}",
        }
        top, bottom = data[0], data[-1]
        described = (
            f"highest {top[str(group_by)]} ({_fmt(top[f'mean_{column}'])}), "
            f"lowest {bottom[str(group_by)]} ({_fmt(bottom[f'mean_{column}'])})"
        )
    elif chart_type == "histogram":
        data = histogram_bins(values.tolist())
        spec = {"type": "histogram", "x": column, "title": f"Distribution of {column}"}
        busiest = max(data, key=lambda b: int(b["count"]))
        described = (
            f"{len(values)} employees from {_fmt(values.min())} to {_fmt(values.max())}; "
            f"the most common range is {_fmt(busiest['start'])} to {_fmt(busiest['end'])} "
            f"({busiest['count']} employees)"
        )
    else:
        data = [
            {str(group_by): str(key), **box_summary(block[column].astype(float).tolist())}
            for key, block in frame.groupby(group_by)
        ]
        data.sort(key=lambda row: float(row["median"]), reverse=True)
        spec = {"type": "box", "x": group_by, "y": column, "title": f"{column} by {group_by}"}
        described = "medians: " + ", ".join(
            f"{row[str(group_by)]} {_fmt(row['median'])}" for row in data
        )

    audit.record(ctx, "plot", "allowed", rows=len(data), layer="tool", detail=spec["title"])
    return ToolResult(
        summary=f"Chart ready: {spec['title']}, shown to the user under your answer. "
        f"It shows {described}.",
        rows=tuple(data) if chart_type == "bar" else (),
        chart={**spec, "data": data},
    )


#: Roughly how many bars a histogram gets. Nice bin widths move it a little.
TARGET_BINS: Final = 12


def histogram_bins(values: list[float], target: int = TARGET_BINS) -> list[dict[str, Any]]:
    """Count values into equal-width bins with round edges.

    In plain terms: a histogram needs bins a reader can say out loud, like
    "80,000 to 90,000", not "81,337 to 93,902". The width is the nearest
    1, 2, 2.5 or 5 times a power of ten that gives about ``target`` bins, and
    the edges are multiples of it. Every value lands in exactly one bin; the
    last bin includes its upper edge.
    """
    if not values:
        return []
    low, high = min(values), max(values)
    if low == high:
        return [{"start": low, "end": high, "count": len(values)}]
    width = _nice_step((high - low) / target)
    first = math.floor(low / width) * width
    count = max(1, math.ceil((high - first) / width))
    if first + count * width <= high:
        count += 1
    counts = [0] * count
    for value in values:
        counts[min(int((value - first) // width), count - 1)] += 1
    return [
        {"start": _round(first + i * width), "end": _round(first + (i + 1) * width), "count": n}
        for i, n in enumerate(counts)
    ]


def box_summary(values: list[float]) -> dict[str, Any]:
    """The five numbers a box plot draws, plus the points beyond its whiskers.

    Quartiles use linear interpolation, the same as pandas' default, so the
    box agrees with any figure computed elsewhere. Whiskers reach the furthest
    value within 1.5 times the interquartile range of the box; anything beyond
    is listed as an outlier and drawn as a dot.
    """
    ordered = sorted(values)
    q1, median, q3 = (statistics.quantiles(ordered, n=4, method="inclusive")
                      if len(ordered) > 1 else [ordered[0]] * 3)
    reach = 1.5 * (q3 - q1)
    inside = [v for v in ordered if q1 - reach <= v <= q3 + reach]
    return {
        "n": len(ordered),
        "min": _round(ordered[0]),
        "q1": _round(q1),
        "median": _round(median),
        "q3": _round(q3),
        "max": _round(ordered[-1]),
        "whisker_low": _round(inside[0]),
        "whisker_high": _round(inside[-1]),
        "outliers": [_round(v) for v in ordered if v < inside[0] or v > inside[-1]],
    }


def _nice_step(raw: float) -> float:
    """The nearest 1, 2, 2.5 or 5 times a power of ten at or above ``raw``."""
    power = 10 ** math.floor(math.log10(raw))
    for multiple in (1.0, 2.0, 2.5, 5.0, 10.0):
        if multiple * power >= raw:
            return float(multiple * power)
    return float(10 * power)  # pragma: no cover - the loop always returns


def _round(value: float) -> float | int:
    """Whole numbers as int, others to 2 places, so chart data reads cleanly."""
    return int(value) if float(value).is_integer() else round(float(value), 2)


def _fmt(value: object) -> str:
    """A number for the one-line chart description."""
    number = float(value)  # type: ignore[arg-type]
    return f"{number:,.0f}" if number.is_integer() or abs(number) >= 100 else f"{number:,.2f}"
