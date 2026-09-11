"""Aggregates without SQL.

Most questions an analyst asks -- average salary by department, headcount, how
many people clear a performance bar -- do not need a generated query. Serving
them from a structured tool removes a class of failure: there is no SQL to get
wrong, and none to attack.

The filter arguments here were not in the first design. The evaluation suite
showed why they had to be: asked "how many employees earn more than 100,000?",
the model reached for this tool anyway, could not express the threshold, and
answered with the plain headcount -- a real number, from a real tool call,
answering a different question. Telling it in the prompt to use `query_db`
instead did not help, and the grounding check cannot catch it, because the
figure is perfectly well grounded.

The conclusion was that the tool's vocabulary was too narrow rather than that
the model was disobedient. Filters are named and typed rather than free-form
expressions: that keeps the tool declarative and validated, and leaves genuinely
open-ended questions to `query_db`, where the SQL guard is waiting for them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

from db import DEFAULT_DB_PATH, tenant_frame
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext
from secure_rls.tools.base import ToolResult
from secure_rls.tools.frames import ColumnError, check_groupable, check_numeric

if TYPE_CHECKING:
    import pandas as pd

Metric = Literal["avg", "sum", "min", "max", "count", "median", "spread"]

_PANDAS_METRIC = {
    "avg": "mean", "sum": "sum", "min": "min",
    "max": "max", "count": "count", "median": "median",
}


FILTERABLE: Final[frozenset[str]] = frozenset({"salary", "performance_score", "hire_date"})

#: Comparison keywords accepted in a nested filter, mapped to what they mean.
#: Models do not agree on this vocabulary -- one writes ``min``, another
#: ``gte``, another ``lt`` -- so all the usual spellings are accepted rather
#: than insisting on one and rejecting calls that were perfectly clear.
OPERATORS: Final[dict[str, str]] = {
    "min": ">=", "gte": ">=", "ge": ">=", ">=": ">=",
    "max": "<=", "lte": "<=", "le": "<=", "<=": "<=",
    "gt": ">", ">": ">",
    "lt": "<", "<": "<",
    "eq": "==", "==": "==", "equals": "==",
}


@dataclass(frozen=True, slots=True)
class Predicate:
    """One validated comparison. Not an expression -- a column, an operator
    from a closed set, and a literal."""

    column: str
    operator: str
    value: float | str

    def describe(self) -> str:
        return f"{self.column} {self.operator} {self.value}"

    def apply(self, frame: pd.DataFrame) -> pd.DataFrame:
        series = frame[self.column]
        if self.column == "hire_date":
            series = series.astype(str)
            value: object = str(self.value)
        else:
            value = float(self.value)
        match self.operator:
            case ">=":
                return frame[series >= value]
            case "<=":
                return frame[series <= value]
            case ">":
                return frame[series > value]
            case "<":
                return frame[series < value]
            case _:
                return frame[series == value]


def parse_filter(raw: dict[str, object] | None) -> tuple[Predicate, ...]:
    """Read the nested ``{column: {operator: value}}`` shape models emit.

    This shape was not in the original design; the evaluation suite showed the
    model producing it regardless, ignoring the flat arguments the schema
    declared, and then answering an unfiltered question as though it were
    filtered. Arguing with the model did not work: told exactly which arguments
    existed, it apologised and sent the nested form again.

    So the tool accepts it -- under validation. Column and operator both come
    from closed sets and the value is a literal, so this is still a declarative
    filter, not a query language with a parser attached.
    """
    if not raw:
        return ()
    predicates: list[Predicate] = []
    for column, condition in raw.items():
        if column not in FILTERABLE:
            raise ColumnError(
                f"cannot filter on {column!r}; filterable columns are {sorted(FILTERABLE)}"
            )
        if isinstance(condition, dict):
            for operator, value in condition.items():
                symbol = OPERATORS.get(str(operator).lower().strip())
                if symbol is None:
                    raise ColumnError(
                        f"unknown comparison {operator!r}; use one of "
                        f"{sorted(set(OPERATORS))}"
                    )
                predicates.append(Predicate(column, symbol, _literal(value)))
        else:
            predicates.append(Predicate(column, "==", _literal(condition)))
    return tuple(predicates)


def _literal(value: object) -> float | str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip()
    for symbol in (">=", "<=", ">", "<", "="):
        text = text.removeprefix(symbol).strip()
    try:
        return float(text)
    except ValueError:
        return text


@dataclass(frozen=True, slots=True)
class Filters:
    """Everything this tool can narrow by, in one validated object."""

    department: str | None = None
    predicates: tuple[Predicate, ...] = ()

    @classmethod
    def build(
        cls,
        *,
        department: str | None = None,
        min_salary: float | None = None,
        max_salary: float | None = None,
        min_performance: float | None = None,
        max_performance: float | None = None,
        hired_from: str | None = None,
        hired_to: str | None = None,
        nested: dict[str, object] | None = None,
    ) -> Filters:
        """Flat arguments and the nested form end up as the same predicates."""
        flat = [
            Predicate("salary", ">=", min_salary) if min_salary is not None else None,
            Predicate("salary", "<=", max_salary) if max_salary is not None else None,
            Predicate("performance_score", ">=", min_performance)
            if min_performance is not None else None,
            Predicate("performance_score", "<=", max_performance)
            if max_performance is not None else None,
            Predicate("hire_date", ">=", hired_from) if hired_from else None,
            Predicate("hire_date", "<=", hired_to) if hired_to else None,
        ]
        return cls(
            department=department,
            predicates=tuple(p for p in flat if p is not None) + parse_filter(nested),
        )

    def describe(self) -> str:
        parts = [f"department {self.department}"] if self.department else []
        parts += [p.describe() for p in self.predicates]
        if not parts:
            # Blunt on purpose. The evaluation suite caught the agent calling
            # this tool with no filters and reporting the total as though it
            # were a filtered count -- "450 employees scored below 3.0". The
            # figure is real, so the grounding check cannot object; the text the
            # model reads is the only place left to say so.
            return "ALL employees, no filter applied"
        return ", ".join(parts)

    def apply(self, frame: pd.DataFrame) -> pd.DataFrame:
        if self.department:
            frame = frame[frame["department"].str.lower() == self.department.lower()]
        for predicate in self.predicates:
            frame = predicate.apply(frame)
        return frame


def aggregate(
    metric: Metric,
    column: str | None,
    ctx: SecurityContext,
    audit: AuditLog,
    *,
    group_by: str | None = None,
    filters: Filters | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> ToolResult:
    """Compute one aggregate over the caller's employees."""
    filters = filters or Filters()
    try:
        if group_by:
            check_groupable(group_by)
        if metric not in {*_PANDAS_METRIC, "spread"}:
            raise ColumnError(
                f"unknown metric {metric!r}; choose one of "
                f"{sorted({*_PANDAS_METRIC, 'spread'})}"
            )
        # Counting rows is not an operation on a column, so a column is not
        # required -- "how many employees are there?" has to be expressible.
        if metric != "count" and column is None:
            raise ColumnError(f"{metric!r} needs a column: salary or performance_score")
        if column is not None:
            check_numeric(column)
    except ColumnError as err:
        audit.record(ctx, "stats", "refused", detail=str(err), layer="tool")
        return ToolResult(summary="", refused=True, reason=str(err))

    frame = filters.apply(tenant_frame(ctx, db_path))
    scope = filters.describe()

    if frame.empty:
        audit.record(ctx, "stats", "allowed", detail=f"no rows for {scope}", rows=0)
        return ToolResult(summary=f"No employees match: {scope}.")

    if metric == "count" and column is None:
        rows, summary = _headcount(frame, group_by, scope)
    elif group_by:
        rows, summary = _grouped(frame, metric, str(column), group_by, scope)
    else:
        rows, summary = _scalar(frame, metric, str(column), scope)

    audit.record(
        ctx, "stats", "allowed", rows=len(rows), layer="tool",
        detail=f"{metric}({column or 'rows'}) where {scope}"
        + (f" by {group_by}" if group_by else ""),
    )
    return ToolResult(summary=summary, rows=rows)


def _headcount(
    frame: pd.DataFrame, group_by: str | None, scope: str
) -> tuple[tuple[dict[str, object], ...], str]:
    if group_by:
        counts = frame.groupby(group_by).size().sort_values(ascending=False)
        rows = tuple({group_by: str(k), "employees": int(v)} for k, v in counts.items())
        return rows, f"headcount by {group_by} ({scope}), {len(rows)} group(s)."
    return ({"employees": int(len(frame))},), f"{len(frame)} employee(s) matching: {scope}."


def _grouped(
    frame: pd.DataFrame, metric: str, column: str, group_by: str, scope: str
) -> tuple[tuple[dict[str, object], ...], str]:
    grouped = frame.groupby(group_by)[column]
    series = (
        grouped.max() - grouped.min() if metric == "spread"
        else getattr(grouped, _PANDAS_METRIC[metric])()
    )
    rows = tuple(
        {group_by: str(key), f"{metric}_{column}": _number(value)}
        for key, value in series.sort_values(ascending=False).items()
    )
    return rows, f"{metric} of {column} by {group_by} ({scope}), {len(rows)} group(s)."


def _scalar(
    frame: pd.DataFrame, metric: str, column: str, scope: str
) -> tuple[tuple[dict[str, object], ...], str]:
    values = frame[column]
    result = (
        values.max() - values.min() if metric == "spread"
        else getattr(values, _PANDAS_METRIC[metric])()
    )
    value = _number(result)
    row: dict[str, object] = {f"{metric}_{column}": value, "employees": int(len(frame))}

    # "Who earns the most?" is a min/max question with a name attached. Without
    # the name this tool answers "231,377" and the model, having chosen it, then
    # has no way to say who -- so it either guesses or answers a lesser
    # question. Returning the row makes the obvious follow-up answerable.
    if metric in ("min", "max"):
        holder = frame.loc[values.idxmax() if metric == "max" else values.idxmin()]
        row["name"] = str(holder["name"])
        row["department"] = str(holder["department"])

    return (row,), f"{metric} of {column} for {scope}: {value} (over {len(frame)} employees)"


def _number(value: object) -> float | int:
    number = float(value)  # type: ignore[arg-type]
    return int(number) if number.is_integer() else round(number, 2)
