"""Column vocabulary shared by the pandas-backed tools.

The SQL tool gets its safety from the guard and the authorizer. These tools
never build SQL at all -- they operate on the tenant's DataFrame, which
:func:`db.tenant_frame` has already restricted. What they still need is a
closed vocabulary: a column name arriving from the model is an untrusted
string, and pandas will happily accept one that turns a chart request into
something else. Everything below is checked against these sets first.
"""

from __future__ import annotations

from typing import Final

NUMERIC_COLUMNS: Final[frozenset[str]] = frozenset({"salary", "performance_score"})
CATEGORICAL_COLUMNS: Final[frozenset[str]] = frozenset({"department", "name", "hire_date"})
GROUPABLE_COLUMNS: Final[frozenset[str]] = frozenset({"department"})


class ColumnError(ValueError):
    """A column name from the model is not part of the vocabulary."""


def check_numeric(column: str) -> str:
    if column not in NUMERIC_COLUMNS:
        raise ColumnError(
            f"{column!r} is not a numeric column; choose one of "
            f"{sorted(NUMERIC_COLUMNS)}"
        )
    return column


def check_groupable(column: str) -> str:
    if column not in GROUPABLE_COLUMNS:
        raise ColumnError(
            f"cannot group by {column!r}; groupable columns are "
            f"{sorted(GROUPABLE_COLUMNS)}"
        )
    return column
