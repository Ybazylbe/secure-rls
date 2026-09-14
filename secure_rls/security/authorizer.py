"""The kernel layer (L3) of the RLS design: an SQLite authorizer callback.

In plain terms: A callback that SQLite asks before every read or function call.
It only lets the real table be read through the tenant's own view, and refuses
everything else.

Layer L2 gives each connection a per-tenant view over the base table. This
layer makes that view the *only* way in. SQLite invokes the authorizer for
every object a statement touches, before any row is produced, so the control
sits below SQL parsing: it holds even if the query text is adversarial and even
if the SQL guard (L4) has a bug.

The mechanism is a documented detail of the authorizer contract: when a read is
performed while expanding a view, the callback's fifth argument carries that
view's name; a direct read of the same table carries ``None``. We allow reads of
the base table only in the first case.

    SELECT * FROM employees       -> READ employees_all ... source='employees'  OK
    SELECT * FROM employees_all   -> READ employees_all ... source=None         DENY
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Final

#: Statement kinds a read-only analytics connection legitimately needs.
_ALLOWED_ACTIONS: Final[frozenset[int]] = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_RECURSIVE,  # common table expressions
    }
)

#: SQL functions the agent may call. Default-deny: anything not listed here is
#: refused, which rules out extension loading and file I/O by construction.
#: The SQL guard (L4) imports this same set, so the two layers cannot drift
#: apart and disagree about what is callable.
#:
#: ``group_concat`` is deliberately absent. The row cap (L4's LIMIT 500) counts
#: *output rows*, and a bare aggregate is always one row -- so
#: ``SELECT group_concat(name || ':' || salary) FROM employees`` returned an
#: entire tenant's names and salaries concatenated into a single cell,
#: unlimited by anything upstream. Nothing crossed a tenant boundary, but it
#: defeated the bulk-extraction guard the cap exists for. No tool here needs it.
ALLOWED_FUNCTIONS: Final[frozenset[str]] = frozenset(
    {
        # aggregates
        "avg", "count", "max", "min", "sum", "total",
        # numeric
        "abs", "round", "ceil", "ceiling", "floor", "cast", "sqrt", "pow", "power",
        # string
        "coalesce", "ifnull", "nullif", "length", "lower", "upper", "ltrim",
        "rtrim", "trim", "replace", "substr", "substring", "instr", "printf",
        "format", "like", "glob",
        # date / time
        "date", "time", "datetime", "julianday", "strftime", "unixepoch",
        # window / misc
        "row_number", "rank", "dense_rank", "ntile", "lag", "lead",
        "first_value", "last_value", "iif", "typeof",
    }
)

DenyHook = Callable[[str], None]


class AuthorizerDenial(sqlite3.DatabaseError):
    """Raised by SQLite when the authorizer refuses an access."""


def make_authorizer(
    *,
    view_name: str = "employees",
    base_table: str = "employees_all",
    on_deny: DenyHook | None = None,
) -> Callable[[int, str | None, str | None, str | None, str | None], int]:
    """Build an authorizer callback bound to one tenant view.

    Args:
        view_name: the per-tenant view created by :mod:`db` for this connection.
        base_table: the multi-tenant table the view reads from.
        on_deny: optional audit hook, called with a human-readable reason.
    """

    def deny(reason: str) -> int:
        """Tell the audit hook why, then tell SQLite to refuse."""
        if on_deny is not None:
            on_deny(reason)
        return sqlite3.SQLITE_DENY

    def authorizer(
        action: int,
        arg1: str | None,
        arg2: str | None,
        db_name: str | None,
        source: str | None,
    ) -> int:
        """Called by SQLite for every action a statement needs. Returns OK or DENY."""
        if action in _ALLOWED_ACTIONS:
            return sqlite3.SQLITE_OK

        if action == sqlite3.SQLITE_READ:
            table, column = arg1, arg2
            if table == base_table:
                # Only reachable through the tenant view, never directly.
                if source == view_name:
                    return sqlite3.SQLITE_OK
                return deny(f"direct read of base table {base_table}.{column}")
            if table == view_name:
                return sqlite3.SQLITE_OK
            if db_name == "temp":
                return sqlite3.SQLITE_OK
            return deny(f"read of out-of-scope object {table}.{column}")

        if action == sqlite3.SQLITE_FUNCTION:
            name = (arg2 or "").lower()
            if name in ALLOWED_FUNCTIONS:
                return sqlite3.SQLITE_OK
            return deny(f"call to non-allowlisted function {name!r}")

        # Everything else -- ATTACH, DETACH, PRAGMA, writes, DDL, transactions,
        # sqlite_master introspection -- is refused.
        return deny(f"disallowed action {action} on {arg1!r}")

    return authorizer
