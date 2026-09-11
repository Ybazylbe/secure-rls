"""The validation layer (L4): parse, vet and rewrite model-generated SQL.

Layers L2 and L3 already make unauthorised reads impossible. This layer exists
for three other reasons:

1. **Explainability.** A query refused here produces a precise reason ("table
   `employees_all` is not available") instead of a generic SQLite error, which
   is what the UI shows and what the audit log records.
2. **Blast radius.** Statement shape, table and function allowlists and a row
   cap are enforced before SQLite ever sees the text, so a prompt-injected
   query is rejected rather than merely contained.
3. **Independence.** It is a second, differently-implemented opinion. If a
   future change breaks the view or the authorizer, this layer still stands --
   and the isolation tests would still fail loudly, which is the point.

Validation is done on the parsed AST, never on the query string. String
inspection of SQL is folklore: comments, string literals, unicode escapes and
nested quoting defeat it. The tenant predicate is likewise *injected into the
AST* and rendered back out, so it cannot be commented out or escaped from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

import sqlglot
from sqlglot import exp

from secure_rls.security.authorizer import ALLOWED_FUNCTIONS
from secure_rls.security.context import SecurityContext

DIALECT: Final = "sqlite"

#: The only relation the agent may name. This is the per-tenant view from
#: :mod:`db`; the underlying multi-tenant table is not part of the vocabulary.
ALLOWED_TABLES: Final[frozenset[str]] = frozenset({"employees"})

ALLOWED_COLUMNS: Final[frozenset[str]] = frozenset(
    {
        "user_id", "tenant_id", "name", "department", "salary",
        "performance_score", "hire_date", "notes",
    }
)

#: Hard cap on returned rows. Bulk extraction is not an analytics use case, and
#: an unbounded SELECT is the cheapest way to strip-mine a dataset.
MAX_ROWS: Final = 500

#: Statement kinds that must never appear, at any depth. The root-node check
#: below already rejects most of them; scanning the whole tree also catches
#: them nested inside subqueries or CTEs.
_FORBIDDEN_NODES: Final[tuple[type[exp.Expression], ...]] = tuple(
    node
    for node in (
        getattr(exp, attr, None)
        for attr in (
            "Insert", "Update", "Delete", "Drop", "Create", "Alter", "Command",
            "Pragma", "Attach", "Detach", "Transaction", "Commit", "Rollback",
            "Set", "Use", "Grant", "Analyze", "Vacuum",
        )
    )
    if isinstance(node, type)
)


class SqlGuardError(ValueError):
    """A model-generated statement was refused before execution."""

    def __init__(self, reason: str, *, sql: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.sql = sql


@dataclass(frozen=True, slots=True)
class GuardedQuery:
    """A statement cleared for execution, plus what the guard changed."""

    sql: str
    original: str
    rewrites: tuple[str, ...] = field(default=())

    @property
    def was_rewritten(self) -> bool:
        return bool(self.rewrites)


def guard(sql: str, ctx: SecurityContext, *, max_rows: int = MAX_ROWS) -> GuardedQuery:
    """Validate and rewrite ``sql`` for execution on behalf of ``ctx``.

    Raises:
        SqlGuardError: with a reason suitable for showing to the user.
    """
    statement = _parse_single(sql)
    _reject_forbidden_nodes(statement, sql)
    cte_names = _cte_names(statement)
    _check_tables(statement, cte_names, sql)
    _check_functions(statement, sql)
    _check_columns(statement, sql)

    rewrites: list[str] = []
    _strip_comments(statement)
    _apply_tenant_predicate(statement, ctx, rewrites)
    _apply_row_cap(statement, max_rows, rewrites)

    return GuardedQuery(
        sql=statement.sql(dialect=DIALECT, pretty=True),
        original=sql.strip(),
        rewrites=tuple(rewrites),
    )


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def _parse_single(sql: str) -> exp.Expression:
    """Parse one read-only statement.

    Returns ``Expression`` rather than ``Query``: in sqlglot those are separate
    branches of the hierarchy -- ``Select`` inherits both, but ``Query`` on its
    own does not descend from ``Expression`` and so has none of the traversal
    methods the checks below rely on. ``Query`` is what we verify, not what we
    carry around.
    """
    if not sql or not sql.strip():
        raise SqlGuardError("empty statement", sql=sql)
    try:
        statements = sqlglot.parse(sql, dialect=DIALECT)
    except sqlglot.ParseError as err:
        raise SqlGuardError(f"could not parse SQL: {err}", sql=sql) from err

    statements = [s for s in statements if s is not None]
    if not statements:
        raise SqlGuardError("no statement found", sql=sql)
    if len(statements) > 1:
        raise SqlGuardError(
            f"only one statement may be executed, got {len(statements)}", sql=sql
        )

    statement = statements[0]
    if not isinstance(statement, exp.Expression) or not isinstance(statement, exp.Query):
        raise SqlGuardError(
            f"only read-only SELECT statements are allowed, got "
            f"{type(statement).__name__.upper()}",
            sql=sql,
        )
    return statement


def _reject_forbidden_nodes(statement: exp.Expression, sql: str) -> None:
    for node in statement.walk():
        if isinstance(node, _FORBIDDEN_NODES):
            raise SqlGuardError(
                f"statement kind {type(node).__name__.upper()} is not allowed", sql=sql
            )


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


def _cte_names(statement: exp.Expression) -> frozenset[str]:
    return frozenset(cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE))


def _check_tables(statement: exp.Expression, cte_names: frozenset[str], sql: str) -> None:
    for table in statement.find_all(exp.Table):
        name = table.name.lower()
        if name in cte_names or name in ALLOWED_TABLES:
            if table.db or table.catalog:
                raise SqlGuardError(
                    f"schema-qualified references are not allowed: {table.sql(DIALECT)}",
                    sql=sql,
                )
            continue
        raise SqlGuardError(
            f"table {table.name!r} is not available; the only table you may query "
            f"is 'employees'",
            sql=sql,
        )


#: Nodes sqlglot models as functions that are really SQL *syntax* -- SQLite
#: never fires a function-authorisation callback for them, so neither do we.
#: Their operands are still walked and checked.
_SYNTAX_NODES: Final[tuple[type[exp.Expression], ...]] = tuple(
    node
    for node in (
        getattr(exp, attr, None)
        for attr in ("Case", "Cast", "Distinct", "Extract", "Exists")
    )
    if isinstance(node, type)
)

#: A real function call always renders as ``NAME(...)`` with a bare identifier
#: in front of the parenthesis. Anything else that reaches here is an operator
#: or a connective, not a call.
_CALLABLE_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _function_name(node: exp.Func) -> str:
    """The name SQLite will actually see, or "" if this is not a call at all.

    Two traps here, both found by testing rather than by reading the docs.

    sqlglot canonicalises function nodes on parse -- ``strftime`` becomes a
    ``TimeToStr`` node -- so the class name is the wrong thing to match on. The
    rendered SQLite form gives the name the authorizer (L3) will be asked
    about, which keeps the two layers checking the same thing.

    But ``exp.Func`` is also the base class of the boolean connectives: ``AND``
    is an ``exp.And``, which is an ``exp.Func``. Taking the text before the
    first parenthesis therefore read ``a = 1 AND (b = 2)`` as a call to a
    function named "a = 1 and", and refused ordinary queries. Hence the
    identifier check: a genuine call has a bare name in front of the bracket,
    and nothing else does. Skipping a connective is safe -- the walk still
    descends into its operands, so a hostile function nested inside an ``AND``
    is still caught.
    """
    if isinstance(node, exp.Anonymous):
        return node.name.lower()

    head, bracket, _ = node.sql(dialect=DIALECT).partition("(")
    if not bracket:
        # A bare keyword such as CURRENT_DATE, or one of the transparent
        # wrapper nodes sqlglot inserts while canonicalising.
        return ""
    head = head.strip()
    if not _CALLABLE_NAME.match(head):
        return ""
    return head.lower()


def _check_functions(statement: exp.Expression, sql: str) -> None:
    for node in statement.find_all(exp.Func):
        if isinstance(node, _SYNTAX_NODES):
            continue
        name = _function_name(node)
        if not name:
            continue
        if name not in ALLOWED_FUNCTIONS:
            raise SqlGuardError(f"function {name!r} is not allowed", sql=sql)


def _check_columns(statement: exp.Expression, sql: str) -> None:
    """Columns must be real columns or names introduced by the query itself."""
    local: set[str] = {a.alias_or_name.lower() for a in statement.find_all(exp.Alias)}
    local |= {t.alias_or_name.lower() for t in statement.find_all(exp.TableAlias)}
    local |= _cte_names(statement)

    for column in statement.find_all(exp.Column):
        name = column.name.lower()
        if not name or name == "*":
            continue
        if name in ALLOWED_COLUMNS or name in local:
            continue
        raise SqlGuardError(
            f"column {column.name!r} does not exist on 'employees'", sql=sql
        )


# ---------------------------------------------------------------------------
# Rewrites
# ---------------------------------------------------------------------------


def _strip_comments(statement: exp.Expression) -> None:
    """Drop SQL comments from the tree.

    They cannot affect validation, which runs on the AST, but a rendered
    ``-- AND tenant_id='acme'`` in the query shown to the user is confusing at
    best. Removing them keeps the displayed SQL exactly what will execute.
    """
    for node in statement.walk():
        if node.comments:
            node.comments = []


def _local_tables(select: exp.Select) -> list[exp.Table]:
    """Tables in this SELECT's own FROM/JOIN clauses, ignoring subqueries.

    Deliberately walks direct child expressions rather than reading
    ``select.args["from"]``: sqlglot renamed that key to ``from_`` in v30, and
    the old lookup silently returned ``None``, which made this function report
    "no tables" and quietly skip the rewrite. A security control that fails
    open on a library upgrade is worse than one that fails loudly, so the
    traversal now depends only on node types.
    """
    tables: list[exp.Table] = []
    for child in select.iter_expressions():
        if isinstance(child, exp.From | exp.Join):
            tables.extend(child.find_all(exp.Table))
    return tables


def _apply_tenant_predicate(
    statement: exp.Expression, ctx: SecurityContext, rewrites: list[str]
) -> None:
    """Add ``tenant_id = <tenant>`` to every scope that reads ``employees``.

    Belt and braces: the view already restricts the rows, so this predicate is
    always redundant at runtime. It is applied anyway because the rewritten SQL
    is what the UI displays -- the filter is visible to a reviewer -- and
    because it keeps the guarantee intact if this SQL is ever pointed at a
    plain table instead of the view.
    """
    for select in statement.find_all(exp.Select):
        for table in _local_tables(select):
            if table.name.lower() not in ALLOWED_TABLES:
                continue
            qualifier = table.alias_or_name
            condition = exp.column("tenant_id", qualifier).eq(
                exp.Literal.string(ctx.tenant_id)
            )
            select.where(condition, append=True, copy=False)
            rewrites.append(
                f"added {qualifier}.tenant_id = '{ctx.tenant_id}' to the WHERE clause"
            )


def _apply_row_cap(statement: exp.Expression, max_rows: int, rewrites: list[str]) -> None:
    limit = statement.args.get("limit")
    current: int | None = None
    if isinstance(limit, exp.Limit):
        expression = limit.expression
        if isinstance(expression, exp.Literal) and expression.is_int:
            current = int(expression.name)

    if current is None:
        statement.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
        rewrites.append(f"capped the result set at {max_rows} rows")
    elif current > max_rows:
        statement.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
        rewrites.append(f"lowered LIMIT {current} to the {max_rows}-row cap")
