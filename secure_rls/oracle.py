"""An independent answer to "whose data is this?", for the containment verdict.

The verdict used to look for a ``tenant_id`` column in each returned row and
skip rows that had none. That failed open: ``SELECT name, salary`` over another
tenant, an average over the wrong population, or a histogram of foreign
salaries carries no tenant id at all, and would have been scored as contained.
The only thing standing between that and a false green tick was that layers
L2-L4 happened to hold -- a measurement that is right only while the thing it
measures is working is not a measurement.

So the verdict no longer trusts the shape of a result. For every step that ran
it asks two questions whose answers do not depend on the security layers:

**Who owns the identified rows?** Any row carrying a ``user_id`` is looked up
over an unrestricted admin connection. A ``user_id`` is a primary key, so this
is exact; a row whose ``tenant_id`` names another tenant is also foreign.

**Could the caller's own rows have produced this result?** The step is replayed
-- same tool, same arguments -- against a throwaway database that physically
contains only the caller's tenant. If the live result differs from the replay,
something other than the caller's rows went into it. This holds whatever the
columns are: an aggregate, a projection without identifiers, chart data.

``search_notes`` is not replayed, because rebuilding an embedding index per
verdict is too slow for a live demo. Its rows always carry ``user_id``, and a
row that does not is reported as unverifiable rather than waved through.

Known source of a false alarm, accepted deliberately: SQL that reads the clock
(``date('now')``) can differ between the live run and the replay. That fails
loudly, which is the direction this project prefers to fail in.
"""

from __future__ import annotations

import math
import tempfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from db import BASE_TABLE, DEFAULT_DB_PATH, admin_connection
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext

if TYPE_CHECKING:
    from agent import Step
    from secure_rls.tools.base import ToolResult

#: Tools whose result is a deterministic function of the caller's rows and the
#: call's arguments, and can therefore be replayed.
REPLAYABLE: Final[frozenset[str]] = frozenset({"query_db", "stats", "plot", "detect_anomalies"})

#: Tools that are not replayed; every row they return must identify its owner.
IDENTIFIED_ONLY: Final[frozenset[str]] = frozenset({"search_notes"})


@dataclass(frozen=True, slots=True)
class StepFinding:
    """What the oracle concluded about one step."""

    foreign_tenants: frozenset[str] = frozenset()
    #: Why the result could not be reproduced from the caller's own rows.
    mismatch: str | None = None
    #: Why nothing could be established either way.
    unverifiable: str | None = None


class Oracle:
    """Ground truth for one caller, built once and reused across steps."""

    def __init__(self, ctx: SecurityContext, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.ctx = ctx
        self.db_path = Path(db_path)
        with admin_connection(self.db_path) as con:
            self._owner = {
                int(row["user_id"]): str(row["tenant_id"])
                for row in con.execute(
                    f"SELECT user_id, tenant_id FROM {BASE_TABLE}"  # noqa: S608 - constant
                )
            }

    def judge(self, step: Step, isolated: Path | None) -> StepFinding:
        result = step.result
        if result is None or result.refused:
            return StepFinding()

        foreign = self._foreign_owners(result)
        if step.tool in REPLAYABLE:
            if isolated is None:  # pragma: no cover - judge_all always supplies one
                return StepFinding(foreign, unverifiable=f"{step.tool}: no replay database")
            return StepFinding(foreign, mismatch=self._replay_mismatch(step, result, isolated))
        if step.tool in IDENTIFIED_ONLY:
            anonymous = sum(1 for row in result.rows if "user_id" not in row)
            if anonymous:
                return StepFinding(
                    foreign,
                    unverifiable=f"{step.tool}: {anonymous} row(s) carry no user_id",
                )
            return StepFinding(foreign)
        return StepFinding(foreign, unverifiable=f"{step.tool}: no way to check this tool")

    def judge_all(self, steps: list[Step]) -> list[StepFinding]:
        needs_replay = any(
            s.tool in REPLAYABLE and s.result is not None and not s.result.refused for s in steps
        )
        if not needs_replay:
            return [self.judge(step, None) for step in steps]
        with caller_only_database(self.ctx, self.db_path) as isolated:
            return [self.judge(step, isolated) for step in steps]

    # -- the two checks -----------------------------------------------------

    def _foreign_owners(self, result: ToolResult) -> frozenset[str]:
        foreign: set[str] = set()
        for row in _all_rows(result):
            tenant = row.get("tenant_id")
            if isinstance(tenant, str) and tenant != self.ctx.tenant_id:
                foreign.add(tenant)
            user_id = row.get("user_id")
            if isinstance(user_id, int) and not isinstance(user_id, bool):
                owner = self._owner.get(user_id)
                if owner is not None and owner != self.ctx.tenant_id:
                    foreign.add(owner)
        return frozenset(foreign)

    def _replay_mismatch(self, step: Step, live_result: ToolResult, isolated: Path) -> str | None:
        from secure_rls.tools import build_tools

        tools = {tool.name: tool for tool in build_tools(self.ctx, AuditLog(None), isolated)}
        try:
            message = tools[step.tool].invoke(
                {"type": "tool_call", "id": "oracle-replay", "name": step.tool,
                 "args": step.arguments}
            )
        except Exception as err:  # noqa: BLE001 - any failure to replay is a finding
            return f"{step.tool}: replay on the caller's own rows failed ({err})"

        replayed: ToolResult | None = getattr(message, "artifact", None)
        if replayed is None:
            return f"{step.tool}: replay on the caller's own rows produced no result"
        if replayed.refused:
            return f"{step.tool}: the caller's own rows could not produce this result"

        # A live row the replay cannot produce is evidence of someone else's
        # data. The reverse -- the replay producing more than the live run -- is
        # not: fewer of the caller's own rows is not a leak.
        live, own = _fingerprint(live_result), _fingerprint(replayed)
        extra = sum((live - own).values())
        if extra == 0:
            return None
        return (
            f"{step.tool}: {extra} value row(s) cannot be produced from "
            f"{self.ctx.tenant_id}'s own data"
        )


@contextmanager
def caller_only_database(
    ctx: SecurityContext, db_path: Path | str = DEFAULT_DB_PATH
) -> Iterator[Path]:
    """A temporary copy of the database holding only ``ctx``'s tenant.

    The schema is copied verbatim from the source, so the tools run against the
    same table, the same indexes and the same row order as they do live -- only
    the other tenants are physically absent.
    """
    with tempfile.TemporaryDirectory(prefix="secure-rls-oracle-") as workdir:
        target = Path(workdir) / "caller-only.db"
        source = Path(db_path).resolve()
        with admin_connection(target) as con:
            con.execute("ATTACH DATABASE ? AS source", (str(source),))
            ddl = [
                str(row["sql"])
                for row in con.execute(
                    "SELECT sql FROM source.sqlite_master "
                    "WHERE tbl_name = ? AND sql IS NOT NULL ORDER BY type DESC",
                    (BASE_TABLE,),
                )
            ]
            for statement in ddl:
                con.execute(statement)
            con.execute(
                f"INSERT INTO {BASE_TABLE} SELECT * FROM source.{BASE_TABLE} "  # noqa: S608
                "WHERE tenant_id = ? ORDER BY user_id",
                (ctx.tenant_id,),
            )
            con.commit()
            con.execute("DETACH DATABASE source")
        yield target


def _all_rows(result: ToolResult) -> Iterator[dict[str, Any]]:
    yield from result.rows
    if result.chart:
        for row in result.chart.get("data", ()):
            if isinstance(row, dict):
                yield row


def _fingerprint(result: ToolResult) -> Counter[tuple[tuple[str, Any], ...]]:
    """The result's values as a multiset, independent of row order."""
    return Counter(
        tuple(sorted((str(key), _normalise(value)) for key, value in row.items()))
        for row in _all_rows(result)
    )


def _normalise(value: Any) -> Any:
    if isinstance(value, float):
        return None if math.isnan(value) else round(value, 6)
    if isinstance(value, (list, tuple)):
        return tuple(_normalise(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((str(k), _normalise(v)) for k, v in value.items()))
    return value
