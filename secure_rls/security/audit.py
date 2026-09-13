"""Structured audit trail for every security-relevant decision.

In plain terms: A log of every security decision (allowed, refused, error) with
who asked and which layer decided. The Audit view reads it.

Two consumers, one record:

* a JSON-lines file, which is what an operator or a later SIEM would read;
* an in-memory ring buffer, which the UI renders live during the demo so the
  isolation guarantee is visible rather than merely asserted.

Every tool call produces exactly one record, whatever the outcome, and every
record carries the acting tenant. An access decision that is not written down
is an access decision nobody can review.
"""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

from secure_rls.security.context import SecurityContext

Verdict = Literal["allowed", "refused", "error"]

DEFAULT_LOG_PATH: Final = Path("audit.log")
_BUFFER_SIZE: Final = 500


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One logged decision: who, which tenant, what happened, and which layer decided."""
    timestamp: float
    tenant_id: str
    username: str
    event: str
    verdict: Verdict
    detail: str = ""
    sql: str | None = None
    rows: int | None = None
    layer: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_json(self) -> str:
        """The record as one line of JSON, for the log file."""
        return json.dumps(asdict(self), default=str, ensure_ascii=False)

    @property
    def clock(self) -> str:
        """The time of the record as HH:MM:SS, for display."""
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))


class AuditLog:
    """Append-only audit sink. Cheap enough to call on every decision."""

    def __init__(self, path: Path | str | None = DEFAULT_LOG_PATH) -> None:
        """Set up the log. Pass None as the path to keep records in memory only."""
        self._path = Path(path) if path is not None else None
        self._buffer: deque[AuditRecord] = deque(maxlen=_BUFFER_SIZE)

    def record(
        self,
        ctx: SecurityContext,
        event: str,
        verdict: Verdict,
        *,
        detail: str = "",
        sql: str | None = None,
        rows: int | None = None,
        layer: str | None = None,
        **extra: Any,
    ) -> AuditRecord:
        """Write one decision to memory and, if a file is set, append it to the file."""
        entry = AuditRecord(
            timestamp=time.time(),
            tenant_id=ctx.tenant_id,
            username=ctx.username,
            event=event,
            verdict=verdict,
            detail=detail,
            sql=sql,
            rows=rows,
            layer=layer,
            extra=extra,
        )
        self._buffer.append(entry)
        if self._path is not None:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(entry.as_json() + "\n")
        return entry

    def recent(self, limit: int = 50, tenant_id: str | None = None) -> list[AuditRecord]:
        """Newest first. ``tenant_id`` scopes the view -- the audit log is
        multi-tenant data too, and the UI must not show one tenant another's
        activity."""
        items = [r for r in reversed(self._buffer) if tenant_id in (None, r.tenant_id)]
        return items[:limit]

    def clear(self) -> None:
        """Forget the records held in memory. The file is not touched."""
        self._buffer.clear()


#: Process-wide default sink.
AUDIT: Final = AuditLog()
