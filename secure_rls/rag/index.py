"""Semantic search over the free-text ``notes`` column.

**One index per tenant, not one index with a filter.**

The usual RAG design is a single vector store where each chunk carries a
tenant id, filtered at query time. It works until it doesn't: a filter that is
applied after the nearest-neighbour search silently degrades recall, a filter
that is forgotten on one code path leaks, and no test of the store's contents
can tell the two apart. Here each tenant gets its own index, built through the
same guarded connection everything else uses, so a foreign note is never
embedded into a structure the caller can search. Isolation becomes a property
of what exists rather than of a parameter someone has to remember to pass.

The cost is real and worth stating: more memory, and rebuilding N indexes
instead of one when the data changes. At three tenants and a thousand rows
that is nothing. At ten thousand tenants it would not be, and the answer there
is a per-tenant namespace in a store that enforces it server-side -- the same
idea, moved down a layer.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from db import DEFAULT_DB_PATH, TENANT_VIEW, tenant_connection
from secure_rls.security.context import SecurityContext

EMBEDDING_MODEL: Final = "BAAI/bge-small-en-v1.5"

#: bge asks for this prefix on the query side only; it measurably improves
#: retrieval and costs nothing.
_QUERY_PREFIX: Final = "Represent this sentence for searching relevant passages: "

_indexes: dict[str, NoteIndex] = {}
_lock = threading.Lock()
_encoder: Any = None


def _get_encoder() -> Any:
    """Load the sentence encoder once per process."""
    global _encoder
    if _encoder is None:
        from sentence_transformers import SentenceTransformer

        _encoder = SentenceTransformer(EMBEDDING_MODEL)
    return _encoder


@dataclass(frozen=True, slots=True)
class Note:
    user_id: int
    name: str
    department: str
    tenant_id: str
    text: str


class NoteIndex:
    """A vector index containing exactly one tenant's notes."""

    def __init__(self, tenant_id: str, notes: list[Note], vectors: Any) -> None:
        self.tenant_id = tenant_id
        self._notes = notes
        self._vectors = vectors

    def __len__(self) -> int:
        return len(self._notes)

    @property
    def tenants_present(self) -> set[str]:
        """Every tenant represented in the index. Used by the isolation tests:
        for a correctly built index this is always a single-element set."""
        return {note.tenant_id for note in self._notes}

    def search(self, query: str, k: int = 5) -> list[tuple[Note, float]]:
        import numpy as np

        if not self._notes:
            return []
        encoder = _get_encoder()
        vector = encoder.encode(
            [_QUERY_PREFIX + query], normalize_embeddings=True, show_progress_bar=False
        )
        scores = np.asarray(self._vectors) @ np.asarray(vector).T
        scores = scores.ravel()
        top = np.argsort(-scores)[: min(k, len(self._notes))]
        return [(self._notes[int(i)], float(scores[int(i)])) for i in top]


def _build(ctx: SecurityContext, db_path: Path | str) -> NoteIndex:
    with tenant_connection(ctx, db_path) as con:
        rows = con.execute(
            f"SELECT user_id, name, department, tenant_id, notes FROM {TENANT_VIEW}"  # noqa: S608
        ).fetchall()

    notes = [
        Note(
            user_id=int(r["user_id"]),
            name=str(r["name"]),
            department=str(r["department"]),
            tenant_id=str(r["tenant_id"]),
            text=str(r["notes"]),
        )
        for r in rows
    ]
    encoder = _get_encoder()
    vectors = encoder.encode(
        [f"{n.name} ({n.department}): {n.text}" for n in notes],
        normalize_embeddings=True,
        show_progress_bar=False,
        batch_size=64,
    )
    return NoteIndex(ctx.tenant_id, notes, vectors)


def get_index(ctx: SecurityContext, db_path: Path | str = DEFAULT_DB_PATH) -> NoteIndex:
    """Return this tenant's index, building it on first use.

    Keyed by tenant id, so one tenant's cached index can never be served to
    another. Building takes a couple of seconds for a thousand notes, which is
    why it is cached rather than done per query.
    """
    with _lock:
        index = _indexes.get(ctx.tenant_id)
        if index is None:
            index = _build(ctx, db_path)
            _indexes[ctx.tenant_id] = index
        return index


def reset_indexes() -> None:
    """Drop every cached index. For tests and for reloading the dataset."""
    with _lock:
        _indexes.clear()
