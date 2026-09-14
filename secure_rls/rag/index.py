"""Semantic search over the free-text ``notes`` column.

In plain terms: Builds and searches a separate vector index of employee notes
for each tenant, so one tenant's search can never find another tenant's notes.

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

import re
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

_indexes: dict[tuple[str, str], NoteIndex] = {}
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
    """One employee note, ready to be searched."""
    user_id: int
    name: str
    department: str
    tenant_id: str
    text: str


class NoteIndex:
    """A vector index containing exactly one tenant's notes."""

    def __init__(self, tenant_id: str, notes: list[Note], vectors: Any) -> None:
        """Store one tenant's notes and their vectors."""
        self.tenant_id = tenant_id
        self._notes = notes
        self._vectors = vectors

    def __len__(self) -> int:
        """How many notes are in the index."""
        return len(self._notes)

    @property
    def tenants_present(self) -> set[str]:
        """Every tenant represented in the index. Used by the isolation tests:
        for a correctly built index this is always a single-element set."""
        return {note.tenant_id for note in self._notes}

    def search(
        self,
        query: str,
        k: int = 5,
        *,
        name_weight: float | None = None,
        text_weight: float | None = None,
    ) -> list[tuple[Note, float]]:
        """Return the k best-matching notes, with their scores.

        The score is semantic similarity plus a word-match bonus (see
        _keyword_scores). Meaning alone could not find a named person: asked
        for "Ravi Sato", it returned five other employees called Sato and
        ranked Ravi's own note below them, because his note's wording was
        further from the query than theirs.

        The weights default to the tuned values below; evals/retrieval.py
        passes zero to measure what semantic search alone would have done.
        """
        import numpy as np

        if not self._notes:
            return []
        encoder = _get_encoder()
        vector = encoder.encode(
            [_QUERY_PREFIX + query], normalize_embeddings=True, show_progress_bar=False
        )
        semantic = (np.asarray(self._vectors) @ np.asarray(vector).T).ravel()
        bonus = _keyword_scores(
            query,
            self._notes,
            _NAME_WEIGHT if name_weight is None else name_weight,
            _TEXT_WEIGHT if text_weight is None else text_weight,
        )
        scores = semantic + np.asarray(bonus)
        top = np.argsort(-scores)[: min(k, len(self._notes))]
        return [(self._notes[int(i)], float(scores[int(i)])) for i in top]


#: How much an exact word match adds to semantic similarity (which runs 0..1).
#: A name counts far more than a word in the note text: a person named in the
#: query is almost certainly the person being asked about.
_NAME_WEIGHT: Final = 0.5
_TEXT_WEIGHT: Final = 0.1
_WORD: Final = re.compile(r"[a-z0-9]+")


def _keyword_scores(
    query: str,
    notes: list[Note],
    name_weight: float = _NAME_WEIGHT,
    text_weight: float = _TEXT_WEIGHT,
) -> list[float]:
    """A bonus per note for words it shares with the query.

    In plain terms: this is the "keyword" half of a hybrid search. For each
    note it adds (a) the share of the employee's name that appears in the query,
    so "Ravi Sato" scores Ravi Sato 1.0 and Kenji Sato 0.5, and (b) a smaller
    amount for query words that appear in the note text. A query with no names
    or shared words gets no bonus, so searching by meaning works as before.
    """
    words = {w for w in _WORD.findall(query.lower()) if len(w) > 1}
    if not words:
        return [0.0] * len(notes)
    scores: list[float] = []
    for note in notes:
        name = set(_WORD.findall(note.name.lower()))
        text = set(_WORD.findall(note.text.lower()))
        name_share = len(name & words) / len(name) if name else 0.0
        text_share = len(text & words) / len(words)
        scores.append(name_weight * name_share + text_weight * text_share)
    return scores


#: A note's text is replaced with this when the caller's role masks the
#: `notes` column (see db.VIEWER_MASKED_COLUMNS). Explicit rather than an
#: empty string, so a masked result reads as "hidden", not as "this person
#: wrote nothing".
_MASKED_NOTE: Final = "[notes masked for this role]"


def _build(ctx: SecurityContext, db_path: Path | str) -> NoteIndex:
    """Read one tenant's notes through the guarded connection and embed them into a new index."""
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
            # NULL only ever means "masked for this role": the column is
            # `NOT NULL DEFAULT ''` in the base table, so a real note is never
            # NULL -- it can be empty, but that is a different, unmasked value.
            text=_MASKED_NOTE if r["notes"] is None else str(r["notes"]),
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


def _cache_key(ctx: SecurityContext) -> tuple[str, str]:
    """(tenant, role): what an index's *content* actually depends on.

    Keying by tenant alone was a masking bypass waiting to happen: a viewer
    and an analyst from the same tenant would share one cached index, so
    whichever of them triggered the build first decided what the other one
    searched -- real note text for a viewer if an analyst asked first, or
    :data:`_MASKED_NOTE` garbage for an analyst if a viewer did. Role is part
    of the cache key for the same reason it is part of the view: the content
    behind ``ctx`` is not determined by tenant alone.
    """
    return (ctx.tenant_id, ctx.role)


def get_index(ctx: SecurityContext, db_path: Path | str = DEFAULT_DB_PATH) -> NoteIndex:
    """Return this tenant-and-role's index, building it on first use.

    Keyed by :func:`_cache_key`, so one tenant's cached index can never be
    served to another, and one role's cannot be served to another either.
    Building takes a couple of seconds for a thousand notes, which is why it
    is cached rather than done per query.
    """
    key = _cache_key(ctx)
    with _lock:
        index = _indexes.get(key)
        if index is None:
            index = _build(ctx, db_path)
            _indexes[key] = index
        return index


def reset_indexes() -> None:
    """Drop every cached index. For tests and for reloading the dataset."""
    with _lock:
        _indexes.clear()
