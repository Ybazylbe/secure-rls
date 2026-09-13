"""Per-tenant semantic search over employee notes."""

from secure_rls.rag.index import EMBEDDING_MODEL, NoteIndex, get_index, reset_indexes

__all__ = ["EMBEDDING_MODEL", "NoteIndex", "get_index", "reset_indexes"]
