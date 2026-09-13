"""The identity layer (L1) of the RLS design.

In plain terms: The SecurityContext: a small, unchangeable object saying who
the user is and which tenant they belong to. Tools receive it from our code,
never from the model.

A ``SecurityContext`` is the *only* source of the current tenant. It is built
from the server-side session at login and is never derived from model output,
tool arguments or user-supplied text. Tools therefore take no ``tenant_id``
parameter at all: there is nothing for the LLM to forge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: Closed set of tenants. Also acts as an allowlist: the tenant id is
#: interpolated into the per-tenant view definition, so it must never be
#: free-form text.
TENANTS: Final[tuple[str, ...]] = ("acme", "beta", "gamma")


class TenantError(ValueError):
    """Raised when a tenant id is not part of the known, closed set."""


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Immutable identity of the caller.

    Frozen on purpose: once the request is under way, nothing -- including the
    agent -- can widen its own scope by mutating the context in place.
    """

    user_id: int
    username: str
    tenant_id: str
    role: str = "analyst"

    def __post_init__(self) -> None:
        """Refuse to create a context for an unknown tenant or an empty username."""
        if self.tenant_id not in TENANTS:
            raise TenantError(
                f"unknown tenant {self.tenant_id!r}; expected one of {TENANTS}"
            )
        if not self.username:
            raise ValueError("username must not be empty")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        """A readable one-line description, for debugging."""
        return (
            f"SecurityContext(user_id={self.user_id}, username={self.username!r}, "
            f"tenant_id={self.tenant_id!r}, role={self.role!r})"
        )
