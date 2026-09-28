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

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

#: Closed set of tenants. Also acts as an allowlist: the tenant id is
#: interpolated into the per-tenant view definition, so it must never be
#: free-form text.
TENANTS: Final[tuple[str, ...]] = ("acme", "beta", "gamma")


#: Columns each role sees as NULL, keyed by every role that exists. Also the
#: closed set of roles: a context for any other value is refused at
#: construction, like an unknown tenant. Masking used to be decided by
#: ``role == "viewer"`` on free text, so a typo ("Viewer") or an unknown role
#: fell through to the analyst's full view -- a mistake in the role widened
#: access instead of refusing it. The view built from this in :mod:`db` is
#: what actually hides the values; this is only the policy it reads.
ROLE_MASKED_COLUMNS: Final[Mapping[str, frozenset[str]]] = MappingProxyType({
    "analyst": frozenset(),
    "viewer": frozenset({"salary", "notes"}),
})
ROLES: Final[tuple[str, ...]] = tuple(ROLE_MASKED_COLUMNS)


class RoleError(ValueError):
    """Raised when a role is not part of the known, closed set."""


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
        """Refuse to create a context for an unknown tenant or role, or an empty username."""
        if self.tenant_id not in TENANTS:
            raise TenantError(
                f"unknown tenant {self.tenant_id!r}; expected one of {TENANTS}"
            )
        if self.role not in ROLE_MASKED_COLUMNS:
            raise RoleError(f"unknown role {self.role!r}; expected one of {ROLES}")
        if not self.username:
            raise ValueError("username must not be empty")

    @property
    def masked_columns(self) -> frozenset[str]:
        """The columns this caller's role sees as NULL."""
        return ROLE_MASKED_COLUMNS[self.role]

    def masked_reason(self, columns: frozenset[str] | set[str]) -> str:
        """Why a request touching ``columns`` is refused for this role.

        Worded for the model to pass on. Without it, a viewer's "average
        salary" came back as 0, NaN or a crash, depending on the tool -- the
        view held, and the answer was still wrong.
        """
        names = ", ".join(sorted(columns))
        return (
            f"your role ({self.role}) cannot see {names}: the column is masked for this "
            "account, so no figure can be computed from it. Tell the user their role has "
            f"no access to {names}; this is not missing or zero data."
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        """A readable one-line description, for debugging."""
        return (
            f"SecurityContext(user_id={self.user_id}, username={self.username!r}, "
            f"tenant_id={self.tenant_id!r}, role={self.role!r})"
        )
