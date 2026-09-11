"""Login: where the tenant is decided, once, for the whole request.

This is the top of the chain the rest of the system rests on. Everything else
refuses to take a tenant as a parameter precisely because it is settled here
and then carried in an immutable :class:`SecurityContext`.

Two details that are small but not optional:

* Passwords are stored as argon2id hashes, never in plain text, even for four
  demo accounts. A repository that ships plaintext credentials teaches the
  habit, and the habit is what ends up in production.
* An unknown username still costs a full hash verification. Returning early
  would make failed logins measurably faster for names that do not exist,
  which is a user-enumeration oracle -- cheap to close, tedious to explain
  after the fact.

The demo credentials are in the README. Real deployments would replace this
module with the identity provider they already have; nothing downstream
changes, because downstream only ever sees a SecurityContext.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from secure_rls.security.context import SecurityContext

_hasher: Final = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)


@dataclass(frozen=True, slots=True)
class _User:
    username: str
    tenant_id: str
    role: str
    password_hash: str


#: Demo accounts. Two of them share a tenant on purpose: it shows that the
#: boundary is the tenant, not the individual, which is what row-level security
#: in a multi-tenant product actually means.
_USERS: Final[dict[str, _User]] = {
    "alice": _User("alice", "acme", "analyst",
           "$argon2id$v=19$m=65536,t=2,p=2$Zq9FTgUiiX2VpQ0QmPKPww$QmLQ5uqy39LwCSrAo+YzYPgJPW40HNOQZB3sqCyRVyk"),
    "arthur": _User("arthur", "acme", "viewer",
           "$argon2id$v=19$m=65536,t=2,p=2$4rKYNYTXg3i23F2+xUureQ$xyyk4AAyVJfUga07fDz125vaQl96yPAhqKKluOD0YN4"),
    "bob": _User("bob", "beta", "analyst",
           "$argon2id$v=19$m=65536,t=2,p=2$NAjHibv15XiWuyJ8L0pglw$shEvJOkV0YCYYY0UKBbvBZggI19fyg7yY1CpSRHI8Lo"),
    "gita": _User("gita", "gamma", "analyst",
           "$argon2id$v=19$m=65536,t=2,p=2$72RToa8t9XoQ7FuF1FncOA$n9rP9SixgIZ33SLBW2IT5obL3+rkWA5C3YqYteijd6s"),
}

#: Verified against when the username does not exist, so that the work done --
#: and therefore the time taken -- does not reveal which names are real.
_DECOY_HASH: Final = _USERS["alice"].password_hash

USER_IDS: Final[dict[str, int]] = {name: i for i, name in enumerate(sorted(_USERS), start=1)}


def authenticate(username: str, password: str) -> SecurityContext | None:
    """Return a context for valid credentials, or ``None``."""
    user = _USERS.get(username.strip().lower())
    reference = user.password_hash if user else _DECOY_HASH
    try:
        _hasher.verify(reference, password)
    except (VerifyMismatchError, VerificationError):
        return None
    if user is None:
        return None
    return SecurityContext(
        user_id=USER_IDS[user.username],
        username=user.username,
        tenant_id=user.tenant_id,
        role=user.role,
    )


def demo_accounts() -> tuple[tuple[str, str], ...]:
    """(username, tenant) pairs, for the login screen's hint text."""
    return tuple((u.username, u.tenant_id) for u in _USERS.values())
