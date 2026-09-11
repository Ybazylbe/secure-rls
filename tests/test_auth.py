"""Login tests: the one place a tenant is chosen."""

from __future__ import annotations

import time

import pytest

from secure_rls.auth import authenticate, demo_accounts
from secure_rls.security.context import TENANTS


@pytest.mark.parametrize(("username", "tenant"), demo_accounts())
def test_demo_accounts_sign_in_to_their_own_tenant(username: str, tenant: str) -> None:
    ctx = authenticate(username, f"{tenant}-demo-2026")
    assert ctx is not None
    assert ctx.tenant_id == tenant
    assert ctx.username == username


def test_two_users_can_share_a_tenant() -> None:
    """The boundary is the tenant, not the individual."""
    alice = authenticate("alice", "acme-demo-2026")
    arthur = authenticate("arthur", "acme-demo-2026")
    assert alice is not None and arthur is not None
    assert alice.tenant_id == arthur.tenant_id == "acme"
    assert alice.user_id != arthur.user_id


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("alice", "wrong"),
        ("alice", ""),
        ("alice", "beta-demo-2026"),  # another tenant's password
        ("ghost", "acme-demo-2026"),
        ("", "acme-demo-2026"),
    ],
)
def test_bad_credentials_are_rejected(username: str, password: str) -> None:
    assert authenticate(username, password) is None


def test_every_tenant_has_an_account() -> None:
    assert {tenant for _, tenant in demo_accounts()} == set(TENANTS)


def test_no_password_is_stored_in_plain_text() -> None:
    from pathlib import Path

    source = Path("secure_rls/auth.py").read_text(encoding="utf-8")
    for _, tenant in demo_accounts():
        assert f"{tenant}-demo-2026" not in source


def test_an_unknown_user_costs_the_same_as_a_wrong_password() -> None:
    """Returning early for unknown names would be a user-enumeration oracle.

    The threshold is deliberately loose -- this asserts that the same work is
    done in both branches, not a precise timing budget, because a strict bound
    would flake on a busy CI machine.
    """

    def elapsed(username: str) -> float:
        start = time.perf_counter()
        authenticate(username, "definitely-wrong")
        return time.perf_counter() - start

    known = min(elapsed("alice") for _ in range(3))
    unknown = min(elapsed("nobody-here") for _ in range(3))
    assert 0.5 < unknown / known < 2.0, (known, unknown)
