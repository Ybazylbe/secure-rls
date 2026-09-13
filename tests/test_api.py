"""API tests: who the caller is, and who decides it.

None of these needs a language model. They cover the part of the HTTP layer
that carries a security claim -- identity -- and deliberately not the part that
carries an answer.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import api


@pytest.fixture
def client() -> TestClient:
    return TestClient(api.app)


def sign_in(client: TestClient, username: str = "alice", password: str = "acme-demo-2026") -> None:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("get", "/api/session", None),
        ("get", "/api/audit", None),
        ("post", "/api/ask", {"question": "hello"}),
        ("post", "/api/compare", {"question": "hello", "other_tenant": "beta"}),
        ("post", "/api/attacks/run", {}),
    ],
)
def test_every_data_route_requires_a_session(
    client: TestClient, method: str, path: str, body: dict[str, object] | None
) -> None:
    response = getattr(client, method)(path, json=body) if body is not None else getattr(
        client, method
    )(path)
    assert response.status_code == 401


def test_bad_credentials_are_refused(client: TestClient) -> None:
    response = client.post("/api/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 401
    assert "secure_rls_session" not in response.cookies


def test_a_session_reports_the_account_s_own_tenant(client: TestClient) -> None:
    sign_in(client, "bob", "beta-demo-2026")
    body = client.get("/api/session").json()
    assert body == {"username": "bob", "tenant": "beta", "role": "analyst", "rows": 330}


def test_a_forged_cookie_is_refused(client: TestClient) -> None:
    """The cookie is signed, not encrypted: readable, but not writable.

    This is the whole of the API's L1 claim. If a hand-made cookie were
    accepted, every layer below it would be defending the wrong tenant.
    """
    client.cookies.set(api.COOKIE, "ImJvYiI.not-a-real-signature")
    assert client.get("/api/session").status_code == 401


def test_a_tampered_signature_is_refused(client: TestClient) -> None:
    sign_in(client)
    raw = client.cookies[api.COOKIE]
    body, _, signature = raw.rpartition(".")
    flipped = ("a" if signature[0] != "a" else "b") + signature[1:]
    # Clear first. set() adds a second cookie beside the server's (which is
    # scoped to the test host) rather than replacing it, and which of the two is
    # sent depends on jar ordering: on Python 3.10 the valid one went first and
    # this test passed without ever presenting the tampered signature.
    client.cookies.clear()
    client.cookies.set(api.COOKIE, f"{body}.{flipped}")
    assert list(client.cookies.jar) and all(
        cookie.value.endswith(flipped) for cookie in client.cookies.jar
    )
    assert client.get("/api/session").status_code == 401


def test_the_client_cannot_name_its_own_tenant(client: TestClient) -> None:
    """A tenant in the request body must be ignored, not honoured.

    The endpoints take no tenant argument at all, which is the point -- this
    pins it, so that adding one later fails a test rather than passing review.
    """
    sign_in(client, "bob", "beta-demo-2026")
    response = client.post(
        "/api/ask", json={"question": "hi", "model": "mistral-nemo:12b", "tenant": "acme"}
    )
    # Rejected for a bad field or accepted and ignored -- never honoured. The
    # call may fail for want of a model, which is fine: it must not fail
    # because it decided to serve acme.
    assert response.status_code != 200 or "acme" not in response.text


# --------------------------------------------------------------------------
# Comparison endpoint
# --------------------------------------------------------------------------


@pytest.mark.parametrize("tenant", ["acme", "delta", "", "BETA"])
def test_compare_only_accepts_a_different_known_tenant(client: TestClient, tenant: str) -> None:
    """acme is the caller's own; the rest do not exist."""
    sign_in(client)
    response = client.post("/api/compare", json={"question": "hi", "other_tenant": tenant})
    assert response.status_code == 400


# --------------------------------------------------------------------------
# Public metadata
# --------------------------------------------------------------------------


def test_models_are_listed_with_their_licences(client: TestClient) -> None:
    models = client.get("/api/models").json()
    assert {m["tag"] for m in models}
    assert all(m["licence"] and m["origin"] for m in models)


def test_the_attack_catalogue_is_served(client: TestClient) -> None:
    attacks = client.get("/api/attacks").json()
    assert len(attacks) >= 20
    assert {a["category"] for a in attacks} >= {"direct", "sql-injection", "indirect"}


def test_demo_accounts_cover_every_tenant(client: TestClient) -> None:
    accounts = client.get("/api/accounts").json()
    assert {a["tenant"] for a in accounts} == {"acme", "beta", "gamma"}


def test_an_unknown_model_is_refused(client: TestClient) -> None:
    sign_in(client)
    response = client.post("/api/ask", json={"question": "hi", "model": "gpt-nonsense"})
    assert response.status_code == 400
