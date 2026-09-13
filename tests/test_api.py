"""API tests: who the caller is, and who decides it.

None of these needs a language model. They cover the part of the HTTP layer
that carries a security claim -- identity -- and deliberately not the part that
carries an answer.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import api
from secure_rls.security.context import SecurityContext


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Used as a context manager so the app's startup hook runs and loads the
    # database. Without it these tests passed only on machines that already had
    # secure_rls.db lying around, and failed on a clean CI checkout.
    with TestClient(api.app) as test_client:
        yield test_client


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> list[SecurityContext]:
    """Replace the agent and record the identity each call was made for.

    Tests assert on the context actually handed down, so they need no model and
    cannot be fooled by whatever text a model would have written. An earlier
    version called Ollama for real and failed in CI, where none runs.
    """
    seen: list[SecurityContext] = []

    def fake_ask(question: str, ctx: SecurityContext, *args: object, **kwargs: object) -> object:
        seen.append(ctx)
        rows = ({"tenant_id": ctx.tenant_id, "salary": 1},)
        step = SimpleNamespace(
            tool="query_db", arguments={}, rejected=False, skipped=False, unverifiable=False,
            error=None, result=SimpleNamespace(
                refused=False, reason=None, sql="", rewrites=(), flags=(), rows=rows, chart=None
            ),
        )
        return SimpleNamespace(
            text=f"answer for {ctx.tenant_id}", steps=[step], charts=[], flags=[],
            retried=False, ungrounded=(),
        )

    monkeypatch.setattr(api, "ask", fake_ask)
    return seen


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
        ("post", "/api/compare", {"question": "hello"}),
        ("post", "/api/compare/peer", {"username": "bob", "password": "beta-demo-2026"}),
        ("get", "/api/compare/peer", None),
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


def test_the_client_cannot_name_its_own_tenant(
    client: TestClient, asked: list[SecurityContext]
) -> None:
    """A tenant in the request body must be ignored, not honoured.

    The endpoints take no tenant argument at all, which is the point -- this
    pins it, so that adding one later fails a test rather than passing review.
    """
    sign_in(client, "bob", "beta-demo-2026")
    response = client.post(
        "/api/ask", json={"question": "hi", "model": "mistral-nemo:12b", "tenant": "acme"}
    )
    # Rejected for a bad field, or accepted and ignored -- never honoured.
    assert response.status_code in (200, 422), response.text
    if response.status_code == 200:
        assert [ctx.tenant_id for ctx in asked] == ["beta"]


# --------------------------------------------------------------------------
# Comparison endpoint
# --------------------------------------------------------------------------


def sign_in_peer(
    client: TestClient, username: str = "bob", password: str = "beta-demo-2026"
) -> None:
    response = client.post("/api/compare/peer", json={"username": username, "password": password})
    assert response.status_code == 200, response.text


def test_naming_another_tenant_no_longer_returns_its_data(
    client: TestClient, asked: list[SecurityContext]
) -> None:
    """The leak this endpoint used to have.

    Signed in as alice (acme), a request naming beta made the server build a
    beta context itself and return beta's rows -- names and salaries -- to
    alice. Every layer below held; the data left anyway. A tenant name in the
    body must now be refused outright, and the agent must never run as beta.
    """
    sign_in(client)
    response = client.post(
        "/api/compare", json={"question": "top earners", "other_tenant": "beta"}
    )
    assert response.status_code == 422, response.text
    assert asked == [], "the agent ran at all, so it may have run as beta"


def test_compare_without_a_second_sign_in_is_refused(
    client: TestClient, asked: list[SecurityContext]
) -> None:
    sign_in(client)
    response = client.post("/api/compare", json={"question": "top earners"})
    assert response.status_code == 401
    assert asked == []


def test_the_second_account_needs_its_own_password(client: TestClient) -> None:
    sign_in(client)
    response = client.post("/api/compare/peer", json={"username": "bob", "password": "wrong"})
    assert response.status_code == 401
    assert api.PEER_COOKIE not in response.cookies


def test_the_second_account_must_be_another_tenant(client: TestClient) -> None:
    """arthur shares acme with alice; comparing a tenant with itself proves nothing."""
    sign_in(client)
    response = client.post(
        "/api/compare/peer", json={"username": "arthur", "password": "acme-demo-2026"}
    )
    assert response.status_code == 400


def test_each_side_is_answered_as_its_own_signed_in_account(
    client: TestClient, asked: list[SecurityContext]
) -> None:
    sign_in(client)
    sign_in_peer(client)
    assert client.get("/api/compare/peer").json()["tenant"] == "beta"

    body = client.post("/api/compare", json={"question": "top earners"}).json()
    assert [ctx.username for ctx in asked] == ["alice", "bob"]
    assert (body["mine"]["tenant"], body["theirs"]["tenant"]) == ("acme", "beta")


def test_a_main_session_cookie_is_not_accepted_as_the_second_account(
    client: TestClient, asked: list[SecurityContext]
) -> None:
    """The two cookies are signed with different salts and are not interchangeable.

    bob's ordinary session token, obtained by signing in as bob elsewhere, must
    not work as the peer cookie: otherwise the peer sign-in would be one
    copy-paste away from being skipped.
    """
    with TestClient(api.app) as bob_client:
        sign_in(bob_client, "bob", "beta-demo-2026")
        bob_token = bob_client.cookies[api.COOKIE]

    sign_in(client)
    alice_token = client.cookies[api.COOKIE]
    client.cookies.clear()
    client.cookies.set(api.COOKIE, alice_token)
    client.cookies.set(api.PEER_COOKIE, bob_token)

    response = client.post("/api/compare", json={"question": "top earners"})
    assert response.status_code == 401
    assert asked == []


def test_a_peer_cookie_stops_working_when_it_matches_the_new_main_account(
    client: TestClient, asked: list[SecurityContext]
) -> None:
    """Sign in as alice, add bob, then switch the main account to bob."""
    sign_in(client)
    sign_in_peer(client)
    sign_in(client, "bob", "beta-demo-2026")
    response = client.post("/api/compare", json={"question": "top earners"})
    assert response.status_code == 400
    assert asked == []


def test_signing_out_also_signs_out_the_second_account(client: TestClient) -> None:
    sign_in(client)
    sign_in_peer(client)
    client.post("/api/logout")
    sign_in(client)
    assert client.get("/api/compare/peer").status_code == 401


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
