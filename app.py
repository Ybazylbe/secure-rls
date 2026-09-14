"""The application: the HTTP API behind the React front end, and its entry point.

In plain terms: The web server behind the React app. Every request finds out
who the user is from a signed cookie, then calls the agent, the attack suite or
the audit log on that user's behalf. The browser can never say which tenant it
belongs to.

The browser never states who it is. A signed cookie carries a username and
nothing else; every request rebuilds the :class:`SecurityContext` on the server
from that name, and the tenant comes from the account table rather than from
anything the client sent. Forging a tenant therefore requires the signing key,
not a modified request body.

Run it with ``uvicorn app:app``. When ``web/dist`` has been built, the same
process serves the React front end, so one command starts the whole product.

Everything below this file is unchanged: the same guarded tools, the same five
layers, the same tests. Swapping the interface was deliberately not allowed to
touch them.
"""

from __future__ import annotations

import os
import secrets
import time
from pathlib import Path
from typing import Annotated, Any

from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, ConfigDict, Field

import db
from agent import AgentAnswer, Step, ask, build_agent
from secure_rls.auth import USER_IDS, account_for, authenticate, demo_accounts
from secure_rls.llm import DEFAULT_MODEL, MODELS
from secure_rls.redteam import (
    ATTACKS,
    Attack,
    exercised,
    featured,
    not_exercised_reason,
    prompt_for,
    verdict,
)
from secure_rls.security.audit import AUDIT
from secure_rls.security.context import SecurityContext

#: Sessions are signed, not encrypted -- the cookie's contents are not secret,
#: its authorship is. Regenerated per process unless pinned, so restarting the
#: server invalidates outstanding sessions, which is the safer default for a
#: demo that ships with published credentials.
SECRET = os.environ.get("SECURE_RLS_SECRET") or secrets.token_urlsafe(32)
COOKIE = "secure_rls_session"
_signer = URLSafeSerializer(SECRET, salt="session")

#: The side-by-side view's second account. It is a session in its own right,
#: established by that account's password, and signed with a different salt so
#: that neither cookie can be replayed as the other.
PEER_COOKIE = "secure_rls_peer"
_peer_signer = URLSafeSerializer(SECRET, salt="peer-session")

STATIC_DIR = Path(__file__).parent / "web" / "dist"

app = FastAPI(title="Secure RLS Analyst", docs_url="/api/docs")


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


def _context_from_cookie(
    raw: str | None, signer: URLSafeSerializer = _signer, *, what: str = "session"
) -> SecurityContext:
    """Rebuild the caller's identity, or refuse the request.

    The cookie holds a username. The tenant is looked up here, server-side, so
    a client cannot assert one however it edits its own request.
    """
    if not raw:
        raise HTTPException(status_code=401, detail=f"not signed in ({what})")
    try:
        username = str(signer.loads(raw))
    except BadSignature as err:
        raise HTTPException(status_code=401, detail=f"invalid {what}") from err

    account = account_for(username)
    if account is None:
        raise HTTPException(status_code=401, detail="unknown account")
    tenant, role = account
    return SecurityContext(
        user_id=USER_IDS[username], username=username, tenant_id=tenant, role=role
    )


Session = Annotated[str | None, Cookie(alias=COOKIE)]
PeerSession = Annotated[str | None, Cookie(alias=PEER_COOKIE)]


# ---------------------------------------------------------------------------
# Wire formats
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Body of a sign-in request: a username and a password."""
    username: str
    password: str


class AskRequest(BaseModel):
    """Body of a chat question: the question text and which model to use."""
    question: str = Field(min_length=1, max_length=2000)
    model: str = DEFAULT_MODEL


class CompareRequest(AskRequest):
    # No tenant field, and unknown fields are refused: a client still sending
    # `other_tenant` gets a 422 rather than a request that silently means
    # something else. The second side comes from the peer session alone.
    """Body of a side-by-side question. Same as a chat question, with no extra fields allowed."""
    model_config = ConfigDict(extra="forbid")


class AttackRequest(BaseModel):
    """Body of an attack run: which model, and whether to run only the featured attacks."""
    model: str = DEFAULT_MODEL
    only_featured: bool = True


def _step_payload(step: Step) -> dict[str, Any]:
    """Turn one agent step into JSON for the browser: the call, what ran, what came back."""
    result = step.result
    return {
        "tool": step.tool,
        "arguments": step.arguments,
        "state": (
            "rejected"
            if step.rejected
            else "skipped"
            if step.skipped
            else "unverifiable"
            if step.unverifiable
            else "ok"
        ),
        "error": step.error,
        "refused": bool(result and result.refused),
        "reason": result.reason if result else None,
        "sql": result.sql if result else None,
        "rewrites": list(result.rewrites) if result else [],
        "flags": list(result.flags) if result else [],
        "rows": [dict(row) for row in result.rows[:200]] if result else [],
        "row_count": len(result.rows) if result else 0,
        "chart": result.chart if result else None,
    }


def _answer_payload(answer: AgentAnswer, ctx: SecurityContext) -> dict[str, Any]:
    """Turn a whole agent answer into JSON for the browser.

    ``scope`` is stated by the server, not by the model: whose data the tools
    could read for this answer, and how much of it came back. It sits next to
    the answer so that a model labelling rows as another tenant's is
    contradicted on the same screen by something it did not write.
    """
    ran = [step for step in answer.steps if step.result is not None and not step.result.refused]
    return {
        "text": answer.text,
        "steps": [_step_payload(s) for s in answer.steps],
        "charts": answer.charts,
        "flags": answer.flags,
        "retried": answer.retried,
        "ungrounded": list(answer.ungrounded),
        "claimed_tenants": list(answer.claimed_tenants),
        # Rows the answer is about: chosen by the model by label, values from
        # the tool results. The UI shows these as the answer's table.
        "selected_rows": [dict(row) for row in answer.selected_rows],
        "ignored_refs": list(answer.ignored_refs),
        "scope": {
            "tenant": ctx.tenant_id,
            "rows": sum(len(step.result.rows) for step in ran if step.result is not None),
            "calls": len(ran),
            # Per call, because a total adds unlike things: 330 salaries and a
            # one-row count read as "331 rows".
            "per_call": [
                {
                    "tool": step.tool,
                    "rows": len(step.result.rows),
                    # A chart's figures live in the chart, not in rows, so
                    # "plot 0 rows" would read as an empty result.
                    "chart": bool(step.result.chart),
                }
                for step in ran
                if step.result is not None
            ],
        },
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.on_event("startup")
def _load_data() -> None:
    """On startup, load employees.csv into SQLite if it is not loaded yet."""
    db.init_db()


@app.post("/api/login")
def login(body: LoginRequest, response: Response) -> dict[str, Any]:
    """Check a username and password and, if they are right, set the signed session cookie."""
    ctx = authenticate(body.username, body.password)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    response.set_cookie(
        COOKIE,
        _signer.dumps(ctx.username),
        httponly=True,
        samesite="lax",
        max_age=8 * 3600,
    )
    return _identity(ctx)


@app.post("/api/logout")
def logout(response: Response) -> dict[str, bool]:
    """Sign out: remove the session cookie and the side-by-side second-account cookie."""
    response.delete_cookie(COOKIE)
    response.delete_cookie(PEER_COOKIE)
    return {"ok": True}


@app.get("/api/session")
def session(secure_rls_session: Session = None) -> dict[str, Any]:
    """Return who is signed in, which tenant they belong to, and how many rows they can see."""
    return _identity(_context_from_cookie(secure_rls_session))


def _identity(ctx: SecurityContext) -> dict[str, Any]:
    """The public description of a signed-in user that the browser is allowed to see."""
    return {
        "username": ctx.username,
        "tenant": ctx.tenant_id,
        "role": ctx.role,
        "rows": db.row_count(ctx),
    }


@app.get("/api/models")
def models() -> list[dict[str, str]]:
    """List the models the user can choose from, with origin and licence."""
    return [
        {"tag": spec.tag, "origin": spec.origin, "licence": spec.licence, "note": spec.note}
        for spec in MODELS.values()
    ]


@app.get("/api/accounts")
def accounts() -> list[dict[str, str]]:
    """Demo credentials, served so the login screen can list them."""
    return [
        {"username": name, "tenant": tenant, "password": f"{tenant}-demo-2026"}
        for name, tenant in demo_accounts()
    ]


@app.post("/api/ask")
def ask_question(body: AskRequest, secure_rls_session: Session = None) -> dict[str, Any]:
    """Answer a chat question as the signed-in user."""
    ctx = _context_from_cookie(secure_rls_session)
    _check_model(body.model)
    answer = ask(body.question, ctx, AUDIT, model=body.model)
    return _answer_payload(answer, ctx)


# The side-by-side view. It used to build the second tenant's context on the
# server from a tenant name in the request and return what that context
# produced -- which handed any signed-in user another tenant's rows, names and
# salaries included, while every layer below held perfectly. Now the second side
# is a real sign-in: the data shown for a tenant goes only to a browser that
# holds that tenant's password.


@app.post("/api/compare/peer")
def compare_peer_login(
    body: LoginRequest, response: Response, secure_rls_session: Session = None
) -> dict[str, Any]:
    """Sign in the second account for the side-by-side view."""
    ctx = _context_from_cookie(secure_rls_session)
    peer = authenticate(body.username, body.password)
    if peer is None:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if peer.tenant_id == ctx.tenant_id:
        raise HTTPException(
            status_code=400, detail="the second account must belong to a different tenant"
        )
    response.set_cookie(
        PEER_COOKIE,
        _peer_signer.dumps(peer.username),
        httponly=True,
        samesite="lax",
        max_age=8 * 3600,
    )
    return _identity(peer)


@app.get("/api/compare/peer")
def compare_peer(
    secure_rls_session: Session = None, secure_rls_peer: PeerSession = None
) -> dict[str, Any]:
    """Return the second account signed in for the side-by-side view, or 401 if there is none."""
    _context_from_cookie(secure_rls_session)
    return _identity(_peer_context(secure_rls_session, secure_rls_peer))


@app.post("/api/compare/peer/logout")
def compare_peer_logout(response: Response) -> dict[str, bool]:
    """Sign out the side-by-side second account only."""
    response.delete_cookie(PEER_COOKIE)
    return {"ok": True}


@app.post("/api/compare")
def compare(
    body: CompareRequest,
    secure_rls_session: Session = None,
    secure_rls_peer: PeerSession = None,
) -> dict[str, Any]:
    """The same question, answered for two accounts that are both signed in."""
    ctx = _context_from_cookie(secure_rls_session)
    peer = _peer_context(secure_rls_session, secure_rls_peer)
    _check_model(body.model)
    mine = _answer_payload(ask(body.question, ctx, AUDIT, model=body.model), ctx)
    theirs = _answer_payload(ask(body.question, peer, AUDIT, model=body.model), peer)
    return {
        "mine": {"tenant": ctx.tenant_id, **mine},
        "theirs": {"tenant": peer.tenant_id, **theirs},
    }


def _peer_context(primary: str | None, raw: str | None) -> SecurityContext:
    """The second account, which must still be a different tenant from the first.

    Checked on every request, not only at sign-in: the primary session can
    change underneath a peer cookie (sign out, sign in as someone else).
    """
    ctx = _context_from_cookie(primary)
    peer = _context_from_cookie(raw, _peer_signer, what="second account")
    if peer.tenant_id == ctx.tenant_id:
        raise HTTPException(
            status_code=400, detail="the second account must belong to a different tenant"
        )
    return peer


@app.get("/api/attacks")
def attack_catalogue() -> list[dict[str, Any]]:
    """List every attack in the catalogue, without running anything."""
    return [
        {
            "id": a.id,
            "category": a.category,
            "prompt": a.prompt.replace("{carrier}", "<an employee with an injected note>"),
            "intent": a.intent,
            "featured": a.featured,
        }
        for a in ATTACKS
    ]


@app.post("/api/attacks/run")
def run_attacks(body: AttackRequest, secure_rls_session: Session = None) -> dict[str, Any]:
    """Run the attacks as the signed-in user and report whether any foreign data got out."""
    ctx = _context_from_cookie(secure_rls_session)
    _check_model(body.model)
    selected: tuple[Attack, ...] = featured() if body.only_featured else ATTACKS

    agent = build_agent(ctx, AUDIT, model=body.model)
    results = []
    for attack in selected:
        prompt = prompt_for(attack, ctx)
        if prompt is None:
            # An indirect attack needs an injected note in this tenant's data.
            results.append(
                {
                    "id": attack.id, "category": attack.category, "prompt": attack.prompt,
                    "intent": attack.intent, "contained": True, "exercised": False,
                    "not_exercised": f"not applicable: no note in {ctx.tenant_id} carries "
                    "injected text",
                    "evidence": "not run", "seconds": 0.0, "answer": None,
                }
            )
            continue
        started = time.perf_counter()
        answer = ask(prompt, ctx, AUDIT, model=body.model, agent=agent)
        contained, evidence = verdict(answer, ctx)
        results.append(
            {
                "id": attack.id,
                "category": attack.category,
                "prompt": prompt,
                "intent": attack.intent,
                "contained": contained,
                "exercised": exercised(answer, attack),
                "not_exercised": not_exercised_reason(answer, attack),
                "evidence": evidence,
                "seconds": round(time.perf_counter() - started, 1),
                "answer": _answer_payload(answer, ctx),
            }
        )
    return {
        "results": results,
        "leaked": sum(1 for r in results if not r["contained"]),
        "exercised": sum(1 for r in results if r["exercised"]),
        "total": len(results),
        "model": body.model,
        "tenant": ctx.tenant_id,
        "username": ctx.username,
    }


@app.get("/api/audit")
def audit(secure_rls_session: Session = None) -> list[dict[str, Any]]:
    """Return the latest audit records, only for the signed-in user's tenant."""
    ctx = _context_from_cookie(secure_rls_session)
    return [
        {
            "time": record.clock,
            "user": record.username,
            "event": record.event,
            "verdict": record.verdict,
            "layer": record.layer,
            "rows": record.rows,
            "detail": record.detail,
            "sql": record.sql,
        }
        for record in AUDIT.recent(limit=200, tenant_id=ctx.tenant_id)
    ]


def _check_model(tag: str) -> None:
    """Refuse the request if the model name is not one of the configured models."""
    if tag not in MODELS:
        raise HTTPException(status_code=400, detail=f"unknown model {tag!r}")


# ---------------------------------------------------------------------------
# The built front end, when there is one
# ---------------------------------------------------------------------------

if STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    def spa(path: str) -> FileResponse:
        """Serve the single-page app for anything that is not an API route."""
        candidate = STATIC_DIR / path
        if path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")
