"""HTTP API behind the React front end.

The browser never states who it is. A signed cookie carries a username and
nothing else; every request rebuilds the :class:`SecurityContext` on the server
from that name, and the tenant comes from the account table rather than from
anything the client sent. Forging a tenant therefore requires the signing key,
not a modified request body -- which is the same L1 property the Streamlit app
has, expressed somewhere it is easier to check.

Everything below this file is unchanged: the same guarded tools, the same five
layers, the same tests. Swapping the interface was deliberately not allowed to
touch them.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Annotated, Any

from fastapi import Cookie, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, Field

import db
from agent import AgentAnswer, Step, ask, build_agent
from secure_rls.auth import authenticate, demo_accounts
from secure_rls.llm import DEFAULT_MODEL, MODELS
from secure_rls.redteam import ATTACKS, Attack, featured, verdict
from secure_rls.security.audit import AUDIT
from secure_rls.security.context import TENANTS, SecurityContext

#: Sessions are signed, not encrypted -- the cookie's contents are not secret,
#: its authorship is. Regenerated per process unless pinned, so restarting the
#: server invalidates outstanding sessions, which is the safer default for a
#: demo that ships with published credentials.
SECRET = os.environ.get("SECURE_RLS_SECRET") or secrets.token_urlsafe(32)
COOKIE = "secure_rls_session"
_signer = URLSafeSerializer(SECRET, salt="session")

STATIC_DIR = Path(__file__).parent / "web" / "dist"

app = FastAPI(title="Secure RLS Analyst", docs_url="/api/docs")


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


def _context_from_cookie(raw: str | None) -> SecurityContext:
    """Rebuild the caller's identity, or refuse the request.

    The cookie holds a username. The tenant is looked up here, server-side, so
    a client cannot assert one however it edits its own request.
    """
    if not raw:
        raise HTTPException(status_code=401, detail="not signed in")
    try:
        username = str(_signer.loads(raw))
    except BadSignature as err:
        raise HTTPException(status_code=401, detail="invalid session") from err

    for name, tenant in demo_accounts():
        if name == username:
            from secure_rls.auth import USER_IDS

            return SecurityContext(
                user_id=USER_IDS[name], username=name, tenant_id=tenant, role="analyst"
            )
    raise HTTPException(status_code=401, detail="unknown account")


Session = Annotated[str | None, Cookie(alias=COOKIE)]


# ---------------------------------------------------------------------------
# Wire formats
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    model: str = DEFAULT_MODEL


class CompareRequest(AskRequest):
    other_tenant: str


class AttackRequest(BaseModel):
    model: str = DEFAULT_MODEL
    only_featured: bool = True


def _step_payload(step: Step) -> dict[str, Any]:
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


def _answer_payload(answer: AgentAnswer) -> dict[str, Any]:
    return {
        "text": answer.text,
        "steps": [_step_payload(s) for s in answer.steps],
        "charts": answer.charts,
        "flags": answer.flags,
        "retried": answer.retried,
        "ungrounded": list(answer.ungrounded),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.on_event("startup")
def _load_data() -> None:
    db.init_db()


@app.post("/api/login")
def login(body: LoginRequest, response: Response) -> dict[str, Any]:
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
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/session")
def session(secure_rls_session: Session = None) -> dict[str, Any]:
    return _identity(_context_from_cookie(secure_rls_session))


def _identity(ctx: SecurityContext) -> dict[str, Any]:
    return {
        "username": ctx.username,
        "tenant": ctx.tenant_id,
        "role": ctx.role,
        "rows": db.row_count(ctx),
    }


@app.get("/api/models")
def models() -> list[dict[str, str]]:
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
    ctx = _context_from_cookie(secure_rls_session)
    _check_model(body.model)
    answer = ask(body.question, ctx, AUDIT, model=body.model)
    return _answer_payload(answer)


@app.post("/api/compare")
def compare(body: CompareRequest, secure_rls_session: Session = None) -> dict[str, Any]:
    """The same question, as the caller and as another tenant.

    The second context is built here rather than accepted from the client, and
    only from the closed tenant list -- the endpoint demonstrates isolation, it
    does not offer a way around it.
    """
    ctx = _context_from_cookie(secure_rls_session)
    _check_model(body.model)
    if body.other_tenant not in TENANTS or body.other_tenant == ctx.tenant_id:
        raise HTTPException(status_code=400, detail="unknown tenant")

    peer_name = {"acme": "alice", "beta": "bob", "gamma": "gita"}[body.other_tenant]
    from secure_rls.auth import USER_IDS

    peer = SecurityContext(
        user_id=USER_IDS[peer_name],
        username=peer_name,
        tenant_id=body.other_tenant,
        role="analyst",
    )
    mine = _answer_payload(ask(body.question, ctx, AUDIT, model=body.model))
    theirs = _answer_payload(ask(body.question, peer, AUDIT, model=body.model))
    return {
        "mine": {"tenant": ctx.tenant_id, **mine},
        "theirs": {"tenant": peer.tenant_id, **theirs},
    }


@app.get("/api/attacks")
def attack_catalogue() -> list[dict[str, Any]]:
    return [
        {
            "id": a.id,
            "category": a.category,
            "prompt": a.prompt,
            "intent": a.intent,
            "featured": a.featured,
        }
        for a in ATTACKS
    ]


@app.post("/api/attacks/run")
def run_attacks(body: AttackRequest, secure_rls_session: Session = None) -> dict[str, Any]:
    ctx = _context_from_cookie(secure_rls_session)
    _check_model(body.model)
    selected: tuple[Attack, ...] = featured() if body.only_featured else ATTACKS

    agent = build_agent(ctx, AUDIT, model=body.model)
    results = []
    for attack in selected:
        answer = ask(attack.prompt, ctx, AUDIT, model=body.model, agent=agent)
        contained, evidence = verdict(answer, ctx)
        results.append(
            {
                "id": attack.id,
                "category": attack.category,
                "prompt": attack.prompt,
                "intent": attack.intent,
                "contained": contained,
                "evidence": evidence,
                "answer": _answer_payload(answer),
            }
        )
    leaked = sum(1 for r in results if not r["contained"])
    return {"results": results, "leaked": leaked, "total": len(results)}


@app.get("/api/audit")
def audit(secure_rls_session: Session = None) -> list[dict[str, Any]]:
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
