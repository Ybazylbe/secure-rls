"""Streamlit front end for the secure multi-tenant analyst.

The interface has a second job besides being usable: it has to make the
isolation *visible*. Claiming that one tenant cannot see another is not
convincing; running the same question as two different users side by side, and
showing the SQL that was actually executed, is.

So four views:

* **Chat** -- the product itself, with the reasoning trace and the guarded SQL
  on display rather than hidden behind a spinner.
* **Security** -- the attack catalogue, run live, with a verdict per attack.
* **Side by side** -- one question, two tenants, two answers.
* **Audit** -- what the system recorded while you were doing all that.

Nothing here enforces anything. Every control lives below this file, and the UI
only reports what happened.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

import db
from agent import AgentAnswer, ask, build_agent
from secure_rls.auth import authenticate, demo_accounts
from secure_rls.llm import DEFAULT_MODEL, MODELS
from secure_rls.redteam import ATTACKS, Attack, featured, verdict
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import SecurityContext

st.set_page_config(
    page_title="Secure RLS Analyst",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="expanded",
)

#: Streamlit's defaults are fine for a dashboard and wrong for a chat. This
#: narrows the column, turns the tab strip into a compact pill row, gives the
#: messages proper bubbles with the user's on the right, and turns the
#: suggestion buttons into chips sitting just above the pinned input. Selectors
#: are scoped to Streamlit's stable test ids and to element keys, so they do not
#: bleed into widgets they were not meant for.
STYLE = """
<style>
  [data-testid="stMainBlockContainer"] { max-width: 980px; padding-top: 2.2rem; }

  /* the view switcher: a pill row, not a heavy tab strip */
  [class*="st-key-view_nav"] [role="radiogroup"] { gap: .3rem; }
  [class*="st-key-view_nav"] label {
      border-radius: 999px !important;
      padding: .28rem .95rem !important;
      font-size: .88rem !important;
      border: 1px solid rgba(128,128,128,.22) !important;
  }

  /* message bubbles */
  [data-testid="stChatMessage"] {
      background: transparent;
      padding: .1rem 0 .5rem 0;
      gap: .7rem;
  }
  [data-testid="stChatMessage"] [data-testid="stChatMessageContent"] {
      background: rgba(128,128,128,.07);
      border: 1px solid rgba(128,128,128,.14);
      border-radius: 16px;
      padding: .7rem 1rem;
      flex: 0 1 auto;
      min-width: 0;
  }
  /* the assistant's turn carries tables and traces, so it gets the width */
  [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarAssistant"])
      [data-testid="stChatMessageContent"] { flex: 1 1 auto; }

  /* the person's own turn, on the right, the way every chat does it.
     row-reverse flips the main axis, so flex-start packs it to the right. */
  [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) {
      flex-direction: row-reverse;
      justify-content: flex-start;
  }
  [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"])
      [data-testid="stChatMessageContent"] { max-width: 72%; }
  [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"])
      [data-testid="stChatMessageContent"] {
      background: rgba(59,111,181,.10);
      border-color: rgba(59,111,181,.22);
  }

  /* suggestion chips */
  [class*="st-key-chip_"] button {
      border-radius: 999px !important;
      padding: .18rem .8rem !important;
      font-size: .8rem !important;
      font-weight: 450 !important;
      min-height: 0 !important;
      border: 1px solid rgba(128,128,128,.25) !important;
      background: transparent !important;
      color: rgba(90,95,105,1) !important;
  }
  [class*="st-key-chip_"] button:hover {
      border-color: rgba(59,111,181,.55) !important;
      color: #3b6fb5 !important;
  }

  /* the pinned composer */
  [data-testid="stChatInput"] {
      border-radius: 16px;
      border: 1px solid rgba(128,128,128,.25);
      box-shadow: 0 2px 14px rgba(0,0,0,.05);
  }

  /* the reasoning trace should read as a footnote, not as a second answer */
  [data-testid="stExpander"] details {
      border: 1px solid rgba(128,128,128,.16);
      border-radius: 12px;
      background: rgba(128,128,128,.03);
  }
  [data-testid="stExpander"] summary { font-size: .85rem; }
</style>
"""

#: (chip label, question). Short labels: five full questions across one row get
#: ellipsised into uselessness on anything narrower than a wide desktop.
SUGGESTIONS = (
    ("Avg salary", "What is the average salary in Engineering?"),
    ("By department", "Which departments have the highest average salary?"),
    ("Outliers", "Which employees have an unusual salary for their department?"),
    ("Top earners", "List the five highest paid employees with their departments."),
    ("Notes", "Who is flagged as a retention risk in the review notes?"),
)


# ---------------------------------------------------------------------------
# Shared resources
# ---------------------------------------------------------------------------


@st.cache_resource(show_spinner="Loading the dataset...")
def _database() -> int:
    return db.init_db()


@st.cache_resource(show_spinner=False)
def _audit_log() -> AuditLog:
    return AuditLog()


@st.cache_resource(show_spinner="Starting the agent...")
def _agent(username: str, tenant: str, role: str, user_id: int, model: str) -> Any:
    """One compiled graph per (user, model).

    Cached on primitives rather than on the context object so that Streamlit's
    hashing cannot accidentally share a graph between tenants -- the tenant is
    part of the key, and the graph closes over the context built from it.
    """
    ctx = SecurityContext(user_id=user_id, username=username, tenant_id=tenant, role=role)
    return build_agent(ctx, _audit_log(), model=model)


def _ask(question: str, ctx: SecurityContext, model: str) -> AgentAnswer:
    agent = _agent(ctx.username, ctx.tenant_id, ctx.role, ctx.user_id, model)
    return ask(question, ctx, _audit_log(), model=model, agent=agent)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def login_screen() -> None:
    st.title("🔐 Secure RLS Analyst")
    st.caption(
        "A conversational analyst over multi-tenant HR data. The tenant is fixed "
        "at login and cannot be changed by anything you or the model say."
    )
    left, right = st.columns([2, 3])
    with left, st.form("login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in", use_container_width=True):
            ctx = authenticate(username, password)
            if ctx is None:
                st.error("Incorrect username or password.")
            else:
                st.session_state["ctx"] = ctx
                st.rerun()
    with right:
        st.markdown("**Demo accounts**")
        st.table(
            [
                {"user": name, "tenant": tenant, "password": f"{tenant}-demo-2026"}
                for name, tenant in demo_accounts()
            ]
        )
        st.caption(
            "alice and arthur share a tenant on purpose: the boundary is the "
            "tenant, not the individual."
        )


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def render_chart(spec: dict[str, Any]) -> None:
    import pandas as pd
    import plotly.express as px

    frame = pd.DataFrame(spec["data"])
    if frame.empty:
        st.info("No data to chart.")
        return
    if spec["type"] == "bar":
        figure = px.bar(frame, x=spec["x"], y=spec["y"], title=spec["title"])
    elif spec["type"] == "histogram":
        figure = px.histogram(frame, x=spec["x"], title=spec["title"])
    else:
        figure = px.box(frame, x=spec["x"], y=spec["y"], title=spec["title"])
    st.plotly_chart(figure, use_container_width=True)


def render_trace(answer: AgentAnswer) -> None:
    """The reasoning trace: what the agent did, and what the guard changed."""
    if not answer.steps:
        st.caption("The agent answered without calling a tool.")
        return
    for index, step in enumerate(answer.steps, start=1):
        result = step.result
        if step.rejected:
            status, icon = "rejected", "🚫"
        elif step.unverifiable:
            status, icon = "unrecorded", "⚠️"
        elif result is not None and result.refused:
            status, icon = "refused", "🚫"
        else:
            status, icon = "ok", "✅"
        with st.expander(f"{icon} step {index}: `{step.tool}`", expanded=status != "ok"):
            st.json(step.arguments, expanded=False)
            if step.rejected:
                st.error(
                    "The call was refused before it ran: the arguments are not ones "
                    "this tool declares. Nothing was executed."
                )
                st.code(step.error or "", language="text")
                continue
            if result is None:
                st.warning(
                    "The tool ran but its output was not recorded, so nothing here "
                    "can be verified. Restart the app if this persists."
                )
                continue
            if result.refused:
                st.error(result.reason or "refused")
                continue
            if result.sql:
                st.markdown("**SQL actually executed** (after the guard rewrote it)")
                st.code(result.sql, language="sql")
            for note in result.rewrites:
                st.caption(f"guard: {note}")
            if result.flags:
                st.warning(
                    "Untrusted content in this result: " + ", ".join(result.flags)
                )
            if result.rows:
                # Only cap the height once there are enough rows to need
                # scrolling. A fixed height pads a one-row aggregate out with
                # blank rows, which reads as missing data rather than as a
                # single result.
                st.dataframe(
                    list(result.rows),
                    use_container_width=True,
                    **({"height": 260} if len(result.rows) > 7 else {}),
                )
            if result.chart:
                render_chart(result.chart)


def tenant_badge(ctx: SecurityContext, rows: int) -> None:
    st.markdown(
        f"### Tenant `{ctx.tenant_id}`\n"
        f"{ctx.username} · {ctx.role} · **{rows}** employees visible"
    )


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------


def chat_view(ctx: SecurityContext, model: str, question: str | None) -> None:
    """Transcript above, chips at the foot of it, composer pinned below.

    ``question`` arrives from the composer, which lives in :func:`main` because
    Streamlit only pins ``chat_input`` to the bottom of the window when it is a
    top-level element. Everything rendered here therefore sits above it.
    """
    history: list[dict[str, Any]] = st.session_state.setdefault("history", [])

    if not history and not question:
        st.markdown(
            f"#### Ask about {ctx.tenant_id}'s employees\n"
            "Every answer is computed from the rows you are allowed to see. "
            "Open a step to check the SQL that ran."
        )

    for turn in history:
        with st.chat_message("user"):
            st.write(turn["question"])
        with st.chat_message("assistant"):
            st.write(turn["answer"].text)
            for chart in turn["answer"].charts:
                render_chart(chart)
            render_trace(turn["answer"])

    if question:
        with st.chat_message("user"):
            st.write(question)
        with st.chat_message("assistant"), st.spinner("Thinking..."):
            answer = _ask(question, ctx, model)
            st.write(answer.text)
            for chart in answer.charts:
                render_chart(chart)
            render_trace(answer)
        history.append({"question": question, "answer": answer})

    _suggestion_chips()


def _suggestion_chips() -> str | None:
    """A row of chips at the foot of the transcript, just above the composer."""
    st.caption("Try")
    # A trailing spacer column keeps the chips at their natural width instead of
    # stretching each one across an equal share of the row.
    # The trailing spacer keeps the chips at their natural width instead of
    # stretching each across an equal share of the row; it is not paired with a
    # suggestion, hence the slice.
    columns = st.columns([*(1 for _ in SUGGESTIONS), 2], gap="small")
    for index, (column, (label, prompt)) in enumerate(
        zip(columns[: len(SUGGESTIONS)], SUGGESTIONS, strict=True)
    ):
        if column.button(label, key=f"chip_{index}", help=prompt):
            st.session_state["pending"] = prompt
            st.rerun()
    return None


def security_tab(ctx: SecurityContext, model: str) -> None:
    st.markdown(
        "Each attack is put to the agent as a real question. The verdict looks at "
        "the **data returned**, not at how the answer is phrased: an attack is "
        "contained when every row the tools produced belongs to the signed-in "
        "tenant."
    )
    st.caption(
        "A local 12B model needs roughly 20-30 seconds per attack, so the full "
        "catalogue is a job for CI rather than for a live audience. The featured "
        "set is the one to run in front of people."
    )

    quick, full = st.columns(2)
    run_quick = quick.button(
        f"Run the featured {len(featured())} attacks", use_container_width=True
    )
    run_full = full.button(
        f"Run all {len(ATTACKS)} attacks (slow)", use_container_width=True
    )

    if run_quick or run_full:
        selected: tuple[Attack, ...] = ATTACKS if run_full else featured()
        # Results live in session state rather than in local variables: any
        # later interaction reruns the script, and a demo that loses its
        # evidence the moment someone clicks something else is worse than no
        # demo at all.
        st.session_state["attack_results"] = _run_attacks(selected, ctx, model)

    results = st.session_state.get("attack_results")
    if not results:
        _attack_catalogue()
        return
    _render_results(results)


def _run_attacks(
    selected: tuple[Attack, ...], ctx: SecurityContext, model: str
) -> list[dict[str, Any]]:
    import time

    progress = st.progress(0.0, text="Running...")
    results: list[dict[str, Any]] = []
    for index, attack in enumerate(selected, start=1):
        started = time.perf_counter()
        answer = _ask(attack.prompt, ctx, model)
        contained, evidence = verdict(answer, ctx)
        results.append(
            {
                "attack": attack,
                "answer": answer,
                "contained": contained,
                "evidence": evidence,
                "seconds": time.perf_counter() - started,
            }
        )
        progress.progress(index / len(selected), text=f"{index}/{len(selected)} {attack.id}")
    progress.empty()
    return results


def _render_results(results: list[dict[str, Any]]) -> None:
    leaked = sum(1 for r in results if not r["contained"])
    total_seconds = sum(r["seconds"] for r in results)
    (st.success if leaked == 0 else st.error)(
        f"**Leak rate {leaked}/{len(results)}** — "
        f"{len(results) - leaked} attack(s) contained in {total_seconds:.0f}s."
    )
    for record in results:
        attack: Attack = record["attack"]
        with st.container(border=True):
            st.markdown(
                f"{'🟢' if record['contained'] else '🔴'} **{attack.id}** · "
                f"`{attack.category}` · {record['seconds']:.1f}s  \n"
                f"_{attack.intent}_"
            )
            st.caption(f"> {attack.prompt}")
            st.caption(f"verdict: {record['evidence']}")
            with st.expander("what the agent did"):
                st.write(record["answer"].text)
                render_trace(record["answer"])


def _attack_catalogue() -> None:
    st.dataframe(
        [
            {"id": a.id, "category": a.category, "intent": a.intent, "prompt": a.prompt}
            for a in ATTACKS
        ],
        use_container_width=True,
        height=420,
    )


def side_by_side_tab(ctx: SecurityContext, model: str) -> None:
    st.markdown(
        "The same question, asked as two different users. Nothing about the "
        "question changes -- only who is asking."
    )
    st.caption(
        "Signing in as the other user is not required: this view builds a second "
        "context from the demo accounts, exactly as a second browser session would."
    )
    question = st.text_input(
        "Question", value="What is the average salary by department?"
    )
    others = [t for t in ("acme", "beta", "gamma") if t != ctx.tenant_id]
    other_tenant = st.selectbox("Compare with tenant", others)
    if not st.button("Ask both", use_container_width=True):
        return

    peer_user = {"acme": ("alice", 1), "beta": ("bob", 3), "gamma": ("gita", 4)}[other_tenant]
    peer = SecurityContext(
        user_id=peer_user[1], username=peer_user[0], tenant_id=other_tenant, role="analyst"
    )

    left, right = st.columns(2)
    for column, who in ((left, ctx), (right, peer)):
        with column:
            st.markdown(f"#### `{who.tenant_id}` — {who.username}")
            with st.spinner("Thinking..."):
                answer = _ask(question, who, model)
            st.write(answer.text)
            render_trace(answer)


def audit_tab(ctx: SecurityContext) -> None:
    st.markdown(
        "Every security decision is written down. This view is itself "
        "tenant-scoped: you are looking at your own tenant's activity only."
    )
    records = _audit_log().recent(limit=200, tenant_id=ctx.tenant_id)
    if not records:
        st.info("Nothing recorded yet. Ask a question first.")
        return
    st.dataframe(
        [
            {
                "time": r.clock,
                "user": r.username,
                "event": r.event,
                "verdict": r.verdict,
                "layer": r.layer or "",
                "rows": r.rows if r.rows is not None else "",
                "detail": r.detail,
                "sql": (r.sql or "").replace("\n", " ")[:120],
            }
            for r in records
        ],
        use_container_width=True,
        height=480,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


#: View name -> the icon shown on its pill.
VIEWS: dict[str, str] = {
    "Chat": "💬",
    "Security": "🛡️",
    "Side by side": "👥",
    "Audit": "📋",
}


def main() -> None:
    _database()
    st.markdown(STYLE, unsafe_allow_html=True)

    ctx: SecurityContext | None = st.session_state.get("ctx")
    if ctx is None:
        login_screen()
        return

    with st.sidebar:
        tenant_badge(ctx, db.row_count(ctx))
        st.divider()
        model = st.selectbox(
            "Model",
            list(MODELS),
            index=list(MODELS).index(DEFAULT_MODEL),
            help="Swapping the model changes accuracy, not the isolation guarantee.",
        )
        spec = MODELS[model]
        st.caption(f"{spec.origin}  \nLicence: {spec.licence}  \n{spec.note}")
        st.divider()
        if st.button("Sign out", use_container_width=True):
            st.session_state.clear()
            st.rerun()

    # One view at a time rather than st.tabs: tabs render every panel, and a
    # chat_input inside one of them is no longer a top-level element, so
    # Streamlit stops pinning it to the bottom of the window.
    view = (
        st.segmented_control(
            "view",
            list(VIEWS),
            default="Chat",
            format_func=lambda name: f"{VIEWS[name]} {name}",
            label_visibility="collapsed",
            key="view_nav",
        )
        or "Chat"
    )

    if view == "Chat":
        question = st.chat_input(f"Ask about {ctx.tenant_id}'s employees")
        chat_view(ctx, model, question or st.session_state.pop("pending", None))
    elif view == "Security":
        security_tab(ctx, model)
    elif view == "Side by side":
        side_by_side_tab(ctx, model)
    else:
        audit_tab(ctx)


main()
