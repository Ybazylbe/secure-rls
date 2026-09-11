"""Running the evaluation suites and collecting the numbers.

Two suites, answering two different questions:

* **Correctness** -- does the agent give the right answer? Scored against
  ground truth computed here, from an unrestricted connection, with pandas.
  That path deliberately bypasses every security layer: if the guarded path
  ever returned the wrong rows, the expected answers would still be right and
  the agent's would not, so an isolation bug shows up as an accuracy collapse
  rather than hiding behind a matching expectation.

* **Red team** -- does anything ever leak? Scored by the same
  :func:`secure_rls.redteam.verdict` the UI uses, so the number on a demo
  screen and the number in a CI run are the same measurement.

The correctness set is run against every tenant. Each tenant has its own pay
scale, so an agent that answered from the whole table would fail two thirds of
the cases outright -- correctness and isolation are measured by the same run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from agent import build_agent
from db import BASE_TABLE, DEFAULT_DB_PATH, admin_connection
from evals.golden import CASES, Case, matches_name, matches_number
from secure_rls.auth import USER_IDS
from secure_rls.llm import DEFAULT_MODEL
from secure_rls.redteam import ATTACKS, Attack, verdict
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import TENANTS, SecurityContext

TENANT_USER = {"acme": "alice", "beta": "bob", "gamma": "gita"}


@dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    kind: str
    tenant: str
    model: str
    passed: bool
    tool_ok: bool | None
    expected: Any
    answer: str
    tools_used: tuple[str, ...]
    seconds: float
    note: str = ""
    #: Whether the grounding check fired, and whether anything survived it.
    retried: bool = False
    ungrounded: int = 0


@dataclass(frozen=True, slots=True)
class AttackResult:
    attack_id: str
    category: str
    tenant: str
    model: str
    contained: bool
    evidence: str
    seconds: float


@dataclass(slots=True)
class SuiteResult:
    model: str
    cases: list[CaseResult] = field(default_factory=list)
    attacks: list[AttackResult] = field(default_factory=list)

    @property
    def accuracy(self) -> float | None:
        scored = [c for c in self.cases if c.kind != "refusal"]
        return _ratio(sum(c.passed for c in scored), len(scored))

    @property
    def refusal_accuracy(self) -> float | None:
        scored = [c for c in self.cases if c.kind == "refusal"]
        return _ratio(sum(c.passed for c in scored), len(scored))

    @property
    def tool_accuracy(self) -> float | None:
        scored = [c for c in self.cases if c.tool_ok is not None]
        return _ratio(sum(bool(c.tool_ok) for c in scored), len(scored))

    @property
    def leak_rate(self) -> str:
        leaked = sum(not a.contained for a in self.attacks)
        return f"{leaked}/{len(self.attacks)}" if self.attacks else "n/a"

    @property
    def leaks(self) -> int:
        return sum(not a.contained for a in self.attacks)

    @property
    def grounded_rate(self) -> float | None:
        """Share of answers stating no figure a tool did not produce.

        Measured after the corrective retry, so it reports what the user
        actually sees rather than what the model said first.
        """
        return _ratio(sum(c.ungrounded == 0 for c in self.cases), len(self.cases))

    @property
    def retry_rate(self) -> float | None:
        return _ratio(sum(c.retried for c in self.cases), len(self.cases))

    @property
    def median_seconds(self) -> float:
        times = sorted(c.seconds for c in self.cases) or [0.0]
        return times[len(times) // 2]


def _ratio(hits: int, total: int) -> float | None:
    """``None`` when nothing was measured.

    Returning 0.0 for an empty set reads as "everything failed", which is a
    different and much more alarming claim than "this was not run" -- and on a
    filtered smoke run it is the wrong one.
    """
    return hits / total if total else None


def percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def context_for(tenant: str) -> SecurityContext:
    username = TENANT_USER[tenant]
    return SecurityContext(
        user_id=USER_IDS[username], username=username, tenant_id=tenant, role="analyst"
    )


def truth_frame(tenant: str, db_path: Path | str = DEFAULT_DB_PATH) -> pd.DataFrame:
    """Ground truth, read without any of the security layers in the way."""
    with admin_connection(db_path) as con:
        rows = con.execute(  # noqa: S608 - constant table name, bound parameter
            f"SELECT * FROM {BASE_TABLE} WHERE tenant_id = ?", (tenant,)
        ).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


def _score(case: Case, answer_text: str, frame: pd.DataFrame) -> tuple[bool, Any, str]:
    if case.expected is None:
        return False, None, "no expectation"
    expected = case.expected(frame)
    if case.kind in ("number", "count"):
        tolerance = 0.0001 if case.kind == "count" else case.tolerance
        return matches_number(answer_text, float(expected), tolerance), expected, ""
    return matches_name(answer_text, str(expected)), expected, ""


def run_cases(
    model: str,
    tenants: tuple[str, ...] = TENANTS,
    cases: tuple[Case, ...] = CASES,
    db_path: Path | str = DEFAULT_DB_PATH,
    on_progress: Any = None,
) -> list[CaseResult]:
    from agent import ask

    results: list[CaseResult] = []
    audit = AuditLog(None)
    for tenant in tenants:
        ctx = context_for(tenant)
        frame = truth_frame(tenant, db_path)
        agent = build_agent(ctx, audit, model=model, db_path=db_path)
        for case in cases:
            started = time.perf_counter()
            answer = ask(case.question, ctx, audit, model=model, db_path=db_path, agent=agent)
            elapsed = time.perf_counter() - started
            tools_used = tuple(step.tool for step in answer.steps)

            if case.kind == "refusal":
                contained, note = verdict(answer, ctx)
                passed, expected = contained, "no foreign data"
            else:
                passed, expected, note = _score(case, answer.text, frame)

            results.append(
                CaseResult(
                    case_id=case.id, kind=case.kind, tenant=tenant, model=model,
                    passed=passed, expected=expected, answer=answer.text.strip(),
                    tools_used=tools_used, seconds=elapsed, note=note,
                    tool_ok=(bool(set(tools_used) & set(case.tools)) if case.tools else None),
                    retried=answer.retried,
                    ungrounded=len(answer.ungrounded),
                )
            )
            if on_progress:
                on_progress(results[-1])
    return results


def run_attacks(
    model: str,
    tenants: tuple[str, ...] = ("acme",),
    attacks: tuple[Attack, ...] = ATTACKS,
    db_path: Path | str = DEFAULT_DB_PATH,
    on_progress: Any = None,
) -> list[AttackResult]:
    from agent import ask

    results: list[AttackResult] = []
    audit = AuditLog(None)
    for tenant in tenants:
        ctx = context_for(tenant)
        agent = build_agent(ctx, audit, model=model, db_path=db_path)
        for attack in attacks:
            started = time.perf_counter()
            answer = ask(attack.prompt, ctx, audit, model=model, db_path=db_path, agent=agent)
            contained, evidence = verdict(answer, ctx)
            results.append(
                AttackResult(
                    attack_id=attack.id, category=attack.category, tenant=tenant,
                    model=model, contained=contained, evidence=evidence,
                    seconds=time.perf_counter() - started,
                )
            )
            if on_progress:
                on_progress(results[-1])
    return results


def run_suite(
    model: str = DEFAULT_MODEL,
    *,
    tenants: tuple[str, ...] = TENANTS,
    attack_tenants: tuple[str, ...] = ("acme",),
    cases: tuple[Case, ...] = CASES,
    attacks: tuple[Attack, ...] = ATTACKS,
    db_path: Path | str = DEFAULT_DB_PATH,
    on_progress: Any = None,
) -> SuiteResult:
    return SuiteResult(
        model=model,
        cases=run_cases(model, tenants, cases, db_path, on_progress),
        attacks=run_attacks(model, attack_tenants, attacks, db_path, on_progress),
    )
