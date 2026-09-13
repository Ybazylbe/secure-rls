"""Compare the configured models on the same questions, and say which to use.

In plain terms: Runs the full evaluation for several models one after another
and writes a comparison with a recommendation.

The evaluation suite answers "is this agent correct and does it leak". This
answers a narrower, more practical question: **given three models that all hold
the same security guarantee, which one should the product ship with?**

Method, stated because a benchmark whose method is implicit is a benchmark
nobody should believe:

* The same 37 questions are put to every model, against all three tenants --
  111 question-runs each, which is also an isolation test, since each tenant has
  its own pay scale and an agent answering from the whole table fails two
  thirds of them.
* Then the same 25 attacks, in six categories.
* Each model is **warmed up first** with one unmeasured question. The first
  call after a switch pays for loading several gigabytes of weights into
  memory, and charging that to the first question would make whichever model
  ran first look terrible.
* Runs are sequential, never concurrent: the local Ollama server serves one
  request at a time, so overlapping them would measure queueing rather than the
  models.
* Temperature is 0 everywhere, so a rerun measures the agent rather than the
  sampler.

What "optimal" means here, in order:

1. **Leak rate must be zero.** A model that leaks is not a candidate, whatever
   else it scores. In practice none of them leaks -- the guarantee does not
   depend on the model -- but the rule is stated first because it is the one
   that would override everything.
2. **Answer accuracy**, then correct refusals.
3. **Latency**, as the tie-breaker: median for the feel of it, p95 for the
   stalls an audience actually notices.
4. **Licence**, when two models are otherwise level.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import db
from evals.golden import CASES, Case
from evals.runner import (
    AttackResult,
    CaseResult,
    SuiteResult,
    context_for,
    percent,
    run_attacks,
    run_cases,
)
from secure_rls.llm import MODELS
from secure_rls.redteam import ATTACKS, Attack
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import TENANTS

WARM_UP = "How many employees are there?"


@dataclass(frozen=True, slots=True)
class Verdict:
    """Which model to ship, and the honest reason."""

    winner: str
    reason: str
    runners_up: tuple[str, ...]


def warm_up(model: str, db_path: Path | str = db.DEFAULT_DB_PATH) -> float:
    """One unmeasured question, to pay the model-loading cost out of band."""
    from agent import ask, build_agent

    ctx = context_for("acme")
    audit = AuditLog(None)
    started = time.perf_counter()
    agent = build_agent(ctx, audit, model=model, db_path=db_path)
    ask(WARM_UP, ctx, audit, model=model, db_path=db_path, agent=agent)
    return time.perf_counter() - started


def benchmark(
    models: list[str],
    *,
    cases: tuple[Case, ...] = CASES,
    attacks: tuple[Attack, ...] = ATTACKS,
    tenants: tuple[str, ...] = TENANTS,
    attack_tenants: tuple[str, ...] = ("acme",),
    db_path: Path | str = db.DEFAULT_DB_PATH,
) -> tuple[list[SuiteResult], dict[str, float]]:
    """Run every question and every attack against each model in turn, after a warm-up."""
    suites: list[SuiteResult] = []
    warm: dict[str, float] = {}
    for model in models:
        print(f"\n=== {model} ===", flush=True)
        warm[model] = warm_up(model, db_path)
        print(f"  warm-up (not counted): {warm[model]:.1f}s", flush=True)

        suite = SuiteResult(model=model)
        suite.cases = run_cases(model, tenants, cases, db_path, on_progress=_tick)
        suite.attacks = run_attacks(model, attack_tenants, attacks, db_path, on_progress=_tick)
        suites.append(suite)
        print(
            f"  accuracy {percent(suite.accuracy)} | refusals "
            f"{percent(suite.refusal_accuracy)} | tools {percent(suite.tool_accuracy)} "
            f"| grounded {percent(suite.grounded_rate)} | leaks {suite.leak_rate} "
            f"| median {suite.median_seconds:.1f}s | p95 {suite.p95_seconds:.1f}s",
            flush=True,
        )
    return suites, warm


def _tick(result: CaseResult | AttackResult) -> None:
    """Print one progress line for a finished question or attack."""
    if isinstance(result, CaseResult):
        mark = "." if result.passed else "F"
        name = result.case_id
    else:
        mark = "." if result.contained else "LEAK"
        name = result.attack_id
    print(f"  {mark} {result.tenant:5s} {name:28s} {result.seconds:5.1f}s", flush=True)


def decide(suites: list[SuiteResult]) -> Verdict:
    """Rank the models by the criteria above and explain the choice."""
    safe = [s for s in suites if s.leaks == 0]
    if not safe:
        return Verdict(
            winner="none",
            reason="every model leaked; nothing here is shippable",
            runners_up=(),
        )

    def key(suite: SuiteResult) -> tuple[float, float, float]:
        # Higher accuracy first, then faster. Latency is negated so that one
        # sort direction serves both.
        """Sort key: accuracy first, then correct refusals, then speed."""
        return (suite.accuracy or 0.0, suite.refusal_accuracy or 0.0, -suite.median_seconds)

    ranked = sorted(safe, key=key, reverse=True)
    best, *rest = ranked

    reason = (
        f"{best.model} answers {percent(best.accuracy)} of the questions correctly "
        f"at a median of {best.median_seconds:.1f}s"
    )
    if rest:
        second = rest[0]
        gap = (best.accuracy or 0) - (second.accuracy or 0)
        if abs(gap) < 0.03 and second.median_seconds < best.median_seconds:
            reason += (
                f"; {second.model} is within {abs(gap):.0%} of it and faster "
                f"({second.median_seconds:.1f}s), so the choice between them is "
                f"licence and latency rather than quality"
            )
    return Verdict(winner=best.model, reason=reason, runners_up=tuple(s.model for s in rest))


def markdown(suites: list[SuiteResult], warm: dict[str, float]) -> str:
    """Write the benchmark results as a Markdown report with a recommendation."""
    verdict = decide(suites)
    lines = [
        "# Model benchmark",
        "",
        f"_Generated {time.strftime('%Y-%m-%d %H:%M')}_",
        "",
        f"{len(suites[0].cases)} question-runs and {len(suites[0].attacks)} attacks per "
        "model, identical for all of them. Each model was warmed up with one unmeasured "
        "question first, so the cost of loading its weights is not charged to whichever "
        "question happened to come first. Runs are sequential; the local server answers "
        "one request at a time.",
        "",
        "## Result",
        "",
        f"**{verdict.winner}** — {verdict.reason}.",
        "",
        "| model | accuracy | refusals | tool choice | grounded | misattributed "
        "| written calls | leak rate | exercised | median | p95 | slowest |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for suite in suites:
        slowest = max((c.seconds for c in suite.cases), default=0.0)
        lines.append(
            f"| `{suite.model}` | {percent(suite.accuracy)} "
            f"| {percent(suite.refusal_accuracy)} | {percent(suite.tool_accuracy)} "
            f"| {percent(suite.grounded_rate)} | {percent(suite.misattribution_rate)} "
            f"| {percent(suite.written_call_rate)} | **{suite.leak_rate}** "
            f"| {percent(suite.exercised_rate)} "
            f"| {suite.median_seconds:.1f}s | {suite.p95_seconds:.1f}s | {slowest:.0f}s |"
        )

    lines += [
        "",
        "## Cost of a run",
        "",
        "| model | warm-up | total wall clock | mean per question |",
        "| --- | --- | --- | --- |",
    ]
    for suite in suites:
        lines.append(
            f"| `{suite.model}` | {warm.get(suite.model, 0):.0f}s "
            f"| {suite.total_seconds / 60:.0f} min | {suite.mean_seconds:.1f}s |"
        )

    lines += ["", "## Licences", "", "| model | origin | licence |", "| --- | --- | --- |"]
    for suite in suites:
        spec = MODELS.get(suite.model)
        if spec:
            lines.append(f"| `{suite.model}` | {spec.origin} | {spec.licence} |")

    lines += [
        "",
        "## What this does not show",
        "",
        "Isolation. Every model returns the same leak rate because none of them is "
        "inside the trust boundary: the tenant view, the SQLite authorizer, the SQL "
        "guard and the egress check hold whatever the model emits. A benchmark can "
        "rank these models on accuracy and speed; it cannot rank them on safety, "
        "because safety here is not theirs to affect.",
        "",
        "*Misattributed* and *written calls* are answer-quality faults, lower is "
        "better; *exercised* is the share of attacks that reached what they test.",
        "",
        "Measured on one machine, one run each. Treat differences under a couple of "
        "points as noise.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Command line entry point: python -m evals.benchmark."""
    parser = argparse.ArgumentParser(prog="evals.benchmark", description=__doc__)
    parser.add_argument("--models", default="all", help="comma-separated tags, or 'all'")
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="first N cases AND attacks only. Limiting the cases alone made a "
        "'smoke run' take as long as the real thing, since the attack suite is "
        "the slow half.",
    )
    parser.add_argument("--out", type=Path, default=Path("evals/results/benchmark.md"))
    args = parser.parse_args(argv)

    models = list(MODELS) if args.models == "all" else [m.strip() for m in args.models.split(",")]
    cases = CASES[: args.limit] if args.limit else CASES
    attacks = ATTACKS[: args.limit] if args.limit else ATTACKS

    db.init_db()
    started = time.perf_counter()
    suites, warm = benchmark(models, cases=cases, attacks=attacks)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown(suites, warm), encoding="utf-8")

    verdict = decide(suites)
    print(f"\ntotal {(time.perf_counter() - started) / 60:.0f} min")
    print(f"recommended: {verdict.winner} -- {verdict.reason}")
    print(f"wrote {args.out}")
    return 1 if any(s.leaks for s in suites) else 0


if __name__ == "__main__":
    sys.exit(main())
