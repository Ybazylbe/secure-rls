"""Command line entry point: ``python -m evals``.

Examples::

    python -m evals                          # default model, everything
    python -m evals --models all             # the three configured models
    python -m evals --attacks-only           # just the leak rate
    python -m evals --limit 5                # a quick smoke run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import db
from evals.golden import CASES
from evals.report import write
from evals.runner import SuiteResult, percent, run_attacks, run_cases
from secure_rls.llm import DEFAULT_MODEL, MODELS
from secure_rls.redteam import ATTACKS
from secure_rls.security.context import TENANTS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals", description=__doc__)
    parser.add_argument("--models", default=DEFAULT_MODEL,
                        help="comma-separated model tags, or 'all'")
    parser.add_argument("--tenants", default=",".join(TENANTS),
                        help="tenants to run the correctness set against")
    parser.add_argument("--attack-tenants", default="acme")
    parser.add_argument("--limit", type=int, default=0,
                        help="use only the first N cases and attacks (smoke run)")
    parser.add_argument("--only", default="",
                        help="comma-separated case ids, for re-checking known failures")
    parser.add_argument("--cases-only", action="store_true")
    parser.add_argument("--attacks-only", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("evals/results"))
    args = parser.parse_args(argv)

    models = list(MODELS) if args.models == "all" else [m.strip() for m in args.models.split(",")]
    tenants = tuple(t.strip() for t in args.tenants.split(",") if t.strip())
    attack_tenants = tuple(t.strip() for t in args.attack_tenants.split(",") if t.strip())
    cases = CASES
    if args.only:
        wanted = {c.strip() for c in args.only.split(",") if c.strip()}
        unknown = wanted - {c.id for c in CASES}
        if unknown:
            parser.error(f"unknown case id(s): {sorted(unknown)}")
        cases = tuple(c for c in CASES if c.id in wanted)
    if args.limit:
        cases = cases[: args.limit]
    attacks = ATTACKS[: args.limit] if args.limit else ATTACKS

    db.init_db()
    suites: list[SuiteResult] = []
    for model in models:
        print(f"\n=== {model} ===", flush=True)
        suite = SuiteResult(model=model)
        if not args.attacks_only:
            suite.cases = run_cases(model, tenants, cases, on_progress=_case_progress)
        if not args.cases_only:
            suite.attacks = run_attacks(
                model, attack_tenants, attacks, on_progress=_attack_progress
            )
        suites.append(suite)
        print(
            f"  accuracy {percent(suite.accuracy)} "
            f"| refusals {percent(suite.refusal_accuracy)} "
            f"| tools {percent(suite.tool_accuracy)} | leaks {suite.leak_rate}",
            flush=True,
        )

    report_path, json_path = write(suites, args.out)
    print(f"\nwrote {report_path} and {json_path}")
    return 1 if any(s.leaks for s in suites) else 0


def _case_progress(result: object) -> None:
    r = result  # type: ignore[assignment]
    mark = "." if r.passed else "F"  # type: ignore[attr-defined]
    print(f"  {mark} {r.tenant:5s} {r.case_id:28s} {r.seconds:5.1f}s", flush=True)  # type: ignore[attr-defined]


def _attack_progress(result: object) -> None:
    r = result  # type: ignore[assignment]
    mark = "." if r.contained else "LEAK"  # type: ignore[attr-defined]
    print(f"  {mark} {r.tenant:5s} {r.attack_id:28s} {r.seconds:5.1f}s", flush=True)  # type: ignore[attr-defined]


if __name__ == "__main__":
    sys.exit(main())
