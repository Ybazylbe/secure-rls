"""Turning results into something a reviewer can read in thirty seconds."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from evals.runner import SuiteResult, percent


def markdown(suites: list[SuiteResult]) -> str:
    """A report whose first table is the one that matters."""
    lines: list[str] = [
        "# Evaluation report",
        "",
        f"_Generated {time.strftime('%Y-%m-%d %H:%M')}_",
        "",
        "Accuracy is scored against ground truth computed with pandas over an "
        "unrestricted connection, so a failure of isolation would show up here as "
        "a collapse in accuracy rather than as a matching expectation. The leak "
        "rate uses the same verdict function as the Security tab in the app. "
        "*Grounded* is the share of answers containing no figure that no tool "
        "produced, measured after the agent's one corrective retry; *retried* is "
        "how often that correction was needed. *Misattributed* is the share of "
        "answers that presented the caller's data as another tenant's, *written "
        "calls* the share that wrote a tool call out as text instead of making it, "
        "and *exercised* the share of attacks that reached what they test.",
        "",
        "## Summary",
        "",
        "| model | answer accuracy | refusals correct | tool choice | grounded "
        "| retried | misattributed | written calls | leak rate | exercised | median latency |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for suite in suites:
        lines.append(
            f"| `{suite.model}` | {percent(suite.accuracy)} "
            f"| {percent(suite.refusal_accuracy)} | {percent(suite.tool_accuracy)} "
            f"| {percent(suite.grounded_rate)} | {percent(suite.retry_rate)} "
            f"| {percent(suite.misattribution_rate)} | {percent(suite.written_call_rate)} "
            f"| **{suite.leak_rate}** | {percent(suite.exercised_rate)} "
            f"| {suite.median_seconds:.1f}s |"
        )

    lines += ["", "## Isolation", ""]
    total_attacks = sum(len(s.attacks) for s in suites)
    total_leaks = sum(s.leaks for s in suites)
    if total_attacks:
        verdict = "No attack in any suite returned another tenant's data."
        if total_leaks:
            verdict = f"**{total_leaks} of {total_attacks} attacks leaked.**"
        lines += [verdict, ""]
        lines += ["| model | category | attacks | contained |", "| --- | --- | --- | --- |"]
        for suite in suites:
            by_category: dict[str, list[bool]] = {}
            for attack in suite.attacks:
                by_category.setdefault(attack.category, []).append(attack.contained)
            for category, outcomes in sorted(by_category.items()):
                lines.append(
                    f"| `{suite.model}` | {category} | {len(outcomes)} | "
                    f"{sum(outcomes)}/{len(outcomes)} |"
                )

    lines += ["", "## Accuracy by tenant", ""]
    lines += ["| model | tenant | cases | passed |", "| --- | --- | --- | --- |"]
    for suite in suites:
        by_tenant: dict[str, list[bool]] = {}
        for case in suite.cases:
            if case.kind != "refusal":
                by_tenant.setdefault(case.tenant, []).append(case.passed)
        for tenant, outcomes in sorted(by_tenant.items()):
            lines.append(
                f"| `{suite.model}` | {tenant} | {len(outcomes)} | "
                f"{sum(outcomes)}/{len(outcomes)} |"
            )

    failures = [
        (suite, case)
        for suite in suites
        for case in suite.cases
        if not case.passed
    ]
    lines += ["", f"## Failures ({len(failures)})", ""]
    if not failures:
        lines.append("None.")
    for suite, case in failures:
        answer = case.answer.replace("\n", " ")
        lines += [
            f"**`{case.case_id}`** · {case.tenant} · `{suite.model}`  ",
            f"expected: `{case.expected}`  ",
            f"tools: `{', '.join(case.tools_used) or 'none'}`  ",
            f"answer: {answer[:300]}",
            "",
        ]

    leaked = [(s, a) for s in suites for a in s.attacks if not a.contained]
    if leaked:
        lines += ["## Leaks", ""]
        for suite, attack in leaked:
            lines += [f"- `{attack.attack_id}` ({suite.model}): {attack.evidence}"]

    return "\n".join(lines) + "\n"


def write(suites: list[SuiteResult], out_dir: Path) -> tuple[Path, Path]:
    """Write the human report and the machine-readable results beside it."""
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.md"
    json_path = out_dir / "results.json"

    report_path.write_text(markdown(suites), encoding="utf-8")
    json_path.write_text(
        json.dumps(
            [
                {
                    "model": suite.model,
                    "accuracy": suite.accuracy,
                    "refusal_accuracy": suite.refusal_accuracy,
                    "tool_accuracy": suite.tool_accuracy,
                    "leaks": suite.leaks,
                    "misattribution_rate": suite.misattribution_rate,
                    "written_call_rate": suite.written_call_rate,
                    "exercised_rate": suite.exercised_rate,
                    "attacks": len(suite.attacks),
                    "cases": [asdict(c) for c in suite.cases],
                    "attack_results": [asdict(a) for a in suite.attacks],
                }
                for suite in suites
            ],
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return report_path, json_path
