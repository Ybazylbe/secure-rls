"""How well search_notes finds the right notes, measured rather than assumed.

In plain terms: the note search mixes meaning (embeddings) with word matches
(names and note words). The word-match weights were first picked on a single
example, which says nothing about whether search got better or worse overall.
This runs a fixed set of lookups for every tenant, with the hybrid search and
with meaning alone, and reports both, so a change to the weights or the
embedding model shows up as a number.

Two kinds of lookup:

* **By name.** Every tenth employee is searched for by full name. Scored
  hit@1: is the top note that person's? Names repeat, so any employee with
  that exact name counts.
* **By topic.** Plain questions about kinds of note ("who might leave the
  company"). Scored precision@5: how many of the top five notes are about that
  topic, judged by the phrases the dataset generator uses for it.

Run it with ``python -m evals.retrieval``. It needs the embedding model but no
language model.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import db
from secure_rls.rag import get_index, reset_indexes
from secure_rls.security.context import TENANTS, SecurityContext

#: Topic questions and the note phrases that answer them. Test data, like the
#: golden questions: written by hand, independent of how search works.
TOPICS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("underperforming employees",
     ("Below target", "Missed two delivery", "Struggling after the reorg", "Attendance concerns")),
    ("who might leave the company", ("Retention risk",)),
    ("strongest performers", ("High performer", "Top quartile", "process overhaul")),
    ("attendance problems", ("Attendance concerns",)),
    ("pay outside the normal salary band",
     ("Executive retention package", "Part-time arrangement")),
    ("people who recently changed team", ("Transferred into",)),
)

#: Search for every Nth employee by name.
NAME_STEP: Final = 10

CONFIGS: Final[dict[str, dict[str, float | None]]] = {
    "hybrid (current)": {"name_weight": None, "text_weight": None},
    "semantic only": {"name_weight": 0.0, "text_weight": 0.0},
}


@dataclass(frozen=True, slots=True)
class RetrievalScore:
    """Results for one search configuration on one tenant."""

    config: str
    tenant: str
    name_hit_at_1: float
    topic_precision_at_5: float


def evaluate(db_path: Path | str = db.DEFAULT_DB_PATH) -> list[RetrievalScore]:
    """Run every lookup for every tenant under every configuration."""
    reset_indexes()
    scores: list[RetrievalScore] = []
    for tenant in TENANTS:
        index = get_index(SecurityContext(1, "eval", tenant), db_path)
        with db.admin_connection(db_path) as con:
            names = [
                str(row["name"])
                for row in con.execute(
                    f"SELECT name FROM {db.BASE_TABLE} "  # noqa: S608 - constant table name
                    "WHERE tenant_id = ? ORDER BY user_id",
                    (tenant,),
                )
            ][::NAME_STEP]
        for config, weights in CONFIGS.items():
            hits = sum(
                index.search(name, k=1, **weights)[0][0].name == name for name in names
            )
            relevant = 0
            for question, phrases in TOPICS:
                top = index.search(question, k=5, **weights)
                relevant += sum(any(p in note.text for p in phrases) for note, _ in top)
            scores.append(
                RetrievalScore(
                    config=config,
                    tenant=tenant,
                    name_hit_at_1=hits / len(names),
                    topic_precision_at_5=relevant / (5 * len(TOPICS)),
                )
            )
    reset_indexes()
    return scores


def markdown(scores: list[RetrievalScore]) -> str:
    """The scores as a Markdown table, one row per configuration and tenant."""
    lines = [
        "# Note search",
        "",
        f"Name lookups: every {NAME_STEP}th employee, hit@1. "
        f"Topic lookups: {len(TOPICS)} questions, precision@5.",
        "",
        "| search | tenant | name hit@1 | topic precision@5 |",
        "| --- | --- | --- | --- |",
    ]
    for score in scores:
        lines.append(
            f"| {score.config} | {score.tenant} | {score.name_hit_at_1:.0%} "
            f"| {score.topic_precision_at_5:.0%} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Command line entry point: python -m evals.retrieval."""
    parser = argparse.ArgumentParser(prog="evals.retrieval", description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("evals/results/retrieval.md"))
    args = parser.parse_args(argv)
    db.init_db()
    report = markdown(evaluate())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
