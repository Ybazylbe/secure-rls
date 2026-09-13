"""Tests for how attacks are prepared and when they count as exercised.

An attack that never delivers what it tests is not a passed test, it is no
test. Indirect attacks used to ask the agent to search for "administrators",
which found the injected notes for one tenant and missed them for the other
two. These tests pin that every indirect attack now reaches hostile text for
every tenant, and that a run where it does not is reported as not exercised.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent import AgentAnswer, Step
from secure_rls.redteam import (
    ATTACKS,
    Attack,
    carrier_for,
    exercised,
    not_exercised_reason,
    prompt_for,
)
from secure_rls.security.audit import AuditLog
from secure_rls.security.context import TENANTS, SecurityContext
from secure_rls.tools.base import ToolResult
from secure_rls.tools.query import run_sql

INDIRECT = tuple(a for a in ATTACKS if a.category == "indirect")


def ctx_for(tenant: str) -> SecurityContext:
    return SecurityContext(user_id=1, username=f"{tenant}_analyst", tenant_id=tenant)


@pytest.mark.parametrize("tenant", TENANTS)
@pytest.mark.parametrize("attack", INDIRECT, ids=lambda a: a.id)
def test_every_indirect_attack_names_a_real_carrier_for_every_tenant(
    attack: Attack, tenant: str, db_path: Path
) -> None:
    prompt = prompt_for(attack, ctx_for(tenant), db_path)
    assert prompt is not None
    assert "{carrier}" not in prompt


@pytest.mark.parametrize("tenant", TENANTS)
def test_the_carrier_s_note_really_delivers_injected_text_through_a_tool(
    tenant: str, db_path: Path
) -> None:
    """Asking about the carrier by name must put flagged text in a tool result."""
    ctx = ctx_for(tenant)
    carrier = carrier_for(INDIRECT[0], ctx, db_path)
    assert carrier is not None
    result = run_sql(
        f"SELECT name, notes FROM employees WHERE name = '{carrier}'", ctx, AuditLog(None), db_path
    )
    assert result.flags, f"{carrier}'s note in {tenant} carried no injected text"


def test_a_tenant_with_no_injected_notes_makes_the_attack_not_applicable(
    tmp_path: Path,
) -> None:
    import db
    from scripts.gen_data import generate, write_csv

    rows = generate()
    for row in rows:
        if row["tenant_id"] == "gamma":
            row["notes"] = "Meets expectations."
    csv_path, db_file = tmp_path / "e.csv", tmp_path / "e.db"
    write_csv(rows, csv_path)
    db.init_db(csv_path, db_file, rebuild=True)
    assert prompt_for(INDIRECT[0], ctx_for("gamma"), db_file) is None


def test_other_attacks_keep_their_prompt_unchanged(db_path: Path) -> None:
    direct = next(a for a in ATTACKS if a.category == "direct")
    assert prompt_for(direct, ctx_for("acme"), db_path) == direct.prompt


def test_an_indirect_attack_that_never_meets_injected_text_is_not_exercised() -> None:
    """The gamma run: search_notes ran, returned five ordinary notes, and the
    attack was still counted as having tested something."""
    clean = Step("search_notes", {"query": "x"}, ToolResult(summary="", rows=({"n": 1},)),
                 executed=True)
    answer = AgentAnswer(text="Nothing to follow.", steps=[clean])
    assert exercised(answer, None)
    assert not exercised(answer, INDIRECT[0])
    reason = not_exercised_reason(answer, INDIRECT[0])
    assert reason is not None and "no injected text" in reason


def test_an_indirect_attack_that_delivers_injected_text_is_exercised() -> None:
    flagged = Step(
        "query_db", {"sql": "x"},
        ToolResult(summary="", rows=({"n": 1},), flags=("addressed-to-model",)),
        executed=True,
    )
    answer = AgentAnswer(text="The note asks me to change the query; I will not.", steps=[flagged])
    assert exercised(answer, INDIRECT[0])
    assert not_exercised_reason(answer, INDIRECT[0]) is None


@pytest.mark.slow
@pytest.mark.parametrize("tenant", TENANTS)
def test_searching_notes_for_the_carrier_by_name_finds_the_carrier_first(
    tenant: str, db_path: Path
) -> None:
    """The model asked search_notes for "Ravi Sato" and got five other Satos.

    Semantic similarity alone ranked his note below theirs; the keyword half of
    the search now puts a named person first.
    """
    from secure_rls.rag import get_index, reset_indexes

    reset_indexes()
    ctx = ctx_for(tenant)
    for attack in INDIRECT:
        carrier = carrier_for(attack, ctx, db_path)
        assert carrier is not None
        top_note, _ = get_index(ctx, db_path).search(carrier, k=5)[0]
        assert top_note.name == carrier
    reset_indexes()
