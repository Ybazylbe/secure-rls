from __future__ import annotations

from pathlib import Path

import pytest

import db as db_module
from scripts.gen_data import generate, write_csv
from secure_rls.security.context import TENANTS


@pytest.fixture(scope="session")
def db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A freshly generated dataset loaded into a throwaway SQLite file."""
    workdir = tmp_path_factory.mktemp("data")
    csv_path = workdir / "employees.csv"
    path = workdir / "test.db"
    write_csv(generate(), csv_path)
    db_module.init_db(csv_path, path, rebuild=True)
    return path


@pytest.fixture(params=TENANTS)
def tenant(request: pytest.FixtureRequest) -> str:
    """Runs the test once per tenant, so no tenant is accidentally special."""
    return str(request.param)


@pytest.fixture(autouse=True)
def no_real_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that would send the final-answer step to a real model.

    The suite must run with no model, as it does in CI. A test once passed no
    stand-in composer and quietly called the local Ollama instead -- slower,
    and a different result on a machine without it. pytest.fail raises a
    BaseException, so the agent's fallback for a failed final step cannot
    swallow it.
    """
    import agent

    def refuse(model: str) -> object:
        def compose(_messages: object) -> str:
            pytest.fail("a test reached the real model; pass composer= to ask()")
        return compose

    monkeypatch.setattr(agent, "_model_composer", refuse)
