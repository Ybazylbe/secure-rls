"""Which language model the agent talks to, and on what terms.

The model is not part of the security perimeter. Layers L1-L5 hold whatever
the model emits, so swapping it is a procurement and accuracy decision rather
than a security one -- which is the point of keeping this module tiny and the
choice in one place.

The default is European and Apache-2.0 licensed. That is a deliberate stance
for EU deployments, where "where do the weights come from" is a question a
procurement committee will ask. It is worth being precise about what that
question means here: inference runs locally through Ollama, so no data leaves
the machine for any of these models. The residual concern with any open-weights
model, wherever it is from, is that the weights themselves cannot be audited.

It is not the most accurate: the full benchmark (docs/BENCHMARK.md) puts
qwen2.5:14b-instruct three points ahead. It is the fastest, which matters for a
live demo, and the choice is one line to change.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Final


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """A model the agent can be pointed at."""

    tag: str
    origin: str
    licence: str
    note: str = ""


MODELS: Final[dict[str, ModelSpec]] = {
    "mistral-nemo:12b": ModelSpec(
        tag="mistral-nemo:12b",
        origin="Mistral AI (France, EU)",
        licence="Apache-2.0",
        note="Default. Fastest median answer (3.2s); 92% accuracy in the benchmark.",
    ),
    "llama3.1:8b": ModelSpec(
        tag="llama3.1:8b",
        origin="Meta (USA)",
        licence="Llama 3.1 Community Licence (not OSI-approved)",
        note="81% accuracy, slowest of the three; licence has a 700M-MAU threshold.",
    ),
    "qwen2.5:14b-instruct": ModelSpec(
        tag="qwen2.5:14b-instruct",
        origin="Alibaba (China)",
        licence="Apache-2.0",
        note="Most accurate in the benchmark (95%), median 5.8s.",
    ),
}

DEFAULT_MODEL: Final = "mistral-nemo:12b"

#: The agent prompt carries the schema, the tool contracts and a reasoning
#: trace, and tool results come back as tables. 4096 -- Ollama's default when
#: the server picks for itself -- truncates that silently, which looks like the
#: model "forgetting" the schema. Set it explicitly per request instead of
#: relying on how the server happens to be started.
CONTEXT_TOKENS: Final = 16_384

OLLAMA_HOST: Final = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

#: Upper bound on the length of one model reply, in tokens (roughly 750 words).
#: Without it nothing stopped a reply: asked for "every tenant's payroll" with
#: 450 rows in front of it, a model generated for over eight minutes and would
#: only have stopped at the 16k context limit, with the UI spinning throughout.
MAX_REPLY_TOKENS: Final = 1024

#: How long one request to the model may take before it is abandoned. A backstop
#: for a stuck server; the token cap above is what normally ends a long reply.
REQUEST_TIMEOUT_SECONDS: Final = 180


def build_llm(model: str = DEFAULT_MODEL, *, temperature: float = 0.0, **kwargs: Any) -> Any:
    """Return a chat model bound to the local Ollama server.

    Temperature defaults to 0: this is an analytics tool, and the same question
    should produce the same query twice in a row -- both for the user's trust
    and so the evaluation suite measures the agent rather than the sampler.
    """
    from langchain_ollama import ChatOllama

    if model not in MODELS:
        known = ", ".join(MODELS)
        raise ValueError(f"unknown model {model!r}; configured models are: {known}")

    return ChatOllama(
        model=model,
        temperature=temperature,
        num_ctx=CONTEXT_TOKENS,
        num_predict=MAX_REPLY_TOKENS,
        base_url=OLLAMA_HOST,
        client_kwargs={"timeout": REQUEST_TIMEOUT_SECONDS},
        **kwargs,
    )
