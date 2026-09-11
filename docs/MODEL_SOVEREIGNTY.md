# Choosing a model, and answering the procurement question

For a European deployment, "where does the model come from?" arrives early and
is usually asked by someone who is not going to read the code. It deserves a
precise answer rather than a reassuring one.

## The distinction that settles most of it

Almost everything written about the risk of non-EU models concerns **hosted
services**, where prompts and data leave the building. The 2025 DeepSeek
episode — the Italian regulator's block, bans on government devices in several
countries — was about an application and an API that transmitted user data
abroad.

This system runs weights locally through Ollama. Inference happens on the host;
no prompt, no row and no embedding leaves it. The data-residency question
therefore does not arise for any of the three models, and GDPR has nothing to
say about the origin of a file on disk. The EU AI Act does not restrict models
by provenance either.

What does remain, for open weights of **any** origin: the weights are an opaque
binary that cannot be meaningfully audited for backdoors or latent behaviour.
That is a genuine supply-chain concern, it applies equally to Mistral, Llama and
Qwen, and nothing in this project addresses it. It should be stated plainly
rather than argued away.

## Licences

The counter-intuitive part, and worth knowing before the meeting:

| model | origin | licence | notes |
| --- | --- | --- | --- |
| `mistral-nemo:12b` | Mistral AI, France | Apache-2.0 | OSI-approved, no usage conditions |
| `qwen2.5:14b-instruct` | Alibaba, China | Apache-2.0 | OSI-approved for this size |
| `llama3.1:8b` | Meta, USA | Llama 3.1 Community Licence | not OSI-approved: 700M-MAU threshold, acceptable-use policy, attribution requirement |
| `gemma` | Google, USA | Gemma Terms of Use | not OSI-approved |

For a commercial product, the two Apache-2.0 models are the legally simpler
choice, and one of them is the Chinese one. Procurement conversations that sort
models by country of origin tend to miss this.

*(Licence terms change between releases and sizes; verify against the specific
variant before relying on this table.)*

## Why the default is what it is

`mistral-nemo:12b` is the default for three reasons, in this order:

1. **It measured best at tool selection.** In an early smoke test it picked the
   right tool in 3 of 3 cases where `qwen2.5:14b-instruct` — the largest of the
   three — managed 2 of 3, choosing a chart tool for "what is the average
   salary". More parameters did not mean better tool discipline.
2. **Apache-2.0**, so no licence conversation is needed.
3. **European origin**, which removes a procurement objection at no cost, given
   that (1) and (2) already pointed here.

Note the ordering. The model was not chosen for its passport and then justified;
it was chosen on measurement, and the passport happened to agree.

## Why it does not matter much

The model is not part of the trust boundary. Layers L1–L5 hold whatever it
emits, so swapping it changes accuracy and licence exposure — not isolation. The
evaluation suite is built to demonstrate this rather than assert it:

```bash
python -m evals --models all
```

Expect different accuracy per model and the same leak rate: zero. That is the
claim worth making in a procurement meeting — not "we picked a trustworthy
model", but "our guarantee does not depend on which one you pick, and here is
the run that shows it".

Changing model is one line of configuration:

```python
# secure_rls/llm/provider.py
DEFAULT_MODEL = "mistral-nemo:12b"
```

or at runtime, from the sidebar in the app.
