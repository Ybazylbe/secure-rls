# Model benchmark

_Generated 2026-09-13 19:27_

111 question-runs and 25 attacks per model, identical for all of them. Each model was warmed up with one unmeasured question first, so the cost of loading its weights is not charged to whichever question happened to come first. Runs are sequential; the local server answers one request at a time.

## Result

**qwen2.5:14b-instruct** — qwen2.5:14b-instruct answers 95% of the questions correctly at a median of 5.8s.

| model | accuracy | refusals | tool choice | grounded | leak rate | median | p95 | slowest |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mistral-nemo:12b` | 92% | 100% | 91% | 97% | **0/25** | 3.2s | 16.5s | 75s |
| `llama3.1:8b` | 81% | 100% | 97% | 100% | **0/25** | 7.1s | 33.6s | 64s |
| `qwen2.5:14b-instruct` | 95% | 100% | 97% | 98% | **0/25** | 5.8s | 19.5s | 24s |

## Cost of a run

| model | warm-up | total wall clock | mean per question |
| --- | --- | --- | --- |
| `mistral-nemo:12b` | 2s | 20 min | 7.2s |
| `llama3.1:8b` | 15s | 24 min | 10.8s |
| `qwen2.5:14b-instruct` | 26s | 26 min | 8.2s |

## Licences

| model | origin | licence |
| --- | --- | --- |
| `mistral-nemo:12b` | Mistral AI (France, EU) | Apache-2.0 |
| `llama3.1:8b` | Meta (USA) | Llama 3.1 Community Licence (not OSI-approved) |
| `qwen2.5:14b-instruct` | Alibaba (China) | Apache-2.0 |

## What this does not show

Isolation. Every model returns the same leak rate because none of them is inside the trust boundary: the tenant view, the SQLite authorizer, the SQL guard and the egress check hold whatever the model emits. A benchmark can rank these models on accuracy and speed; it cannot rank them on safety, because safety here is not theirs to affect.

Measured on one machine, one run each. Treat differences under a couple of points as noise.
