# Working with Claude Code on this project

The repository is configured for agentic development rather than merely having
been written with an assistant open. Everything below is checked in, under
[`.claude/`](../.claude), and is what a second person joining the project would
inherit.

## What is configured

**[`CLAUDE.md`](../.claude/CLAUDE.md)** — the project's standing rules. Not a
description of the code (the code describes itself), but the things an agent
cannot infer: that the prompt is never a control, that no tool schema may take
a tenant argument, that SQL is validated on the AST and never as a string, and
that failing loudly beats failing open. It also carries the layer table, so any
change can be located in the design before it is judged.

**[`agents/security-reviewer.md`](../.claude/agents/security-reviewer.md)** — a
subagent with one question: can a tenant now reach data it could not reach
before? It is deliberately narrow. Style and performance findings are someone
else's job, and a reviewer that reports everything gets skimmed. It is asked to
run the isolation tests itself before concluding, and to describe the exploit
sequence or admit it could not find one — which keeps it from dressing
preferences up as findings.

**[`commands/redteam.md`](../.claude/commands/redteam.md)** — generate new
attacks, run them, and keep only the ones that teach something. The instruction
that matters is the disposal rule: a near-duplicate is discarded, because a
catalogue padded with rephrasings makes the leak rate look more impressive and
means less. A leak stops the command and becomes a finding, not a test case.

**[`commands/check-isolation.md`](../.claude/commands/check-isolation.md)** —
runs the CI gate locally and, on failure, names which of the five layers broke
before proposing anything. It is explicitly forbidden from proposing a relaxed
assertion.

**[`settings.json`](../.claude/settings.json)** — a `PostToolUse` hook that runs
the isolation tests automatically whenever `secure_rls/security/**` or `db.py`
is edited. The security tests take under a second and need no model, so there is
no reason for them not to run on every edit rather than at commit time.

## How it was used

The work ran in phases — data and storage, the security kernel, tools and agent,
UI, evaluation, delivery — each ending in a commit that states what was built
and what broke. The commit messages are the honest record: several of them
describe defects found in code written earlier in the same session.

Two patterns did most of the work.

**Verify the library, do not trust the docstring.** The SQLite authorizer's
view-expansion behaviour, `sqlglot`'s node hierarchy, and LangGraph's reducer
semantics were each checked with a throwaway script before being built on. All
three turned out to differ from the obvious assumption, and two of them had
already caused silent bugs by the time they were checked.

**Let the evaluation drive the design.** The six defects in
[`EVALUATION.md`](EVALUATION.md) were found by running the thing against ground
truth, not by reading it. Each fix was verified by re-running only the affected
cases, which takes about a minute, and the full suite was re-run before the
phase was committed. One of those fixes made accuracy worse and the run said so;
it was reverted in favour of a different approach rather than argued with.

## The live task for the demo

`/redteam inference` — extend the thinnest attack category, run it, and report
what was kept and what was discarded as a duplicate. It exercises the subagent,
a slash command, the shared catalogue and the evaluation harness in one pass,
and it produces a real answer rather than a scripted one.
