# Threat model

## What this system is for

A conversational analyst over one table of employee records belonging to three
tenants. Any authenticated user may ask arbitrary natural-language questions
about **their own tenant's** rows. The security property is one sentence:

> No sequence of user input, model output, or content stored in the database
> can cause data belonging to one tenant to reach a user of another.

Everything below exists to make that sentence testable.

## Trust boundaries

```
  user  ──►  login  ──►  SecurityContext  ──►  tools  ──►  connection  ──►  data
             (L1)         immutable           (L1)        (L2, L3)
                             │                  ▲
                             │                  │
                             └──► prompt ──► MODEL ──┘
                                          (untrusted)
```

The model sits inside the request path and outside the trust boundary. It
chooses *what* to ask for; it has no means of choosing *whose*.

Also outside the boundary: the `notes` column. It is free text written by
people, some of it written specifically to be read by a model, and it is
treated as data everywhere it is used.

## Actors

| Actor | Capability | Assumed hostile |
| --- | --- | --- |
| Authenticated user | Arbitrary chat input, any tool the agent exposes | Yes |
| Language model | Arbitrary tool calls and SQL, within the declared schemas | Yes |
| Stored content (`notes`) | Arbitrary text placed in front of the model | Yes |
| Operator of the host | Full filesystem and database access | No — out of scope |

The third row is the one most designs omit. An attacker who can get text into
the database can address the model directly, and the victim is whoever asks the
next question.

## Attacks, and what stops them

| # | Attack | Stopped by | Evidence |
| --- | --- | --- | --- |
| 1 | Ask for another tenant's data outright | L2: the view has no other rows | `direct-*` attacks |
| 2 | `... WHERE 1=1 OR tenant_id IS NOT NULL` | L2: there is no predicate to escape | `test_predicate_tricks_cannot_widen_the_slice` |
| 3 | Query `employees_all` directly | L3: authorizer denies reads not coming from the view | `test_authorizer_blocks_escape_attempts` |
| 4 | `UNION` the view with the base table | L4 rejects the table; L3 would refuse it anyway | `sql-union` |
| 5 | Stack a second statement after `;` | L4: one statement per call; sqlite3 refuses too | `sql-stacked` |
| 6 | Comment out an appended filter | L4 validates the AST, where comments do not exist | `test_comments_cannot_disguise_the_rewrite` |
| 7 | `ATTACH` a second database to write into | L3: action denied | `sql-attach` |
| 8 | Read the filesystem via a SQL function | L3 + L4 function allowlists | `sql-readfile` |
| 9 | Enumerate the schema via `sqlite_master` | L3: out-of-scope object | `sql-schema` |
| 10 | Claim administrator authority in chat | L1: no tool accepts a tenant, so authority buys nothing | `jb-admin` |
| 11 | Instructions planted in `notes` | L1, plus fencing so the model reports rather than obeys | `indirect-*` |
| 12 | Reach the data through retrieval instead of SQL | Per-tenant indexes: foreign notes are not in the index | `tool-search-other` |
| 13 | Infer foreign figures from aggregates | L2 — aggregates are computed over the tenant's rows only | `infer-*` |
| 14 | Anomaly thresholds computed over everyone | Peer groups are tenant-local | `test_outliers_are_judged_against_the_caller_s_own_peers` |
| 15 | A bug in any single layer above | L5 refuses result sets carrying foreign ids | `test_a_single_foreign_row_aborts_the_result_set` |

## Explicitly out of scope

Named because an unstated exclusion is indistinguishable from an oversight.

- **Statistical inference within a tenant.** A user may narrow aggregates over
  their own data until an individual's salary is recoverable. That is a
  legitimate question about their own records under this model; if it were not,
  the answer would be query-set-size limits or differential privacy.
- **Host compromise.** Anyone with the database file has everything. This
  design protects tenants from each other, not from the operator.
- **Denial of service.** Row caps and a step limit bound a single request; there
  is no rate limiting, and a user can keep the model busy.
- **Model supply chain.** Weights cannot be audited for backdoors. Local
  inference removes the data-residency concern, not this one.
- **Transport and session security.** The app's session handling (a signed
  cookie) and TLS termination are deployment concerns and are not addressed here.
- **Multi-user audit integrity.** The audit log is a file the application can
  rewrite. A real deployment needs an append-only sink it cannot.

## Assumptions

1. `SecurityContext` is constructed only by `secure_rls/auth.py`, from a
   verified login. Nothing else in the codebase constructs one from user input.
2. The tenant allowlist in `context.py` is complete and closed. The tenant id
   is interpolated into the view definition, so this is load-bearing —
   `test_unknown_tenants_are_refused_at_construction` pins it.
3. SQLite's authorizer behaves as documented, in particular that reads
   performed while expanding a view carry the view's name. This is verified
   empirically by the isolation tests rather than taken on faith.
4. Tools are constructed per request by `build_tools`, closing over one
   context. A cached tool bound to the wrong context would defeat L1; the UI
   caches on the tenant as part of the key.

## What would change at scale

The design maps onto Postgres row-level security almost directly: the temporary
view becomes a `CREATE POLICY`, and the authorizer's job is done by the database
role. Layers L4 and L5 stay as they are. The per-tenant vector indexes become a
per-tenant namespace in a store that enforces it server-side — same idea, moved
down a layer, for the same reason.
