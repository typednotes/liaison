# liaison — agent notes

`liaison` is a v0, minimal-but-real implementation of the delegation broker
described in `typednotes/typednotes`'s `docs/services/broker.md` and
`docs/services/ledger.md`: verify a macaroon-style warrant, enforce a credit
hold, make (or refuse) one outbound call, record the attempt. It is built on
`linen` (pinned `v1.0.0`).

## Layout

- `Liaison/Warrant/Caveat.lean` — the `Caveat` inductive and `permits`
  (ported from `broker.md` §4 near-verbatim).
- `Liaison/Warrant/Core.lean` — `Warrant`, `attenuate`, `attenuate_monotone`.
- `Liaison/Warrant/Tag.lean` — the HMAC-SHA256 tag chain (`mintTag`,
  `recomputeTag`, `verifyTag`). **Deviation from `broker.md`:** `orgId` is
  folded into `s₀` alongside the warrant id (`mintingInput`), so a warrant
  cannot be re-attached to a different org without invalidating its tag.
  `broker.md` does not fold `orgId` into the tag at all. Documented here and
  in the module's own doc comment.
- `Liaison/Auth.lean` — `Authorized`, `authorize` (verify tag, then check
  `permits`, in that order — an unverified warrant's caveats are not
  trustworthy input).
- `Liaison/Budget.lean` — `Reserved`, `withReservation`, and the credit-hold
  SQL (ported from `ledger.md` §7's atomic conditional-insert pattern).
- `Liaison/Egress/Secrets.lean` — `typednotes/secrets` HTTP client
  (`SecretsConfig`, `fetchCredential`, `Credential`).
- `Liaison/Egress/Provider.lean` — `callProvider` (generic HTTP egress) and
  `callInference` (a loud, structured-denial stub — see below).
- `Liaison/Audit.lean` — `recordAttempt`, writing to `audit_log`.
- `Liaison/Server.lean` — the HTTP wire format: parses a warrant + request
  off the wire, calls `authorize` → `withReservation` → `callProvider`/
  `callInference`, records the attempt, shapes the response.
- `Main.lean` — reads `LIAISON_ROOT_KEY`, `DATABASE_URL`,
  `SECRETS_HOST`/`SECRETS_PORT`/`SECRETS_INSECURE`/`SECRETS_TOKEN`,
  `LIAISON_PORT` (default `8080`), then serves `Liaison.application`.

## Running tests

```
LIAISON_ROOT_KEY=$(openssl rand -hex 32) lake build LiaisonTests
```

The env var is required: `RootKey`'s only constructor is `RootKey.fromEnv`,
and Lean has no `setenv` — an env-sourced value cannot be driven end to end
from *inside* a `#eval` (the same limitation `linen`'s own
`Tests/Linen/Cloud/CredentialsTest.lean` documents). `LiaisonTests/Liaison/Warrant/TagTest.lean`
and `LiaisonTests/Liaison/AuthTest.lean` are the two files that need it; every
other test file is pure `#guard`s or signature-pinning `example`s and builds
without it.

`lake build` (no target) builds everything, including the `liaison`
executable, and does not require the env var (the executable itself only
calls `RootKey.fromEnv` at process start, not at build time).

## Not yet implemented (named gaps, not silent omissions)

Everything below is a deliberate v0 scope cut, not an oversight:

- **Phase 2, out of scope entirely for v0**: rate limiter, circuit breaker,
  OpenTelemetry tracing/metrics, human-in-the-loop (HITL) policy, warrant
  revocation checking, per-provider inference request shaping
  (`Liaison/Egress/Inference/*.lean` — Baseten/Mistral/Scaleway-specific).
- **`Liaison.Egress.callInference`** (`Liaison/Egress/Provider.lean:59`) is a
  loud, structured-denial stub: it always returns
  `.error .inferenceNotImplemented`, never a silent success, never
  `sorry`/`panic!`. Inference routing (`broker.md` §8) is unimplemented.
- **No live-database test coverage.** Every SQL statement in
  `Liaison/Budget.lean` and `Liaison/Audit.lean` is pinned as literal `#guard`
  text (`LiaisonTests/Liaison/BudgetTest.lean`,
  `LiaisonTests/Liaison/AuditTest.lean`), but none of it has been exercised
  against a real Postgres connection as part of the automated test suite.
  `Liaison.Budget.Reserved`'s private constructor also means
  `LiaisonTests/Liaison/Egress/ProviderTest.lean`/`LiaisonTests/Liaison/ServerTest.lean`
  cannot construct one to drive `callProvider`/`callInference`/the HTTP
  handler end to end — see those files' own doc comments for the exact gap.
  A scratch-Postgres smoke test is optional future work, not done here.
- **The `secrets` credential JSON shape is a v0 assumption, not confirmed.**
  `Liaison/Egress/Secrets.lean:66-72`: `Credential.token` assumes a single
  `"token"` string field under `"data"`. The route
  (`/v1/secret/data/thirdparty/{provider}/{account}`), the `/v1/` prefix, the
  `Authorization: Bearer` header, and the top-level `"data"` envelope were
  confirmed by reading `secrets-server`'s own source
  (`crates/secrets-server/src/handlers.rs`,
  `crates/secrets-server/tests/integration.rs`); the exact fields *inside*
  `"data"` for a thirdparty OAuth credential were not.
- **`callProvider` charges the warrant's full authorized cost regardless of
  actual usage** (`Liaison/Egress/Provider.lean:47-51`) — there is no
  per-call cost model for generic HTTP egress (unlike inference, there is no
  token count to meter on).
- **`Liaison.Budget.withReservation`'s `actual ≤ h.amount` inequality is not
  re-checked** (`Liaison/Budget.lean:144-146`) — `ledger.md` §5's
  `Settlement` witness is not enforced here; a callback could in principle
  report an `actual` cost exceeding the hold and it would be recorded as-is.
- **`Denial` does not distinguish infra failure from a real denial**
  (`Liaison/Budget.lean:105-111`): `reserveHold` returns
  `.error .budgetUnavailable` both when the balance is insufficient and when
  the Postgres call itself failed. No separate `Denial` variant exists for
  "the database is down."
- **`authorize` never cross-checks `Request.orgId` against `Warrant.orgId`**
  (`Liaison/Auth.lean:39-47`) — a request's own `orgId` field is not compared
  against the warrant's. In v0 the only caller (`Server.lean`) always derives
  both from the same wire payload, but nothing in the type system enforces
  agreement between them if that changes.
- **The v0 wire format (`Liaison/Server.lean`) is a placeholder design**, not
  a reviewed/versioned API — every parsing/response-shaping function in that
  file is `private`, deliberately, so nothing downstream is tempted to reuse
  a half-trusted parser; a real end-to-end HTTP smoke test of it has not been
  run as part of this implementation (would require a live Postgres pool and
  a running `Main`; not exercised — see `LiaisonTests/Liaison/ServerTest.lean`'s
  doc comment).

## Deviations from the plan/docs, and why

- **`Tag.lean` folds `orgId` into the root HMAC input** (`s₀ = HMAC(rootKey,
  id⧺orgId)`), which `broker.md`'s tag chain does not do. This is a
  deliberate hardening: without it, a warrant's tag would still verify after
  changing its `orgId` in transit, since `orgId` never entered the HMAC input
  at all. Pinned by `LiaisonTests/Liaison/Warrant/TagTest.lean`'s "Tamper 3"
  case.
