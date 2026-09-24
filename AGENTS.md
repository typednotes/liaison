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
- `Liaison/Clock.lean` — `nowUnixSeconds`, liaison's own wall clock (via
  `linen`'s `Data.Time.getCurrentTime` → `Std.Time.Timestamp.now`; no FFI).
- `Liaison/Egress/Credential.lean` — the typed credential of
  `typednotes/typednotes`'s `docs/connections.md` §3.3 (`CredentialAuth`:
  `bearer`/`header`/`oauth` (issuer `google`/`dropbox`/`gitlab`)/`s3`/
  `azureSas`; `Credential.parse`, `setHeaderNames`, `refreshed`). No
  `Repr`/`ToString` on credentials, deliberately (`OAuthIssuer` has one: it
  is not secret).
- `Liaison/Egress/Policy.lean` — pure request policy (`connections.md` §5):
  `accountMatchesResource`, `checkCallerHeaders`, `urlWithinBase`/`checkUrl`/
  `parseTarget`, `reservedQueryKeys`/`checkCallerQuery`/`appendQuery` (the
  SAS a credential appends), `needsRefresh`.
- `Liaison/Egress/Secrets.lean` — `typednotes/secrets` HTTP client
  (`SecretsConfig` with `userpass` login + cached token or static token,
  `fetchCredential`, `writeCredential`).
- `Liaison/Egress/OAuth.lean` — refresh for `google_oauth`, `dropbox_oauth`
  and `gitlab_oauth` (`OAuthClients`, one optional client per issuer from
  `{GOOGLE,DROPBOX,GITLAB}_CLIENT_ID`/`_SECRET`; token endpoints fixed per
  issuer; `refreshForm`, `parseTokenResponse`, `refreshToken`).
- `Liaison/Egress/S3.lean` — SigV4 for `s3` credentials over `linen`'s
  `Crypto.SigV4.sign` (`s3Canonical`, `s3AuthHeaders`).
- `Liaison/Egress/Provider.lean` — `EgressConfig`, `callProvider` (generic
  HTTP egress; never throws — every failure is a `Denial`) and
  `callInference` (a loud, structured-denial stub — see below).
- `Liaison/Audit.lean` — `recordAttempt`, writing to `audit_log`.
- `sql/0001_audit_log.sql` — the `audit_log` table, the one table `liaison`
  owns (`credit_holds`/`credit_ledger` are `ledger`'s).
  `typednotes-infra` reads `sql/*.sql` from GitHub at the release tag and
  applies it as an `infra` `postgresMigrations` history; `liaison` itself
  never migrates. Shipped migrations are append-only — add a new
  `sql/NNNN_*.sql` file instead of editing one.
- `Liaison/Server.lean` — the HTTP wire format: parses a warrant + request
  off the wire, calls `authorize` → `withReservation` → `callProvider`/
  `callInference`, records the attempt, shapes the response.
- `Main.lean` — reads `LIAISON_ROOT_KEY`, `DATABASE_URL`,
  `SECRETS_HOST`/`SECRETS_PORT`/`SECRETS_INSECURE`, `SECRETS_USERNAME`+
  `SECRETS_PASSWORD` (or the fallback `SECRETS_TOKEN`), the optional
  `{GOOGLE,DROPBOX,GITLAB}_CLIENT_ID`/`_CLIENT_SECRET`, `LIAISON_PORT`
  (default `8080`),
  then serves `Liaison.application` (`POST /v0/egress`, `GET /_health`).

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
- **`Liaison.Egress.callInference`** (`Liaison/Egress/Provider.lean`) is a
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
  Likewise the vault client (login, 403 retry, write-back), the Google
  refresh round trip and a real SigV4 call against an S3 endpoint are not
  exercised against live services; their pure parts (parsers, policy,
  signatures against AWS's published S3 vectors) are.
  A scratch-Postgres smoke test is optional future work, not done here.
- **`callProvider` charges the warrant's full authorized cost regardless of
  actual usage** (`Liaison/Egress/Provider.lean`, end of `callProvider`) — there is no
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
  "the database is down." The same code is used when an exception escapes
  `withReservation` (a failed settle/release): `Server.lean` catches it and
  audits `budget_unavailable` — even if the provider call itself happened
  (its response is then not returned).
- **`authorize` never cross-checks `Request.orgId` against `Warrant.orgId`**
  (`Liaison/Auth.lean:39-47`) — a request's own `orgId` field is not compared
  against the warrant's. In v0 the only caller (`Server.lean`) always derives
  both from the same wire payload, but nothing in the type system enforces
  agreement between them if that changes.
- **The wire format (`Liaison/Server.lean`)** is now the one
  `connections.md` §5 fixes for requests, but the success envelope (hex
  body) is still liaison's own design. Every parsing function in that file
  is `private` (only `denialStatus` is public, for tests), deliberately, so nothing downstream is tempted to reuse
  a half-trusted parser; a real end-to-end HTTP smoke test of it has not been
  run as part of this implementation (would require a live Postgres pool and
  a running `Main`; not exercised — see `LiaisonTests/Liaison/ServerTest.lean`'s
  doc comment).
- **Warrant expiry still uses the caller's `now`** (`connections.md` §9);
  liaison's own wall clock is used only for Google `expires_at`, the vault
  token's expiry and the SigV4 timestamp.
- **Concurrent OAuth refreshes are not coalesced**: two requests that both
  see a due token both refresh and both write back (last write wins; both
  tokens are valid).
- **S3 requests sign only `host`, `x-amz-content-sha256`, `x-amz-date`**;
  caller headers (e.g. `content-type`) and the credential's static headers
  are sent unsigned, so a static `x-amz-*` header in an `s3` credential would
  be rejected by S3.

## Git

**Never run `git push` in this repo.** Commits are fine when asked for; pushing
is always left to the user to review and do themselves.

## Deviations from the plan/docs, and why

- **`connections.md` §5 caller-header list, extended**: besides the listed
  names, `transfer-encoding` and `connection` are refused
  (`Policy.forbiddenHeaderNames`) — both would let a caller desynchronise the
  framing (`Content-Length`/`Connection: close`) `linen`'s HTTP client writes.
  Malformed header names/values (non-token names, CR/LF in values) are
  `header_denied` too.
- **URL rule, hardened**: besides the string-prefix rule, the URL must parse
  as an RFC 3986 `http(s)` URI with no userinfo, no fragment and no `.`/`..`
  segment (encoded or not), and its scheme/host/port must equal the base's —
  otherwise `url_denied`. A trailing `/` on a stored `base_url` is ignored.
- **OAuth write-back path**: the refreshed credential is written back to
  the path it was read from (`thirdparty/{provider}/{account}`), e.g.
  `thirdparty/gdrive/{account}` for every `google_oauth` credential the app
  writes, `thirdparty/gitlab/{account}` for `gitlab_oauth`.
- **GitLab rotates refresh tokens**: every refresh invalidates the stored
  one, so a failed write-back (or two concurrent refreshes) leaves the
  connection unusable until it is reconnected. Google and Dropbox keep
  theirs.
- **`call.method`** must be uppercase ASCII letters (`malformed_warrant`
  otherwise), so nothing can be injected into the outbound request line.
- **`account`/`resource` mismatch and a statically forbidden header are
  checked after `authorize` and before a hold is placed**; headers the
  credential sets and the URL are checked after the credential is fetched,
  inside the hold (which is then released).

- **`Tag.lean` folds `orgId` into the root HMAC input** (`s₀ = HMAC(rootKey,
  id⧺orgId)`), which `broker.md`'s tag chain does not do. This is a
  deliberate hardening: without it, a warrant's tag would still verify after
  changing its `orgId` in transit, since `orgId` never entered the HMAC input
  at all. Pinned by `LiaisonTests/Liaison/Warrant/TagTest.lean`'s "Tamper 3"
  case.
