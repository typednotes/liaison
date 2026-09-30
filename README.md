<p align="center">
  <img src="logo.svg" alt="liaison" width="180">
</p>

<h1 align="center">liaison</h1>

<p align="center">
  <em>A delegation broker in Lean 4: verify a warrant, hold the credit, execute a scoped native operation, record it — with authority and local spend bounds carried in the types.</em>
</p>

<p align="center">
  <a href="https://github.com/typednotes/liaison/actions/workflows/lean_action_ci.yml"><img src="https://github.com/typednotes/liaison/actions/workflows/lean_action_ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/typednotes/liaison/actions/workflows/docker-publish.yml"><img src="https://github.com/typednotes/liaison/actions/workflows/docker-publish.yml/badge.svg" alt="Docker publish"></a>
  <a href="https://github.com/typednotes/liaison/pkgs/container/liaison"><img src="https://img.shields.io/badge/ghcr.io-typednotes%2Fliaison-blue?logo=docker" alt="Docker image"></a>
  <a href="https://github.com/typednotes/liaison/tags"><img src="https://img.shields.io/github/v/tag/typednotes/liaison?label=version&sort=semver" alt="Version"></a>
  <a href="https://lean-lang.org/"><img src="https://img.shields.io/badge/Lean-v4.34.0-blue" alt="Lean v4.34.0"></a>
  <a href="https://github.com/typednotes/linen"><img src="https://img.shields.io/badge/built%20on-linen%20v1.10.0-c9b896" alt="Built on linen v1.10.0"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

---

`liaison` is the single egress chokepoint through which delegated work reaches
third-party providers. Each request carries a macaroon-style **warrant**;
liaison verifies it, places a **credit hold**, executes (or refuses) a scoped
**native operation** with the stored credential, and **records the attempt**.
Native operations can include bounded relationship preflights.
It implements the service described in
[`typednotes/typednotes`](https://github.com/typednotes/typednotes)'s
`docs/services/broker.md` and `docs/services/ledger.md`, and is built on
[`linen`](https://github.com/typednotes/linen).

The coordinated release line is **Liaison 0.6.0 / Linen 1.10.0**, verified with
Lode/Lun 0.3.0 and Typednotes 0.6.0. Release versions, dependency pins and tags are
managed together by the release owner.

> Lean checks authority and local bounds. HMAC verifies warrants; Postgres
> implements hold transitions. Concurrent spend isolation remains a separate
> ledger concern (see [Guarantees](#guarantees)).

## Table of contents

- [Features](#features)
- [Role](#role)
- [Guarantees](#guarantees)
- [How a call flows](#how-a-call-flows)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [HTTP API](#http-api)
- [Lean clients](#lean-clients)
- [Credentials](#credentials)
- [Database schema](#database-schema)
- [Docker](#docker)
- [Project status](#project-status)
- [License](#license)

## Features

- **Warrants** — HMAC-SHA256 tag chains with attenuating caveats (provider,
  action, resource, run, expiry, budget); the tag is verified before any
  caveat is trusted.
- **Credit holds** — an atomic conditional insert against `ledger`'s
  `credit_holds`/`credit_ledger`, settled or released around the call.
- **Typed credentials** — `bearer`, `header`, Google/Dropbox/GitLab/Microsoft OAuth
  (with refresh and vault write-back), AWS S3 (SigV4) and Azure SAS, fetched
  from [`typednotes/secrets`](https://github.com/typednotes/secrets).
- **Request confinement** — native transport derived inside the broker,
  confined to the stored base or a fixed provider-owned origin mapping;
  sensitive/framing headers and SAS parameters remain protected.
- **Rich connector scopes** — named operations, structured selectors, and
  organization/connection/cell/warrant intersections, with private prepared
  execution witnesses. See [the native connector contract](docs/connector-permissions.md)
  for coverage, payloads, independent hot policies and revocable run projections.
- **Native writer protocols** — bounded context, local function tools and replay
  for Messages/Chat/Responses/Gemini/Pi, plus authenticated repository checkout
  and atomic scoped publication. See [the writer contract](docs/native-writer.md).
- **Audit** — every attempt, allowed or refused, writes exactly one
  `audit_log` row.
- **A pure wire module** — `Liaison.Wire` is both the format the server parses
  and the Lean SDK clients import, without linking any HMAC, Postgres or
  egress code.
- **Kernel-checked authority evidence** — attenuation, four-ceiling resource
  membership, secondary selectors, function allowlists, payload-indexed
  publication and settlement bounds are carried in types/proofs consumed by
  execution. Integration tests check parsing and native correspondence in
  addition to those proofs; see [Guarantees](#guarantees).
- **Hot revocation** — each native call reloads independent organization,
  connection and warrant-keyed run documents. Closed ceilings or deleted run
  projections deny subsequent calls even while the token's HMAC still verifies.

## Role

In `typednotes`, delegated work (an agent run, a tool, a sub-tool) never holds
a provider credential and never talks to a provider directly. It holds a
**warrant** — a bearer token that says *what* it may do (provider, action,
resource), *for which run*, *until when*, and *up to what cost* — and asks
`liaison` to make the call on its behalf. `liaison` is therefore the one place
where three things meet:

| | Owned by | `liaison`'s part |
|---|---|---|
| **Authority** — may this caller do this? | the app, which mints warrants | verifies the HMAC chain against `LIAISON_ROOT_KEY`, then checks every caveat against the exact request |
| **Spend** — can the org afford it? | [`ledger`](https://github.com/typednotes/ledger), which owns `credit_ledger`/`credit_holds` | places, settles and releases the hold on the request path, directly in Postgres |
| **Credentials** — how do we authenticate upstream? | [`secrets`](https://github.com/typednotes/secrets), the vault | fetches, refreshes and writes back the credential; the caller never sees it |

### The division of labour with `ledger`

`ledger` is the record of what an org may spend, what is reserved and what
was spent; `liaison` is the component that *spends*. They share tables, not
an API:

1. **Reserve** — before any outbound call, `liaison` inserts a `held` row in
   `credit_holds` for the request's cost, *only if* `balance − held ≥ cost`
   (one conditional `insert … select … where`, the statement `ledger` defines
   in `Ledger/Sql/Reserve.lean`). No row, no call: the request is refused
   with `budget_unavailable`.
2. **Settle** — on success, in one transaction, the hold becomes `settled`
   and a negative `usage` row is appended to `credit_ledger`.
3. **Release** — on a refusal or an exception after the hold was placed, the
   hold becomes `released` and nothing is charged.
4. **Expire** — if `liaison` dies mid-call, the hold's 15-minute
   `expires_at` passes and `ledger`'s sweeper releases it. A crash can delay
   credit, never lose it.

`ledger` owns the schema and its migrations; `liaison` owns only `audit_log`.
`liaison` never migrates either: `typednotes-infra` applies `ledger`'s history
before `liaison`'s (see [Database schema](#database-schema)).

## Guarantees

Lean's kernel checks the local authority and arithmetic proofs; private
constructors ensure execution consumes the validated witnesses. HMAC verification,
vault ownership/ACLs, database behavior, native transport and remote provider
semantics are explicit trusted boundaries. Tests supplement the proofs by
checking their correspondence to parsers, HTTP, SQL and actual local Git.

| Guarantee | Held by | Where |
|---|---|---|
| No native outbound call without verified, explicitly bound authority | types: private `Authorized r` carries `VerifiedTag w`, `w.permits r`, organization equality and required execution bindings; HTTP expiry uses the broker clock | [`Liaison/Auth.lean`](Liaison/Auth.lean), [`Liaison/Server.lean`](Liaison/Server.lean) |
| No native outbound call without a reserved credit hold | types: private `Reserved r` is constructed through `withReservation` and consumed by `callConnector` and its credentialed native programs; SQL availability is a trusted runtime condition | [`Liaison/Budget.lean`](Liaison/Budget.lean), [`Liaison/Egress/Provider.lean`](Liaison/Egress/Provider.lean) |
| Resource and byte authority is the four-ceiling intersection | types/proofs: private `Prepared`, `AuthorizedResource`, recursive attenuation and secondary-selector evidence; `Resolved` retains ordinary-adapter origin/method/account/body checks | [`Liaison/Egress/Connector.lean`](Liaison/Egress/Connector.lean), [`Provider.lean`](Liaison/Egress/Provider.lean) |
| Local function replay and publication cannot substitute unvalidated selectors | types/proofs: `Prepared.function_allowed`, matched replay validation and payload-indexed private `AuthorizedPlan` consumed by publication | [`Liaison/Egress/Inference.lean`](Liaison/Egress/Inference.lean), [`Repository.lean`](Liaison/Egress/Repository.lean) |
| Settlement does not exceed the reservation | private `BoundedUsage` carries `actual ≤ r.cost` into `settleReserved` | [`Liaison/Budget.lean`](Liaison/Budget.lean) |
| Attenuating a warrant can only narrow it, never widen it | theorem `Warrant.attenuate_monotone` | [`Liaison/Warrant/Core.lean`](Liaison/Warrant/Core.lean) |
| A warrant cannot be forged, have its caveats altered, or be moved to another org without the root key | HMAC-SHA256 chain over every caveat; `orgId` folded into the first link (`s₀ = HMAC(key, id ⧺ orgId)`); tag, spliced-caveat and org-swap tampering pinned in `TagTest` | [`Liaison/Warrant/Tag.lean`](Liaison/Warrant/Tag.lean) |
| The root key comes from the environment, never from code | types: `RootKey` has a private constructor; the only route in is `RootKey.fromEnv` | [`Liaison/Warrant/Tag.lean`](Liaison/Warrant/Tag.lean) |
| A client's request cannot disagree with its warrant | theorem `Request.ofWarrant_unique` | [`Liaison/Wire.lean`](Liaison/Wire.lean) |
| A client can decode every refusal code liaison sends | theorem `Denial.ofCode?_code` | [`Liaison/Warrant/Caveat.lean`](Liaison/Warrant/Caveat.lean) |
| A reservation checks balance and held amounts in one database statement | Postgres: conditional `insert … select … where balance − held ≥ amount`; this alone does not isolate concurrent reservations, see below | [`Liaison/Budget.lean`](Liaison/Budget.lean) |
| Every hold is settled or released, including when the call throws | code: `withReservation` brackets the callback (`try`/`catch`, release on any exception); a crash is covered by `expires_at` and `ledger`'s sweeper | [`Liaison/Budget.lean`](Liaison/Budget.lean) |
| A hold leaves `held` at most once, and never comes back | Postgres: every transition is `update … where state = 'held'` | [`Liaison/Budget.lean`](Liaison/Budget.lean) |
| A settled hold and its usage row commit together or not at all | Postgres: the state change and the `credit_ledger` insert are one transaction | [`Liaison/Budget.lean`](Liaison/Budget.lean) |
| The broker never serializes credentials into replies or audit | private credential use, no credential `Repr`/`ToString`, no caller-selected transport/auth; fixed Dropbox and GitLab origin mappings are broker-owned. Provider behavior remains trusted | [`Liaison/Egress/Policy.lean`](Liaison/Egress/Policy.lean), [`Credential.lean`](Liaison/Egress/Credential.lean), [`Provider.lean`](Liaison/Egress/Provider.lean) |
| Every attempt, allowed or refused, writes exactly one audit row, or the request fails loudly | code: one call site per outcome in `handleEgress`; `recordAttempt` throws rather than drop a row | [`Liaison/Server.lean`](Liaison/Server.lean), [`Liaison/Audit.lean`](Liaison/Audit.lean) |
| liaison issues exactly the SQL `ledger` and the schema expect | test: every statement's text is pinned | [`LiaisonTest/Liaison/BudgetTest.lean`](LiaisonTest/Liaison/BudgetTest.lean), [`AuditTest.lean`](LiaisonTest/Liaison/AuditTest.lean) |
| The wire format does not drift | test: the literal body is pinned (`golden`), plus `decode ∘ encode` | [`LiaisonTest/Liaison/WireTest.lean`](LiaisonTest/Liaison/WireTest.lean) |

> **⚠ Known gap — the reserve race** (shared with `ledger`). A single
> statement is atomic but not isolated from a concurrent one: under
> Postgres's default `READ COMMITTED`, two concurrent reserves for the same
> org each evaluate `balance − held` without the other's uncommitted hold, so
> both can succeed and together overspend. `liaison` does not set the
> isolation level. The fix (e.g. a per-org `pg_advisory_xact_lock`) changes a
> contract shared with `ledger` and is tracked there.

### Revocation and trusted boundaries

The app closes organization/connection ceilings and removes tracked run
projections before acknowledging policy or declaration changes. The broker
reloads those documents on every call; missing mandatory organization/run
documents deny access. A valid, unexpired token therefore cannot restore revoked
authority. In-flight requests retain their already-fetched snapshot.

This is **policy/projection revocation**, not a per-token blacklist: there is no
independent deny-list for otherwise valid warrant IDs/tags, and expiry does not
cancel work already authorized in flight.

The following limits remain explicit:

- **No Lean theorem states no-double-spend.** Lean cannot see two containers;
  that is the reserve statement's job, with the caveat above.
- **Tag comparison uses `Crypto.ConstantTime.eq`**, not plain `==`. Correctness
  is tested; compiled machine-code timing behavior is not a Lean theorem.
- **Cost is declared, not metered**: a successful native operation is charged
  the request's full `cost` (capped by the warrant's `budget` caveat).
  `BoundedUsage` carries `actual ≤ hold` into the settlement path.
- **A database outage looks like an empty budget**: both are
  `budget_unavailable`.
- **The optional local integration suite executes real HTTP/Postgres** with
  disposable vault/upstream fixtures, including native SigV4/SAS. Paid provider
  conformance and live OAuth refresh are not tested.

The full list of named gaps is in [`AGENTS.md`](AGENTS.md).

## How a call flows

```
caller ──POST /v0/egress──▶ liaison
                              1. decode           Liaison.Wire      → malformed_warrant
                              2. authorize        HMAC, caveats     → tag_invalid, expired, …
                              3. pre-check        account, operation → capability_denied
                              4. reserve  ───────▶ credit_holds     → budget_unavailable
                              5. hot authority ──▶ organization, connection, run documents
                              6. prepare          scoped selectors, payload/context/tools, byte bounds
                              7. native program ─▶ credential + refresh, bounded preflights/effects
                              8. settle  ────────▶ credit_holds + credit_ledger
                              9. audit   ────────▶ audit_log         (every path, exactly once)
caller ◀── 200 {status, headers, body} or {error} ─┘
```

## Quick start

### Build

```sh
lake build            # the Liaison library and the `liaison` executable
```

Requires the Lean toolchain in [`lean-toolchain`](lean-toolchain) (via
[elan](https://github.com/leanprover/elan)), plus `libpq`, `pkg-config` and
OpenSSL/zlib headers for `linen`'s native code (`brew install libpq pkg-config
openssl` plus the macOS Command Line Tools SDK; on Debian/Ubuntu, see the
`apt-get` line in [`Dockerfile`](Dockerfile)).

### Test

```sh
LIAISON_ROOT_KEY=$(openssl rand -hex 32) lake test
```

### Run

```sh
LIAISON_ROOT_KEY=... DATABASE_URL=... SECRETS_HOST=... \
  SECRETS_USERNAME=liaison SECRETS_PASSWORD=... \
  GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
  DROPBOX_CLIENT_ID=... DROPBOX_CLIENT_SECRET=... \
  GITLAB_CLIENT_ID=... GITLAB_CLIENT_SECRET=... \
  lake exe liaison
```

## Configuration

| Variable | Required | Notes |
|---|---|---|
| `LIAISON_ROOT_KEY` | yes | hex root key the warrant tag chain is verified with |
| `DATABASE_URL` | yes | Postgres URI (`audit_log`, `ledger`'s `credit_holds`/`credit_ledger`) |
| `SECRETS_HOST` | yes | `typednotes/secrets` host |
| `SECRETS_PORT` | no | default `443` (`80` with `SECRETS_INSECURE=1`) |
| `SECRETS_INSECURE` | no | `1` disables TLS to `secrets` (local dev only) |
| `SECRETS_USERNAME`, `SECRETS_PASSWORD` | one of these… | `userpass` login (`POST /v1/auth/userpass/login`); the token is cached and renewed when < 60 s remain, and once after a `403` |
| `SECRETS_TOKEN` | …or this | static vault token, used only when `SECRETS_USERNAME` is unset. Startup fails if neither is configured |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | no | needed to refresh `google_oauth` credentials; without them a due refresh is `credential_unavailable` |
| `DROPBOX_CLIENT_ID`, `DROPBOX_CLIENT_SECRET` | no | the same, for `dropbox_oauth` (the app's Dropbox app) |
| `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET` | no | the same, for `gitlab_oauth` (the app's gitlab.com OAuth application) |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` | no | refresh `microsoft_oauth` for Outlook and Microsoft Calendar; same Entra Web app as Typednotes, personal + work/school accounts via the fixed common tenant |
| `LIAISON_PORT` | no | default `8080` |

## HTTP API

- `GET /_health` → `200 ok` (liveness only).
- `POST /v0/egress` — the one egress chokepoint. The wire format is
  [`Liaison/Wire.lean`](Liaison/Wire.lean), which Lean clients import (see
  [Lean clients](#lean-clients)); the cross-service contract is
  `typednotes/typednotes`'s `docs/connections.md` §5. The `call` object:

```jsonc
"call": {
  "kind": "connector",
  "account": "{user_id}/{connection_id}",   // last segment must equal "resource"
  "operation": "objects.read",              // signed warrant action
  "resource": ["reports", "invoice.json"],   // within all four ceilings
  "payload": "{}"                          // operation-specific JSON text
}
```

The independent organization and run policies in the
[native connector contract](docs/connector-permissions.md) are required.
Legacy `kind: provider` calls decode for compatibility but are denied.

On success the response is `200` with `{"status", "headers", "body": <hex>}`
relaying whatever the provider answered. Every attempt writes exactly one
`audit_log` row whose `outcome` is `ok` or the denial's `error` code:

| `error` | HTTP | When |
|---|---|---|
| `malformed_warrant` | 400 | invalid wire/scalar/selector/context schema or incomplete execution bindings |
| `tag_invalid`, `capability_denied`, `resource_denied`, `wrong_run`, `expired`, `budget_exceeded` | 403 | warrant, owner/operation, hot-policy, scoped-resource, payload/tool or byte-bound checks |
| `budget_unavailable` | 402 | no hold could be placed (or the hold lifecycle's Postgres calls failed) |
| `header_denied` | 400 | malformed or conflicting native headers, or forbidden headers in a rejected legacy request; native callers cannot select headers |
| `url_denied` | 403 | derived native target fails stored/fixed-provider origin, URI/path or reserved SAS-query checks; native callers cannot select URLs |
| `credential_unavailable` | 502 | no credential, unknown `kind`, malformed credential, vault failure, OAuth refresh failed/impossible |
| `upstream_failed` | 502 | the provider could not be reached |
| `inference_not_implemented` | 501 | `{"kind": "inference"}` (stub) |

## Lean clients

`Liaison.Wire` is the format the server parses, and the module a Lean client
imports to speak it (pure; it links none of liaison's HMAC, Postgres or egress
code):

```lean
require liaison from git "https://github.com/typednotes/liaison" @ "v0.6.0"
```

```lean
import Liaison.Wire
open Liaison.Wire

-- `warrant ← decodeWarrant v` (v : Data.Json.Value, as the app handed it out), then per call:
let body ← Body.connector warrant now 0
  { account := "{user_id}/{connection_id}", operation := "objects.read",
    resource := ["reports", "invoice.json"], payload := "{}" }
-- POST body.encode to /v0/egress, then:
match ← decodeReply httpStatus responseText with
| .relayed r => … r.status, r.header? "location", r.body …
| .refused status code => … Liaison.Denial.ofCode? code …
```

`Body.connector` reads provider, action, resource, run and org off the
warrant's caveats (`Request.ofWarrant`), so the request cannot disagree with
the warrant, and refuses an `account` that does not name the warrant's
resource. It additionally requires the call's named operation to match the
warrant action. The coordinated release uses Linen 1.10.0 and Liaison 0.6.0;
the local override workspace verifies their working trees before release tags.

## Credentials

Read from `secret/data/thirdparty/{provider}/{account}`; the `data` object is
one of (every value a JSON string; optional `headers`: static headers added to
every call):

| `kind` | Fields | Authentication |
|---|---|---|
| `bearer` | `base_url`, `token` | `Authorization: Bearer {token}` |
| `header` | `base_url`, `header`, `token` | `{header}: {token}` |
| `google_oauth` | `base_url`, `access_token`, `refresh_token`, `expires_at` (Unix s) | `Authorization: Bearer {access_token}`; refreshed at `https://oauth2.googleapis.com/token` when `expires_at - 60 ≤ now` (liaison's wall clock), then written back to the vault (best-effort) |
| `dropbox_oauth` | as `google_oauth` | the same, refreshed at `https://api.dropboxapi.com/oauth2/token` |
| `gitlab_oauth` | as `google_oauth` | the same, refreshed at `https://gitlab.com/oauth/token`; GitLab rotates the refresh token on every refresh, so a failed write-back means reconnecting |
| `microsoft_oauth` | as `google_oauth` | the same, refreshed at `https://login.microsoftonline.com/common/oauth2/v2.0/token`; replaces the refresh token when returned |
| `s3` | `base_url`, `region`, `access_key_id`, `secret_access_key` | AWS SigV4, service `s3`, payload hash = SHA-256 of the body, signed headers `host;x-amz-content-sha256;x-amz-date` |
| `azure_sas` | `base_url`, `sas` (a query string of SAS parameters only, with `sv` and `sig`) | the SAS appended to the call's query; the caller's query may not use any SAS parameter name (`url_denied`) |

## Database schema

`liaison` owns one table, `audit_log` ([`sql/0001_audit_log.sql`](sql/0001_audit_log.sql)),
and writes `ledger`'s `credit_holds`/`credit_ledger`. It never migrates at
startup: in production `typednotes-infra` reads `sql/*.sql` at the release tag
and applies it as a declared migration history before the container rolls out
(the container also waits for `ledger`'s history, whose tables it writes). For
a local database, apply the app's, then `ledger`'s, then `sql/*.sql` here, in
that order.

## Docker

Images are published to `ghcr.io/typednotes/liaison` — `edge` from `main`,
and `latest`, `X.Y.Z` and `X.Y` from release tags.

```sh
docker run --rm -p 8080:8080 \
  -e LIAISON_ROOT_KEY=... -e DATABASE_URL=... \
  -e SECRETS_HOST=... -e SECRETS_USERNAME=liaison -e SECRETS_PASSWORD=... \
  ghcr.io/typednotes/liaison:latest
```

To build the image locally:

```sh
docker build -t liaison .
```

## Project status

The **0.6.0 release line** implements native connector permissions, hot-policy/
run-projection revocation, bounded model protocols and atomic scoped repository
publication. The shared catalog covers **54 providers / 165 supported pairs**
with zero unsupported advertised pairs. Coordinated local verification reports
**99 API tests, 24 browser groups, 655 real broker cases and 69 real compiled
runtime cases**, including app-to-writer-to-broker-to-runtime handoffs.

Rate limiting, circuit breaking, OpenTelemetry, human-in-the-loop policy, a
per-token blacklist and usage-based billing remain outside this release. The
deprecated `kind: inference` entry is a refusal; native model routing is
implemented through `kind: connector`. See [`AGENTS.md`](AGENTS.md) and the
contracts for the remaining trusted boundaries and supported-shape restrictions.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
