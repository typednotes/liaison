<p align="center">
  <img src="logo.svg" alt="liaison" width="180">
</p>

<h1 align="center">liaison</h1>

<p align="center">
  <em>A small delegation broker in Lean 4: verify a warrant, hold the credit, make one call, record it.</em>
</p>

<p align="center">
  <a href="https://github.com/typednotes/liaison/actions/workflows/lean_action_ci.yml"><img src="https://github.com/typednotes/liaison/actions/workflows/lean_action_ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/typednotes/liaison/actions/workflows/docker-publish.yml"><img src="https://github.com/typednotes/liaison/actions/workflows/docker-publish.yml/badge.svg" alt="Docker publish"></a>
  <a href="https://github.com/typednotes/liaison/pkgs/container/liaison"><img src="https://img.shields.io/badge/ghcr.io-typednotes%2Fliaison-blue?logo=docker" alt="Docker image"></a>
  <a href="https://github.com/typednotes/liaison/tags"><img src="https://img.shields.io/github/v/tag/typednotes/liaison?label=version&sort=semver" alt="Version"></a>
  <a href="https://lean-lang.org/"><img src="https://img.shields.io/badge/Lean-v4.34.0-blue" alt="Lean v4.34.0"></a>
  <a href="https://github.com/typednotes/linen"><img src="https://img.shields.io/badge/built%20on-linen%20v1.2.0-c9b896" alt="Built on linen v1.2.0"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

---

`liaison` is the single egress chokepoint through which delegated work reaches
third-party providers. Each request carries a macaroon-style **warrant**;
liaison verifies it, places a **credit hold**, makes (or refuses) exactly
**one outbound call** with the stored credential, and **records the attempt**.
It implements the service described in
[`typednotes/typednotes`](https://github.com/typednotes/typednotes)'s
`docs/services/broker.md` and `docs/services/ledger.md`, and is built on
[`linen`](https://github.com/typednotes/linen).

## Table of contents

- [Features](#features)
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
- **Typed credentials** — `bearer`, `header`, Google/Dropbox/GitLab OAuth
  (with refresh and vault write-back), AWS S3 (SigV4) and Azure SAS, fetched
  from [`typednotes/secrets`](https://github.com/typednotes/secrets).
- **Request confinement** — URLs pinned to the credential's `base_url`,
  sensitive and framing headers refused, SAS parameters reserved.
- **Audit** — every attempt, allowed or refused, writes exactly one
  `audit_log` row.
- **A pure wire module** — `Liaison.Wire` is both the format the server parses
  and the Lean SDK clients import, without linking any HMAC, Postgres or
  egress code.

## Quick start

### Build

```sh
lake build
```

### Test

```sh
LIAISON_ROOT_KEY=$(openssl rand -hex 32) lake build LiaisonTests
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
| `LIAISON_PORT` | no | default `8080` |

## HTTP API

- `GET /_health` → `200 ok` (liveness only).
- `POST /v0/egress` — the one egress chokepoint. The wire format is
  [`Liaison/Wire.lean`](Liaison/Wire.lean), which Lean clients import (see
  [Lean clients](#lean-clients)); the cross-service contract is
  `typednotes/typednotes`'s `docs/connections.md` §5. The `call` object:

```jsonc
"call": {
  "kind": "provider",
  "account": "{user_id}/{connection_id}",   // last segment must equal "resource"
  "method": "GET",                          // uppercase letters only
  "url": "https://api.github.com/user",     // base_url, base_url/…, or base_url?…
  "headers": {"accept": "application/json"},  // optional, string → string
  "body": "…"                               // optional, UTF-8 text
}
```

On success the response is `200` with `{"status", "headers", "body": <hex>}`
relaying whatever the provider answered. Every attempt writes exactly one
`audit_log` row whose `outcome` is `ok` or the denial's `error` code:

| `error` | HTTP | When |
|---|---|---|
| `malformed_warrant` | 400 | unparsable body (including a `u64` field outside `[0, 2^64)`), bad `method`, `account` not `a/b` of `[A-Za-z0-9_-]` or its last segment ≠ `resource` |
| `tag_invalid`, `capability_denied`, `resource_denied`, `wrong_run`, `expired`, `budget_exceeded` | 403 | warrant checks |
| `budget_unavailable` | 402 | no hold could be placed (or the hold lifecycle's Postgres calls failed) |
| `header_denied` | 400 | a caller header is `authorization`, `proxy-authorization`, `x-api-key`, `host`, `content-length`, `cookie`, `transfer-encoding`, `connection`, any `x-amz-*`, a header the credential sets, or malformed |
| `url_denied` | 403 | URL not `base_url`, under `base_url + "/"`, or `base_url + "?"`; or unparsable, with userinfo, a fragment or a dot segment; or, for `azure_sas`, a query key that is a SAS parameter |
| `credential_unavailable` | 502 | no credential, unknown `kind`, malformed credential, vault failure, OAuth refresh failed/impossible |
| `upstream_failed` | 502 | the provider could not be reached |
| `inference_not_implemented` | 501 | `{"kind": "inference"}` (stub) |

## Lean clients

`Liaison.Wire` is the format the server parses, and the module a Lean client
imports to speak it (pure; it links none of liaison's HMAC, Postgres or egress
code):

```lean
require liaison from git "https://github.com/typednotes/liaison" @ "v0.5.1"
```

```lean
import Liaison.Wire
open Liaison.Wire

-- `warrant ← decodeWarrant v` (v : Data.Json.Value, as the app handed it out), then per call:
let body ← Body.provider warrant now 0
  { account := "{user_id}/{connection_id}", method := "GET", url := "https://api.github.com/user" }
-- POST body.encode to /v0/egress, then:
match ← decodeReply httpStatus responseText with
| .relayed r => … r.status, r.header? "location", r.body …
| .refused status code => … Liaison.Denial.ofCode? code …
```

`Body.provider` reads provider, action, resource, run and org off the
warrant's caveats (`Request.ofWarrant`), so the request cannot disagree with
the warrant, and refuses an `account` that does not name the warrant's
resource.

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

`liaison` is at **v0**: minimal but real. Deliberately out of scope for now —
rate limiting, circuit breaking, OpenTelemetry, human-in-the-loop policy,
warrant revocation and inference routing (`{"kind": "inference"}` is a loud,
structured-denial stub). See [`AGENTS.md`](AGENTS.md) for the module layout,
the full list of named gaps, and every deliberate deviation from the design
docs.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
