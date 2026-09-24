# liaison

A small delegation broker: verify a macaroon-style warrant, enforce a credit
hold, make (or refuse) one outbound call, record the attempt. v0 of the
service described in `typednotes/typednotes`'s `docs/services/broker.md` and
`docs/services/ledger.md`. Built on [`linen`](https://github.com/typednotes/linen).

See [`AGENTS.md`](./AGENTS.md) for the module layout, test-running
instructions, and the full list of what v0 deliberately does not implement.

## Building

```
lake build
```

## Testing

```
LIAISON_ROOT_KEY=$(openssl rand -hex 32) lake build LiaisonTests
```

## Running

```
LIAISON_ROOT_KEY=... DATABASE_URL=... SECRETS_HOST=... \
  SECRETS_USERNAME=liaison SECRETS_PASSWORD=... \
  GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
  lake exe liaison
```

### Environment

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
| `LIAISON_PORT` | no | default `8080` |

## API

- `GET /_health` → `200 ok` (liveness only).
- `POST /v0/egress` — the one egress chokepoint (the wire format is in
  `Liaison/Server.lean`'s header; the cross-service contract is
  `typednotes/typednotes`'s `docs/connections.md` §5). The `call` object:

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
| `malformed_warrant` | 400 | unparsable body, bad `method`, `account` not `a/b` of `[A-Za-z0-9_-]` or its last segment ≠ `resource` |
| `tag_invalid`, `capability_denied`, `resource_denied`, `wrong_run`, `expired`, `budget_exceeded` | 403 | warrant checks |
| `budget_unavailable` | 402 | no hold could be placed (or the hold lifecycle's Postgres calls failed) |
| `header_denied` | 400 | a caller header is `authorization`, `proxy-authorization`, `x-api-key`, `host`, `content-length`, `cookie`, `transfer-encoding`, `connection`, any `x-amz-*`, a header the credential sets, or malformed |
| `url_denied` | 403 | URL not `base_url`, under `base_url + "/"`, or `base_url + "?"`; or unparsable, with userinfo, a fragment or a dot segment |
| `credential_unavailable` | 502 | no credential, unknown `kind`, malformed credential, vault failure, Google refresh failed/impossible |
| `upstream_failed` | 502 | the provider could not be reached |
| `inference_not_implemented` | 501 | `{"kind": "inference"}` (stub) |

### Credentials

Read from `secret/data/thirdparty/{provider}/{account}`; the `data` object is
one of (every value a JSON string; optional `headers`: static headers added to
every call):

| `kind` | Fields | Authentication |
|---|---|---|
| `bearer` | `base_url`, `token` | `Authorization: Bearer {token}` |
| `header` | `base_url`, `header`, `token` | `{header}: {token}` |
| `google_oauth` | `base_url`, `access_token`, `refresh_token`, `expires_at` (Unix s) | `Authorization: Bearer {access_token}`; refreshed at `https://oauth2.googleapis.com/token` when `expires_at - 60 ≤ now` (liaison's wall clock), then written back to the vault (best-effort) |
| `s3` | `base_url`, `region`, `access_key_id`, `secret_access_key` | AWS SigV4, service `s3`, payload hash = SHA-256 of the body, signed headers `host;x-amz-content-sha256;x-amz-date` |

## Schema

`liaison` owns one table, `audit_log` (`sql/0001_audit_log.sql`), and writes
`ledger`'s `credit_holds`/`credit_ledger`. It never migrates at startup: in
production `typednotes-infra` reads `sql/*.sql` at the release tag and
applies it as a declared migration history before the container rolls out
(the container also waits for `ledger`'s history, whose tables it writes). For a local database, apply the
app's, then `ledger`'s, then `sql/*.sql` here, in that order.

## Docker usage

Local image builds use [`podman`](https://podman.io/), not `docker`:

```
podman build -t liaison .
podman run --rm -p 8080:8080 \
  -e LIAISON_ROOT_KEY=... -e DATABASE_URL=... \
  -e SECRETS_HOST=... -e SECRETS_USERNAME=liaison -e SECRETS_PASSWORD=... \
  liaison
```

The GitHub Actions publish workflow (`.github/workflows/docker-publish.yml`)
runs on GitHub-hosted runners and uses the standard `docker/*-action` steps —
that is unrelated to local dev tooling and unaffected by the above.
