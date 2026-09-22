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

Requires `LIAISON_ROOT_KEY`, `DATABASE_URL`, `SECRETS_HOST`, `SECRETS_TOKEN`
(see `Main.lean`):

```
LIAISON_ROOT_KEY=... DATABASE_URL=... SECRETS_HOST=... SECRETS_TOKEN=... \
  lake exe liaison
```

## Docker usage

Local image builds use [`podman`](https://podman.io/), not `docker`:

```
podman build -t liaison .
podman run --rm -p 8080:8080 \
  -e LIAISON_ROOT_KEY=... -e DATABASE_URL=... \
  -e SECRETS_HOST=... -e SECRETS_TOKEN=... \
  liaison
```

The GitHub Actions publish workflow (`.github/workflows/docker-publish.yml`)
runs on GitHub-hosted runners and uses the standard `docker/*-action` steps —
that is unrelated to local dev tooling and unaffected by the above.
