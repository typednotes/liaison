# Liaison v0.6.1

Fixes GitHub's `403 Request forbidden by administrative rules` response caused
by requests without a valid `User-Agent` header.

## Fix and coverage

The common credentialed native HTTP API builder now supplies
`User-Agent: typednotes-liaison` if the existing headers have no nonblank agent.
The private `NativeHeaders` value carries evidence of the fixed default header
or the successful check of an existing agent, and execution consumes that value
when converting the HTTP headers. Explicit provider identities, including the
writer's `typednotes-lode` header for Copilot, are preserved.

This covers GitHub inventory, repository relationship preflights, immutable
tree/blob reads, REST writes and GraphQL atomic publication. The regression peer
returns GitHub's missing-agent 403 and asserts the header on every GitHub API
request. It fails against the previous broker binary and passes against this fix.

Verified: Lean build and test suite; all 655 native broker HTTP cases, including
actual local Git publication; and 10 real app/broker/PostgreSQL integration groups.
Catalog drift remains zero across 54 providers and 165 supported operation/provider
pairs. Credentials, scoped operations, authority ceilings, the wire contract and
SQL migrations are unchanged.

## Publish and deploy

The release owner pushes broker `main` first and waits for **Lean Action CI** on
the exact release commit. Then push `v0.6.1` and wait for **Publish Docker image**.
The broker publisher still uses an immediate main-CI gate, unlike the app's
bounded waiting publisher.

Run the reviewed `typednotes-infra` Apply after the image is published. The fleet
resolves `ghcr.io/typednotes/liaison:latest` to a digest and rolls out changed
content; no fleet code change, app release or migration-history bump is needed.
An infra Apply before publication still selects the old broker image.

After the rollout, retry **Test** on the existing GitHub connection. Reconnecting
or changing the organization's grants does not fix this missing-header defect;
the existing credential can be reused once the broker is updated.
