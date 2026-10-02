# Liaison v0.6.3

Extends existing repository operations for Typednotes v0.9.0. No new operation
ID, preset, authentication scope, credential shape or warrant envelope is added.

- `repositories.list` accepts optional `page` as canonical decimal text 1–100,
  defaults to 1 and derives fixed 100-item provider inventory URLs. Account
  inventory authority remains required; there is no owner/URL/header override.
  The private `InventoryPage` witness carries positive/bounded page proofs.
- Inventory replies consume a private `Inventory` witness with at most 100
  entries, in addition to existing response-byte bounds.
- `repositories.read` accepts `{"view":"metadata"}` at exactly `[owner,repo]`.
  It derives the provider repository endpoint and consumes a private `Metadata`
  reply witness matching the authorized resource (GitHub case-only normalization;
  GitLab exact namespace). Missing/mismatched identities refuse.

All four stored ceilings, HMAC/owner/budget checks and prepared native transport
proofs remain. Runtime SDKs use the same operation/resource envelope; parsers,
adapters, permission labels and app validation are coordinated. Older brokers
refuse new payload shapes rather than falling back to raw IO.

Verified Lean tests, 675 real broker HTTP cases, zero catalog gaps across 54
providers/165 pairs, and real app direct-selection/independent denial cases.
The v0.6.1 User-Agent fix and v0.6.2 bounded CI waiting are retained.

The user can push main and v0.6.3 together, wait for CI/image publication, then
deploy with Lun v0.3.1, Typednotes v0.9.0 and fleet v0.6.1.
