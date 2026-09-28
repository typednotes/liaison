# TODO

Suggestions from the linen v1.6.1 dependency review (2026-09-28). Nothing here
blocks the bump — liaison uses none of the modules linen 1.6.x changed. Each
item names where it comes from; re-check before acting.

Several items are **moves into linen** (see linen's `AGENTS.md`, "Importing
external code"): do the linen change and delete liaison's copy in the same
pass, so there are never two live copies.

## Security

- [x] **Compare warrant tags in constant time.** `verifyTag` uses linen's
  `Crypto.ConstantTime.eq` (linen 1.7.0), as do linen's JWS HMAC check, lun
  and lode. (0.5.5)

## Duplicates of linen, and building blocks to move there

- [ ] **`hmacSha256`** (`Tag.lean:24-27`) is a copy of
  `linen/Linen/Crypto/SigV4.lean:193-195`, both passing the magic `0` to
  `Crypto.JOSE.FFI.hmac`. Use linen's, or a new `Crypto.HMAC.sha256` there. (XS)
- [ ] **Seconds since the epoch.** `Liaison/Clock.lean:19-21` divides
  `nanosSinceEpoch` by hand, as do lode, lun, infra and web-data. A
  `getPOSIXSeconds`-style helper in `Linen.Data.Time.Clock` would replace all
  five. (XS)
- [ ] **Strict percent-decoding.** `percentDecode` (`Liaison/Egress/Policy.lean:92-106`,
  UTF-8, `none` on a bad escape) and the first-`=` `decodeQuery`
  (`Liaison/Egress/S3.lean:28-37`) are correct where linen's are lossy:
  `Network.HTTP.Types.urlDecode` turns bad hex into 0, and `parseQuery` returns
  `a=b=c` as a key with no value (`linen/Linen/Network/HTTP/Types/URI.lean:16-25, 91-106`).
  Move liaison's into linen, fix linen's, delete these. (S–M)
- [ ] **`setField`** (`Liaison/Egress/Credential.lean:214`) also exists in infra
  (`infra/Infra/Providers/JsonRead.lean:79`, listed there as a pending move).
  Two siblings: it belongs in linen's `Data.Json`. (S)
- [ ] **Typed environment readers.** `Main.lean` parses the port with
  `toUInt16`, which wraps (70000 becomes 4464), and falls back to 8080 on a
  non-number; ledger range-checks, lun and lode wrap too. The `DATABASE_URL` →
  `PoolSettings` code is the same as ledger's. A `System.Environment` module in
  linen (non-empty, required, Nat, port, seconds) plus `Settings.fromEnv`. (S–M)
- [ ] **Budget SQL is ledger's.** `Liaison/Budget.lean` repeats
  `ledger/Ledger/Sql/Reserve.lean`. Application logic, so not linen: a pure
  module in ledger that liaison imports, as lun and lode import `Liaison.Wire`. (M)

## Workarounds that linen could remove

- [x] **CA bundle.** Nothing to fix: `SSL_CTX_set_default_verify_paths`
  (`linen/ffi/tls.c`) reads `SSL_CERT_FILE`/`SSL_CERT_DIR` first, then
  OpenSSL's compiled-in paths, which on Ubuntu (`/usr/lib/ssl`) point at the
  `ca-certificates` bundle. The `ENV` lines are redundant on this base and
  keep the image correct on another; keep them.
- [ ] **Untyped SQL parameters.** Every statement casts (`$1::uuid`,
  `$3::bigint`, `Budget.lean:54-60`) because linen sends parameter types as
  `NULL` (`linen/ffi/postgres.c:357-359`). Typed `Params` in linen would drop
  them. Harmless as is; low priority. (M)
- [ ] **Copied link flags** (`lakefile.lean:1-81`) — the recipe linen documents
  for consumers; five siblings carry it. Follow any upstream fix.

## Hygiene

- [ ] **CI builds only `LiaisonTest`**, so the executable's link — the part
  the copied flags exist for — is only exercised by the Docker build. Add
  `lake build liaison`, and a macOS leg (the lakefile has a dylib branch).
- [ ] **Stale comment** at `lakefile.lean:69-73`: web-data no longer passes
  OpenSSL link flags.
