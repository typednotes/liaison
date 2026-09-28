# TODO

Suggestions from the linen v1.6.1 dependency review (2026-09-28). Nothing here
blocks the bump — liaison uses none of the modules linen 1.6.x changed. Each
item names where it comes from; re-check before acting.

Several items are **moves into linen** (see linen's `AGENTS.md`, "Importing
external code"): do the linen change and delete liaison's copy in the same
pass, so there are never two live copies.

## Security

- [ ] **Compare warrant tags in constant time.** `verifyTag` compares with a
  plain `==` (`Liaison/Warrant/Tag.lean:131-147`); its comment notes linen has
  nothing to reuse. lun and lode each carry an identical `constantTimeEq`
  (`lun/Lun/Server.lean:55`, `lode/Lode/Server.lean:59`), and linen's own
  `JWS.verifySignature` has the same `==` (`linen/Linen/Crypto/JOSE/JWS.lean:64-73`).
  Add one constant-time comparison to linen, use it in all four places, delete
  the copies. (S)

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

- [ ] **CA bundle.** `Dockerfile:27-33` sets `SSL_CERT_FILE`/`SSL_CERT_DIR`
  because linen's TLS only calls `SSL_CTX_set_default_verify_paths`
  (`linen/ffi/tls.c:553`), which points at the toolchain builder's paths. lun,
  lode, typednotes-infra and infra's scaffolds do the same. Fix once in linen
  (fall back to the usual bundle locations). (S, FFI: every CI axis)
- [ ] **Untyped SQL parameters.** Every statement casts (`$1::uuid`,
  `$3::bigint`, `Budget.lean:54-60`) because linen sends parameter types as
  `NULL` (`linen/ffi/postgres.c:357-359`). Typed `Params` in linen would drop
  them. Harmless as is; low priority. (M)
- [ ] **Copied link flags** (`lakefile.lean:1-81`) — the recipe linen documents
  for consumers; five siblings carry it. Follow any upstream fix.

## Hygiene

- [ ] **CI builds only `LiaisonTests`**, so the executable's link — the part
  the copied flags exist for — is only exercised by the Docker build. Add
  `lake build liaison`, and a macOS leg (the lakefile has a dylib branch).
- [ ] **Stale comment** at `lakefile.lean:69-73`: web-data no longer passes
  OpenSSL link flags.
