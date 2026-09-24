/-
  Liaison.Egress.S3 — AWS Signature Version 4 for an `s3` credential.

  A thin adapter over `linen`'s `Crypto.SigV4.sign` (the implementation
  `linen`'s own `Tests/Linen/Crypto/SigV4Test.lean` pins against AWS's
  published vectors). Service `s3`, the credential's region, payload hash =
  SHA-256 of the body, signed headers `host`, `x-amz-content-sha256`,
  `x-amz-date`.

  S3 signs the path **as sent** (no double encoding), so the caller's URL is
  canonicalised once — path segments percent-decoded then re-encoded with
  `Crypto.SigV4.canonicalUri`, query parameters decoded then rendered with
  `canonicalQuery` — and that one rendering is both signed and sent, exactly
  as `linen`'s `Cloud.Transport` does, so the two cannot diverge.
-/

import Liaison.Egress.Policy
import Linen.Crypto.SigV4
import Linen.Network.HTTP.Types.URI

namespace Liaison.Egress

open Network.HTTP.Types (Query canonicalQuery)

/-- Split a raw query string into decoded `(name, value)` pairs, splitting
    each item on its **first** `=` only (a value may contain `=`). `none` if a
    component does not percent-decode. Empty items (`a=1&&b=2`) are dropped. -/
def decodeQuery (raw : String) : Option Query :=
  if raw.isEmpty then some []
  else
    ((raw.splitOn "&").filter (!·.isEmpty)).mapM fun item =>
      match item.splitOn "=" with
      | [] => none
      | k :: rest => do
        let k ← percentDecode k
        if rest.isEmpty then return (k, none)
        return (k, some (← percentDecode ("=".intercalate rest)))

/-- An S3 target, canonicalised once. -/
structure S3Path where
  /-- Unencoded path, as `Crypto.SigV4.sign` wants it. -/
  decodedPath : String
  /-- Decoded query parameters, as `Crypto.SigV4.sign` wants them. -/
  query       : Query
  /-- The path sent on the wire: `canonicalUri decodedPath` — what is signed. -/
  wirePath    : String
  /-- The query sent on the wire, without `?`: `canonicalQuery query`. -/
  wireQuery   : String

/-- The path and query exactly as they are signed **and** sent: the path's
    decoded segments re-encoded by `Crypto.SigV4.canonicalUri`, and the query
    rendered by `canonicalQuery`. -/
def s3Canonical (t : Target) : Option S3Path := do
  let segs ← decodedSegments t.path
  let q ← decodeQuery t.query
  let decodedPath := "/".intercalate segs
  return { decodedPath, query := q
           wirePath := Crypto.SigV4.canonicalUri decodedPath false
           wireQuery := canonicalQuery q }

/-- The headers to add to an S3 request at `time`: `Host`, `x-amz-date`,
    `x-amz-content-sha256` and `Authorization`. `decodedPath` is unencoded
    (see `s3Canonical`); `authority` is the `Host` value (`host[:port]`). -/
def s3AuthHeaders (region accessKeyId secretAccessKey : String)
    (time : Data.Time.UTCTime) (method authority decodedPath : String) (query : Query)
    (body : ByteArray) : IO (List (String × String)) := do
  let signed ← Crypto.SigV4.sign
    { accessKeyId, secretAccessKey } region "s3" time
    { method, path := decodedPath, query
      headers := [("host", authority)]
      payload := body }
  return ("Host", authority) :: signed

end Liaison.Egress
