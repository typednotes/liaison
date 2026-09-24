/-
  Tests for `Liaison.Egress.S3`.

  The signatures below are pinned against **AWS's published S3 SigV4
  examples** ("Signature Calculations for the Authorization Header:
  Transferring Payload in a Single Chunk" — the GET Bucket Lifecycle and
  List Objects examples), whose signed-header set is exactly the one
  `liaison` signs (`host;x-amz-content-sha256;x-amz-date`), plus one value
  pinned against `linen`'s own tested `Crypto.SigV4.sign`
  (`Tests/Linen/Crypto/SigV4Test.lean`). Signing calls the OpenSSL HMAC FFI,
  so those checks run under `#eval` (a thrown error fails the build).
-/
import Liaison.Egress.S3

open Liaison.Egress Data.Time

namespace LiaisonTests.Liaison.Egress.S3

private def check (b : Bool) (msg : String) : IO Unit :=
  unless b do throw (IO.userError msg)

private def get (hs : List (String × String)) (n : String) : String :=
  (hs.find? (·.1 == n)).map (·.2) |>.getD ""

-- ── Query decoding and canonical form ──

#guard decodeQuery "" == some []
#guard decodeQuery "list-type=2&max-keys=1" ==
  some [("list-type", some "2"), ("max-keys", some "1")]
#guard decodeQuery "lifecycle" == some [("lifecycle", none)]
#guard decodeQuery "a=b=c" == some [("a", some "b=c")]
#guard decodeQuery "prefix=a%20b" == some [("prefix", some "a b")]
#guard decodeQuery "a=%zz" == none

private def target (path query : String) : Target :=
  { isSecure := true, host := "s3.fr-par.scw.cloud", port := 443
    authority := "s3.fr-par.scw.cloud", path, query }

-- The contract's test call: parameters sorted, rendered once.
#guard (s3Canonical (target "/my-bucket" "max-keys=1&list-type=2")).map
  (fun p => (p.decodedPath, p.wirePath, p.wireQuery)) ==
  some ("/my-bucket", "/my-bucket", "list-type=2&max-keys=1")
-- A key with an encoded space is decoded for signing and re-encoded on the wire.
#guard (s3Canonical (target "/my-bucket/a%20b.txt" "")).map
  (fun p => (p.decodedPath, p.wirePath, p.wireQuery)) ==
  some ("/my-bucket/a b.txt", "/my-bucket/a%20b.txt", "")
#guard (s3Canonical (target "/my-bucket/%2e%2e/x" "")).isNone

-- ── Signatures ──

/-- AWS's S3 documentation credentials. Not a real key. -/
private def keyId : String := "AKIAIOSFODNN7EXAMPLE"
private def secret : String := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
/-- 2013-05-24T00:00:00Z, the timestamp of AWS's S3 examples. -/
private def t2013 : UTCTime := UTCTime.ofNanosSinceEpoch (1369353600 * 1000000000)

-- GET Bucket Lifecycle: `GET /?lifecycle`, host `examplebucket.s3.amazonaws.com`.
#eval show IO Unit from do
  let hs ← s3AuthHeaders "us-east-1" keyId secret t2013 "GET"
    "examplebucket.s3.amazonaws.com" "/" [("lifecycle", none)] ByteArray.empty
  check (get hs "Host" == "examplebucket.s3.amazonaws.com") "Host"
  check (get hs "x-amz-date" == "20130524T000000Z") s!"x-amz-date: {get hs "x-amz-date"}"
  check (get hs "x-amz-content-sha256" ==
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") "empty payload hash"
  check (get hs "Authorization" == "AWS4-HMAC-SHA256 \
Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")
    s!"lifecycle Authorization: {get hs "Authorization"}"

-- List Objects: `GET /?max-keys=2&prefix=J`.
#eval show IO Unit from do
  let hs ← s3AuthHeaders "us-east-1" keyId secret t2013 "GET"
    "examplebucket.s3.amazonaws.com" "/" [("max-keys", some "2"), ("prefix", some "J")]
    ByteArray.empty
  check (get hs "Authorization" == "AWS4-HMAC-SHA256 \
Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
    s!"list Authorization: {get hs "Authorization"}"

-- The same request `linen`'s own SigV4 test signs (path-style bucket, PUT).
#eval show IO Unit from do
  let t : UTCTime := UTCTime.ofNanosSinceEpoch (1440938160 * 1000000000)
  let hs ← s3AuthHeaders "eu-west-1" "AKIDEXAMPLE" "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" t
    "PUT" "s3.eu-west-1.amazonaws.com" "/my-bucket" [] ByteArray.empty
  check (get hs "Authorization" == "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/eu-west-1/s3/aws4_request, \
SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
Signature=b1ba7bd1e79e9726d5be98201bf756baa5d2e2b505a3ff12e45bbaa0e7068520")
    s!"linen-pinned Authorization: {get hs "Authorization"}"

-- The payload hash is SHA-256 of the body.
#eval show IO Unit from do
  let hs ← s3AuthHeaders "fr-par" "k" "s" t2013 "PUT" "s3.fr-par.scw.cloud" "/b/k" []
    "hello".toUTF8
  check (get hs "x-amz-content-sha256" ==
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    s!"payload hash: {get hs "x-amz-content-sha256"}"

end LiaisonTests.Liaison.Egress.S3
