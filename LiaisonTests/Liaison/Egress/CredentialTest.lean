/-
  Tests for `Liaison.Egress.Credential`: parsing the vault's `data` object
  for each kind of `docs/connections.md` §3.3, refusing unknown/malformed
  credentials, the header names each kind sets, and the refresh write-back
  shape.

  `Credential` deliberately has no `Repr`/`BEq`, so the checks go through its
  accessors (`kindName`, `baseUrl`, `headers`, `setHeaderNames`) and pattern
  matches on `auth` — never by printing it.
-/
import Liaison.Egress.Credential

open Liaison.Egress

namespace LiaisonTests.Liaison.Egress.Credential

private def parse (s : String) : Option _root_.Liaison.Egress.Credential :=
  (Data.Json.Decode.decode s).toOption.bind _root_.Liaison.Egress.Credential.parse

private def kindOf (s : String) : Option String := (parse s).map (·.kindName)

-- ── The four kinds ──

private def bearerJson : String :=
  "{\"kind\": \"bearer\", \"base_url\": \"https://api.github.com\", \"token\": \"gho_x\"}"
private def headerJson : String :=
  "{\"kind\": \"header\", \"base_url\": \"https://api.anthropic.com/v1\", " ++
  "\"header\": \"X-Api-Key\", \"token\": \"sk-ant-x\", " ++
  "\"headers\": {\"anthropic-version\": \"2023-06-01\"}}"
private def googleJson : String :=
  "{\"kind\": \"google_oauth\", \"base_url\": \"https://www.googleapis.com\", " ++
  "\"access_token\": \"ya29.x\", \"refresh_token\": \"1//r\", \"expires_at\": \"1790000000\", " ++
  "\"extra\": \"kept\"}"
private def s3Json : String :=
  "{\"kind\": \"s3\", \"base_url\": \"https://s3.fr-par.scw.cloud/my-bucket\", " ++
  "\"region\": \"fr-par\", \"access_key_id\": \"SCWX\", \"secret_access_key\": \"s\"}"

private def authOf (s : String) : Option CredentialAuth := (parse s).map (·.auth)

#guard kindOf bearerJson == some "bearer"
#guard kindOf headerJson == some "header"
#guard kindOf googleJson == some "google_oauth"
#guard kindOf s3Json == some "s3"

#guard (parse bearerJson).map (·.baseUrl) == some "https://api.github.com"
#guard (parse s3Json).map (·.baseUrl) == some "https://s3.fr-par.scw.cloud/my-bucket"
#guard (parse headerJson).map (·.headers) == some [("anthropic-version", "2023-06-01")]
#guard (parse bearerJson).map (·.headers) == some []

#guard match authOf bearerJson with
  | some (.bearer t) => t == "gho_x"
  | _ => false
-- The `header` name is lowercased.
#guard match authOf headerJson with
  | some (.header h t) => h == "x-api-key" && t == "sk-ant-x"
  | _ => false
#guard match authOf googleJson with
  | some (.googleOauth a r e) => a == "ya29.x" && r == "1//r" && e == 1790000000
  | _ => false
#guard match authOf s3Json with
  | some (.s3 region k s) => region == "fr-par" && k == "SCWX" && s == "s"
  | _ => false

-- A trailing `/` on `base_url` is dropped.
#guard (parse "{\"kind\": \"bearer\", \"base_url\": \"https://x.test/v1/\", \"token\": \"t\"}").map
  (·.baseUrl) == some "https://x.test/v1"

-- ── Refused ──

-- Unknown kind, missing kind.
#guard (parse "{\"kind\": \"oauth1\", \"base_url\": \"https://x.test\", \"token\": \"t\"}").isNone
#guard (parse "{\"base_url\": \"https://x.test\", \"token\": \"t\"}").isNone
-- Missing `base_url`, missing token.
#guard (parse "{\"kind\": \"bearer\", \"token\": \"t\"}").isNone
#guard (parse "{\"kind\": \"bearer\", \"base_url\": \"https://x.test\"}").isNone
-- Values must be strings (numbers too).
#guard (parse "{\"kind\": \"bearer\", \"base_url\": \"https://x.test\", \"token\": 1}").isNone
#guard (parse ("{\"kind\": \"google_oauth\", \"base_url\": \"https://x.test\", " ++
  "\"access_token\": \"a\", \"refresh_token\": \"r\", \"expires_at\": 1790000000}")).isNone
#guard (parse ("{\"kind\": \"google_oauth\", \"base_url\": \"https://x.test\", " ++
  "\"access_token\": \"a\", \"refresh_token\": \"r\", \"expires_at\": \"soon\"}")).isNone
-- Static headers must all be strings.
#guard (parse ("{\"kind\": \"bearer\", \"base_url\": \"https://x.test\", \"token\": \"t\", " ++
  "\"headers\": {\"a\": 1}}")).isNone
-- Unusable base URLs: non-http scheme, query, userinfo, empty host.
#guard (parse "{\"kind\": \"bearer\", \"base_url\": \"ftp://x.test\", \"token\": \"t\"}").isNone
#guard (parse "{\"kind\": \"bearer\", \"base_url\": \"https://x.test?a=1\", \"token\": \"t\"}").isNone
#guard (parse "{\"kind\": \"bearer\", \"base_url\": \"https://u@x.test\", \"token\": \"t\"}").isNone
#guard (parse "{\"kind\": \"bearer\", \"base_url\": \"https://\", \"token\": \"t\"}").isNone
-- Empty header name.
#guard (parse ("{\"kind\": \"header\", \"base_url\": \"https://x.test\", " ++
  "\"header\": \"\", \"token\": \"t\"}")).isNone
-- Not an object.
#guard (parse "\"bearer\"").isNone

-- ── Header names the credential sets ──

#guard (parse bearerJson).map (·.setHeaderNames) == some ["authorization"]
#guard (parse headerJson).map (·.setHeaderNames) == some ["x-api-key", "anthropic-version"]
#guard ((parse s3Json).map (·.setHeaderNames)).map (·.contains "x-amz-date") == some true

-- ── Refresh write-back ──

-- Token fields replaced, `expires_at` a decimal string, other fields kept.
#guard match (parse googleJson).map (fun c => (c.refreshed "ya29.new" 1790003600 none)) with
  | some c =>
    (match c.auth with
     | .googleOauth a r e => a == "ya29.new" && r == "1//r" && e == 1790003600
     | _ => false) &&
    c.raw.lookup "expires_at" == some (.string "1790003600") &&
    c.raw.lookup "access_token" == some (.string "ya29.new") &&
    c.raw.lookup "extra" == some (.string "kept")
  | none => false
-- A rotated refresh token replaces the stored one.
#guard match (parse googleJson).map (fun c => (c.refreshed "a" 1 (some "1//new"))) with
  | some c => c.raw.lookup "refresh_token" == some (.string "1//new")
  | none => false

end LiaisonTests.Liaison.Egress.Credential
