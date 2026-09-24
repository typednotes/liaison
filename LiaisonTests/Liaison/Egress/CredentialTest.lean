/-
  Tests for `Liaison.Egress.Credential`: parsing the vault's `data` object
  for each kind of `docs/connections.md` §3.3 (`bearer`, `header`, the
  three OAuth kinds, `s3`, `azure_sas`), refusing unknown/malformed
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

-- ── The kinds ──

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
private def dropboxJson : String :=
  "{\"kind\": \"dropbox_oauth\", \"base_url\": \"https://api.dropboxapi.com\", " ++
  "\"access_token\": \"sl.x\", \"refresh_token\": \"r\", \"expires_at\": \"1790014400\"}"
private def gitlabJson : String :=
  "{\"kind\": \"gitlab_oauth\", \"base_url\": \"https://gitlab.com/api/v4\", " ++
  "\"access_token\": \"glo\", \"refresh_token\": \"glr\", \"expires_at\": \"1790007200\"}"
private def azureJson : String :=
  "{\"kind\": \"azure_sas\", \"base_url\": \"https://acme.blob.core.windows.net/notes\", " ++
  "\"sas\": \"sv=2022-11-02&sp=rl&se=2027-01-01&sig=abc%2B%3D\", " ++
  "\"headers\": {\"x-ms-version\": \"2021-12-02\"}}"
private def s3Json : String :=
  "{\"kind\": \"s3\", \"base_url\": \"https://s3.fr-par.scw.cloud/my-bucket\", " ++
  "\"region\": \"fr-par\", \"access_key_id\": \"SCWX\", \"secret_access_key\": \"s\"}"

private def authOf (s : String) : Option CredentialAuth := (parse s).map (·.auth)

#guard kindOf bearerJson == some "bearer"
#guard kindOf headerJson == some "header"
#guard kindOf googleJson == some "google_oauth"
#guard kindOf s3Json == some "s3"
#guard kindOf dropboxJson == some "dropbox_oauth"
#guard kindOf gitlabJson == some "gitlab_oauth"
#guard kindOf azureJson == some "azure_sas"
#guard OAuthIssuer.ofKind? "gitlab_oauth" == some .gitlab
#guard OAuthIssuer.ofKind? "oauth" == none

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
  | some (.oauth .google a r e) => a == "ya29.x" && r == "1//r" && e == 1790000000
  | _ => false
#guard match authOf dropboxJson with
  | some (.oauth .dropbox a r e) => a == "sl.x" && r == "r" && e == 1790014400
  | _ => false
#guard match authOf gitlabJson with
  | some (.oauth .gitlab a _ _) => a == "glo"
  | _ => false
#guard match authOf azureJson with
  | some (.azureSas sas) => sas == "sv=2022-11-02&sp=rl&se=2027-01-01&sig=abc%2B%3D"
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
-- A SAS must be only SAS parameters, with `sv` and `sig`, and no `?`/`#`.
private def sasCred (sas : String) : String :=
  "{\"kind\": \"azure_sas\", \"base_url\": \"https://a.blob.core.windows.net/c\", \"sas\": \"" ++
  sas ++ "\"}"
#guard (parse (sasCred "sv=1&sig=x")).isSome
#guard (parse (sasCred "")).isNone
#guard (parse (sasCred "sv=1&sp=r")).isNone              -- no signature
#guard (parse (sasCred "sv=1&sig=x&comp=list")).isNone   -- not a SAS parameter
#guard (parse (sasCred "?sv=1&sig=x")).isNone
#guard (parse (sasCred "sv=1&sig=x#f")).isNone
#guard (parse (sasCred "sv=1&sig")).isNone
#guard validSas "SV=1&Sig=x"                             -- keys compare lowercased
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
#guard (parse gitlabJson).map (·.setHeaderNames) == some ["authorization"]
-- A SAS sets no header of its own; its static headers still count.
#guard (parse azureJson).map (·.setHeaderNames) == some ["x-ms-version"]

-- ── Refresh write-back ──

-- Token fields replaced, `expires_at` a decimal string, other fields kept.
#guard match (parse googleJson).map (fun c => (c.refreshed "ya29.new" 1790003600 none)) with
  | some c =>
    (match c.auth with
     | .oauth .google a r e => a == "ya29.new" && r == "1//r" && e == 1790003600
     | _ => false) &&
    c.raw.lookup "expires_at" == some (.string "1790003600") &&
    c.raw.lookup "access_token" == some (.string "ya29.new") &&
    c.raw.lookup "extra" == some (.string "kept")
  | none => false
-- A rotated refresh token replaces the stored one (GitLab rotates every time).
#guard match (parse googleJson).map (fun c => (c.refreshed "a" 1 (some "1//new"))) with
  | some c => c.raw.lookup "refresh_token" == some (.string "1//new")
  | none => false
#guard match (parse gitlabJson).map (fun c => (c.refreshed "glo2" 2 (some "glr2"))) with
  | some c =>
    (match c.auth with
     | .oauth .gitlab a r e => a == "glo2" && r == "glr2" && e == 2
     | _ => false) &&
    c.raw.lookup "kind" == some (.string "gitlab_oauth")
  | none => false
-- Kinds that are not refreshed come back unchanged.
#guard match (parse azureJson).map (fun c => (c.refreshed "a" 1 none)) with
  | some c => c.raw.lookup "access_token" == none
  | none => false

end LiaisonTests.Liaison.Egress.Credential
