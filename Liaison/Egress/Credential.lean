/-
  Liaison.Egress.Credential — the typed third-party credential `liaison`
  reads out of `secrets`.

  The shape is the cross-service contract `typednotes/typednotes`'s
  `docs/connections.md` §3.3 fixes: the app writes it, `liaison` is its only
  reader. Every value is a JSON **string** (numbers too, so no side parses a
  float); every kind carries `kind` and `base_url`, and may carry `headers`,
  an object of static headers added to every call.

  ```jsonc
  {"kind": "bearer", "base_url": "…", "token": "…"}
  {"kind": "header", "base_url": "…", "header": "x-api-key", "token": "…",
   "headers": {"anthropic-version": "2023-06-01"}}
  {"kind": "google_oauth", "base_url": "…", "access_token": "…",
   "refresh_token": "…", "expires_at": "1790000000"}
  {"kind": "s3", "base_url": "…", "region": "…", "access_key_id": "…",
   "secret_access_key": "…"}
  ```

  Parsing fails closed: an unknown or missing `kind`, a missing field, a
  non-string value, or an unusable `base_url` all yield `none`, which the
  egress path reports as `credential_unavailable`.

  **Nothing here is printable.** Neither `CredentialAuth` nor `Credential`
  has a `Repr`/`ToString` instance, so a stray `s!"{cred}"` is a compile
  error rather than a leak. `Credential.kindName` is the only rendering, and
  it names the kind, never the material.
-/

import Linen.Data.Json

namespace Liaison.Egress

open Data.Json (Value)

/-- How a credential authenticates a call. The four kinds of
    `connections.md` §3.3; closed, so an unrecognised kind cannot be
    constructed and silently treated as one of these. -/
inductive CredentialAuth
  /-- `Authorization: Bearer {token}`. -/
  | bearer (token : String)
  /-- `{header}: {token}`. `header` is stored lowercased. -/
  | header (header : String) (token : String)
  /-- `Authorization: Bearer {accessToken}`, refreshed by `liaison` once
      `expiresAt - 60 ≤ now` (Unix seconds). -/
  | googleOauth (accessToken : String) (refreshToken : String) (expiresAt : Nat)
  /-- AWS Signature Version 4, service `s3`. -/
  | s3 (region : String) (accessKeyId : String) (secretAccessKey : String)

/-- A parsed credential. `raw` is the vault's `data` object exactly as read,
    kept so a Google refresh can write back the same object with only the
    token fields replaced (anything else the app stored survives). -/
structure Credential where
  /-- `base_url`, with any trailing `/` removed. Starts with `https://` or
      `http://` (checked by `parse`). -/
  baseUrl : String
  /-- Static headers from `headers`, in the order stored. -/
  headers : List (String × String)
  auth    : CredentialAuth
  raw     : Value

/-- The contract's name for a credential's kind (`"bearer"`, `"header"`,
    `"google_oauth"`, `"s3"`). Never the secret material. -/
def CredentialAuth.kindName : CredentialAuth → String
  | .bearer _ => "bearer"
  | .header _ _ => "header"
  | .googleOauth _ _ _ => "google_oauth"
  | .s3 _ _ _ => "s3"

/-- See `CredentialAuth.kindName`. -/
def Credential.kindName (c : Credential) : String := c.auth.kindName

/-- Remove every trailing `/`. Structural on the character list. -/
def stripTrailingSlashes (s : String) : String :=
  String.ofList (s.toList.reverse.dropWhile (· == '/')).reverse

/-- Whether a `base_url` is one `liaison` will scope calls to: an `http(s)`
    scheme, a non-empty authority, and no query, fragment or userinfo (the
    prefix check in `Policy.urlWithinBase` compares strings, so the base must
    be a plain `scheme://host[:port][/path]`). -/
def validBaseUrl (s : String) : Bool :=
  let rest? :=
    if s.startsWith "https://" then some (s.drop 8).toString
    else if s.startsWith "http://" then some (s.drop 7).toString
    else none
  match rest? with
  | none => false
  | some rest =>
    let authority := (rest.splitOn "/").headD ""
    !authority.isEmpty &&
      rest.all (fun c => c != '?' && c != '#' && c != '@' && c != ' ' &&
                         c.toNat > 0x20 && c.toNat != 0x7f)

private def str (v : Value) (field : String) : Option String :=
  v.lookup field |>.bind Value.asString

/-- Static headers: absent (or `null`) → `[]`; an object whose every value is
    a string → its entries; anything else → `none` (the credential is
    refused rather than half-applied). Names are lowercased. -/
def parseStaticHeaders (v : Value) : Option (List (String × String)) :=
  match v.lookup "headers" with
  | none => some []
  | some .null => some []
  | some (.object fields) =>
    fields.mapM (fun (k, val) => val.asString.map (fun s => (k.toLower, s)))
  | some _ => none

/-- The kind-specific part of a credential (`connections.md` §3.3). -/
def parseAuth (kind : String) (data : Value) : Option CredentialAuth :=
  match kind with
  | "bearer" => do
    let token ← str data "token"
    some (CredentialAuth.bearer token)
  | "header" => do
    let h ← str data "header"
    let token ← str data "token"
    if h.isEmpty then none else some (CredentialAuth.header h.toLower token)
  | "google_oauth" => do
    let access ← str data "access_token"
    let refresh ← str data "refresh_token"
    let expStr ← str data "expires_at"
    let exp ← expStr.toNat?
    some (CredentialAuth.googleOauth access refresh exp)
  | "s3" => do
    let region ← str data "region"
    let keyId ← str data "access_key_id"
    let secret ← str data "secret_access_key"
    some (CredentialAuth.s3 region keyId secret)
  | _ => none

/-- Parse the vault's `data` object (`connections.md` §3.3). `none` for an
    unknown or missing `kind`, a missing or non-string required field, an
    `expires_at` that is not a decimal natural, or an unusable `base_url`. -/
def Credential.parse (data : Value) : Option Credential := do
  let kind ← str data "kind"
  let base ← str data "base_url"
  let baseUrl := stripTrailingSlashes base
  let headers ← parseStaticHeaders data
  let auth ← parseAuth kind data
  if validBaseUrl baseUrl then
    some { baseUrl, headers, auth, raw := data }
  else
    none

/-- Every header name (lowercased) the credential itself sets on a call:
    its static `headers`, plus the authentication header(s) of its kind.
    `Policy.checkCallerHeaders` refuses a caller header with any of these
    names, so a caller cannot override or duplicate what the credential
    supplies. -/
def Credential.setHeaderNames (c : Credential) : List String :=
  let authNames := match c.auth with
    | .bearer _ => ["authorization"]
    | .header h _ => [h]
    | .googleOauth _ _ _ => ["authorization"]
    | .s3 _ _ _ => ["authorization", "host", "x-amz-date", "x-amz-content-sha256"]
  authNames ++ c.headers.map (·.1)

/-- Replace (or append) one field of a JSON object. -/
def setField (fields : List (String × Value)) (k : String) (v : Value)
    : List (String × Value) :=
  if fields.any (·.1 == k) then
    fields.map (fun (k', v') => if k' == k then (k', v) else (k', v'))
  else
    fields ++ [(k, v)]

/-- The credential after a Google refresh: same object, with `access_token`,
    `expires_at` (a decimal string, per §3.3) and — when Google rotated it —
    `refresh_token` replaced. For any other kind the credential is returned
    unchanged. This is the value written back to the vault. -/
def Credential.refreshed (c : Credential) (accessToken : String) (expiresAt : Nat)
    (newRefresh : Option String) : Credential :=
  match c.auth with
  | .googleOauth _ oldRefresh _ =>
    let refresh := newRefresh.getD oldRefresh
    let fields := match c.raw with
      | .object fs => fs
      | _ => []
    let fields := setField fields "access_token" (.string accessToken)
    let fields := setField fields "expires_at" (.string (toString expiresAt))
    let fields := setField fields "refresh_token" (.string refresh)
    { c with auth := .googleOauth accessToken refresh expiresAt, raw := .object fields }
  | _ => c

end Liaison.Egress
