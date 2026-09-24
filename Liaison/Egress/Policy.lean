/-
  Liaison.Egress.Policy — the pure checks that scope one outbound call to one
  connection (`typednotes/typednotes`'s `docs/connections.md` §5).

  Everything here is a total, pure function over strings, so every rule is
  pinned by `#guard`s in `LiaisonTests/Liaison/Egress/PolicyTest.lean`:

  - `validAccount`/`accountMatchesResource` — `call.account` is
    `{user_id}/{connection_id}` and its last segment is the warrant-bound
    `resource`, so a warrant for one connection cannot read another's
    credential.
  - `checkCallerHeaders` — caller headers may not set or override
    authentication, framing or anything the credential sets.
  - `urlWithinBase` + `parseTarget` — the outbound URL stays under the
    credential's `base_url`, so a token can only ever be sent to the host (and
    path prefix) it was issued for.
  - `checkCallerQuery` — a caller's URL may not carry the query parameters
    the credential appends (an Azure SAS), so the credential's signature is
    the only one on the request.
  - `needsRefresh` — when an OAuth access token is due for a refresh.
-/

import Liaison.Egress.Credential
import Linen.Network.URI

namespace Liaison.Egress

-- ── Account ──────────────────────────────────────────────────────────

/-- One account segment: non-empty, `[A-Za-z0-9_-]` only. -/
def validAccountSegment (s : String) : Bool :=
  !s.isEmpty && s.all (fun c => c.isAlphanum || c == '_' || c == '-')

/-- `call.account` is exactly two valid segments separated by one `/`. -/
def validAccount (account : String) : Bool :=
  match account.splitOn "/" with
  | [u, c] => validAccountSegment u && validAccountSegment c
  | _ => false

/-- `validAccount`, and the connection segment equals the request's
    `resource` (which the warrant's `resource` caveat binds). -/
def accountMatchesResource (account resource : String) : Bool :=
  validAccount account &&
    (match account.splitOn "/" with
     | [_, c] => c == resource
     | _ => false)

-- ── Caller headers ───────────────────────────────────────────────────

/-- Header names a caller may never send, whatever the credential
    (`connections.md` §5), plus two framing headers — `transfer-encoding` and
    `connection` — that would let a caller desynchronise the request framing
    `liaison`'s HTTP client writes (deviation, documented in `AGENTS.md`).
    Every `x-amz-*` name is refused too (`isForbiddenHeader`). -/
def forbiddenHeaderNames : List String :=
  [ "authorization", "proxy-authorization", "x-api-key", "host"
  , "content-length", "cookie", "transfer-encoding", "connection" ]

/-- An RFC 9110 `token` character. -/
def isTokenChar (c : Char) : Bool :=
  c.isAlphanum || "!#$%&'*+-.^_`|~".toList.contains c

/-- A header name is a non-empty RFC 9110 token. -/
def validHeaderName (n : String) : Bool :=
  !n.isEmpty && n.all isTokenChar

/-- A header value contains no control character other than horizontal tab
    (so no CR/LF: nothing a caller sends can start a new header line). -/
def validHeaderValue (v : String) : Bool :=
  v.all (fun c => c == '\t' || (c.toNat ≥ 0x20 && c.toNat != 0x7f))

/-- Whether a (case-insensitive) caller header name is refused, given the
    names the credential itself sets (`Credential.setHeaderNames`,
    lowercased). -/
def isForbiddenHeader (credentialSets : List String) (name : String) : Bool :=
  let n := name.toLower
  forbiddenHeaderNames.contains n || n.startsWith "x-amz-" || credentialSets.contains n

/-- `true` iff every caller header is well-formed and allowed. -/
def checkCallerHeaders (credentialSets : List String) (headers : List (String × String))
    : Bool :=
  headers.all (fun (n, v) =>
    validHeaderName n && validHeaderValue v && !isForbiddenHeader credentialSets n)

-- ── URL ──────────────────────────────────────────────────────────────

/-- The outbound URL is `base` itself, or under `base + "/"`, or is `base`
    with a query (`base + "?"`, e.g. S3's `GET {base}?list-type=2`).
    Compared on the whole string, so `https://api.github.com.evil.com` is not
    under `https://api.github.com`. The scheme is therefore always the
    base's own — `http` is reachable only when the stored `base_url` is
    `http`. `base` is assumed to carry no trailing `/`
    (`Credential.parse` strips it). -/
def urlWithinBase (base url : String) : Bool :=
  (base.startsWith "https://" || base.startsWith "http://") &&
    (url == base || url.startsWith (base ++ "/") || url.startsWith (base ++ "?"))

/-- Where an outbound call goes, decomposed from an already-checked URL. -/
structure Target where
  isSecure : Bool
  host     : String
  port     : UInt16
  /-- `authority` as it appears in the URL: `host` or `host:port`. -/
  authority : String
  /-- The raw (still percent-encoded) path; `/` when the URL has none. -/
  path     : String
  /-- The raw query, without the leading `?`; empty when absent. -/
  query    : String
  deriving Repr, DecidableEq

/-- Decode `%XX` escapes into bytes, then read the bytes as UTF-8. `none` on
    a malformed escape or invalid UTF-8. `+` is left alone (it is only a
    space in form bodies, not in paths). -/
def percentDecode (s : String) : Option String :=
  let hex (c : Char) : Option Nat :=
    if c.isDigit then some (c.toNat - '0'.toNat)
    else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
    else if 'A' ≤ c && c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
    else none
  let rec go : List Char → ByteArray → Option ByteArray
    | [], acc => some acc
    | '%' :: h :: l :: rest, acc => do
      let v ← hex h
      let w ← hex l
      go rest (acc.push (v * 16 + w).toUInt8)
    | '%' :: _, _ => none
    | c :: rest, acc => go rest (acc ++ (String.singleton c).toUTF8)
  (go s.toList ByteArray.empty).bind String.fromUTF8?

/-- The path's segments, each percent-decoded. `none` if a segment does not
    decode, or is a dot segment (`.`/`..`, however encoded) — a dot segment
    could walk a request out from under a `base_url` with a path. -/
def decodedSegments (path : String) : Option (List String) := do
  let segs ← (path.splitOn "/").mapM percentDecode
  if segs.any (fun s => s == "." || s == "..") then none
  return segs

/-- A URI port (`""` or `":1234"`): the default, or the number when it is
    in `1..65535`. -/
def parsePort (defaultPort : UInt16) (p : String) : Option UInt16 :=
  if p.isEmpty then some defaultPort
  else
    match (p.drop 1).toString.toNat? with
    | some n => if 0 < n && n < 65536 then some n.toUInt16 else none
    | none => none

/-- Decompose a URL for sending. `none` if it does not parse as an RFC 3986
    absolute `http(s)` URI (which also rules out spaces and control
    characters — nothing can be smuggled into the request line), carries
    userinfo or a fragment, has an unparsable port, or has a dot segment. -/
def parseTarget (url : String) : Option Target := do
  let u ← Network.URI.parseURI url
  let isSecure ← match u.uriScheme with
    | "https:" => some true
    | "http:" => some false
    | _ => none
  let auth ← u.uriAuthority
  if !auth.uriUserInfo.isEmpty || !u.uriFragment.isEmpty || auth.uriRegName.isEmpty then none
  let defaultPort : UInt16 := if isSecure then 443 else 80
  let port ← parsePort defaultPort auth.uriPort
  let path := if u.uriPath.isEmpty then "/" else u.uriPath
  let _ ← decodedSegments path
  return { isSecure, host := auth.uriRegName, port
           authority := auth.uriRegName ++ auth.uriPort
           path, query := (u.uriQuery.drop 1).toString }

/-- The full URL check: `urlWithinBase` on the strings, then both URLs parse
    and agree on scheme, host and port (defence in depth — the string prefix
    already implies it for a `base_url` accepted by `validBaseUrl`). Returns
    the decomposed target on success. -/
def checkUrl (base url : String) : Option Target := do
  if !urlWithinBase base url then none
  let t ← parseTarget url
  let b ← parseTarget base
  if t.isSecure != b.isSecure || t.host != b.host || t.port != b.port then none
  return t

-- ── Query parameters the credential appends ──────────────────────────

/-- The query keys (lowercased) a caller's URL may not use with this
    credential: an Azure SAS's parameters. -/
def reservedQueryKeys : CredentialAuth → List String
  | .azureSas _ => sasParamNames
  | _ => []

/-- The keys of a raw query string, percent-decoded and lowercased; `none`
    if a key does not decode (refused, rather than guessed at). -/
def queryKeys (query : String) : Option (List String) :=
  if query.isEmpty then some []
  else (query.splitOn "&").mapM (fun p => (percentDecode ((p.splitOn "=").headD "")).map (·.toLower))

/-- `true` iff no key of the caller's query is reserved. -/
def checkCallerQuery (reserved : List String) (query : String) : Bool :=
  match queryKeys query with
  | some keys => !keys.any (reserved.contains ·)
  | none => false

/-- A raw query with `extra` appended (`&`-joined; either may be empty). -/
def appendQuery (query extra : String) : String :=
  if query.isEmpty then extra
  else if extra.isEmpty then query
  else query ++ "&" ++ extra

-- ── OAuth refresh ────────────────────────────────────────────────────

/-- An OAuth access token is refreshed when `expires_at - 60 ≤ now` (Unix
    seconds, `connections.md` §5). Written without subtraction so it is
    right for `expires_at < 60` too. -/
def needsRefresh (expiresAt now : Nat) : Bool :=
  expiresAt ≤ now + 60

end Liaison.Egress
