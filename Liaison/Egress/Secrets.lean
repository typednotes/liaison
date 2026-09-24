/-
  Liaison.Egress.Secrets — the `typednotes/secrets` HTTP client.

  Route and auth convention confirmed by reading `secrets-server`'s own
  source (`crates/secrets-server/src/handlers.rs`,
  `crates/secrets-engine-kv/src/lib.rs`):
  - every route lives under `/v1/`;
  - `GET /v1/secret/data/{path}` answers `{"data": <stored object>,
    "metadata": {…}}`; `POST` stores its JSON body **as is** (not wrapped in
    `data`) and answers `204`;
  - `POST /v1/auth/userpass/login` with `{"username", "password"}` answers
    `{"auth": {"client_token", "lease_duration", …}}`;
  - an invalid or expired token is `403`, a missing one `401`; the token
    travels as `Authorization: Bearer <token>`.

  KV path convention: `secret/data/thirdparty/{provider}/{account}`, where
  `account = "{user_id}/{connection_id}"` (`docs/connections.md` §3.2).

  ## Vault auth (`connections.md` §4–§5)

  With `SECRETS_USERNAME` + `SECRETS_PASSWORD`, `liaison` logs in with
  `userpass` and caches the token (in an `IO.Ref`) with its expiry. It logs in
  again when less than 60 s remain, and once more — then retries the call
  once — after a `403`. Without `SECRETS_USERNAME` it falls back to a static
  `SECRETS_TOKEN`. `SecretsConfig.fromEnv` fails loudly if neither is set.
-/

import Liaison.Warrant.Caveat
import Liaison.Clock
import Liaison.Egress.Credential
import Linen.Network.HTTP.Simple
import Linen.Data.Json

namespace Liaison.Egress

open Network.HTTP.Client
open Network.HTTP.Types
open Network.HTTP.Simple
open Data.Json (Value)

/-- A cached vault token and the Unix second it expires at (`none`: the vault
    reported no expiry — `lease_duration` 0). -/
structure VaultToken where
  token     : String
  expiresAt : Option Nat

/-- How `liaison` authenticates to `secrets`. Never printable. -/
inductive VaultAuth
  /-- A static `SECRETS_TOKEN` (fallback). -/
  | static (token : String)
  /-- `userpass` login, with the current token cached in `cache`. -/
  | userpass (username password : String) (cache : IO.Ref (Option VaultToken))

/-- How to reach `typednotes/secrets`. Carries `liaison`'s own service
    credential against `secrets` — **never** the end user's or a third
    party's — and is never logged (no `Repr`/`ToString`). -/
structure SecretsConfig where
  private mk ::
  host     : String
  port     : UInt16
  isSecure : Bool
  auth     : VaultAuth

/-- Build from env: `SECRETS_HOST`, `SECRETS_PORT` (default 443, or 80 with
    TLS off), `SECRETS_INSECURE` (`"1"` disables TLS, for local dev against a
    plaintext `secrets-server`), then either `SECRETS_USERNAME` +
    `SECRETS_PASSWORD` (preferred) or `SECRETS_TOKEN`. Fails loudly if
    `SECRETS_HOST` is unset, if `SECRETS_USERNAME` is set without
    `SECRETS_PASSWORD`, or if no credential is configured at all. -/
def SecretsConfig.fromEnv : IO SecretsConfig := do
  let host ← match ← IO.getEnv "SECRETS_HOST" with
    | some h => pure h
    | none => throw <| IO.userError "SECRETS_HOST is not set"
  let auth ← match ← IO.getEnv "SECRETS_USERNAME" with
    | some user =>
      match ← IO.getEnv "SECRETS_PASSWORD" with
      | some pw => pure (VaultAuth.userpass user pw (← IO.mkRef none))
      | none => throw <| IO.userError "SECRETS_USERNAME is set but SECRETS_PASSWORD is not"
    | none =>
      match ← IO.getEnv "SECRETS_TOKEN" with
      | some t => pure (VaultAuth.static t)
      | none =>
        throw <| IO.userError "neither SECRETS_USERNAME/SECRETS_PASSWORD nor SECRETS_TOKEN is set"
  let isSecure := (← IO.getEnv "SECRETS_INSECURE") != some "1"
  let port : UInt16 := match ← IO.getEnv "SECRETS_PORT" with
    | some p => (p.toNat?.getD (if isSecure then 443 else 80)).toUInt16
    | none => if isSecure then 443 else 80
  return ⟨host, port, isSecure, auth⟩

/-- A JSON number that is a non-negative integer, as a `Nat`. `Data.Json`
    numbers are `Float`s; anything fractional, negative or non-finite is
    refused rather than rounded. -/
def jsonNat? (v : Value) : Option Nat := do
  let f ← v.asNumber
  if f.isNaN || f.isInf || f < 0 || f.floor != f || f > 9.0e15 then none
  return f.toUInt64.toNat

/-- A vault token is renewed when fewer than 60 seconds remain. -/
def VaultToken.fresh (t : VaultToken) (now : Nat) : Bool :=
  match t.expiresAt with
  | none => true
  | some exp => now + 60 < exp

/-- Parse a `userpass` login response into a token expiring
    `lease_duration` seconds after `now` (`0`: no expiry). -/
def parseLogin (body : String) (now : Nat) : Option VaultToken := do
  let root ← (Data.Json.Decode.decode body).toOption
  let auth ← root.lookup "auth"
  let token ← auth.lookup "client_token" |>.bind Value.asString
  if token.isEmpty then none
  let lease ← auth.lookup "lease_duration" |>.bind jsonNat?
  return { token, expiresAt := if lease == 0 then none else some (now + lease) }

private def vaultRequest (cfg : SecretsConfig) (method : StdMethod) (path : String)
    (token : String) (body : Option ByteArray := none) : Network.HTTP.Client.Request :=
  { method := Method.standard method
    host := cfg.host
    port := cfg.port
    path
    headers := (hAuthorization, s!"Bearer {token}") ::
      (if body.isSome then [(hContentType, "application/json")] else [])
    body
    isSecure := cfg.isSecure }

/-- `POST /v1/auth/userpass/login`. Throws on any failure. -/
private def login (cfg : SecretsConfig) (username password : String) : IO VaultToken := do
  let body := Data.Json.Encode.encode
    (.object [("username", .string username), ("password", .string password)])
  let req : Network.HTTP.Client.Request :=
    { method := Method.standard .POST
      host := cfg.host, port := cfg.port, path := "/v1/auth/userpass/login"
      headers := [(hContentType, "application/json")]
      body := some body.toUTF8
      isSecure := cfg.isSecure }
  let resp ← httpBS req
  if !resp.isSuccess then
    throw <| IO.userError s!"secrets userpass login failed: HTTP {resp.statusCode.statusCode}"
  let now ← nowUnixSeconds
  match (String.fromUTF8? resp.body).bind (parseLogin · now) with
  | some t => return t
  | none => throw <| IO.userError "secrets userpass login: unexpected response shape"

/-- The token to use now: the static one, or the cached `userpass` token,
    logging in first when there is none, or it has under 60 s left, or
    `force` is set (after a `403`). -/
private def currentToken (cfg : SecretsConfig) (force : Bool) : IO String := do
  match cfg.auth with
  | .static t => return t
  | .userpass user pw cache =>
    let now ← nowUnixSeconds
    match ← cache.get with
    | some t =>
      if !force && t.fresh now then return t.token
    | none => pure ()
    let t ← login cfg user pw
    cache.set (some t)
    return t.token

/-- Send an authenticated vault request; after a `403` under `userpass`, log
    in again and retry exactly once. Throws on a transport failure. -/
private def sendVault (cfg : SecretsConfig) (method : StdMethod) (path : String)
    (body : Option ByteArray := none) : IO Response := do
  let resp ← httpBS (vaultRequest cfg method path (← currentToken cfg false) body)
  match cfg.auth with
  | .userpass .. =>
    if resp.statusCode.statusCode == 403 then
      httpBS (vaultRequest cfg method path (← currentToken cfg true) body)
    else
      return resp
  | .static _ => return resp

/-- The KV path of a third-party credential. -/
def credentialPath (provider : Provider) (account : String) : String :=
  s!"/v1/secret/data/thirdparty/{provider.value}/{account}"

/-- `GET secret/data/thirdparty/{provider}/{account}`, parsed with
    `Credential.parse`. `.error` (never a throw) on a transport failure, a
    non-2xx, a malformed body, or a credential of unknown/unusable kind — the
    message names what failed, never the credential. -/
def fetchCredential (cfg : SecretsConfig) (provider : Provider) (account : String)
    : IO (Except String Credential) := do
  try
    let resp ← sendVault cfg .GET (credentialPath provider account)
    if !resp.isSuccess then
      return .error s!"secrets read failed: HTTP {resp.statusCode.statusCode}"
    let some text := String.fromUTF8? resp.body
      | return .error "secrets read: body is not UTF-8"
    match Data.Json.Decode.decode text with
    | .error _ => return .error "secrets read: body is not JSON"
    | .ok root =>
      match root.lookup "data" with
      | none => return .error "secrets read: no data field"
      | some data =>
        match Credential.parse data with
        | none => return .error "secrets read: credential has an unknown kind or is malformed"
        | some c => return .ok c
  catch e =>
    return .error s!"secrets read failed: {e}"

/-- `POST secret/data/thirdparty/{provider}/{account}` with the credential
    object itself as the body (the KV engine stores the body as is). `.error`
    on any failure, never a throw. -/
def writeCredential (cfg : SecretsConfig) (provider : Provider) (account : String)
    (cred : Credential) : IO (Except String Unit) := do
  try
    let body := (Data.Json.Encode.encode cred.raw).toUTF8
    let resp ← sendVault cfg .POST (credentialPath provider account) (some body)
    if resp.isSuccess then return .ok ()
    else return .error s!"secrets write failed: HTTP {resp.statusCode.statusCode}"
  catch e =>
    return .error s!"secrets write failed: {e}"

end Liaison.Egress
