/-
  Liaison.Egress.Secrets — connector credentials and independent policy
  documents backed by typednotes/secrets, the OS keychain, or OpenBao KV v2.

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

import Liaison.Wire
import Liaison.Clock
import Liaison.Egress.Credential
import Linen.Network.HTTP.Simple
import Linen.Data.Json
import Linen.System.Keychain
import Std.Data.HashSet

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
private structure VaultConfig where
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
private def vaultConfigFromEnv (openBao : Bool) : IO VaultConfig := do
  let host ← match ← IO.getEnv "SECRETS_HOST" with
    | some h => pure h
    | none => throw <| IO.userError "SECRETS_HOST is not set"
  let username ← if openBao then pure none else IO.getEnv "SECRETS_USERNAME"
  let auth ← match username with
    | some user =>
      match ← IO.getEnv "SECRETS_PASSWORD" with
      | some pw => pure (VaultAuth.userpass user pw (← IO.mkRef none))
      | none => throw <| IO.userError "SECRETS_USERNAME is set but SECRETS_PASSWORD is not"
    | none =>
      match ← IO.getEnv "SECRETS_TOKEN" with
      | some t =>
        if t.isEmpty then throw (IO.userError "SECRETS_TOKEN is empty")
        pure (VaultAuth.static t)
      | none =>
        if openBao then throw (IO.userError "SECRETS_TOKEN is required for OpenBao")
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

private def vaultRequest (cfg : VaultConfig) (method : StdMethod) (path : String)
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
private def login (cfg : VaultConfig) (username password : String) : IO VaultToken := do
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
private def currentToken (cfg : VaultConfig) (force : Bool) : IO String := do
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
private def sendVault (cfg : VaultConfig) (method : StdMethod) (path : String)
    (body : Option ByteArray := none) : IO Response := do
  let resp ← httpBS (vaultRequest cfg method path (← currentToken cfg false) body)
  match cfg.auth with
  | .userpass .. =>
    if resp.statusCode.statusCode == 403 then
      httpBS (vaultRequest cfg method path (← currentToken cfg true) body)
    else
      return resp
  | .static _ => return resp

/-- Credentials and policy documents use one backend selected at startup. -/
inductive SecretsConfig where
  | typednotes (vault : VaultConfig)
  | keychain (service : String) (index : System.FilePath)
  | openbao (vault : VaultConfig) (mount : String)

/-- Select `typednotes` (default), `keychain`, or `openbao` via `SECRETS_BACKEND`. -/
def SecretsConfig.fromEnv : IO SecretsConfig := do
  match (← IO.getEnv "SECRETS_BACKEND").getD "typednotes" with
  | "typednotes" => return .typednotes (← vaultConfigFromEnv false)
  | "keychain" =>
    let some index ← IO.getEnv "SECRETS_KEYCHAIN_INDEX"
      | throw (IO.userError "SECRETS_KEYCHAIN_INDEX is required for keychain storage")
    let service := (← IO.getEnv "SECRETS_KEYCHAIN_SERVICE").getD "typednotes.liaison"
    if index.isEmpty || service.isEmpty || service.contains (Char.ofNat 0) then
      throw (IO.userError "invalid keychain configuration")
    return .keychain service index
  | "openbao" =>
    let mount := (← IO.getEnv "SECRETS_MOUNT").getD "secret"
    unless Wire.validAccountSegment mount do
      throw (IO.userError "SECRETS_MOUNT must be a single path segment")
    return .openbao (← vaultConfigFromEnv true) mount
  | _ => throw (IO.userError "SECRETS_BACKEND must be typednotes, keychain, or openbao")

/-- Logical path identity for an inventory entry. -/
structure SecretId where
  provider : String
  account : String
  deriving BEq, Hashable, Inhabited

/-- Parse a credential path relative to the storage mount, excluding policy documents. -/
def SecretId.parse (path : String) : Option SecretId :=
  match path.splitOn "/" with
  | ["thirdparty", provider, owner, connection] =>
    if [provider, owner, connection].all Wire.validAccountSegment then
      some ⟨provider, owner ++ "/" ++ connection⟩
    else none
  | _ => none

/-- Logical path shared by all the storage backends. -/
def SecretId.path (id : SecretId) : String :=
  s!"thirdparty/{id.provider}/{id.account}"

/-- The KV HTTP path of a third-party credential on typednotes/secrets. -/
def credentialPath (provider : Provider) (account : String) : String :=
  "/v1/secret/data/" ++ (SecretId.mk provider.value account).path

private def parseJson (text : String) : IO Value := do
  let root ← IO.ofExcept (Data.Json.Decode.decode text |>.mapError fun _ =>
    IO.userError "secret store returned invalid JSON")
  unless Wire.uniqueKeys root do
    throw (IO.userError "secret store returned duplicate JSON fields")
  return root

private def parseResponse (resp : Response) : IO Value := do
  unless resp.isSuccess do
    throw (IO.userError s!"secret store returned HTTP {resp.statusCode.statusCode}")
  let some text := String.fromUTF8? resp.body
    | throw (IO.userError "secret store returned invalid UTF-8")
  parseJson text

private def sendBao (vault : VaultConfig) (method : StdMethod) (path : String)
    (body : Option ByteArray := none) (queryString := "") : IO Response := do
  let token ← currentToken vault false
  let req := vaultRequest vault method path token body
  httpBS { req with queryString, headers := (Data.CI.mk' "X-Vault-Token", token) ::
    req.headers.filter (fun (name, _) => name != hAuthorization) }

private def requireField (value : Value) (name : String) : IO Value :=
  match value.lookup name with
  | some field => pure field
  | none => throw (IO.userError s!"secret store response is missing {name}")

private structure Document where
  data : Value
  version : Option Nat := none

private def readDocument (cfg : SecretsConfig) (path : String) : IO (Option Document) := do
  match cfg with
  | .keychain service _ =>
    let text ← try (System.Keychain.Entry.new service path).getPassword catch e =>
      match e with
      | .userError "keychain: no matching entry found" => return none
      | _ => throw (IO.userError "keychain entry is unavailable")
    return some { data := ← parseJson text }
  | .typednotes vault =>
    let resp ← sendVault vault .GET ("/v1/secret/data/" ++ path)
    if resp.statusCode.statusCode == 404 then return none
    return some { data := ← requireField (← parseResponse resp) "data" }
  | .openbao vault mount =>
    let resp ← sendBao vault .GET s!"/v1/{mount}/data/{path}"
    if resp.statusCode.statusCode == 404 then return none
    let envelope ← requireField (← parseResponse resp) "data"
    let metadata ← requireField envelope "metadata"
    let some version := metadata.lookup "version" >>= jsonNat?
      | throw (IO.userError "OpenBao response is missing a valid version")
    if version == 0 then throw (IO.userError "OpenBao returned version zero")
    return some { data := ← requireField envelope "data", version := some version }

private def stringArray (value : Value) : IO (List String) := do
  let .array values := value | throw (IO.userError "secret inventory must be an array")
  values.toList.mapM fun value =>
    match value with
    | .string name => pure name
    | _ => throw (IO.userError "secret inventory keys must be strings")

private def baoKeys (vault : VaultConfig) (mount path : String) : IO (List String) := do
  let resp ← sendBao vault .GET s!"/v1/{mount}/metadata/{path}/" (queryString := "?list=true")
  if resp.statusCode.statusCode == 404 then return []
  stringArray (← requireField (← requireField (← parseResponse resp) "data") "keys")

private def folderNames (keys : List String) : List String :=
  keys.filterMap fun key =>
    let name := (key.dropEnd 1).toString
    if key.endsWith "/" && Wire.validAccountSegment name then some name else none

/-- Enumerate connector credential identities. Policy documents are outside the
    inventory. The keychain uses an operator-supplied JSON array of paths. -/
def SecretsConfig.listCredentials (cfg : SecretsConfig) : IO (List SecretId) := do
  let paths ← match cfg with
    | .keychain _ index =>
      let keys ← stringArray (← parseJson (← IO.FS.readFile index))
      unless keys.all (fun path => (SecretId.parse path).isSome) do
        throw (IO.userError "keychain index must contain thirdparty/provider/owner/connection paths")
      pure keys
    | .typednotes vault =>
      stringArray (← requireField
        (← parseResponse (← sendVault vault .GET "/v1/secret/metadata/thirdparty/")) "keys")
    | .openbao vault mount => do
      let mut paths := []
      for provider in folderNames (← baoKeys vault mount "thirdparty") do
        for owner in folderNames (← baoKeys vault mount s!"thirdparty/{provider}") do
          for connection in ← baoKeys vault mount s!"thirdparty/{provider}/{owner}" do
            if Wire.validAccountSegment connection then
              paths := s!"thirdparty/{provider}/{owner}/{connection}" :: paths
      pure paths
  let ids := Std.HashSet.ofList (paths.filterMap SecretId.parse)
  return ids.toList.mergeSort (fun a b => a.path ≤ b.path)

/-- A parsed credential and its optional store revision for conditional updates. -/
structure StoredCredential where
  credential : Credential
  version : Option Nat

/-- Fetch a credential and a revision without exposing the credential on errors. -/
def loadCredential (cfg : SecretsConfig) (id : SecretId) : IO (Except String StoredCredential) := do
  unless SecretId.parse id.path == some id do return .error "invalid credential identity"
  try
    let some document ← readDocument cfg id.path | return .error "credential is missing"
    let some credential := Credential.parse document.data | return .error "credential is malformed"
    return .ok { credential, version := document.version }
  catch _ => return .error "credential store is unavailable"

/-- Fetch the credential selected by the signed provider and account. -/
def fetchCredential (cfg : SecretsConfig) (provider : Provider) (account : String)
    : IO (Except String Credential) :=
  (·.map (·.credential)) <$> loadCredential cfg ⟨provider.value, account⟩

/-- Fetch the independent connection policy. An absent legacy policy may use
    read defaults. Unavailable or malformed policy data refuses the request. -/
def fetchPermissions (cfg : SecretsConfig) (provider : Provider) (account : String) :
    IO (Except String (Option Value)) := do
  let id : SecretId := ⟨provider.value, account⟩
  unless SecretId.parse id.path == some id do return .error "invalid credential identity"
  try
    let doc ← readDocument cfg (id.path ++ "/permissions")
    return .ok (doc.map (·.data))
  catch _ => return .error "connection permissions are unavailable"

private def requiredPolicy (cfg : SecretsConfig) (path : String) :
    IO (Except String Value) := do
  try
    let some doc ← readDocument cfg path | return .error "policy document is missing"
    return .ok doc.data
  catch _ => return .error "policy document is unavailable"

/-- Fetch the mandatory run projection along the verified warrant path. -/
def fetchRunPermissions (cfg : SecretsConfig) (warrant : Warrant) (run : RunId) :
    IO (Except String Value) := do
  unless [warrant.orgId.value, run.value, warrant.id.value].all Wire.validAccountSegment do
    return .error "invalid authority identity"
  requiredPolicy cfg s!"connector-authority/{warrant.orgId.value}/{run.value}/{warrant.id.value}"

/-- Fetch the live organization policy independently of the connection and run. -/
def fetchOrganizationPermissions (cfg : SecretsConfig) (org : OrgId) (provider : Provider)
    (connection : ResourceId) : IO (Except String Value) := do
  unless [org.value, provider.value, connection.value].all Wire.validAccountSegment do
    return .error "invalid organization policy identity"
  requiredPolicy cfg s!"connector-policy/{org.value}/{provider.value}/{connection.value}"

/-- Persist a refresh. OpenBao requires the version from the original read. -/
def storeCredential (cfg : SecretsConfig) (id : SecretId) (credential : Credential)
    (version : Option Nat) : IO (Except String Unit) := do
  unless SecretId.parse id.path == some id do return .error "invalid credential identity"
  try
    match cfg with
    | .keychain service _ =>
      (System.Keychain.Entry.new service id.path).setPassword (Data.Json.Encode.encode credential.raw)
    | .typednotes vault =>
      let body := (Data.Json.Encode.encode credential.raw).toUTF8
      let resp ← sendVault vault .POST ("/v1/secret/data/" ++ id.path) (some body)
      unless resp.isSuccess do return .error "secret store rejected the refresh write"
    | .openbao vault mount =>
      let some revision := version | return .error "OpenBao refresh requires a version"
      let body := Data.Json.Encode.encode (.object [("data", credential.raw),
        ("options", .object [("cas", .number revision.toFloat)])])
      let resp ← sendBao vault .POST s!"/v1/{mount}/data/{id.path}" (some body.toUTF8)
      unless resp.isSuccess do return .error "OpenBao rejected the conditional refresh write"
    return .ok ()
  catch _ => return .error "refresh write failed"

/-- Replace a credential using the current storage revision. -/
def writeCredential (cfg : SecretsConfig) (provider : Provider) (account : String)
    (credential : Credential) : IO (Except String Unit) := do
  let id : SecretId := ⟨provider.value, account⟩
  match cfg with
  | .openbao .. =>
    match ← loadCredential cfg id with
    | .error err => return .error err
    | .ok old => storeCredential cfg id credential old.version
  | _ => storeCredential cfg id credential none

end Liaison.Egress
