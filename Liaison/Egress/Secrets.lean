/-
  Liaison.Egress.Secrets — the `typednotes/secrets` HTTP client.

  Route and auth convention confirmed by reading `secrets-server`'s own
  source (not assumed from `secrets/docs/delegation/README.md` alone):
  - `crates/secrets-server/src/handlers.rs` registers every route under a
    `/v1/` prefix.
  - `crates/secrets-server/tests/integration.rs`'s `data_url` helper
    confirms the read route is `/v1/secret/data/{path}` — the plan's
    original sketch omitted the `/v1` prefix.
  - `bearer_token` in `handlers.rs` reads a standard `Authorization: Bearer
    <token>` header, not a custom Vault-style header.
  - The read response is JSON with a top-level `"data"` key
    (`assert_eq!(body["data"], ...)` in `integration.rs`); the exact shape
    *inside* `data` for a thirdparty OAuth credential was not pinned down
    during implementation — see the doc-comment on `Credential` below and
    `AGENTS.md`'s "Not yet implemented" list.

  KV path convention (`secret/data/thirdparty/{provider}/{account}`) is from
  `secrets/docs/delegation/README.md`'s "Path and policy conventions".
-/

import Liaison.Warrant.Caveat
import Linen.Network.HTTP.Simple
import Linen.Data.Json

namespace Liaison.Egress

open Network.HTTP.Client
open Network.HTTP.Types
open Network.HTTP.Simple

/-- How to reach `typednotes/secrets`. `serviceToken` is `liaison`'s own
    service credential against `secrets` — **never** the end user's or a
    third party's credential, and never logged (kept out of any `Repr`/
    `ToString` derivation). -/
structure SecretsConfig where
  private mk ::
  host  : String
  port  : UInt16
  isSecure : Bool
  serviceToken : String

/-- Build from env: `SECRETS_HOST`, `SECRETS_PORT` (default 443),
    `SECRETS_INSECURE` (`"1"` to disable TLS, for local dev against a
    plaintext `secrets-server`), `SECRETS_TOKEN`. Fails loudly if
    `SECRETS_HOST` or `SECRETS_TOKEN` is unset. -/
def SecretsConfig.fromEnv : IO SecretsConfig := do
  let host ← match ← IO.getEnv "SECRETS_HOST" with
    | some h => pure h
    | none => throw <| IO.userError "SECRETS_HOST is not set"
  let token ← match ← IO.getEnv "SECRETS_TOKEN" with
    | some t => pure t
    | none => throw <| IO.userError "SECRETS_TOKEN is not set"
  let isSecure := (← IO.getEnv "SECRETS_INSECURE") != some "1"
  let port : UInt16 := match ← IO.getEnv "SECRETS_PORT" with
    | some p => (p.toNat?.getD (if isSecure then 443 else 80)).toUInt16
    | none => if isSecure then 443 else 80
  return { host, port, isSecure, serviceToken := token }

/-- A fetched third-party credential. No public constructor and no `Repr`/
    `ToString` instance — the only way to obtain one is `fetchCredential`,
    and it is designed to never be printable, so a stray `s!"{cred}"`
    somewhere is a compile error rather than a leak.

    **Open question, not resolved during implementation:** the exact JSON
    shape of a thirdparty credential under `"data"` (a single `"token"`
    field? `"username"`/`"password"`? engine-dependent?) was not pinned
    down against `secrets-server`'s KV engine source — `Credential.token`
    below is a v0 assumption (a single string field named `"token"`), named
    explicitly in `AGENTS.md`'s "Not yet implemented" list rather than
    silently treated as confirmed. -/
structure Credential where
  private mk ::
  data : Data.Json.Value

/-- v0 assumption: the credential is a single bearer token under a `"token"`
    field. Returns `none` (fail closed) if that assumption doesn't hold for
    a given secret. -/
def Credential.token (c : Credential) : Option String :=
  c.data.lookup "token" |>.bind Data.Json.Value.asString

/-- `GET secret/data/thirdparty/{provider}/{account}` (via the confirmed
    `/v1/` route prefix). No retry, no caching — fails closed on any
    non-200 response or malformed body, both named as open questions in
    `broker.md` §8 rather than defaults invented here. -/
def fetchCredential (cfg : SecretsConfig) (provider : Provider) (account : String)
    : IO (Option Credential) := do
  let path := s!"/v1/secret/data/thirdparty/{provider.value}/{account}"
  let req : Network.HTTP.Client.Request :=
    { method := Method.standard .GET
      host := cfg.host
      port := cfg.port
      path
      headers := [(hAuthorization, s!"Bearer {cfg.serviceToken}")]
      isSecure := cfg.isSecure }
  try
    let resp ← httpBS req
    if !resp.isSuccess then
      return none
    else
      match Data.Json.Decode.decode (String.fromUTF8! resp.body) with
      | .error _ => return none
      | .ok root =>
        match root.getField "data" with
        | .error _ => return none
        | .ok data => return some ⟨data⟩
  catch _ =>
    return none

end Liaison.Egress
