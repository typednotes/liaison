/-
  Liaison.Egress.OAuth — refreshing `google_oauth`, `dropbox_oauth` and
  `gitlab_oauth` credentials (`typednotes/typednotes`'s
  `docs/connections.md` §5).

  When `expires_at - 60 ≤ now` (`Policy.needsRefresh`, `now` from
  `liaison`'s own wall clock), `liaison` exchanges the `refresh_token` at the
  issuer's token endpoint (`grant_type=refresh_token`, form encoded, with the
  issuer's `{GOOGLE,DROPBOX,GITLAB}_CLIENT_ID`/`_CLIENT_SECRET`), uses the
  new access token, and writes the updated credential back to the vault —
  best-effort, see `Provider.lean`.

  | Issuer | Token endpoint | Refresh token |
  |---|---|---|
  | `google` | `https://oauth2.googleapis.com/token` | kept, occasionally rotated |
  | `dropbox` | `https://api.dropboxapi.com/oauth2/token` | kept |
  | `gitlab` | `https://gitlab.com/oauth/token` | rotated on every refresh |

  The endpoints are fixed here, per issuer — never read from the credential
  — so a stored credential cannot direct its refresh token elsewhere.

  The request body and the response parser are pure (`refreshForm`,
  `parseTokenResponse`) and pinned in
  `LiaisonTests/Liaison/Egress/OAuthTest.lean`; only `refreshToken` does I/O.
-/

import Liaison.Egress.Credential
import Liaison.Egress.Secrets
import Linen.Network.HTTP.Simple
import Linen.Network.HTTP.Types.URI
import Linen.Data.Json

namespace Liaison.Egress

open Network.HTTP.Client
open Network.HTTP.Types
open Network.HTTP.Simple
open Data.Json (Value)

/-- An OAuth client `liaison` refreshes tokens with. Never printable. -/
structure OAuthClient where
  clientId     : String
  clientSecret : String

/-- The environment variable prefix of an issuer's client:
    `{prefix}_CLIENT_ID`, `{prefix}_CLIENT_SECRET`. -/
def OAuthIssuer.envPrefix : OAuthIssuer → String
  | .google => "GOOGLE"
  | .dropbox => "DROPBOX"
  | .gitlab => "GITLAB"

/-- The issuer's token endpoint host. -/
def OAuthIssuer.tokenHost : OAuthIssuer → String
  | .google => "oauth2.googleapis.com"
  | .dropbox => "api.dropboxapi.com"
  | .gitlab => "gitlab.com"

/-- The issuer's token endpoint path. -/
def OAuthIssuer.tokenPath : OAuthIssuer → String
  | .google => "/token"
  | .dropbox => "/oauth2/token"
  | .gitlab => "/oauth/token"

/-- `{prefix}_CLIENT_ID` + `{prefix}_CLIENT_SECRET`, both optional at
    startup: without them, every due refresh of that issuer's credentials
    fails as `credential_unavailable`. Only the pair counts — one without
    the other is treated as unset. -/
def OAuthClient.fromEnv (issuer : OAuthIssuer) : IO (Option OAuthClient) := do
  match ← IO.getEnv s!"{issuer.envPrefix}_CLIENT_ID",
        ← IO.getEnv s!"{issuer.envPrefix}_CLIENT_SECRET" with
  | some id, some secret =>
    if id.isEmpty || secret.isEmpty then return none
    else return some { clientId := id, clientSecret := secret }
  | _, _ => return none

/-- One optional client per issuer. -/
structure OAuthClients where
  google  : Option OAuthClient := none
  dropbox : Option OAuthClient := none
  gitlab  : Option OAuthClient := none

/-- The client for `issuer`, if configured. -/
def OAuthClients.get (clients : OAuthClients) : OAuthIssuer → Option OAuthClient
  | .google => clients.google
  | .dropbox => clients.dropbox
  | .gitlab => clients.gitlab

/-- Every issuer's client, from the environment. -/
def OAuthClients.fromEnv : IO OAuthClients := do
  return { google := ← OAuthClient.fromEnv .google
           dropbox := ← OAuthClient.fromEnv .dropbox
           gitlab := ← OAuthClient.fromEnv .gitlab }

/-- The `application/x-www-form-urlencoded` refresh body. Every value is
    percent-encoded (RFC 3986 unreserved set). The same for every issuer. -/
def refreshForm (client : OAuthClient) (refreshToken : String) : String :=
  "&".intercalate
    ([ ("grant_type", "refresh_token"), ("refresh_token", refreshToken)
     , ("client_id", client.clientId), ("client_secret", client.clientSecret) ].map
      (fun (k, v) => k ++ "=" ++ urlEncode v))

/-- What a successful refresh yields. -/
structure TokenResponse where
  accessToken  : String
  expiresIn    : Nat
  /-- Present only when the issuer rotated the refresh token. -/
  refreshToken : Option String

/-- Parse a token response: `access_token` (string), `expires_in` (JSON
    integer), optional `refresh_token` (string). Google, Dropbox and GitLab
    all answer in this shape. -/
def parseTokenResponse (body : String) : Option TokenResponse := do
  let root ← (Data.Json.Decode.decode body).toOption
  let accessToken ← root.lookup "access_token" |>.bind Value.asString
  if accessToken.isEmpty then none
  let expiresIn ← root.lookup "expires_in" |>.bind jsonNat?
  let refreshToken := root.lookup "refresh_token" |>.bind Value.asString
  return { accessToken, expiresIn, refreshToken }

/-- `POST https://{tokenHost}{tokenPath}`. `.error` (never a throw) on a
    transport failure, a non-2xx, or an unexpected body; the message never
    contains a token. -/
def refreshToken (issuer : OAuthIssuer) (client : OAuthClient) (refreshToken : String)
    : IO (Except String TokenResponse) := do
  let name := issuer.envPrefix.toLower
  let req : Network.HTTP.Client.Request :=
    { method := Method.standard .POST
      host := issuer.tokenHost, port := 443, path := issuer.tokenPath
      headers := [ (hContentType, "application/x-www-form-urlencoded")
                 , (hAccept, "application/json") ]
      body := some (refreshForm client refreshToken).toUTF8
      isSecure := true }
  try
    let resp ← httpBS req
    if !resp.isSuccess then
      return .error s!"{name} token refresh failed: HTTP {resp.statusCode.statusCode}"
    match (String.fromUTF8? resp.body).bind parseTokenResponse with
    | some t => return .ok t
    | none => return .error s!"{name} token refresh: unexpected response shape"
  catch e =>
    return .error s!"{name} token refresh failed: {e}"

end Liaison.Egress
