/-
  Liaison.Egress.Google — refreshing a `google_oauth` credential
  (`typednotes/typednotes`'s `docs/connections.md` §5).

  When `expires_at - 60 ≤ now` (`Policy.needsRefresh`, `now` from
  `liaison`'s own wall clock), `liaison` exchanges the `refresh_token` at
  `https://oauth2.googleapis.com/token` (`grant_type=refresh_token`, form
  encoded, with `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`), uses the new
  access token, and writes the updated credential back to the vault —
  best-effort, see `Provider.lean`.

  The request body and the response parser are pure (`refreshForm`,
  `parseTokenResponse`) and pinned in
  `LiaisonTests/Liaison/Egress/GoogleTest.lean`; only `refresh` does I/O.
-/

import Liaison.Egress.Secrets
import Linen.Network.HTTP.Simple
import Linen.Network.HTTP.Types.URI
import Linen.Data.Json

namespace Liaison.Egress

open Network.HTTP.Client
open Network.HTTP.Types
open Network.HTTP.Simple
open Data.Json (Value)

/-- `liaison`'s Google OAuth client. Never printable. -/
structure GoogleClient where
  clientId     : String
  clientSecret : String

/-- `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`, both optional at startup:
    without them, every refresh fails as `credential_unavailable`. Only the
    pair counts — one without the other is treated as unset. -/
def GoogleClient.fromEnv : IO (Option GoogleClient) := do
  match ← IO.getEnv "GOOGLE_CLIENT_ID", ← IO.getEnv "GOOGLE_CLIENT_SECRET" with
  | some id, some secret =>
    if id.isEmpty || secret.isEmpty then return none
    else return some { clientId := id, clientSecret := secret }
  | _, _ => return none

/-- Google's token endpoint host; the path is `/token`. -/
def googleTokenHost : String := "oauth2.googleapis.com"

/-- The `application/x-www-form-urlencoded` refresh body. Every value is
    percent-encoded (RFC 3986 unreserved set). -/
def refreshForm (client : GoogleClient) (refreshToken : String) : String :=
  "&".intercalate
    ([ ("grant_type", "refresh_token"), ("refresh_token", refreshToken)
     , ("client_id", client.clientId), ("client_secret", client.clientSecret) ].map
      (fun (k, v) => k ++ "=" ++ urlEncode v))

/-- What a successful refresh yields. -/
structure TokenResponse where
  accessToken  : String
  expiresIn    : Nat
  /-- Present only when Google rotated the refresh token. -/
  refreshToken : Option String

/-- Parse Google's token response: `access_token` (string), `expires_in`
    (JSON integer), optional `refresh_token` (string). -/
def parseTokenResponse (body : String) : Option TokenResponse := do
  let root ← (Data.Json.Decode.decode body).toOption
  let accessToken ← root.lookup "access_token" |>.bind Value.asString
  if accessToken.isEmpty then none
  let expiresIn ← root.lookup "expires_in" |>.bind jsonNat?
  let refreshToken := root.lookup "refresh_token" |>.bind Value.asString
  return { accessToken, expiresIn, refreshToken }

/-- `POST https://oauth2.googleapis.com/token`. `.error` (never a throw) on a
    transport failure, a non-2xx, or an unexpected body; the message never
    contains a token. -/
def refreshGoogle (client : GoogleClient) (refreshToken : String)
    : IO (Except String TokenResponse) := do
  let req : Network.HTTP.Client.Request :=
    { method := Method.standard .POST
      host := googleTokenHost, port := 443, path := "/token"
      headers := [ (hContentType, "application/x-www-form-urlencoded")
                 , (hAccept, "application/json") ]
      body := some (refreshForm client refreshToken).toUTF8
      isSecure := true }
  try
    let resp ← httpBS req
    if !resp.isSuccess then
      return .error s!"google token refresh failed: HTTP {resp.statusCode.statusCode}"
    match (String.fromUTF8? resp.body).bind parseTokenResponse with
    | some t => return .ok t
    | none => return .error "google token refresh: unexpected response shape"
  catch e =>
    return .error s!"google token refresh failed: {e}"

end Liaison.Egress
