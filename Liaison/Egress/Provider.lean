/-
  Liaison.Egress.Provider — the only functions that can make an outbound
  call.

  `callProvider` and `callInference` both take a `Reserved r`, and there is
  no other way to obtain one (`Liaison.Budget.Reserved` has no public
  constructor other than `withReservation`). This is the chokepoint
  property `broker.md` §6 describes as "held by typing rather than by
  review" — no outbound call is reachable without a verified warrant and a
  reserved budget.

  `callProvider` implements `typednotes/typednotes`'s `docs/connections.md`
  §5 (0.3.0): fetch the typed credential, refuse caller headers the policy
  forbids, keep the URL under the credential's `base_url`, refresh a Google
  token when due, attach the credential (bearer / header / SigV4), send the
  caller's headers and body. **It never throws**: every failure is a
  `Denial` (`credentialUnavailable`, `headerDenied`, `urlDenied`,
  `upstreamFailed`), so `Server.lean` always gets a value to audit.
-/

import Liaison.Budget
import Liaison.Clock
import Liaison.Egress.Secrets
import Liaison.Egress.Policy
import Liaison.Egress.Google
import Liaison.Egress.S3
import Linen.Network.HTTP.Simple

namespace Liaison.Egress

open Network.HTTP.Client
open Network.HTTP.Types
open Network.HTTP.Simple
open Liaison (Reserved Response Denial)

/-- Everything `callProvider` needs from the environment. Never printable. -/
structure EgressConfig where
  secrets : SecretsConfig
  /-- `none` when `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` are unset: a
      `google_oauth` credential still works until its token is due, and a
      due refresh is `credential_unavailable`. -/
  google  : Option GoogleClient

/-- `SecretsConfig.fromEnv` (fails loudly) and `GoogleClient.fromEnv`
    (optional). -/
def EgressConfig.fromEnv : IO EgressConfig := do
  let secrets ← SecretsConfig.fromEnv
  let google ← GoogleClient.fromEnv
  if google.isNone then
    IO.eprintln "liaison: GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET unset; google_oauth refresh disabled"
  return { secrets, google }

/-- A parsed `"call": {"kind": "provider", …}` (`connections.md` §5). -/
structure ProviderCall where
  /-- `{user_id}/{connection_id}`; checked by `Policy.accountMatchesResource`
      in `Server.lean` before any reservation. -/
  account : String
  /-- Uppercase letters only (checked by `Server.lean`). -/
  method  : String
  url     : String
  /-- Caller headers, in order. -/
  headers : List (String × String) := []
  /-- UTF-8 body. -/
  body    : Option String := none

/-- The authentication headers of a non-S3 credential: `Authorization:
    Bearer …` for `bearer`/`google_oauth`, `{header}: {token}` for `header`.
    `none` for `s3`, which is signed per request (`S3.s3AuthHeaders`). -/
def staticAuthHeaders : CredentialAuth → Option (List (String × String))
  | .bearer token => some [("Authorization", s!"Bearer {token}")]
  | .header h token => some [(h, token)]
  | .googleOauth access _ _ => some [("Authorization", s!"Bearer {access}")]
  | .s3 _ _ _ => none

/-- A `google_oauth` credential whose token is due is refreshed and the
    updated credential written back (best-effort: a write-back failure is
    logged to stderr, not fatal). Any other credential, or a token not yet
    due, is returned as is. `.error` when a refresh is due but impossible
    (no Google client configured) or fails. -/
private def ensureFresh (cfg : EgressConfig) (provider : Provider) (account : String)
    (cred : Credential) : IO (Except String Credential) := do
  match cred.auth with
  | .googleOauth _ refreshToken expiresAt =>
    let now ← nowUnixSeconds
    if !needsRefresh expiresAt now then return .ok cred
    let some client := cfg.google
      | return .error "google_oauth token is due but GOOGLE_CLIENT_ID/SECRET are unset"
    match ← refreshGoogle client refreshToken with
    | .error e => return .error e
    | .ok t =>
      let updated := cred.refreshed t.accessToken (now + t.expiresIn) t.refreshToken
      match ← writeCredential cfg.secrets provider account updated with
      | .ok () => pure ()
      | .error e =>
        IO.eprintln s!"liaison: refreshed {provider.value} token not written back: {e}"
      return .ok updated
  | _ => return .ok cred

/-- Build the outbound request: the caller's method, the checked target, the
    credential's static headers, the caller's headers, the credential's
    authentication, and the body. `none` only if an S3 target cannot be
    canonicalised (reported as `urlDenied`). -/
private def buildRequest (cred : Credential) (call : ProviderCall) (target : Target)
    : IO (Option Network.HTTP.Client.Request) := do
  let body := (call.body.map String.toUTF8).getD ByteArray.empty
  let base : Network.HTTP.Client.Request :=
    { method := parseMethod call.method
      host := target.host
      port := target.port
      path := target.path
      queryString := if target.query.isEmpty then "" else "?" ++ target.query
      body := call.body.map String.toUTF8
      isSecure := target.isSecure }
  let plain := cred.headers ++ call.headers
  let toHeaders (hs : List (String × String)) : RequestHeaders :=
    hs.map (fun (n, v) => (Data.CI.mk' n, v))
  match staticAuthHeaders cred.auth with
  | some auth =>
    return some { base with headers := toHeaders (plain ++ auth) }
  | none =>
    match cred.auth, s3Canonical target with
    | .s3 region keyId secret, some p =>
      let now ← Data.Time.getCurrentTime
      let auth ← s3AuthHeaders region keyId secret now call.method target.authority
        p.decodedPath p.query body
      return some { base with
        path := p.wirePath
        queryString := if p.wireQuery.isEmpty then "" else "?" ++ p.wireQuery
        headers := toHeaders (plain ++ auth) }
    | _, _ => return none

/-- The generic third-party egress call (`connections.md` §5). The fetched
    credential is used to build the outbound request here and is **never**
    returned — this function's result carries only a `Liaison.Response` or a
    `Denial`, so there is no path for it to reach `Server.lean`'s response or
    the audit log. Never throws. -/
def callProvider {r : Liaison.Request} (cfg : EgressConfig) (call : ProviderCall)
    (_reserved : Reserved r) : IO (Except Denial (Response × Liaison.Credits)) := do
  match ← fetchCredential cfg.secrets r.provider call.account with
  | .error e =>
    IO.eprintln s!"liaison: credential {r.provider.value}/{call.account} unavailable: {e}"
    return .error .credentialUnavailable
  | .ok cred =>
    if !checkCallerHeaders cred.setHeaderNames call.headers then
      return .error .headerDenied
    let some target := checkUrl cred.baseUrl call.url
      | return .error .urlDenied
    match ← ensureFresh cfg r.provider call.account cred with
    | .error e =>
      IO.eprintln s!"liaison: credential {r.provider.value}/{call.account} unusable: {e}"
      return .error .credentialUnavailable
    | .ok cred =>
      let req? ← try buildRequest cred call target
        catch e =>
          IO.eprintln s!"liaison: signing failed: {e}"
          return .error .credentialUnavailable
      let some req := req? | return .error .urlDenied
      let resp? ← try pure (some (← httpBS req))
        catch e =>
          IO.eprintln s!"liaison: upstream {target.host} unreachable: {e}"
          pure none
      let some resp := resp? | return .error .upstreamFailed
      let out : Response :=
        { status := resp.statusCode.statusCode.toUInt16
          headers := resp.headers.map (fun (n, v) => (toString n, v))
          body := resp.body }
      -- Charges the warrant's full authorized cost regardless of what the
      -- call actually consumed — no per-call cost model exists yet for
      -- generic HTTP egress. Named in `AGENTS.md`'s "Not yet implemented".
      return .ok (out, r.cost)

/-- **Loud, structured-denial stub.** Inference routing (`broker.md` §8:
    "where does inference routing live") is explicitly out of scope for v0.
    This function type-checks, is wired into `Server.lean`'s routing, and
    unconditionally denies — never a silent success, never a bare
    `sorry`/`panic!`. `LiaisonTests/Liaison/Egress/ProviderTest.lean` pins its
    type and documents (by inspection, not by test — see that file) that it
    never returns `.ok`. -/
def callInference {r : Liaison.Request} (_reserved : Reserved r)
    : IO (Except Denial (Response × Liaison.Credits)) :=
  return .error .inferenceNotImplemented

end Liaison.Egress
