/-
  Liaison.Egress.Provider — the only functions that can make an outbound
  call.

  `callConnector`, `callProvider` and `callInference` take a `Reserved r`, and there is
  no other way to obtain one (`Liaison.Budget.Reserved` has no public
  constructor other than `withReservation`). This is the chokepoint
  property `broker.md` §6 describes as "held by typing rather than by
  review" — no outbound call is reachable without a verified warrant and a
  reserved budget.

  Native `callConnector` intersects independently stored organization,
  connection, cell and warrant ceilings, prepares a typed native transport,
  and resolves provider-owned relationships before credentialed execution.
  The credential remains private to this module. Raw `callProvider` calls
  unconditionally refuse; there is no legacy URL/method escape hatch.
  See `docs/connector-permissions.md` for selector semantics and the trusted
  remote API correspondence boundary.
-/

import Liaison.Budget
import Liaison.Wire
import Liaison.Clock
import Liaison.Egress.Secrets
import Liaison.Egress.Policy
import Liaison.Egress.OAuth
import Liaison.Egress.S3
import Liaison.Egress.Connector
import Liaison.Egress.GitPack
import Linen.Network.HTTP.Simple

namespace Liaison.Egress

open Network.HTTP.Client
open Network.HTTP.Types
open Network.HTTP.Simple
open Liaison (Reserved Denial)
open Liaison.Wire (ProviderCall)

/-- Everything `callProvider` needs from the environment. Never printable. -/
structure EgressConfig where
  secrets : SecretsConfig
  /-- One client per OAuth issuer, each `none` when its
      `{GOOGLE,DROPBOX,GITLAB,MICROSOFT}_CLIENT_ID`/`_CLIENT_SECRET` are unset: that
      issuer's credentials still work until their token is due, and a due
      refresh is `credential_unavailable`. -/
  oauth   : OAuthClients

/-- `SecretsConfig.fromEnv` (fails loudly) and `OAuthClients.fromEnv`
    (each optional). -/
def EgressConfig.fromEnv : IO EgressConfig := do
  let secrets ← SecretsConfig.fromEnv
  let oauth ← OAuthClients.fromEnv
  for issuer in [OAuthIssuer.google, .dropbox, .gitlab, .microsoft] do
    if (oauth.get issuer).isNone then
      IO.eprintln s!"liaison: {issuer.envPrefix}_CLIENT_ID/{issuer.envPrefix}_CLIENT_SECRET unset; {issuer.kindName} refresh disabled"
  return { secrets, oauth }

/-- The authentication headers of a non-S3 credential: `Authorization:
    Bearer …` for `bearer` and the OAuth kinds, `{header}: {token}` for
    `header`, none for `azure_sas` (whose signature is in the query, see
    `buildRequest`). `none` for `s3`, which is signed per request
    (`S3.s3AuthHeaders`). -/
def staticAuthHeaders : CredentialAuth → Option (List (String × String))
  | .bearer token => some [("Authorization", s!"Bearer {token}")]
  | .header h token => some [(h, token)]
  | .oauth _ access _ _ => some [("Authorization", s!"Bearer {access}")]
  | .azureSas _ => some []
  | .s3 _ _ _ => none

/-- The query the credential appends to every call: an Azure SAS. -/
def credentialQuery : CredentialAuth → String
  | .azureSas sas => sas
  | _ => ""

/-- An OAuth credential whose token is due is refreshed at its issuer and
    the updated credential written back (best-effort: a write-back failure
    is logged to stderr, not fatal — but GitLab rotates its refresh token,
    so such a connection must then be reconnected). Any other credential,
    or a token not yet due, is returned as is. `.error` when a refresh is
    due but impossible (no client configured for the issuer) or fails. -/
private def ensureFresh (cfg : EgressConfig) (provider : Provider) (account : String)
    (cred : Credential) : IO (Except String Credential) := do
  match cred.auth with
  | .oauth issuer _ refreshToken' expiresAt =>
    let now ← nowUnixSeconds
    if !needsRefresh expiresAt now then return .ok cred
    let some client := cfg.oauth.get issuer
      | return .error s!"{issuer.kindName} token is due but {issuer.envPrefix}_CLIENT_ID/SECRET are unset"
    match ← refreshToken issuer client refreshToken' with
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
      queryString :=
        let q := appendQuery target.query (credentialQuery cred.auth)
        if q.isEmpty then "" else "?" ++ q
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

/- The generic third-party egress call (`connections.md` §5). The fetched
    credential is used to build the outbound request here and is **never**
    returned — this function's result carries only a `Wire.Response` or a
    `Denial`, so there is no path for it to reach `Server.lean`'s response or
    the audit log. Never throws. -/
/-- Bound the HTTP parser's cumulative wire input as well as the final body.
    The extra 64 KiB permits headers/chunk framing. Redirects are not followed.
    Clipping each read prevents an upstream Content-Length from controlling a
    socket allocation. The socket/TLS reader remains a native trusted boundary. -/
private def boundedHttp (req : Network.HTTP.Client.Request) (limit : Nat) :
    IO (Except Denial Network.HTTP.Client.Response) := do
  let exceeded ← IO.mkRef false
  let readBytes ← IO.mkRef (0 : Nat)
  let conn ← connect req.host req.port req.isSecure req.timeoutMillis
  let guarded := { conn with connRead := fun count => do
    let used ← readBytes.get
    let remaining := limit + 65536 - used
    let chunk ← conn.connRead (min count (min 8192 (remaining + 1)))
    if chunk.size > remaining then
      exceeded.set true
      throw (IO.userError "connector response exceeds its wire limit")
    readBytes.set (used + chunk.size)
    return chunk }
  try
    let response ← performRequest guarded req
    if response.body.size > limit then return .error .capabilityDenied
    return .ok response
  catch _ =>
    let tooLarge ← exceeded.get
    return .error (if tooLarge then .capabilityDenied else .upstreamFailed)
  finally
    conn.connClose

private def sendWithCredential {r : Liaison.Request} (_cfg : EgressConfig) (cred : Credential) (call : ProviderCall)
    (responseLimit : Nat)
    (_reserved : Reserved r) : IO (Except Denial (Wire.Response × Liaison.Credits)) := do
  unless cred.headers.all (fun (name, value) => validHeaderName name && validHeaderValue value) do return .error .credentialUnavailable
  unless ((staticAuthHeaders cred.auth).getD []).all (fun (name, value) => validHeaderName name && validHeaderValue value) do return .error .credentialUnavailable
  if !checkCallerHeaders cred.setHeaderNames call.headers then return .error .headerDenied
  let some target := checkUrl cred.baseUrl call.url | return .error .urlDenied
  if !checkCallerQuery (reservedQueryKeys cred.auth) target.query then return .error .urlDenied
  let req? ← try buildRequest cred call target
    catch _ => return .error .credentialUnavailable
  let some req := req? | return .error .urlDenied
  let result ← try boundedHttp req responseLimit catch _ => pure (.error .upstreamFailed)
  let resp ← match result with
    | .error denial => return .error denial
    | .ok resp => pure resp
  let out : Wire.Response :=
    { status := resp.statusCode.statusCode.toUInt16
      headers := resp.headers.map (fun (n, v) => (toString n, v)), body := resp.body }
  return .ok (out, r.cost)

/-- Raw legacy calls cannot bypass native authority, even when the connection
    policy is absent. Typed calls derive transport from a named operation. -/
def callProvider {r : Liaison.Request} (_cfg : EgressConfig) (_call : ProviderCall)
    (_reserved : Reserved r) : IO (Except Denial (Wire.Response × Liaison.Credits)) :=
  -- A generic method/URL does not identify a scoped native operation. Even a
  -- GET can disclose other folders or execute an RPC with write effects.
  return .error .capabilityDenied

private def metadata {r : Liaison.Request} (cfg : EgressConfig) (cred : Credential)
    (account path : String) (limit : Nat) (reserved : Reserved r) :
    IO (Except Denial (Lean.Json × Option String)) := do
  match ← sendWithCredential cfg cred { account, method := "GET", url := cred.baseUrl ++ path } (min limit 65536) reserved with
  | .error denial => return .error denial
  | .ok (response, _) =>
    unless response.status == 200 && response.body.size ≤ min limit 65536 do return .error .resourceDenied
    let some text := String.fromUTF8? response.body | return .error .resourceDenied
    let .ok json := Connector.parseJson text | return .error .resourceDenied
    return .ok (json, response.header? "etag")

private def jmapMetadata {r : Liaison.Request} (cfg : EgressConfig) (cred : Credential)
    (account method : String) (args : Lean.Json) (requestLimit responseLimit : Nat) (reserved : Reserved r) :
    IO (Except Denial Lean.Json) := do
  let body := (Connector.jmapBody [Connector.jmapMethod method args]
    (if method == "Identity/get" then ["urn:ietf:params:jmap:submission"] else [])).compress
  if body.toUTF8.size > requestLimit then return .error .capabilityDenied
  let call : ProviderCall :=
    { account, method := "POST", url := cred.baseUrl
      headers := [("content-type", "application/json")], body := some body }
  match ← sendWithCredential cfg cred call (min responseLimit 65536) reserved with
  | .error denial => return .error denial
  | .ok (response, _) =>
    unless response.status == 200 && response.body.size ≤ min responseLimit 65536 do return .error .resourceDenied
    let some text := String.fromUTF8? response.body | return .error .resourceDenied
    let .ok json := Connector.parseJson text | return .error .resourceDenied
    let .ok result := Connector.jmapResult json method (args.getObjValAs? String "accountId" |>.toOption.getD "")
      | return .error .resourceDenied
    return .ok result

/-- After resolving provider-owned relationships, execution still consumes a
    private typed witness bound to the original prepared operation. Resolver
    rewrites cannot change method/account, escape the fixed provider origin,
    or exceed any request ceiling. Native metadata and conditions are the
    explicit trusted correspondence boundary with the remote service. -/
private structure Resolved {authority : Control.Monad.Effect.Connector.Authority}
    {operation : String} (prepared : Connector.Prepared authority operation) where
  mk ::
  transport : ProviderCall
  accountBound : transport.account = prepared.transport.account
  methodBound : transport.method = prepared.transport.method
  target : Target
  originBound : checkUrl (Connector.transportBase authority.cell.provider operation prepared.base) transport.url = some target
  bodyBound : ((transport.body.map String.toUTF8).getD ByteArray.empty).size ≤ authority.maxRequestBytes

private def resolved? {authority : Control.Monad.Effect.Connector.Authority} {operation : String}
    (prepared : Connector.Prepared authority operation) (transport : ProviderCall) : Option (Resolved prepared) :=
  if ha : transport.account = prepared.transport.account then
    if hm : transport.method = prepared.transport.method then
      match ht : checkUrl (Connector.transportBase authority.cell.provider operation prepared.base) transport.url with
      | none => none
      | some target =>
        if hb : ((transport.body.map String.toUTF8).getD ByteArray.empty).size ≤ authority.maxRequestBytes then
          some ⟨transport, ha, hm, target, ht, hb⟩ else none
    else none
  else none

private def jsonResponse (value : Lean.Json) : Wire.Response :=
  { status := 200, headers := [("content-type", "application/json")], body := value.compress.toUTF8 }

/-- Fixed native repository requests. The caller cannot supply any path/header
    here; every invocation is part of the private Prepared repository program. -/
private def repoReply {r : Liaison.Request} (cfg : EgressConfig) (cred : Credential)
    (account method path : String) (body : Option Lean.Json) (requestLimit responseLimit : Nat) (reserved : Reserved r) :
    IO (Except Denial Wire.Response) := do
  let body := body.map Lean.Json.compress
  if ((body.map String.toUTF8).getD ByteArray.empty).size > requestLimit then return .error .capabilityDenied
  let call : ProviderCall :=
    { account, method, url := cred.baseUrl ++ path
      headers := [("accept", "application/json")] ++ (if body.isSome then [("content-type", "application/json")] else [])
      body }
  match ← sendWithCredential cfg cred call responseLimit reserved with
  | .error denial => return .error denial
  | .ok (response, _) => return .ok response

private def repoJson {r : Liaison.Request} (cfg : EgressConfig) (cred : Credential)
    (account method path : String) (body : Option Lean.Json) (requestLimit responseLimit : Nat) (reserved : Reserved r) :
    IO (Except Denial Lean.Json) := do
  match ← repoReply cfg cred account method path body requestLimit responseLimit reserved with
  | .error denial => return .error denial
  | .ok response =>
    unless [200, 201].contains response.status do return .error .resourceDenied
    let some text := String.fromUTF8? response.body | return .error .resourceDenied
    return (Connector.parseJson text).mapError (fun _ => .resourceDenied)

private def repoTree {r : Liaison.Request} (cfg : EgressConfig) (cred : Credential)
    (account provider repo revision : String) (requestLimit responseLimit : Nat) (reserved : Reserved r) :
    IO (Except Denial (String × List Lean.Json)) := do
  if provider == "github" then
    let json ← match ← repoJson cfg cred account "GET" (repo ++ "/git/commits/" ++ revision) none requestLimit responseLimit reserved with
      | .error denial => return .error denial | .ok json => pure json
    unless (json.getObjValAs? String "sha").toOption == some revision do return .error .resourceDenied
    let .ok tree := json.getObjVal? "tree" >>= fun tree => tree.getObjValAs? String "sha" | return .error .resourceDenied
    unless Repository.commit tree do return .error .resourceDenied
    let json ← match ← repoJson cfg cred account "GET" (repo ++ "/git/trees/" ++ tree ++ "?recursive=1") none requestLimit responseLimit reserved with
      | .error denial => return .error denial | .ok json => pure json
    match Repository.normalizeTree provider json with
    | .error _ => return .error .resourceDenied | .ok entries => return .ok (tree, entries)
  else
    let mut entries : List Lean.Json := []
    let mut total := 0
    for page in [1:102] do
      let response ← match ← repoReply cfg cred account "GET"
          (repo ++ "/repository/tree?ref=" ++ revision ++ s!"&recursive=true&per_page=100&page={page}") none requestLimit responseLimit reserved with
        | .error denial => return .error denial | .ok response => pure response
      unless response.status == 200 do return .error .resourceDenied
      total := total + response.body.size
      unless total ≤ responseLimit do return .error .capabilityDenied
      let some text := String.fromUTF8? response.body | return .error .resourceDenied
      let .ok values := Connector.parseJson text >>= Lean.Json.getArr? | return .error .resourceDenied
      unless values.size ≤ 100 do return .error .resourceDenied
      entries := entries ++ values.toList
      match response.header? "x-next-page" with
      | some next =>
        if !next.isEmpty then
          unless next == toString (page + 1) do return .error .resourceDenied
          continue
      | none =>
        -- Without authoritative pagination metadata, a full page is ambiguous.
        if values.size == 100 then return .error .resourceDenied
      match Repository.normalizeTree provider (Lean.Json.arr entries.toArray) with
      | .error _ => return .error .resourceDenied | .ok normalized => return .ok ("", normalized)
    return .error .resourceDenied

private def githubPublish {r : Liaison.Request} {authority : Control.Monad.Effect.Connector.Authority}
    {policy : Repository.PublicationPolicy} {payload : Lean.Json} (cfg : EgressConfig) (cred : Credential)
    (account repo : String) (resource : List String) (authorized : Repository.AuthorizedPlan authority resource policy payload) (built : GitPack.Built)
    (baseTree : String) (requestLimit responseLimit : Nat) (reserved : Reserved r) : IO (Except Denial String) := do
  let plan := authorized.plan
  let metadata ← match ← repoJson cfg cred account "GET" repo none requestLimit responseLimit reserved with
    | .error denial => return .error denial | .ok json => pure json
  let .ok repositoryId := metadata.getObjValAs? String "node_id" | return .error .resourceDenied
  unless (metadata.getObjValAs? String "full_name").toOption == some (resource[0]! ++ "/" ++ resource[1]!) do return .error .resourceDenied
  let entries := plan.changes.map fun change => Lean.Json.mkObj ([
    ("path", .str ("/".intercalate (resource.drop 2 ++ change.resource))),
    ("mode", .str (if change.delete then "100644" else change.mode)), ("type", .str "blob")] ++
    (if change.delete then [("sha", .null)] else [("content", .str (change.contents.getD ""))]))
  let tree ← match ← repoJson cfg cred account "POST" (repo ++ "/git/trees")
      (some (Lean.Json.mkObj [("base_tree", .str baseTree), ("tree", Lean.toJson entries)])) requestLimit responseLimit reserved with
    | .error denial => return .error denial | .ok json => pure json
  unless (tree.getObjValAs? String "sha").toOption == some built.root.id do return .error .resourceDenied
  let commit ← match ← repoJson cfg cred account "POST" (repo ++ "/git/commits")
      (some (Lean.Json.mkObj [("message", .str plan.message), ("tree", .str built.root.id), ("parents", Lean.toJson [plan.expectedHead])])) requestLimit responseLimit reserved with
    | .error denial => return .error denial | .ok json => pure json
  let .ok next := commit.getObjValAs? String "sha" | return .error .resourceDenied
  let .ok parents := commit.getObjValAs? (List Lean.Json) "parents" | return .error .resourceDenied
  unless Repository.commit next && parents.length == 1 &&
      (parents[0]!.getObjValAs? String "sha").toOption == some plan.expectedHead &&
      (commit.getObjVal? "tree" >>= fun value => value.getObjValAs? String "sha").toOption == some built.root.id do return .error .resourceDenied
  let result ← match ← repoJson cfg cred account "POST" "/graphql"
      (some (Repository.githubPublish repositoryId plan.branch plan.expectedHead next)) requestLimit responseLimit reserved with
    | .error denial => return .error denial | .ok json => pure json
  unless (result.getObjVal? "errors").toOption.isNone &&
      (result.getObjVal? "data" >>= fun value => value.getObjVal? "updateRefs").isOk do return .error .resourceDenied
  return .ok next

/-- GitLab REST lacks an exact-head mutation. Its fixed same-host smart-HTTP
    route uses Git's mandatory old-OID reference compare-and-swap instead.
    This is a typed publication program, not a caller-accessible raw Git API. -/
private def gitlabPublish {r : Liaison.Request} {authority : Control.Monad.Effect.Connector.Authority}
    {policy : Repository.PublicationPolicy} {payload : Lean.Json} (cred : Credential) (resource : List String)
    (authorized : Repository.AuthorizedPlan authority resource policy payload) (built : GitPack.Built) (requestLimit responseLimit : Nat) (_reserved : Reserved r) :
    IO (Except Denial String) := do
  let plan := authorized.plan
  let token ← match cred.auth with
    | .oauth .gitlab access _ _ | .bearer access => pure access
    | .header name token => if name.toLower == "private-token" then pure token else return .error .credentialUnavailable
    | _ => return .error .credentialUnavailable
  let base := if cred.baseUrl.endsWith "/api/v4" then (cred.baseUrl.dropEnd 7).toString else cred.baseUrl
  let path := "/" ++ Connector.encodeComponent resource[0]! ++ "/" ++ Connector.encodeComponent resource[1]! ++ ".git"
  let auth := "Basic " ++ Data.Base64.encode ("oauth2:" ++ token).toUTF8
  let request (method path : String) (body : Option ByteArray) : Option Network.HTTP.Client.Request := do
    let target ← checkUrl base (base ++ path)
    unless validHeaderValue auth do none
    return { method := Network.HTTP.Types.parseMethod method
             host := target.host, port := target.port, isSecure := target.isSecure, path := target.path
             queryString := if target.query.isEmpty then "" else "?" ++ target.query
             headers := [(Data.CI.mk' "authorization", auth), (Data.CI.mk' "content-type", "application/x-git-receive-pack-request")]
             body }
  let some req := request "GET" (path ++ "/info/refs?service=git-receive-pack") none | return .error .urlDenied
  let response ← match ← boundedHttp req (min responseLimit 1048576) with
    | .error denial => return .error denial | .ok response => pure response
  unless response.statusCode.statusCode == 200 do return .error .resourceDenied
  let some text := String.fromUTF8? response.body | return .error .resourceDenied
  unless (GitPack.advertised text plan.branch plan.expectedHead).isOk do return .error .resourceDenied
  let packed ← GitPack.pack built
  let body := GitPack.publicationBody built plan.branch packed
  if body.size > requestLimit then return .error .capabilityDenied
  let some req := request "POST" (path ++ "/git-receive-pack") (some body) | return .error .urlDenied
  let response ← match ← boundedHttp req responseLimit with
    | .error denial => return .error denial | .ok response => pure response
  unless response.statusCode.statusCode == 200 && GitPack.published ((String.fromUTF8? response.body).getD "") plan.branch do return .error .resourceDenied
  return .ok built.commit.id

private def repositoryCall {r : Liaison.Request} {authority : Control.Monad.Effect.Connector.Authority} {operation : String}
    (cfg : EgressConfig) (cred : Credential) (prepared : Connector.Prepared authority operation) (reserved : Reserved r) :
    IO (Except Denial (Wire.Response × Liaison.Credits)) := do
  let .ok payload := Connector.parseJson prepared.payload | return .error .capabilityDenied
  let some view := Repository.view payload | return .error .capabilityDenied
  let resource := prepared.resource.resource
  let provider := authority.cell.provider
  let repo := Repository.apiPath provider resource
  let account := prepared.account
  let response ← if view == "tree" then do
    let .ok revision := payload.getObjValAs? String "ref" | return .error .capabilityDenied
    match ← repoTree cfg cred account provider repo revision authority.maxRequestBytes authority.maxResponseBytes reserved with
    | .error denial => return .error denial
    | .ok (_, entries) => pure (jsonResponse (Lean.Json.mkObj [("truncated", .bool false), ("tree", Lean.toJson entries)]))
    else if view == "commit" then do
      let some policy := prepared.publication | return .error .capabilityDenied
      let .ok authorized := Repository.authorize authority resource policy payload | return .error .resourceDenied
      let plan := authorized.plan
      let branchPath := repo ++ (if provider == "github" then "/branches/" else "/repository/branches/") ++ Connector.encodeComponent plan.branch
      let branch ← match ← repoJson cfg cred account "GET" branchPath none authority.maxRequestBytes authority.maxResponseBytes reserved with
        | .error denial => return .error denial | .ok branch => pure branch
      unless (branch.getObjVal? "commit" >>= fun value => value.getObjValAs? String (if provider == "github" then "sha" else "id")).toOption == some plan.expectedHead do return .error .resourceDenied
      let (baseTree, entries) ← match ← repoTree cfg cred account provider repo plan.expectedHead authority.maxRequestBytes authority.maxResponseBytes reserved with
        | .error denial => return .error denial | .ok tree => pure tree
      let timestamp ← nowUnixSeconds
      let .ok built := GitPack.build entries (resource.drop 2) plan timestamp | return .error .resourceDenied
      let next ← match ← (if provider == "github" then githubPublish cfg cred account repo resource authorized built baseTree authority.maxRequestBytes authority.maxResponseBytes reserved
          else gitlabPublish cred resource authorized built authority.maxRequestBytes authority.maxResponseBytes reserved) with
        | .error denial => return .error denial | .ok next => pure next
      pure (jsonResponse (Lean.Json.mkObj [("commit", .str next)]))
    else do
      let response ← match ← repoReply cfg cred account prepared.transport.method
          ((prepared.transport.url.drop cred.baseUrl.length).toString) none authority.maxRequestBytes authority.maxResponseBytes reserved with
        | .error denial => return .error denial | .ok response => pure response
      if response.status == 200 then
        let some text := String.fromUTF8? response.body | return .error .resourceDenied
        let .ok json := Connector.parseJson text | return .error .resourceDenied
        if view == "branch" then
          let .ok revision := json.getObjVal? "commit" >>= fun value => value.getObjValAs? String (if provider == "github" then "sha" else "id") | return .error .resourceDenied
          unless Repository.commit revision && (json.getObjValAs? String "name").toOption == (payload.getObjValAs? String "ref").toOption do return .error .resourceDenied
        else if view == "ancestry" then
          if provider == "github" then
            unless [some "behind", some "identical"].contains (json.getObjValAs? String "status").toOption do return .error .resourceDenied
          else unless (json.getObjValAs? String "id").toOption == (payload.getObjValAs? String "ref").toOption do return .error .resourceDenied
      pure response
  unless response.body.size ≤ authority.maxResponseBytes do return .error .capabilityDenied
  return .ok (response, r.cost)

/-- Provider-owned relationships are resolved with the same credential snapshot
    as execution, never by trusting caller-supplied ancestry or label IDs. -/
private def resolve {r : Liaison.Request} {authority : Control.Monad.Effect.Connector.Authority}
    {operation : String} (cfg : EgressConfig) (cred : Credential)
    (prepared : Connector.Prepared authority operation) (reserved : Reserved r) :
    IO (Except Denial (Resolved prepared)) := do
  let resource := prepared.resource.resource
  let mut transport := prepared.transport
  let provider := authority.cell.provider
  if provider == "gdrive" then
    let ancestry := if operation == "files.share" then resource.take (resource.length - 1) else resource
    -- Direct parent membership can be guarded by the child's ETag. A longer
    -- mutable ancestor chain has no atomic native condition and is refused.
    unless ancestry.length ≤ 2 do return .error .resourceDenied
    if ["files.list", "files.create"].contains operation && ancestry.length != 1 then return .error .resourceDenied
    if ancestry.length == 2 then
      let path := "/drive/v3/files/" ++ Connector.encodeComponent ancestry[1]! ++ "?fields=id,parents,mimeType"
      match ← metadata cfg cred transport.account path authority.maxResponseBytes reserved with
      | .error denial => return .error denial
      | .ok (json, etag) =>
        unless (json.getObjValAs? String "id").toOption == some ancestry[1]! do return .error .resourceDenied
        let .ok parents := json.getObjValAs? (List String) "parents" | return .error .resourceDenied
        unless parents.contains ancestry[0]! do return .error .resourceDenied
        if ["files.delete", "files.share"].contains operation then
          let .ok mime := json.getObjValAs? String "mimeType" | return .error .resourceDenied
          if mime == "application/vnd.google-apps.folder" then return .error .resourceDenied
        let some etag := etag | return .error .resourceDenied
        unless strongEtag etag do return .error .resourceDenied
        transport := { transport with headers := ("if-match", etag) :: transport.headers }
    if ["files.delete", "files.share"].contains operation && ancestry.length == 1 then
      let path := "/drive/v3/files/" ++ Connector.encodeComponent ancestry.getLast! ++ "?fields=id,mimeType"
      match ← metadata cfg cred transport.account path authority.maxResponseBytes reserved with
      | .error denial => return .error denial
      | .ok (json, etag) =>
        unless (json.getObjValAs? String "id").toOption == some ancestry.getLast! do return .error .resourceDenied
        let .ok mime := json.getObjValAs? String "mimeType" | return .error .resourceDenied
        if mime == "application/vnd.google-apps.folder" then return .error .resourceDenied
        let some etag := etag | return .error .resourceDenied
        unless strongEtag etag do return .error .resourceDenied
        transport := { transport with headers := ("if-match", etag) :: (transport.headers.filter (fun h => h.1 != "if-match")) }
  if provider == "github" && operation == "repositories.read" then
    let .ok payload := Lean.Json.parse prepared.payload | return .error .capabilityDenied
    let .ok revision := payload.getObjValAs? String "ref" | return .error .capabilityDenied
    let path := "/repos/" ++ Connector.encodeComponent resource[0]! ++ "/" ++ Connector.encodeComponent resource[1]! ++
      "/git/trees/" ++ Connector.encodeComponent revision ++ "?recursive=1"
    match ← metadata cfg cred transport.account path authority.maxResponseBytes reserved with
    | .error denial => return .error denial
    | .ok (json, _) =>
      unless (json.getObjValAs? Bool "truncated").toOption == some false do return .error .resourceDenied
      let .ok tree := json.getObjValAs? (List Lean.Json) "tree" | return .error .resourceDenied
      let filePath := "/".intercalate (resource.drop 2)
      let some entry := tree.find? (fun entry => (entry.getObjValAs? String "path").toOption == some filePath)
        | return .error .resourceDenied
      unless (entry.getObjValAs? String "type").toOption == some "blob" do return .error .resourceDenied
      let .ok sha := entry.getObjValAs? String "sha" | return .error .resourceDenied
      unless (sha.length == 40 || sha.length == 64) && sha.all (fun c => c.isDigit || "abcdef".toList.contains c) do return .error .resourceDenied
      -- Read the immutable Git blob, not /contents (which follows symlinks).
      transport := { transport with url := cred.baseUrl ++ "/repos/" ++ Connector.encodeComponent resource[0]! ++ "/" ++ Connector.encodeComponent resource[1]! ++ "/git/blobs/" ++ sha }
  if provider == "notion" && operation == "databases.query" then
    -- The application stores Notion-Version 2026-03-11. Database containers
    -- no longer have a query endpoint: resolve only a provider-owned source.
    let path := "/databases/" ++ Connector.encodeComponent resource[0]!
    match ← metadata cfg cred transport.account path authority.maxResponseBytes reserved with
    | .error denial => return .error denial
    | .ok (json, _) =>
      unless (json.getObjValAs? String "id").toOption == some resource[0]! do return .error .resourceDenied
      let .ok sources := json.getObjValAs? (List Lean.Json) "data_sources" | return .error .resourceDenied
      let source ← if resource.length == 2 then pure resource[1]! else
        match sources with
        | [source] => match source.getObjValAs? String "id" with
          | .ok id => pure id
          | .error _ => return .error .resourceDenied
        | _ => return .error .resourceDenied
      unless Wire.validResource [source] && sources.any (fun entry => (entry.getObjValAs? String "id").toOption == some source) do return .error .resourceDenied
      transport := { transport with url := cred.baseUrl ++ "/data_sources/" ++ Connector.encodeComponent source ++ "/query" }
  if provider == "dropbox" && operation == "files.delete" then
    let body := (Lean.Json.mkObj [("path", Lean.Json.str ("/" ++ "/".intercalate resource))]).compress
    if body.toUTF8.size > authority.maxRequestBytes then return .error .capabilityDenied
    let call : ProviderCall := { account := transport.account, method := "POST", url := cred.baseUrl ++ "/2/files/get_metadata", headers := [("content-type", "application/json")], body := some body }
    match ← sendWithCredential cfg cred call (min authority.maxResponseBytes 65536) reserved with
    | .error denial => return .error denial
    | .ok (response, _) =>
      unless response.status == 200 do return .error .resourceDenied
      let some text := String.fromUTF8? response.body | return .error .resourceDenied
      let .ok json := Connector.parseJson text | return .error .resourceDenied
      unless (json.getObjValAs? String ".tag").toOption == some "file" do return .error .resourceDenied
      let .ok revision := json.getObjValAs? String "rev" | return .error .resourceDenied
      unless !revision.isEmpty && revision.all (fun c => c.isDigit || "abcdef".toList.contains c) do return .error .resourceDenied
      unless (json.getObjValAs? String "path_lower").toOption == some ("/" ++ "/".intercalate resource).toLower do return .error .resourceDenied
      -- Path plus revision is atomic: a replacement folder cannot become a
      -- recursive delete, nor can an ID moved outside this path be deleted.
      transport := { transport with body := some (Lean.Json.mkObj [
        ("path", Lean.Json.str ("/" ++ "/".intercalate resource)), ("parent_rev", Lean.Json.str revision)]).compress }
  if provider == "caldav" && ["events.update", "events.delete"].contains operation then
    let call : ProviderCall := { account := transport.account, method := "GET", url := transport.url }
    match ← sendWithCredential cfg cred call (min authority.maxResponseBytes 65536) reserved with
    | .error denial => return .error denial
    | .ok (response, _) =>
      unless response.status == 200 do return .error .resourceDenied
      let some text := String.fromUTF8? response.body | return .error .resourceDenied
      let unfolded := (text.replace "\r\n " "").replace "\r\n\t" ""
      if ["ATTENDEE", "ORGANIZER", "METHOD:"].any (fun word => (unfolded.toUpper.splitOn word).length > 1) then return .error .resourceDenied
      unless response.header? "etag" == (transport.headers.find? (fun header => header.1 == "if-match")).map Prod.snd do return .error .resourceDenied
      if operation == "events.update" then
        let [uid] := (unfolded.splitOn "\r\n").filter (fun line => line.toUpper.startsWith "UID:") | return .error .resourceDenied
        let value := (uid.drop 4).toString
        unless !value.isEmpty && value.all (fun c => c.isAlphanum || "@._-".toList.contains c) do return .error .resourceDenied
        let some body := transport.body | return .error .capabilityDenied
        transport := { transport with body := some (body.replace ("UID:" ++ resource[1]! ++ "\r\n") ("UID:" ++ value ++ "\r\n")) }
  if provider == "gmail" && resource.length ≥ 3 &&
      ["messages.update", "messages.delete", "attachments.read"].contains operation then
    let path := "/gmail/v1/users/me/messages/" ++ Connector.encodeComponent resource[2]! ++ "?format=minimal"
    match ← metadata cfg cred transport.account path authority.maxResponseBytes reserved with
    | .error denial => return .error denial
    | .ok (json, _) =>
      unless (json.getObjValAs? String "id").toOption == some resource[2]! do return .error .resourceDenied
      let .ok labels := json.getObjValAs? (List String) "labelIds" | return .error .resourceDenied
      unless labels.contains resource[1]! do return .error .resourceDenied
      if operation == "messages.delete" then
        for label in labels do
          let some _ := Control.Monad.Effect.Connector.AuthorizedResource.check? authority operation ["me", label, resource[2]!]
            | return .error .resourceDenied
  if provider == "jmap" then
    if operation == "drafts.create" then
      let args := Lean.Json.mkObj [("accountId", Lean.Json.str resource[0]!), ("ids", Lean.toJson [resource[1]!])]
      match ← jmapMetadata cfg cred transport.account "Mailbox/get" args authority.maxRequestBytes authority.maxResponseBytes reserved with
      | .error denial => return .error denial
      | .ok result =>
        let .ok [mailbox] := result.getObjValAs? (List Lean.Json) "list" | return .error .resourceDenied
        unless (mailbox.getObjValAs? String "id").toOption == some resource[1]! &&
            (mailbox.getObjValAs? String "role").toOption == some "drafts" do return .error .resourceDenied
    else if resource.length ≥ 3 && operation != "messages.read" then
      let args := Lean.Json.mkObj [("accountId", Lean.Json.str resource[0]!), ("ids", Lean.toJson [resource[2]!]),
        ("properties", Lean.toJson ["id", "mailboxIds", "to", "cc", "bcc", "attachments"])]
      match ← jmapMetadata cfg cred transport.account "Email/get" args authority.maxRequestBytes authority.maxResponseBytes reserved with
      | .error denial => return .error denial
      | .ok result =>
        let .ok [message] := result.getObjValAs? (List Lean.Json) "list" | return .error .resourceDenied
        unless (message.getObjValAs? String "id").toOption == some resource[2]! do return .error .resourceDenied
        let .ok mailboxes := message.getObjVal? "mailboxIds" >>= Lean.Json.getObj? | return .error .resourceDenied
        unless (mailboxes.toList.find? (fun entry => entry.1 == resource[1]!)).map Prod.snd == some (Lean.Json.bool true) do return .error .resourceDenied
        if operation == "messages.delete" then
          for (mailbox, present) in mailboxes.toList do
            unless present == Lean.Json.bool true do return .error .resourceDenied
            let some _ := Control.Monad.Effect.Connector.AuthorizedResource.check? authority operation [resource[0]!, mailbox, resource[2]!]
              | return .error .resourceDenied
        if operation == "attachments.read" then
          let .ok attachments := message.getObjValAs? (List Lean.Json) "attachments" | return .error .resourceDenied
          unless attachments.any (fun attachment => (attachment.getObjValAs? String "blobId").toOption == some resource[3]!) do return .error .resourceDenied
        if operation == "messages.send" then
          let .ok [recipient] := message.getObjValAs? (List Lean.Json) "to" | return .error .resourceDenied
          unless (recipient.getObjValAs? String "email").toOption == some resource[3]! do return .error .resourceDenied
          for field in ["cc", "bcc"] do
            match message.getObjVal? field with
            | .ok (.null) => pure ()
            | .ok (.arr values) => unless values.isEmpty do return .error .resourceDenied
             | _ => return .error .resourceDenied
          let args := Lean.Json.mkObj [("accountId", Lean.Json.str resource[0]!), ("ids", Lean.toJson [resource[4]!])]
          match ← jmapMetadata cfg cred transport.account "Identity/get" args authority.maxRequestBytes authority.maxResponseBytes reserved with
          | .error denial => return .error denial
          | .ok result =>
            let .ok [identity] := result.getObjValAs? (List Lean.Json) "list" | return .error .resourceDenied
            unless (identity.getObjValAs? String "id").toOption == some resource[4]! do return .error .resourceDenied
            let .ok sender := identity.getObjValAs? String "email" >>= Connector.email | return .error .resourceDenied
            let some body := transport.body | return .error .capabilityDenied
            let .ok json := Lean.Json.parse body | return .error .capabilityDenied
            let .ok [[.str "EmailSubmission/set", args, .str "op"]] := json.getObjValAs? (List (List Lean.Json)) "methodCalls" | return .error .capabilityDenied
            let .ok create := args.getObjVal? "create" | return .error .capabilityDenied
            let .ok send := create.getObjVal? "send" | return .error .capabilityDenied
            let .ok envelope := send.getObjVal? "envelope" | return .error .capabilityDenied
            let send := send.setObjVal! "envelope" (envelope.setObjVal! "mailFrom" (Lean.Json.mkObj [("email", Lean.Json.str sender)]))
            let args := args.setObjVal! "create" (Lean.Json.mkObj [("send", send)])
            transport := { transport with body := some (Connector.jmapBody [Connector.jmapMethod "EmailSubmission/set" args] ["urn:ietf:params:jmap:submission"]).compress }
        if ["messages.update", "messages.delete"].contains operation then
          let .ok state := result.getObjValAs? String "state" | return .error .resourceDenied
          let some body := transport.body | return .error .capabilityDenied
          let .ok json := Lean.Json.parse body | return .error .capabilityDenied
          let .ok [[.str "Email/set", args, .str "op"]] := json.getObjValAs? (List (List Lean.Json)) "methodCalls" | return .error .capabilityDenied
          let changed := (Connector.jmapBody [Connector.jmapMethod "Email/set" (args.setObjVal! "ifInState" (Lean.Json.str state))]).compress
          transport := { transport with body := some changed }
  if ["google-calendar", "microsoft-calendar"].contains provider && ["events.invite", "events.update", "events.delete"].contains operation then
    match ← metadata cfg cred transport.account (transport.url.drop cred.baseUrl.length |>.toString) authority.maxResponseBytes reserved with
    | .error denial => return .error denial
    | .ok (json, etag) =>
      let existing ← match json.getObjVal? "attendees" with
        | .error _ => pure []
        | .ok attendees => match Lean.fromJson? attendees with
          | .error _ => return .error .resourceDenied
          | .ok (attendees : List Lean.Json) => pure attendees
      unless existing.length ≤ 256 do return .error .resourceDenied
      for attendee in existing do
        let address := if provider == "google-calendar" then attendee.getObjValAs? String "email" else do
          let emailAddress ← attendee.getObjVal? "emailAddress"
          emailAddress.getObjValAs? String "address"
        let .ok address := address | return .error .resourceDenied
        let some _ := Control.Monad.Effect.Connector.AuthorizedResource.check? authority "events.invite" [resource[0]!, resource[1]!, address]
          | return .error .resourceDenied
      let some etag := etag | return .error .resourceDenied
      unless strongEtag etag do return .error .resourceDenied
      transport := { transport with headers := ("if-match", etag) :: transport.headers }
      if operation == "events.invite" then
        let some body := transport.body | return .error .capabilityDenied
        let .ok newBody := Lean.Json.parse body | return .error .capabilityDenied
        let .ok added := newBody.getObjValAs? (List Lean.Json) "attendees" | return .error .capabilityDenied
        let merged := (Lean.Json.mkObj [("attendees", Lean.toJson (existing ++ added))]).compress
        transport := { transport with body := some merged }
  let some resolved := resolved? prepared transport | return .error .capabilityDenied
  return .ok resolved

private def sendConnector {r : Liaison.Request} {authority : Control.Monad.Effect.Connector.Authority}
    {operation : String} (cfg : EgressConfig) (cred : Credential)
    (prepared : Connector.Prepared authority operation) (reserved : Reserved r) :
    IO (Except Denial (Wire.Response × Liaison.Credits)) := do
  if ["github", "gitlab"].contains authority.cell.provider &&
      ((Connector.parseJson prepared.payload >>= fun payload => pure (Repository.view payload)).toOption.bind id).isSome then
    return ← repositoryCall cfg cred prepared reserved
  let resolved ← match ← resolve cfg cred prepared reserved with
    | .error denial => return .error denial
    | .ok resolved => pure resolved
  let transport := resolved.transport
  let cred := { cred with baseUrl := Connector.transportBase authority.cell.provider operation cred.baseUrl }
  match ← sendWithCredential cfg cred transport authority.maxResponseBytes reserved with
  | .error denial => return .error denial
  | .ok (response, cost) =>
    if response.body.size > authority.maxResponseBytes then return .error .capabilityDenied
    if authority.cell.provider == "radius" && operation == "inference.generate" && response.status == 200 then
      let some text := String.fromUTF8? response.body | return .error .resourceDenied
      let .ok stream := Inference.checkSse text ((prepared.conversation.map (·.allowedTools)).getD []) | return .error .resourceDenied
      let _ := stream.validated
    -- Validate membership on the actual response that will be disclosed, not
    -- an earlier mutable label/mailbox observation followed by another GET.
    if authority.cell.provider == "gmail" && operation == "messages.read" && prepared.resource.resource.length == 3 && response.status == 200 then
      let some text := String.fromUTF8? response.body | return .error .resourceDenied
      let .ok json := Connector.parseJson text | return .error .resourceDenied
      unless (json.getObjValAs? String "id").toOption == some prepared.resource.resource[2]! do return .error .resourceDenied
      let .ok labels := json.getObjValAs? (List String) "labelIds" | return .error .resourceDenied
      unless labels.contains prepared.resource.resource[1]! do return .error .resourceDenied
    if authority.cell.provider == "jmap" && operation == "messages.read" && prepared.resource.resource.length == 3 && response.status == 200 then
      let some text := String.fromUTF8? response.body | return .error .resourceDenied
      let .ok json := Connector.parseJson text >>= (Connector.jmapResult · "Email/get" prepared.resource.resource[0]!) | return .error .resourceDenied
      let .ok [message] := json.getObjValAs? (List Lean.Json) "list" | return .error .resourceDenied
      unless (message.getObjValAs? String "id").toOption == some prepared.resource.resource[2]! do return .error .resourceDenied
      let .ok mailboxes := message.getObjVal? "mailboxIds" >>= Lean.Json.getObj? | return .error .resourceDenied
      unless (mailboxes.toList.find? (fun entry => entry.1 == prepared.resource.resource[1]!)).map Prod.snd == some (Lean.Json.bool true) do return .error .resourceDenied
    return .ok (response, cost)

/-- Resource permission is a typed witness consumed before any credential is
    used. The signed warrant independently binds the provider, operation and
    connection; a caller cannot select another credential or an arbitrary URL. -/
def callConnector {r : Liaison.Request} (cfg : EgressConfig) (call : Wire.ConnectorCall)
    (reserved : Reserved r) : IO (Except Denial (Wire.Response × Liaison.Credits)) := do
  unless call.operation == r.action.value && Wire.accountMatchesResource call.account r.resource.value &&
      (Connector.operations r.provider.value).contains call.operation do
    return .error .capabilityDenied
  let permissions ← match ← fetchPermissions cfg.secrets r.provider call.account with
    | .error _ => return .error .credentialUnavailable
    | .ok none => pure { Connector.readDefaults with scopes := Connector.readDefaults.scopes.filter (fun scope => (Connector.operations r.provider.value).contains scope.operation) }
    | .ok (some value) => match Connector.Permissions.parse value with
      | .error _ => return .error .capabilityDenied
      | .ok permissions => match permissions.validate r.provider.value with
        | .error _ => return .error .capabilityDenied
        | .ok permissions => pure permissions
  let cap := permissions.capability r.provider.value r.resource.value
  let organization ← match ← fetchOrganizationPermissions cfg.secrets r.orgId r.provider r.resource with
    | .error _ => return .error .capabilityDenied
    | .ok value => match Connector.Permissions.parse value >>= (fun permissions => permissions.validate r.provider.value) with
      | .error _ => return .error .capabilityDenied
      | .ok permissions => pure (permissions.capability r.provider.value r.resource.value)
  let policy ← match ← fetchRunPermissions cfg.secrets reserved.authorized.warrant r.runId with
    | .error _ => return .error .capabilityDenied
    | .ok value => match Connector.RunPermissions.parse value r.provider.value r.resource.value call.account with
      | .error _ => return .error .capabilityDenied
      | .ok policy => pure policy
  let authority := policy.authority organization cap
  let some authorized := Control.Monad.Effect.Connector.AuthorizedResource.check? authority call.operation call.resource
    | return .error .resourceDenied
  if call.payload.toUTF8.size > authority.maxRequestBytes then return .error .capabilityDenied
  let credential ← match ← fetchCredential cfg.secrets r.provider call.account with
    | .error _ => return .error .credentialUnavailable
    | .ok credential => pure credential
  let prepared ← match Connector.prepare authority call.operation authorized credential.baseUrl call.account call.payload call.context policy.conversation policy.publication with
    | .error _ => return .error .capabilityDenied
    | .ok prepared => pure prepared
  let credential ← match ← ensureFresh cfg r.provider call.account credential with
    | .error _ => return .error .credentialUnavailable
    | .ok credential => pure credential
  sendConnector cfg credential prepared reserved

/-- **Loud, structured-denial stub.** Inference routing (`broker.md` §8:
    "where does inference routing live") is explicitly out of scope for v0.
    This function type-checks, is wired into `Server.lean`'s routing, and
    unconditionally denies — never a silent success, never a bare
    `sorry`/`panic!`. `LiaisonTest/Liaison/Egress/ProviderTest.lean` pins its
    type and documents (by inspection, not by test — see that file) that it
    never returns `.ok`. -/
def callInference {r : Liaison.Request} (_reserved : Reserved r)
    : IO (Except Denial (Wire.Response × Liaison.Credits)) :=
  return .error .inferenceNotImplemented

end Liaison.Egress
