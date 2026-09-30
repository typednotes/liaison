/-
  Liaison.Server — the one HTTP boundary, and the one place that parses raw
  request bytes into `Warrant`/`Request`/an outbound-call description
  ("parse, don't validate" — `proof-strategy.md`), with `Liaison.Wire`.

  Every other module in `liaison` receives already-parsed, already-checked
  values; this module is the only one that looks at a `ByteArray` and
  decides what it means. `authorize` and `withReservation` are called from
  exactly one place below, so there is one call site to review for "every
  attempt is logged" (`Audit.recordAttempt` is called on every outcome,
  success and every `Denial` variant, including parse failure).

  Three distinct "Request"/"Response" types are in play here and are kept
  fully qualified throughout to avoid confusing them: `Liaison.Request`/
  `Liaison.Denial` (the trusted, parsed call and its outcome), the inbound
  `Network.WebApp.Request`/`Response` (this module's actual HTTP boundary),
  and the outbound `Network.HTTP.Client.Request` (built for `callProvider`).

  ## Wire format

  Defined once, in `Liaison.Wire` (the format, its decoders and encoders),
  which this module uses to decode the request (`Wire.Body.decode`) and to
  encode every reply (`Wire.encodeResponse`, `Wire.encodeRefusal`) — the same
  module liaison's Lean clients import, so a client cannot drift from what
  this server parses.

  0.3.0 (`typednotes/typednotes`'s `docs/connections.md` §5): `account` is two
  `[A-Za-z0-9_-]` segments whose last equals `resource` (else
  `malformed_warrant`); caller headers are policed (`header_denied`); the URL
  must stay under the credential's `base_url` (`url_denied`); vault/refresh
  failures are `credential_unavailable`, network failures `upstream_failed`.
  `GET /_health` answers `200 ok`.
-/

import Liaison.Auth
import Liaison.Budget
import Liaison.Audit
import Liaison.Egress.Provider
import Liaison.Egress.Secrets
import Liaison.Egress.Policy
import Liaison.Wire
import Linen.Network.WebApp
import Linen.Network.HTTP.Client.Types
import Linen.Network.HTTP.Simple
import Linen.Database.SQL.Pool

namespace Liaison

open Network.HTTP.Types
open Database.SQL.Pool (Pool)
open Egress (EgressConfig callProvider callInference callConnector)

/-- The HTTP status of each denial (`connections.md` §5 for the 0.3.0
    ones). Public so `LiaisonTest/Liaison/ServerTest.lean` can pin it; the
    response body's `error` is `Denial.code`. -/
def denialStatus : Denial → Status
  | .malformedWarrant => status400
  | .tagInvalid => status403
  | .capabilityDenied => status403
  | .resourceDenied => status403
  | .wrongRun => status403
  | .expired => status403
  | .budgetExceeded => status403
  | .budgetUnavailable => status402
  | .inferenceNotImplemented => status501
  | .urlDenied => status403
  | .headerDenied => status400
  | .credentialUnavailable => status502
  | .upstreamFailed => status502

private def denialResponse (d : Denial) : Network.WebApp.Response :=
  Network.WebApp.responseLBS (denialStatus d) [(hContentType, "application/json")]
    (Wire.encodeRefusal d)

/-- Relay a provider's answer (`Wire.Response`, the type `Budget.lean` and
    `Egress.Provider` share) in liaison's JSON envelope, so a caller always
    gets `application/json` back from `liaison` itself, regardless of what the
    upstream provider returned. -/
private def wrapUpstream (r : Wire.Response) : Network.WebApp.Response :=
  Network.WebApp.responseLBS status200 [(hContentType, "application/json")]
    (Wire.encodeResponse r)

/-- `POST /v0/egress` handler. Every path — parse failure, `authorize`
    denial, request-policy denial, `withReservation` denial (including every
    `callProvider` failure, which `callProvider` returns as a `Denial` rather
    than throwing), an exception escaping the hold lifecycle, and success —
    writes exactly one `AuditRow` before responding. -/
private def handleEgress (rootKey : RootKey) (pool : Pool) (cfg : EgressConfig)
    (req : Network.WebApp.Request) : IO Network.WebApp.Response := do
  let bytes ← Network.WebApp.strictRequestBody req
  match Wire.Body.decode bytes with
  | .error _ =>
    -- No `Warrant`/`Request` was recovered, so there is nothing to key an
    -- audit row on beyond "a malformed attempt happened" — recorded with
    -- empty identifiers rather than skipped, per `broker.md` §1's "complete
    -- audit log."
    recordAttempt pool
      { warrantId := ⟨""⟩, orgId := ⟨""⟩, runId := ⟨""⟩
        provider := ⟨""⟩, action := ⟨""⟩, outcome := some .malformedWarrant }
    return denialResponse .malformedWarrant
  | .ok parsed =>
    -- Expiry is decided using the broker's clock, never a replayed caller time.
    let now ← nowUnixSeconds
    let parsed := { parsed with request := { parsed.request with now := now.toUInt64 } }
    let mkRow (outcome : Option Denial) : AuditRow :=
      { warrantId := parsed.warrant.id, orgId := parsed.warrant.orgId, runId := parsed.request.runId
        provider := parsed.request.provider, action := parsed.request.action, outcome }
    let deny (d : Denial) : IO Network.WebApp.Response := do
      recordAttempt pool (mkRow (some d))
      return denialResponse d
    match ← authorize rootKey parsed.warrant parsed.request with
    | .error d => deny d
    | .ok authorized =>
      -- Request policy that needs no credential, checked before a hold is
      -- placed: the account must name the warrant-bound resource, and no
      -- caller header may be one refused for every credential.
      let preCheck : Option Denial := match parsed.call with
        | .inference => none
        | .provider call =>
          if !Wire.accountMatchesResource call.account parsed.request.resource.value then
            some .malformedWarrant
          else if !Egress.checkCallerHeaders [] call.headers then
            some .headerDenied
           else none
        | .connector call =>
          if !Wire.accountMatchesResource call.account parsed.request.resource.value ||
              call.operation != parsed.request.action.value then some .capabilityDenied else none
      match preCheck with
      | some d => deny d
      | none =>
        -- `withReservation` releases the hold and rethrows on any exception
        -- (a Postgres failure settling/releasing the hold — `callProvider`
        -- itself never throws). Caught here so that path is audited too,
        -- as `budget_unavailable`: the ledger, not the provider, failed.
        let outcome ← try
            withReservation pool authorized (r := parsed.request) (fun reserved =>
              match parsed.call with
              | .inference => callInference reserved
               | .provider call => callProvider cfg call reserved
               | .connector call => callConnector cfg call reserved)
          catch e =>
            IO.eprintln s!"liaison: hold lifecycle failed: {e}"
            pure (.error .budgetUnavailable)
        match outcome with
        | .error d => deny d
        | .ok resp =>
          recordAttempt pool (mkRow none)
          return wrapUpstream resp

/-- The `liaison` `Application`: `POST /v0/egress`, the one egress
    chokepoint, and `GET /_health` (`200 ok`, no database or vault check —
    liveness only). Everything else is `404`. -/
def application (rootKey : RootKey) (pool : Pool) (cfg : EgressConfig)
    : Network.WebApp.Application :=
  fun req respond =>
    if req.rawPathInfo == "/v0/egress" && req.requestMethod == .standard .POST then
      Network.WebApp.AppM.respondIO respond (handleEgress rootKey pool cfg req)
    else if req.rawPathInfo == "/_health" && req.requestMethod == .standard .GET then
      Network.WebApp.AppM.respond respond
        (Network.WebApp.responseLBS status200 [(hContentType, "text/plain")] "ok")
    else
      Network.WebApp.AppM.respond respond (Network.WebApp.responseLBS status404 [] "not found")

end Liaison
