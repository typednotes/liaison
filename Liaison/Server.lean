/-
  Liaison.Server — the one HTTP boundary, and the one place that parses raw
  request bytes into `Warrant`/`Request`/an outbound-call description
  ("parse, don't validate" — `proof-strategy.md`).

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

  ## Wire format (v0, not specified by the plan — designed here)

  `POST /v0/egress`, JSON body:

  ```json
  {
    "warrant": {
      "id": "...", "orgId": "...", "tag": "<hex>",
      "caveats": [
        {"kind": "expiresAt",  "value": "<u64 decimal string>"},
        {"kind": "capability", "provider": "...", "action": "..."},
        {"kind": "resource",   "value": "..."},
        {"kind": "budget",     "value": "<nat decimal string>"},
        {"kind": "runId",      "value": "..."}
      ]
    },
    "now": "<u64 decimal string>", "cost": "<nat decimal string>",
    "provider": "...", "action": "...", "resource": "...",
    "runId": "...", "orgId": "...",
    "call": {"kind": "provider", "account": "...", "method": "GET", "url": "https://..."}
      -- or {"kind": "inference"}
  }
  ```

  `now`/`cost` are decimal **strings**, not JSON numbers — `Data.Json.Value.number`
  is `Float`-backed, and this avoids writing/justifying any float→exact-Nat/UInt64
  conversion for what must be exact integers (`proof-strategy.md`'s "integers only
  for money"). Every other numeric-looking field (`budget`, `expiresAt`) is a
  string for the same reason.

  This format is a v0 design choice, not something `broker.md`/`ledger.md`
  specify — named in `AGENTS.md` as a place a real client integration may
  want something different (e.g. protobuf) once one exists.
-/

import Liaison.Auth
import Liaison.Budget
import Liaison.Audit
import Liaison.Egress.Provider
import Liaison.Egress.Secrets
import Linen.Network.WebApp
import Linen.Network.HTTP.Client.Types
import Linen.Network.HTTP.Simple
import Linen.Data.Json
import Linen.Data.Hex
import Linen.Database.SQL.Pool

namespace Liaison

open Network.HTTP.Types
open Data.Json (Value)
open Database.SQL.Pool (Pool)
open Egress (SecretsConfig callProvider callInference)

/-- What to do after a request is authorized and its budget reserved. Parsed
    once, here, from the `"call"` object — never re-derived downstream. -/
private inductive Call
  | provider (account : String) (method : String) (url : String)
  | inference

private def orErr (o : Option α) (msg : String) : Except String α :=
  match o with
  | some v => .ok v
  | none => .error msg

private def getString (v : Value) (field : String) : Except String String := do
  orErr (← v.getField field).asString s!"{field} not a string"

private def getDecimalNat (v : Value) (field : String) : Except String Nat := do
  let s ← getString v field
  orErr s.toNat? s!"{field} not a decimal natural number"

private def parseCaveat (v : Value) : Except String Caveat := do
  let kind ← getString v "kind"
  match kind with
  | "expiresAt" =>
    let n ← getDecimalNat v "value"
    return .expiresAt n.toUInt64
  | "capability" =>
    let p ← getString v "provider"
    let a ← getString v "action"
    return .capability ⟨p⟩ ⟨a⟩
  | "resource" =>
    let s ← getString v "value"
    return .resource ⟨s⟩
  | "budget" =>
    let n ← getDecimalNat v "value"
    return .budget n
  | "runId" =>
    let s ← getString v "value"
    return .runId ⟨s⟩
  | other => .error s!"unknown caveat kind {other}"

private def parseWarrant (v : Value) : Except String Warrant := do
  let id ← getString v "id"
  let orgId ← getString v "orgId"
  let tagHex ← getString v "tag"
  let tag ← orErr (Data.Hex.decode tagHex) "warrant.tag not valid hex"
  let caveatsField ← v.getField "caveats"
  let caveatsArr ← orErr caveatsField.asArray "warrant.caveats not an array"
  let caveats ← caveatsArr.toList.mapM parseCaveat
  return { id := ⟨id⟩, orgId := ⟨orgId⟩, caveats, tag }

private def parseRequest (v : Value) : Except String Request := do
  let now ← getDecimalNat v "now"
  let cost ← getDecimalNat v "cost"
  let provider ← getString v "provider"
  let action ← getString v "action"
  let resource ← getString v "resource"
  let runId ← getString v "runId"
  let orgId ← getString v "orgId"
  return { now := now.toUInt64, cost, provider := ⟨provider⟩, action := ⟨action⟩,
            resource := ⟨resource⟩, runId := ⟨runId⟩, orgId := ⟨orgId⟩ }

private def parseCall (v : Value) : Except String Call := do
  let kind ← getString v "kind"
  match kind with
  | "provider" =>
    let account ← getString v "account"
    let method ← getString v "method"
    let url ← getString v "url"
    return .provider account method url
  | "inference" => return .inference
  | other => .error s!"unknown call kind {other}"

private structure ParsedBody where
  warrant : Warrant
  request : Request
  call    : Call

private def parseBody (bytes : ByteArray) : Except String ParsedBody := do
  let root ← Data.Json.Decode.decode (String.fromUTF8! bytes)
  let warrant ← parseWarrant (← root.getField "warrant")
  let request ← parseRequest root
  let call ← parseCall (← root.getField "call")
  return { warrant, request, call }

private def denialStatus : Denial → Status
  | .malformedWarrant => status400
  | .tagInvalid => status403
  | .capabilityDenied => status403
  | .resourceDenied => status403
  | .wrongRun => status403
  | .expired => status403
  | .budgetExceeded => status403
  | .budgetUnavailable => status402
  | .inferenceNotImplemented => status501

private def denialBody : Denial → String
  | .malformedWarrant => "malformed_warrant"
  | .tagInvalid => "tag_invalid"
  | .capabilityDenied => "capability_denied"
  | .resourceDenied => "resource_denied"
  | .wrongRun => "wrong_run"
  | .expired => "expired"
  | .budgetExceeded => "budget_exceeded"
  | .budgetUnavailable => "budget_unavailable"
  | .inferenceNotImplemented => "inference_not_implemented"

private def denialResponse (d : Denial) : Network.WebApp.Response :=
  let body := Data.Json.Encode.encode (.object [("error", .string (denialBody d))])
  Network.WebApp.responseLBS (denialStatus d) [(hContentType, "application/json")] body

/-- Turn a `Liaison.Response` (the generic egress-call response `Budget.lean`
    and `Egress.Provider` share) into a `Network.WebApp.Response`, wrapped in
    a JSON envelope so a caller always gets `application/json` back from
    `liaison` itself, regardless of what the upstream provider returned. -/
private def wrapUpstream (r : Liaison.Response) : Network.WebApp.Response :=
  let body := Data.Json.Encode.encode
    (.object
      [ ("status", .number r.status.toNat.toFloat)
      , ("headers", .object (r.headers.map (fun (k, v) => (k, .string v))))
      , ("body", .string (Data.Hex.encode r.body)) ])
  Network.WebApp.responseLBS status200 [(hContentType, "application/json")] body

/-- `POST /v0/egress` handler. Every path — parse failure, `authorize`
    denial, `withReservation` denial, and success — writes exactly one
    `AuditRow` before responding. -/
private def handleEgress (rootKey : RootKey) (pool : Pool) (secretsCfg : SecretsConfig)
    (req : Network.WebApp.Request) : IO Network.WebApp.Response := do
  let bytes ← Network.WebApp.strictRequestBody req
  match parseBody bytes with
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
    let mkRow (outcome : Option Denial) : AuditRow :=
      { warrantId := parsed.warrant.id, orgId := parsed.warrant.orgId, runId := parsed.request.runId
        provider := parsed.request.provider, action := parsed.request.action, outcome }
    match ← authorize rootKey parsed.warrant parsed.request with
    | .error d =>
      recordAttempt pool (mkRow (some d))
      return denialResponse d
    | .ok authorized =>
      let outcome ← withReservation pool authorized (r := parsed.request) (fun reserved =>
        match parsed.call with
        | .inference => callInference reserved
        | .provider account method url =>
          match Network.HTTP.Simple.parseUrl url with
          | none => return .error .malformedWarrant
          | some target =>
            let target := { target with method := Network.HTTP.Types.parseMethod method }
            callProvider secretsCfg account target reserved)
      match outcome with
      | .error d =>
        recordAttempt pool (mkRow (some d))
        return denialResponse d
      | .ok resp =>
        recordAttempt pool (mkRow none)
        return wrapUpstream resp

/-- The `liaison` `Application`. `/v0/egress` is the one egress chokepoint;
    everything else (including `/_health`, added by `Main.lean`'s middleware
    stack) is out of this module's concern. -/
def application (rootKey : RootKey) (pool : Pool) (secretsCfg : SecretsConfig)
    : Network.WebApp.Application :=
  fun req respond =>
    if req.rawPathInfo == "/v0/egress" && req.requestMethod == .standard .POST then
      Network.WebApp.AppM.respondIO respond (handleEgress rootKey pool secretsCfg req)
    else
      Network.WebApp.AppM.respond respond (Network.WebApp.responseLBS status404 [] "not found")

end Liaison
