import Liaison.Egress.Connector
import Liaison.Budget

/- The only linked-device FFI entry consumes a private checked plan and a real
   reservation. Protocol libraries, crypto/storage and the C ABI are trusted. -/
namespace Liaison.Egress.Paired
open Lean (Json)
open Control.Monad.Effect.Connector (Authority)

def base : String := "https://paired.typednotes.invalid"
def providers : List String := ["signal", "whatsapp"]
def controls : List String := ["device.pair", "device.status", "device.unlink"]

@[extern "liaison_paired_invoke"]
private opaque invoke (provider request : @& String) : IO String

/-- Availability loads only the library; it never starts a provider session. -/
def available (provider : String) : IO Bool := do
  try return (← invoke provider "") == "available" catch _ => return false

structure Plan (authority : Authority) (operation : String) where
  private mk ::
  prepared : Connector.Prepared authority operation
  providerBound : providers.contains authority.cell.provider = true
  operationBound : ["messages.read", "messages.send"].contains operation = true
  nativeBase : prepared.base = base

def prepare {authority : Authority} {operation : String}
    (prepared : Connector.Prepared authority operation) : Except String (Plan authority operation) :=
  if hp : providers.contains authority.cell.provider = true then
    if ho : ["messages.read", "messages.send"].contains operation = true then
      if hb : prepared.base = base then .ok ⟨prepared, hp, ho, hb⟩ else .error "not a paired connection"
    else .error "unsupported paired operation"
  else .error "unsupported paired provider"

theorem Plan.organization_permits {authority : Authority} {operation : String}
    (plan : Plan authority operation) : authority.organization.permits operation plan.prepared.resource.resource = true :=
  plan.prepared.organization_permits
theorem Plan.connection_permits {authority : Authority} {operation : String}
    (plan : Plan authority operation) : authority.connection.permits operation plan.prepared.resource.resource = true :=
  plan.prepared.connection_permits
theorem Plan.cell_permits {authority : Authority} {operation : String}
    (plan : Plan authority operation) : authority.cell.permits operation plan.prepared.resource.resource = true :=
  plan.prepared.cell_permits
theorem Plan.warrant_permits {authority : Authority} {operation : String}
    (plan : Plan authority operation) : authority.warrant.permits operation plan.prepared.resource.resource = true :=
  plan.prepared.warrant_permits

/-- Provisioning warrants cannot be substituted for messaging warrants or rebound
    to another owner. The authenticated app mints these only for connection admins. -/
structure Control (r : Liaison.Request) where
  private mk ::
  reserved : Reserved r
  call : Wire.ConnectorCall
  providerBound : providers.contains r.provider.value = true
  actionBound : controls.contains ((r.action.value.splitOn ":").headD "") = true
  operationBound : call.operation = r.action.value
  connectionBound : Wire.accountMatchesResource call.account r.resource.value = true
  ownerBound : r.action.value = ((r.action.value.splitOn ":").headD "") ++ ":" ++ ((call.account.splitOn "/").headD "")
  emptyPayload : call.payload = "{}"
  emptyResource : call.resource = []
  emptyContext : call.context = none

def control {r : Liaison.Request} (reserved : Reserved r) (call : Wire.ConnectorCall) : Except String (Control r) :=
  if hp : providers.contains r.provider.value = true then
    if ha : controls.contains ((r.action.value.splitOn ":").headD "") = true then
      if ho : call.operation = r.action.value then
        if hc : Wire.accountMatchesResource call.account r.resource.value = true then
          if hu : r.action.value = ((r.action.value.splitOn ":").headD "") ++ ":" ++ ((call.account.splitOn "/").headD "") then
            if hj : call.payload = "{}" then
              if hr : call.resource = [] then
                if hx : call.context = none then .ok ⟨reserved, call, hp, ha, ho, hc, hu, hj, hr, hx⟩
                else .error "device context forbidden"
              else .error "device selectors forbidden"
            else .error "device payload forbidden"
          else .error "device owner mismatch"
        else .error "device connection mismatch"
      else .error "device action mismatch"
    else .error "unsupported device action"
  else .error "unsupported device provider"

private def dispatch (provider organization account key action sender peer text after : String)
    (limit : Nat) : IO (Except Denial Wire.Response) := do
  try
    let request := Json.mkObj [("provider", provider), ("organization", organization), ("account", account),
      ("key", key), ("action", action), ("sender", sender), ("peer", peer), ("text", text), ("after", after),
      ("responseLimit", Lean.toJson limit)]
    let answer ← invoke provider request.compress
    let .ok json := Connector.parseJson answer | return .error .upstreamFailed
    let .ok status := json.getObjValAs? Nat "status" | return .error .upstreamFailed
    let .ok body := json.getObjValAs? String "body" | return .error .upstreamFailed
    unless status ≤ 599 && body.toUTF8.size ≤ limit do return .error .capabilityDenied
    return .ok { status := status.toUInt16, headers := [("content-type", "application/json")], body := body.toUTF8 }
  catch _ => return .error .credentialUnavailable

structure Execution (r : Liaison.Request) (authority : Authority) (operation : String) where
  private mk ::
  plan : Plan authority operation
  reserved : Reserved r
  providerBound : authority.cell.provider = r.provider.value
  connectionBound : authority.cell.connection = r.resource.value
  actionBound : operation = r.action.value
  accountBound : Wire.accountMatchesResource plan.prepared.account r.resource.value = true

private def executeBound {r : Liaison.Request} {authority : Authority} {operation : String}
    (execution : Execution r authority operation) (key : String) :
    IO (Except Denial (Wire.Response × Liaison.Credits)) := do
  let prepared := execution.plan.prepared
  let .ok payload := Connector.parseJson prepared.payload | return .error .capabilityDenied
  let text := (payload.getObjValAs? String "text").toOption.getD ""
  let after := (payload.getObjValAs? String "after").toOption.getD "0"
  let response ← dispatch authority.cell.provider r.orgId.value prepared.account key
    (if operation == "messages.send" then "send" else "read")
    (prepared.resource.resource[0]?.getD "") (prepared.resource.resource[1]?.getD "") text after authority.maxResponseBytes
  return response.map (fun response => (response, r.cost))

def execute {r : Liaison.Request} {authority : Authority} {operation : String}
    (plan : Plan authority operation) (key : String) (reserved : Reserved r) :
    IO (Except Denial (Wire.Response × Liaison.Credits)) := do
  if hp : authority.cell.provider = r.provider.value then
    if hc : authority.cell.connection = r.resource.value then
      if ho : operation = r.action.value then
        if ha : Wire.accountMatchesResource plan.prepared.account r.resource.value = true then
          return ← executeBound ⟨plan, reserved, hp, hc, ho, ha⟩ key
  return .error .capabilityDenied

def executeControl {r : Liaison.Request} (control : Control r) (key : String) :
    IO (Except Denial (Wire.Response × Liaison.Credits)) := do
  let action := (((control.call.operation.splitOn ":").headD "").drop 7).toString
  let response ← dispatch r.provider.value r.orgId.value control.call.account key action "" "" "" "0" 65536
  return response.map (fun response => (response, r.cost))
end Liaison.Egress.Paired
