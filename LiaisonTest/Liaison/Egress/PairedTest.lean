import Liaison.Egress.Paired
open Liaison Liaison.Egress
open Control.Monad.Effect.Connector
namespace PairedTests
private def cap (provider : String) : Capability :=
  { provider, connection := "connection", scopes := [
      { operation := "messages.read", root := ["sender", "alice"], descendants := false },
      { operation := "messages.send", root := ["sender", "alice"], descendants := false }],
    maxRequestBytes := 4096, maxResponseBytes := 4096 }
private def authority (provider : String) : Authority :=
  { organization := cap provider, connection := cap provider, cell := cap provider, warrant := cap provider }
private def check (provider operation : String) (resource : List String) (payload := "{}") : Bool :=
  match AuthorizedResource.check? (authority provider) operation resource with
  | none => false
  | some resource => ((Connector.prepare (authority provider) operation resource Paired.base "user/connection" payload).bind Paired.prepare).isOk
#guard check "signal" "messages.read" ["sender", "alice"]
#guard check "whatsapp" "messages.send" ["sender", "alice"] "{\"text\":\"hello\"}"
#guard !check "signal" "messages.read" ["sender"]
#guard !check "signal" "messages.read" ["other", "alice"]
#guard !check "whatsapp" "messages.send" ["sender", "bob"] "{\"text\":\"hello\"}"
#guard !check "whatsapp" "messages.send" ["sender", "alice"] "{\"text\":\"hello\",\"peer\":\"bob\"}"
#guard !check "signal" "device.pair" ["sender", "alice"]
#guard !check "signal" "messages.read" ["sender", "alice"] "{\"after\":\"01\"}"
#guard !check "signal" "messages.read" ["sender", "alice"] "{\"after\":\"18446744073709551616\"}"
#guard !(Connector.request "signal" "https://legacy.example" { account := "user/connection", operation := "messages.read", resource := ["sender"] }).isOk
#guard Paired.controls.all (fun operation => !(Connector.operations "signal").contains operation)
example (a : Authority) (op : String) (p : Paired.Plan a op) :
    a.organization.permits op p.prepared.resource.resource = true := p.organization_permits
example (a : Authority) (op : String) (p : Paired.Plan a op) :
    a.warrant.permits op p.prepared.resource.resource = true := p.warrant_permits
example (r : Request) (a : Authority) (op : String) (e : Paired.Execution r a op) :
    a.cell.provider = r.provider.value := e.providerBound
example (r : Request) (c : Paired.Control r) :
    r.action.value = ((r.action.value.splitOn ":").headD "") ++ ":" ++ ((c.call.account.splitOn "/").headD "") := c.ownerBound
end PairedTests
