import Liaison.Egress.Connector
open Lean Liaison.Egress Control.Monad.Effect.Connector
namespace NativeRepositoryTests
private def json (text : String) := (Json.parse text).toOption.getD .null
def scope (operation : String) : Scope := { operation, root := ["owner", "repo", "typednotes", "graph"], descendants := true }
def cap : Capability := { provider := "github", connection := "c", scopes := [scope "repositories.write"] }
def authority : Authority := ⟨cap, cap, cap, cap⟩
def policy : Repository.PublicationPolicy := { branch := "main", root := ["typednotes", "graph"] }
def resource := ["owner", "repo", "typednotes", "graph"]
def payload := json "{\"view\":\"commit\",\"branch\":\"main\",\"expectedHead\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"message\":\"writer\",\"changes\":[{\"resource\":[\"Main.lean\"],\"contents\":\"hello\",\"mode\":\"100644\",\"delete\":false}]}"
#guard (Repository.authorize authority resource policy payload).isOk
#guard (Repository.authorize authority resource { policy with branch := "other" } payload).toOption.isNone
#guard (Repository.authorize authority ["owner", "repo", "outside"] policy payload).toOption.isNone
#guard (Repository.parsePlan resource (json (payload.compress.replace "Main.lean" ".."))).toOption.isNone
#guard (Repository.parsePlan resource (json (payload.compress.replace "100644" "120000"))).toOption.isNone
def deletion := json "{\"view\":\"commit\",\"branch\":\"main\",\"expectedHead\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"message\":\"writer\",\"changes\":[{\"resource\":[\"Main.lean\"],\"contents\":null,\"mode\":\"000000\",\"delete\":true}]}"
#guard (Repository.authorize authority resource policy deletion).toOption.isNone
def deleteCap := { cap with scopes := [scope "repositories.delete"] }
#guard (Repository.authorize ⟨deleteCap, deleteCap, deleteCap, deleteCap⟩ resource policy deletion).isOk
#guard !Repository.branch "main..outside"
#guard !Repository.branch "refs/heads/.secret"
#guard !(Repository.normalizeTree "github" (json "{\"truncated\":true,\"tree\":[]}")).isOk
#guard !(Repository.normalizeTree "gitlab" (json "[{\"path\":\"link\",\"mode\":\"120000\",\"type\":\"blob\",\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]")).isOk
example (authorized : Repository.AuthorizedPlan authority resource policy payload) (change : Repository.Change) (member : change ∈ authorized.plan.changes) :
    authority.permits (Repository.changeOperation change) (resource ++ change.resource) = true := authorized.changesBound change member
example (authorized : Repository.AuthorizedPlan authority resource policy payload) : Repository.parsePlan resource payload = .ok authorized.plan := authorized.derived
end NativeRepositoryTests
