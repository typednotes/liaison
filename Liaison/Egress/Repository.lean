/- Broker-owned immutable repository views and scoped publication plans. No
   caller may supply a transport, arbitrary Git object, tree or GraphQL query. -/
import Liaison.Egress.Inference
import Linen.Control.Monad.Effect.Connector
import Linen.Network.HTTP.Types.URI
import Linen.Crypto.SHA1
import Linen.Crypto.Zlib.FFI
import Linen.Data.Hex

namespace Liaison.Egress.Repository
open Lean (Json)
open Control.Monad.Effect.Connector (Authority AuthorizedResource Capability)

def commit (value : String) : Bool := value.length == 40 && value.all (fun c => c.isDigit || "abcdef".toList.contains c)
def branch (value : String) : Bool :=
  !value.isEmpty && value.length ≤ 255 && !value.startsWith "-" && !value.endsWith "." &&
    !(value.splitOn "..").length > 1 && !(value.splitOn "@{").length > 1 &&
    (value.splitOn "/").all (fun part => Wire.validResource [part] && !part.startsWith "." && !part.endsWith ".lock") &&
    value.all (fun c => c.isAlphanum || c == '-' || c == '_' || c == '/' || c == '.')

def safePath (parts : List String) : Bool := Wire.validResource parts && !parts.isEmpty &&
  parts.all (fun part => part.toLower != ".git" && part.toLower != ".lake")

def apiPath (provider : String) (resource : List String) : String :=
  if provider == "github" then "/repos/" ++ Network.HTTP.Types.urlEncode resource[0]! ++ "/" ++ Network.HTTP.Types.urlEncode resource[1]!
  else "/projects/" ++ Network.HTTP.Types.urlEncode (resource[0]! ++ "/" ++ resource[1]!)

def view (payload : Json) : Option String := (payload.getObjValAs? String "view").toOption

/-- Inventory pagination cannot select a URL, owner or larger provider page. -/
structure InventoryPage where
  private mk ::
  value : Nat
  positive : 1 ≤ value
  bounded : value ≤ 100

def InventoryPage.parse (payload : Json) : Except String InventoryPage := do
  Inference.fieldsOnly payload ["page"]
  let value ← match payload.getObjVal? "page" with
    | .error _ => pure 1
    | .ok raw => do
      let text ← raw.getStr?
      let some number := text.toNat? | throw "repository page must be decimal text"
      unless text == toString number do throw "repository page must be canonical decimal text"
      pure number
  if hp : 1 ≤ value then
    if hb : value ≤ 100 then return ⟨value, hp, hb⟩
    else throw "repository page exceeds 100"
  else throw "repository page must be positive"

structure Inventory where
  private mk ::
  entries : Array Json
  bounded : entries.size ≤ 100

def Inventory.check (value : Json) : Except String Inventory := do
  let entries ← value.getArr?
  if h : entries.size ≤ 100 then return ⟨entries, h⟩
  else throw "repository inventory exceeds 100 entries per page"

def metadataMatches (provider : String) (resource : List String) (json : Json) : Bool :=
  resource.length == 2 && Wire.validResource resource &&
    match json.getObjValAs? String (if provider == "github" then "full_name" else "path_with_namespace") with
    | .error _ => false
    | .ok name => if provider == "github" then name.toLower == ("/".intercalate resource).toLower
        else name == "/".intercalate resource

/-- A repository metadata reply must identify the authorized selector before
    the application can adopt it as a project target. Remote API honesty is
    still a trusted boundary; a mismatched response is a structured refusal. -/
structure Metadata (provider : String) (resource : List String) where
  private mk ::
  value : Json
  identity : metadataMatches provider resource value = true

def Metadata.check (provider : String) (resource : List String) (value : Json) : Except String (Metadata provider resource) :=
  if h : metadataMatches provider resource value = true then .ok ⟨value, h⟩
  else .error "repository metadata does not match its authorized selector"

structure Change where
  resource : List String
  contents : Option String
  mode : String
  delete : Bool
  deriving Lean.FromJson, Lean.ToJson

/-- A delete is independently grantable in the trusted publication projection.
    It additionally requires the same four-ceiling write permission on its path. -/
structure PublicationPolicy where
  branch : String
  root : List String
  deriving Lean.FromJson

structure Plan where
  branch : String
  expectedHead : String
  message : String
  changes : List Change
  deriving Lean.FromJson

def changeOperation (change : Change) : String := if change.delete then "repositories.delete" else "repositories.write"

def parsePlan (resource : List String) (payload : Json) : Except String Plan := do
  Inference.fieldsOnly payload ["view", "branch", "expectedHead", "message", "changes"]
  unless view payload == some "commit" && resource.length ≥ 2 do throw "invalid publication target"
  let plan : Plan ← Lean.fromJson? payload
  unless branch plan.branch && commit plan.expectedHead && !plan.message.isEmpty && plan.message.toUTF8.size ≤ 16384 &&
      !plan.changes.isEmpty && plan.changes.length ≤ 1000 do throw "invalid bounded commit plan"
  for change in ← payload.getObjValAs? (List Json) "changes" do
    Inference.fieldsOnly change ["resource", "contents", "mode", "delete"]
    for name in ["resource", "contents", "mode", "delete"] do let _ ← change.getObjVal? name
  for change in plan.changes do
    unless safePath change.resource && safePath (resource.drop 2 ++ change.resource) do throw "commit path leaves its project"
    unless if change.delete then change.mode == "000000" && change.contents.isNone
      else ["100644", "100755"].contains change.mode && change.contents.isSome do throw "invalid commit file mode/content"
  let paths := plan.changes.map (·.resource)
  unless paths.eraseDups.length == paths.length do throw "duplicate publication path"
  for a in paths do
    for b in paths do
      if a != b && (a.isPrefixOf b || b.isPrefixOf a) then throw "file/directory publication conflict"
  return plan

structure AuthorizedPlan (authority : Authority) (resource : List String) (policy : PublicationPolicy) (payload : Json) where
  private mk ::
  plan : Plan
  derived : parsePlan resource payload = .ok plan
  branchBound : plan.branch = policy.branch
  rootBound : policy.root.isPrefixOf (resource.drop 2) = true
  changesBound : ∀ change ∈ plan.changes, authority.permits (changeOperation change) (resource ++ change.resource) = true
  deletionBound : ∀ change ∈ plan.changes, change.delete = true →
    authority.permits "repositories.delete" (resource ++ change.resource) = true

def authorize (authority : Authority) (resource : List String) (policy : PublicationPolicy) (payload : Json) :
    Except String (AuthorizedPlan authority resource policy payload) := do
  match hp : parsePlan resource payload with
  | .error error => throw error
  | .ok plan =>
    if hb : plan.branch = policy.branch then
      if hr : policy.root.isPrefixOf (resource.drop 2) = true then
        if hc : plan.changes.all (fun change => authority.permits (changeOperation change) (resource ++ change.resource)) = true then
          if hd : plan.changes.all (fun change => !change.delete || authority.permits "repositories.delete" (resource ++ change.resource)) = true then
            return ⟨plan, hp, hb, hr, List.all_eq_true.mp hc, fun change member deletion => by
              have h := List.all_eq_true.mp hd change member
              simpa [deletion] using h⟩
          else throw "deletion is not independently authorized"
        else throw "changed file leaves one of its four ceilings"
      else throw "publication leaves trusted project boundary"
    else throw "publication branch differs from trusted branch"

def normalizeTree (provider : String) (json : Json) : Except String (List Json) := do
  let entries ← if provider == "github" then do
    unless (json.getObjValAs? Bool "truncated").toOption == some false do throw "truncated repository tree"
    json.getObjValAs? (List Json) "tree"
    else json.getArr? |>.map Array.toList
  unless entries.length ≤ 10000 do throw "repository tree exceeds inventory limit"
  let mut out := []
  let mut paths : List String := []
  for entry in entries do
    let path ← entry.getObjValAs? String "path"
    let kind ← entry.getObjValAs? String "type"
    let mode ← entry.getObjValAs? String "mode"
    let sha ← entry.getObjValAs? String (if provider == "github" then "sha" else "id")
    unless safePath (path.splitOn "/") && commit sha &&
        ((kind == "blob" && ["100644", "100755"].contains mode) || (kind == "tree" && ["040000", "40000"].contains mode)) do
      throw "unsafe repository entry (symlink, submodule or bookkeeping)"
    unless !paths.any (fun previous => previous.toLower == path.toLower) do throw "duplicate or case-alias tree path"
    paths := path :: paths
    out := out ++ [Json.mkObj [("path", .str path), ("type", .str kind), ("mode", .str mode), ("sha", .str sha)]]
  return out

/-- Fixed GraphQL program, with typed variables; never caller-selected code. -/
def githubUpdateRefs : String := "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}"

def githubPublish (repositoryId branch expected next : String) : Json := Json.mkObj [
  ("query", .str githubUpdateRefs), ("variables", Json.mkObj [("input", Json.mkObj [
    ("repositoryId", .str repositoryId), ("refUpdates", Lean.toJson [Json.mkObj [
      ("name", .str ("refs/heads/" ++ branch)), ("beforeOid", .str expected), ("afterOid", .str next), ("force", .bool false)]])])])]

end Liaison.Egress.Repository
