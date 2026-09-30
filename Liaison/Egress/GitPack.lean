/- Minimal broker-owned Git v0 publication. One existing branch, one expected
   SHA-1 head, regular UTF-8 files, no refs/objects/pack bytes chosen by callers. -/
import Liaison.Egress.Repository

namespace Liaison.Egress.GitPack
open Lean (Json)

structure Object where
  kind : String
  data : ByteArray

def Object.id (object : Object) : String :=
  Data.Hex.encode (Crypto.SHA1.hash ((s!"{object.kind} {object.data.size}\x00").toUTF8 ++ object.data))

private inductive Trie where
  | node (files : List (String × String × String)) (children : List (String × Trie))

private def insert (parts : List String) (mode oid : String) (tree : Trie) : Trie :=
  match parts, tree with
  | [], tree => tree
  | [name], .node files children => .node ((name, mode, oid) :: files.filter (·.1 != name)) children
  | name :: rest@(_ :: _), .node files children =>
    let child := (children.find? (·.1 == name)).map Prod.snd |>.getD (.node [] [])
    .node files ((name, insert rest mode oid child) :: children.filter (·.1 != name))
termination_by parts.length

mutual
private def trees : Trie → Except String (Object × List Object)
  | .node files children => do
    let (entries, objects) ← childTrees children
    let entries := (files.map fun (name, mode, oid) => (name, mode, oid)) ++ entries
    -- Git sorts a directory as if '/' were appended to its name.
    let entries := entries.mergeSort (fun a b => (a.1 ++ if a.2.1 == "40000" then "/" else "") ≤
      (b.1 ++ if b.2.1 == "40000" then "/" else ""))
    let mut body := ByteArray.empty
    for (name, mode, oid) in entries do
      let some hash := Data.Hex.decode oid | throw "invalid Git tree hash"
      unless hash.size == 20 do throw "only SHA-1 repositories are supported"
      body := body ++ (mode ++ " " ++ name ++ "\x00").toUTF8 ++ hash
    let object : Object := { kind := "tree", data := body }
    return (object, object :: objects)
private def childTrees : List (String × Trie) → Except String (List (String × String × String) × List Object)
  | [] => .ok ([], [])
  | (name, child) :: rest => do
    let (object, objects) ← trees child
    let (entries, remaining) ← childTrees rest
    return ((name, "40000", object.id) :: entries, objects ++ remaining)
end

structure Built where
  private mk ::
  commit : Object
  root : Object
  objects : List Object
  parent : String
  parentBound : Repository.commit parent = true

def build (entries : List Json) (boundary : List String) (plan : Repository.Plan) (timestamp : Nat := 0) : Except String Built := do
  unless plan.changes.all (fun change => Repository.safePath (boundary ++ change.resource)) do throw "invalid scoped Git change"
  let blobs := entries.filter (fun entry => (entry.getObjValAs? String "type").toOption == some "blob")
  let mut files : List (List String × String × String) := []
  for entry in blobs do
    let path ← entry.getObjValAs? String "path"
    let mode ← entry.getObjValAs? String "mode"
    let oid ← entry.getObjValAs? String "sha"
    unless Repository.safePath (path.splitOn "/") && ["100644", "100755"].contains mode && Repository.commit oid do throw "unsafe existing tree"
    files := files ++ [(path.splitOn "/", mode, oid)]
  let mut objects : List Object := []
  for change in plan.changes do
    let target := boundary ++ change.resource
    for old in files do
      if old.1 != target && (old.1.isPrefixOf target || target.isPrefixOf old.1) then throw "publication would replace an unselected file/directory"
    if change.delete then
      unless files.any (·.1 == target) do throw "deletion target does not exist"
      files := files.filter (·.1 != target)
    else
      let some contents := change.contents | throw "missing regular file contents"
      let blob : Object := { kind := "blob", data := contents.toUTF8 }
      objects := objects ++ [blob]
      files := files.filter (·.1 != target) ++ [(target, change.mode, blob.id)]
  let tree := files.foldl (fun tree (parts, mode, oid) => insert parts mode oid tree) (.node [] [])
  let (root, allTrees) ← trees tree
  let body := s!"tree {root.id}\nparent {plan.expectedHead}\nauthor Typednotes <writer@typednotes.invalid> {timestamp} +0000\ncommitter Typednotes <writer@typednotes.invalid> {timestamp} +0000\n\n{plan.message}\n"
  let object : Object := { kind := "commit", data := body.toUTF8 }
  if h : Repository.commit plan.expectedHead = true then return ⟨object, root, object :: (allTrees ++ objects), plan.expectedHead, h⟩
  else throw "publication parent is not an immutable commit"

private def sizeBytes (n : Nat) : List UInt8 :=
  if n == 0 then [] else ((n % 128 + if n / 128 == 0 then 0 else 128).toUInt8) :: sizeBytes (n / 128)
termination_by n
decreasing_by
  apply Nat.div_lt_self
  · simp_all; omega
  · decide

private def objectHeader (object : Object) : ByteArray :=
  let code := if object.kind == "commit" then 1 else if object.kind == "tree" then 2 else 3
  let size := object.data.size
  ByteArray.mk ((code * 16 + size % 16 + if size / 16 == 0 then 0 else 128).toUInt8 :: sizeBytes (size / 16)).toArray

def pack (built : Built) : IO ByteArray := do
  let count := built.objects.length.toUInt32
  let mut out := "PACK".toUTF8 ++ ByteArray.mk #[0, 0, 0, 2] ++ ByteArray.mk (Crypto.SHA1.wordBytesBE count)
  for object in built.objects do out := out ++ objectHeader object ++ (← Crypto.Zlib.compress object.data)
  return out ++ Crypto.SHA1.hash out

def packet (value : String) : String :=
  let size := value.toUTF8.size + 4
  Data.Hex.encode (ByteArray.mk #[(size / 256).toUInt8, size.toUInt8]) ++ value

private def decodePackets : List Char → Except String (List String)
  | a :: b :: c :: d :: rest => do
    let some header := Data.Hex.decode (String.ofList [a,b,c,d]) | throw "malformed Git packet header"
    let size := header[0]!.toNat * 256 + header[1]!.toNat
    if size == 0 then decodePackets rest
    else
      unless size ≥ 4 && size - 4 ≤ rest.length do throw "truncated Git packet"
      let value := String.ofList (rest.take (size - 4))
      return value :: (← decodePackets (rest.drop (size - 4)))
  | [] => .ok []
  | _ => .error "truncated Git packet header"
termination_by value => value.length
decreasing_by all_goals simp_wf; omega

def advertised (body branch expected : String) : Except String Unit := do
  let packets ← decodePackets body.toList
  unless packets.head? == some "# service=git-receive-pack\n" do throw "unexpected Git service advertisement"
  let entries := packets.drop 1
  unless entries.any (fun line => ((line.splitOn "\x00").headD "").trimAscii.toString == expected ++ " refs/heads/" ++ branch) &&
      entries.any (fun line => ((line.splitOn "\x00")[1]?).any (fun capabilities => (capabilities.trimAscii.toString.splitOn " ").contains "report-status")) do
    throw "Git branch moved or report-status unavailable"

def publicationBody (built : Built) (branch : String) (packed : ByteArray) : ByteArray :=
  (packet s!"{built.parent} {built.commit.id} refs/heads/{branch}\x00report-status\n" ++ "0000").toUTF8 ++ packed

def published (body branch : String) : Bool :=
  match decodePackets body.toList with
  | .ok packets => packets == ["unpack ok\n", "ok refs/heads/" ++ branch ++ "\n"]
  | .error _ => false

end Liaison.Egress.GitPack
