/- Real Lode SDK, model serializers/parsers and Workspace against the real
   credential broker. Only the authenticated API backends are disposable mocks. -/
import Lode.Model
import Lode.Workspace

open Lean Lode
private def read (value : Json) (name : String) : IO String := IO.ofExcept ((value.getObjValAs? String name).mapError IO.userError)

def main : IO Unit := do
  let json ← IO.ofExcept ((Json.parse (← (← IO.getStdin).getLine)).mapError IO.userError)
  let broker ← read json "broker"
  let provider ← read json "provider"
  let credentials ← IO.ofExcept ((json.getObjVal? "credentials" >>= fun value =>
    Liaison.Credentials.parse value "fixture" [provider]).mapError IO.userError)
  if (← read json "mode") == "model" then
    let model ← read json "model"
    let api ← read json "api"
    let protocol := if api == "messages" then Model.Api.anthropic else if api == "responses" then .responses else if api == "gemini" then .gemini else if api == "pi" then .pi else .openai
    let cfg : Model.Config := { api := protocol, name := model, baseUrl := "https://fixture.invalid/v1" }
    let tools : Array Model.ToolSpec := #[{ name := "todo", description := "Local writer metadata", schema := Json.mkObj [("type", "object"), ("properties", Json.mkObj [])] }]
    let abort ← IO.mkRef false
    let mut messages : Array Lode.Message := #[.user "fixture writer task"]
    for step in [0:3] do
      let reply ← if api == "pi" then do
        let body := Model.piRequest cfg "Fixture" tools messages "fixture-session"
        let fields ← IO.ofExcept (body.getObj? |>.mapError IO.userError)
        let payload := Json.mkObj (fields.toList.filter (·.1 != "model"))
        let response ← Liaison.inference broker credentials model payload
          { sessionId := "fixture-session", initiator := if step == 0 then "user" else "agent" } 10000
        IO.ofExcept ((Model.piReply (Liaison.text response) (some cfg)).mapError IO.userError)
        else Model.complete cfg (.liaison broker credentials) "Fixture" tools messages step 10000 abort "fixture-session"
      if step < 2 then
        unless reply.calls.size == 1 && reply.calls[0]!.name == "todo" do throw (IO.userError "writer tool response did not survive broker")
        messages := messages.push (match reply.replay with
          | some replay => .assistantReplay reply.text reply.calls replay
          | none => .assistant reply.text reply.calls)
        messages := messages.push (.toolResults (reply.calls.map fun call => { id := call.id, name := call.name, content := "local metadata result", isError := false, nativeId := call.nativeId }))
      else unless reply.text == "writer finished" && reply.calls.isEmpty do throw (IO.userError "writer continuation failed")
    IO.println "PASS: real writer serializers, signed reasoning, function replay and reply parsers"
  else
    let directory ← read json "directory"
    let url := if provider == "github" then "https://github.com/owner/repo" else "https://gitlab.com/owner/repo"
    let repo ← IO.ofExcept ((System.Git.Repository.parse url).mapError IO.userError)
    let source : Workspace.Source := { repo, branch := "main", path := "typednotes/graph" }
    let context : Workspace.Context := { liaisonUrl := some broker, timeoutMs := 10000 }
    let state ← Workspace.«open» context source (some credentials) directory
    unless (← IO.FS.readFile (directory / "Outside.txt" : System.FilePath)) == "published outside\n" do throw (IO.userError "checkout lost out-of-project file")
    IO.FS.writeFile (directory / "typednotes" / "graph" / "Main.lean" : System.FilePath) "writer changed\n"
    let (published, _) ← Workspace.publish context source (some credentials) directory state "Native fixture writer"
    unless published.remoteHead != state.remoteHead do throw (IO.userError "publication did not advance remote head")
    IO.println "PASS: real authenticated Workspace checkout, local commit and scoped atomic publication"
