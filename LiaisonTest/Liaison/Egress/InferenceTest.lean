import Liaison.Egress.Inference
import Liaison.Egress.Connector

open Lean Liaison.Egress Liaison.Egress.Inference Control.Monad.Effect.Connector
namespace NativeInferenceTests
private def json (text : String) : Json := (Json.parse text).toOption.getD .null
def chat := json "{\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"todo\",\"parameters\":{\"type\":\"object\"}}}],\"messages\":[{\"role\":\"assistant\",\"content\":null,\"reasoning_content\":\"signed text\",\"tool_calls\":[{\"id\":\"one\",\"type\":\"function\",\"function\":{\"name\":\"todo\",\"arguments\":\"{}\"}}]},{\"role\":\"tool\",\"tool_call_id\":\"one\",\"content\":\"done\"}]}"
#guard (authorize ["todo"] "chat" chat).isOk
#guard (authorize [] "chat" chat).toOption.isNone
#guard (validate "chat" (json "{\"messages\":[{\"role\":\"tool\",\"tool_call_id\":\"missing\",\"content\":\"done\"}]}" )).toOption.isNone
#guard (validate "responses" (json "{\"input\":[{\"type\":\"item_reference\",\"id\":\"remote\"}]}" )).toOption.isNone
#guard (validate "responses" (json "{\"input\":\"hello\",\"store\":true}" )).toOption.isNone
#guard (validate "responses" (json "{\"input\":\"hello\",\"include\":[\"web_search_call.action.sources\"]}" )).toOption.isNone
#guard (validate "chat" (json "{\"messages\":[],\"tools\":[{\"type\":\"web_search\"}]}" )).toOption.isNone
#guard (validate "chat" (json "{\"messages\":[],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"todo\",\"parameters\":{\"$ref\":\"https://remote.invalid/schema\"}}}]}" )).toOption.isNone
#guard (validate "messages" (json "{\"messages\":[{\"role\":\"assistant\",\"content\":[{\"type\":\"thinking\",\"thinking\":\"text\",\"signature\":\"opaque\"},{\"type\":\"redacted_thinking\",\"data\":\"opaque\"}]}]}" )).isOk
#guard (validate "responses" (json "{\"input\":[{\"type\":\"reasoning\",\"id\":\"inline\",\"summary\":[],\"encrypted_content\":\"opaque\"}]}" )).isOk
#guard (validate "gemini" (json "{\"contents\":[{\"role\":\"model\",\"parts\":[{\"text\":\"signed\",\"thoughtSignature\":\"opaque\"}]}]}" )).isOk
#guard (validate "gemini" (json "{\"contents\":[{\"role\":\"user\",\"parts\":[{\"fileData\":{\"fileUri\":\"https://remote.invalid\"}}]}]}" )).toOption.isNone

def cap : Capability := { provider := "openai", connection := "c", scopes := [{ operation := "inference.generate", root := ["model"], descendants := false }] }
def authority : Authority := ⟨cap, cap, cap, cap⟩
def context : Liaison.Wire.NativeContext := { sessionId := "session", initiator := "agent", client := "typednotes-lode" }
#guard match AuthorizedResource.check? authority "inference.generate" ["model"] with
  | none => false
  | some resource => (Connector.prepare authority "inference.generate" resource "https://fixture.invalid" "u/c" chat.compress (some context)
      (some { sessionId := "session", allowedTools := ["todo"] })).isOk
#guard !Connector.contextPermitted (some context) (some { sessionId := "another", allowedTools := ["todo"] })
example {allowed api payload} (authorized : Inference.Authorized allowed api payload) (name : String) (member : name ∈ authorized.references) :
    name ∈ allowed := authorized.reference_allowed name member

def sse := "data: {\"type\":\"start\"}\n\ndata: {\"type\":\"text_start\",\"contentIndex\":0}\n\ndata: {\"type\":\"text_end\",\"contentIndex\":0,\"content\":\"hi\"}\n\ndata: {\"type\":\"done\",\"reason\":\"stop\",\"usage\":{\"input\":1,\"output\":1}}\n\n"
#guard (validateSse sse []).isOk
#guard (validateSse (sse.replace "\"stop\"" "\"unsupported\"") []).toOption.isNone
#guard (validateSse "data: {\"type\":\"start\"}\n\n" []).toOption.isNone
#guard (validateSse (sse ++ "data: {\"type\":\"start\"}\n\n") []).toOption.isNone
end NativeInferenceTests
