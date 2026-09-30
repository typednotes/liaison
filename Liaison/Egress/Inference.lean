/- Bounded inline writer protocols. Functions are local metadata, never hosted
   provider tools. Replay references are resolved within the supplied transcript. -/
import Liaison.Wire
import Linen.Data.Json.Bridge

namespace Liaison.Egress.Inference
open Lean (Json)

/-- Independently provisioned by the trusted writer/minting service. -/
structure Policy where
  sessionId : String
  allowedTools : List String
  deriving Lean.FromJson

def toolName (name : String) : Bool :=
  !name.isEmpty && name.length ≤ 64 && name.all (fun c => c.isAlphanum || c == '_' || c == '-')

def Policy.valid (policy : Policy) : Bool :=
  Wire.validAccountSegment policy.sessionId && policy.sessionId.length ≤ 128 &&
    policy.allowedTools.length ≤ 128 && policy.allowedTools.all toolName &&
    policy.allowedTools.eraseDups.length == policy.allowedTools.length

def fieldsOnly (value : Json) (allowed : List String) : Except String Unit := do
  let fields ← value.getObj?
  unless fields.toList.all (fun entry => allowed.contains entry.1) do throw "unsupported native inference field"

private def text (value : Json) (key : String) : Except String String := value.getObjValAs? String key
private def array (value : Json) (key : String) : Except String (List Json) := value.getObjValAs? (List Json) key
private def optional (value : Json) (key : String) (check : Json → Except String Unit) : Except String Unit :=
  match value.getObjVal? key with | .error _ => .ok () | .ok value => check value
private def isText (value : Json) : Except String Unit := do let _ ← value.getStr?; pure ()
private def isObject (value : Json) : Except String Unit := do let _ ← value.getObj?; pure ()

mutual
/-- Remote schema references/dynamic resolution are not local tool metadata. -/
private def localSchema : Data.Json.Value → Bool
  | .object fields => fields.all (fun (key, value) =>
      if key == "$ref" then (value.asString).any (·.startsWith "#/")
      else !key.startsWith "$" || key == "$defs") && schemaFields fields
  | .array values => schemaValues values.toList
  | _ => true
private def schemaFields : List (String × Data.Json.Value) → Bool
  | [] => true | (_, value) :: rest => localSchema value && schemaFields rest
private def schemaValues : List Data.Json.Value → Bool
  | [] => true | value :: rest => localSchema value && schemaValues rest
end

private def schema (value : Json) : Except String Unit := do
  isObject value
  unless localSchema (← Data.Json.Value.ofLeanJson value) do throw "remote/dynamic function schema reference"

private def cache (value : Json) : Except String Unit := do
  fieldsOnly value ["type"]
  unless (← text value "type") == "ephemeral" do throw "unsupported cache directive"

private def definition (value : Json) (api : String) : Except String String := do
  fieldsOnly value (if api == "messages" then ["name", "description", "input_schema", "cache_control"]
    else ["name", "description", "parameters", "strict"])
  let name ← text value "name"
  unless toolName name do throw "invalid function name"
  optional value "description" isText
  schema (← value.getObjVal? (if api == "messages" then "input_schema" else "parameters"))
  optional value "strict" (fun value => do unless value == .bool false do throw "only local non-strict function tools are supported")
  optional value "cache_control" cache
  return name

private def tools (api : String) (payload : Json) : Except String (List String) := do
  let values ← match payload.getObjVal? "tools" with | .error _ => pure [] | .ok value => value.getArr? |>.map Array.toList
  unless values.length ≤ 128 do throw "too many function tools"
  let mut names := []
  for value in values do
    if api == "gemini" then
      fieldsOnly value ["functionDeclarations"]
      for tool in ← array value "functionDeclarations" do names := names ++ [← definition tool api]
    else if api == "chat" then
      fieldsOnly value ["type", "function"]
      unless (← text value "type") == "function" do throw "provider-hosted tools are forbidden"
      names := names ++ [← definition (← value.getObjVal? "function") api]
    else if api == "responses" then
      fieldsOnly value ["type", "name", "description", "parameters", "strict"]
      unless (← text value "type") == "function" do throw "provider-hosted tools are forbidden"
      let obj ← value.getObj?
      names := names ++ [← definition (Json.mkObj (obj.toList.filter (·.1 != "type"))) api]
    else names := names ++ [← definition value api]
  unless names.length ≤ 128 && names.eraseDups.length == names.length do throw "duplicate function definition"
  return names

private structure Reference where
  id : String
  name : String
  deriving DecidableEq

private structure Replay where
  seen : List String := []
  pending : List Reference := []
  names : List String := []

private def add (state : Replay) (id name : String) : Except String Replay := do
  unless state.seen.length < 4096 && !id.isEmpty && id.length ≤ 256 && toolName name && !state.seen.contains id do
    throw "invalid, duplicate or excessive replay function reference"
  return { seen := id :: state.seen, pending := state.pending ++ [⟨id, name⟩], names := name :: state.names }

private def answer (state : Replay) (id : String) (name : Option String := none) : Except String Replay := do
  let some call := state.pending.find? (fun call => call.id == id && name.all (· == call.name))
    | throw "tool result does not resolve to a preceding authorized function call"
  return { state with pending := state.pending.filter (· != call) }

private def blockText (value : Json) : Except String Unit := do
  fieldsOnly value ["type", "text", "cache_control"]
  unless (← text value "type") == "text" do throw "only inline text is supported"
  let _ ← text value "text"
  optional value "cache_control" cache

private def messages (values : List Json) : Except String (List String) := do
  let mut state : Replay := {}
  for message in values do
    fieldsOnly message ["role", "content"]
    let role ← text message "role"
    unless ["user", "assistant"].contains role do throw "invalid Messages role"
    let content ← message.getObjVal? "content"
    if content.getStr?.isOk then continue
    for block in ← content.getArr? |>.map Array.toList do
      match ← text block "type" with
      | "text" => blockText block
      | "tool_use" =>
        unless role == "assistant" do throw "function calls require assistant role"
        fieldsOnly block ["type", "id", "name", "input", "cache_control"]
        isObject (← block.getObjVal? "input")
        optional block "cache_control" cache
        state := ← add state (← text block "id") (← text block "name")
      | "tool_result" =>
        unless role == "user" do throw "tool outputs require user role"
        fieldsOnly block ["type", "tool_use_id", "content", "is_error", "cache_control"]
        let _ ← text block "content"
        optional block "is_error" (fun value => do let _ ← value.getBool?; pure ())
        optional block "cache_control" cache
        state := ← answer state (← text block "tool_use_id")
      | "thinking" =>
        unless role == "assistant" do throw "thinking requires assistant role"
        fieldsOnly block ["type", "thinking", "signature", "cache_control"]
        let _ ← text block "thinking"; let _ ← text block "signature"
        optional block "cache_control" cache
      | "redacted_thinking" =>
        unless role == "assistant" do throw "redacted thinking requires assistant role"
        fieldsOnly block ["type", "data", "cache_control"]
        let _ ← text block "data"; optional block "cache_control" cache
      | _ => throw "remote/unsupported Messages block"
  unless state.pending.isEmpty do throw "unanswered Messages function call"
  return state.names

private def chat (values : List Json) : Except String (List String) := do
  let mut state : Replay := {}
  for message in values do
    fieldsOnly message ["role", "content", "tool_calls", "tool_call_id", "reasoning_content"]
    let role ← text message "role"
    unless ["system", "user", "assistant", "tool"].contains role do throw "invalid Chat role"
    let content ← message.getObjVal? "content"
    unless content.getStr?.isOk || (role == "assistant" && content == .null) do throw "Chat content must be inline text"
    optional message "reasoning_content" isText
    if role == "tool" then
      fieldsOnly message ["role", "content", "tool_call_id"]
      state := ← answer state (← text message "tool_call_id")
    else
      unless (message.getObjVal? "tool_call_id").toOption.isNone do throw "unexpected tool result selector"
      if let .ok calls := message.getObjVal? "tool_calls" then
        unless role == "assistant" do throw "function calls require assistant role"
        for call in ← calls.getArr? |>.map Array.toList do
          fieldsOnly call ["id", "type", "function"]
          unless (← text call "type") == "function" do throw "hosted Chat tool"
          let function ← call.getObjVal? "function"
          fieldsOnly function ["name", "arguments"]
          let arguments ← text function "arguments"
          let _ ← Json.parse arguments >>= Json.getObj?
          state := ← add state (← text call "id") (← text function "name")
  unless state.pending.isEmpty do throw "unanswered Chat function call"
  return state.names

private def responses (values : List Json) : Except String (List String) := do
  let mut state : Replay := {}
  for item in values do
    let kind := (item.getObjValAs? String "type").toOption.getD "message"
    match kind with
    | "message" =>
      fieldsOnly item ["type", "id", "role", "status", "content"]
      unless ["user", "assistant", "system", "developer"].contains (← text item "role") do throw "invalid Responses role"
      let content ← item.getObjVal? "content"
      if content.getStr?.isOk then continue
      for part in ← content.getArr? |>.map Array.toList do
        fieldsOnly part ["type", "text", "annotations", "logprobs"]
        unless ["input_text", "output_text"].contains (← text part "type") do throw "remote Responses content"
        let _ ← text part "text"
        for field in ["annotations", "logprobs"] do optional part field (fun value => do unless value == .arr #[] do throw "unsupported Responses annotations")
    | "reasoning" =>
      fieldsOnly item ["type", "id", "summary", "encrypted_content", "status"]
      let _ ← text item "encrypted_content"
      for part in ← array item "summary" do
        fieldsOnly part ["type", "text"]
        unless (← text part "type") == "summary_text" do throw "unsupported reasoning summary"
        let _ ← text part "text"
    | "function_call" =>
      fieldsOnly item ["type", "id", "call_id", "name", "arguments", "status"]
      let _ ← Json.parse (← text item "arguments") >>= Json.getObj?
      state := ← add state (← text item "call_id") (← text item "name")
    | "function_call_output" =>
      fieldsOnly item ["type", "call_id", "output"]
      let _ ← text item "output"
      state := ← answer state (← text item "call_id")
    | _ => throw "hosted/reference Responses item"
  unless state.pending.isEmpty do throw "unanswered Responses function call"
  return state.names

private def gemini (values : List Json) : Except String (List String) := do
  let mut state : Replay := {}
  for message in values do
    fieldsOnly message ["role", "parts"]
    let role ← text message "role"
    unless ["user", "model"].contains role do throw "invalid Gemini role"
    for part in ← array message "parts" do
      fieldsOnly part ["text", "thought", "thoughtSignature", "functionCall", "functionResponse"]
      optional part "thoughtSignature" isText
      optional part "thought" (fun value => do let _ ← value.getBool?; pure ())
      let kinds := ["text", "functionCall", "functionResponse"].filter (fun name => (part.getObjVal? name).isOk)
      unless kinds.length == 1 do throw "ambiguous Gemini part"
      if kinds == ["text"] then let _ ← text part "text"
      else if kinds == ["functionCall"] then
        unless role == "model" do throw "Gemini calls require model role"
        let call ← part.getObjVal? "functionCall"
        fieldsOnly call ["id", "name", "args"]
        let name ← text call "name"
        isObject (← call.getObjVal? "args")
        optional call "id" isText
        let id := (call.getObjValAs? String "id").toOption.getD (s!"anonymous:{state.seen.length}:" ++ name)
        state := ← add state id name
      else
        unless role == "user" do throw "Gemini results require user role"
        let output ← part.getObjVal? "functionResponse"
        fieldsOnly output ["id", "name", "response"]
        let name ← text output "name"
        isObject (← output.getObjVal? "response")
        optional output "id" isText
        let id ← match output.getObjValAs? String "id" with
          | .ok id => pure id
          | .error _ => match state.pending.filter (·.name == name) with
            | [reference] => pure reference.id
            | _ => throw "ambiguous anonymous Gemini function result"
        state := ← answer state id (some name)
  unless state.pending.isEmpty do throw "unanswered Gemini function call"
  return state.names

private def pi (payload : Json) (model : String) : Except String (List String) := do
  fieldsOnly payload ["context", "options"]
  let options ← payload.getObjVal? "options"
  fieldsOnly options ["maxTokens", "sessionId"]
  let n ← options.getObjValAs? Nat "maxTokens"
  unless n > 0 && n ≤ 128000 do throw "invalid Pi output token bound"
  let session ← text options "sessionId"
  unless Wire.validAccountSegment session && session.length ≤ 128 do throw "invalid Pi session"
  let context ← payload.getObjVal? "context"
  fieldsOnly context ["messages"]
  let messages ← array context "messages"
  unless messages.length ≤ 2048 do throw "Pi transcript exceeds replay limit"
  let mut state : Replay := {}
  let mut names : List String := []
  for message in messages do
    let role ← text message "role"
    if role == "system" then
      fieldsOnly message ["role", "content", "timestamp", "toolsAdded"]
      let _ ← text message "content"
      for tool in ← array message "toolsAdded" do names := names ++ [← definition tool "pi"]
    else if role == "user" then
      fieldsOnly message ["role", "content", "timestamp"]
      let _ ← text message "content"
    else if role == "assistant" then
      fieldsOnly message ["role", "content", "api", "provider", "model", "timestamp", "stopReason", "usage"]
      unless (← text message "api") == "pi-messages" && (← text message "provider") == "radius" &&
          (← text message "model") == model do throw "Pi replay changes the selected model/provider"
      unless ["stop", "length", "toolUse"].contains (← text message "stopReason") do throw "invalid Pi stop reason"
      let usage ← message.getObjVal? "usage"
      fieldsOnly usage ["input", "output", "cacheRead", "cacheWrite", "totalTokens", "cost"]
      for name in ["input", "output", "cacheRead", "cacheWrite", "totalTokens"] do let _ ← usage.getObjValAs? Nat name
      let cost ← usage.getObjVal? "cost"
      fieldsOnly cost ["input", "output", "cacheRead", "cacheWrite", "total"]
      for name in ["input", "output", "cacheRead", "cacheWrite", "total"] do let _ ← cost.getObjValAs? Float name
      for block in ← array message "content" do
        match ← text block "type" with
        | "text" =>
          fieldsOnly block ["type", "text", "textSignature"]
          let _ ← text block "text"; optional block "textSignature" isText
        | "thinking" =>
          fieldsOnly block ["type", "thinking", "thinkingSignature", "redacted"]
          let _ ← text block "thinking"; optional block "thinkingSignature" isText
          optional block "redacted" (fun value => do let _ ← value.getBool?; pure ())
        | "toolCall" =>
          fieldsOnly block ["type", "id", "name", "arguments", "thoughtSignature"]
          isObject (← block.getObjVal? "arguments")
          optional block "thoughtSignature" isText
          state := ← add state (← text block "id") (← text block "name")
        | _ => throw "unsupported Pi content block"
    else if role == "toolResult" then
      fieldsOnly message ["role", "toolCallId", "toolName", "content", "isError", "timestamp"]
      let _ ← message.getObjValAs? Bool "isError"
      for block in ← array message "content" do
        fieldsOnly block ["type", "text"]
        unless (← text block "type") == "text" do throw "unsupported Pi result block"
        let _ ← text block "text"
      state := ← answer state (← text message "toolCallId") (some (← text message "toolName"))
    else throw "unsupported Pi role"
    let _ ← message.getObjValAs? Nat "timestamp"
  unless state.pending.isEmpty && names.length ≤ 128 && names.eraseDups.length == names.length do throw "invalid Pi function replay"
  return names ++ state.names

private def tokenBound (value : Json) : Except String Unit := do
  let n ← Lean.fromJson? (α := Nat) value
  unless n > 0 && n ≤ 128000 do throw "invalid output token bound"

private def format (value : Json) : Except String Unit := do
  fieldsOnly value ["type", "name", "description", "schema", "strict", "json_schema"]
  let kind ← text value "type"
  unless ["text", "json_object", "json_schema"].contains kind do throw "unsupported inline output format"
  optional value "name" isText
  optional value "description" isText
  optional value "schema" schema
  optional value "strict" (fun value => do let _ ← value.getBool?; pure ())
  optional value "json_schema" (fun value => do
    fieldsOnly value ["name", "description", "schema", "strict"]
    let _ ← text value "name"
    schema (← value.getObjVal? "schema")
    optional value "description" isText
    optional value "strict" (fun value => do let _ ← value.getBool?; pure ()))

/-- Every secondary function reference is returned for trusted-policy checking.
    Only inline transcript shapes are accepted; IDs cannot fetch hosted state. -/
def validate (api : String) (payload : Json) (model : String := "") : Except String (List String) := do
  if api == "pi" then return ← pi payload model
  let top := if api == "messages" then ["messages", "system", "max_tokens", "temperature", "top_p", "stop_sequences", "thinking", "tools"]
    else if api == "chat" then ["messages", "max_tokens", "max_completion_tokens", "temperature", "top_p", "stop", "response_format", "reasoning_effort", "tools"]
    else if api == "responses" then ["input", "instructions", "max_output_tokens", "temperature", "top_p", "reasoning", "text", "tools", "store", "include"]
    else if api == "gemini" then ["contents", "systemInstruction", "generationConfig", "safetySettings", "tools"] else []
  fieldsOnly payload top
  let names ← tools api payload
  for name in ["max_tokens", "max_completion_tokens", "max_output_tokens"] do
    optional payload name tokenBound
  optional payload "response_format" format
  optional payload "text" (fun value => do
    fieldsOnly value ["format", "verbosity"]
    optional value "format" format
    optional value "verbosity" isText)
  optional payload "reasoning" (fun value => do
    fieldsOnly value ["effort", "summary"]
    optional value "effort" isText
    optional value "summary" isText)
  optional payload "thinking" (fun value => do
    fieldsOnly value ["type", "budget_tokens"]
    unless ["enabled", "adaptive", "disabled"].contains (← text value "type") do throw "unsupported Messages thinking mode"
    optional value "budget_tokens" tokenBound)
  if api == "responses" then
    optional payload "store" (fun value => do unless value == .bool false do throw "provider conversation persistence is forbidden")
    optional payload "include" (fun value => do unless value == Lean.toJson ["reasoning.encrypted_content"] do throw "unsupported Responses include")
    optional payload "instructions" isText
  if api == "messages" then
    optional payload "system" (fun value => if value.getStr?.isOk then pure () else do for block in ← value.getArr? |>.map Array.toList do blockText block)
  if api == "gemini" then
    optional payload "systemInstruction" (fun value => do
      fieldsOnly value ["parts"]
      for part in ← array value "parts" do fieldsOnly part ["text"]; let _ ← text part "text")
    optional payload "generationConfig" (fun value => do
      fieldsOnly value ["maxOutputTokens", "temperature", "topP", "topK", "thinkingConfig"]
      optional value "maxOutputTokens" tokenBound
      optional value "thinkingConfig" (fun value => do
        fieldsOnly value ["includeThoughts", "thinkingBudget", "thinkingLevel"]
        optional value "includeThoughts" (fun value => do let _ ← value.getBool?; pure ())
        optional value "thinkingBudget" (fun value => do let n ← Lean.fromJson? (α := Int) value; unless n ≥ -1 && n ≤ 128000 do throw "invalid thinking budget")
        optional value "thinkingLevel" isText))
    optional payload "safetySettings" (fun value => do
      for value in ← value.getArr? |>.map Array.toList do
        fieldsOnly value ["category", "threshold"]
        let _ ← text value "category"; let _ ← text value "threshold")
  let key := if api == "responses" then "input" else if api == "gemini" then "contents" else "messages"
  let value ← payload.getObjVal? key
  if api == "responses" && value.getStr?.isOk then return names
  let values ← value.getArr? |>.map Array.toList
  unless values.length ≤ 2048 && value.compress.toUTF8.size ≤ 67108864 do throw "conversation exceeds replay limits"
  let referenced ← if api == "messages" then messages values else if api == "chat" then chat values
    else if api == "responses" then responses values else if api == "gemini" then gemini values else throw "unsupported inference protocol"
  return names ++ referenced

/-- Buffered SSE must terminate cleanly and name only authorized local tools. -/
def validateSse (body : String) (allowed : List String) : Except String Unit := do
  let lines := (body.replace "\r\n" "\n").splitOn "\n"
  unless lines.length ≤ 65536 do throw "too many SSE records"
  let mut pending : List (Nat × String) := []
  let mut ended : List Nat := []
  let mut toolIds : List String := []
  let mut toolStarts : List (Nat × String × String) := []
  let mut terminal := false
  for line in lines do
    if line.isEmpty || line.startsWith ":" || line.startsWith "event:" then continue
    unless line.startsWith "data:" do throw "unsupported SSE framing"
    let value := (line.drop 5).toString.trimAscii.toString
    if value == "[DONE]" then
      unless terminal do throw "SSE ended before terminal event"
      continue
    unless !terminal do throw "SSE data after terminal event"
    let event ← Json.parse value
    let kind ← text event "type"
    if kind == "start" then fieldsOnly event ["type"]
    else if kind == "done" then
      fieldsOnly event ["type", "reason", "usage"]
      unless pending.isEmpty do throw "SSE ended with unfinished blocks"
      let reason ← text event "reason"
      unless ["stop", "length", "toolUse"].contains reason && (reason == "toolUse") == !toolIds.isEmpty do throw "SSE stop/tool mismatch"
      let usage ← event.getObjVal? "usage"
      fieldsOnly usage ["input", "output", "cacheRead", "cacheWrite"]
      for name in ["input", "output"] do let _ ← usage.getObjValAs? Nat name
      for name in ["cacheRead", "cacheWrite"] do optional usage name (fun value => do let _ ← Lean.fromJson? (α := Nat) value; pure ())
      terminal := true
    else
      let index ← event.getObjValAs? Nat "contentIndex"
      unless index < 4096 do throw "SSE content index out of bounds"
      let category := (kind.splitOn "_").headD ""
      unless ["text", "thinking", "toolcall"].contains category do throw "unsupported/error SSE event"
      if kind.endsWith "_start" then
        fieldsOnly event ["type", "contentIndex", "id", "toolName"]
        unless !ended.contains index && !(pending.any (·.1 == index)) do throw "duplicate SSE block"
        if category == "toolcall" then
          let name ← text event "toolName"
          let id ← text event "id"
          unless allowed.contains name && !id.isEmpty && !toolIds.contains id do throw "unlisted/duplicate SSE function"
          toolStarts := (index, id, name) :: toolStarts
        pending := (index, category) :: pending
      else
        unless pending.contains (index, category) do throw "SSE block does not resolve to its start"
        if kind.endsWith "_delta" then
          fieldsOnly event ["type", "contentIndex", "delta"]
          let _ ← text event "delta"
        else if kind.endsWith "_end" then
          if category == "toolcall" then
            fieldsOnly event ["type", "contentIndex", "toolCall"]
            let call ← event.getObjVal? "toolCall"
            fieldsOnly call ["type", "id", "name", "arguments", "thoughtSignature"]
            unless (← text call "type") == "toolCall" && allowed.contains (← text call "name") do throw "unlisted SSE function"
            let id ← text call "id"
            unless !id.isEmpty && !toolIds.contains id do throw "duplicate SSE function ID"
            unless toolStarts.contains (index, id, (← text call "name")) do throw "SSE function end differs from its start"
            isObject (← call.getObjVal? "arguments")
            toolIds := id :: toolIds
          else
            fieldsOnly event ["type", "contentIndex", "content", "contentSignature", "redacted"]
            let _ ← text event "content"
          pending := pending.filter (·.1 != index)
          ended := index :: ended
        else throw "unsupported SSE event"
  unless terminal do throw "SSE stream has no terminal event"

structure CheckedSse (allowed : List String) where
  private mk ::
  body : String
  validated : validateSse body allowed = .ok ()

def checkSse (body : String) (allowed : List String) : Except String (CheckedSse allowed) :=
  match h : validateSse body allowed with
  | .error error => .error error
  | .ok () => .ok ⟨body, h⟩

/-- Execution consumes proof that every declared/replayed name is authorized. -/
structure Authorized (allowed : List String) (api : String) (payload : Json) where
  private mk ::
  references : List String
  valid : validate api payload = .ok references
  named : references.all allowed.contains = true

def authorize (allowed : List String) (api : String) (payload : Json) : Except String (Authorized allowed api payload) :=
  match hv : validate api payload with
  | .error error => .error error
  | .ok references => if hn : references.all allowed.contains = true then .ok ⟨references, hv, hn⟩
      else .error "function reference is not in the trusted run tool allowlist"

theorem Authorized.reference_allowed {allowed api payload} (value : Authorized allowed api payload)
    (name : String) (membership : name ∈ value.references) : name ∈ allowed := by
  have h := List.all_eq_true.mp value.named name membership
  exact List.contains_iff_mem.mp h

end Liaison.Egress.Inference
