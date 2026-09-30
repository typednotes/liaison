/- Named connector operations. URLs and methods are derived by the broker,
   never selected by a computation holding a scoped resource witness. -/
import Liaison.Wire
import Liaison.Egress.Policy
import Linen.Data.Json.Bridge
import Linen.Control.Monad.Effect.Connector
import Linen.Network.HTTP.Types.URI
import Linen.Data.Base64
import Liaison.Egress.Inference
import Liaison.Egress.Repository

namespace Liaison.Egress.Connector

open Lean (Json)
open Control.Monad.Effect.Connector (Capability Scope AuthorizedResource Authority)

/-- The vault document owns the connection ceiling independently of its key. -/
structure Permissions where
  scopes : List Scope
  maxRequestBytes : Nat
  maxResponseBytes : Nat
  deriving Lean.FromJson

def Permissions.capability (permissions : Permissions) (provider connection : String) : Capability :=
  { provider, connection, scopes := permissions.scopes,
    maxRequestBytes := permissions.maxRequestBytes, maxResponseBytes := permissions.maxResponseBytes }

/-- Check raw numeric input before the Float-to-JSON bridge can round it. -/
private def permissionLimits (value : Data.Json.Value) : Except String Unit := do
  for name in ["maxRequestBytes", "maxResponseBytes"] do
    let some number := value.lookup name >>= Data.Json.Value.asNumber | throw "permission limits must be numbers"
    unless !number.isNaN && !number.isInf && number.floor == number && number > 0 && number ≤ 67108864 do
      throw "permission limits must be integers from 1 byte to 64 MiB"

def Permissions.parse (value : Data.Json.Value) : Except String Permissions := do
  Wire.objectFields value ["scopes", "maxRequestBytes", "maxResponseBytes"] ["scopes", "maxRequestBytes", "maxResponseBytes"]
  permissionLimits value
  let some scopes := value.lookup "scopes" >>= Data.Json.Value.asArray | throw "scopes must be an array"
  for scope in scopes do
    Wire.objectFields scope ["operation", "root", "descendants"] ["operation", "root", "descendants"]
  let permissions : Permissions ← Lean.fromJson? (← value.toLeanJson)
  unless permissions.scopes.length ≤ 128 && permissions.maxRequestBytes > 0 && permissions.maxRequestBytes ≤ 67108864 &&
      permissions.maxResponseBytes > 0 && permissions.maxResponseBytes ≤ 67108864 &&
      permissions.scopes.all (fun scope => !scope.operation.isEmpty && scope.operation.length ≤ 64 && Wire.validResource scope.root) do
    throw "invalid connection permission limits"
  return permissions

/-- Legacy connections have narrowly useful read defaults for typed effects.
    Mutating operations require an explicit independently stored grant. -/
def readDefaults : Permissions :=
  { scopes := ["objects.list", "objects.read", "files.list", "files.read", "calendars.list", "events.read",
      "mailboxes.list", "messages.read", "messages.search", "attachments.read", "pages.read", "databases.query",
      "channels.list", "repositories.list", "repositories.read", "issues.read", "models.list", "inference.generate", "classification.evaluate"].map
      (fun operation => { operation, root := [], descendants := true }),
    maxRequestBytes := 1048576, maxResponseBytes := 16777216 }

def aiProviders : List String :=
  ["anthropic", "mistral", "openai", "openai-compatible", "ant-ling", "baseten", "cerebras", "deepseek",
   "fireworks", "github-copilot", "gemini", "groq", "huggingface", "kimi-coding", "meta", "minimax", "minimax-cn",
   "moonshotai", "moonshotai-cn", "nvidia", "opencode-go", "opencode", "openrouter", "qwen-token-plan",
   "qwen-token-plan-cn", "qwen-token-plan-individual", "radius", "scaleway", "together", "typesafe",
   "vercel-ai-gateway", "xiaomi", "xiaomi-token-plan-ams", "xiaomi-token-plan-cn", "xiaomi-token-plan-sgp",
   "zai-coding-cn", "zai", "xai"]

def encodeComponent (s : String) : String := Network.HTTP.Types.urlEncode s

private def field (payload : Json) (name : String) : Except String Json := payload.getObjVal? name
private def string (payload : Json) (name : String) : Except String String := payload.getObjValAs? String name

/-- Strict across both JSON implementations; keep original numeric precision. -/
def parseJson (text : String) : Except String Json := do
  let raw ← Data.Json.Decode.decode text
  unless Wire.uniqueKeys raw do throw "duplicate JSON field"
  Json.parse text

/-- Unknown fields are refused, including selector, URL and header overrides.
    Nested provider objects also use explicit allowlists. -/
def fieldsOnly (payload : Json) (allowed : List String) : Except String Unit := do
  let fields ← payload.getObj?
  unless fields.toList.all (fun (key, _) => allowed.contains key) do
    throw "unsupported payload field"

def email (address : String) : Except String String := do
  unless (address.splitOn "@").length == 2 && !address.startsWith "@" && !address.endsWith "@" && address.all (fun c => c.isAlphanum || "@._+-".toList.contains c) do
    throw "one plain email address is required"
  return address

private def usesResponses (model : String) : Bool :=
  (model.startsWith "gpt-" && ((model.drop 4).toString.splitOn "." |>.headD "" |>.splitOn "-" |>.headD "" |>.toNat? |>.getD 0) ≥ 5) ||
    ["o1", "o3", "o4"].any (fun stem => model.startsWith stem)

/-- Kept in sync with typednotes `api/src/ai.rs::ai_api`. -/
def modelApi (provider model : String) : String :=
  if provider == "typesafe" || (provider == "opencode" && model.startsWith "jev-") then "classifier"
  else if provider == "radius" then "pi"
  else if provider == "gemini" || (provider == "opencode" && model.startsWith "gemini-") then "gemini"
  else if ["anthropic", "minimax", "minimax-cn", "kimi-coding"].contains provider ||
      (["opencode", "opencode-go", "github-copilot"].contains provider && model.startsWith "claude-") ||
      (["opencode", "opencode-go"].contains provider && model.startsWith "qwen" && !(provider == "opencode" && model == "qwen3.8-max")) ||
      (provider == "opencode-go" && model.startsWith "minimax-") then "messages"
  else if ["meta", "xai"].contains provider || (provider == "openai" && usesResponses model) ||
      (["opencode", "opencode-go"].contains provider && (usesResponses model || model.startsWith "grok-" || model.startsWith "muse-spark-")) ||
      (provider == "github-copilot" && model.startsWith "gpt-" && usesResponses model && !model.startsWith "gpt-5-mini") then "responses"
  else "chat"

/-- Dropbox's documented content origin is a fixed provider route, never a
    caller-selected host. Custom/test gateways retain their own stored origin. -/
def transportBase (provider operation base : String) : String :=
  if provider == "dropbox" && ["files.read", "files.create", "files.update"].contains operation &&
      base == "https://api.dropboxapi.com" then "https://content.dropboxapi.com" else base

/-- Native adapter coverage, not the aspirational application catalog. -/
def operations (provider : String) : List String :=
  if ["s3", "azure"].contains provider then ["objects.list", "objects.read", "objects.write", "objects.delete"]
  else if aiProviders.contains provider then
    if provider == "typesafe" then ["models.list", "classification.evaluate"]
    else ["models.list", "inference.generate"] ++ (if provider == "opencode" then ["classification.evaluate"] else [])
  else if provider == "gdrive" then ["files.list", "files.read", "files.create", "files.update", "files.delete", "files.share"]
  else if provider == "dropbox" then ["files.list", "files.read", "files.create", "files.update", "files.delete", "files.share"]
  else if ["google-calendar", "microsoft-calendar"].contains provider then
    ["calendars.list", "events.read", "events.create", "events.update", "events.delete", "events.invite"]
  else if provider == "caldav" then ["calendars.list", "events.read", "events.create", "events.update", "events.delete"]
  else if ["gmail", "outlook", "jmap"].contains provider then
    ["mailboxes.list", "messages.read", "messages.search", "drafts.create", "messages.send", "messages.update", "messages.delete", "attachments.read"]
  else if provider == "notion" then ["pages.read", "databases.query", "pages.create", "pages.update", "pages.delete", "comments.create"]
  else if provider == "slack" then ["channels.list", "messages.read", "messages.send", "messages.update", "messages.delete"]
  else if ["signal", "whatsapp"].contains provider then ["messages.send"]
  else if ["github", "gitlab"].contains provider then
    ["repositories.list", "repositories.read", "repositories.write", "repositories.delete", "issues.read", "issues.write", "pull_requests.write"]
  else []

/-- Local runtime grant groups use the same strict ceiling schema but are not
    remote connector transports. SQL and graph-secret execution remain in Lun's
    bound handlers; registering a policy family never exposes raw SQL/secret IO. -/
def policyOperations (provider : String) : List String :=
  if provider == "postgres" then ["rows.select", "rows.insert", "rows.update", "rows.delete"]
  else if provider == "vault" then ["secrets.describe", "secrets.read", "secrets.write", "secrets.list"]
  else operations provider

def Permissions.validate (permissions : Permissions) (provider : String) : Except String Permissions := do
  unless permissions.scopes.all (fun scope => (policyOperations provider).contains scope.operation) do
    throw "permission document contains an unsupported operation"
  return permissions

/-- An independent, server-owned run policy, keyed by the verified warrant.
    Clients cannot supply these ceilings in the connector payload. -/
structure RunPermissions where
  account : String
  cell : Capability
  warrant : Capability
  conversation : Option Inference.Policy := none
  publication : Option Repository.PublicationPolicy := none
  deriving Lean.FromJson

def RunPermissions.parse (value : Data.Json.Value) (provider connection account : String) : Except String RunPermissions := do
  Wire.objectFields value ["account", "cell", "warrant"] ["account", "cell", "warrant", "conversation", "publication"]
  if let some conversation := value.lookup "conversation" then
    Wire.objectFields conversation ["sessionId", "allowedTools"] ["sessionId", "allowedTools"]
  if let some publication := value.lookup "publication" then
    Wire.objectFields publication ["branch", "root"] ["branch", "root"]
  for name in ["cell", "warrant"] do
    let some cap := value.lookup name | throw "missing run ceiling"
    Wire.objectFields cap ["provider", "connection", "scopes", "maxRequestBytes", "maxResponseBytes"]
      ["provider", "connection", "scopes", "maxRequestBytes", "maxResponseBytes"]
    permissionLimits cap
    let some scopes := cap.lookup "scopes" >>= Data.Json.Value.asArray | throw "scopes must be an array"
    for scope in scopes do
      Wire.objectFields scope ["operation", "root", "descendants"] ["operation", "root", "descendants"]
  let policy : RunPermissions ← Lean.fromJson? (← value.toLeanJson)
  unless policy.account == account do throw "authority belongs to a different credential owner"
  if let some conversation := policy.conversation then
    unless conversation.valid do throw "invalid trusted conversation policy"
  if let some publication := policy.publication then
    unless Repository.branch publication.branch && Wire.validResource publication.root do throw "invalid trusted publication policy"
  for cap in [policy.cell, policy.warrant] do
    unless cap.provider == provider && cap.connection == connection do throw "authority identity mismatch"
    let permissions : Permissions := { scopes := cap.scopes, maxRequestBytes := cap.maxRequestBytes, maxResponseBytes := cap.maxResponseBytes }
    let _ ← Permissions.parse (← Data.Json.Value.ofLeanJson (Json.mkObj [
      ("scopes", Lean.toJson cap.scopes), ("maxRequestBytes", Lean.toJson cap.maxRequestBytes),
      ("maxResponseBytes", Lean.toJson cap.maxResponseBytes)]))
    let _ ← permissions.validate provider
  return policy

def RunPermissions.authority (policy : RunPermissions) (organization connection : Capability) : Authority :=
  { organization, connection, cell := policy.cell, warrant := policy.warrant }

def jmapBody (calls : List Json) (extra : List String := []) : Json :=
  Json.mkObj [("using", Lean.toJson (["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"] ++ extra)),
    ("methodCalls", Lean.toJson calls)]

def jmapMethod (name : String) (args : Json) : Json := Lean.toJson [Json.str name, args, Json.str "op"]

def jmapResult (json : Json) (name account : String) : Except String Json := do
  let responses ← json.getObjValAs? (List (List Json)) "methodResponses"
  match responses with
  | [[.str method, result, .str "op"]] =>
    unless method == name && (← result.getObjValAs? String "accountId") == account do throw "JMAP result identity mismatch"
    return result
  | _ => throw "unexpected JMAP method response"

private def calendarText (value : String) : String :=
  ((((value.replace "\\" "\\\\").replace "\r\n" "\n").replace "\r" "\n").replace "\n" "\\n").replace ";" "\\;" |>.replace "," "\\,"

private def calendarTime (payload : Json) (name : String) : Except String String := do
  let value ← string payload name
  unless value.length == 16 && (value.take 8).toString.all Char.isDigit &&
      (value.drop 8 |>.take 1 |>.toString) == "T" && (value.drop 9 |>.take 6 |>.toString).all Char.isDigit && value.endsWith "Z" do
    throw "calendar times must use UTC YYYYMMDDTHHMMSSZ"
  return value

/-- Inference accepts inline data, not provider-side URL/file retrieval,
    connector tools, fallback routing, or undocumented nested selectors. -/
private def inlineData : Nat → Json → Bool
  | 0, _ => false
  | fuel + 1, .obj fields => fields.toList.all (fun (key, value) =>
      !["url", "file_uri", "fileUri", "file_id", "fileId", "image_url", "fileData", "source", "tools", "models", "provider", "fallbacks"].contains key && inlineData fuel value)
  | fuel + 1, .arr values => values.all (inlineData fuel)
  | _, _ => true

/-- No operation has a raw URL or header override. Unsupported shapes fail
    closed; extending this adapter also requires extending its coverage tests. -/
def request (provider base : String) (call : Wire.ConnectorCall) : Except String Wire.ProviderCall := do
  unless Wire.validResource call.resource && (operations provider).contains call.operation do
    throw "unsupported operation or invalid resource"
  let payload ← parseJson call.payload
  unless (payload.getObj?).isOk do throw "connector payload must be an object"
  let mut method := "GET"
  let mut path := ""
  let mut body : Option String := none
  let mut headers := [("accept", "application/json")]
  let segment (index : Nat) := (call.resource[index]?).map encodeComponent
  let required (index : Nat) : Except String String := match segment index with
    | some value => .ok value
    | none => .error "the operation requires a resource identifier"
  let jsonBody (value : Json) := some value.compress
  if ["s3", "azure"].contains provider then
    fieldsOnly payload (if call.operation == "objects.write" then ["contents"] else [])
    let key := "/".intercalate (call.resource.map encodeComponent)
    match call.operation with
    | "objects.list" =>
      let objectPrefix := if key.isEmpty then "" else key ++ "/"
      path := if provider == "s3" then s!"?list-type=2&prefix={encodeComponent objectPrefix}" else s!"?restype=container&comp=list&prefix={encodeComponent objectPrefix}"
    | "objects.read" =>
      unless !key.isEmpty do throw "object read requires a key"
      path := "/" ++ key
    | "objects.write" =>
      unless !key.isEmpty do throw "object write requires a key"
      method := "PUT"; path := "/" ++ key
      body := some (← string payload "contents")
      headers := if provider == "azure" then [("x-ms-blob-type", "BlockBlob"), ("content-type", "application/octet-stream")] else [("content-type", "application/octet-stream")]
    | "objects.delete" =>
      unless !key.isEmpty do throw "object delete requires a key"
      method := "DELETE"; path := "/" ++ key
    | _ => throw "unsupported object operation"
  else if aiProviders.contains provider then
    let model := "/".intercalate call.resource
    match call.operation with
    | "models.list" =>
      fieldsOnly payload []
      unless call.resource.isEmpty do throw "model inventory requires the account resource"
      path := if provider == "radius" then "/config" else "/models"
    | "inference.generate" =>
      unless call.resource.length == 1 || (call.resource.length == 2 && ["huggingface", "openrouter", "fireworks", "together", "openai-compatible"].contains provider) ||
          (provider == "fireworks" && call.resource.length == 4 && call.resource[0]! == "accounts" && call.resource[2]! == "models") do
        throw "inference requires one model id (or an explicitly supported namespaced id)"
      method := "POST"
      let api := modelApi provider model
      if api == "classifier" then throw "this model does not use the generation protocol"
      let _ ← Inference.validate api payload model
      if api == "pi" then
        let some context := call.context | throw "Pi requires a bound native conversation context"
        let options ← field payload "options"
        unless (← string options "sessionId") == context.sessionId do throw "Pi session differs from native context"
        path := "/messages"; body := some (payload.setObjVal! "model" (.str model)).compress
        headers := [("accept", "text/event-stream")]
      else if api == "gemini" then
        path := "/models/" ++ encodeComponent model ++ ":generateContent"
        body := some payload.compress
      else
        path := if api == "messages" then "/messages" else if api == "responses" then "/responses" else "/chat/completions"
        let payload := if api == "responses" then payload.setObjVal! "store" (.bool false) else payload
        body := some (payload.setObjVal! "model" (Json.str model)).compress
      if let some context := call.context then
        unless context.valid do throw "invalid native context"
        headers := headers ++ [("user-agent", "typednotes-lode")]
        if ["opencode", "opencode-go"].contains provider then headers := headers ++ [("x-opencode-session", context.sessionId)]
        if provider == "github-copilot" then headers := headers ++ [("x-initiator", context.initiator), ("x-intent", "conversation-panel")]
    | "classification.evaluate" =>
      unless inlineData 64 payload do throw "remote classifier reference"
      fieldsOnly payload ["state", "questions"]
      unless modelApi provider model == "classifier" && call.resource.length == 1 do throw "classification requires one classifier model"
      let _ ← field payload "state"
      let questions ← field payload "questions"
      unless (← questions.getObj?).toList.length > 0 do throw "classification requires typed questions"
      method := "POST"; path := "/systemone"
      body := some (payload.setObjVal! "model" (Json.str model)).compress
    | _ => throw "unsupported model operation"
  else if ["google-calendar", "microsoft-calendar"].contains provider then
    let calendar := (segment 0).getD ""
    let eventBase := if provider == "google-calendar" then s!"/calendar/v3/calendars/{calendar}/events" else s!"/me/calendars/{calendar}/events"
    match call.operation with
    | "calendars.list" =>
      fieldsOnly payload []
      unless call.resource.isEmpty do throw "calendar inventory requires the account resource"
      path := if provider == "google-calendar" then "/calendar/v3/users/me/calendarList" else "/me/calendars"
    | "events.read" =>
      fieldsOnly payload []
      unless call.resource.length == 1 || call.resource.length == 2 do throw "event read requires a calendar and optional event id"
      path := eventBase ++ (segment 1 |>.map ("/" ++ ·) |>.getD "")
    | "events.create" | "events.update" =>
      fieldsOnly payload ["event"]
      let event ← field payload "event"
      fieldsOnly event (if provider == "google-calendar" then ["summary", "description", "start", "end", "location"]
        else ["subject", "body", "start", "end", "location"])
      for name in (if provider == "google-calendar" then ["summary", "description", "location"] else ["subject"]) do
        match event.getObjVal? name with
        | .error _ => pure ()
        | .ok value => unless value.getStr?.isOk do throw "event text must be a string"
      for name in ["start", "end"] do
        match event.getObjVal? name with
        | .error _ => if call.operation == "events.create" then throw "event creation requires start and end"
        | .ok value =>
          fieldsOnly value (if provider == "google-calendar" then ["date", "dateTime", "timeZone"] else ["dateTime", "timeZone"])
          unless (← value.getObj?).toList.all (fun (_, val) => val.getStr?.isOk) do throw "event times must be strings"
      if provider == "microsoft-calendar" then
        match event.getObjVal? "location" with
        | .error _ => pure ()
        | .ok location =>
          fieldsOnly location ["displayName"]
          let _ ← string location "displayName"
        match event.getObjVal? "body" with
        | .error _ => pure ()
        | .ok content =>
          fieldsOnly content ["contentType", "content"]
          unless ["Text", "HTML", "text", "html"].contains (← string content "contentType") do throw "invalid event body content type"
          let _ ← string content "content"
      if call.operation == "events.create" then
        unless call.resource.length == 1 do throw "event create requires exactly one calendar"
        method := "POST"; path := eventBase
      else
        unless call.resource.length == 2 do throw "event update requires a calendar and event id"
        method := "PATCH"; path := eventBase ++ "/" ++ (← required 1)
      body := jsonBody event
    | "events.delete" =>
      fieldsOnly payload []
      unless call.resource.length == 2 do throw "event delete requires a calendar and event id"
      method := "DELETE"; path := eventBase ++ "/" ++ (← required 1)
    | "events.invite" =>
      fieldsOnly payload []
      unless call.resource.length == 3 do throw "invitation requires calendar, event and one recipient"
      let recipient ← email (call.resource[2]!)
      method := "PATCH"; path := eventBase ++ "/" ++ (← required 1)
      -- The broker preflight merges this attendee with the current set.
      let attendee := if provider == "google-calendar" then Json.mkObj [("email", Json.str recipient)] else
        Json.mkObj [("emailAddress", Json.mkObj [("address", Json.str recipient)]), ("type", "required")]
      body := jsonBody (Json.mkObj [("attendees", Lean.toJson [attendee])])
    | _ => throw "unsupported calendar operation"
  else if provider == "caldav" then
    match call.operation with
    | "calendars.list" =>
      fieldsOnly payload []
      unless call.resource.isEmpty do throw "calendar inventory requires the base resource"
      method := "PROPFIND"; path := "/"
      headers := [("depth", "1"), ("content-type", "application/xml")]
      body := some "<d:propfind xmlns:d=\"DAV:\"><d:prop><d:displayname/><d:resourcetype/></d:prop></d:propfind>"
    | "events.read" =>
      fieldsOnly payload []
      unless call.resource.length == 2 && call.resource[1]!.endsWith ".ics" do throw "CalDAV read requires calendar and .ics filename"
      path := "/" ++ (← required 0) ++ "/" ++ (← required 1)
    | "events.create" | "events.update" | "events.delete" =>
      unless call.resource.length == 2 && (call.resource[1]!).endsWith ".ics" do throw "CalDAV writes require calendar and .ics filename"
      fieldsOnly payload (if call.operation == "events.delete" then ["etag"] else if call.operation == "events.update" then ["etag", "summary", "start", "end"] else ["summary", "start", "end"])
      path := "/" ++ (← required 0) ++ "/" ++ (← required 1)
      let condition ← if call.operation == "events.create" then pure ("if-none-match", "*") else do
        let etag ← string payload "etag"
        unless strongEtag etag do throw "one strong ETag is required"
        pure ("if-match", etag)
      headers := [condition, ("content-type", "text/calendar; charset=utf-8")]
      if call.operation == "events.delete" then method := "DELETE"
      else
        method := "PUT"
        let start ← calendarTime payload "start"
        let finish ← calendarTime payload "end"
        let uid := calendarText call.resource[1]!
        let summary := calendarText (← string payload "summary")
        body := some s!"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Typednotes//Liaison//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:{start}\r\nDTSTART:{start}\r\nDTEND:{finish}\r\nSUMMARY:{summary}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    | _ => throw "CalDAV scheduling requires a separate verified scheduling adapter"
  else if provider == "jmap" then
    unless !call.resource.isEmpty do throw "JMAP requires an account id"
    let account := call.resource[0]!
    let args (fields : List (String × Json)) := Json.mkObj (("accountId", Json.str account) :: fields)
    let mut calls : List Json := []
    let mut extra : List String := []
    method := "POST"
    match call.operation with
    | "mailboxes.list" =>
      fieldsOnly payload []
      unless call.resource.length == 1 do throw "mailbox inventory requires the JMAP account"
      calls := [jmapMethod "Mailbox/get" (args [("ids", .null)])]
    | "messages.read" | "messages.search" =>
      fieldsOnly payload (if call.operation == "messages.search" then ["query"] else [])
      unless (call.operation == "messages.read" && (call.resource.length == 2 || call.resource.length == 3)) ||
          (call.operation == "messages.search" && call.resource.length == 2) do throw "JMAP read requires mailbox and optional email"
      if call.resource.length == 3 then calls := [jmapMethod "Email/get" (args [("ids", Lean.toJson [call.resource[2]!]), ("fetchTextBodyValues", true)])]
      else
        let filter ← if call.operation == "messages.search" then do
          pure (Json.mkObj [("inMailbox", Json.str call.resource[1]!), ("text", Json.str (← string payload "query"))])
          else pure (Json.mkObj [("inMailbox", Json.str call.resource[1]!)])
        calls := [jmapMethod "Email/query" (args [("filter", filter), ("limit", Lean.toJson (100 : Nat))])]
    | "drafts.create" =>
      fieldsOnly payload ["subject", "text"]
      unless call.resource.length == 2 do throw "draft requires account and drafts mailbox"
      let draft := Json.mkObj [("mailboxIds", Json.mkObj [(call.resource[1]!, true)]),
        ("keywords", Json.mkObj [("$draft", true)]), ("subject", Json.str (← string payload "subject")),
        ("textBody", Lean.toJson [Json.mkObj [("partId", "text"), ("type", "text/plain")]]),
        ("bodyValues", Json.mkObj [("text", Json.mkObj [("value", Json.str (← string payload "text"))])])]
      calls := [jmapMethod "Email/set" (args [("create", Json.mkObj [("draft", draft)])])]
    | "messages.update" =>
      fieldsOnly payload []
      unless call.resource.length == 4 do throw "move requires account, source mailbox, email and target mailbox"
      let pointer (id : String) := "mailboxIds/" ++ (id.replace "~" "~0").replace "/" "~1"
      let change := Json.mkObj [(pointer call.resource[1]!, .null), (pointer call.resource[3]!, true)]
      calls := [jmapMethod "Email/set" (args [("update", Json.mkObj [(call.resource[2]!, change)])])]
    | "messages.delete" =>
      fieldsOnly payload []
      unless call.resource.length == 3 do throw "delete requires account, mailbox and email"
      calls := [jmapMethod "Email/set" (args [("destroy", Lean.toJson [call.resource[2]!])])]
    | "messages.send" =>
      fieldsOnly payload []
      unless call.resource.length == 5 do throw "submission requires account, mailbox, email, recipient and identity"
      let recipient ← email call.resource[3]!
      -- The identity's validated address is added by the broker preflight.
      -- rcptTo is explicit so To/Cc/Bcc can never expand the actual delivery.
      calls := [jmapMethod "EmailSubmission/set" (args [("create", Json.mkObj [("send", Json.mkObj [
        ("emailId", Json.str call.resource[2]!), ("identityId", Json.str call.resource[4]!),
        ("envelope", Json.mkObj [("rcptTo", Lean.toJson [Json.mkObj [("email", Json.str recipient)]])])])])])]
      extra := ["urn:ietf:params:jmap:submission"]
    | "attachments.read" =>
      fieldsOnly payload []
      unless call.resource.length == 4 do throw "blob read requires account, mailbox, email and attachment blob id"
      calls := [jmapMethod "Blob/get" (args [("ids", Lean.toJson [call.resource[3]!]), ("properties", Lean.toJson ["data:asBase64", "size"])])]
      extra := ["urn:ietf:params:jmap:blob"]
    | _ => throw "unsupported JMAP operation"
    body := jsonBody (jmapBody calls extra)
  else if provider == "outlook" then
    let mailbox ← required 0
    unless mailbox == "me" do throw "this connection only opens its own mailbox"
    match call.operation with
    | "mailboxes.list" =>
      fieldsOnly payload []
      unless call.resource.length == 1 do throw "mailbox inventory requires me"
      path := "/me/mailFolders"
    | "messages.read" | "messages.search" =>
      fieldsOnly payload (if call.operation == "messages.search" then ["query"] else [])
      unless (call.operation == "messages.read" && (call.resource.length == 2 || call.resource.length == 3)) ||
          (call.operation == "messages.search" && call.resource.length == 2) do throw "message read/search requires a folder and optional message"
      path := "/me/mailFolders/" ++ (← required 1) ++ "/messages" ++ (segment 2 |>.map ("/" ++ ·) |>.getD "")
      if call.operation == "messages.search" then path := path ++ "?$search=" ++ encodeComponent (Json.str (← string payload "query")).compress
    | "drafts.create" =>
      fieldsOnly payload ["subject", "text"]
      unless call.resource == ["me", "drafts"] do throw "draft creation requires the drafts resource"
      method := "POST"; path := "/me/messages"
      body := jsonBody (Json.mkObj [("subject", Json.str (← string payload "subject")),
        ("body", Json.mkObj [("contentType", "Text"), ("content", Json.str (← string payload "text"))])])
    | "messages.send" =>
      fieldsOnly payload ["subject", "text"]
      unless call.resource.length == 3 && call.resource[1]! == "sentitems" do throw "send requires me, sentitems and one recipient"
      let recipient ← email call.resource[2]!
      method := "POST"; path := "/me/sendMail"
      body := jsonBody (Json.mkObj [("message", Json.mkObj [("subject", Json.str (← string payload "subject")),
        ("body", Json.mkObj [("contentType", "Text"), ("content", Json.str (← string payload "text"))]),
        ("toRecipients", Lean.toJson [Json.mkObj [("emailAddress", Json.mkObj [("address", Json.str recipient)])]])]),
        ("saveToSentItems", true)])
    | "messages.update" =>
      fieldsOnly payload []
      unless call.resource.length == 4 do throw "move requires source folder, message and destination folder"
      method := "POST"; path := "/me/mailFolders/" ++ (← required 1) ++ "/messages/" ++ (← required 2) ++ "/move"
      body := jsonBody (Json.mkObj [("destinationId", Json.str call.resource[3]!)])
    | "messages.delete" =>
      fieldsOnly payload []
      unless call.resource.length == 3 do throw "delete requires folder and message"
      method := "DELETE"; path := "/me/mailFolders/" ++ (← required 1) ++ "/messages/" ++ (← required 2)
    | "attachments.read" =>
      fieldsOnly payload []
      unless call.resource.length == 4 do throw "attachment requires folder, message and attachment"
      path := "/me/mailFolders/" ++ (← required 1) ++ "/messages/" ++ (← required 2) ++ "/attachments/" ++ (← required 3) ++ "/$value"
    | _ => throw "unsupported mailbox operation"
  else if provider == "gmail" then
    let mailbox ← required 0
    unless mailbox == "me" do throw "this connection only opens its own mailbox"
    match call.operation with
    | "mailboxes.list" =>
      fieldsOnly payload []
      unless call.resource.length == 1 do throw "mailbox inventory requires me"
      path := "/gmail/v1/users/me/labels"
    | "messages.read" | "messages.search" =>
      fieldsOnly payload (if call.operation == "messages.search" then ["query"] else [])
      unless (call.operation == "messages.read" && (call.resource.length == 2 || call.resource.length == 3)) ||
          (call.operation == "messages.search" && call.resource.length == 2) do throw "message read/search requires label and optional message"
      if call.resource.length == 3 then path := "/gmail/v1/users/me/messages/" ++ (← required 2)
      else
        path := "/gmail/v1/users/me/messages?labelIds=" ++ (← required 1)
        if call.operation == "messages.search" then path := path ++ "&q=" ++ encodeComponent (← string payload "query")
    | "drafts.create" | "messages.send" =>
      fieldsOnly payload ["subject", "text"]
      let subject ← string payload "subject"
      unless subject.all (fun c => c.toNat ≥ 32 && c.toNat < 127) do throw "subject must be plain ASCII without header injection"
      let recipient ← if call.operation == "messages.send" then do
        unless call.resource.length == 3 && call.resource[1]! == "SENT" do throw "send requires me, SENT and one recipient"
        pure ("To: " ++ (← email call.resource[2]!) ++ "\r\n")
        else do
          unless call.resource == ["me", "DRAFT"] do throw "draft requires me/DRAFT"
          pure ""
      let mime := recipient ++ "Subject: " ++ subject ++ "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" ++ Data.Base64.encode (← string payload "text").toUTF8
      let message := Json.mkObj [("raw", Json.str (((Data.Base64.encode mime.toUTF8).replace "+" "-").replace "/" "_"))]
      method := "POST"
      path := "/gmail/v1/users/me/" ++ (if call.operation == "drafts.create" then "drafts" else "messages/send")
      body := jsonBody (if call.operation == "drafts.create" then Json.mkObj [("message", message)] else message)
    | "messages.update" =>
      fieldsOnly payload []
      unless call.resource.length == 4 do throw "label move requires source label, message and target label"
      method := "POST"; path := "/gmail/v1/users/me/messages/" ++ (← required 2) ++ "/modify"
      body := jsonBody (Json.mkObj [("removeLabelIds", Lean.toJson [call.resource[1]!]), ("addLabelIds", Lean.toJson [call.resource[3]!])])
    | "messages.delete" =>
      fieldsOnly payload []
      unless call.resource.length == 3 do throw "delete requires label and message"
      method := "DELETE"; path := "/gmail/v1/users/me/messages/" ++ (← required 2)
    | "attachments.read" =>
      fieldsOnly payload []
      unless call.resource.length == 4 do throw "attachment requires label, message and attachment"
      path := "/gmail/v1/users/me/messages/" ++ (← required 2) ++ "/attachments/" ++ (← required 3)
    | _ => throw "unsupported Gmail operation or resource scope"
  else if provider == "gdrive" then
    -- Every supplied ancestor is checked against Drive metadata in the broker.
    unless !call.resource.isEmpty do throw "Drive requires a file or folder id"
    let leaf := encodeComponent (call.resource.getLast!)
    match call.operation with
    | "files.list" =>
      fieldsOnly payload []
      let folder := call.resource.getLast!
      unless folder.all (fun c => c.isAlphanum || c == '_' || c == '-') do throw "invalid Drive query identifier"
      path := s!"/drive/v3/files?q={encodeComponent ("'" ++ folder ++ "' in parents and trashed = false")}&fields=files(id,name,mimeType,parents),nextPageToken"
    | "files.read" =>
      fieldsOnly payload []
      path := "/drive/v3/files/" ++ leaf ++ "?alt=media"
    | "files.create" =>
      fieldsOnly payload ["name"]
      let name ← string payload "name"
      method := "POST"; path := "/drive/v3/files"
      body := jsonBody (Json.mkObj [("name", Json.str name), ("parents", Lean.toJson [call.resource.getLast!])])
    | "files.update" =>
      fieldsOnly payload ["name"]
      method := "PATCH"; path := "/drive/v3/files/" ++ leaf
      body := jsonBody (Json.mkObj [("name", Json.str (← string payload "name"))])
    | "files.delete" =>
      fieldsOnly payload []
      method := "DELETE"; path := "/drive/v3/files/" ++ leaf
    | "files.share" =>
      fieldsOnly payload []
      unless call.resource.length ≥ 2 do throw "share requires file and one recipient"
      let recipient ← email call.resource.getLast!
      method := "POST"; path := "/drive/v3/files/" ++ encodeComponent (call.resource[call.resource.length - 2]!) ++ "/permissions"
      body := jsonBody (Json.mkObj [("type", "user"), ("role", "reader"), ("emailAddress", Json.str recipient)])
    | _ => throw "unsupported Drive operation or resource scope"
  else if provider == "dropbox" then
    let resource := if call.resource.isEmpty then "" else "/" ++ "/".intercalate call.resource
    method := "POST"
    match call.operation with
    | "files.list" => fieldsOnly payload []; path := "/2/files/list_folder"; body := jsonBody (Json.mkObj [("path", resource), ("recursive", false)])
    | "files.read" =>
      fieldsOnly payload []
      unless !call.resource.isEmpty do throw "download requires a file path"
      path := "/2/files/download"
      headers := [("dropbox-api-arg", (Json.mkObj [("path", Json.str resource)]).compress)]
    | "files.create" | "files.update" =>
      fieldsOnly payload (if call.operation == "files.update" then ["contents", "revision"] else ["contents"])
      unless !call.resource.isEmpty do throw "upload requires a file path"
      let mode ← if call.operation == "files.create" then pure (Json.str "add") else do
        pure (Json.mkObj [(".tag", "update"), ("update", Json.str (← string payload "revision"))])
      path := "/2/files/upload"; body := some (← string payload "contents")
      headers := [("content-type", "application/octet-stream"), ("dropbox-api-arg",
        (Json.mkObj [("path", Json.str resource), ("mode", mode), ("autorename", false), ("strict_conflict", true)]).compress)]
    | "files.delete" =>
      fieldsOnly payload []
      unless !call.resource.isEmpty do throw "cannot delete the Dropbox root"
      path := "/2/files/delete_v2"; body := jsonBody (Json.mkObj [("path", resource)])
    | "files.share" =>
      fieldsOnly payload []
      unless call.resource.length ≥ 2 do throw "share requires file path and recipient"
      let recipient ← email call.resource.getLast!
      path := "/2/sharing/add_file_member"
      let member := Json.mkObj [(".tag", "email"), ("email", Json.str recipient)]
      body := jsonBody (Json.mkObj [("file", Json.str ("/" ++ "/".intercalate (call.resource.take (call.resource.length - 1)))),
        ("members", Lean.toJson [member]), ("access_level", "viewer")])
    | _ => throw "unsupported Dropbox operation"
  else if provider == "notion" then
    unless call.resource.length == 1 || (call.operation == "databases.query" && call.resource.length == 2) do
      throw "Notion requires one page/database id and an optional query data source"
    let resource ← required 0
    match call.operation with
    | "pages.read" => fieldsOnly payload []; path := "/pages/" ++ resource
    | "databases.query" => fieldsOnly payload []; method := "POST"; path := "/databases/" ++ resource ++ "/query"; body := some "{}"
    | "pages.delete" => fieldsOnly payload []; method := "PATCH"; path := "/pages/" ++ resource; body := some "{\"in_trash\":true}"
    | "pages.create" =>
      fieldsOnly payload ["title"]
      method := "POST"; path := "/pages"
      let title := Json.mkObj [("title", Lean.toJson [Json.mkObj [("text", Json.mkObj [("content", Json.str (← string payload "title"))])]])]
      body := jsonBody (Json.mkObj [("parent", Json.mkObj [("page_id", Json.str call.resource[0]!)]),
        ("properties", Json.mkObj [("title", title)])])
    | "pages.update" =>
      fieldsOnly payload ["title"]
      method := "PATCH"; path := "/pages/" ++ resource
      let title := Json.mkObj [("title", Lean.toJson [Json.mkObj [("text", Json.mkObj [("content", Json.str (← string payload "title"))])]])]
      body := jsonBody (Json.mkObj [("properties", Json.mkObj [("title", title)])])
    | "comments.create" =>
      fieldsOnly payload ["text"]
      method := "POST"; path := "/comments"
      let text := Json.mkObj [("text", Json.mkObj [("content", Json.str (← string payload "text"))])]
      body := jsonBody (Json.mkObj [("parent", Json.mkObj [("page_id", Json.str call.resource[0]!)]),
        ("rich_text", Lean.toJson [text])])
    | _ => throw "unsupported Notion operation"
  else if provider == "slack" then
    let channel := (segment 0).getD ""
    match call.operation with
    | "channels.list" =>
      fieldsOnly payload []
      unless call.resource.isEmpty do throw "channel inventory requires the account resource"
      path := "/conversations.list?exclude_archived=true"
    | "messages.read" =>
      fieldsOnly payload []
      unless call.resource.length == 1 do throw "history requires one channel"
      path := "/conversations.history?channel=" ++ channel
    | "messages.send" =>
      fieldsOnly payload ["text"]
      unless call.resource.length == 1 do throw "send requires one channel"
      method := "POST"; path := "/chat.postMessage"
      body := jsonBody (Json.mkObj [("channel", Json.str (call.resource.headD "")), ("text", Json.str (← string payload "text"))])
    | "messages.update" | "messages.delete" =>
      fieldsOnly payload (if call.operation == "messages.update" then ["text"] else [])
      unless call.resource.length == 2 do throw "edit/delete requires channel and timestamp"
      method := "POST"; path := if call.operation == "messages.update" then "/chat.update" else "/chat.delete"
      let extra ← if call.operation == "messages.update" then do
        pure [("text", Json.str (← string payload "text"))]
        else pure []
      body := jsonBody (Json.mkObj ([("channel", Json.str call.resource[0]!), ("ts", Json.str call.resource[1]!)] ++
        extra))
    | _ => throw "unsupported Slack operation"
  else if provider == "signal" then
    fieldsOnly payload ["text"]
    match call.resource, call.operation with
    | [account, recipient], "messages.send" =>
      method := "POST"; path := "/v2/send"
      body := jsonBody (Json.mkObj [("number", account), ("recipients", Lean.toJson [recipient]), ("message", Json.str (← string payload "text"))])
    | _, _ => throw "Signal sends require an account and one recipient"
  else if provider == "whatsapp" then
    fieldsOnly payload ["text"]
    match call.resource, call.operation with
    | [account, recipient], "messages.send" =>
      method := "POST"; path := "/" ++ encodeComponent account ++ "/messages"
      body := jsonBody (Json.mkObj [("messaging_product", "whatsapp"), ("to", recipient), ("type", "text"),
        ("text", Json.mkObj [("body", Json.str (← string payload "text"))])])
    | _, _ => throw "WhatsApp sends require a phone-id and one recipient"
  else if ["github", "gitlab"].contains provider then
    if let some view := Repository.view payload then
      unless ["repositories.read", "repositories.write", "repositories.delete"].contains call.operation && call.resource.length ≥ 2 do throw "invalid repository view operation"
      let repo := Repository.apiPath provider call.resource
      if view == "commit" then
        unless ["repositories.write", "repositories.delete"].contains call.operation do throw "commit requires write/delete authority"
        let plan ← Repository.parsePlan call.resource payload
        if call.operation == "repositories.delete" then unless plan.changes.all (·.delete) do throw "delete operation cannot write files"
        method := "POST"; path := repo ++ (if provider == "github" then "/git/commits" else "/repository/commits")
        body := some payload.compress
      else
        unless call.operation == "repositories.read" && call.resource.length == 2 do throw "repository view requires exactly owner/repository"
        fieldsOnly payload (if view == "ancestry" then ["view", "ref", "branch"] else ["view", "ref"])
        let ref ← string payload "ref"
        if view == "branch" then
          unless Repository.branch ref do throw "invalid branch selector"
          path := repo ++ (if provider == "github" then "/branches/" else "/repository/branches/") ++ encodeComponent ref
        else if view == "tree" then
          unless Repository.commit ref do throw "tree inventory requires an immutable commit"
          path := repo ++ (if provider == "github" then "/git/trees/" ++ ref ++ "?recursive=1" else "/repository/tree?ref=" ++ ref ++ "&recursive=true&per_page=100&page=1")
        else if view == "ancestry" then
          let branch ← string payload "branch"
          unless Repository.commit ref && Repository.branch branch do throw "invalid ancestry selectors"
          path := repo ++ (if provider == "github" then "/compare/" ++ encodeComponent branch ++ "..." ++ ref
            else "/repository/merge_base?refs%5B%5D=" ++ ref ++ "&refs%5B%5D=" ++ encodeComponent branch)
        else throw "unsupported repository view"
    else match call.operation with
    | "repositories.list" =>
      fieldsOnly payload []
      unless call.resource.isEmpty do throw "repository inventory requires the account resource"
      path := if provider == "github" then "/user/repos" else "/projects?membership=true"
    | _ =>
      unless call.resource.length ≥ 2 do throw "repository requires owner and repository components"
      let repo := if provider == "github" then "/repos/" ++ encodeComponent call.resource[0]! ++ "/" ++ encodeComponent call.resource[1]!
        else "/projects/" ++ encodeComponent (call.resource[0]! ++ "/" ++ call.resource[1]!)
      match call.operation with
      | "repositories.read" =>
        fieldsOnly payload ["ref"]
        unless call.resource.length ≥ 3 do throw "code read requires a file path"
        let filePath := "/".intercalate (call.resource.drop 2 |>.map encodeComponent)
        path := if provider == "github" then repo ++ "/contents/" ++ filePath else repo ++ "/repository/files/" ++ encodeComponent ("/".intercalate (call.resource.drop 2))
        path := path ++ "?ref=" ++ encodeComponent (← string payload "ref")
      | "repositories.write" =>
        fieldsOnly payload (if provider == "github" then ["branch", "message", "contents", "sha"] else ["branch", "message", "contents"])
        unless call.resource.length ≥ 3 do throw "code write requires a file path"
        method := "PUT"
        path := if provider == "github" then repo ++ "/contents/" ++ "/".intercalate (call.resource.drop 2 |>.map encodeComponent)
          else repo ++ "/repository/files/" ++ encodeComponent ("/".intercalate (call.resource.drop 2))
        if provider == "github" then
          let sha ← match payload.getObjVal? "sha" with
            | .error _ => pure []
            | .ok _ => pure [("sha", Json.str (← string payload "sha"))]
          body := jsonBody (Json.mkObj ([("branch", Json.str (← string payload "branch")), ("message", Json.str (← string payload "message")),
            ("content", Json.str (Data.Base64.encode (← string payload "contents").toUTF8))] ++
            sha))
        else
          body := jsonBody (Json.mkObj [("branch", Json.str (← string payload "branch")), ("commit_message", Json.str (← string payload "message")), ("content", Json.str (← string payload "contents"))])
      | "issues.read" =>
        fieldsOnly payload []
        unless call.resource.length == 2 || call.resource.length == 3 do throw "issues requires repository and optional issue number"
        if call.resource.length == 3 then unless call.resource[2]!.all Char.isDigit && (call.resource[2]!.toNat?.getD 0) > 0 do throw "issue number must be positive decimal"
        path := repo ++ "/issues" ++ (segment 2 |>.map ("/" ++ ·) |>.getD "")
      | "issues.write" =>
        fieldsOnly payload ["title", "text"]
        unless call.resource.length == 2 || call.resource.length == 3 do throw "issue write requires repository and optional issue number"
        if call.resource.length == 3 then unless call.resource[2]!.all Char.isDigit && (call.resource[2]!.toNat?.getD 0) > 0 do throw "issue number must be positive decimal"
        method := if call.resource.length == 2 then "POST" else if provider == "github" then "PATCH" else "PUT"
        path := repo ++ "/issues" ++ (segment 2 |>.map ("/" ++ ·) |>.getD "")
        body := jsonBody (Json.mkObj [("title", Json.str (← string payload "title")), (if provider == "github" then "body" else "description", Json.str (← string payload "text"))])
      | "pull_requests.write" =>
        -- Updating text cannot choose another repository, branch or merge code.
        fieldsOnly payload ["title", "text"]
        unless call.resource.length == 3 do throw "pull request update requires repository and pull request number"
        unless call.resource[2]!.all Char.isDigit && (call.resource[2]!.toNat?.getD 0) > 0 do throw "pull request number must be positive decimal"
        method := if provider == "github" then "PATCH" else "PUT"
        path := repo ++ (if provider == "github" then "/pulls/" else "/merge_requests/") ++ (← required 2)
        body := jsonBody (Json.mkObj [("title", Json.str (← string payload "title")), (if provider == "github" then "body" else "description", Json.str (← string payload "text"))])
      | _ => throw "unsupported repository operation"
  else throw "this connector operation has no supported adapter"
  if call.context.isSome && call.operation != "inference.generate" then throw "context is only valid for native inference"
  if body.isSome && !headers.any (fun header => header.1.toLower == "content-type") then
    headers := headers ++ [("content-type", "application/json")]
  let base := transportBase provider call.operation base
  let url := base ++ path
  unless (checkUrl base url).isSome do throw "the operation leaves its connection's base URL"
  return { account := call.account, method, url, headers, body }

/-- Operations affecting a secondary selector carry independent evidence.
    Gmail does not provide a label-conditioned atomic mutation: those writes
    require account-level authority, while scoped reads are response-checked.
    Sharing by a mutable Dropbox path likewise has no atomic path condition.
    Notion archival affects a subtree whose IDs are not hierarchical paths. -/
def secondaryResources (provider operation : String) (resource : List String) : List (List String) :=
  if ["gmail", "outlook", "jmap"].contains provider && operation == "messages.update" then
    [[resource[0]?.getD "", resource[3]?.getD ""]] else []

/-- These native effects need authority on every resource in the account
    subtree, not merely an exact grant on the empty/account selector. -/
def recursiveResources (provider operation : String) (resource : List String := []) (payload : String := "{}") : List (List String) :=
  if provider == "gmail" && ["messages.update", "messages.delete", "attachments.read"].contains operation then [["me"]]
  else if ["github", "gitlab"].contains provider && operation == "repositories.read" &&
      (parseJson payload >>= fun value => pure (Repository.view value)).toOption == some (some "tree") then [resource]
  else if (provider == "dropbox" && operation == "files.share") ||
      (provider == "notion" && operation == "pages.delete") then [[]] else []

def recursiveCapability (authority : Authority) (operation : String) (root : List String) : Capability :=
  { provider := authority.cell.provider, connection := authority.cell.connection,
    scopes := [{ operation, root, descendants := true }],
    maxRequestBytes := authority.maxRequestBytes, maxResponseBytes := authority.maxResponseBytes }

def functionReferences (provider operation : String) (resource : List String) (payload : String) : Except String (List String) :=
  if operation == "inference.generate" then parseJson payload >>= fun payload =>
    Inference.validate (modelApi provider ("/".intercalate resource)) payload ("/".intercalate resource) else .ok []

def contextPermitted (context : Option Wire.NativeContext) (conversation : Option Inference.Policy) : Bool :=
  context.all (fun context => context.valid && conversation.any (fun policy => policy.valid && policy.sessionId == context.sessionId))

def publicationPermit (authority : Authority) (resource : List String) (payload : String)
    (policy : Option Repository.PublicationPolicy) : Prop :=
  match parseJson payload with
  | .error _ => False
  | .ok value => Repository.view value = some "commit" →
      Nonempty (Repository.AuthorizedPlan authority resource (policy.getD { branch := "", root := [] }) value)

def checkPublication (authority : Authority) (resource : List String) (payload : String)
    (policy : Option Repository.PublicationPolicy) : Except String (PLift (publicationPermit authority resource payload policy)) :=
  match hp : parseJson payload with
  | .error error => .error error
  | .ok value =>
    if hv : Repository.view value = some "commit" then do
      let plan ← Repository.authorize authority resource (policy.getD { branch := "", root := [] }) value
      return ⟨by simp only [publicationPermit, hp]; intro _; exact ⟨plan⟩⟩
    else .ok ⟨by simp [publicationPermit, hp, hv]⟩

/-- Only `prepare` constructs a native request ready for execution. The
    operation/resource proof is inseparable from the transport it derives. -/
structure Prepared (authority : Authority) (operation : String) where
  private mk ::
  resource : AuthorizedResource authority operation
  base : String
  account : String
  payload : String
  context : Option Wire.NativeContext
  conversation : Option Inference.Policy
  publication : Option Repository.PublicationPolicy
  transport : Wire.ProviderCall
  derived : request authority.cell.provider base { account, operation, resource := resource.resource, payload, context } = .ok transport
  payloadBound : payload.toUTF8.size ≤ authority.maxRequestBytes
  bodyBound : ((transport.body.map String.toUTF8).getD ByteArray.empty).size ≤ authority.maxRequestBytes
  secondaryBound : ∀ target ∈ secondaryResources authority.cell.provider operation resource.resource,
    authority.permits operation target = true
  recursiveBound : ∀ root ∈ recursiveResources authority.cell.provider operation resource.resource payload,
    ∀ ceiling ∈ [authority.organization, authority.connection, authority.cell, authority.warrant],
      (recursiveCapability authority operation root).Narrows ceiling
  functions : List String
  functionsDerived : functionReferences authority.cell.provider operation resource.resource payload = .ok functions
  functionsBound : functions.all ((conversation.map (·.allowedTools)).getD []).contains = true
  contextBound : contextPermitted context conversation = true
  publicationBound : publicationPermit authority resource.resource payload publication

def prepare (authority : Authority) (operation : String)
    (resource : AuthorizedResource authority operation) (base account payload : String)
    (context : Option Wire.NativeContext := none) (conversation : Option Inference.Policy := none)
    (publication : Option Repository.PublicationPolicy := none) :
    Except String (Prepared authority operation) := do
  unless payload.toUTF8.size ≤ authority.maxRequestBytes do throw "payload exceeds authority limit"
  let pub ← checkPublication authority resource.resource payload publication
  match hf : functionReferences authority.cell.provider operation resource.resource payload with
  | .error reason => throw reason
  | .ok functions =>
    if hn : functions.all ((conversation.map (·.allowedTools)).getD []).contains = true then
      if hc : contextPermitted context conversation = true then
        if ht : (recursiveResources authority.cell.provider operation resource.resource payload).all (fun root =>
            [authority.organization, authority.connection, authority.cell, authority.warrant].all
              ((recursiveCapability authority operation root).narrows ·)) = true then
          if hs : (secondaryResources authority.cell.provider operation resource.resource).all (authority.permits operation) = true then
            match derived : request authority.cell.provider base { account, operation, resource := resource.resource, payload, context } with
            | .error reason => throw reason
            | .ok transport =>
              if hp : payload.toUTF8.size ≤ authority.maxRequestBytes then
                if hb : ((transport.body.map String.toUTF8).getD ByteArray.empty).size ≤ authority.maxRequestBytes then
                  return ⟨resource, base, account, payload, context, conversation, publication, transport, derived, hp, hb, List.all_eq_true.mp hs,
                    fun root membership ceiling member => Capability.narrows_sound
                      (List.all_eq_true.mp (List.all_eq_true.mp ht root membership) ceiling member), functions, hf, hn, hc, pub.down⟩
                else throw "native body exceeds authority limit"
              else throw "payload exceeds authority limit"
          else throw "secondary selector is outside authority"
        else throw "native operation requires recursive account authority"
      else throw "conversation context is not bound to this run"
    else throw "function is not in the trusted run allowlist"

theorem Prepared.organization_permits {authority : Authority} {operation : String}
    (prepared : Prepared authority operation) : authority.organization.permits operation prepared.resource.resource = true :=
  prepared.resource.organization_permits

theorem Prepared.connection_permits {authority : Authority} {operation : String}
    (prepared : Prepared authority operation) : authority.connection.permits operation prepared.resource.resource = true :=
  prepared.resource.connection_permits

theorem Prepared.cell_permits {authority : Authority} {operation : String}
    (prepared : Prepared authority operation) : authority.cell.permits operation prepared.resource.resource = true :=
  prepared.resource.cell_permits

theorem Prepared.warrant_permits {authority : Authority} {operation : String}
    (prepared : Prepared authority operation) : authority.warrant.permits operation prepared.resource.resource = true :=
  prepared.resource.warrant_permits

/-- Secondary selectors are subject to the same four-ceiling intersection. -/
theorem Prepared.secondary_permits {authority : Authority} {operation : String}
    (prepared : Prepared authority operation) (target : List String)
    (membership : target ∈ secondaryResources authority.cell.provider operation prepared.resource.resource) :
    authority.permits operation target = true := prepared.secondaryBound target membership

theorem Prepared.function_allowed {authority : Authority} {operation : String}
    (prepared : Prepared authority operation) (name : String) (member : name ∈ prepared.functions) :
    name ∈ (prepared.conversation.map (·.allowedTools)).getD [] :=
  List.contains_iff_mem.mp (List.all_eq_true.mp prepared.functionsBound name member)

end Liaison.Egress.Connector
