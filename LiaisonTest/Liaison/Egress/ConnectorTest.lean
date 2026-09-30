import Liaison.Egress.Connector

open Liaison.Egress.Connector
open Control.Monad.Effect.Connector
open Liaison

private def Except.isError (value : Except α β) : Bool := !value.isOk

namespace ConnectorAdapterTests

def call (operation : String) (resource : List String) (payload := "{}") : Liaison.Wire.ConnectorCall :=
  { account := "user/connection", operation, resource, payload }

def storage : Permissions :=
  { scopes := [{ operation := "objects.read", root := ["reports"], descendants := true },
               { operation := "objects.write", root := ["reports"], descendants := true }],
    maxRequestBytes := 1024, maxResponseBytes := 4096 }

def cap := storage.capability "s3" "connection"
#guard (ScopedResource.check? cap "objects.read" ["reports", "2026", "invoice.json"]).isSome
#guard (ScopedResource.check? cap "objects.read" ["reports-private", "invoice.json"]).isNone
#guard (ScopedResource.check? cap "objects.delete" ["reports", "invoice.json"]).isNone
#guard ((request "s3" "https://storage.example.com/bucket" (call "objects.read" ["reports", "x.json"])).toOption.map (fun c => (c.method, c.url))) ==
  some ("GET", "https://storage.example.com/bucket/reports/x.json")
#guard ((request "s3" "https://storage.example.com/bucket" (call "objects.list" ["reports"])).toOption.map (·.url)) ==
  some "https://storage.example.com/bucket?list-type=2&prefix=reports%2F"
#guard ((request "s3" "https://storage.example.com/bucket" (call "objects.write" ["reports", "x"] "{\"contents\":\"hello\"}")).toOption.map (fun c => (c.method, c.body))) ==
  some ("PUT", some "hello")
#guard (request "s3" "https://storage.example.com/bucket" (call "unknown" ["reports"])).toOption.isNone

#guard ((request "google-calendar" "https://www.googleapis.com" (call "events.read" ["primary", "e1"])).toOption.map (·.url)) ==
  some "https://www.googleapis.com/calendar/v3/calendars/primary/events/e1"
#guard (request "google-calendar" "https://www.googleapis.com" (call "events.read" ["primary", "e1", "ignored"])).toOption.isNone
#guard (request "google-calendar" "https://www.googleapis.com" (call "events.create" ["primary"] "{\"event\":{\"attendees\":[]}}")).toOption.isNone
#guard (request "outlook" "https://graph.microsoft.com/v1.0" (call "messages.read" ["someone-else", "inbox"])).toOption.isNone
#guard (request "gmail" "https://www.googleapis.com" (call "messages.send" ["me", "inbox"])).toOption.isNone
#guard (request "gdrive" "https://www.googleapis.com" (call "files.read" ["folder", "child"])).isOk
-- This is only the pure plan; the broker must resolve its Drive parent edge.
#guard (request "slack" "https://slack.com/api" (call "messages.send" ["C123"] "{\"text\":\"hello\",\"channel\":\"C999\"}")).toOption.isNone
#guard (request "unknown" "https://api.example.com" (call "objects.read" ["x"])).toOption.isNone

def examples (provider : String) : List Liaison.Wire.ConnectorCall :=
  if ["s3", "azure"].contains provider then
    [call "objects.list" ["reports"], call "objects.read" ["reports", "x"], call "objects.write" ["reports", "x"] "{\"contents\":\"hello\"}", call "objects.delete" ["reports", "x"]]
  else if provider == "gdrive" then
    [call "files.list" ["folder"], call "files.read" ["folder", "file"], call "files.create" ["folder"] "{\"name\":\"hello\"}",
     call "files.update" ["folder", "file"] "{\"name\":\"new\"}", call "files.delete" ["folder", "file"], call "files.share" ["folder", "file", "a@example.com"]]
  else if provider == "dropbox" then
    [call "files.list" ["folder"], call "files.read" ["folder", "file"], call "files.create" ["folder", "file"] "{\"contents\":\"hello\"}",
     call "files.update" ["folder", "file"] "{\"contents\":\"new\",\"revision\":\"rev\"}", call "files.delete" ["folder", "file"], call "files.share" ["folder", "file", "a@example.com"]]
  else if ["google-calendar", "microsoft-calendar"].contains provider then
    [call "calendars.list" [], call "events.read" ["cal", "event"], call "events.create" ["cal"] "{\"event\":{\"start\":{\"dateTime\":\"2026-09-30T12:00:00Z\"},\"end\":{\"dateTime\":\"2026-09-30T13:00:00Z\"}}}",
     call "events.update" ["cal", "event"] "{\"event\":{}}", call "events.delete" ["cal", "event"], call "events.invite" ["cal", "event", "a@example.com"]]
  else if provider == "caldav" then
    [call "calendars.list" [], call "events.read" ["cal", "event.ics"],
     call "events.create" ["cal", "event.ics"] "{\"summary\":\"hello\",\"start\":\"20260930T120000Z\",\"end\":\"20260930T130000Z\"}",
     call "events.update" ["cal", "event.ics"] "{\"summary\":\"hello\",\"start\":\"20260930T120000Z\",\"end\":\"20260930T130000Z\",\"etag\":\"\\\"one\\\"\"}",
     call "events.delete" ["cal", "event.ics"] "{\"etag\":\"\\\"one\\\"\"}"]
  else if ["gmail", "outlook", "jmap"].contains provider then
    [call "mailboxes.list" ["me"], call "messages.read" ["me", "inbox", "m"], call "messages.search" ["me", "inbox"] "{\"query\":\"hello\"}",
     call "drafts.create" ["me", if provider == "gmail" then "DRAFT" else "drafts"] "{\"subject\":\"hi\",\"text\":\"hello\"}",
     if provider == "jmap" then call "messages.send" ["me", "drafts", "m", "a@example.com", "identity"] else
       call "messages.send" ["me", if provider == "gmail" then "SENT" else "sentitems", "a@example.com"] "{\"subject\":\"hi\",\"text\":\"hello\"}",
     call "messages.update" ["me", "inbox", "m", "archive"], call "messages.delete" ["me", "inbox", "m"], call "attachments.read" ["me", "inbox", "m", "blob"]]
  else if provider == "notion" then
    [call "pages.read" ["page"], call "databases.query" ["db"], call "pages.create" ["parent"] "{\"title\":\"hi\"}",
     call "pages.update" ["page"] "{\"title\":\"hi\"}", call "pages.delete" ["page"], call "comments.create" ["page"] "{\"text\":\"hello\"}"]
  else if provider == "slack" then
    [call "channels.list" [], call "messages.read" ["C123"], call "messages.send" ["C123"] "{\"text\":\"hello\"}",
     call "messages.update" ["C123", "123.456"] "{\"text\":\"hello\"}", call "messages.delete" ["C123", "123.456"]]
  else if ["signal", "whatsapp"].contains provider then [call "messages.send" ["number", "+1234"] "{\"text\":\"hello\"}"]
  else if ["github", "gitlab"].contains provider then
    [call "repositories.list" [], call "repositories.read" ["owner", "repo", "src", "file"] "{\"ref\":\"main\"}",
     call "repositories.write" ["owner", "repo", "src", "file"] "{\"branch\":\"main\",\"message\":\"update\",\"contents\":\"hello\"}",
     call "issues.read" ["owner", "repo", "1"], call "issues.write" ["owner", "repo", "1"] "{\"title\":\"hi\",\"text\":\"hello\"}",
      call "pull_requests.write" ["owner", "repo", "1"] "{\"title\":\"hi\",\"text\":\"hello\"}",
      call "repositories.delete" ["owner", "repo"] "{\"view\":\"commit\",\"branch\":\"main\",\"expectedHead\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"message\":\"remove\",\"changes\":[{\"resource\":[\"file\"],\"contents\":null,\"mode\":\"000000\",\"delete\":true}]}"]
  else if provider == "typesafe" then [call "models.list" [], call "classification.evaluate" ["jev-latest"] "{\"state\":{},\"questions\":{\"ready\":\"bool\"}}"]
  else if provider == "radius" then [call "models.list" [],
    { (call "inference.generate" ["model"] "{\"options\":{\"maxTokens\":1024,\"sessionId\":\"session\"},\"context\":{\"messages\":[{\"role\":\"system\",\"content\":\"hello\",\"timestamp\":0,\"toolsAdded\":[]}]}}") with
      context := some { sessionId := "session", initiator := "agent", client := "typednotes-lode" } }]
  else [call "models.list" [], call "inference.generate" ["model"] (if provider == "gemini" then "{\"contents\":[]}" else if modelApi provider "model" == "responses" then "{\"input\":\"hello\"}" else "{\"messages\":[]}")] ++
    (if provider == "opencode" then [call "classification.evaluate" ["jev-1.13"] "{\"state\":{},\"questions\":{\"ready\":\"bool\"}}"] else [])

def providers : List String := ["s3", "azure", "gdrive", "dropbox", "google-calendar", "microsoft-calendar", "caldav", "gmail", "outlook", "jmap", "notion", "slack", "signal", "whatsapp", "github", "gitlab"] ++ aiProviders

-- Every advertised broker operation has a positive native plan fixture. A new
-- operation or provider cannot quietly skip this check.
#guard providers.all (fun provider => (operations provider).all (fun operation =>
  (examples provider).any (fun c => c.operation == operation && (request provider "https://mock.example/base" c).isOk)))
#guard providers.all (fun provider => (examples provider).all (fun c => (operations provider).contains c.operation))

#guard !(Wire.validResource [".."])
#guard !(Wire.validResource ["%2e%2e"])
#guard !(Wire.validResource ["folder/other"])
#guard (request "gmail" "https://mock.example" (call "messages.read" ["me", "inbox", "m", "ignored"])).isError
#guard (request "outlook" "https://mock.example" (call "mailboxes.list" ["me", "ignored"])).isError
#guard (request "notion" "https://mock.example" (call "pages.delete" ["page", "ignored"])).isError
#guard (request "slack" "https://mock.example" (call "messages.delete" ["C123", "t", "ignored"])).isError
#guard (request "gmail" "https://mock.example" (call "messages.send" ["me", "SENT", "a@example.com"] "{\"subject\":\"hi\\r\\nBcc:other@example.com\",\"text\":\"hello\"}")).isError
#guard (request "google-calendar" "https://mock.example" (call "events.invite" ["cal", "event", "a@example.com,b@example.com"])).isError
#guard (request "openai" "https://mock.example" (call "inference.generate" ["m"] "{\"messages\":[],\"tools\":[{}]}")).isError
#guard (request "typesafe" "https://mock.example" (call "inference.generate" ["jev"])).isError
#guard (request "radius" "https://mock.example" (call "inference.generate" ["m"])).isError
#guard modelApi "opencode" "jev-1.13" == "classifier"
#guard modelApi "opencode" "qwen3.8-max" == "chat"
#guard modelApi "opencode-go" "qwen3.8-max" == "messages"
#guard modelApi "github-copilot" "gpt-5-mini" == "chat"
#guard modelApi "openai" "gpt-7.1" == "responses"

def authority : Authority := { organization := cap, connection := cap, cell := cap, warrant := cap }
#guard (AuthorizedResource.check? authority "objects.read" ["reports", "x"]).isSome
#guard (AuthorizedResource.check? { authority with organization := { cap with scopes := [] } } "objects.read" ["reports", "x"]).isNone
#guard (AuthorizedResource.check? { authority with connection := { cap with scopes := [] } } "objects.read" ["reports", "x"]).isNone
#guard (AuthorizedResource.check? { authority with cell := { cap with scopes := [] } } "objects.read" ["reports", "x"]).isNone
#guard (AuthorizedResource.check? { authority with warrant := { cap with scopes := [] } } "objects.read" ["reports", "x"]).isNone
#guard (AuthorizedResource.check? { authority with warrant := { cap with provider := "azure" } } "objects.read" ["reports", "x"]).isNone
#guard (Permissions.parse (Data.Json.Decode.decode "{\"scopes\":[{\"operation\":\"objects.read\",\"root\":[\"..\"],\"descendants\":true}],\"maxRequestBytes\":1024,\"maxResponseBytes\":1024}" |>.toOption.getD .null)).isError
#guard (storage.validate "slack").isError
#guard ({ storage with scopes := [{ operation := "rows.select", root := ["bound_schema"], descendants := true }] } : Permissions).validate "postgres" |>.isOk
#guard ({ storage with scopes := [{ operation := "secrets.read", root := ["inputs"], descendants := true }] } : Permissions).validate "vault" |>.isOk
#guard ({ storage with scopes := [{ operation := "rows.select", root := ["bound_schema"], descendants := true }] } : Permissions).validate "vault" |>.isError
#guard (request "postgres" "https://fixture.invalid" (call "rows.select" ["bound_schema", "table"] "{\"sql\":\"select * from other.schema\"}")).isError

private def policy (text : String) := (Data.Json.Decode.decode text).toOption.getD .null
#guard (Permissions.parse (policy "{\"scopes\":[{\"operation\":\"objects.read\",\"root\":[]}],\"maxRequestBytes\":1024,\"maxResponseBytes\":1024}")).isError
#guard (Permissions.parse (policy "{\"scopes\":[],\"maxRequestBytes\":1.00000001,\"maxResponseBytes\":1024}")).isError
#guard (Permissions.parse (policy "{\"scopes\":[],\"maxRequestBytes\":1024,\"maxResponseBytes\":1024,\"allowAll\":true}")).isError
#guard (Permissions.parse (policy "{\"scopes\":[],\"maxRequestBytes\":1024,\"maxRequestBytes\":1,\"maxResponseBytes\":1024}")).isError
#guard (Permissions.parse (policy "{\"scopes\":[],\"maxRequestBytes\":1024,\"maxResponseBytes\":1024}")).isOk
#guard (request "s3" "https://mock.example/bucket" (call "objects.write" ["x"] "{\"contents\":\"one\",\"contents\":\"two\"}")).isError
#guard (request "slack" "https://mock.example" (call "messages.send" ["C123", "ignored"] "{\"text\":\"hi\"}")).isError
#guard (request "openai" "https://mock.example" (call "inference.generate" ["model", "ignored"] "{\"messages\":[]}")).isError
#guard (request "openrouter" "https://mock.example" (call "inference.generate" ["org", "model"] "{\"messages\":[]}")).isOk
#guard (request "fireworks" "https://mock.example" (call "inference.generate" ["accounts", "fireworks", "models", "llama"] "{\"messages\":[]}")).isOk
#guard (request "google-calendar" "https://mock.example" (call "events.update" ["cal", "event"] "{\"event\":{\"description\":{\"attendees\":[]}}}")).isError
#guard !(Wire.validResource ["x\u0085y"])
#guard Liaison.Egress.strongEtag "\"one\""
#guard !Liaison.Egress.strongEtag "*"
#guard !Liaison.Egress.strongEtag "W/\"one\""
#guard !Liaison.Egress.strongEtag "\"one\",\"two\""
#guard (request "s3" "https://mock.example/bucket" (call "objects.read" ["report?x=1&y=2"])).toOption.map (·.url) ==
  some "https://mock.example/bucket/report%3Fx%3D1%26y%3D2"
#guard transportBase "dropbox" "files.read" "https://api.dropboxapi.com" == "https://content.dropboxapi.com"
#guard transportBase "dropbox" "files.read" "https://api.dropboxapi.com.evil.example" == "https://api.dropboxapi.com.evil.example"
#guard transportBase "dropbox" "files.delete" "https://api.dropboxapi.com" == "https://api.dropboxapi.com"

-- A source-folder proof alone cannot authorize a destination or a native
-- operation without an atomic provider-side label/path condition.
def mailCap : Capability := { provider := "gmail", connection := "connection", scopes := [
  { operation := "messages.update", root := ["me", "inbox"], descendants := true }] }
def mailAuthority : Authority := { organization := mailCap, connection := mailCap, cell := mailCap, warrant := mailCap }
#guard match AuthorizedResource.check? mailAuthority "messages.update" ["me", "inbox", "message", "archive"] with
  | none => false
  | some resource => (prepare mailAuthority "messages.update" resource "https://mock.example" "user/connection" "{}").isError

-- Presets are per-provider projections: read defaults never authorize sends,
-- shares, invitations, destructive writes or arbitrary methods.
#guard providers.all (fun provider => (readDefaults.scopes.filter (fun scope => (operations provider).contains scope.operation)).all
  (fun scope => !["objects.write", "objects.delete", "files.create", "files.update", "files.delete", "files.share", "events.create", "events.update", "events.delete", "events.invite",
    "drafts.create", "messages.send", "messages.update", "messages.delete", "pages.create", "pages.update", "pages.delete", "comments.create",
    "repositories.write", "issues.write", "pull_requests.write"].contains scope.operation))

example (prepared : Prepared authority "objects.read") : authority.organization.permits "objects.read" prepared.resource.resource = true :=
  prepared.organization_permits
example (prepared : Prepared mailAuthority "messages.update") :
    ∀ destination ∈ secondaryResources "gmail" "messages.update" prepared.resource.resource,
      mailAuthority.permits "messages.update" destination = true := prepared.secondaryBound

end ConnectorAdapterTests
