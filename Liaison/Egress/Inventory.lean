import Liaison.Egress.Provider
import Linen.Crypto.ConstantTime
import Linen.Data.Base64
import Linen.Network.WebApp
import Std.Time.Format

namespace Liaison.Egress

open Network.HTTP.Types

private inductive Health where
  | staticCredential | current | expiring | refreshFailed | unavailable
  deriving BEq

private def Health.label : Health → String
  | .staticCredential => "Static"
  | .current => "Current"
  | .expiring => "Expiring"
  | .refreshFailed => "Refresh failed"
  | .unavailable => "Unavailable"

private structure Row where
  id : SecretId
  kind : String
  expiry : Option Nat
  health : Health
  refreshed : Bool := false

private structure Snapshot where
  rows : List Row := []
  completedAt : Option Nat := none
  listingFailed : Bool := false

/-- Settings and the last completed inventory snapshot. The snapshot contains
    identities, kind, expiry, and outcomes only. -/
structure Inventory where
  private mk ::
  private intervalSeconds : Nat
  private basicToken : Option String
  private snapshot : IO.Ref Snapshot

/-- Start with an empty snapshot. By default, scan every 30 seconds. Zero
    disables scanning. The dashboard requires a separate operator password. -/
def Inventory.fromEnv : IO Inventory := do
  let raw := (← IO.getEnv "SECRETS_REFRESH_INTERVAL_SECONDS").getD "30"
  let some seconds := raw.toNat? | throw (IO.userError "invalid SECRETS_REFRESH_INTERVAL_SECONDS")
  if seconds > 3600 then throw (IO.userError "SECRETS_REFRESH_INTERVAL_SECONDS must be 0–3600")
  let password ← IO.getEnv "SECRETS_STATUS_PASSWORD"
  if password == some "" then throw (IO.userError "SECRETS_STATUS_PASSWORD is empty")
  if password.isSome && seconds == 0 then
    throw (IO.userError "the secret status page needs periodic scanning")
  let token := password.map fun value => Data.Base64.encode ("liaison:" ++ value).toUTF8
  return ⟨seconds, token, ← IO.mkRef {}⟩

private def expiryOf (credential : Credential) : Option Nat :=
  match credential.auth with
  | .oauth _ _ _ expiry => some expiry
  | _ => none

private def inspect (cfg : EgressConfig) (id : SecretId) : IO Row := do
  let .ok stored ← loadCredential cfg.secrets id
    | return { id, kind := "Unknown", expiry := none, health := .unavailable }
  let credential := stored.credential
  let kind := credential.kindName
  let some before := expiryOf credential
    | return { id, kind, expiry := none, health := .staticCredential }
  if !needsRefresh before (← nowUnixSeconds) then
    return { id, kind, expiry := some before, health := .current }
  match ← cfg.refresh.ensureFresh cfg.secrets.refreshStore cfg.oauth id stored with
  | .error _ => return { id, kind, expiry := some before, health := .refreshFailed }
  | .ok outcome =>
    let updated := outcome.credential
    let expiry := expiryOf updated
    let now ← nowUnixSeconds
    let health := if expiry.isNone then .staticCredential
      else if updated.refreshDue now then .expiring else .current
    return { id, kind := updated.kindName, expiry, health, refreshed := outcome.persisted }

private def scan (inventory : Inventory) (cfg : EgressConfig) : IO Unit := do
  try
    let ids ← cfg.secrets.listCredentials
    let mut rows := []
    for id in ids do
      if ← IO.checkCanceled then return
      rows := (← inspect cfg id) :: rows
    inventory.snapshot.set { rows := rows.reverse, completedAt := some (← nowUnixSeconds) }
  catch _ =>
    let old ← inventory.snapshot.get
    unless old.listingFailed do
      IO.eprintln "liaison: cannot scan connector credential inventory"
    inventory.snapshot.set { old with listingFailed := true }

/-- Start background inventory and refresh work. The server owns the returned
    task and cancels it on shutdown. -/
def Inventory.start (inventory : Inventory) (cfg : EgressConfig) :
    IO (Option (Task (Except IO.Error Unit))) := do
  if inventory.intervalSeconds == 0 then return none
  return some (← IO.asTask (prio := .dedicated) do
    while !(← IO.checkCanceled) do
      scan inventory cfg
      IO.sleep (UInt32.ofNat (1000 * inventory.intervalSeconds)))

private def htmlText (text : String) : String :=
  String.join (text.toList.map fun c =>
    match c with
    | '&' => "&amp;"
    | '<' => "&lt;"
    | '>' => "&gt;"
    | '"' => "&quot;"
    | '\'' => "&#39;"
    | _ => String.singleton c)

private def displayTime (time : Nat) : String :=
  (Std.Time.DateTime.ofTimestampWithZone (Std.Time.Timestamp.ofSecondsSinceUnixEpoch
    (Std.Time.Second.Offset.ofNat time)) Std.Time.TimeZone.UTC).toISO8601String

private def renderRow (row : Row) (now : Nat) : String :=
  let expired := row.expiry.any (· ≤ now)
  let attention := expired || row.health == .unavailable || row.health == .refreshFailed
  let expiring := row.expiry.any (needsRefresh · now)
  let severity := if attention then "attention" else if expiring then "soon" else "normal"
  let label := if expired then
      if row.health == .refreshFailed then "Expired · refresh failed" else "Expired"
    else if expiring && row.health == .current then Health.expiring.label
    else row.health.label
  let expiry := (row.expiry.map displayTime).getD "—"
  s!"<tr><th scope=\"row\">{htmlText row.id.provider}</th><td>{htmlText row.id.account}</td>" ++
    s!"<td>{htmlText row.kind}</td><td class=\"{severity}\">{label}</td><td>{expiry}</td></tr>"

private def pageStart : String := r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Credential status · Liaison</title>
<style>
:root{color-scheme:light;--paper:#f1f5fa;--ink:#162838;--accent:#15547a;--line:#b8c8d5;--bad:#9b2638;--soon:#805111}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:1rem system-ui,sans-serif}
main{width:min(72rem,100%);margin:auto;padding:clamp(1.25rem,4vw,4rem)}
header{display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between;align-items:baseline;border-bottom:4px solid var(--accent)}
h1{font:600 clamp(2rem,5vw,3.25rem) Georgia,serif;margin:0 0 .9rem}
a{color:var(--accent);text-underline-offset:.2em}a:focus-visible{outline:2px solid var(--accent);outline-offset:4px}
dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(8rem,1fr));gap:1rem;margin:1.75rem 0}
dl div{border-left:1px solid var(--line);padding:0 .8rem}dd{margin:.25rem 0 0;font-size:1.8rem;font-variant-numeric:tabular-nums}
.table{overflow:auto;border-bottom:1px solid var(--line);background:#fff}
table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:.8rem .65rem;border-top:1px solid var(--line);overflow-wrap:anywhere}
thead th{color:var(--accent);background:var(--paper)}th:first-child,td:last-child{white-space:nowrap}
.attention{color:var(--bad);font-weight:650}.soon{color:var(--soon);font-weight:650}
</style></head><body><main><header><h1>Credential status</h1><a href="/_secrets">Reload status</a></header>"#

private def render (snapshot : Snapshot) (now : Nat) : String :=
  let refreshable := snapshot.rows.countP (·.expiry.isSome)
  let refreshed := snapshot.rows.countP (·.refreshed)
  let attention := snapshot.rows.countP fun row =>
    row.health == .unavailable || row.health == .refreshFailed || row.expiry.any (· ≤ now)
  let scanned := (snapshot.completedAt.map fun time =>
    s!"<p>Last completed scan {displayTime time}</p>").getD "<p>Waiting for the first scan.</p>"
  let failed := if snapshot.listingFailed then
    "<p role=\"status\" class=\"attention\">The latest scan could not list credentials. Check the store connection and list permissions.</p>"
    else ""
  let stats := s!"<dl><div><dt>Credentials</dt><dd>{snapshot.rows.length}</dd></div>" ++
    s!"<div><dt>Refreshable</dt><dd>{refreshable}</dd></div>" ++
    s!"<div><dt>Refreshed last scan</dt><dd>{refreshed}</dd></div>" ++
    s!"<div><dt>Need attention</dt><dd>{attention}</dd></div></dl>"
  let content := if snapshot.rows.isEmpty then
      if snapshot.completedAt.isSome then "<p>The store has no connector credentials.</p>" else ""
    else "<div class=\"table\"><table><thead><tr><th scope=\"col\">Provider</th><th scope=\"col\">Account</th>" ++
      "<th scope=\"col\">Kind</th><th scope=\"col\">Status</th><th scope=\"col\">Expiry (UTC)</th></tr></thead><tbody>" ++
      String.join (snapshot.rows.map (renderRow · now)) ++ "</tbody></table></div>"
  pageStart ++ scanned ++ failed ++ stats ++ content ++ "</main></body></html>"

private def authorized (expected : String) (headers : RequestHeaders) : Bool :=
  match (headers.filter (fun (name, _) => name == hAuthorization)).map Prod.snd with
  | [value] =>
    match value.splitOn " " with
    | [scheme, token] => scheme.toLower == "basic" && Crypto.ConstantTime.eqString expected token
    | _ => false
  | _ => false

/-- Serve the protected status page from a metadata snapshot. Requests never
    read storage or initiate a refresh. -/
private def Inventory.statusPage (inventory : Inventory) (request : Network.WebApp.Request) :
    IO Network.WebApp.Response := do
  let headers : ResponseHeaders := [(hCacheControl, "no-store")]
  let some expected := inventory.basicToken
    | return Network.WebApp.responseLBS status404 headers "not found"
  unless authorized expected request.requestHeaders do
    return Network.WebApp.responseLBS status401
      ((hWWWAuthenticate, "Basic realm=\"Liaison credential status\", charset=\"UTF-8\"") :: headers)
      "authentication required"
  return Network.WebApp.responseLBS status200
    ([(hContentType, "text/html; charset=utf-8"),
      (Data.CI.mk' "Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"),
      (Data.CI.mk' "X-Content-Type-Options", "nosniff")] ++ headers)
    (render (← inventory.snapshot.get) (← nowUnixSeconds))

/-- Add the opt-in dashboard route to a WebApp application. -/
def Inventory.withStatus (inventory : Inventory) (app : Network.WebApp.Application) :
    Network.WebApp.Application :=
  fun request respond =>
    if request.rawPathInfo == "/_secrets" && request.requestMethod == .standard .GET then
      Network.WebApp.AppM.respondIO respond (inventory.statusPage request)
    else app request respond

end Liaison.Egress
