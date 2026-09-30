/-
  Liaison.Wire — `POST /v0/egress` on the wire, both ways

  The one definition of liaison's wire format, used by liaison itself
  (`Server.lean` decodes requests and encodes replies with it) and by its Lean
  clients (which encode requests and decode replies). A client importing this
  module speaks exactly the format the server parses: there is no second copy
  to drift. The cross-service contract is `typednotes/typednotes`'s
  `docs/connections.md` §5.

  Pure, and deliberately light: it imports the warrant *types* only
  (`Liaison.Warrant.Core`), never `Warrant.Tag` (HMAC, FFI), the budget
  (Postgres) or the egress code, so a client links none of them.

  ## The request

  ```json
  {
    "warrant": {
      "id": "...", "orgId": "...", "tag": "<hex>",
      "caveats": [
        {"kind": "expiresAt",  "value": "<u64 decimal string>"},
        {"kind": "capability", "provider": "...", "action": "..."},
        {"kind": "resource",   "value": "..."},
        {"kind": "budget",     "value": "<nat decimal string>"},
        {"kind": "runId",      "value": "..."}
      ]
    },
    "now": "<u64 decimal string>", "cost": "<nat decimal string>",
    "provider": "...", "action": "...", "resource": "...",
    "runId": "...", "orgId": "...",
    "call": {"kind": "provider", "account": "{user_id}/{connection_id}",
             "method": "GET", "url": "https://...",
             "headers": {"accept": "application/json"},   -- optional
             "body": "..."}                               -- optional, UTF-8
      -- or {"kind": "inference"}
  }
  ```

  Caveats travel most recent first. `now`, `cost`, `budget` and `expiresAt`
  are decimal **strings**, not JSON numbers: `Data.Json.Value.number` is
  `Float`-backed, and exact integers (money, times) are never routed through a
  float (`proof-strategy.md`'s "integers only for money"). A `u64` field
  outside `[0, 2^64)` is malformed, not wrapped.

  The fields next to the warrant are what the call claims; liaison checks them
  against the warrant's caveats. A client should not choose them:
  `Request.ofWarrant` reads them off the warrant, and
  `Request.ofWarrant_unique` shows that whenever the warrant permits any
  request at all (for the warrant's org, at that `now` and `cost`), it is this
  one.

  ## The reply

  - `200` with `{"status": <number>, "headers": {…}, "body": "<hex>"}`: the
    provider answered (whatever its status), relayed.
  - Anything else: liaison refused, `{"error": "<code>"}` with
    `Denial.code` (the HTTP status is `Server.denialStatus`).
-/

import Liaison.Warrant.Core
import Linen.Data.Json
import Linen.Data.Hex

namespace Liaison.Wire

open Data.Json (Value)

-- ── Reading JSON ─────────────────────────────────────────────────────

private def orErr (o : Option α) (msg : String) : Except String α :=
  match o with
  | some v => .ok v
  | none => .error msg

mutual
/-- Refuse ambiguous objects before converting to map-backed provider JSON.
    Duplicate keys must never choose different selectors in different parsers. -/
def uniqueKeys : Value → Bool
  | .object fields => (fields.map Prod.fst).eraseDups.length == fields.length && uniqueFields fields
  | .array values => uniqueValues values.toList
  | _ => true
private def uniqueFields : List (String × Value) → Bool
  | [] => true
  | (_, value) :: rest => uniqueKeys value && uniqueFields rest
private def uniqueValues : List Value → Bool
  | [] => true
  | value :: rest => uniqueKeys value && uniqueValues rest
end

/-- Required/allowed object fields, including duplicate-key rejection. -/
def objectFields (value : Value) (required allowed : List String) : Except String Unit := do
  let some fields := value.asObject | throw "expected a JSON object"
  unless uniqueKeys value && fields.all (fun entry => allowed.contains entry.1) &&
      required.all (fun name => fields.any (fun entry => entry.1 == name)) do
    throw "missing, duplicate or unsupported JSON field"

private def getString (v : Value) (ctx field : String) : Except String String := do
  let f ← (v.getField field).mapError fun _ => s!"{ctx}.{field}: missing"
  orErr f.asString s!"{ctx}.{field}: not a string"

private def getDecimalNat (v : Value) (ctx field : String) : Except String Nat := do
  let s ← getString v ctx field
  if s.isEmpty || !s.all Char.isDigit then
    .error s!"{ctx}.{field}: not a decimal natural number"
  orErr s.toNat? s!"{ctx}.{field}: not a decimal natural number"

private def getDecimalU64 (v : Value) (ctx field : String) : Except String UInt64 := do
  let n ← getDecimalNat v ctx field
  if n < UInt64.size then .ok n.toUInt64
  else .error s!"{ctx}.{field}: out of range for a u64"

-- ── Accounts ─────────────────────────────────────────────────────────

/-- One account segment: non-empty, `[A-Za-z0-9_-]` only. -/
def validAccountSegment (s : String) : Bool :=
  !s.isEmpty && s.all (fun c => c.isAlphanum || c == '_' || c == '-')

/-- `call.account` is exactly two valid segments separated by one `/`:
    `{user_id}/{connection_id}`. -/
def validAccount (account : String) : Bool :=
  match account.splitOn "/" with
  | [u, c] => validAccountSegment u && validAccountSegment c
  | _ => false

/-- `validAccount`, and the connection segment equals the request's
    `resource` (which the warrant's `resource` caveat binds), so a warrant for
    one connection cannot read another's credential (`connections.md` §5). -/
def accountMatchesResource (account resource : String) : Bool :=
  validAccount account &&
    (match account.splitOn "/" with
     | [_, c] => c == resource
     | _ => false)

-- ── Calls ────────────────────────────────────────────────────────────

/-- A `"call": {"kind": "provider", …}` (`connections.md` §5). -/
structure ProviderCall where
  /-- `{user_id}/{connection_id}`; checked by `accountMatchesResource` before
      any reservation. -/
  account : String
  /-- Uppercase letters only (checked when decoding), so nothing can be
      smuggled into the outbound request line. -/
  method  : String
  url     : String
  /-- Caller headers, in order. -/
  headers : List (String × String) := []
  /-- UTF-8 body. -/
  body    : Option String := none
  deriving DecidableEq, Repr

/-- Truthful conversation metadata; no arbitrary caller headers. -/
structure NativeContext where
  sessionId : String
  initiator : String
  client : String
  deriving DecidableEq, Repr

def NativeContext.valid (context : NativeContext) : Bool :=
  !context.sessionId.isEmpty && context.sessionId.length ≤ 128 && validAccountSegment context.sessionId &&
    ["user", "agent"].contains context.initiator && context.client == "typednotes-lode"

/-- URL-free typed connector call. The broker derives the transport from the
    operation and resource, so an authorized selector cannot mask another URL. -/
structure ConnectorCall where
  account : String
  operation : String
  resource : List String
  /-- Operation-specific JSON, encoded as UTF-8 text, never request headers. -/
  payload : String := "{}"
  context : Option NativeContext := none
  deriving DecidableEq, Repr

/-- Shared validation for wire input, stored grants and native adapters. A
    selector is a hierarchy, never an encoded path or an API query. -/
def validResource (resource : List String) : Bool :=
  resource.length ≤ 32 && resource.all (fun part =>
    !part.isEmpty && part.toUTF8.size ≤ 255 && part != "." && part != ".." &&
    !part.contains '/' && !part.contains '\\' && !part.contains '%' &&
    part.all (fun (c : Char) => c.toNat ≥ 0x20 && !(0x7f ≤ c.toNat && c.toNat ≤ 0x9f)))

/-- What to do once a request is authorized and its budget reserved. -/
inductive Call
  | provider (call : ProviderCall)
  | connector (call : ConnectorCall)
  | inference
  deriving DecidableEq, Repr

/-- A whole `POST /v0/egress` body. -/
structure Body where
  warrant : Warrant
  request : Request
  call    : Call

-- ── Decoding a request ───────────────────────────────────────────────

/-- One caveat. -/
def decodeCaveat (v : Value) : Except String Caveat := do
  let ctx := "warrant.caveats[]"
  match ← getString v ctx "kind" with
  | "expiresAt" => return .expiresAt (← getDecimalU64 v ctx "value")
  | "capability" => return .capability ⟨← getString v ctx "provider"⟩ ⟨← getString v ctx "action"⟩
  | "resource" => return .resource ⟨← getString v ctx "value"⟩
  | "budget" => return .budget (← getDecimalNat v ctx "value")
  | "runId" => return .runId ⟨← getString v ctx "value"⟩
  | other => .error s!"{ctx}.kind: unknown caveat kind {other}"

/-- A warrant. Its tag is not checked here (`Auth.authorize` does, first). -/
def decodeWarrant (v : Value) : Except String Warrant := do
  let id ← getString v "warrant" "id"
  let orgId ← getString v "warrant" "orgId"
  let tag ← orErr (Data.Hex.decode (← getString v "warrant" "tag")) "warrant.tag: not hex"
  let caveats ← (v.getField "caveats").mapError fun _ => "warrant.caveats: missing"
  let caveats ← orErr caveats.asArray "warrant.caveats: not an array"
  let caveats ← caveats.toList.mapM decodeCaveat
  return { id := ⟨id⟩, orgId := ⟨orgId⟩, caveats, tag }

/-- The request fields of the body (everything but `warrant` and `call`). -/
def decodeRequest (v : Value) : Except String Request := do
  return { now := ← getDecimalU64 v "request" "now", cost := ← getDecimalNat v "request" "cost"
           provider := ⟨← getString v "request" "provider"⟩
           action := ⟨← getString v "request" "action"⟩
           resource := ⟨← getString v "request" "resource"⟩
           runId := ⟨← getString v "request" "runId"⟩
           orgId := ⟨← getString v "request" "orgId"⟩ }

/-- `call.headers`: absent or `null` → `[]`; otherwise an object whose every
    value is a string. -/
private def decodeHeaders (v : Value) (ctx : String) : Except String (List (String × String)) := do
  match ← v.getFieldOpt "headers" with
  | none => return []
  | some (.object fields) =>
    fields.mapM fun (k, val) => (orErr val.asString s!"{ctx}.headers.{k}: not a string").map (k, ·)
  | some _ => .error s!"{ctx}.headers: not an object"

/-- The `call` object. -/
def decodeCall (v : Value) : Except String Call := do
  match ← getString v "call" "kind" with
  | "provider" =>
    let account ← getString v "call" "account"
    let method ← getString v "call" "method"
    if method.isEmpty || !method.all Char.isUpper then
      .error "call.method: not an uppercase method name"
    let url ← getString v "call" "url"
    let headers ← decodeHeaders v "call"
    let body ← match ← v.getFieldOpt "body" with
      | none => pure none
      | some (.string s) => pure (some s)
      | some _ => .error "call.body: not a string"
    return .provider { account, method, url, headers, body }
  | "connector" =>
    objectFields v ["kind", "account", "operation", "resource"] ["kind", "account", "operation", "resource", "payload", "context"]
    let account ← getString v "call" "account"
    let operation ← getString v "call" "operation"
    let resources ← (v.getField "resource").mapError fun _ => "call.resource: missing"
    let resources ← orErr resources.asArray "call.resource: not an array"
    let resource : List String ← resources.toList.mapM fun value => orErr value.asString "call.resource: not strings"
    unless !operation.isEmpty && operation.length ≤ 64 && validResource resource do
      throw "call: invalid connector operation/resource"
    let payload ← match ← v.getFieldOpt "payload" with
      | none => pure "{}"
      | some (.string s) => pure s
      | some _ => throw "call.payload: must be JSON text"
    let context ← match v.lookup "context" with
      | none => pure none
      | some value => do
        objectFields value ["sessionId", "initiator", "client"] ["sessionId", "initiator", "client"]
        let sessionId ← getString value "context" "sessionId"
        let initiator ← getString value "context" "initiator"
        let client ← getString value "context" "client"
        let context : NativeContext := { sessionId, initiator, client }
        unless context.valid && operation == "inference.generate" do throw "invalid native conversation context"
        pure (some context)
    return .connector { account, operation, resource, payload, context }
  | "inference" => return .inference
  | other => .error s!"call.kind: unknown call kind {other}"

/-- A whole body, from its JSON text. -/
def Body.parse (text : String) : Except String Body := do
  let root ← Data.Json.Decode.decode text
  unless uniqueKeys root do throw "duplicate JSON field"
  let warrant ← decodeWarrant (← (root.getField "warrant").mapError fun _ => "warrant: missing")
  let request ← decodeRequest root
  let call ← decodeCall (← (root.getField "call").mapError fun _ => "call: missing")
  return { warrant, request, call }

/-- A whole body, from the request's bytes (which must be UTF-8). -/
def Body.decode (bytes : ByteArray) : Except String Body := do
  Body.parse (← orErr (String.fromUTF8? bytes) "body: not UTF-8")

-- ── Encoding a request ───────────────────────────────────────────────

/-- One caveat, as `decodeCaveat` reads it. -/
def encodeCaveat : Caveat → Value
  | .expiresAt t => .object [("kind", .string "expiresAt"), ("value", .string (toString t.toNat))]
  | .capability p a =>
    .object [("kind", .string "capability"), ("provider", .string p.value), ("action", .string a.value)]
  | .resource r => .object [("kind", .string "resource"), ("value", .string r.value)]
  | .budget c => .object [("kind", .string "budget"), ("value", .string (toString c))]
  | .runId r => .object [("kind", .string "runId"), ("value", .string r.value)]

/-- A warrant, as `decodeWarrant` reads it. -/
def encodeWarrant (w : Warrant) : Value :=
  .object
    [ ("id", .string w.id.value), ("orgId", .string w.orgId.value)
    , ("tag", .string (Data.Hex.encode w.tag))
    , ("caveats", .array (w.caveats.map encodeCaveat).toArray) ]

/-- The `call` object, as `decodeCall` reads it. -/
def encodeCall : Call → Value
  | .inference => .object [("kind", .string "inference")]
  | .provider c =>
    .object <|
      [ ("kind", .string "provider"), ("account", .string c.account)
      , ("method", .string c.method), ("url", .string c.url)
      , ("headers", .object (c.headers.map fun (k, v) => (k, .string v))) ]
       ++ (c.body.map fun b => [("body", .string b)]).getD []
  | .connector c => Value.object <|
      [("kind", .string "connector"), ("account", .string c.account),
       ("operation", .string c.operation), ("resource", .array (c.resource.map Value.string).toArray),
        ("payload", .string c.payload)] ++ (c.context.map fun context => [("context", .object [
          ("sessionId", .string context.sessionId), ("initiator", .string context.initiator), ("client", .string context.client)])]).getD []

/-- A whole body, as JSON. -/
def Body.toValue (b : Body) : Value :=
  .object
    [ ("warrant", encodeWarrant b.warrant)
    , ("now", .string (toString b.request.now.toNat)), ("cost", .string (toString b.request.cost))
    , ("provider", .string b.request.provider.value), ("action", .string b.request.action.value)
    , ("resource", .string b.request.resource.value), ("runId", .string b.request.runId.value)
    , ("orgId", .string b.request.orgId.value)
    , ("call", encodeCall b.call) ]

/-- A whole body, as the JSON text `Body.parse` reads. -/
def Body.encode (b : Body) : String :=
  Data.Json.Encode.encode b.toValue

-- ── What a warrant determines ────────────────────────────────────────

/-- The provider and action a caveat grants, if it is a capability. -/
def capabilityOf : Caveat → Option (Provider × Action)
  | .capability p a => some (p, a)
  | _ => none

/-- The resource a caveat binds, if it is a resource caveat. -/
def resourceOf : Caveat → Option ResourceId
  | .resource r => some r
  | _ => none

/-- The run a caveat binds, if it is a run caveat. -/
def runIdOf : Caveat → Option RunId
  | .runId r => some r
  | _ => none

/-- The request a warrant is for, at `now` and `cost`: provider, action,
    resource and run read off its first caveat of each kind (every caveat must
    hold, so if two of a kind disagree no request is permitted and the first
    is as good as any), org off the warrant. Fails if the warrant lacks one of
    these kinds. -/
def Request.ofWarrant (w : Warrant) (now : UInt64) (cost : Credits) : Except String Request :=
  match w.caveats.findSome? capabilityOf, w.caveats.findSome? resourceOf,
      w.caveats.findSome? runIdOf with
  | some (provider, action), some resource, some runId =>
    .ok { now, cost, provider, action, resource, runId, orgId := w.orgId }
  | none, _, _ => .error "warrant: no capability caveat"
  | _, none, _ => .error "warrant: no resource caveat"
  | _, _, none => .error "warrant: no runId caveat"

/-- The first of a kind among caveats that all permit `r` is `r`'s. -/
private theorem findSome?_of_permits (f : Caveat → Option α) (r : Request) (v : α)
    (hf : ∀ c x, f c = some x → c.permits r → x = v) :
    ∀ (l : List Caveat), (∀ c ∈ l, c.permits r) → ∀ x, l.findSome? f = some x → x = v
  | [], _, x, h => by simp at h
  | c :: cs, hl, x, h => by
    rw [List.findSome?_cons] at h
    cases hc : f c with
    | none =>
      rw [hc] at h
      exact findSome?_of_permits f r v hf cs (fun c' h' => hl c' (List.mem_cons_of_mem c h')) x h
    | some y =>
      rw [hc] at h
      simp only [Option.some.injEq] at h
      subst h
      exact hf c _ hc (hl c List.mem_cons_self)

/-- `Request.ofWarrant` cannot disagree with the warrant: any request the
    warrant permits, for the warrant's org at the same `now` and `cost`, is the
    one it derives. -/
theorem Request.ofWarrant_unique (w : Warrant) (r r' : Request)
    (hd : Request.ofWarrant w r.now r.cost = .ok r') (hp : w.permits r) (ho : r.orgId = w.orgId) :
    r' = r := by
  unfold Request.ofWarrant at hd
  cases h1 : w.caveats.findSome? capabilityOf with
  | none => simp [h1] at hd
  | some pa =>
    cases h2 : w.caveats.findSome? resourceOf with
    | none => cases pa; simp [h1, h2] at hd
    | some res =>
      cases h3 : w.caveats.findSome? runIdOf with
      | none => cases pa; simp [h1, h2, h3] at hd
      | some run =>
        obtain ⟨p, a⟩ := pa
        simp only [h1, h2, h3, Except.ok.injEq] at hd
        subst hd
        have e1 := findSome?_of_permits capabilityOf r (r.provider, r.action)
          (fun c x hc hpc => by
            cases c <;> simp [capabilityOf] at hc
            subst hc; simp [Caveat.permits] at hpc; simp [hpc])
          w.caveats hp _ h1
        have e2 := findSome?_of_permits resourceOf r r.resource
          (fun c x hc hpc => by
            cases c <;> simp [resourceOf] at hc
            subst hc; simpa [Caveat.permits] using hpc.symm)
          w.caveats hp _ h2
        have e3 := findSome?_of_permits runIdOf r r.runId
          (fun c x hc hpc => by
            cases c <;> simp [runIdOf] at hc
            subst hc; simpa [Caveat.permits] using hpc.symm)
          w.caveats hp _ h3
        simp only [Prod.mk.injEq] at e1
        obtain ⟨e1a, e1b⟩ := e1
        subst e1a e1b e2 e3
        rw [← ho]

/-- The body of a provider call under `w`: the request fields derived from
    the warrant (`Request.ofWarrant`), refused client-side if the account does
    not name the warrant's resource (liaison would refuse it too). -/
def Body.provider (w : Warrant) (now : UInt64) (cost : Credits) (call : ProviderCall) :
    Except String Body := do
  let request ← Request.ofWarrant w now cost
  unless accountMatchesResource call.account request.resource.value do
    .error "call.account: must be {user_id}/{connection_id}, the connection being the warrant's resource"
  return { warrant := w, request, call := .provider call }

def Body.connector (w : Warrant) (now : UInt64) (cost : Credits) (call : ConnectorCall) :
    Except String Body := do
  let request ← Request.ofWarrant w now cost
  unless accountMatchesResource call.account request.resource.value do
    throw "call.account: does not name the warranted connection"
  unless call.operation == request.action.value do
    throw "call.operation: does not match the warrant's operation"
  return { warrant := w, request, call := .connector call }

-- ── Replies ──────────────────────────────────────────────────────────

/-- What a provider answered, as liaison relays it. -/
structure Response where
  status  : UInt16
  headers : List (String × String)
  body    : ByteArray

/-- A header's value, by case-insensitive name. -/
def Response.header? (r : Response) (name : String) : Option String :=
  (r.headers.find? fun (k, _) => k.toLower == name.toLower).map Prod.snd

/-- The `200` body relaying a provider's answer. -/
def encodeResponse (r : Response) : String :=
  Data.Json.Encode.encode <| .object
    [ ("status", .number r.status.toNat.toFloat)
    , ("headers", .object (r.headers.map fun (k, v) => (k, .string v)))
    , ("body", .string (Data.Hex.encode r.body)) ]

/-- The body of a refusal: `{"error": code}`. -/
def encodeRefusal (d : Denial) : String :=
  Data.Json.Encode.encode (.object [("error", .string d.code)])

/-- What liaison answered a `POST /v0/egress`. -/
inductive Reply
  /-- The provider answered (with any status); liaison relays it. -/
  | relayed (r : Response)
  /-- liaison refused, with this HTTP status and `error` code (a
      `Denial.code`; `Denial.ofCode?` reads it back, and a code this version
      does not know is kept as is). -/
  | refused (httpStatus : Nat) (code : String)

private def decodeStatus (f : Float) : Except String UInt16 :=
  if 0 ≤ f && f < 65536 && f.floor == f then .ok f.toUInt16
  else .error "reply.status: not an HTTP status"

/-- Read liaison's answer, given its HTTP status and body. -/
def decodeReply (httpStatus : Nat) (body : String) : Except String Reply := do
  let root ← (Data.Json.Decode.decode body).mapError
    (s!"liaison answered {httpStatus} with non-JSON: " ++ ·)
  if httpStatus != 200 then
    return .refused httpStatus ((root.lookup "error" >>= (·.asString)).getD "unknown")
  let status ← decodeStatus (← orErr ((root.lookup "status").bind (·.asNumber)) "reply.status: missing")
  let headers ← match root.lookup "headers" with
    | some (.object kvs) =>
      kvs.mapM fun (k, v) => (orErr v.asString s!"reply.headers.{k}: not a string").map (k, ·)
    | _ => .error "reply.headers: not an object"
  let hex ← orErr ((root.lookup "body").bind (·.asString)) "reply.body: missing"
  let bytes ← orErr (Data.Hex.decode hex) "reply.body: not hex"
  return .relayed { status, headers, body := bytes }

end Liaison.Wire
