/-
  Tests for `Liaison.Wire`: the request format pinned literally (both
  directions), decode ∘ encode on every shape of body, what is refused, the
  request a warrant determines, and the replies.
-/
import Liaison.Wire

open Liaison Liaison.Wire

namespace LiaisonTests.Liaison.Wire

-- ── Helpers ──

/-- Warrants carry a `ByteArray` tag (no `DecidableEq`): compare field-wise. -/
def sameWarrant (a b : Warrant) : Bool :=
  a.id == b.id && a.orgId == b.orgId && a.caveats == b.caveats && a.tag.toList == b.tag.toList

def sameBody (a b : Body) : Bool :=
  sameWarrant a.warrant b.warrant && a.request == b.request && a.call == b.call

def roundTrips (b : Body) : Bool :=
  match Body.parse b.encode with
  | .ok b' => sameBody b b'
  | .error _ => false

def refused (text : String) : Bool := (Body.parse text).toOption.isNone

-- ── Fixtures ──

/-- A warrant as the app mints it (caveats most recent first). -/
def warrant : Warrant :=
  { id := ⟨"w-1"⟩, orgId := ⟨"org-1"⟩, tag := ⟨#[0xab, 0x01]⟩
    caveats := [ .runId ⟨"run-1"⟩, .budget 0, .resource ⟨"conn-1"⟩
               , .capability ⟨"github"⟩ ⟨"read"⟩, .expiresAt 1790000000 ] }

def call : ProviderCall :=
  { account := "user-1/conn-1", method := "GET", url := "https://api.github.com/user"
    headers := [("accept", "application/json")] }

def request : Request :=
  { now := 1700000000, cost := 0, provider := ⟨"github"⟩, action := ⟨"read"⟩
    resource := ⟨"conn-1"⟩, runId := ⟨"run-1"⟩, orgId := ⟨"org-1"⟩ }

def body : Body := { warrant, request, call := .provider call }

-- ── The format, literally ──

/-- `body` on the wire. Pins every field name, the decimal strings and the hex
    tag (linen's encoder escapes `/`). -/
def golden : String :=
  "{\"warrant\":{\"id\":\"w-1\",\"orgId\":\"org-1\",\"tag\":\"ab01\",\"caveats\":[" ++
  "{\"kind\":\"runId\",\"value\":\"run-1\"},{\"kind\":\"budget\",\"value\":\"0\"}," ++
  "{\"kind\":\"resource\",\"value\":\"conn-1\"}," ++
  "{\"kind\":\"capability\",\"provider\":\"github\",\"action\":\"read\"}," ++
  "{\"kind\":\"expiresAt\",\"value\":\"1790000000\"}]}," ++
  "\"now\":\"1700000000\",\"cost\":\"0\",\"provider\":\"github\",\"action\":\"read\"," ++
  "\"resource\":\"conn-1\",\"runId\":\"run-1\",\"orgId\":\"org-1\"," ++
  "\"call\":{\"kind\":\"provider\",\"account\":\"user-1\\/conn-1\",\"method\":\"GET\"," ++
  "\"url\":\"https:\\/\\/api.github.com\\/user\",\"headers\":{\"accept\":\"application\\/json\"}}}"

#guard body.encode == golden

/-- The same body as a client may write it: whitespace, another field order,
    upper-case hex, an unknown top-level field (ignored). -/
def handWritten : String := "{
  \"call\": {\"kind\": \"provider\", \"account\": \"user-1/conn-1\", \"method\": \"GET\",
           \"url\": \"https://api.github.com/user\", \"headers\": {\"accept\": \"application/json\"}},
  \"orgId\": \"org-1\", \"runId\": \"run-1\", \"resource\": \"conn-1\",
  \"action\": \"read\", \"provider\": \"github\", \"cost\": \"0\", \"now\": \"1700000000\",
  \"extra\": true,
  \"warrant\": {\"tag\": \"AB01\", \"orgId\": \"org-1\", \"id\": \"w-1\", \"caveats\": [
    {\"kind\": \"runId\", \"value\": \"run-1\"}, {\"kind\": \"budget\", \"value\": \"0\"},
    {\"kind\": \"resource\", \"value\": \"conn-1\"},
    {\"kind\": \"capability\", \"provider\": \"github\", \"action\": \"read\"},
    {\"kind\": \"expiresAt\", \"value\": \"1790000000\"}]}
}"

#guard match Body.parse handWritten with
  | .ok b => sameBody b body
  | .error _ => false

-- ── decode ∘ encode ──

#guard roundTrips body
#guard roundTrips { body with call := .inference }
#guard roundTrips { body with call := .provider { call with headers := [] } }
#guard roundTrips { body with call := .provider { call with method := "POST", body := some "{\"a\": \"é\\n\"}" } }
#guard roundTrips { body with call := .provider { call with headers := [("a", "1"), ("a", "2")] } }
#guard roundTrips { body with warrant := { warrant with caveats := [], tag := .empty } }
-- The ends of the ranges.
#guard roundTrips { body with request := { request with now := 0, cost := 0 } }
#guard roundTrips { body with
  request := { request with now := UInt64.ofNat (UInt64.size - 1), cost := 10 ^ 30 }
  warrant := { warrant with caveats := [.expiresAt (UInt64.ofNat (UInt64.size - 1)), .budget (10 ^ 30)] } }
-- Strings that need escaping.
#guard roundTrips { body with
  request := { request with runId := ⟨"a\"b\\c/d\u0001"⟩ }
  warrant := { warrant with id := ⟨"ü\t"⟩ } }

-- ── Refused ──

def replace (old new : String) : String := golden.replace old new

#guard !refused golden
#guard refused "not json"
#guard (Body.decode ⟨#[0xff, 0xfe]⟩).toOption.isNone                 -- not UTF-8
#guard refused (replace "\"now\":\"1700000000\"" "\"now\":1700000000")  -- a number, not a string
#guard refused (replace "\"now\":\"1700000000\"" "\"now\":\"18446744073709551616\"")  -- ≥ 2^64
#guard !refused (replace "\"now\":\"1700000000\"" "\"now\":\"18446744073709551615\"")
#guard refused (replace "\"value\":\"1790000000\"" "\"value\":\"18446744073709551616\"")
#guard refused (replace "\"cost\":\"0\"" "\"cost\":\"-1\"")
#guard refused (replace "\"cost\":\"0\"" "\"cost\":\"+1\"")
#guard refused (replace "\"cost\":\"0\"" "\"cost\":\"1_0\"")
#guard refused (replace "\"cost\":\"0\"" "\"cost\":\"\"")
#guard refused (replace "\"cost\":\"0\"" "\"cost\":\" 1\"")
#guard refused (replace "\"tag\":\"ab01\"" "\"tag\":\"xyz\"")
#guard refused (replace "\"kind\":\"runId\"" "\"kind\":\"sudo\"")
#guard refused (replace "\"method\":\"GET\"" "\"method\":\"get\"")
#guard refused (replace "\"method\":\"GET\"" "\"method\":\"GET \\r\\n\"")
#guard refused (replace "\"method\":\"GET\"" "\"method\":\"\"")
#guard refused (replace "{\"accept\":\"application\\/json\"}" "{\"accept\":1}")
#guard refused (replace "{\"accept\":\"application\\/json\"}" "[]")
#guard refused (replace "\"kind\":\"provider\"" "\"kind\":\"shell\"")
#guard refused (replace "\"orgId\":\"org-1\",\"call\"" "\"call\"")      -- a missing field
#guard !refused (replace ",\"headers\":{\"accept\":\"application\\/json\"}" "")  -- headers optional
#guard !refused (replace ",\"headers\":{\"accept\":\"application\\/json\"}" ",\"headers\":null")
#guard refused (replace ",\"headers\":{\"accept\":\"application\\/json\"}" ",\"body\":7")

-- ── What a warrant determines ──

#guard Request.ofWarrant warrant 1700000000 0 == .ok request
-- The first caveat of a kind (most recent first).
#guard (Request.ofWarrant { warrant with caveats := .resource ⟨"conn-2"⟩ :: warrant.caveats } 0 0).toOption.map
  (·.resource) == some ⟨"conn-2"⟩
#guard (Request.ofWarrant { warrant with caveats := [.resource ⟨"r"⟩, .runId ⟨"x"⟩] } 0 0) matches .error _
#guard (Request.ofWarrant { warrant with caveats := [.capability ⟨"p"⟩ ⟨"a"⟩, .runId ⟨"x"⟩] } 0 0) matches .error _
#guard (Request.ofWarrant { warrant with caveats := [.capability ⟨"p"⟩ ⟨"a"⟩, .resource ⟨"r"⟩] } 0 0) matches .error _

#guard match Body.provider warrant 1700000000 0 call with
  | .ok b => sameBody b body
  | .error _ => false
-- The account must name the warrant's resource.
#guard (Body.provider warrant 0 0 { call with account := "user-1/conn-2" }) matches .error _
#guard (Body.provider warrant 0 0 { call with account := "conn-1" }) matches .error _

-- ── Accounts ──

#guard validAccount "user_1/conn-2"
#guard validAccount "0d6f1c5e-aaaa-4bbb-8ccc-123456789abc/5e1c-77"
#guard !validAccount "conn"                -- one segment
#guard !validAccount "a/b/c"               -- three segments
#guard !validAccount "a//b"                -- empty middle segment
#guard !validAccount "/b"
#guard !validAccount "a/"
#guard !validAccount "a/../b"
#guard !validAccount "a/b.c"               -- `.` not allowed
#guard !validAccount "a/b c"
#guard !validAccount "a/b?x"
#guard !validAccount ""

#guard accountMatchesResource "user/conn" "conn"
#guard !accountMatchesResource "user/conn" "other"
#guard !accountMatchesResource "conn/user" "conn"   -- the *last* segment is bound
#guard !accountMatchesResource "user/conn/x" "x"

-- ── Replies ──

def upstream : Response :=
  { status := 302, headers := [("Location", "https://codeload.github.com/x"), ("x", "")]
    body := ⟨#[0x68, 0x69, 0x00, 0xff]⟩ }

#guard encodeResponse upstream ==
  "{\"status\":302,\"headers\":{\"Location\":\"https:\\/\\/codeload.github.com\\/x\",\"x\":\"\"},\"body\":\"686900ff\"}"

#guard match decodeReply 200 (encodeResponse upstream) with
  | .ok (.relayed r) => r.status == 302 && r.headers == upstream.headers && r.body.toList == upstream.body.toList
  | _ => false
#guard match decodeReply 200 (encodeResponse upstream) with
  | .ok (.relayed r) => r.header? "location" == some "https://codeload.github.com/x" && r.header? "nope" == none
  | _ => false

-- Every refusal reads back as its denial.
#guard Denial.all.all fun d =>
  match decodeReply 403 (encodeRefusal d) with
  | .ok (.refused 403 code) => Denial.ofCode? code == some d
  | _ => false
-- A code this version does not know is kept.
#guard match decodeReply 429 "{\"error\": \"rate_limited\"}" with
  | .ok (.refused 429 "rate_limited") => Denial.ofCode? "rate_limited" == none
  | _ => false
#guard match decodeReply 502 "{}" with
  | .ok (.refused 502 "unknown") => true
  | _ => false

#guard (decodeReply 200 "not json") matches .error _
#guard (decodeReply 502 "Bad Gateway") matches .error _
#guard (decodeReply 200 "{\"status\": 200, \"headers\": {}, \"body\": \"zz\"}") matches .error _
#guard (decodeReply 200 "{\"status\": 200.5, \"headers\": {}, \"body\": \"\"}") matches .error _
#guard (decodeReply 200 "{\"status\": 70000, \"headers\": {}, \"body\": \"\"}") matches .error _
#guard (decodeReply 200 "{\"status\": -1, \"headers\": {}, \"body\": \"\"}") matches .error _
#guard (decodeReply 200 "{\"status\": 200, \"headers\": {\"a\": 1}, \"body\": \"\"}") matches .error _
#guard (decodeReply 200 "{\"status\": 200, \"body\": \"\"}") matches .error _
#guard (decodeReply 200 "{\"status\": 204, \"headers\": {}, \"body\": \"\"}") matches .ok (.relayed _)

end LiaisonTests.Liaison.Wire
