/-
  Tests for `Liaison.Egress.Policy`: account validation, the caller-header
  policy, the URL-prefix rule and target decomposition, and the Google
  refresh predicate (`docs/connections.md` §5).
-/
import Liaison.Egress.Policy

open Liaison.Egress

namespace LiaisonTests.Liaison.Egress.Policy

-- ── Account ──

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

-- ── Caller headers ──

#guard checkCallerHeaders [] [("accept", "application/json"), ("content-type", "text/plain")]
#guard checkCallerHeaders [] []
-- The fixed list, case-insensitively.
#guard !checkCallerHeaders [] [("Authorization", "Bearer x")]
#guard !checkCallerHeaders [] [("PROXY-AUTHORIZATION", "x")]
#guard !checkCallerHeaders [] [("x-api-key", "x")]
#guard !checkCallerHeaders [] [("Host", "evil.com")]
#guard !checkCallerHeaders [] [("Content-Length", "0")]
#guard !checkCallerHeaders [] [("Cookie", "a=b")]
#guard !checkCallerHeaders [] [("Transfer-Encoding", "chunked")]
#guard !checkCallerHeaders [] [("connection", "keep-alive")]
-- Every `x-amz-*`.
#guard !checkCallerHeaders [] [("X-Amz-Date", "x")]
#guard !checkCallerHeaders [] [("x-amz-security-token", "x")]
-- Whatever the credential sets (its auth header and static headers).
#guard !checkCallerHeaders ["anthropic-version"] [("Anthropic-Version", "2024-01-01")]
#guard !checkCallerHeaders ["x-goog-api-key"] [("X-Goog-Api-Key", "x")]
#guard checkCallerHeaders ["anthropic-version"] [("anthropic-beta", "x")]
-- Malformed names and values.
#guard !checkCallerHeaders [] [("bad name", "x")]
#guard !checkCallerHeaders [] [("", "x")]
#guard !checkCallerHeaders [] [("x-a", "v\r\nAuthorization: Bearer y")]
#guard !checkCallerHeaders [] [("x-a", "v\n")]
#guard checkCallerHeaders [] [("x-a", "v\twith tab")]
-- One bad header refuses the lot.
#guard !checkCallerHeaders [] [("accept", "x"), ("cookie", "y")]

-- ── URL ──

#guard urlWithinBase "https://api.github.com" "https://api.github.com/user"
#guard urlWithinBase "https://api.github.com" "https://api.github.com"
#guard urlWithinBase "https://s3.fr-par.scw.cloud/b" "https://s3.fr-par.scw.cloud/b?list-type=2"
#guard !urlWithinBase "https://api.github.com" "https://api.github.com.evil.com"
#guard !urlWithinBase "https://api.github.com" "https://api.github.com.evil.com/user"
#guard !urlWithinBase "https://api.github.com" "https://api.github.com@evil.com/"
#guard !urlWithinBase "https://api.github.com" "https://api.github.com:444/user"
#guard !urlWithinBase "https://api.github.com" "http://api.github.com/user"   -- no downgrade
#guard !urlWithinBase "https://api.openai.com/v1" "https://api.openai.com/v2/models"
#guard !urlWithinBase "https://api.openai.com/v1" "https://api.openai.com/v1beta"
#guard !urlWithinBase "https://s3.x/bucket" "https://s3.x/bucket-other/key"
-- `http` only when the base itself is `http`.
#guard urlWithinBase "http://localhost:9000/b" "http://localhost:9000/b/key"
#guard !urlWithinBase "ftp://x" "ftp://x/y"

#guard (checkUrl "https://api.github.com" "https://api.github.com/user") ==
  some { isSecure := true, host := "api.github.com", port := 443
         authority := "api.github.com", path := "/user", query := "" }
#guard (checkUrl "https://s3.fr-par.scw.cloud/my-bucket"
    "https://s3.fr-par.scw.cloud/my-bucket?list-type=2&max-keys=1") ==
  some { isSecure := true, host := "s3.fr-par.scw.cloud", port := 443
         authority := "s3.fr-par.scw.cloud", path := "/my-bucket"
         query := "list-type=2&max-keys=1" }
-- A bare base with a query gets path `/`.
#guard (checkUrl "https://www.googleapis.com" "https://www.googleapis.com?x=1").map (·.path) ==
  some "/"
#guard (checkUrl "http://localhost:9000/b" "http://localhost:9000/b/k").map
  (fun t => (t.isSecure, t.port, t.authority)) == some (false, 9000, "localhost:9000")
#guard (checkUrl "https://api.github.com" "https://api.github.com.evil.com/user").isNone
-- Dot segments (plain or encoded) could escape a base path.
#guard (checkUrl "https://api.openai.com/v1" "https://api.openai.com/v1/../admin").isNone
#guard (checkUrl "https://api.openai.com/v1" "https://api.openai.com/v1/%2e%2e/admin").isNone
#guard (checkUrl "https://api.openai.com/v1" "https://api.openai.com/v1/./models").isNone
-- Nothing can reach the request line: spaces, CR/LF, fragments.
#guard (checkUrl "https://api.github.com" "https://api.github.com/user HTTP/1.1").isNone
#guard (checkUrl "https://api.github.com" "https://api.github.com/user\r\nX: y").isNone
#guard (checkUrl "https://api.github.com" "https://api.github.com/user#frag").isNone

#guard percentDecode "a%20b" == some "a b"
#guard percentDecode "%C3%A9" == some "é"
#guard percentDecode "a+b" == some "a+b"
#guard percentDecode "%zz" == none
#guard percentDecode "%4" == none

-- ── Google refresh predicate ──

#guard needsRefresh 1000 940             -- exactly 60 s left: refresh
#guard needsRefresh 1000 999
#guard needsRefresh 1000 2000            -- already expired
#guard !needsRefresh 1000 939            -- 61 s left: not yet
#guard needsRefresh 30 0                 -- no Nat-subtraction underflow

end LiaisonTests.Liaison.Egress.Policy
