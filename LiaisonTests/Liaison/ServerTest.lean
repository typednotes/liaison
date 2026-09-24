/-
  Tests for `Liaison.Server`.

  **Gap, named here and in `AGENTS.md`:** every parsing function in
  `Server.lean` (`parseWarrant`, `parseRequest`, `parseCaveat`, `parseCall`,
  `parseBody`) and every response-shaping function (`denialStatus`,
  `denialBody`, `denialResponse`, `wrapUpstream`) is `private` to that file
  — deliberately, since `Server.lean` is meant to be the one place that
  looks at raw bytes, and nothing downstream should be tempted to import
  and reuse a half-trusted parser. That leaves nothing to unit-test from
  outside the file: the wire format is exercised only by an actual HTTP
  request against a running `application`, which needs a live Postgres
  pool (`Liaison.Budget`) and so is not run as part of `lake build LiaisonTests`.

  A real end-to-end check (`curl localhost:PORT/v0/egress` against a
  `Main`-started server backed by a scratch Postgres) was run manually
  during implementation rather than automated here — see the final
  implementation report for what was and wasn't exercised that way.

  What *is* checked: `application`'s public signature, and the
  denial → HTTP status / `error` code mapping (`denialStatus`, `Denial.code`),
  including the four 0.3.0 denials of `docs/connections.md` §5.
-/
import Liaison.Server

open Liaison

namespace LiaisonTests.Liaison.Server

example : RootKey → Database.SQL.Pool.Pool → Egress.EgressConfig → Network.WebApp.Application :=
  application

private def row (d : Denial) : Nat × String := ((denialStatus d).statusCode, d.code)

#guard row .urlDenied == (403, "url_denied")
#guard row .headerDenied == (400, "header_denied")
#guard row .credentialUnavailable == (502, "credential_unavailable")
#guard row .upstreamFailed == (502, "upstream_failed")
#guard row .malformedWarrant == (400, "malformed_warrant")
#guard row .tagInvalid == (403, "tag_invalid")
#guard row .capabilityDenied == (403, "capability_denied")
#guard row .resourceDenied == (403, "resource_denied")
#guard row .wrongRun == (403, "wrong_run")
#guard row .expired == (403, "expired")
#guard row .budgetExceeded == (403, "budget_exceeded")
#guard row .budgetUnavailable == (402, "budget_unavailable")
#guard row .inferenceNotImplemented == (501, "inference_not_implemented")

end LiaisonTests.Liaison.Server
