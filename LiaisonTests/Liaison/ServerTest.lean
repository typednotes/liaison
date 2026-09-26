/-
  Tests for `Liaison.Server`.

  The wire format itself (decoding requests, encoding replies) is
  `Liaison.Wire`, tested in `LiaisonTests/Liaison/WireTest.lean`.

  **Gap, named here and in `AGENTS.md`:** the handler is exercised only by an
  actual HTTP request against a running `application`, which needs a live
  Postgres pool (`Liaison.Budget`) and so is not run as part of
  `lake build LiaisonTests`.

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
