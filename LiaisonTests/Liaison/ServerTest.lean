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

  What *is* checked: `application`'s public signature.
-/
import Liaison.Server

open Liaison

namespace LiaisonTests.Liaison.Server

example : RootKey → Database.SQL.Pool.Pool → Egress.SecretsConfig → Network.WebApp.Application :=
  application

end LiaisonTests.Liaison.Server
