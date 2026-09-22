/-
  Tests for `Liaison.Egress.Provider`.

  **Gap, named here and in `AGENTS.md`:** `callInference`'s "never returns
  `.ok`" property cannot be given a black-box `IO` test in this file. Both
  `callProvider` and `callInference` take a `Reserved r`, and — by the
  chokepoint design `Provider.lean`'s own doc-comment describes — `Reserved`
  has no public constructor; the only way to obtain one is
  `Budget.withReservation`, which needs a live Postgres connection
  (`Budget.reserveHold`). No such connection exists in this build's test
  suite (see `AGENTS.md`'s "Not yet implemented": no live-database test
  coverage in v0), so there is no way to construct a `Reserved r` here to
  pass in.

  What *is* checked: `callInference`'s type (pinned by the `example` below,
  the same signature-pinning convention `Tests/Linen/Crypto/JOSE/FFITest.lean`
  uses for IO/FFI-bound code that `#guard`/`#eval` cannot exercise
  deterministically), and — by inspection, not by test — that its body is
  the single line `return .error .inferenceNotImplemented`, which never
  touches `_reserved` and has no other return path. A real end-to-end test
  of this property is one of the reasons the optional scratch-Postgres
  smoke test (`AGENTS.md`) is worth running before trusting this in
  production.
-/
import Liaison.Egress.Provider

open Liaison Liaison.Egress

namespace LiaisonTests.Liaison.Egress.Provider

example : {r : Request} → Reserved r → IO (Except Denial (Response × Credits)) :=
  @callInference

example : {r : Request} → SecretsConfig → String → Network.HTTP.Client.Request →
    Reserved r → IO (Except Denial (Response × Credits)) :=
  @callProvider

end LiaisonTests.Liaison.Egress.Provider
