/-
  Tests for `Liaison.Egress.Provider`.

  `callInference`'s "never returns `.ok`" property cannot be given a
  black-box `IO` test in this pure module. Both
  `callProvider` and `callInference` take a `Reserved r`, and — by the
  chokepoint design `Provider.lean`'s own doc-comment describes — `Reserved`
  has no public constructor; the only way to obtain one is
  `Budget.withReservation`, which needs a live Postgres connection
  (`Budget.reserveHold`). The separate `LiaisonTest/integration/connectors.py`
  suite supplies disposable Postgres and exercises the actual HTTP broker.

  The same constraint means native `callConnector` orchestration (policy,
  credential fetch → scope resolution → refresh → sign → send, every failure a
  `Denial`) is not driven end to end here; its pure parts are tested in
  `CredentialTest`, `PolicyTest`, `S3Test`, `OAuthTest` and below
  (`staticAuthHeaders`, `credentialQuery`).

  What *is* checked: `callInference`'s type (pinned by the `example` below,
  the same signature-pinning convention `LinenTest/Linen/Crypto/JOSE/FFITest.lean`
  uses for IO/FFI-bound code that `#guard`/`#eval` cannot exercise
  deterministically), and — by inspection, not by test — that its body is
  the single line `return .error .inferenceNotImplemented`, which never
  touches `_reserved` and has no other return path. Generic `callProvider`
  likewise unconditionally denies rather than bypass native operation scopes.
-/
import Liaison.Egress.Provider

open Liaison Liaison.Egress Liaison.Wire

namespace LiaisonTests.Liaison.Egress.Provider

example : {r : Request} → Reserved r → IO (Except Denial (Response × Credits)) :=
  @callInference

example : {r : Request} → EgressConfig → ProviderCall →
    Reserved r → IO (Except Denial (Response × Credits)) :=
  @callProvider

example : {r : Request} → EgressConfig → ConnectorCall →
    Reserved r → IO (Except Denial (Response × Credits)) := @callConnector

-- How each non-S3 kind authenticates (`docs/connections.md` §3.3).
#guard staticAuthHeaders (.bearer "gho_x") == some [("Authorization", "Bearer gho_x")]
#guard staticAuthHeaders (.header "x-api-key" "sk") == some [("x-api-key", "sk")]
#guard staticAuthHeaders (.oauth .google "ya29" "1//r" 0) == some [("Authorization", "Bearer ya29")]
#guard staticAuthHeaders (.oauth .gitlab "glo" "glr" 0) == some [("Authorization", "Bearer glo")]
-- A SAS authenticates in the query, not in a header.
#guard staticAuthHeaders (.azureSas "sv=1&sig=x") == some []
#guard credentialQuery (.azureSas "sv=1&sig=x") == "sv=1&sig=x"
#guard credentialQuery (.bearer "t") == ""
-- S3 is signed per request, not a static header.
#guard staticAuthHeaders (.s3 "fr-par" "k" "s") == none

-- Presence is carried in the value consumed by the actual HTTP builder.
example (headers : List (String × String)) :
    ("user-agent", "typednotes-liaison") ∈ (NativeHeaders.ofList headers).values ∨
      hasUserAgent (NativeHeaders.ofList headers).values = true :=
  (NativeHeaders.ofList headers).userAgentPresent

#guard (NativeHeaders.ofList []).values == [("user-agent", "typednotes-liaison")]
#guard (NativeHeaders.ofList [("accept", "application/json")]).values ==
  [("user-agent", "typednotes-liaison"), ("accept", "application/json")]
#guard (NativeHeaders.ofList [("User-Agent", "typednotes-lode"), ("authorization", "Bearer fixture")]).values ==
  [("User-Agent", "typednotes-lode"), ("authorization", "Bearer fixture")]
#guard (NativeHeaders.ofList [("USER-AGENT", " \t"), ("accept", "application/json")]).values ==
  [("user-agent", "typednotes-liaison"), ("accept", "application/json")]
#guard (NativeHeaders.ofList [("user-agent", "")]).values == [("user-agent", "typednotes-liaison")]

end LiaisonTests.Liaison.Egress.Provider
