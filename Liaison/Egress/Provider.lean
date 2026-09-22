/-
  Liaison.Egress.Provider — the only functions that can make an outbound
  call.

  `callProvider` and `callInference` both take a `Reserved r`, and there is
  no other way to obtain one (`Liaison.Budget.Reserved` has no public
  constructor other than `withReservation`). This is the chokepoint
  property `broker.md` §6 describes as "held by typing rather than by
  review" — no outbound call is reachable without a verified warrant and a
  reserved budget.
-/

import Liaison.Budget
import Liaison.Egress.Secrets
import Linen.Network.HTTP.Simple

namespace Liaison.Egress

open Network.HTTP.Client
open Network.HTTP.Types
open Network.HTTP.Simple
open Liaison (Reserved Response Denial)

/-- A generic third-party HTTP envelope: fetch the credential, make one call,
    return the response. No per-provider (Baseten/Mistral/Scaleway) request
    shaping — that is Phase 2 (`Liaison/Egress/Inference/*.lean`, see
    `AGENTS.md`). The fetched credential is used to build the outbound
    request here and is **never** returned — `Credential` has no `Repr`/
    `ToString` instance and this function's return type carries only a
    `Liaison.Response`, so there is no path for the credential to leak
    into `Server.lean`'s response or the audit log. -/
def callProvider {r : Liaison.Request} (secretsCfg : SecretsConfig) (account : String)
    (target : Network.HTTP.Client.Request) (_reserved : Reserved r)
    : IO (Except Denial (Response × Liaison.Credits)) := do
  match ← fetchCredential secretsCfg r.provider account with
  | none => throw <| IO.userError s!"no credential for provider {r.provider.value}"
  | some cred =>
    match cred.token with
    | none => throw <| IO.userError s!"credential for provider {r.provider.value} has no usable token"
    | some tok =>
      let req := { target with headers := (hAuthorization, s!"Bearer {tok}") :: target.headers }
      let resp ← httpBS req
      let out : Response :=
        { status := resp.statusCode.statusCode.toUInt16
          headers := resp.headers.map (fun (n, v) => (toString n, v))
          body := resp.body }
      -- v0 charges the warrant's full authorized cost regardless of what the
      -- call actually consumed — no per-call cost model exists yet for
      -- generic HTTP egress (unlike inference, there is no token count to
      -- meter on). Named in `AGENTS.md`'s "Not yet implemented" list.
      return .ok (out, r.cost)

/-- **Loud, structured-denial stub.** Inference routing (`broker.md` §8:
    "where does inference routing live") is explicitly out of scope for v0.
    This function type-checks, is wired into `Server.lean`'s routing, and
    unconditionally denies — never a silent success, never a bare
    `sorry`/`panic!`. `LiaisonTests/Liaison/Egress/ProviderTest.lean` pins its
    type and documents (by inspection, not by test — see that file) that it
    never returns `.ok`. -/
def callInference {r : Liaison.Request} (_reserved : Reserved r)
    : IO (Except Denial (Response × Liaison.Credits)) :=
  return .error .inferenceNotImplemented

end Liaison.Egress
