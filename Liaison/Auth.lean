/-
  Liaison.Auth — the `Authorized` witness and the `authorize` check.

  Ported from `broker.md` §5: verify the tag first, then decide
  `w.permits r`.
-/

import Liaison.Warrant.Tag

namespace Liaison

/-- Authority to perform exactly `r`. No public constructor: the only route
    in is `authorize`. -/
structure Authorized (r : Request) where
  private mk ::
  warrant   : Warrant
  tagOk     : VerifiedTag warrant
  permitted : warrant.permits r

/-- Best-effort diagnosis of *which* caveat failed, for a nicer audit-log
    entry. This is a **diagnostic only** — it never gates access. The actual
    gate is `decide (w.permits r)` in `authorize` below; this function is
    only ever called after that gate has already denied, to pick a `Denial`
    variant to record. Kept in its own function, separate from `authorize`,
    so it can never accidentally become the real check. -/
private def diagnoseDenial (w : Warrant) (r : Request) : Denial :=
  let failing := w.caveats.find? (fun c => ¬ decide (c.permits r))
  match failing with
  | some (.expiresAt _)    => .expired
  | some (.capability _ _) => .capabilityDenied
  | some (.resource _)     => .resourceDenied
  | some (.budget _)       => .budgetExceeded
  | some (.runId _)        => .wrongRun
  | none                   => .malformedWarrant  -- unreachable: permits held for every caveat

/-- Verify a warrant's HMAC tag, then check it permits `r`. Denies with
    `.tagInvalid` before ever inspecting caveats — an unverified warrant's
    caveats are not trustworthy input. -/
def authorize (rootKey : RootKey) (w : Warrant) (r : Request)
    : IO (Except Denial (Authorized r)) := do
  match ← verifyTag rootKey w with
  | none => return .error .tagInvalid
  | some tagOk =>
    if h : w.permits r then
      return .ok ⟨w, tagOk, h⟩
    else
      return .error (diagnoseDenial w r)

end Liaison
