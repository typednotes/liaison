/-
  Liaison.Auth — the `Authorized` witness and the `authorize` check.

  Ported from `broker.md` §5: verify the tag first, then decide
  `w.permits r`.
-/

import Liaison.Warrant.Tag

namespace Liaison

/-- A usable execution warrant must explicitly bind every authority dimension.
    A valid HMAC on an empty/incomplete caveat list is not execution authority. -/
def Warrant.executionBound (w : Warrant) : Bool :=
  w.caveats.any (fun c => match c with | .capability .. => true | _ => false) &&
  w.caveats.any (fun c => match c with | .resource .. => true | _ => false) &&
  w.caveats.any (fun c => match c with | .runId .. => true | _ => false) &&
  w.caveats.any (fun c => match c with | .expiresAt .. => true | _ => false) &&
  w.caveats.any (fun c => match c with | .budget .. => true | _ => false)

/-- Authority to perform exactly `r`. No public constructor: the only route
    in is `authorize`. -/
structure Authorized (r : Request) where
  private mk ::
  warrant   : Warrant
  tagOk     : VerifiedTag warrant
  permitted : warrant.permits r
  orgBound  : r.orgId = warrant.orgId
  executionBound : warrant.executionBound = true

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
    if ho : r.orgId = w.orgId then
      if h : w.permits r then
        if hb : w.executionBound = true then return .ok ⟨w, tagOk, h, ho, hb⟩
        else return .error .malformedWarrant
      else
        return .error (diagnoseDenial w r)
    else return .error .resourceDenied

end Liaison
