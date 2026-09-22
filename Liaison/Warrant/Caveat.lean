/-
  Liaison.Warrant.Caveat — the closed caveat vocabulary and the parsed,
  trusted request it is checked against.

  Ported from `typednotes/typednotes`'s `docs/services/broker.md` §4-§5,
  essentially verbatim.
-/

namespace Liaison

-- ── Identifiers ──────────────────────────────────────────────────────
--
-- Thin `DecidableEq`/`Repr` wrappers around `String` (textual UUIDs). None
-- of these carry a proof obligation — they exist so `ResourceId`, `RunId`,
-- `WarrantId` and `OrgId` cannot be silently substituted for one another at
-- a call site, not to validate UUID syntax.

structure ResourceId where
  value : String
  deriving DecidableEq, Repr

structure RunId where
  value : String
  deriving DecidableEq, Repr

structure WarrantId where
  value : String
  deriving DecidableEq, Repr

/-- The organization a warrant's spend authority is bound to. Not present in
    `broker.md`'s literal `Warrant` type — see the doc-comment on
    `Liaison.Warrant.Core.Warrant` for why it was added here. -/
structure OrgId where
  value : String
  deriving DecidableEq, Repr

/-- A third-party provider a warrant may grant capability over
    (`"notion"`, `"github"`, ...). -/
structure Provider where
  value : String
  deriving DecidableEq, Repr

/-- An action on a `Provider` (`"read"`, `"write"`, ...). -/
structure Action where
  value : String
  deriving DecidableEq, Repr

/-- `Credits := Nat` mirrors `ledger.md` §5's `Credits := Nat` exactly — a
    negative balance is unrepresentable by construction. `liaison` does not
    depend on the (not-yet-implemented) `ledger` service as a Lean library;
    this is a local mirror of its type that must be kept in sync by hand
    until a shared library exists. -/
abbrev Credits := Nat

-- ── Caveat ───────────────────────────────────────────────────────────

/-- A closed inductive of every restriction a warrant may carry. Closed, so
    no unrecognised caveat can be constructed and silently ignored — the
    classic policy-engine failure `broker.md` §6 calls out. No new
    constructors should be added without re-reading `Warrant.permits` and
    `Caveat.toBytes` (`Liaison/Warrant/Tag.lean`) together. -/
inductive Caveat
  | expiresAt  : UInt64            → Caveat
  | capability : Provider → Action → Caveat
  | resource   : ResourceId        → Caveat
  | budget     : Credits           → Caveat
  | runId      : RunId             → Caveat
  deriving DecidableEq, Repr

/-- The parsed, trusted inbound call a warrant is checked against. Only ever
    constructed at the `Server.lean` boundary (parse, don't validate) — every
    other module receives a `Request` as a given, never builds one from raw
    input itself. -/
structure Request where
  now      : UInt64
  provider : Provider
  action   : Action
  resource : ResourceId
  cost     : Credits
  runId    : RunId
  orgId    : OrgId
  deriving DecidableEq, Repr

/-- Every way `authorize`/`withReservation` can refuse a request. -/
inductive Denial
  /-- A caveat that failed `Caveat.permits`: expiry. -/
  | expired
  /-- A caveat that failed `Caveat.permits`: provider/action capability. -/
  | capabilityDenied
  /-- A caveat that failed `Caveat.permits`: resource membership. -/
  | resourceDenied
  /-- A caveat that failed `Caveat.permits`: the warrant's own budget cap
      (Tier 1 — a property of the warrant, not of the org's balance). -/
  | budgetExceeded
  /-- The org's Postgres-tracked balance could not cover the hold (Tier 4 —
      distinct from `budgetExceeded`, which is about the warrant's own cap). -/
  | budgetUnavailable
  /-- A caveat that failed `Caveat.permits`: run binding. -/
  | wrongRun
  /-- The HMAC tag did not recompute to match `warrant.tag`. -/
  | tagInvalid
  /-- The warrant could not be parsed from the request. -/
  | malformedWarrant
  /-- `callInference` is not implemented in this build (v0 loud stub — see
      `Liaison/Egress/Provider.lean`). -/
  | inferenceNotImplemented
  deriving DecidableEq, Repr

/-- $$\text{Caveat.permits} : \text{Caveat} \to \text{Request} \to \text{Prop}$$
    Ported from `broker.md` §4 verbatim. -/
def Caveat.permits : Caveat → Request → Prop
  | .expiresAt t,    r => r.now < t
  | .capability p a, r => r.provider = p ∧ r.action = a
  | .resource id,    r => r.resource = id
  | .budget c,       r => r.cost ≤ c
  | .runId rid,      r => r.runId = rid

instance (c : Caveat) (r : Request) : Decidable (c.permits r) := by
  cases c <;> unfold Caveat.permits <;> infer_instance

end Liaison
