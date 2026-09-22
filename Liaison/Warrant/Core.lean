/-
  Liaison.Warrant.Core — the `Warrant` type, `permits`, `attenuate`, and the
  `attenuate_monotone` theorem.

  Ported from `typednotes/typednotes`'s `docs/services/broker.md` §5-§6.
-/

import Liaison.Warrant.Caveat

namespace Liaison

/-- Authority to perform some bounded set of requests, carried as an HMAC
    macaroon chain (`Liaison/Warrant/Tag.lean` mints and verifies `tag`).

    **Deviation from `broker.md`'s literal `Warrant` type:** this adds
    `orgId : OrgId`, bound into the HMAC chain by `Tag.mintTag`/
    `Tag.recomputeTag`. `broker.md`'s `Warrant` has no `orgId` field — the
    field was added here, per the approved plan, to close a gap that would
    otherwise leave the Postgres budget hold's `org_id` column
    (`ledger.md` §4) unauthenticated: without a warrant-carried `orgId`,
    nothing would stop a request from spending against an org it was never
    scoped to. `core.md` describes `Warrant` as a type meant to be shared
    across services once `core` (identity/warrant-minting) exists; when it
    does, this field should be reconciled against `core`'s own definition
    rather than assumed to already match. -/
structure Warrant where
  id      : WarrantId
  orgId   : OrgId
  caveats : List Caveat
  tag     : ByteArray

/-- $$\text{Warrant.permits} : \text{Warrant} \to \text{Request} \to \text{Prop}$$
    A warrant denotes the set of requests every one of its caveats permits —
    attenuation is intersection. Ported from `broker.md` §5 verbatim. -/
def Warrant.permits (w : Warrant) (r : Request) : Prop :=
  ∀ c ∈ w.caveats, c.permits r

instance (w : Warrant) (r : Request) : Decidable (w.permits r) :=
  List.decidableBAll (fun c : Caveat => c.permits r) w.caveats

/-- Attenuate a warrant by prepending a new caveat and replacing its tag with
    the freshly-folded `tag'` (computed by `Tag.mintTag`/`Tag.recomputeTag`
    over the new caveat list — `attenuate` itself does not touch the HMAC,
    it only records the result). This is the only way to *extend* a warrant
    from Lean code. `Warrant`'s constructor is not private — `Server.lean` is
    the trusted parse boundary and must build a `Warrant` directly from wire
    bytes (id/orgId/caveats/tag), before that tag has been checked by
    anything. That constructed value carries no authority on its own: nothing
    downstream of `Server.lean` accepts a bare `Warrant`, only an
    `Authorized r` obtained from `Auth.authorize`, which calls
    `Tag.verifyTag` first. -/
def Warrant.attenuate (w : Warrant) (c : Caveat) (tag' : ByteArray) : Warrant :=
  { w with caveats := c :: w.caveats, tag := tag' }

/-- The security property of delegation: attenuating a warrant can only
    narrow what it permits, never widen it. Ported from `broker.md` §6
    verbatim — the proof is a one-line consequence of `attenuate` only
    prepending to `caveats`. An agent, or a hijacked sub-tool, cannot widen
    a warrant not because we check, but because no constructor widens. -/
theorem Warrant.attenuate_monotone (w : Warrant) (c : Caveat) (tag' : ByteArray) (r : Request)
    : (w.attenuate c tag').permits r → w.permits r := by
  intro h c' hc'; exact h c' (List.mem_cons_of_mem _ hc')

end Liaison
