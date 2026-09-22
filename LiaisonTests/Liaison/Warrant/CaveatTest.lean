/-
  Tests for `Liaison.Warrant.Caveat`.

  Every case here is pure (`Caveat.permits` is a `Prop` with a `Decidable`
  instance, so `decide` reduces at elaboration time) — no IO, no FFI,
  matching linen's own `#guard`-on-pure-values convention
  (`Tests/Linen/Database/SQL/StatementTest.lean`).
-/
import Liaison.Warrant.Caveat

open Liaison

namespace LiaisonTests.Liaison.Warrant.Caveat

private def req : Request :=
  { now := 100, provider := ⟨"notion"⟩, action := ⟨"read"⟩
    resource := ⟨"doc-1"⟩, cost := 5, runId := ⟨"run-1"⟩, orgId := ⟨"org-1"⟩ }

-- ── expiresAt: strict `<`, not `≤` ───────────────────────────────────
#guard decide ((Caveat.expiresAt 200).permits req)
#guard !decide ((Caveat.expiresAt 100).permits req)  -- now == t is already expired
#guard !decide ((Caveat.expiresAt 50).permits req)

-- ── capability: both provider and action must match ─────────────────
#guard decide ((Caveat.capability ⟨"notion"⟩ ⟨"read"⟩).permits req)
#guard !decide ((Caveat.capability ⟨"notion"⟩ ⟨"write"⟩).permits req)
#guard !decide ((Caveat.capability ⟨"github"⟩ ⟨"read"⟩).permits req)
#guard !decide ((Caveat.capability ⟨"github"⟩ ⟨"write"⟩).permits req)

-- ── resource: exact id match ─────────────────────────────────────────
#guard decide ((Caveat.resource ⟨"doc-1"⟩).permits req)
#guard !decide ((Caveat.resource ⟨"doc-2"⟩).permits req)

-- ── budget: `cost ≤ c`, so exact equality is permitted ───────────────
#guard decide ((Caveat.budget 5).permits req)
#guard decide ((Caveat.budget 100).permits req)
#guard !decide ((Caveat.budget 4).permits req)
#guard !decide ((Caveat.budget 0).permits req)

-- ── runId: exact match ────────────────────────────────────────────────
#guard decide ((Caveat.runId ⟨"run-1"⟩).permits req)
#guard !decide ((Caveat.runId ⟨"run-2"⟩).permits req)

end LiaisonTests.Liaison.Warrant.Caveat
