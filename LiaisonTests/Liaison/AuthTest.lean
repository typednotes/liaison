/-
  Tests for `Liaison.Auth` — `authorize`'s tag check and its per-caveat
  denial diagnosis.

  **Requires `LIAISON_ROOT_KEY` in the environment**, for the same reason
  as `LiaisonTests/Liaison/Warrant/TagTest.lean` (`RootKey.fromEnv` is the only
  constructor). Exercised via `#eval`, same rationale as that file.
-/
import Liaison.Auth

open Liaison

namespace LiaisonTests.Liaison.Auth

private def check (b : Bool) (msg : String) : IO Unit :=
  unless b do throw (IO.userError msg)

private def wid : WarrantId := ⟨"w-auth-1"⟩
private def org : OrgId := ⟨"org-auth-1"⟩

/-- Build a single-caveat warrant with a correctly-minted tag, so every
    denial case below fails on exactly the one caveat under test — never
    on `.tagInvalid`. -/
private def warrantWith (rootKey : RootKey) (c : Caveat) : IO Warrant := do
  let tag ← mintTag rootKey wid org [c]
  return { id := wid, orgId := org, caveats := [c], tag }

private def baseReq : Request :=
  { now := 100, provider := ⟨"notion"⟩, action := ⟨"read"⟩
    resource := ⟨"doc-1"⟩, cost := 5, runId := ⟨"run-1"⟩, orgId := ⟨"org-auth-1"⟩ }

#eval show IO Unit from do
  let rootKey ← RootKey.fromEnv

  -- ── Success: every caveat present, request satisfies all of them ────
  let successCaveats :=
    [ Caveat.expiresAt 1000
    , Caveat.capability ⟨"notion"⟩ ⟨"read"⟩
    , Caveat.resource ⟨"doc-1"⟩
    , Caveat.budget 100
    , Caveat.runId ⟨"run-1"⟩ ]
  let tag ← mintTag rootKey wid org successCaveats
  -- `mintTag`'s argument is in minting order; `Warrant.caveats` is stored in
  -- attenuate order (head = most recently added), i.e. `successCaveats.reverse`
  -- (`Tag.lean`'s `mintTag`/`recomputeTag` doc comments).
  let goodWarrant : Warrant :=
    { id := wid, orgId := org, caveats := successCaveats.reverse, tag }
  match ← authorize rootKey goodWarrant baseReq with
  | .error _ => throw (IO.userError "expected authorize to succeed on a matching request")
  | .ok _ => pure ()

  -- ── `.tagInvalid`: same warrant, tampered tag ────────────────────────
  let badTag : ByteArray :=
    match tag.data[0]? with
    | none => tag
    | some b0 => ByteArray.mk (tag.data.set! 0 (if b0 == 0 then 1 else 0))
  let badTagWarrant := { goodWarrant with tag := badTag }
  match ← authorize rootKey badTagWarrant baseReq with
  | .error .tagInvalid => pure ()
  | .error _ => throw (IO.userError "expected .tagInvalid, got some other denial")
  | .ok _ => throw (IO.userError "expected a tampered tag to be denied")

  -- ── Per-caveat denial diagnosis: one caveat, one specific violation ──
  let expiredWarrant ← warrantWith rootKey (Caveat.expiresAt 50)
  match ← authorize rootKey expiredWarrant baseReq with
  | .error .expired => pure ()
  | _ => throw (IO.userError "expected .expired")

  let wrongCapWarrant ← warrantWith rootKey (Caveat.capability ⟨"notion"⟩ ⟨"write"⟩)
  match ← authorize rootKey wrongCapWarrant baseReq with
  | .error .capabilityDenied => pure ()
  | _ => throw (IO.userError "expected .capabilityDenied")

  let wrongResourceWarrant ← warrantWith rootKey (Caveat.resource ⟨"doc-2"⟩)
  match ← authorize rootKey wrongResourceWarrant baseReq with
  | .error .resourceDenied => pure ()
  | _ => throw (IO.userError "expected .resourceDenied")

  let overBudgetWarrant ← warrantWith rootKey (Caveat.budget 1)
  match ← authorize rootKey overBudgetWarrant baseReq with
  | .error .budgetExceeded => pure ()
  | _ => throw (IO.userError "expected .budgetExceeded")

  let wrongRunWarrant ← warrantWith rootKey (Caveat.runId ⟨"run-2"⟩)
  match ← authorize rootKey wrongRunWarrant baseReq with
  | .error .wrongRun => pure ()
  | _ => throw (IO.userError "expected .wrongRun")

  IO.println "AuthTest: ok"

end LiaisonTests.Liaison.Auth
