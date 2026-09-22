/-
  Tests for `Liaison.Warrant.Tag` — the HMAC chain's multi-attenuation
  round trip.

  **Requires `LIAISON_ROOT_KEY` in the environment to run.** `RootKey`'s
  only constructor is `RootKey.fromEnv` — deliberately no test-only
  backdoor, matching `Tag.lean`'s "no default/fallback key" design.
  linen's own `Tests/Linen/Cloud/CredentialsTest.lean` notes exactly this
  limit: "Lean has no `setenv`", so an env-sourced value cannot be driven
  end to end from *inside* a `#eval`. The fix used there and here is the
  same: set the variable in the shell that invokes the build, e.g.

    LIAISON_ROOT_KEY=$(openssl rand -hex 32) lake build LiaisonTests

  (see `AGENTS.md`'s "Running tests" section). Every HMAC call below is a
  live OpenSSL FFI operation in `IO`, so — like
  `Tests/Linen/Crypto/SigV4Test.lean` — it is exercised with `#eval` and a
  `check` helper that throws on failure, since a thrown error fails the
  build; there is no deterministic `#guard` for FFI-bound code.
-/
import Liaison.Warrant.Tag

open Liaison

namespace LiaisonTests.Liaison.Warrant.Tag

private def check (b : Bool) (msg : String) : IO Unit :=
  unless b do throw (IO.userError msg)

private def wid : WarrantId := ⟨"w-test-1"⟩
private def org : OrgId := ⟨"org-test-1"⟩

/-- Flips the first byte of a tag to a value guaranteed different, without
    relying on `ByteArray`'s bitwise operators (whose availability we did
    not want to depend on here). Used to simulate a forged/corrupted tag. -/
private def flipFirstByte (b : ByteArray) : ByteArray :=
  match b.data[0]? with
  | none => b
  | some byte0 =>
    let byte0' : UInt8 := if byte0 == 0 then 1 else 0
    ByteArray.mk (b.data.set! 0 byte0')

#eval show IO Unit from do
  let rootKey ← RootKey.fromEnv

  -- Mint order: `[c1, c2, c3]` means `s0 -HMAC(c1)-> s1 -HMAC(c2)-> s2
  -- -HMAC(c3)-> s3`. `Warrant.attenuate` prepends, so the *stored*
  -- `caveats` list is the reverse of minting order (`Tag.lean`'s
  -- `recomputeTag` doc-comment) — `w0.caveats` below is `[c3, c2, c1]`.
  let c1 := Caveat.expiresAt 1000
  let c2 := Caveat.capability ⟨"notion"⟩ ⟨"read"⟩
  let c3 := Caveat.budget 100
  let tag0 ← mintTag rootKey wid org [c1, c2, c3]
  let w0 : Warrant := { id := wid, orgId := org, caveats := [c3, c2, c1], tag := tag0 }
  match ← verifyTag rootKey w0 with
  | none => throw (IO.userError "freshly minted warrant failed to verify")
  | some _ => pure ()

  -- Attenuate three times in a row, each time recomputing the tag over the
  -- new head-prepended caveat list (exactly what `Server.lean`/a future
  -- `core` client is expected to do around `Warrant.attenuate`).
  let c4 := Caveat.resource ⟨"doc-1"⟩
  let tag1 ← recomputeTag rootKey wid org (c4 :: w0.caveats)
  let w1 := w0.attenuate c4 tag1
  check (← verifyTag rootKey w1).isSome "warrant failed to verify after 1st attenuation"

  let c5 := Caveat.runId ⟨"run-1"⟩
  let tag2 ← recomputeTag rootKey wid org (c5 :: w1.caveats)
  let w2 := w1.attenuate c5 tag2
  check (← verifyTag rootKey w2).isSome "warrant failed to verify after 2nd attenuation"

  let c6 := Caveat.expiresAt 500
  let tag3 ← recomputeTag rootKey wid org (c6 :: w2.caveats)
  let w3 := w2.attenuate c6 tag3
  check (← verifyTag rootKey w3).isSome "warrant failed to verify after 3rd attenuation"
  check (w3.caveats.length == 6) "expected 6 caveats after 3 attenuations of a 3-caveat mint"

  -- ── Tamper 1: flip a byte of the final tag ─────────────────────────
  let wBadTag := { w3 with tag := flipFirstByte w3.tag }
  check (← verifyTag rootKey wBadTag).isNone "tampered tag byte incorrectly verified"

  -- ── Tamper 2: splice in an extra caveat without recomputing the tag ──
  -- Simulates an attacker who can edit the wire bytes but does not hold
  -- `rootKey` — they can lengthen `caveats` but cannot produce a `tag`
  -- that folds over the new list.
  let wExtraCaveat := { w3 with caveats := Caveat.budget 1000000 :: w3.caveats }
  check (← verifyTag rootKey wExtraCaveat).isNone
    "warrant with an un-recomputed appended caveat incorrectly verified"

  -- ── Tamper 3: swap the orgId, keeping the old tag ──────────────────
  -- Pins down the load-bearing deviation from `broker.md`: `orgId` is
  -- folded into `s0` (`Tag.lean`'s `mintingInput`), so re-attaching a
  -- warrant to a different org invalidates its tag.
  let wOtherOrg := { w3 with orgId := ⟨"org-evil"⟩ }
  check (← verifyTag rootKey wOtherOrg).isNone
    "warrant re-attached to a different orgId incorrectly verified"

  IO.println "TagTest: ok"
