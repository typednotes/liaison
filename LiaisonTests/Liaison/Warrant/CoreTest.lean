/-
  Tests for `Liaison.Warrant.Core`.

  `Warrant.permits`/`attenuate` are pure (the tag itself is opaque bytes
  here — `Tag.lean`'s HMAC chain is exercised separately in `TagTest.lean`),
  so this file, like `CaveatTest.lean`, is `#guard`-only.
-/
import Liaison.Warrant.Core

open Liaison

namespace LiaisonTests.Liaison.Warrant.Core

private def req : Request :=
  { now := 100, provider := ⟨"notion"⟩, action := ⟨"read"⟩
    resource := ⟨"doc-1"⟩, cost := 5, runId := ⟨"run-1"⟩, orgId := ⟨"org-1"⟩ }

private def w : Warrant :=
  { id := ⟨"w1"⟩, orgId := ⟨"org-1"⟩
    caveats := [Caveat.expiresAt 200, Caveat.capability ⟨"notion"⟩ ⟨"read"⟩]
    tag := ByteArray.mk #[] }

-- ── `permits` is the conjunction of every caveat ─────────────────────
#guard decide (w.permits req)
#guard !decide ((w.attenuate (Caveat.resource ⟨"doc-2"⟩) (ByteArray.mk #[9])).permits req)

-- ── `attenuate` only ever prepends — never drops or reorders ─────────
private def w' := w.attenuate (Caveat.budget 10) (ByteArray.mk #[1])
#guard decide (w'.caveats = (Caveat.budget 10) :: w.caveats)
#guard w'.caveats.length == w.caveats.length + 1
#guard w'.tag == ByteArray.mk #[1]

-- Attenuating with a caveat the request still satisfies keeps `permits`.
#guard decide (w'.permits req)

-- Attenuating with a caveat the request violates narrows `permits` to deny,
-- without touching any caveat already present.
private def w'' := w.attenuate (Caveat.budget 1) (ByteArray.mk #[2])
#guard !decide (w''.permits req)
#guard decide (w.permits req)  -- the original `w` is untouched (no mutation)

-- ── `attenuate_monotone`: pins the theorem's statement, not just its proof ──
example (r : Request) :
    (w.attenuate (Caveat.budget 1) (ByteArray.mk #[2])).permits r → w.permits r :=
  Warrant.attenuate_monotone w (Caveat.budget 1) (ByteArray.mk #[2]) r

end LiaisonTests.Liaison.Warrant.Core
