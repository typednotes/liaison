/-
  Liaison.Warrant.Tag — the macaroon-style HMAC-SHA256 chain that makes a
  `Warrant` unforgeable and its attenuation irreversible.

  Not given verbatim by `broker.md` — that document specifies the chain
  algebraically (§3):

    s₀  = HMAC(rootKey, id)          -- minting, in core
    sᵢ  = HMAC(sᵢ₋₁, caveatᵢ)        -- attenuation, needs no key
    tag = sₙ

  This module is the concrete Lean implementation against `linen`'s real
  HMAC surface, `Crypto.JOSE.FFI.hmac key data algorithm` (`algorithm := 0`
  selects SHA-256) — the same calling convention `Linen.Crypto.SigV4.hmacSha256`
  uses, copied here rather than re-derived.
-/

import Liaison.Warrant.Core
import Linen.Crypto.JOSE.FFI
import Linen.Data.Hex

namespace Liaison

/-- HMAC-SHA256 via `linen`'s JOSE FFI. `0` selects SHA-256 in the FFI's
    algorithm encoding (mirrors `Linen.Crypto.SigV4.hmacSha256`). -/
def hmacSha256 (key data : ByteArray) : IO ByteArray :=
  Crypto.JOSE.FFI.hmac key data 0

-- ── Root key ─────────────────────────────────────────────────────────

/-- The symmetric key `core` (once it exists) uses to mint a warrant's first
    HMAC link (`s₀`). `liaison` never mints; it only recomputes `s₀` to
    verify a warrant's tag, so it needs the same key, shared out of band
    (an env var here, since no secret-distribution mechanism between `core`
    and `liaison` exists yet). No public constructor: the only way to obtain
    a `RootKey` is `RootKey.fromEnv`, which fails loudly rather than falling
    back to a default key. -/
structure RootKey where
  private mk ::
  bytes : ByteArray

/-- Load the root key from `LIAISON_ROOT_KEY`, hex-encoded. Fails loudly
    (never a default/fallback key) if the variable is unset, empty, or not
    valid hex. -/
def RootKey.fromEnv (var : String := "LIAISON_ROOT_KEY") : IO RootKey := do
  match ← IO.getEnv var with
  | none => throw <| IO.userError s!"{var} is not set — refusing to start with no root key"
  | some hex =>
    if hex.isEmpty then
      throw <| IO.userError s!"{var} is empty — refusing to start with no root key"
    match Data.Hex.decode hex with
    | none => throw <| IO.userError s!"{var} is not valid hex"
    | some bytes =>
      if bytes.size == 0 then
        throw <| IO.userError s!"{var} decoded to zero bytes — refusing to start with no root key"
      return { bytes }

-- ── Deterministic caveat encoding ────────────────────────────────────

private def u64Bytes (n : UInt64) : ByteArray :=
  ByteArray.mk #[
    (n >>> 56).toUInt8, (n >>> 48).toUInt8, (n >>> 40).toUInt8, (n >>> 32).toUInt8,
    (n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]

/-- Length-prefix a string's UTF-8 bytes so concatenated fields cannot be
    confused with each other (`("ab", "c")` vs `("a", "bc")`) — required for
    the encoding below to be injective-enough to use as HMAC input. -/
private def lenPrefixed (s : String) : ByteArray :=
  u64Bytes s.toUTF8.size.toUInt64 ++ s.toUTF8

/-- A deterministic byte encoding of a `Caveat`, used as HMAC input for
    attenuation. **Not `Repr`'s output** — `Repr` is for debugging and is not
    a security contract; changing its format must never change a warrant's
    tag. Each variant is tagged with a distinct leading byte so the encoding
    cannot collide across constructors, and every field is length-prefixed
    (`lenPrefixed`) so it cannot collide within one. Adding a new `Caveat`
    constructor requires adding a case here with a fresh tag byte. -/
def Caveat.toBytes : Caveat → ByteArray
  | .expiresAt t    => ByteArray.mk #[0] ++ u64Bytes t
  | .capability p a => ByteArray.mk #[1] ++ lenPrefixed p.value ++ lenPrefixed a.value
  | .resource id    => ByteArray.mk #[2] ++ lenPrefixed id.value
  | .budget c       => ByteArray.mk #[3] ++ u64Bytes c.toUInt64
  | .runId rid      => ByteArray.mk #[4] ++ lenPrefixed rid.value

/-- The bytes `s₀ = HMAC(rootKey, id)` is computed over: the warrant id and
    the bound `orgId`, both length-prefixed. Binding `orgId` here (not just
    at authorization time) is what makes the `Warrant.orgId` deviation from
    `broker.md` actually load-bearing — an attacker cannot re-attach a
    different `orgId` to a warrant without invalidating its tag. -/
private def mintingInput (id : WarrantId) (orgId : OrgId) : ByteArray :=
  lenPrefixed id.value ++ lenPrefixed orgId.value

/-- Recompute the HMAC chain for a warrant id/org and a caveat list, folding
    forward **in minting order**. `Warrant.attenuate` prepends new caveats
    (so the most recently added caveat is at the head of `caveats`), which
    means minting order is `caveats.reverse` — this ordering is the single
    highest-risk detail in this module; see `LiaisonTests/Liaison/Warrant/TagTest.lean`
    for the hand-computed multi-step round trip that pins it down. -/
def recomputeTag (rootKey : RootKey) (id : WarrantId) (orgId : OrgId)
    (caveats : List Caveat) : IO ByteArray := do
  let s0 ← hmacSha256 rootKey.bytes (mintingInput id orgId)
  caveats.reverse.foldlM (fun s c => hmacSha256 s c.toBytes) s0

/-- Mint a fresh warrant's tag (`caveatsInMintingOrder` given in minting
    order — the order the caveats are actually folded in, first-applied
    first — not `Warrant.caveats`'s attenuate order; callers construct the
    `Warrant.caveats` list as `caveatsInMintingOrder.reverse` to match
    `attenuate`'s prepend convention). `liaison` does not mint warrants in
    v0 (that is `core`'s job once it exists); this function exists so
    `RootKey`-holding tests and tooling can construct fixtures without
    duplicating `recomputeTag`'s logic.

    **Must pre-reverse before delegating to `recomputeTag`**:
    `recomputeTag`'s own `caveats` parameter is in attenuate order (it
    reverses internally to recover minting order — see its doc comment),
    so passing `caveatsInMintingOrder` straight through would fold it
    backwards. `LiaisonTests/Liaison/Warrant/TagTest.lean`'s multi-attenuation
    round trip caught this the first time this function was written
    without the `.reverse` below. -/
def mintTag (rootKey : RootKey) (id : WarrantId) (orgId : OrgId)
    (caveatsInMintingOrder : List Caveat) : IO ByteArray :=
  recomputeTag rootKey id orgId caveatsInMintingOrder.reverse

-- ── Verification ─────────────────────────────────────────────────────

/-- Witness that a warrant's tag was recomputed from `rootKey` and matches.
    No public constructor: the only route in is `verifyTag`. -/
structure VerifiedTag (w : Warrant) where
  private mk ::

/-- Recompute the HMAC chain and compare to `w.tag`.

    **Not constant-time.** The comparison below is `ByteArray`'s ordinary
    `==`. `linen`'s own HMAC verifier
    (`Crypto.JOSE.JWS.verifySignature`, for `HS256`/`HS384`/`HS512`) does the
    same plain `==` compare — there is no `CRYPTO_memcmp`-equivalent exposed
    anywhere in `Crypto.JOSE.FFI` to reuse, confirmed by reading that module.
    Per `proof-strategy.md`'s "never provable in Lean" table, constant-time
    execution is a Tier-6 concern out of scope for v0, not a shortcut taken
    here — `liaison` is exactly as timing-safe as `linen`'s own JOSE
    verifier, no more and no less. -/
def verifyTag (rootKey : RootKey) (w : Warrant) : IO (Option (VerifiedTag w)) := do
  let expected ← recomputeTag rootKey w.id w.orgId w.caveats
  if expected == w.tag then
    return some ⟨⟩
  else
    return none

end Liaison
