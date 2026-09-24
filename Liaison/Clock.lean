/-
  Liaison.Clock — `liaison`'s own wall clock.

  Lean core's `IO.monoNanosNow` is monotonic (arbitrary epoch), not calendar
  time. `linen`'s `Data.Time.getCurrentTime` reads `Std.Time.Timestamp.now`,
  a genuine POSIX-epoch wall-clock reading, so no FFI is needed.

  Used for the things `liaison` decides on its own authority — a Google
  token's `expires_at`, the vault token's expiry, and the SigV4 timestamp —
  never for warrant expiry, which is still checked against the caller's
  `now` (`docs/connections.md` §9 names that gap).
-/

import Linen.Data.Time.Clock

namespace Liaison

/-- The current wall-clock time, in whole Unix seconds. -/
def nowUnixSeconds : IO Nat := do
  let t ← Data.Time.getCurrentTime
  return t.nanosSinceEpoch / 1000000000

end Liaison
