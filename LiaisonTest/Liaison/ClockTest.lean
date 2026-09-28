/-
  Tests for `Liaison.Clock`: the wall clock is calendar time (Unix seconds),
  not the monotonic clock — a reading must be after 2025-01-01 and before
  2100-01-01.
-/
import Liaison.Clock

namespace LiaisonTests.Liaison.Clock

#eval show IO Unit from do
  let now ← Liaison.nowUnixSeconds
  unless 1735689600 < now && now < 4102444800 do
    throw (IO.userError s!"nowUnixSeconds is not Unix time: {now}")

end LiaisonTests.Liaison.Clock
