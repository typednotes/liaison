/-
  Tests for `Liaison.Audit`.

  Pins `recordAttemptStmt`'s literal SQL text and its encoder's column
  count, per `Audit.lean`'s own comment pointing at this file. `denialText`
  is `private` to `Audit.lean` and so cannot be exercised directly from
  here; it is covered indirectly by `recordAttempt`, which needs a live
  Postgres connection (not exercised in v0 — see `AGENTS.md`).
-/
import Liaison.Audit

open Liaison

namespace LiaisonTests.Liaison.Audit

#guard recordAttemptStmt.sql ==
  "insert into audit_log (warrant_id, org_id, run_id, provider, action, outcome) " ++
  "values ($1, $2, $3, $4, $5, $6)"

#guard recordAttemptStmt.encode.width == 6

end LiaisonTests.Liaison.Audit
