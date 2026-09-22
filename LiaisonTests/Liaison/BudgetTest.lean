/-
  Tests for `Liaison.Budget`.

  `Statement.sql` is plain data, so the credit-hold SQL text is pinned by
  literal-string `#guard`s — a future edit to any of these statements now
  shows as a diff here, per `Budget.lean`'s own comment pointing at this
  file. No live Postgres connection is exercised (see `AGENTS.md`'s "Not
  yet implemented": no live-database test coverage in v0).
-/
import Liaison.Budget

open Liaison

namespace LiaisonTests.Liaison.Budget

#guard reserveHoldStmt.sql ==
  "insert into credit_holds (org_id, run_id, amount, state, expires_at) " ++
  "select $1, $2, $3, 'held', now() + interval '15 minutes' " ++
  "where ( " ++
  "  select coalesce(sum(delta), 0) from credit_ledger where org_id = $1 " ++
  ") - ( " ++
  "  select coalesce(sum(amount), 0) from credit_holds " ++
  "   where org_id = $1 and state = 'held' " ++
  ") >= $3 " ++
  "returning id"

#guard settleHoldStmt.sql ==
  "update credit_holds set state = 'settled' where id = $1 and state = 'held'"

#guard recordUsageStmt.sql ==
  "insert into credit_ledger (org_id, run_id, delta, reason) values ($1, $2, $3, 'usage')"

#guard releaseHoldStmt.sql ==
  "update credit_holds set state = 'released' where id = $1 and state = 'held'"

end LiaisonTests.Liaison.Budget
