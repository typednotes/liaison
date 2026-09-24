/-
  Tests for `Liaison.Audit`.

  Pins `recordAttemptStmt`'s literal SQL text and its encoder's column
  count, per `Audit.lean`'s own comment pointing at this file, and the
  `outcome` text of every result. `recordAttempt` itself needs a live
  Postgres connection (not exercised — see `AGENTS.md`).
-/
import Liaison.Audit

open Liaison

namespace LiaisonTests.Liaison.Audit

#guard recordAttemptStmt.sql ==
  "insert into audit_log (warrant_id, org_id, run_id, provider, action, outcome) " ++
  "values ($1, $2, $3, $4, $5, $6)"

#guard recordAttemptStmt.encode.width == 6

-- The outcome column: "ok", or the denial's code (the HTTP `error` string).
#guard outcomeText none == "ok"
#guard outcomeText (some .urlDenied) == "url_denied"
#guard outcomeText (some .headerDenied) == "header_denied"
#guard outcomeText (some .credentialUnavailable) == "credential_unavailable"
#guard outcomeText (some .upstreamFailed) == "upstream_failed"
#guard outcomeText (some .budgetUnavailable) == "budget_unavailable"
#guard outcomeText (some .malformedWarrant) == "malformed_warrant"

/-- The migration that creates `audit_log`, read at compile time — the test
    reads the `.sql` file; nothing in the library does. -/
private def auditLogSql : String := include_str "../../sql/0001_audit_log.sql"

-- The table the insert above writes exists in the schema, with every column
-- it names, so the statement and the migration cannot drift apart unnoticed.
#guard (auditLogSql.splitOn "create table audit_log").length > 1
#guard ["warrant_id", "org_id", "run_id", "provider", "action", "outcome"].all
  (fun col => (auditLogSql.splitOn s!"    {col} ").length > 1)

end LiaisonTests.Liaison.Audit
