/-
  Liaison.Audit — the append-only audit log.

  `AuditRow` is plain data, not proof-carrying — per `proof-strategy.md`,
  "witnesses do not cross Postgres," and an audit row is exactly the kind of
  state that is written once and never reloaded into a witness. `recordAttempt`
  is called from exactly one place, `Server.lean`'s single request handler,
  so there is one call site to review for "every attempt is logged."
-/

import Liaison.Warrant.Caveat
import Linen.Database.SQL.Statement
import Linen.Database.SQL.Pool

namespace Liaison

open Database.SQL.Statement (Statement)
open Database.SQL.Encoders (Params)
open Database.SQL.Decoders (Result)
open Database.SQL.Pool (Pool)

/-- One row of the append-only `audit_log` table (`broker.md` §4). Every
    outbound-call attempt — success or any `Denial` variant — produces
    exactly one of these. -/
structure AuditRow where
  warrantId : WarrantId
  orgId     : OrgId
  runId     : RunId
  provider  : Provider
  action    : Action
  /-- `none` on success, `some d` naming which `Denial` was returned. -/
  outcome   : Option Denial

/-- The `audit_log.outcome` text: `"ok"` on success, otherwise the denial's
    `Denial.code` (the same string as the HTTP response's `error`). -/
def outcomeText : Option Denial → String
  | none => "ok"
  | some d => d.code

/-- A flat 6-column text encoder. `Encoders.Params` has no six-way
    combinator (only up to `triple`), and nesting `pair`/`triple` just to
    immediately flatten the tuple back would be pure noise here — every
    column is `text`, so a direct `Params` value is clearer than composing
    one. -/
private def sixText : Params (String × String × String × String × String × String) :=
  { encode := fun (a, b, c, d, e, f) => #[some a, some b, some c, some d, some e, some f]
    width := 6 }

/-- Insert one audit row. Params: warrant id, org id, run id, provider,
    action, outcome. SQL text is pinned by a literal-string `#guard` in
    `LiaisonTests/Liaison/AuditTest.lean`. -/
def recordAttemptStmt : Statement (String × String × String × String × String × String) Unit :=
  Statement.command
    ("insert into audit_log (warrant_id, org_id, run_id, provider, action, outcome) " ++
     "values ($1, $2, $3, $4, $5, $6)")
    sixText

/-- Write one audit row. Throws (loudly, via `IO.userError`) on failure —
    a silently-dropped audit write defeats the entire "complete audit log"
    property `broker.md` §1 names as one of the four things the chokepoint
    makes tractable, so a logging failure here must be visible rather than
    swallowed. -/
def recordAttempt (pool : Pool) (row : AuditRow) : IO Unit := do
  let params :=
    ( row.warrantId.value, row.orgId.value, row.runId.value
    , row.provider.value, row.action.value, outcomeText row.outcome)
  match ← Pool.use pool (recordAttemptStmt.run params) with
  | .ok () => pure ()
  | .error e => throw <| IO.userError s!"failed to record audit row: {e}"

end Liaison
