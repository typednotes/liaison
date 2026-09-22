/-
  Liaison.Budget — the credit hold lifecycle: `Reserved`, `withReservation`,
  and the Postgres statements that make budget enforcement a Tier-4
  Constraint rather than a Lean-heap property.

  This is a **local mirror** of `typednotes/typednotes`'s
  `docs/services/ledger.md` §4/§7 schema and statement shape, not a
  dependency on the (not-yet-implemented) `ledger` service — `liaison`
  writes directly to the same `credit_holds`/`credit_ledger` tables
  `ledger` will eventually own. Keep this file in sync with
  `ledger.md` by hand until a shared library exists.

  Per `ledger.md` §3: **Lean makes the arithmetic and the lifecycle
  correct. Postgres makes the concurrency correct.** Nothing in this module
  claims to prove no-double-spend — that is `reserveHoldStmt`'s atomic
  conditional insert, a Tier-4 Constraint, not a Lean theorem. Lean cannot
  see concurrent containers.
-/

import Liaison.Auth
import Linen.Database.SQL.Statement
import Linen.Database.SQL.Session
import Linen.Database.SQL.Pool

namespace Liaison

open Database.SQL.Connection (Settings)
open Database.SQL.Session (Session SessionError)
open Database.SQL.Statement (Statement)
open Database.SQL.Encoders (Params)
open Database.SQL.Decoders (Value Row Result)
open Database.SQL.Pool (Pool PoolError)

/-- Mirrors `credit_holds.id`. -/
structure HoldId where
  value : String
  deriving DecidableEq, Repr

/-- A generic outbound-call response, shared by `Egress/Provider.lean` and
    `Server.lean` so `withReservation`'s callback and `callProvider`/
    `callInference`'s return type agree without either module depending on
    linen's HTTP client types directly. -/
structure Response where
  status  : UInt16
  headers : List (String × String)
  body    : ByteArray

/-- Spend authority, separate from access authority (`Authorized`). No
    public constructor: the only route in is `withReservation`, so an
    outbound call can never be attempted without a live budget hold. -/
structure Reserved (r : Request) where
  private mk ::
  authorized : Authorized r
  holdId     : HoldId

-- ── Statements ─────────────────────────────────────────────────────────
--
-- SQL text is pinned by literal-string `#guard`s in
-- `LiaisonTests/Liaison/BudgetTest.lean` so a future edit shows as a diff.

/-- The exact atomic conditional-insert pattern from `ledger.md` §7,
    keyed on `warrant.orgId` (params: org id, run id, amount). Zero rows
    returned means denied — no race, no advisory lock; the balance check
    and the hold insert are one statement. -/
def reserveHoldStmt : Statement (String × String × Nat) (Option String) :=
  { sql :=
      "insert into credit_holds (org_id, run_id, amount, state, expires_at) " ++
      "select $1, $2, $3, 'held', now() + interval '15 minutes' " ++
      "where ( " ++
      "  select coalesce(sum(delta), 0) from credit_ledger where org_id = $1 " ++
      ") - ( " ++
      "  select coalesce(sum(amount), 0) from credit_holds " ++
      "   where org_id = $1 and state = 'held' " ++
      ") >= $3 " ++
      "returning id"
    encode := Params.triple Params.text Params.text Params.nat
    decode := Result.maybeRow (Row.column Value.text) }

/-- Marks a hold settled. Only affects a row still in `'held'` — settling an
    already-settled or released hold is a no-op, not an error (the phase
    transition is enforced by the `where state = 'held'`, matching
    `ledger.md` §5's `HoldStep` — nothing leaves `.settled` or `.released`). -/
def settleHoldStmt : Statement String Unit :=
  Statement.command
    "update credit_holds set state = 'settled' where id = $1 and state = 'held'"
    Params.text

/-- Records the actual usage against the ledger (params: org id, run id,
    negative delta). Sign comes from the caller passing a negated `Credits`,
    never from the column — mirrors `ledger.md` §5's `Entry.delta`. -/
def recordUsageStmt : Statement (String × String × Int) Unit :=
  Statement.command
    "insert into credit_ledger (org_id, run_id, delta, reason) values ($1, $2, $3, 'usage')"
    (Params.triple Params.text Params.text Params.int)

/-- Releases a hold without recording usage (the exception path). Same
    `state = 'held'` guard as `settleHoldStmt`. -/
def releaseHoldStmt : Statement String Unit :=
  Statement.command
    "update credit_holds set state = 'released' where id = $1 and state = 'held'"
    Params.text

-- ── Hold lifecycle ───────────────────────────────────────────────────

/-- Attempt to place a hold. `.error .budgetUnavailable` covers both "zero
    rows returned" (insufficient balance) and any connection/session error —
    from the caller's perspective both mean the spend cannot be authorized
    right now, and `Denial` deliberately does not distinguish a Postgres
    outage from an exhausted budget (see `AGENTS.md`'s "Not yet implemented"
    list: no separate `Denial` variant for infra failure is one of the
    named v0 gaps). -/
def reserveHold (pool : Pool) (orgId : OrgId) (runId : RunId) (cost : Credits)
    : IO (Except Denial HoldId) := do
  match ← Pool.use pool (reserveHoldStmt.run (orgId.value, runId.value, cost)) with
  | .error _ => return .error .budgetUnavailable
  | .ok none => return .error .budgetUnavailable
  | .ok (some id) => return .ok { value := id }

/-- Settle a hold and record its actual usage, in one transaction. Throws
    (loudly, via `IO.userError`) if either statement fails — a settle
    failure after a real outbound call happened must never be swallowed
    silently, since it would leave the org's balance wrong with no trace. -/
def settleHold (pool : Pool) (orgId : OrgId) (runId : RunId) (holdId : HoldId)
    (actual : Credits) : IO Unit := do
  let session : Session Unit := do
    settleHoldStmt.run holdId.value
    recordUsageStmt.run (orgId.value, runId.value, -(actual : Int))
  match ← Pool.use pool (Session.transaction session) with
  | .ok () => pure ()
  | .error e => throw <| IO.userError s!"failed to settle hold {holdId.value}: {e}"

/-- Release a hold without recording usage. Throws loudly on failure, same
    rationale as `settleHold`. -/
def releaseHold (pool : Pool) (holdId : HoldId) : IO Unit := do
  match ← Pool.use pool (releaseHoldStmt.run holdId.value) with
  | .ok () => pure ()
  | .error e => throw <| IO.userError s!"failed to release hold {holdId.value}: {e}"

/-- Reserve budget, run the callback, then settle on success or release on
    *any* exception (`try`/`catch` around the callback, matching
    `broker.md` §5: "Bracketed, so the hold always settles or releases —
    including on exception"). The callback returns the actual cost incurred
    (which may differ from the warrant's `budget` caveat cap — settlement
    records what was actually spent, per `ledger.md` §5's `Settlement`
    witness `actual ≤ h.amount`; that inequality is not re-checked here in
    v0, a named gap — see `AGENTS.md`).

    The callback returns `Except Denial (Response × Credits)` rather than a
    bare `Response` so a structured refusal (e.g. `Egress.callInference`'s
    loud stub) can flow back as a `Denial` value, not an ad hoc IO
    exception — only genuine failures (a network error, a Postgres error)
    go through the `try`/`catch` below. Either way the hold is always
    settled or released, never left dangling. -/
def withReservation {r : Request} (pool : Pool) (a : Authorized r)
    (k : Reserved r → IO (Except Denial (Response × Credits))) : IO (Except Denial Response) := do
  match ← reserveHold pool a.warrant.orgId r.runId r.cost with
  | .error d => return .error d
  | .ok holdId =>
    let reserved : Reserved r := ⟨a, holdId⟩
    try
      match ← k reserved with
      | .error d =>
        releaseHold pool holdId
        return .error d
      | .ok (resp, actual) =>
        settleHold pool a.warrant.orgId r.runId holdId actual
        return .ok resp
    catch e =>
      releaseHold pool holdId
      throw e

end Liaison
