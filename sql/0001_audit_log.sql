-- The broker's append-only audit log (typednotes/typednotes
-- docs/services/broker.md §4): one row per outbound-call attempt, success or
-- denial, written by `Liaison.recordAttempt` (Liaison/Audit.lean).
--
-- Every attribute column is `text`, with no foreign keys, deliberately. The
-- log must record *every* attempt, including ones whose warrant names an org
-- or run that does not exist, or whose ids are not UUIDs at all
-- (`malformed_warrant`, `tag_invalid`) — a foreign key or a `uuid` column
-- would make exactly those inserts fail, and `recordAttempt` treats a failed
-- audit write as fatal. An audit log that can only record well-formed
-- requests is missing the rows that matter most.
--
-- `liaison` also writes `credit_holds` and `credit_ledger`, which `ledger`'s
-- history creates; `typednotes-infra` orders this history after that one.

create table audit_log (
    id          bigint generated always as identity primary key,
    warrant_id  text not null,
    org_id      text not null,
    run_id      text not null,
    provider    text not null,
    action      text not null,
    outcome     text not null,        -- 'ok' or a Denial name; see Audit.lean
    recorded_at timestamptz not null default now()
);

create index on audit_log (org_id, recorded_at);
create index on audit_log (run_id);
