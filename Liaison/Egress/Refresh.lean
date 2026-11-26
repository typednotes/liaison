import Liaison.Egress.OAuth
import Liaison.Egress.Policy
import Std.Sync.Mutex
import Std.Data.HashMap

namespace Liaison.Egress

/-- Storage operations needed by the refresh coordinator. -/
structure RefreshStore where
  load : SecretId → IO (Except String StoredCredential)
  save : SecretId → Credential → Option Nat → IO (Except String Unit)

/-- Use the configured backend for reloads and refresh writes. -/
def SecretsConfig.refreshStore (cfg : SecretsConfig) : RefreshStore :=
  { load := loadCredential cfg, save := storeCredential cfg }

/-- The credential to use and whether this call persisted a refresh. -/
structure RefreshOutcome where
  credential : Credential
  persisted : Bool := false

private structure PendingRefresh where
  original : StoredCredential
  updated : Credential

/-- Per-process refresh coordination. Each credential uses a stable mutex shard
    shared by the sweeper and request path. -/
structure RefreshState where
  private mk ::
  private locks : Array (Std.Mutex (Std.HashMap SecretId PendingRefresh))
  private exchange : OAuthIssuer → OAuthClient → String → IO (Except String TokenResponse)

/-- Create the refresh coordinator. Tests can supply a deterministic issuer. -/
def RefreshState.create (exchange := refreshToken) : IO RefreshState := do
  let locks ← (Array.range 64).mapM fun _ => Std.Mutex.new {}
  return ⟨locks, exchange⟩

private def sameCredential (a b : StoredCredential) : Bool :=
  a.version == b.version &&
    Data.Json.Encode.encode a.credential.raw == Data.Json.Encode.encode b.credential.raw

/-- Check whether the credential's access token is inside its refresh window. -/
def Credential.refreshDue (credential : Credential) (now : Nat) : Bool :=
  match credential.auth with
  | .oauth _ _ _ expiry => needsRefresh expiry now
  | _ => false

/-- Refresh a due OAuth credential and persist issuer rotations before use.
    Re-read under the lock so overlapping calls share the persisted token.
    If the write fails, keep the new token in memory for the next write attempt
    while the stored credential still matches the original. -/
def RefreshState.ensureFresh (state : RefreshState) (store : RefreshStore)
    (clients : OAuthClients) (id : SecretId) (observed : StoredCredential) :
    IO (Except String RefreshOutcome) := do
  if !observed.credential.refreshDue (← nowUnixSeconds) then return .ok { credential := observed.credential }
  let some lock := state.locks[(hash id).toNat % state.locks.size]?
    | return .error "refresh coordinator is unavailable"
  lock.atomically do
    let .ok current ← store.load id | return .error "credential could not be reloaded"
    let now ← nowUnixSeconds
    let pending ← get
    let updated ← match pending[id]? with
      | some retry =>
        if sameCredential retry.original current then pure (some retry.updated)
        else do
          modify (·.erase id)
          pure none
      | none => pure none
    let updated ← match updated with
      | some updated => pure updated
      | none =>
        let .oauth issuer _ refresh expiry := current.credential.auth
          | return .ok { credential := current.credential }
        if !needsRefresh expiry now || (!sameCredential current observed && now < expiry) then
          return .ok { credential := current.credential }
        let some client := clients.get issuer | return .error "OAuth client is not configured"
        let .ok token ← state.exchange issuer client refresh | return .error "issuer refresh failed"
        let updated := current.credential.refreshed token.accessToken (now + token.expiresIn) token.refreshToken
        modify (·.insert id { original := current, updated })
        pure updated
    let .ok latest ← store.load id | return .error "credential could not be rechecked"
    unless sameCredential latest current do
      modify (·.erase id)
      return .error "credential changed during refresh"
    match ← store.save id updated current.version with
    | .error err => return .error err
    | .ok () =>
      modify (·.erase id)
      if let .oauth _ _ _ expiry := updated.auth then
        if expiry ≤ (← nowUnixSeconds) then return .error "refreshed token already expired"
      return .ok { credential := updated, persisted := true }

end Liaison.Egress
