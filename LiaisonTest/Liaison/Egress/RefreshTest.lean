import Liaison.Egress.Refresh

open Liaison.Egress

namespace LiaisonTests.Liaison.Egress.Refresh

private def credential : Option Credential :=
  (Data.Json.Decode.decode
    "{\"kind\":\"gitlab_oauth\",\"base_url\":\"https://gitlab.com/api/v4\",\"access_token\":\"old\",\"refresh_token\":\"first\",\"expires_at\":\"1\"}").toOption >>= Credential.parse

#guard (credential.map (·.refreshDue 1)) == some true

-- S2: A failed save must not cause a second exchange of a rotated token.
#eval show IO Unit from do
  let some initial := credential | throw (IO.userError "invalid credential fixture")
  let observed : StoredCredential := { credential := initial, version := some 1 }
  let record ← IO.mkRef observed
  let writes ← IO.mkRef 0
  let exchanges ← IO.mkRef 0
  let store : RefreshStore := {
    load := fun _ => .ok <$> record.get
    save := fun _ updated version => do
      unless version == some 1 do throw (IO.userError "unexpected storage revision")
      let attempt ← writes.modifyGet fun n => (n + 1, n + 1)
      if attempt == 1 then return .error "write failed"
      record.set { credential := updated, version := some 2 }
      return .ok () }
  let state ← RefreshState.create fun _ _ token => do
    unless token == "first" do throw (IO.userError "unexpected issuer input")
    exchanges.modify (· + 1)
    return .ok { accessToken := "access-2", refreshToken := some "rotated", expiresIn := 3600 }
  let clients : OAuthClients := { gitlab := some { clientId := "fixture", clientSecret := "fixture" } }
  let refresh := state.ensureFresh store clients ⟨"gitlab", "owner/connection"⟩ observed
  let .error _ ← refresh | throw (IO.userError "used an unpersisted refresh")
  let .ok persisted ← refresh | throw (IO.userError "did not retry the pending write")
  unless persisted.persisted do throw (IO.userError "refresh was not recorded as persisted")
  let .ok reused ← refresh | throw (IO.userError "could not reuse the saved refresh")
  unless !reused.persisted && (← exchanges.get) == 1 && (← writes.get) == 2 do
    throw (IO.userError "a stale observer repeated the token exchange")
  match reused.credential.auth with
  | .oauth .gitlab "access-2" "rotated" _ => pure ()
  | _ => throw (IO.userError "the stored rotation was not reused")

end LiaisonTests.Liaison.Egress.Refresh
