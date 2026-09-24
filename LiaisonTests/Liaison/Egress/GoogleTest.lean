/-
  Tests for `Liaison.Egress.Google`: the refresh request body and the token
  response parser. `refreshGoogle` itself makes a real network call and is
  only signature-pinned; `GoogleClient.fromEnv` reads the environment, which
  a `#eval` cannot set (see `AGENTS.md`).
-/
import Liaison.Egress.Google

open Liaison.Egress

namespace LiaisonTests.Liaison.Egress.Google

private def client : GoogleClient := { clientId := "id.apps", clientSecret := "s/+=" }

#guard refreshForm client "1//r t" ==
  "grant_type=refresh_token&refresh_token=1%2F%2Fr%20t&client_id=id.apps&client_secret=s%2F%2B%3D"

#guard googleTokenHost == "oauth2.googleapis.com"

private def parsed (s : String) : Option (String × Nat × Option String) :=
  (parseTokenResponse s).map (fun t => (t.accessToken, t.expiresIn, t.refreshToken))

#guard parsed "{\"access_token\": \"ya29.a\", \"expires_in\": 3599, \"token_type\": \"Bearer\"}" ==
  some ("ya29.a", 3599, none)
#guard parsed "{\"access_token\": \"a\", \"expires_in\": 3600, \"refresh_token\": \"1//n\"}" ==
  some ("a", 3600, some "1//n")
-- `expires_in` must be a non-negative JSON integer.
#guard parsed "{\"access_token\": \"a\", \"expires_in\": \"3600\"}" == none
#guard parsed "{\"access_token\": \"a\", \"expires_in\": 1.5}" == none
#guard parsed "{\"access_token\": \"a\", \"expires_in\": -1}" == none
#guard parsed "{\"access_token\": \"a\"}" == none
#guard parsed "{\"access_token\": \"\", \"expires_in\": 3600}" == none
#guard parsed "{\"error\": \"invalid_grant\"}" == none
#guard parsed "not json" == none

example : GoogleClient → String → IO (Except String TokenResponse) := refreshGoogle
example : IO (Option GoogleClient) := GoogleClient.fromEnv

end LiaisonTests.Liaison.Egress.Google
