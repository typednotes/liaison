/-
  Tests for `Liaison.Egress.OAuth`: each issuer's fixed token endpoint, the
  refresh request body and the token response parser. `refreshToken` itself
  makes a real network call and is only signature-pinned;
  `OAuthClient.fromEnv` reads the environment, which a `#eval` cannot set
  (see `AGENTS.md`).
-/
import Liaison.Egress.OAuth

open Liaison.Egress

namespace LiaisonTests.Liaison.Egress.OAuth

private def client : OAuthClient := { clientId := "id.apps", clientSecret := "s/+=" }

#guard refreshForm client "1//r t" ==
  "grant_type=refresh_token&refresh_token=1%2F%2Fr%20t&client_id=id.apps&client_secret=s%2F%2B%3D"

-- Fixed endpoints, per issuer.
#guard (OAuthIssuer.google.tokenHost, OAuthIssuer.google.tokenPath) ==
  ("oauth2.googleapis.com", "/token")
#guard (OAuthIssuer.dropbox.tokenHost, OAuthIssuer.dropbox.tokenPath) ==
  ("api.dropboxapi.com", "/oauth2/token")
#guard (OAuthIssuer.gitlab.tokenHost, OAuthIssuer.gitlab.tokenPath) ==
  ("gitlab.com", "/oauth/token")
#guard [OAuthIssuer.google, .dropbox, .gitlab].map (·.envPrefix) == ["GOOGLE", "DROPBOX", "GITLAB"]

-- Only the configured issuer's client is used.
#guard ({ dropbox := some client } : OAuthClients).get .dropbox |>.isSome
#guard ({ dropbox := some client } : OAuthClients).get .gitlab |>.isNone

private def parsed (s : String) : Option (String × Nat × Option String) :=
  (parseTokenResponse s).map (fun t => (t.accessToken, t.expiresIn, t.refreshToken))

#guard parsed "{\"access_token\": \"ya29.a\", \"expires_in\": 3599, \"token_type\": \"Bearer\"}" ==
  some ("ya29.a", 3599, none)
#guard parsed "{\"access_token\": \"a\", \"expires_in\": 3600, \"refresh_token\": \"1//n\"}" ==
  some ("a", 3600, some "1//n")
-- Dropbox's and GitLab's answers (GitLab rotates the refresh token).
#guard parsed "{\"access_token\": \"sl.B\", \"token_type\": \"bearer\", \"expires_in\": 14400}" ==
  some ("sl.B", 14400, none)
#guard parsed ("{\"access_token\": \"glo\", \"token_type\": \"Bearer\", \"expires_in\": 7200, " ++
  "\"refresh_token\": \"glr\", \"created_at\": 1790000000, \"scope\": \"read_api\"}") ==
  some ("glo", 7200, some "glr")
-- `expires_in` must be a non-negative JSON integer.
#guard parsed "{\"access_token\": \"a\", \"expires_in\": \"3600\"}" == none
#guard parsed "{\"access_token\": \"a\", \"expires_in\": 1.5}" == none
#guard parsed "{\"access_token\": \"a\", \"expires_in\": -1}" == none
#guard parsed "{\"access_token\": \"a\"}" == none
#guard parsed "{\"access_token\": \"\", \"expires_in\": 3600}" == none
#guard parsed "{\"error\": \"invalid_grant\"}" == none
#guard parsed "not json" == none

example : OAuthIssuer → OAuthClient → String → IO (Except String TokenResponse) := refreshToken
example : OAuthIssuer → IO (Option OAuthClient) := OAuthClient.fromEnv
example : IO OAuthClients := OAuthClients.fromEnv

end LiaisonTests.Liaison.Egress.OAuth
