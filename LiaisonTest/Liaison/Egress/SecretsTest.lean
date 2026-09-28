/-
  Tests for `Liaison.Egress.Secrets`.

  `SecretsConfig`'s only constructor is `SecretsConfig.fromEnv`, which — like
  `RootKey.fromEnv` — cannot be driven from inside a `#eval` (Lean has no
  `setenv`), and `fetchCredential`/`writeCredential` make real network
  calls, so those are signature-pinned only. The pure pieces — the KV path,
  the `userpass` login parser, token freshness and the JSON-integer reader —
  are checked directly.
-/
import Liaison.Egress.Secrets

open Liaison Liaison.Egress

namespace LiaisonTests.Liaison.Egress.Secrets

#guard credentialPath ⟨"github"⟩ "u1/c2" == "/v1/secret/data/thirdparty/github/u1/c2"

-- userpass login → token + expiry `now + lease_duration`.
#guard (parseLogin "{\"auth\": {\"client_token\": \"hvs.x\", \"lease_duration\": 3600, \"policies\": [\"liaison\"]}}" 1000).map
  (fun t => (t.token, t.expiresAt)) == some ("hvs.x", some 4600)
-- `lease_duration` 0: no expiry reported.
#guard (parseLogin "{\"auth\": {\"client_token\": \"t\", \"lease_duration\": 0}}" 1000).map
  (·.expiresAt) == some none
#guard (parseLogin "{\"auth\": {\"client_token\": \"t\"}}" 0).isNone
#guard (parseLogin "{\"auth\": {\"client_token\": \"\", \"lease_duration\": 1}}" 0).isNone
#guard (parseLogin "{\"errors\": [\"invalid credentials\"]}" 0).isNone

-- Re-login when fewer than 60 s remain.
#guard (VaultToken.mk "t" (some 1000)).fresh 939
#guard !(VaultToken.mk "t" (some 1000)).fresh 940
#guard !(VaultToken.mk "t" (some 1000)).fresh 2000
#guard (VaultToken.mk "t" none).fresh 1000000

#guard jsonNat? (.number 3600) == some 3600
#guard jsonNat? (.number 0) == some 0
#guard jsonNat? (.number 1.5) == none
#guard jsonNat? (.number (-1)) == none
#guard jsonNat? (.string "3600") == none

example : IO SecretsConfig := SecretsConfig.fromEnv
example : SecretsConfig → Provider → String → IO (Except String Credential) := fetchCredential
example : SecretsConfig → Provider → String → Credential → IO (Except String Unit) :=
  writeCredential

end LiaisonTests.Liaison.Egress.Secrets
