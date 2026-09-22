/-
  Tests for `Liaison.Egress.Secrets`.

  **Gap, named here and in `AGENTS.md`:** there is very little pure,
  testable surface in this module. `SecretsConfig`'s only constructor is
  `SecretsConfig.fromEnv`, which — like `RootKey.fromEnv`
  (`LiaisonTests/Liaison/Warrant/TagTest.lean`) — cannot be driven end to end from
  inside a `#eval` (linen has no `setenv`; see
  `Tests/Linen/Cloud/CredentialsTest.lean`'s note on the same limit).
  `Credential`'s only constructor is private to `Secrets.lean` and is only
  ever produced by `fetchCredential`, which makes a real network call —
  not exercised here. `fetchCredential`'s KV path
  (`/v1/secret/data/thirdparty/{provider}/{account}`) is built inline
  rather than as a separately testable pure function.

  What *is* checked: the module's public signatures still type-check
  against the shapes this test file expects, so a signature-changing edit
  to `Secrets.lean` is caught at `lake build LiaisonTests` time even without a
  runtime assertion (the same rationale as
  `Tests/Linen/Crypto/JOSE/FFITest.lean`).
-/
import Liaison.Egress.Secrets

open Liaison Liaison.Egress

namespace LiaisonTests.Liaison.Egress.Secrets

example : IO SecretsConfig := SecretsConfig.fromEnv
example : Credential → Option String := Credential.token
example : SecretsConfig → Provider → String → IO (Option Credential) := fetchCredential

end LiaisonTests.Liaison.Egress.Secrets
