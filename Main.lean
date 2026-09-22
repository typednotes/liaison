import Liaison
import Linen.Network.WebApp.Server

/-- Entry point. Reads `LIAISON_ROOT_KEY`, `DATABASE_URL`, `SECRETS_HOST`/
    `SECRETS_TOKEN`/... (see `Liaison.Egress.SecretsConfig.fromEnv`) and
    `LIAISON_PORT` (default `8080`), then serves `Liaison.application`.
    Fails loudly (via the `IO.userError`s in `RootKey.fromEnv`/
    `SecretsConfig.fromEnv`) rather than starting with a default key or a
    missing `secrets` client. -/
def main : IO Unit := do
  let rootKey ← Liaison.RootKey.fromEnv
  let databaseUrl ← match ← IO.getEnv "DATABASE_URL" with
    | some url => pure url
    | none => throw <| IO.userError "DATABASE_URL is not set"
  let secretsCfg ← Liaison.Egress.SecretsConfig.fromEnv
  let port : UInt16 := match ← IO.getEnv "LIAISON_PORT" with
    | some p => (p.toNat?.getD 8080).toUInt16
    | none => 8080
  let connSettings ←
    if h : databaseUrl.length > 0 then
      pure (Database.SQL.Connection.Settings.uri databaseUrl h)
    else
      throw <| IO.userError "DATABASE_URL is empty"
  let pool ← Database.SQL.Pool.Pool.create { connSettings }
  IO.println s!"liaison listening on :{port}"
  Network.WebApp.Server.run port (Liaison.application rootKey pool secretsCfg)
