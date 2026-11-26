import Liaison
import Liaison.Egress.Inventory
import Linen.Network.WebApp.Server

/-- Run the broker with the environment-selected credential store and refresh
    worker. The middleware exposes the operator page when enabled. See
    `docs/secrets.md` for storage, monitoring, and dashboard settings. -/
def main : IO Unit := do
  let rootKey ← Liaison.RootKey.fromEnv
  let databaseUrl ← match ← IO.getEnv "DATABASE_URL" with
    | some url => pure url
    | none => throw <| IO.userError "DATABASE_URL is not set"
  let egressCfg ← Liaison.Egress.EgressConfig.fromEnv
  let port : UInt16 := match ← IO.getEnv "LIAISON_PORT" with
    | some p => (p.toNat?.getD 8080).toUInt16
    | none => 8080
  let connSettings ←
    if h : databaseUrl.length > 0 then
      pure (Database.SQL.Connection.Settings.uri databaseUrl h)
    else
      throw <| IO.userError "DATABASE_URL is empty"
  let pool ← Database.SQL.Pool.Pool.create { connSettings }
  let inventory ← Liaison.Egress.Inventory.fromEnv
  let maintenance ← inventory.start egressCfg
  IO.println s!"liaison listening on :{port}"
  try
    Network.WebApp.Server.run port (inventory.withStatus (Liaison.application rootKey pool egressCfg))
  finally
    if let some task := maintenance then IO.cancel task
