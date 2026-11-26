import Lake
open System Lake DSL

require linen from git "https://github.com/typednotes/linen" @ "v3.0.0"

package liaison where
  version := v!"0.8.0"
  testDriver := "LiaisonTest"

target paired.o pkg : FilePath := do
  let srcJob ← inputTextFile <| pkg.dir / "ffi" / "paired.c"
  buildO (pkg.buildDir / "ffi" / "paired.o") srcJob
    #["-I", (← getLeanIncludeDir).toString] (traceArgs := #["-O2", "-fPIC"])
    (extraDepTrace := getLeanTrace)

extern_lib pairedffi pkg := do
  let obj ← paired.o.fetch
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "pairedffi") #[obj]

@[default_target]
lean_lib Liaison where

-- `Liaison.Warrant.Tag`'s HMAC round trip (`LiaisonTest/Liaison/Warrant/TagTest.lean`,
-- `LiaisonTest/Liaison/AuthTest.lean`) is exercised via `#eval`, which runs through
-- Lean's interpreter rather than compiled code. The interpreter resolves
-- `@[extern]` declarations (`Crypto.JOSE.FFI.hmac`) by `dlopen`ing a shared
-- library, so this lib is precompiled (matching linen's own
-- `lean_lib LinenTest where precompileModules := true`, confirmed by reading its
-- `lakefile.lean`) so the interpreter can find the native symbol.
--
-- Named `LiaisonTest` (module tree `LiaisonTest.*`), the `{Package}Test`
-- convention of mathlib, batteries and aesop, and the package's `testDriver`
-- (`lake test`). Not `Tests`: before linen 1.7.0 linen's own test tree was
-- `Tests.*`, and two packages in one workspace with modules under the same
-- top-level name made Lake resolve every `Tests.Liaison.*` module against
-- linen's package root (a spurious `Running Tests.X` failure on each).
lean_lib LiaisonTest where
  precompileModules := true

@[default_target]
lean_exe liaison where
  root := `Main
