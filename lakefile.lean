import Lake
open System Lake DSL

-- `liaison`'s executable links against `linen`'s `Database/SQL` FFI (libpq),
-- so it needs its own copy of the native link flags `linen`'s own
-- `lakefile.lean` computes for itself — those don't propagate to a
-- downstream package's final link step, only to `linen`'s own targets.
-- Modeled on `web-data/lakefile.lean`, trimmed of everything `liaison`
-- doesn't need (DuckDB, libsecret/Keychain, macOS framework args), and
-- deliberately *not* copying `web-data`'s OpenSSL link flags — see below.

/-- Run `pkg-config <args>` and return its stdout split into individual
    flags. Returns `#[]` when pkg-config (or the queried package) is
    unavailable. -/
def pkgConfig (args : Array String) : IO (Array String) := do
  let out ← IO.Process.output { cmd := "pkg-config", args }
  if out.exitCode != 0 then
    return #[]
  let normalized := (out.stdout.replace "\n" " ").replace "\t" " "
  return (normalized.splitOn " ").filter (· != "") |>.toArray

/-- Link flags for a pkg-config package that name each library file outright
    (`<libdir>/libfoo.so` / `libfoo.dylib`), rather than adding its directory
    to the linker's search path.

    This is load-bearing on Linux, not cosmetic. `pkg-config --variable=libdir
    libpq` is `/usr/lib/x86_64-linux-gnu`, which holds the *system* `libc.so`
    next to `libpq.so`. Passing that as `-L` puts it ahead of the glibc Lean
    bundles, and Lean's vendored `Scrt1.o` still references the
    `__libc_csu_init`/`__libc_csu_fini` compat symbols glibc 2.34 removed — so
    the executable fails to link with an undefined C-runtime symbol, nowhere
    near anything this package wrote. Naming the `.so` links exactly libpq and
    shadows nothing. Falls back to `-lfoo` if the file is absent, so a distro
    with a different layout still gets a chance.

    Mirrors `infra/lakefile.lean`'s `pkgAbsoluteLibs`, which is the version
    already exercised by a Linux CI that links executables. -/
def pkgAbsoluteLibs (pkg : String) : IO (Array String) := do
  let libs ← pkgConfig #["--libs", pkg]
  let libdirs ← pkgConfig #["--variable=libdir", pkg]
  let libdir : Option String := (libdirs.filter (· != ""))[0]?
  let ext := if System.Platform.isOSX then "dylib" else "so"
  let mut out : Array String := #[]
  for tok in libs do
    if tok.startsWith "-L" then
      continue                                  -- deliberately dropped
    else if tok.startsWith "-l" then
      let name := (tok.drop 2).toString
      match libdir with
      | some d =>
        let candidate : FilePath := (d : FilePath) / s!"lib{name}.{ext}"
        if ← candidate.pathExists then
          out := out.push candidate.toString
        else
          out := out.push tok
      | none => out := out.push tok
    else
      out := out.push tok
  return out

-- No OpenSSL link flags here, deliberately: Lean's own toolchain statically
-- links `libssl.a`/`libcrypto.a` into every executable already (see
-- `infra/lakefile.lean`'s comment on this, verified by reading it), so
-- passing the system OpenSSL `.so` as well breaks the link on Linux
-- (GLIBC-version mismatches against Lean's bundled glibc) and risks a wrong
-- dylib binding on macOS. OpenSSL is needed at *compile time only*, for
-- `linen`'s own `ffi/jose.c` — which `linen` builds, not `liaison` — so CI
-- installs headers but `nativeLinkArgs` carries none. `web-data/lakefile.lean`
-- does pass OpenSSL link flags; that looks like a latent issue there and is
-- out of scope to fix here.

open Lean Elab Command in
run_cmd do
  let mkDef (n : Name) (flags : Array String) : CommandElabM Unit := do
    let lits : Array (TSyntax `term) := flags.map (fun s => quote s)
    elabCommand (← `(def $(mkIdent n) : Array String := #[$lits,*]))
  let pq ← pkgAbsoluteLibs "libpq"
  mkDef `nativeLinkArgs pq

require linen from git "https://github.com/typednotes/linen" @ "v1.0.0"

package liaison where
  version := v!"0.4.0"

@[default_target]
lean_lib Liaison where

-- `Liaison.Warrant.Tag`'s HMAC round trip (`Tests/Liaison/Warrant/TagTest.lean`,
-- `Tests/Liaison/AuthTest.lean`) is exercised via `#eval`, which runs through
-- Lean's interpreter rather than compiled code. The interpreter resolves
-- `@[extern]` declarations (`Crypto.JOSE.FFI.hmac`) by `dlopen`ing a shared
-- library, so this lib is precompiled (matching linen's own
-- `lean_lib Tests where precompileModules := true`, confirmed by reading its
-- `lakefile.lean`) so the interpreter can find the native symbol.
--
-- Named `LiaisonTests`, module tree rooted at `LiaisonTests.*` (not `Tests`):
-- `linen` itself has its own test tree rooted at the module namespace
-- `Tests.*` (its own `Tests.lean`/`Tests/Linen/...`). With both packages in
-- the same workspace declaring modules under a shared top-level `Tests`
-- name, Lake's cross-package module-to-source-file lookup for *every*
-- `Tests.Liaison.*` module resolved against **linen's** package root
-- instead of liaison's own (e.g. looking for
-- `.lake/packages/linen/Tests/Liaison/Warrant/CaveatTest.lean`, which of
-- course doesn't exist there) — a spurious `Running Tests.X` failure on
-- every module, even though the real, correct build/run of each module
-- (from the right path) ran afterward and passed. Renaming liaison's whole
-- test module tree away from the shared `Tests` prefix (to `LiaisonTests`)
-- fixed it — confirmed no more spurious failures after the rename.
lean_lib LiaisonTests where
  precompileModules := true

@[default_target]
lean_exe liaison where
  root := `Main
  moreLinkArgs := nativeLinkArgs
