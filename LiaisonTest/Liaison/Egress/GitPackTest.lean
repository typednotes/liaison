import Liaison.Egress.GitPack
open Liaison.Egress
namespace NativeGitPackTests
#guard ({ kind := "blob", data := "hello\n".toUTF8 } : GitPack.Object).id == "ce013625030ba8dba906f756967f9e9ca394464a"
#guard GitPack.packet "hello\n" == "000ahello\n"
#guard GitPack.published "000eunpack ok\n0017ok refs/heads/main\n0000" "main"
#guard !GitPack.published "000eunpack ok\n0017ok refs/heads/main\n0000" "other"
#guard !(GitPack.advertised "0004" "main" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").isOk
example (built : GitPack.Built) : Repository.commit built.parent = true := built.parentBound
end NativeGitPackTests
