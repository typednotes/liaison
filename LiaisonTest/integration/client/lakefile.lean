import Lake
open Lake DSL

require linen from "../../../../linen"
require liaison from "../../.."
require lun from "../../../../lun"
require lode from "../../../../lode"

package liaison_writer_fixture where
  srcDir := ".."

lean_exe writerClient where
  root := `WriterClient
