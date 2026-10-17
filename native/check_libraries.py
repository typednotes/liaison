#!/usr/bin/env python3
"""Load real native adapters together and exercise their refusal/offline paths.

No pairing is requested and no provider network request is needed. Signal opens
an empty encrypted store; WhatsApp refuses restoration without an identity.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import tempfile
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signal",type=Path,required=True)
    parser.add_argument("--whatsapp",type=Path,required=True)
    parser.add_argument("--temp-root",type=Path,required=True)
    args=parser.parse_args()
    assert args.temp_root.is_dir()
    with tempfile.TemporaryDirectory(prefix="paired-load-",dir=args.temp_root) as directory:
        os.environ["LIAISON_PAIRED_DIR"]=directory
        # Keep both loaded simultaneously to detect native ABI/symbol collisions.
        libraries=[]
        for name,path in (("signal",args.signal),("whatsapp",args.whatsapp)):
            print(f"Loading real {name} adapter",flush=True)
            libraries.append((name,ctypes.CDLL(str(path.resolve()),mode=ctypes.RTLD_LOCAL)))
        for name,library in libraries:
            print(f"Checking real {name} adapter",flush=True)
            library.liaison_paired_call.argtypes=[ctypes.c_char_p]
            library.liaison_paired_call.restype=ctypes.c_void_p
            library.liaison_paired_free.argtypes=[ctypes.c_void_p]
            def invoke(value):
                pointer=library.liaison_paired_call(json.dumps(value).encode())
                try:return json.loads(ctypes.string_at(pointer))
                finally:library.liaison_paired_free(pointer)
            assert invoke({"unknown":"input"})["status"]==502
            print(f"{name}: malformed input refused",flush=True)
            request={"provider":name,"organization":"offline-org","account":"offline-owner/offline-connection","key":"07"*32,
                     "action":"status","responseLimit":65536}
            assert invoke(request)["status"]==200
            print(f"{name}: offline restoration started",flush=True)
            for _ in range(100):
                result=invoke(request)
                if json.loads(result["body"])["state"]=="disconnected":break
                time.sleep(.05)
            else:raise AssertionError("unpaired adapter did not refuse offline restoration")
            if name=="signal":
                database=Path(directory)/name/"offline-org/offline-owner/offline-connection/protocol.db"
                assert database.is_file() and database.stat().st_size>16
                with database.open("rb") as source:
                    assert source.read(16)!=b"SQLite format 3\x00", "Signal SQLCipher encryption was not enabled"
            request["action"]="unlink"
            print(f"{name}: stopping offline restoration",flush=True)
            assert invoke(request)["status"]==200
            assert not (Path(directory)/name/"offline-org/offline-owner/offline-connection").exists()
            print(f"PASS real {name} library: simultaneous loading, strict refusal, offline store/restoration and teardown",flush=True)


if __name__=="__main__":main()
