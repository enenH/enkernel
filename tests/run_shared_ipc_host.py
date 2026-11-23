#!/usr/bin/env python3
"""Run the actual SDK transport between Linux processes, without a driver/root."""
from pathlib import Path
import argparse
import os
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--compiler", default="g++")
args = parser.parse_args()
if sys.platform != "linux" or os.geteuid() == 0:
    parser.error("requires Linux and a non-root user; alternatively run dfm_shared_ipc_check on Android as shell")
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="dfm-ipc-") as temporary:
    for optimization in ("-O0", "-O2"):
        binary = Path(temporary) / ("ipc" + optimization)
        subprocess.run([
            args.compiler, "-std=c++20", optimization, "-Wall", "-Wextra",
            "-Wpedantic", "-Werror", "-I", str(root / "sdk/include"),
            str(root / "sdk/src/shared_ipc.cpp"), str(root / "tests/shared_ipc.cpp"),
            "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True, timeout=70)
        print("DFM_SHARED_IPC_HOST_PASS", optimization, flush=True)
