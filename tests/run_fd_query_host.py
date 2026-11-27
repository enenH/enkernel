#!/usr/bin/env python3
"""Run the production fd-query operations against an instrumented open file."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--compiler', default='gcc')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
abi = (root / 'abi.h').read_text(encoding='utf-8')
source = (root / 'fd_query.c').read_text(encoding='utf-8')
# Lookup locking is unchanged; model its pinned-file result, then compile the
# actual validation, seek calculation, ioctl dispatch, read and cleanup code.
code = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
for forbidden in ('dentry_open(', 'filp_open(', 'vfs_llseek(', '->llseek('):
    assert forbidden not in code, forbidden
start = abi.index('#define DFM_FILE_QUERY_ABI_VERSION')
end = abi.index('};', start) + 2
production = abi[start:end] + '\n' + source[source.index('static int validate_request('):]
with tempfile.TemporaryDirectory(prefix='dfm-fd-query-') as directory:
    directory = Path(directory)
    (directory / 'fd_query_under_test.h').write_text(production, encoding='utf-8')
    for opt in ('-O0', '-O2'):
        binary = directory / ('fd-query' + opt + '.exe')
        subprocess.run([args.compiler, '-std=gnu11', opt, '-Wall', '-Wextra',
                        '-Werror', '-UNDEBUG', '-I', str(directory),
                        str(root / 'tests/fd_query_host.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        print('DFM_FD_QUERY_HOST_PASS', opt, flush=True)
