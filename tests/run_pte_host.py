#!/usr/bin/env python3
"""Execute the production PTE fault/step/notifier paths with a bounded MM model."""
from pathlib import Path
import argparse
import subprocess
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--compiler', default='gcc')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
s = (root / 'pte_bp.c').read_text()

def section(start, end):
    at = s.index(start)
    return s[at:s.index(end, at)]

source = section('struct pte_page {', 'static DEFINE_MUTEX(control_lock);')
source += '\nstatic struct pte_session *session;\n'
source += section('static int set_armed(', 'static void disable_local_step(')
source += section('static void finish_step(', 'static struct step_hook step_hook')
source += section('static void record_hit(', '#define FAULT_WRAPPER')
source += section('static void cancel_current(', 'static void sys_enter(')
source += section('static int invalidate_start(', 'static const struct mmu_notifier_ops')
with tempfile.TemporaryDirectory(prefix='dfm-pte-') as directory:
    directory = Path(directory)
    if sys.platform == 'win32':
        # The model uses ABI structs, never host ioctl commands.
        (directory / 'sys').mkdir()
        (directory / 'sys/ioctl.h').write_text('/* No host ioctl calls. */\n')
    (directory / 'pte_under_test.h').write_text(source)
    for opt in ('-O0', '-O2'):
        binary = directory / ('pte' + opt + '.exe')
        subprocess.run([a.compiler, '-std=gnu11', opt, '-Wall', '-Wextra',
                        '-Werror', '-UNDEBUG', '-I', str(directory), '-I', str(root),
                        str(root / 'tests/pte_host.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        print('DFM_PTE_HOST_PASS', opt, flush=True)
