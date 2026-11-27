#!/usr/bin/env python3
"""Exercise build-tree PTE backend detection, including removed/backported APIs."""
import argparse
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--shell', default='sh')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='dfm-pte-abi-') as directory:
    tree = Path(directory)
    header = tree / 'arch/arm64/include/asm/debug-monitors.h'
    fault = tree / 'arch/arm64/mm/fault.c'
    monitor = tree / 'arch/arm64/kernel/debug-monitors.c'
    sched = tree / 'include/trace/events/sched.h'
    for path in (header, fault, monitor, sched):
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(path, text, crlf):
        path.write_bytes(text.replace('\n', '\r\n' if crlf else '\n').encode())

    def detect():
        return subprocess.check_output([a.shell, str(root / 'scripts/detect_pte_backend.sh'),
                                        tree.as_posix()], text=True).split()

    for crlf in (False, True):
        for width in ('int', 'long'):
            write(sched, 'DEFINE_EVENT(sched_process_template, sched_process_exit,\n'
                  ' TP_PROTO(struct task_struct *p), TP_ARGS(p));\n', crlf)
            write(fault, 'struct fault_info {\n'
                  f' int (*fn)(unsigned long far, unsigned {width} esr, struct pt_regs *regs);\n'
                  ' int sig, code;\n const char *name;\n};\n', crlf)
            write(header, 'struct step_hook {\n'
                  f' int (*fn)(struct pt_regs *regs, unsigned {width} esr);\n'
                  '};\nvoid register_user_step_hook(struct step_hook *hook);\n', crlf)
            expected = ['-DDFM_PTE_USER_STEP_HOOK']
            if width == 'int':
                expected += ['-DDFM_PTE_STEP_ESR32', '-DDFM_PTE_FAULT_ESR32']
            assert detect() == expected

        write(header, '/* Legacy step hook removed. */\n', crlf)
        write(sched, 'TRACE_EVENT(sched_process_exit,\n'
              ' TP_PROTO(struct task_struct *p, bool group_dead), TP_ARGS(p, group_dead));\n', crlf)
        signature = 'void do_el0_softstep(unsigned long esr, struct pt_regs *regs)\n'
        write(monitor, signature + '{ }\n', crlf)
        assert detect() == ['-DDFM_PTE_SOFTSTEP_KPROBE', '-DDFM_PTE_EXIT_GROUP_DEAD']
        write(monitor, signature + '{ }\nNOKPROBE_SYMBOL(do_el0_softstep);\n', crlf)
        assert detect() == []
        write(monitor, signature.replace('void ', 'int ', 1) + '{ return 0; }\n', crlf)
        assert detect() == []
        write(monitor, signature.replace('unsigned long esr', 'unsigned int esr') + '{ }\n', crlf)
        assert detect() == []
        monitor.unlink()
        assert detect() == []
        write(monitor, signature + '{ }\n', crlf)
        write(fault, 'struct fault_info {\n int (*fn)(int unknown);\n};\n', crlf)
        assert detect() == []
    print('DFM_PTE_BACKEND_ABI_PASS: legacy widths, 6.18, blacklist, unknown ABI, LF/CRLF')
