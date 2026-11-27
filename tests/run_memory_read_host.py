#!/usr/bin/env python3
"""Execute the production DFM walker/transfer with a fault-injected MM model."""
from pathlib import Path
import argparse,subprocess,tempfile
p=argparse.ArgumentParser();p.add_argument('--compiler',default='gcc');a=p.parse_args()
root=Path(__file__).resolve().parents[1]
s=(root/'mem_read_backend.h').read_text()
def section(start,end):return s[s.index(start):s.index(end,s.index(start))]
for forbidden in ('set_pte(', 'set_pte_at(', 'handle_mm_fault(', 'pin_user_pages', 'get_user_pages', 'swapin_readahead(', 'access_process_vm('):
    assert forbidden not in s,forbidden
source=section('static __nocfi noinline int bp_bk_lock_page(', '#endif\n\n/* Caller holds')+'\n'
source+=section('static int bp_bk_pte(', 'static void mem_clean_phys(')+'\n'
source+=s[s.index('static int mem_copy_phys('):s.rindex('#endif')]
with tempfile.TemporaryDirectory(prefix='dfm-read-') as directory:
    directory=Path(directory);(directory/'read_under_test.h').write_text(source)
    for lock in ('page','folio'):
        for opt in ('-O0','-O2'):
            binary=directory/('read-'+lock+opt+'.exe')
            flags=['-DDFM_SWAP_FOLIO_LOCKS=1'] if lock=='folio' else []
            subprocess.run([a.compiler,'-std=gnu11',opt,'-Wall','-Wextra','-Werror','-UNDEBUG',*flags,'-I',str(directory),str(root/'tests/memory_read_host.c'),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True)
            print('DFM_MEMORY_READ_HOST_PASS',lock,opt,flush=True)
