#!/usr/bin/env python3
"""Test source-tree ABI detection and the production indirect-call wrapper."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--compiler', default='gcc')
parser.add_argument('--shell', default='sh')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
backend = (root / 'mem_read_backend.h').read_text()
declarations = backend[backend.index('struct swap_iocb;'):backend.index('static typeof(&swap_duplicate)')]
wrapper_start = backend.index('static __nocfi noinline struct page *bp_bk_read_cache(')
wrapper = backend[wrapper_start:backend.index('/* Keep the kernel fast/slow', wrapper_start)]

def detected(path):
    return subprocess.check_output(
        [args.shell, str(root / 'scripts/detect_swap_reader.sh'), str(path)],
        text=True).split()

with tempfile.TemporaryDirectory(prefix='dfm-swap-abi-') as directory:
    directory = Path(directory)
    fixture = directory / 'swap_state.c'
    for kind in ('page', 'folio'):
        for suffix, flags in (
            ('bool do_poll', ['-DDFM_SWAP_READ_POLL']),
            ('struct swap_iocb **plug', ['-DDFM_SWAP_READ_PLUG']),
            ('bool do_poll, struct swap_iocb **plug',
             ['-DDFM_SWAP_READ_POLL', '-DDFM_SWAP_READ_PLUG']),
        ):
            signature = f'''struct {kind} *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
                    struct vm_area_struct *vma, unsigned long addr, {suffix})'''
            # Both multiline and single-line definitions, including CRLF input.
            expected = ['-DDFM_SWAP_READER_KNOWN', *flags]
            if kind == 'folio':
                expected.append('-DDFM_SWAP_READ_FOLIO')
            for text in (signature, signature.replace('\n', ' ')):
                fixture.write_bytes((text + '\n{ return 0; }\n').replace('\n', '\r\n').encode())
                actual = detected(fixture)
                assert actual == expected, (signature, actual, expected)
            code = '''#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
typedef unsigned int gfp_t;
typedef struct { unsigned long val; } swp_entry_t;
struct page { int marker; };
struct folio { struct page page; };
struct vm_area_struct { int marker; };
#define __nocfi
#define noinline __attribute__((noinline))
#define GFP_HIGHUSER_MOVABLE 7
#define IS_ERR(p) false
''' + declarations + wrapper
            code += f'''static struct {kind} result;
static struct vm_area_struct area;
static bool return_null;
''' + signature.replace('read_swap_cache_async', 'fake_reader') + '''
{
    assert(entry.val == 42 && gfp_mask == GFP_HIGHUSER_MOVABLE);
    assert(vma == &area && addr == 0x4000);
'''
            if '-DDFM_SWAP_READ_POLL' in flags:
                code += '    assert(!do_poll);\n'
            if '-DDFM_SWAP_READ_PLUG' in flags:
                code += '    assert(plug == NULL);\n'
            code += '''    return return_null ? NULL : &result;
}
int main(void) {
    bp_bk_cache_fn = fake_reader;
    assert(bp_bk_read_cache((swp_entry_t){42}, &area, 0x4000) ==
''' + ('        &result.page);\n' if kind == 'folio' else '        &result);\n')
            code += '''    return_null = true;
    assert(bp_bk_read_cache((swp_entry_t){42}, &area, 0x4000) == NULL);
    return 0;
}
'''
            source = directory / 'wrapper.c'
            source.write_text(code)
            binary = directory / 'wrapper.exe'
            subprocess.run([args.compiler, '-std=gnu11', '-O2', '-Wall', '-Wextra',
                            '-Werror', *actual, str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
            print('PASS:', kind, suffix, flush=True)
    for signature in (
        '',
        'struct page *read_swap_cache_async(swp_entry_t e, gfp_t g, struct mempolicy *p, unsigned long a, bool b)',
        'struct page *read_swap_cache_async(swp_entry_t e, gfp_t g, struct vm_area_struct *v, unsigned long a, int b)',
        'struct page *read_swap_cache_async(swp_entry_t e, gfp_t g, struct vm_area_struct *v, unsigned long a, bool b, int extra)',
        'struct page *read_swap_cache_async(swp_entry_t e, gfp_t g,',
    ):
        fixture.write_text(signature)
        assert not detected(fixture), signature
    assert not detected(directory / 'missing.c')
    print('PASS: unknown, incomplete and missing signatures disable swap reader')
