/* Adapted Qdrive MM fixture; see docs/third-party/Qdrive-NOTICE.md. */
/* Kernel API model; the walker, transfer and entry functions are production C. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#define __user
#define PAGE_SIZE 4096UL
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PMD_SIZE (512UL * PAGE_SIZE)
#define PMD_MASK (~(PMD_SIZE - 1))
#define PUD_SIZE (512UL * PMD_SIZE)
#define PUD_MASK (~(PUD_SIZE - 1))
#define TASK_SIZE 0x80000000UL
#define offset_in_page(a) ((a) & (PAGE_SIZE - 1))
#define untagged_addr(a) ((a) & 0x00ffffffffffffffULL)
#define min_t(t,a,b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define READ_ONCE(v) (v)
#define PFN_PHYS(pfn) ((phys_addr_t)(pfn) * PAGE_SIZE)
#define VM_IO 1U
#define VM_PFNMAP 2U
#define VM_MIXEDMAP 4U
#define VM_HUGETLB 8U
#define VM_READ 16U
#define GFP_KERNEL 0

typedef uint64_t phys_addr_t;
typedef struct { unsigned long pfn; unsigned int flags; } entry_t;
typedef entry_t pgd_t;
typedef entry_t p4d_t;
typedef entry_t pud_t;
typedef entry_t pmd_t;
typedef entry_t pte_t;
typedef int spinlock_t;
enum { TABLE = 1, LEAF = 2, PRESENT = 4, BAD = 8, PROTNONE = 16, CONTIG = 32 };
enum { PAGES = 6 };
static const unsigned long base = 0x400000;
static const phys_addr_t phys_base = 0x1000000;
static unsigned char ram[PAGES * PAGE_SIZE], cached[PAGES * PAGE_SIZE];
static pgd_t pgd;
static p4d_t p4d;
static pud_t pud;
static pmd_t pmd;
static pte_t ptes[PAGES];
#define MT_NORMAL 1u
#define PTE_ATTRINDX_MASK 7u
#define PTE_ATTRINDX(x) (x)
#define pgprot_val(x) (x)
struct vm_area_struct { unsigned long vm_start, vm_end, vm_flags, vm_page_prot; };
struct mm_struct { int users; };
static struct vm_area_struct vma;
static struct mm_struct mm;
static int mmap_depth, nc_depth, leaf_depth, rcu_depth, clean_calls, copies;
static int allocations, fail_alloc, fail_copy, reschedules;
static size_t copy_prefix;
static bool mutate_pmd, unmap_on_usercopy, teardown_on_usercopy, no_vma;
static int __linearmap_rwlock;
static spinlock_t pud_ptl = 1, pmd_ptl = 2, pte_ptl = 3;
struct __linearmap_info { phys_addr_t phys; size_t size; uintptr_t virt_nc; };
static struct __linearmap_info regions[2], *__linearmap_info_arr=regions;
static unsigned long __linearmap_info_cnt=2;
static int __linearmap_info_ok=1;

static void down_read(int *lock) { assert(lock == &__linearmap_rwlock); assert(!nc_depth); ++nc_depth; }
static void up_read(int *lock) { assert(lock == &__linearmap_rwlock); assert(nc_depth == 1); --nc_depth; }
static void mmap_read_lock(struct mm_struct *m) { assert(m->users); assert(nc_depth); assert(!mmap_depth); ++mmap_depth; }
static void mmap_read_unlock(struct mm_struct *m) { (void)m; assert(mmap_depth == 1 && !leaf_depth && !rcu_depth); --mmap_depth; }
static void rcu_read_lock(void) { assert(mmap_depth); ++rcu_depth; }
static void rcu_read_unlock(void) { assert(rcu_depth == 1 && !leaf_depth); --rcu_depth; }
static void spin_lock(spinlock_t *lock)
{
    assert(mmap_depth && !leaf_depth);
    leaf_depth = *lock;
    if (*lock == 3 && mutate_pmd) { ++pmd.pfn; mutate_pmd = false; }
}
static void spin_unlock(spinlock_t *lock) { assert(leaf_depth == *lock); leaf_depth = 0; }
static spinlock_t *pud_lock(struct mm_struct *m, pud_t *p) { (void)m; (void)p; spin_lock(&pud_ptl); return &pud_ptl; }
static spinlock_t *pmd_lock(struct mm_struct *m, pmd_t *p) { (void)m; (void)p; spin_lock(&pmd_ptl); return &pmd_ptl; }
static spinlock_t *pte_lockptr(struct mm_struct *m, pmd_t *p) { (void)m; (void)p; return &pte_ptl; }
static struct vm_area_struct *find_vma(struct mm_struct *m, unsigned long a)
{ (void)m; assert(mmap_depth); return no_vma || a >= vma.vm_end ? NULL : &vma; }
static pgd_t *pgd_offset(struct mm_struct *m, unsigned long a) { (void)m; (void)a; return &pgd; }
static p4d_t *p4d_offset(pgd_t *p, unsigned long a) { (void)p; (void)a; return &p4d; }
static pud_t *pud_offset(p4d_t *p, unsigned long a) { (void)p; (void)a; return &pud; }
static pmd_t *pmd_offset(pud_t *p, unsigned long a) { (void)p; (void)a; assert(rcu_depth); return &pmd; }
static pte_t *pte_offset_kernel(pmd_t *p, unsigned long a)
{ (void)p; assert(rcu_depth); assert(a >= base && a < base + sizeof(ram)); return &ptes[(a - base) / PAGE_SIZE]; }
#define pgd_none(e) (!(e).flags)
#define pgd_bad(e) ((e).flags & BAD)
#define p4d_none(e) pgd_none(e)
#define p4d_bad(e) pgd_bad(e)
#define pud_none(e) pgd_none(e)
#define pud_bad(e) pgd_bad(e)
#define pmd_none(e) pgd_none(e)
#define pmd_bad(e) pgd_bad(e)
#define pud_leaf(e) ((e).flags & LEAF)
#define pmd_leaf(e) pud_leaf(e)
#define pud_pfn(e) ((e).pfn)
#define pmd_pfn(e) ((e).pfn)
#define pte_pfn(e) ((e).pfn)
#define pte_present(e) ((e).flags & (PRESENT | PROTNONE))
#define pmd_same(a,b) ((a).pfn == (b).pfn && (a).flags == (b).flags)

static bool access_ok(void *p, size_t n) { return (uintptr_t)p > 4096 && n <= (size_t)LONG_MAX; }
static void *kmalloc(size_t n, int flags) { (void)flags; if (fail_alloc) return NULL; ++allocations; return malloc(n); }
static void kfree(void *p) { assert(allocations == 1); --allocations; free(p); }
static void cond_resched(void) { assert(!leaf_depth && !mmap_depth && !nc_depth && !rcu_depth); ++reschedules; }
static void mem_clean_phys(phys_addr_t phys, size_t n)
{
    assert(leaf_depth && mmap_depth && nc_depth);
    assert(phys >= phys_base && phys - phys_base + n <= sizeof(ram));
    memcpy(ram + phys - phys_base, cached + phys - phys_base, n);
    ++clean_calls;
}
static unsigned long copy_to_user(void *dst, const void *src, size_t n)
{
    assert(!leaf_depth && !mmap_depth && !nc_depth && !rcu_depth);
    ++copies;
    size_t done = fail_copy == copies ? copy_prefix : n;
    assert(done <= n);
    memcpy(dst, src, done);
    if (unmap_on_usercopy) { ptes[1].flags = 0; unmap_on_usercopy = false; }
    if (teardown_on_usercopy) __linearmap_info_cnt = 0;
    return (unsigned long)(n - done);
}


#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define current NULL
#define CONFIG_SWAP 1
#define SWAPPED 64u
#define ERESTARTSYS 512
typedef struct { unsigned long val; } swp_entry_t;
struct page {
    unsigned char bytes[2 * PAGE_SIZE];
    unsigned long entry, order;
    int references, locks;
    bool uptodate, error, cached;
};
static struct page cached_page;
static int slot_refs, reads, mode, releases;
static bool interrupted, mutate_on_copy;
static unsigned slow_locks, unlocks;
static bool force_slow_lock;
static int fake_fn;
static int *bp_bk_cache_fn=&fake_fn, *bp_bk_duplicate_fn=&fake_fn, *bp_bk_free_fn=&fake_fn;
static bool pte_same(pte_t a, pte_t b) { return a.pfn==b.pfn && a.flags==b.flags; }
static bool is_swap_pte(pte_t p) { return p.flags==SWAPPED; }
static swp_entry_t pte_to_swp_entry(pte_t p) { return (swp_entry_t){p.pfn}; }
static unsigned long swp_type(swp_entry_t e) { return e.val>>24; }
static unsigned long swp_offset(swp_entry_t e) { return e.val&0xffffff; }
static bool non_swap_entry(swp_entry_t e) { return swp_type(e)>=32; }
static int bp_bk_duplicate(swp_entry_t e) {
    assert(leaf_depth && mmap_depth && swp_offset(e));
    if(mode==1)return -ENOMEM;
    ++slot_refs;return 0;
}
static void bp_bk_free(swp_entry_t e) {
    (void)e;assert(slot_refs==1 && !leaf_depth && !cached_page.locks);
    --slot_refs;++releases;
}
static struct page *bp_bk_read_cache(swp_entry_t e, struct vm_area_struct *v,
                                    unsigned long a) {
    (void)v;(void)a;assert(slot_refs==1 && mmap_depth && !leaf_depth && !rcu_depth);
    ++reads;
    if(mode==2)return NULL;
    if(mode==3)return ERR_PTR(-EIO);
    if(mode==4)ptes[0].flags=PRESENT;
    cached_page.entry=e.val-1; /* Entry identifies tail of a two-page folio. */
    ++cached_page.references;
    return &cached_page;
}
static struct page *compound_head(struct page *p) { return p; }
static unsigned long compound_order(struct page *p) { return p->order; }
static unsigned long page_private(struct page *p) { return p->entry; }
static bool PageSwapCache(struct page *p) { return p->cached; }
static bool PageUptodate(struct page *p) { return p->uptodate; }
static bool PageError(struct page *p) { return p->error; }
static void *page_address(struct page *p) { return p->bytes; }
static int trylock_page(struct page *p) {
    assert(!leaf_depth && !p->locks);
    if(force_slow_lock || mode==5)return 0;
    ++p->locks;return 1;
}
static int lock_page_killable(struct page *p) {
    assert(!leaf_depth && !p->locks);
    ++slow_locks;
    if(mode==5)return -ERESTARTSYS;
    ++p->locks;return 0;
}
static void unlock_page(struct page *p) { assert(p->locks==1);--p->locks;++unlocks; }
#define __nocfi
#define noinline __attribute__((noinline))
#define might_sleep() assert(!leaf_depth && !rcu_depth && !nc_depth)
#ifdef DFM_SWAP_FOLIO_LOCKS
struct folio;
static struct folio *page_folio(struct page *p) { return (struct folio *)p; }
static int folio_trylock(struct folio *f) { return trylock_page((struct page *)f); }
static bool folio_test_swapcache(struct folio *f) { return PageSwapCache((struct page *)f); }
static int fake_folio_lock(struct folio *f) { return lock_page_killable((struct page *)f); }
static void fake_folio_unlock(struct folio *f) { unlock_page((struct page *)f); }
static int (*bp_bk_lock_fn)(struct folio *)=fake_folio_lock;
static void (*bp_bk_unlock_fn)(struct folio *)=fake_folio_unlock;
#else
static int (*bp_bk_lock_fn)(struct page *)=lock_page_killable;
static void (*bp_bk_unlock_fn)(struct page *)=unlock_page;
#endif
static void put_page(struct page *p) { assert(p->references==1 && !p->locks);--p->references; }
static int backing_spin_lock(spinlock_t *p) {
    assert(mmap_depth && !leaf_depth);leaf_depth=*p;
    if (*p == 3 && mutate_pmd) { ++pmd.pfn; mutate_pmd = false; }
    return 0;
}
#define spin_lock(p) ((void)backing_spin_lock(p))
static void *backing_memcpy(void *out, const void *in, size_t n) {
    void *r=memcpy(out,in,n);
    if(mutate_on_copy){ptes[0].pfn++;mutate_on_copy=false;}
    return r;
}
#define memcpy backing_memcpy
static bool fatal_signal_pending(void *task) { (void)task;return interrupted; }

#include "read_under_test.h"
#undef memcpy
static void reset(void)
{
    assert(!allocations && !leaf_depth && !mmap_depth && !rcu_depth && !nc_depth);
    assert(!slot_refs && !cached_page.references && !cached_page.locks);
    mm.users=1;
    vma=(struct vm_area_struct){base,base+sizeof(ram),VM_READ,MT_NORMAL};
    pgd=(pgd_t){0,TABLE};p4d=(p4d_t){0,TABLE};pud=(pud_t){0,TABLE};pmd=(pmd_t){1,TABLE};
    for(unsigned i=0;i<PAGES;++i){
        ptes[i]=(pte_t){phys_base/PAGE_SIZE+i,PRESENT};
        memset(ram+i*PAGE_SIZE,i+1,PAGE_SIZE);memset(cached+i*PAGE_SIZE,0x81+i,PAGE_SIZE);
    }
    regions[0]=(struct __linearmap_info){phys_base,sizeof(ram),(uintptr_t)ram};
    regions[1]=(struct __linearmap_info){0,0,0};
    __linearmap_info_cnt=2;__linearmap_info_ok=1;__linearmap_info_arr=regions;
    allocations=fail_alloc=fail_copy=clean_calls=copies=reschedules=0;copy_prefix=0;
    mutate_pmd=unmap_on_usercopy=teardown_on_usercopy=no_vma=false;
    reads=mode=releases=0;interrupted=mutate_on_copy=force_slow_lock=false;
    slow_locks=unlocks=0;
    bp_bk_cache_fn=bp_bk_duplicate_fn=bp_bk_free_fn=&fake_fn;
#ifdef DFM_SWAP_FOLIO_LOCKS
    bp_bk_lock_fn=fake_folio_lock;bp_bk_unlock_fn=fake_folio_unlock;
#else
    bp_bk_lock_fn=lock_page_killable;bp_bk_unlock_fn=unlock_page;
#endif
    cached_page=(struct page){.order=1,.uptodate=true,.cached=true};
    memset(cached_page.bytes,0x19,PAGE_SIZE);memset(cached_page.bytes+PAGE_SIZE,0x9c,PAGE_SIZE);
}
static void swapped(void){reset();ptes[0]=(pte_t){17,SWAPPED};}
static long execute(unsigned long at,void *output,size_t n,bool user,bool clean)
{
    long rc=mem_copy_range(&mm,at,output,n,user,clean);
    assert(!allocations && !leaf_depth && !mmap_depth && !rcu_depth && !nc_depth);
    assert(!slot_refs && !cached_page.references && !cached_page.locks);
    return rc;
}
int main(void)
{
    unsigned char output[3*PAGE_SIZE];
    reset();assert(!execute(base+PAGE_SIZE-17,output,PAGE_SIZE+23,true,false));
    assert(output[0]==1 && output[16]==1 && output[17]==2 && output[PAGE_SIZE+22]==3);
    assert(copies==3 && reschedules==2 && !clean_calls);
    reset();assert(!execute(base,output,17,true,true)&&output[0]==0x81&&clean_calls==1);
    reset();ptes[0].flags|=CONTIG;ptes[1].pfn+=2;
    assert(!execute(base,output,2*PAGE_SIZE,true,false)&&output[PAGE_SIZE]==4);
    reset();ptes[0].flags=PROTNONE;assert(!execute(base,output,17,true,false));
    reset();pud=(pud_t){phys_base/PAGE_SIZE,LEAF};
    assert(execute(0,output,1,true,false)==-EFAULT); /* outside VMA */
    vma.vm_start=0;assert(!execute(0,output,17,true,false)&&output[0]==1);
    reset();pmd=(pmd_t){phys_base/PAGE_SIZE,LEAF};
    assert(!execute(base,output,17,true,false)&&output[0]==1);
    reset();mutate_pmd=true;assert(execute(base,output,17,true,false)==-EAGAIN);
    reset();ptes[0]=(pte_t){0,0};assert(execute(base,output,17,true,false)==-EFAULT&&!reads);
    reset();regions[0].size=1;assert(execute(base,output,17,true,false)==-EFAULT);
    reset();__linearmap_info_ok=0;assert(execute(base,output,17,true,false)==-EFAULT);
    reset();vma.vm_flags|=VM_PFNMAP;assert(execute(base,output,17,true,false)==-EOPNOTSUPP);
    reset();fail_alloc=1;assert(execute(base,output,17,true,false)==-ENOMEM);
    reset();assert(execute(TASK_SIZE-3,output,8,true,false)==-EFAULT);
    reset();assert(execute(base,NULL,8,true,false)==-EINVAL);
    reset();fail_copy=1;copy_prefix=3;memset(output,0x55,17);
    assert(execute(base,output,17,true,false)==-EFAULT&&output[2]==1&&output[3]==0x55);
    reset();unmap_on_usercopy=true;memset(output,0x55,sizeof(output));
    assert(execute(base,output,2*PAGE_SIZE,true,false)==-EFAULT&&output[PAGE_SIZE]==0x55);
    reset();teardown_on_usercopy=true;assert(execute(base,output,2*PAGE_SIZE,true,false)==-EFAULT);
    swapped();pte_t original=ptes[0];
    assert(!execute(base,output,2*PAGE_SIZE,true,false)&&output[0]==0x9c&&output[PAGE_SIZE]==2);
    assert(pte_same(original,ptes[0])&&reads==1&&releases==1&&unlocks==1);
    swapped();assert(!execute(base+PAGE_SIZE-5,output,10,false,false));
    assert(output[0]==0x9c&&output[5]==2&&!copies);
    swapped();force_slow_lock=true;assert(!execute(base,output,64,true,false)&&slow_locks==1);
    for(int failure=1;failure<=5;++failure){
        swapped();mode=failure;memset(output,0x55,64);
        assert(execute(base,output,64,true,false)<0&&output[0]==0x55);
        assert(releases==(failure==1?0:1));
    }
    swapped();bp_bk_lock_fn=NULL;assert(execute(base,output,64,true,false)==-EOPNOTSUPP&&!reads&&!releases);
    ptes[0]=ptes[1];assert(!execute(base,output,64,true,false)&&!reads);
    swapped();bp_bk_unlock_fn=NULL;assert(execute(base,output,64,true,false)==-EOPNOTSUPP);
    swapped();bp_bk_cache_fn=NULL;assert(execute(base,output,64,true,false)==-EOPNOTSUPP);
    swapped();cached_page.uptodate=false;assert(execute(base,output,64,true,false)==-EIO);
    swapped();cached_page.error=true;assert(execute(base,output,64,true,false)==-EIO);
    swapped();cached_page.cached=false;assert(execute(base,output,64,true,false)==-EAGAIN);
    swapped();cached_page.order=0;assert(execute(base,output,64,true,false)==-EAGAIN);
    swapped();mutate_on_copy=true;memset(output,0x55,64);
    assert(execute(base,output,64,true,false)==-EAGAIN&&output[0]==0x55);
    swapped();ptes[0].pfn=33UL<<24;assert(execute(base,output,64,true,false)==-EOPNOTSUPP&&!reads);
    swapped();interrupted=true;assert(execute(base,output,64,true,false)==-EINTR&&!reads);
    reset();assert(!slot_refs&&!cached_page.references&&!cached_page.locks);
    puts("PASS: DFM resident/swap production reader: locks, mixed pages, compound offsets, cleanup, races, errors and no PTE mutation");
    return 0;
}
