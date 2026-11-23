#ifndef DFM_MEMORY_READ_BACKEND_H
#define DFM_MEMORY_READ_BACKEND_H

#include <linux/pagemap.h>
#include <linux/sched/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>

/* Adapted from Qdrive/bpDrive-main under Apache-2.0; see
 * docs/third-party/Qdrive-NOTICE.md. Included in mem.c after RAM alias setup.
 * Modifications: unified errno-preserving DFM reads and locked resident copies.
 */
#if defined(CONFIG_SWAP) && defined(DFM_SWAP_READER_KNOWN)
#if !defined(DFM_SWAP_READ_POLL) && !defined(DFM_SWAP_READ_PLUG)
#error "Detected swap reader requires an explicit poll/plug ABI"
#endif
struct swap_iocb;
#ifdef DFM_SWAP_READ_FOLIO
typedef struct folio *bp_bk_cache_result;
#else
typedef struct page *bp_bk_cache_result;
#endif
static bp_bk_cache_result (*bp_bk_cache_fn)(swp_entry_t, gfp_t,
                    struct vm_area_struct *, unsigned long
#ifdef DFM_SWAP_READ_POLL
                    , bool
#endif
#ifdef DFM_SWAP_READ_PLUG
                    , struct swap_iocb **
#endif
                    );
static typeof(&swap_duplicate) bp_bk_duplicate_fn;
#ifdef DFM_SWAP_FOLIO_LOCKS
static typeof(&__folio_lock_killable) bp_bk_lock_fn;
static typeof(&folio_unlock) bp_bk_unlock_fn;
#else
static typeof(&__lock_page_killable) bp_bk_lock_fn;
static typeof(&unlock_page) bp_bk_unlock_fn;
#endif
#ifdef DFM_SWAP_FREE_NR
static typeof(&swap_free_nr) bp_bk_free_fn;
#else
static typeof(&swap_free) bp_bk_free_fn;
#endif
#endif

static unsigned long bp_bk_symbol(const char *name)
{
    char cfi[80];
    unsigned long address;
    snprintf(cfi, sizeof(cfi), "%s.cfi_jt", name);
    address = kallsyms_lookup_name(cfi);
    return address ? address : kallsyms_lookup_name(name);
}

static void bp_backing_init(void)
{
#if defined(CONFIG_SWAP) && defined(DFM_SWAP_READER_KNOWN)
    bp_bk_cache_fn = (void *)bp_bk_symbol("read_swap_cache_async");
    bp_bk_duplicate_fn = (void *)bp_bk_symbol("swap_duplicate");
#ifdef DFM_SWAP_FOLIO_LOCKS
    bp_bk_lock_fn = (void *)bp_bk_symbol("__folio_lock_killable");
    bp_bk_unlock_fn = (void *)bp_bk_symbol("folio_unlock");
#else
    bp_bk_lock_fn = (void *)bp_bk_symbol("__lock_page_killable");
    bp_bk_unlock_fn = (void *)bp_bk_symbol("unlock_page");
#endif
#ifdef DFM_SWAP_FREE_NR
    bp_bk_free_fn = (void *)bp_bk_symbol("swap_free_nr");
#else
    bp_bk_free_fn = (void *)bp_bk_symbol("swap_free");
#endif
    if (!bp_bk_cache_fn || !bp_bk_duplicate_fn || !bp_bk_free_fn ||
        !bp_bk_lock_fn || !bp_bk_unlock_fn)
        pr_warn("dfm: swap backing unavailable cache=%d duplicate=%d free=%d lock=%d unlock=%d\n",
                !!bp_bk_cache_fn, !!bp_bk_duplicate_fn, !!bp_bk_free_fn,
                !!bp_bk_lock_fn, !!bp_bk_unlock_fn);
#elif !defined(CONFIG_SWAP)
    pr_warn("dfm: swap backing unavailable: CONFIG_SWAP is disabled\n");
#else
    pr_warn("dfm: swap backing unavailable: reader ABI was not recognized at build time\n");
#endif
}

#if defined(CONFIG_SWAP) && defined(DFM_SWAP_READER_KNOWN)
static __nocfi noinline int bp_bk_duplicate(swp_entry_t entry)
{
    return bp_bk_duplicate_fn(entry);
}

static __nocfi noinline void bp_bk_free(swp_entry_t entry)
{
#ifdef DFM_SWAP_FREE_NR
    bp_bk_free_fn(entry, 1);
#else
    bp_bk_free_fn(entry);
#endif
}

static __nocfi noinline struct page *bp_bk_read_cache(swp_entry_t entry,
                         struct vm_area_struct *vma, unsigned long address)
{
    bp_bk_cache_result result;
    result = bp_bk_cache_fn(entry, GFP_HIGHUSER_MOVABLE, vma, address
#ifdef DFM_SWAP_READ_POLL
                          , false
#endif
#ifdef DFM_SWAP_READ_PLUG
                          , NULL
#endif
                          );
    if (!result || IS_ERR(result)) return (struct page *)result;
#ifdef DFM_SWAP_READ_FOLIO
    return &result->page;
#else
    return result;
#endif
}

/* Keep the kernel fast/slow lock contract without importing optional KMI
 * symbols. Both callbacks are required before any swap slot or page is held. */
static __nocfi noinline int bp_bk_lock_page(struct page *head)
{
    might_sleep();
#ifdef DFM_SWAP_FOLIO_LOCKS
    if (folio_trylock(page_folio(head))) return 0;
    return bp_bk_lock_fn(page_folio(head));
#else
    if (trylock_page(head)) return 0;
    return bp_bk_lock_fn(head);
#endif
}

static __nocfi noinline void bp_bk_unlock_page(struct page *head)
{
#ifdef DFM_SWAP_FOLIO_LOCKS
    bp_bk_unlock_fn(page_folio(head));
#else
    bp_bk_unlock_fn(head);
#endif
}
#endif

/* Caller holds mmap_read_lock. Take a transient PTE lock using the same
 * detached-table protection as the existing resident walker. Never retain a
 * PTE pointer across I/O and never use a PTE setter or a fault-in helper.
 */
static int bp_bk_pte(struct mm_struct *mm, unsigned long address, pte_t *out,
                     bool duplicate)
{
    pgd_t *pgdp, pgd;
    p4d_t *p4dp, p4d;
    pud_t *pudp, pud;
    pmd_t *pmdp, pmd;
    pte_t *ptep, pte;
    spinlock_t *ptl;
    int rc = -EFAULT;
    pgdp = pgd_offset(mm, address);
    pgd = READ_ONCE(*pgdp);
    if (pgd_none(pgd) || pgd_bad(pgd)) return rc;
    p4dp = p4d_offset(pgdp, address);
    p4d = READ_ONCE(*p4dp);
    if (p4d_none(p4d) || p4d_bad(p4d)) return rc;
    pudp = pud_offset(p4dp, address);
    pud = READ_ONCE(*pudp);
    if (pud_none(pud) || pud_bad(pud)) return rc;
    if (pud_leaf(pud)) return -EOPNOTSUPP;
    rcu_read_lock();
    pmdp = pmd_offset(pudp, address);
    pmd = READ_ONCE(*pmdp);
    if (pmd_none(pmd) || pmd_bad(pmd)) goto out;
    if (pmd_leaf(pmd)) { rc = -EOPNOTSUPP; goto out; }
    ptep = pte_offset_kernel(&pmd, address);
    ptl = pte_lockptr(mm, &pmd);
    spin_lock(ptl);
    if (!pmd_same(pmd, READ_ONCE(*pmdp))) { rc = -EAGAIN; goto unlock; }
    pte = READ_ONCE(*ptep);
    *out = pte;
    if (!duplicate) { rc = 0; goto unlock; }
    if (pte_present(pte)) { rc = -EAGAIN; goto unlock; }
#if defined(CONFIG_SWAP) && defined(DFM_SWAP_READER_KNOWN)
    if (is_swap_pte(pte)) {
        swp_entry_t entry = pte_to_swp_entry(pte);
        if (non_swap_entry(entry)) { rc = -EOPNOTSUPP; goto unlock; }
        /* Pin the swap slot, not a target RAM page. Reuse is forbidden until
         * the final recheck and copy have completed.
         */
        rc = bp_bk_duplicate(entry);
    }
#else
    rc = -EOPNOTSUPP;
#endif
unlock:
    spin_unlock(ptl);
out:
    rcu_read_unlock();
    return rc;
}

/* Return backing bytes only when the same swap PTE still identifies them.
 * The kernel swap reader performs cache lookup, zswap/frontswap handling,
 * zram decompression and storage I/O. No vendor zram offsets are embedded.
 */
static int bp_bk_swap_copy(struct mm_struct *mm, struct vm_area_struct *vma,
                       unsigned long address, void *buffer, size_t length)
{
#if defined(CONFIG_SWAP) && defined(DFM_SWAP_READER_KNOWN)
    struct page *page, *head;
    swp_entry_t entry, base;
    pte_t original, check;
    unsigned long index;
    void *mapping;
    int rc;
    if (!bp_bk_cache_fn || !bp_bk_duplicate_fn || !bp_bk_free_fn ||
        !bp_bk_lock_fn || !bp_bk_unlock_fn)
        return -EOPNOTSUPP;
    rc = bp_bk_pte(mm, address, &original, true);
    if (rc) return rc;
    entry = pte_to_swp_entry(original);
    page = bp_bk_read_cache(entry, vma, address & PAGE_MASK);
    if (!page || IS_ERR(page)) {
        rc = page ? PTR_ERR(page) : -EIO;
        goto free_slot;
    }
    head = compound_head(page);
    /* Killable wait also waits for asynchronous swap I/O to complete. */
    rc = bp_bk_lock_page(head);
    if (rc) goto put;
    /* folio.swap aliases page.private on newer trees; 6.1 exposes only
     * private. Use the stable base-page accessor on every supported branch.
     */
    base.val = page_private(head);
#ifdef DFM_SWAP_FOLIO_LOCKS
    if (!folio_test_swapcache(page_folio(head)) ||
#else
    if (!PageSwapCache(head) ||
#endif
        swp_type(base) != swp_type(entry) ||
        swp_offset(entry) < swp_offset(base)) { rc = -EAGAIN; goto unlock; }
    index = swp_offset(entry) - swp_offset(base);
    if (index >= (1UL << compound_order(head))) { rc = -EAGAIN; goto unlock; }
    if (!PageUptodate(head) || PageError(head)) { rc = -EIO; goto unlock; }
    mapping = page_address(head);
    if (!mapping) { rc = -EOPNOTSUPP; goto unlock; }
    rc = bp_bk_pte(mm, address, &check, false);
    if (rc || !pte_same(check, original)) { rc = -EAGAIN; goto unlock; }
    memcpy(buffer, (char *)mapping + index * PAGE_SIZE +
           offset_in_page(address), length);
    rc = bp_bk_pte(mm, address, &check, false);
    if (rc || !pte_same(check, original)) rc = -EAGAIN;
unlock:
    bp_bk_unlock_page(head);
put:
    put_page(page);
free_slot:
    bp_bk_free(entry);
    return rc;
#else
    return -EOPNOTSUPP;
#endif
}

/* Caller holds the RAM alias lifetime read lock. Check the whole range. */
static void *mem_nc_range(phys_addr_t pa, size_t length)
{
    unsigned long i;
    if (!__linearmap_info_ok || !__linearmap_info_arr || !length) return NULL;
    for (i = 0; i < __linearmap_info_cnt; ++i) {
        const struct __linearmap_info *r = &__linearmap_info_arr[i];
        if (pa >= r->phys && pa - r->phys < r->size &&
            length <= r->size - (pa - r->phys) && r->virt_nc)
            return (void *)(r->virt_nc + (pa - r->phys));
    }
    return NULL;
}

static void mem_clean_phys(phys_addr_t pa, size_t length)
{
    unsigned long ctr, line, at, end;
    asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
    line = 4UL << ((ctr >> 16) & 0xf);
    at = (unsigned long)phys_to_virt(pa);
    end = (at + length + line - 1) & ~(line - 1);
    for (at &= ~(line - 1); at < end; at += line)
        asm volatile("dc cvac, %0" : : "r"(at) : "memory");
    asm volatile("dsb sy" : : : "memory");
}

static int mem_copy_phys(phys_addr_t pa, void *buffer, size_t length, bool clean)
{
    void *source = mem_nc_range(pa, length);
    if (!source) return -EFAULT;
    if (clean) mem_clean_phys(pa, length);
    memcpy(buffer, source, length);
    return 0;
}

static int mem_resident_copy(struct mm_struct *mm, unsigned long addr,
			   void *buf, size_t len, bool clean_cache)
{
	struct vm_area_struct *vma;
	pgd_t *pgdp, pgd;
	p4d_t *p4dp, p4d;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	int ret = -EFAULT;

	if (!len || len > PAGE_SIZE - offset_in_page(addr)) return -EINVAL;
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start || len > vma->vm_end - addr)
		return ret;
	if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP | VM_HUGETLB))
		return -EOPNOTSUPP;
	pgdp = pgd_offset(mm, addr);
	pgd = READ_ONCE(*pgdp);
	if (pgd_none(pgd) || pgd_bad(pgd)) return ret;
	p4dp = p4d_offset(pgdp, addr);
	p4d = READ_ONCE(*p4dp);
	if (p4d_none(p4d) || p4d_bad(p4d)) return ret;
	pudp = pud_offset(p4dp, addr);
	ptl = pud_lock(mm, pudp);
	pud = READ_ONCE(*pudp);
	if (pud_leaf(pud)) {
		if (pud_pfn(pud))
			ret = mem_copy_phys(PFN_PHYS(pud_pfn(pud)) +
				(addr & ~PUD_MASK), buf, len, clean_cache);
		spin_unlock(ptl);
		return ret;
	}
	spin_unlock(ptl);
	if (pud_none(pud) || pud_bad(pud)) return ret;

	rcu_read_lock();
	pmdp = pmd_offset(pudp, addr);
	ptl = pmd_lock(mm, pmdp);
	pmd = READ_ONCE(*pmdp);
	if (pmd_leaf(pmd)) {
		if (pmd_pfn(pmd))
			ret = mem_copy_phys(PFN_PHYS(pmd_pfn(pmd)) +
				(addr & ~PMD_MASK), buf, len, clean_cache);
		spin_unlock(ptl);
		goto out;
	}
	spin_unlock(ptl);
	if (pmd_none(pmd) || pmd_bad(pmd)) goto out;
	ptep = pte_offset_kernel(&pmd, addr);
	ptl = pte_lockptr(mm, &pmd);
	spin_lock(ptl);
	if (!pmd_same(pmd, READ_ONCE(*pmdp))) {
        ret = -EAGAIN;
    } else {
		pte = READ_ONCE(*ptep);
		if (pte_present(pte) && pte_pfn(pte))
			ret = mem_copy_phys(PFN_PHYS(pte_pfn(pte)) +
				(addr & ~PAGE_MASK), buf, len, clean_cache);
        else if (is_swap_pte(pte)) ret = -ENODATA;
	}
	spin_unlock(ptl);
out:
	rcu_read_unlock();
	return ret;
}

/* A successful return always means the entire request was copied. On failure,
 * a prefix may have been copied: ioctl callers must discard the whole output.
 * Never usercopy while holding mmap/leaf/alias/swap locks (self-read can fault).
 */
static long mem_copy_range(struct mm_struct *mm, unsigned long address,
                           void *output, size_t count, bool user_output, bool clean)
{
    unsigned long start = untagged_addr(address);
    size_t done = 0;
    char *buffer;
    int rc = 0;
    if (!mm || !output || !count) return -EINVAL;
    if (start >= TASK_SIZE || count > TASK_SIZE - start) return -EFAULT;
    if (user_output && !access_ok((void __user *)output, count)) return -EFAULT;
    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) return -ENOMEM;
    while (done < count) {
        unsigned long va = start + done;
        size_t length = min_t(size_t, count - done, PAGE_SIZE - offset_in_page(va));
        struct vm_area_struct *vma;
        if (fatal_signal_pending(current)) { rc = -EINTR; break; }
        down_read(&__linearmap_rwlock);
        mmap_read_lock(mm);
        vma = find_vma(mm, va);
        if (!vma || va < vma->vm_start || length > vma->vm_end - va) rc = -EFAULT;
        else if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP | VM_HUGETLB))
            rc = -EOPNOTSUPP;
        else rc = mem_resident_copy(mm, va, buffer, length, clean);
        /* Retain the stable VMA, but never the NC lock over sleeping swap I/O. */
        up_read(&__linearmap_rwlock);
        if (rc == -ENODATA) rc = bp_bk_swap_copy(mm, vma, va, buffer, length);
        mmap_read_unlock(mm);
        if (rc) break;
        if (user_output) {
            if (copy_to_user((char __user *)output + done, buffer, length)) {
                rc = -EFAULT; break;
            }
        } else memcpy((char *)output + done, buffer, length);
        done += length;
        if (done < count) cond_resched();
    }
    kfree(buffer);
    return rc;
}
#endif
