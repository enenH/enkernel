# Resident and swap-backed memory reads

MEM_IOC_READ, MEM_IOC_READ_CACHE and the in-kernel mem_read_ctx_read path now
share a bounded page-sized reader. The old unlocked physical walker returned
EFAULT for every nonresident PTE and could race unmap/reclaim while copying.

The implementation follows the supplied Qdrive/bpDrive-main resident and backing
readers (attribution and source hashes in third-party/Qdrive-NOTICE.md):

- Resident ordinary RAM: hold the alias lifetime lock, mmap read lock and the
  appropriate leaf lock while copying to a private kernel buffer. Revalidate the
  PMD after taking the PTE lock. Continuous entries use their own PFNs. Clean
  mode retains CTR_EL0 DminLine cache cleaning before reading the NC alias.
- Swap: identify a genuine swap PTE, reject migration/device/other exceptional
  entries, duplicate its slot under the PTE lock, then release leaf/RCU/alias
  locks before calling the kernel swap-cache reader. The kernel supplies zram,
  zswap/frontswap or storage data; no compression or vendor-offset code is copied.
- Lock the returned page/folio with killable waiting, validate swapcache identity,
  compound-page offset and I/O completion, and check the same target PTE before
  and after the copy. Release page and slot references on every exit.
- Never install a target PTE or fault a target virtual address in. Reading may
  allocate/populate swap cache and perform I/O; it is not a zero-side-effect or
  fixed-latency operation. Holes, exceptional entries and unsupported mappings
  fail explicitly. A concurrent PTE change returns EAGAIN.
- Usercopy occurs only after all target/alias/swap locks are released, including
  self reads whose output can fault. Kernel-buffer requests use the same page
  backend. Existing ioctl success means the entire range copied; a failed call
  can leave an invalid prefix and consumers must discard the whole output.

No request ABI, SDK signature, authentication, process-memory write or injection
policy is changed. The separate process-memory session still uses its existing
GUP-backed policy; this patch covers the ordinary NC read entry points. A mapping
query still describes resident physical identity, not a synthesized swap PFN.

Swap function signatures are selected from the actual build kernel tree rather
than a version-only guess. An unrecognized or absent source declaration disables
the optional swap path; CI checks that all shipped KMI builds actually enable it.
The detector reads the complete `read_swap_cache_async` signature, including
the transitional Android six-argument ABI (`bool do_poll, struct swap_iocb **`).
The presence of `swap_iocb` elsewhere in the kernel does not identify this ABI.
Page/folio return types and poll/plug arguments are selected independently; an
unknown argument list disables the reader instead of making an unsafe call.
Optional cache/slot/lock symbols are resolved as a
complete set; unavailable helpers disable swap reads with EOPNOTSUPP while
resident reads remain usable. Matching kernel/KMI modules are still required.

## Validation

Run python3 tests/run_memory_read_host.py. It executes production walker,
swap lifecycle and copy-loop code with an MM fault model at O0/O2 for both page
and folio locking. Covered: resident/cache/cross-page copies, PTE/PMD/PUD,
PROT_NONE, contiguous PFNs, detached PTE tables, alias teardown, mixed swap/RAM,
compound offsets, interrupted lock waits, unavailable callbacks, stale PTEs,
I/O errors, partial usercopy, buffer/range rejection and reference cleanup.
This is not proof of real hardware MMU/cache behavior or vendor ABI compatibility.
Run `python3 tests/run_swap_reader_abi_host.py` to exercise source-signature
detection and compile/run the production call wrapper for page/folio returns
and all supported poll/plug argument combinations. This test also checks that
unknown and incomplete signatures fail closed.

The Android SDK build includes dfm_memory_read_check. With the matching module
already loaded, run it as root on an authorized test device. It uses only its
own anonymous memory, verifies normal/cache reads, requests MADV_PAGEOUT, and
requires /proc/self/pagemap evidence of swap entries. It compares the returned
bytes against saved data and verifies those swap slots remain nonresident.
Exit 77 means no swap entry was observed: it is a skip, not a pass. The test never
loads/unloads modules or changes root/SELinux settings.
It reports the kernel release, capability response and exact SDK ioctl result
on read failure. Capability bits do not identify the loaded module commit or
prove that the swap backend is enabled. Each read gets a freshly poisoned
output buffer, so a previous successful read cannot mask missing output.

Local host checks and Android SDK/test builds passed. Six-KMI CI results and
real-device results must be recorded separately; no device success is implied by
compilation. Development-branch pushes now build without publishing a release;
PR artifacts and main-branch releases retain their existing paths.

On PLZ110, the previously loaded driver passed resident tests but returned
EFAULT for the observed swapped-page fixture. Boot and system process identities
remained unchanged. This reproduces the old failure; it is not a new-module
success claim. The test does not unload the existing driver.
