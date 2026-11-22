# Qdrive reference attribution

The locked resident walker and swap reader in mem_read_backend.h and the
host MM test fixtures are adapted from the user-supplied Qdrive/bpDrive-main
working tree, licensed under Apache-2.0 (license reproduced alongside).
This is not an unchanged upstream copy.

Changes: DFM RAM-alias lifetime integration, full-range/error semantics, explicit
swap-only dispatch, kernel-buffer entry, and DFM-specific fault-injection tests.
No Qdrive SDK, root identity changes, or write-path changes are imported.

Reference SHA-256:

- hwBreakpointProc_module/memory_access/backing_read.h: a8c1fe8ecd5c8f1da73af7635ba9ef1cf5b1a9e7275dee2908df98b0dbd6b6bd
- hwBreakpointProc_module/memory_access/nc_read.h: 12770c60ab4d0edebd88f6828c81ceb72f8bb977fb163f968a6f12c573d443d5
- hwBreakpointProc_module/Makefile: 8b970259682ef43dc2bb6c36bbdd05e689e69d81d81b3fca2bbf6ad3281254ba
- hwBreakpointProc_module/memory_access/tests/nc_host.c: 44252c680e6ff070788315572aab450beeb560fe04f259c5a28ec8f1c84f581a
- hwBreakpointProc_module/memory_access/tests/backing_host.c: 6965fd84b05f666f4c0d0cecda3a7c1906ece2f6781744ff1772f8a316099fa7
