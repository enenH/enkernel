# Linux-android-arm64 reference

Reference: https://github.com/lsnbm/Linux-android-arm64
Commit: dc99e8dc7a228520f0dbd5cd288355dbbc17f433

The UXN guard/PTE identity and inner-shareable TLB invalidation design in
pte_bp.c was informed by lsdriver/arm64_ptedbg.h and lsdriver/export_fun.h.
This adaptation uses native single stepping, MMU invalidation and file-owned
sessions. It does not import the reference's instruction emulator, UDF/shadow
backend, ghost pages, register modification or mprotect replacement.

Upstream license (retained for the referenced/adapted portions):

MIT License

Copyright (c) 2025 LsLucky

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
