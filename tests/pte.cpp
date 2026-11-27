// SPDX-License-Identifier: GPL-2.0-only
// Uses only a forked child's private code. Requires the matching module loaded.
#include <dfm/driver.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void require(bool ok, const char* what) {
    if (!ok) { std::fprintf(stderr, "FAIL: %s (errno=%d)\n", what, errno); throw std::runtime_error(what); }
}
static void wait_stopped(pid_t pid) {
    int status = 0;
    require(waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status), "child stop");
}
static bool raw_invalid(dfm_pte_set_req& r) {
    errno = 0;
    return ioctl(dfm::native_handle(), DFM_IOCTL_PTE_SET, &r) == -1 && errno == EINVAL;
}
static int run() {
    if (getuid() != 0) { std::puts("SKIP: root required for target ptrace policy"); return 77; }
    require(dfm::init(), "driver connection");
    dfm_pte_info_req info{};
    const auto result = dfm::pte_info(info);
    if (result == -ENOTTY || (!result && !(info.flags & DFM_PTE_INFO_AVAILABLE))) {
        std::printf("SKIP: PTE backend unavailable (%ld/%d)\n", result, info.backend_errno);
        dfm::close(); return 77;
    }
    require(result == 0 && info.abi_version == 1, "PTE information");
    const auto page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void* code = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(code != MAP_FAILED, "private fixture page");
    const uint32_t instructions[] = {0x91000400, 0xd65f03c0}; // ADD X0,X0,#1; RET
    std::memcpy(code, instructions, sizeof(instructions));
    __builtin___clear_cache(static_cast<char*>(code), static_cast<char*>(code) + sizeof(instructions));
    require(mprotect(code, page_size, PROT_READ | PROT_EXEC) == 0, "RX fixture");
    const pid_t child = fork(); require(child >= 0, "fork fixture");
    if (!child) {
        raise(SIGSTOP);
        auto fn = reinterpret_cast<uint64_t (*)(uint64_t)>(code);
        for (unsigned batch = 0; batch < 3; ++batch) {
            for (uint64_t i = 0; i < 100; ++i) if (fn(i) != i + 1) _exit(3);
            raise(SIGSTOP);
        }
        _exit(0);
    }
    struct Cleanup {
        pid_t pid; void* code; size_t size;
        ~Cleanup() { dfm::pte_clear(); if (pid > 0) { kill(pid, SIGKILL); waitpid(pid, nullptr, 0); }
                     munmap(code, size); dfm::close(); }
    } cleanup{child, code, page_size};
    wait_stopped(child);
    const uint64_t address = reinterpret_cast<uint64_t>(code);
    dfm_pte_set_req bad{}; bad.abi_version = 0; bad.pid = child;
    bad.point_count = 1; bad.addresses[0] = address;
    require(raw_invalid(bad), "invalid ABI rejected by kernel");
    bad.abi_version = 1; bad.flags = 1;
    require(raw_invalid(bad), "reserved flags rejected by kernel");
    require(dfm::pte_set(child, &address, 1) == 0, "set PTE breakpoint");
    require(dfm::pte_set(child, &address, 1) == -EALREADY, "owned session not replaced");
    auto out = std::make_unique<dfm_pte_snapshot>();
    for (unsigned batch = 0; batch < 2; ++batch) {
        require(kill(child, SIGCONT) == 0, "resume child"); wait_stopped(child);
        require(dfm::pte_read(*out) == 0, "read snapshot");
        require(out->total_hits == 100ULL * (batch + 1), "persistent exact hits on isolated child");
        require(out->record_count == 64 && out->dropped == out->total_hits - 64,
                "bounded ring overflow");
        require(out->last_error == 0 && out->rearms >= out->total_hits && out->armed_pages == 1,
                "native step rearms page");
        const auto& last = out->records[out->record_count - 1];
        require(last.address == address && last.pc == address && last.x[0] == 99,
                "GPR snapshot before original instruction");
        require(std::memcmp(code, instructions, sizeof(instructions)) == 0, "original instructions unchanged");
    }
    require(dfm::pte_clear() == 0 && dfm::pte_clear() == 0, "idempotent clear");
    require(kill(child, SIGCONT) == 0, "resume after clear"); wait_stopped(child);
    require(dfm::pte_read(*out) == -ENOENT, "clear removes session");
    require(kill(child, SIGCONT) == 0, "finish child");
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "native execution preserved after clear");
    cleanup.pid = -1;
    std::puts("DFM_PTE_DEVICE_PASS");
    return 0;
}
int main() { try { return run(); } catch (const std::exception&) { return 1; } }
