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
extern "C" const unsigned char dfm_pte_vector_begin[], dfm_pte_vector_point[], dfm_pte_vector_end[];
struct VectorImage { uint64_t q[32][2]; uint32_t fpcr, fpsr; };
static VectorImage vector_image(unsigned batch, uint64_t value) {
    VectorImage out{};
    for (unsigned n = 0; n < 32; ++n) {
        out.q[n][0] = 0x0123456789abcdefULL ^ (uint64_t(n) << 32) ^ value;
        out.q[n][1] = 0xfedcba9876543210ULL ^ (uint64_t(batch) << 32) ^ n;
    }
    out.fpcr = batch & 1 ? 0x00400000 : 0x00800000;
    // FPSR cumulative exception flags occupy bits 0..4; bit 5 is RES0.
    // The post-CLEAR sixth batch must not compare a reserved bit as writable.
    out.fpsr = 1U << (batch % 5);
    return out;
}
static dfm_pte_rule write_rule(uint64_t address, unsigned batch) {
    dfm_pte_rule r{};r.address=address;r.x_mask=1;r.x[0]=1024+batch;
    r.q_mask=1U | (1U<<31);r.flags=DFM_PTE_RULE_FPCR | DFM_PTE_RULE_FPSR;
    r.q[0][0]=0x1122334455667788ULL+batch;r.q[0][1]=0x8877665544332211ULL+batch;
    r.q[31][0]=0xabcdef0198765432ULL+batch;r.q[31][1]=0x1234567890abcdefULL+batch;
    r.fpcr=0x00400000;r.fpsr=0x08000001;
    return r;
}

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
    if (result == -ENOTTY || result == -EINVAL || (!result &&
        (info.flags & (DFM_PTE_INFO_AVAILABLE | DFM_PTE_INFO_FPSIMD |
                       DFM_PTE_INFO_WRITE_GPR | DFM_PTE_INFO_WRITE_FPSIMD)) !=
        (DFM_PTE_INFO_AVAILABLE | DFM_PTE_INFO_FPSIMD |
         DFM_PTE_INFO_WRITE_GPR | DFM_PTE_INFO_WRITE_FPSIMD))) {
        std::printf("SKIP: PTE backend unavailable (%ld/%d)\n", result, info.backend_errno);
        dfm::close(); return 77;
    }
    require(result == 0 && info.abi_version == DFM_PTE_ABI_VERSION, "PTE information");
    const auto page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void* code = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(code != MAP_FAILED, "private fixture page");
    const auto code_bytes = size_t(dfm_pte_vector_end - dfm_pte_vector_begin);
    const auto point_offset = size_t(dfm_pte_vector_point - dfm_pte_vector_begin);
    require(code_bytes <= page_size && point_offset < code_bytes, "bounded vector fixture");
    std::memcpy(code, dfm_pte_vector_begin, code_bytes);
    __builtin___clear_cache(static_cast<char*>(code), static_cast<char*>(code) + code_bytes);
    require(mprotect(code, page_size, PROT_READ | PROT_EXEC) == 0, "RX fixture");
    const pid_t child = fork(); require(child >= 0, "fork fixture");
    if (!child) {
        raise(SIGSTOP);
        auto fn = reinterpret_cast<uint64_t (*)(uint64_t, const VectorImage*, VectorImage*)>(code);
        for (unsigned batch = 0; batch < 6; ++batch) {
            for (uint64_t i = 0; i < 100; ++i) {
                const auto in = vector_image(batch, i); VectorImage returned{};
                auto expected=in;uint64_t expected_result=i+1;
                if (batch==2 || batch==3) {
                    const auto r=write_rule(0, batch);
                    expected_result=r.x[0]+1;
                    std::memcpy(expected.q[0],r.q[0],16);std::memcpy(expected.q[31],r.q[31],16);
                    expected.fpcr=r.fpcr;expected.fpsr=r.fpsr;
                }
                if (fn(i, &in, &returned) != expected_result || std::memcmp(&expected, &returned, sizeof(in))) _exit(3);
            }
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
    const uint64_t address = reinterpret_cast<uint64_t>(code) + point_offset;
    dfm_pte_set_req bad{}; bad.abi_version = 0; bad.pid = child;
    bad.point_count = 1; bad.addresses[0] = address;
    require(raw_invalid(bad), "invalid ABI rejected by kernel");
    bad.abi_version = 1;
    require(raw_invalid(bad), "old GPR-only ABI rejected rather than misdecoded");
    bad.abi_version = DFM_PTE_ABI_VERSION; bad.flags = 1;
    require(raw_invalid(bad), "reserved flags rejected by kernel");
    require(dfm::pte_set(child, &address, 1) == 0, "set PTE breakpoint");
    require(dfm::pte_set(child, &address, 1) == -EALREADY, "owned session not replaced");
    auto out = std::make_unique<dfm_pte_snapshot>();
    uint64_t session_generation=0;
    for (unsigned batch = 0; batch < 5; ++batch) {
        if (batch==2 || batch==3) {
            const auto rule=write_rule(address,batch);
            require(dfm::pte_rules(session_generation,&rule,1)==0,"install/replace persistent rules once per batch");
        } else if(batch==4) {
            require(dfm::pte_rules(session_generation,nullptr,0)==0,"remove persistent rules without clearing trace");
        }
        require(kill(child, SIGCONT) == 0, "resume child"); wait_stopped(child);
        require(dfm::pte_read(*out) == 0, "read snapshot");
        session_generation=out->generation;
        require(out->total_hits == 100ULL * (batch + 1), "persistent exact hits on isolated child");
        require(out->record_count == 64 && out->dropped == out->total_hits - 64,
                "bounded ring overflow");
        require(out->last_error == 0 && out->rearms >= out->total_hits && out->armed_pages == 1,
                "native step rearms page");
        const auto& last = out->records[out->record_count - 1];
        require(last.address == address && last.pc == address && last.x[0] == 99,
                "GPR snapshot before original instruction");
        const auto expected = vector_image(batch, 99);
        require(last.fp_status == 0 && !std::memcmp(last.q, expected.q, sizeof(last.q)) &&
                last.fpcr == expected.fpcr && last.fpsr == expected.fpsr,
                "Q0-Q31 including both halves, FPCR and FPSR match the pre-instruction state");
        require(last.patch_status==((batch==2||batch==3)?DFM_PTE_PATCH_APPLIED:0),
                "persistent rules applied only during their configured batches");
        require(std::memcmp(code, dfm_pte_vector_begin, code_bytes) == 0, "original instructions unchanged");
    }
    require(dfm::pte_clear() == 0 && dfm::pte_clear() == 0, "idempotent clear");
    require(kill(child, SIGCONT) == 0, "resume after clear"); wait_stopped(child);
    require(dfm::pte_read(*out) == -ENOENT, "clear removes session");
    require(kill(child, SIGCONT) == 0, "finish child");
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "native execution preserved after clear");
    cleanup.pid = -1;
    std::puts("DFM_PTE_DEVICE_PASS: GPR/FPSIMD, 200 autonomous masked writes, replacement/removal, pre-write snapshots and native results");
    return 0;
}
int main() { try { return run(); } catch (const std::exception&) { return 1; } }
