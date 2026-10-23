/* Build the SDK (NDK r27b, arm64, Android API 26+):
 *   cmake -S . -B cmake-build-debug -G Ninja
 *     -DCMAKE_TOOLCHAIN_FILE=<NDK>/build/cmake/android.toolchain.cmake
 *     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26
 *     -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
 *   cmake --build cmake-build-debug
 *   cmake --install cmake-build-debug --prefix out/enkernel
 *
 * Integrate the source SDK in another NDK CMake project:
 *   set(ENKERNEL_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
 *   set(ENKERNEL_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
 *   add_subdirectory(/path/to/enkernel/sdk enkernel-sdk)
 *   target_link_libraries(your_target PRIVATE enkernel::sdk)
 * Or use find_package(enkernel CONFIG REQUIRED) with enkernel_DIR set to
 * <installed-sdk>/lib/cmake/enkernel; examples/CMakeLists.txt is a complete
 * consumer. An explicit package directory also works with the NDK's sysroot
 * search restrictions.
 *
 * Deploy the combined CI archive after extraction (contains bin/ and modules/):
 *   adb push enkernel-arm64-v8a /data/local/tmp/enkernel
 *   adb shell su -c 'chmod 755 /data/local/tmp/enkernel/bin/dfm_loader /data/local/tmp/enkernel/bin/dfm_example'
 *   adb shell su -c '/data/local/tmp/enkernel/bin/dfm_loader'
 *   adb shell su -c '/data/local/tmp/enkernel/bin/dfm_example <PID> <MODULE_NAME>'
 * To load within this process, pass a .ko file as the final argument instead.
 * No target process is required when running without arguments: it reads self.
 */
#include <dfm/driver.h>
#include <dfm/loader.h>

#include <array>
#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
        std::printf("Usage: %s [PID MODULE_NAME [MODULE_KO]]\n"
                    "Without arguments, reads a value from its own process.\n", argv[0]);
        return 0;
    }
    if (argc != 1 && argc != 3 && argc != 4) {
        std::fprintf(stderr, "Usage: %s [PID MODULE_NAME [MODULE_KO]]\n", argv[0]);
        return 2;
    }
    int pid = getpid();
    if (argc >= 3) {
        char* end = nullptr;
        errno = 0;
        const long parsed = std::strtol(argv[1], &end, 10);
        if (errno || end == argv[1] || *end || parsed <= 0 || parsed > INT_MAX || !*argv[2]) {
            std::fputs("PID must be positive and MODULE_NAME must be nonempty.\n", stderr);
            return 2;
        }
        pid = int(parsed);
    }

    // Establish one connection before starting any threads that use the SDK.
    if (!dfm::init() && !(argc == 4 && loader::load_module_file(argv[3]))) {
        std::fputs("Load the driver with dfm_loader, or provide MODULE_KO.\n", stderr);
        return 1;
    }
    struct ConnectionGuard { ~ConnectionGuard() { dfm::close(); } } connection;

    if (argc == 1) {
        const uint64_t expected = 0x1122334455667788ULL;
        uint64_t value = 0;
        if (!dfm::read_memory(pid, reinterpret_cast<uint64_t>(&expected), &value, sizeof(value)) ||
            value != expected) {
            std::fputs("Self memory read failed.\n", stderr);
            return 1;
        }
        std::printf("SDK self-read OK: pid=%d value=0x%016" PRIx64 "\n", pid, value);
        return 0;
    }

    // Alternatively resolve a PID with dfm::get_process_id(exact_task_comm).
    uint64_t base = 0, size = 0;
    if (!dfm::get_module_base(pid, argv[2], base, size)) {
        std::fputs("Module lookup failed.\n", stderr);
        return 1;
    }
    std::array<unsigned char, 16> bytes{};
    if (!dfm::read_memory(pid, base, bytes.data(), bytes.size())) {
        std::fputs("Module memory read failed.\n", stderr);
        return 1;
    }
    std::printf("pid=%d base=0x%" PRIx64 " span=0x%" PRIx64 " first bytes:", pid, base, size);
    for (auto byte : bytes) std::printf(" %02x", unsigned(byte));
    std::puts("");
    return 0;
}
