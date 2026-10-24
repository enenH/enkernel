#include <dfm/loader.h>
#include "loader_elf.h"

#include <dfm/driver.h>
#include "log.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <vector>

namespace {
using namespace loader::detail;

// Serialize our own temporary sysctl changes, log cursors and insertion attempts.
std::mutex load_mutex;

class FileDescriptor {
public:
    explicit FileDescriptor(int fd = -1) : fd_(fd) {}
    ~FileDescriptor() { if (fd_ >= 0) ::close(fd_); }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

bool read_file(const char* path, char* content, size_t capacity)
{
    if (capacity < 2)
        return false;
    FileDescriptor fd(open(path, O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0)
        return false;
    ssize_t count;
    do {
        count = read(fd.get(), content, capacity - 1);
    } while (count < 0 && errno == EINTR);
    if (count <= 0 || size_t(count) == capacity - 1)
        return false;
    content[count] = '\0';
    return true;
}

bool write_file(const char* path, const char* content)
{
    FileDescriptor fd(open(path, O_WRONLY | O_CLOEXEC));
    if (fd.get() < 0)
        return false;
    size_t left = std::strlen(content);
    while (left != 0) {
        const ssize_t count = write(fd.get(), content, left);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        content += count;
        left -= size_t(count);
    }
    return true;
}

class KptrGuard {
public:
    KptrGuard()
    {
        // Never change global state unless its old value can be restored.
        if (!read_file(path_, old_value_, sizeof(old_value_))) {
            LOGW("loader: cannot read kptr_restrict; leaving it unchanged");
            return;
        }
        // Like ksud, permit privileged kallsyms readers without exposing kernel
        // addresses to everyone (kptr_restrict=0).
        if (std::strtol(old_value_, nullptr, 10) > 1) {
            changed_ = write_file(path_, "1");
            if (!changed_)
                LOGW("loader: cannot lower kptr_restrict; trying current permissions");
        }
    }

    ~KptrGuard()
    {
        if (changed_ && !write_file(path_, old_value_))
            LOGE("loader: failed to restore kptr_restrict to %s", old_value_);
    }
    KptrGuard(const KptrGuard&) = delete;
    KptrGuard& operator=(const KptrGuard&) = delete;

private:
    static constexpr const char* path_ = "/proc/sys/kernel/kptr_restrict";
    char old_value_[32]{};
    bool changed_ = false;
};

bool load_kallsyms(KernelSymbols& symbols)
{
    KptrGuard guard;
    FILE* file = fopen("/proc/kallsyms", "r");
    if (!file)
        return false;
    char line[1024];
    while (fgets(line, sizeof(line), file))
        symbols.add_line(line);
    const bool complete = !ferror(file);
    fclose(file);
    return complete && !symbols.empty();
}

bool patch_module_elf(std::string& image)
{
    ElfView elf(image);
    Elf64_Shdr symtab{}, strtab{};
    if (!elf.parse() || !elf.symbol_tables(symtab, strtab)) {
        LOGE("loader: invalid AArch64 relocatable ELF or symbol table");
        return false;
    }

    struct PendingSymbol {
        uint64_t offset;
        Elf64_Sym symbol;
        std::string name;
    };
    std::vector<PendingSymbol> pending;
    for (uint64_t i = 1; i < symtab.sh_size / sizeof(Elf64_Sym); ++i) {
        const uint64_t offset = symtab.sh_offset + i * sizeof(Elf64_Sym);
        Elf64_Sym symbol{};
        std::string_view name;
        if (!read_object(image, offset, symbol) ||
            !elf.string_at(strtab, symbol.st_name, name)) {
            LOGE("loader: invalid ELF symbol/name at index %llu", (unsigned long long)i);
            return false;
        }
        if (symbol.st_shndx == SHN_UNDEF && !name.empty())
            pending.push_back({offset, symbol, std::string(name)});
    }
    if (pending.empty())
        return true;

    KernelSymbols symbols;
    if (!load_kallsyms(symbols)) {
        // Native resolution of exported symbols may still work. Do not turn
        // inaccessible or zeroed addresses into absolute symbols.
        LOGW("loader: kallsyms unreadable/hidden; keeping native symbol resolution");
        return true;
    }

    [[maybe_unused]] size_t patched = 0, aliased = 0;
    for (auto& item : pending) {
        bool used_alias = false;
        const uint64_t address = symbols.find(item.name, used_alias);
        if (address == 0) {
            LOGW("loader: leaving unresolved kernel symbol: %s", item.name.c_str());
            continue;
        }
        item.symbol.st_value = address;
        item.symbol.st_shndx = SHN_ABS;
        std::memcpy(image.data() + item.offset, &item.symbol, sizeof(item.symbol));
        ++patched;
        aliased += used_alias ? 1 : 0;
    }
    LOGD("loader: symbols total=%zu patched=%zu unresolved=%zu compiler_aliases=%zu",
         pending.size(), patched, pending.size() - patched, aliased);
    return true;
}

class KernelLog {
public:
    KernelLog() : fd_(open_at_end()) {}

    std::string read_new()
    {
        std::string logs;
        if (fd_.get() < 0)
            return logs;
        // Nonblocking and bounded even if other kernel messages keep arriving.
        for (size_t records = 0; records < 128; ++records) {
            char record[8192];
            const ssize_t count = read(fd_.get(), record, sizeof(record));
            if (count < 0) {
                if (errno == EINTR || errno == EPIPE)
                    continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    LOGW("loader: reading kernel log failed: %s", strerror(errno));
                break;
            }
            if (count == 0)
                break;
            logs.append(record, size_t(count));
            logs += '\n';
            LOGW("loader: kernel: %.*s", int(count), record);
        }
        return logs;
    }

private:
    static int open_at_end()
    {
        for (const char* path : {"/dev/kmsg", "/kmsg"}) {
            const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
            if (fd < 0)
                continue;
            if (lseek(fd, 0, SEEK_END) >= 0)
                return fd;
            ::close(fd);
        }
        LOGW("loader: kernel log unavailable; vermagic fallback disabled");
        return -1;
    }
    FileDescriptor fd_;
};

long insert_module(const std::string& image, const std::string& params)
{
    long result = syscall(__NR_init_module, image.data(), image.size(), params.c_str());
    if (result == -1) {
        result = -errno;
        LOGE("loader: init_module ret=%ld: %s", result, strerror(int(-result)));
    }
    return result;
}

bool load_image(std::string image, std::string_view params)
{
    if (params.find('\0') != std::string_view::npos) {
        LOGE("loader: module parameters contain an embedded NUL");
        return false;
    }
    std::string module_name, vermagic;
    ElfView elf(image);
    if (image.size() > kMaxModuleSize || !elf.parse() ||
        !elf.modinfo("name", module_name) || module_name != "dfm") {
        LOGE("loader: expected a raw AArch64 ELF module named dfm");
        return false;
    }
    elf.modinfo("vermagic", vermagic);
    if (!patch_module_elf(image))
        return false;
    const std::string arguments(params);
    KernelLog kernel_log; // Open and seek BEFORE insertion; never use old dmesg.
    long result = insert_module(image, arguments);
    if (result < 0 && result != -EEXIST) {
        const std::string logs = kernel_log.read_new();
        const std::string required = required_vermagic(logs, module_name, vermagic);
        // A permissions/signature/parameter error must not trigger a format fix.
        if (result != -ENOEXEC || required.empty() || required == vermagic)
            return false;
        if (!replace_vermagic(image, required)) {
            LOGE("loader: cannot safely rebuild .modinfo for vermagic retry");
            return false;
        }
        LOGW("loader: retrying with kernel-required vermagic: %s", required.c_str());
        result = insert_module(image, arguments); // At most one retry.
        if (result < 0 && result != -EEXIST) {
            kernel_log.read_new();
            return false;
        }
    }

    // EEXIST alone is not success: an incompatible/other module may own the name.
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (dfm::init()) {
            LOGI("loader: DFM module loaded and verified");
            return true;
        }
        if (attempt != 9)
            usleep(100000);
    }
    LOGE("loader: module inserted/already exists but DFM interface is unavailable");
    return false;
}

} // namespace

namespace loader {

const char* module_filename(std::string_view release) {
    struct Module { const char* version; const char* filename; };
    static constexpr Module modules[] = {
        {"6.18", "dfm-android17-6.18.ko"},
        {"6.12", "dfm-android16-6.12.ko"},
        {"6.6", "dfm-android15-6.6.ko"},
        {"6.1", "dfm-android14-6.1.ko"},
        {"5.15", "dfm-android13-5.15.ko"},
        {"5.10", "dfm-android12-5.10.ko"},
    };
    for (const auto& module : modules) {
        if (release_matches(release, module.version))
            return module.filename;
    }
    return nullptr;
}

bool load_module_from_directory(const char* directory, std::string_view params) {
    if (!directory || !*directory) {
        LOGE("loader: empty module directory");
        return false;
    }
    utsname kernel{};
    if (uname(&kernel) != 0) {
        LOGE("loader: uname failed: %s", strerror(errno));
        return false;
    }
    const char* filename = module_filename(kernel.release);
    if (!filename) {
        LOGE("loader: unsupported kernel release: %s", kernel.release);
        return false;
    }
    std::string path(directory);
    if (path.back() != '/') path += '/';
    path += filename;
    return load_module_file(path.c_str(), params);
}

bool load_module_file(const char* path, std::string_view params)
{
    const std::lock_guard<std::mutex> lock(load_mutex);
    if (!path || !*path) {
        LOGE("loader: empty module path");
        return false;
    }
    // Open directly, without a shell or fixed-size path buffer; symlinks and
    // paths containing spaces work just like ordinary insmod paths.
    FileDescriptor fd(open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK));
    struct stat status{};
    if (fd.get() < 0 || fstat(fd.get(), &status) != 0) {
        LOGE("loader: cannot open/stat module %s: %s", path, strerror(errno));
        return false;
    }
    if (!S_ISREG(status.st_mode) || status.st_size <= 0 ||
        uint64_t(status.st_size) > kMaxModuleSize) {
        LOGE("loader: module must be a nonempty regular file of at most 64 MiB: %s", path);
        return false;
    }
    std::string image(size_t(status.st_size), '\0');
    size_t offset = 0;
    while (offset < image.size()) {
        const ssize_t count = read(fd.get(), image.data() + offset, image.size() - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            LOGE("loader: incomplete module read: %s", path);
            return false;
        }
        offset += size_t(count);
    }
    LOGI("loader: loading DFM module from %s", path);
    return load_image(std::move(image), params);
}

} // namespace loader
