#include <dfm/driver.h>
#include <dfm/loader.h>

#include <cstdio>
#include <cstring>
#include <limits.h>
#include <string>
#include <string_view>
#include <unistd.h>

static void usage(const char* program) {
    std::printf(
        "Usage: %s [--module FILE | --dir DIRECTORY] [--params STRING]\n"
        "       %s --status\n"
        "       %s --help\n\n"
        "With no path, selects a matching .ko from ../modules beside this binary.\n"
        "--status only checks the existing DFM interface; it never loads a module.\n"
        "Exit codes: 0 = ready/help, 1 = load/connection failure, 2 = usage error.\n\n"
        "Device example:\n"
        "  adb shell su -c '/data/local/tmp/enkernel/bin/dfm_loader'\n"
        "  adb shell su -c '/data/local/tmp/enkernel/bin/dfm_loader --module /data/local/tmp/dfm.ko'\n",
        program, program, program);
}

int main(int argc, char** argv) {
    const char* module = nullptr;
    const char* directory = nullptr;
    std::string_view params;
    bool status_only = false;
    bool params_given = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view option(argv[i]);
        if (option == "--help" || option == "-h") {
            usage(argv[0]);
            return 0;
        }
        if (option == "--status") {
            status_only = true;
        } else if (option == "--module" || option == "--dir" || option == "--params") {
            if (++i == argc || (option != "--params" && !*argv[i])) {
                std::fprintf(stderr, "Missing value for %.*s\n", int(option.size()), option.data());
                return 2;
            }
            if (option == "--module") module = argv[i];
            if (option == "--dir") directory = argv[i];
            if (option == "--params") { params = argv[i]; params_given = true; }
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }
    if ((module && directory) || (status_only && (module || directory || params_given))) {
        std::fputs("Choose one of --module, --dir or --status.\n", stderr);
        return 2;
    }

    if (dfm::init()) {
        std::puts("DFM interface is ready (module already loaded).");
        dfm::close();
        return 0;
    }
    if (status_only) {
        std::fputs("DFM interface is unavailable.\n", stderr);
        return 1;
    }

    std::string default_directory;
    if (!module && !directory) {
        char executable[PATH_MAX];
        const ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable));
        if (length <= 0 || size_t(length) == sizeof(executable)) {
            std::fputs("Cannot locate this executable; specify --module or --dir.\n", stderr);
            return 1;
        }
        const std::string path(executable, size_t(length));
        const auto slash = path.rfind('/');
        if (slash == std::string::npos) return 1;
        default_directory = path.substr(0, slash) + "/../modules";
        directory = default_directory.c_str();
    }
    const bool ready = module ? loader::load_module_file(module, params)
                              : loader::load_module_from_directory(directory, params);
    dfm::close();
    if (!ready) {
        std::fputs("DFM load failed; see the error above or logcat -s enkernel.\n", stderr);
        return 1;
    }
    std::puts("DFM module loaded; subsequent applications should call dfm::init().");
    return 0;
}
