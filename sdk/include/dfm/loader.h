#ifndef DFM_LOADER_H
#define DFM_LOADER_H

#include <string_view>

namespace loader {

/* Return the CI artifact filename for a uname release (e.g. 6.1.75-android14).
 * Returns nullptr for an unsupported release; performs no I/O or loading. */
const char* module_filename(std::string_view release);

/* Load a raw, unpacked DFM .ko file using the original project's symbol
 * resolution and one confirmed vermagic retry. Requires module-loading rights.
 * Does not alter ABI CRCs, signatures, the input file or an already loaded module.
 * Returns true only after dfm::init() obtains a working connection. The caller
 * owns that connection and must eventually call dfm::close(). Paths and parameter
 * strings are passed directly to OS calls, never interpreted by a shell.
 *
 * Typical use:
 *   if (!dfm::init() && !loader::load_module_file("/data/local/tmp/dfm.ko"))
 *       return 1;
 *   // dfm::get_process_id, get_module_base, read_memory, hwb_*, touch_*, ...
 *   dfm::close();
 *
 * Initialize/load before starting SDK worker threads. Errors are written to
 * stderr and Android logcat (tag: enkernel), including in Release builds. */
bool load_module_file(const char* path, std::string_view params = {});

/* Select dfm-android*.ko from this directory using uname(), then load it.
 * Version-family selection does not replace the kernel's compatibility checks.
 * Call after dfm::init() fails; never unloads/replaces an existing module. */
bool load_module_from_directory(const char* directory, std::string_view params = {});

} // namespace loader

#endif
