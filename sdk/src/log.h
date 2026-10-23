#ifndef ENKERNEL_LOG_H
#define ENKERNEL_LOG_H

#include <android/log.h>
#include <cstdarg>
#include <cstdio>

namespace enkernel::detail {
inline void log(int priority, const char* format, ...) {
    va_list args, android_args;
    va_start(args, format);
    va_copy(android_args, args);
    std::fputs("[enkernel] ", stderr);
    std::vfprintf(stderr, format, args);
    std::fputc('\n', stderr);
    __android_log_vprint(priority, "enkernel", format, android_args);
    va_end(android_args);
    va_end(args);
}
} // namespace enkernel::detail

#ifndef NDEBUG
#define LOGD(...) ::enkernel::detail::log(ANDROID_LOG_DEBUG, __VA_ARGS__)
#else
#define LOGD(...) ((void)0)
#endif
#define LOGI(...) ::enkernel::detail::log(ANDROID_LOG_INFO, __VA_ARGS__)
#define LOGW(...) ::enkernel::detail::log(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGE(...) ::enkernel::detail::log(ANDROID_LOG_ERROR, __VA_ARGS__)

#endif
