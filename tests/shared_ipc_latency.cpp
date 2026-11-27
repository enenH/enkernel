#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dfm/shared_ipc.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#define CHECK(test) do { if (!(test)) { \
    std::fprintf(stderr, "FAIL line=%d: %s errno=%d\n", __LINE__, #test, errno); \
    std::exit(1); } } while (0)

namespace {
std::int64_t now(clockid_t clock = CLOCK_MONOTONIC) {
    timespec value{};
    CHECK(clock_gettime(clock, &value) == 0);
    return static_cast<std::int64_t>(value.tv_sec) * 1000000000 + value.tv_nsec;
}

void relax() {
#if defined(__aarch64__)
    asm volatile("yield");
#elif defined(__x86_64__) || defined(__i386__)
    asm volatile("pause");
#endif
}

int transfer(dfm::SharedIpc& channel, bool sending, void* data, size_t bytes,
             const char* mode) {
#ifndef DFM_IPC_BASELINE
    if (std::strcmp(mode, "wait") == 0)
        return sending ? channel.send(data, bytes, 1000000000)
                       : channel.receive(data, bytes, 1000000000);
#endif
    int result;
    do {
        result = sending ? channel.try_send(data, bytes) : channel.try_receive(data, bytes);
        if (result == -EAGAIN) {
            if (std::strcmp(mode, "poll") == 0) usleep(1000);
            else relax();
        }
    } while (result == -EAGAIN);
    return result;
}
} // namespace

int main(int argc, char** argv) {
    CHECK(argc == 4 || argc == 5);
    const char* mode = argv[1];
    bool valid_mode = std::strcmp(mode, "poll") == 0 || std::strcmp(mode, "busy") == 0;
#ifndef DFM_IPC_BASELINE
    valid_mode = valid_mode || std::strcmp(mode, "wait") == 0;
#endif
    CHECK(valid_mode);
    const size_t bytes = static_cast<size_t>(std::strtoul(argv[2], nullptr, 10));
    const size_t rounds = static_cast<size_t>(std::strtoul(argv[3], nullptr, 10));
    const auto gap_us = argc == 5 ? std::strtoul(argv[4], nullptr, 10) : 0UL;
    CHECK(gap_us <= 100000);
    CHECK(bytes >= 4 && bytes <= dfm::SharedIpc::max_payload);
    CHECK(rounds > 0 && rounds <= 1000000);
    CHECK(geteuid() != 0);
    CHECK(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
    alarm(45);
    const int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                  "dfm-ipc-latency-%d", getpid());
    const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) +
                                               1 + std::strlen(address.sun_path + 1));
    CHECK(bind(listener, reinterpret_cast<sockaddr*>(&address), length) == 0);
    CHECK(listen(listener, 1) == 0);
    const pid_t parent = getpid();
    const pid_t child = fork();
    CHECK(child >= 0);
    int socket_fd;
    if (child == 0) {
        socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        CHECK(socket_fd >= 0);
        CHECK(connect(socket_fd, reinterpret_cast<sockaddr*>(&address), length) == 0);
    } else {
        socket_fd = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        CHECK(socket_fd >= 0);
    }
    ::close(listener);
    dfm::SharedIpc channel;
    if (child == 0) {
        int result;
        do {
            result = channel.accept(socket_fd, parent, getuid());
            if (result == -EAGAIN) usleep(100);
        } while (result == -EAGAIN);
        CHECK(result == 0);
        CHECK(send(socket_fd, "r", 1, MSG_NOSIGNAL) == 1);
    } else {
        CHECK(channel.offer(socket_fd, child, getuid()) == 0);
        char ready = 0;
        CHECK(recv(socket_fd, &ready, 1, 0) == 1 && ready == 'r');
    }
    ::close(socket_fd);
    constexpr size_t warmup = 64;
    std::vector<unsigned char> data(bytes), reply(bytes);
    std::vector<std::int64_t> samples;
    samples.reserve(rounds);
    const auto cpu_start = now(CLOCK_PROCESS_CPUTIME_ID);
    for (size_t i = 0; i < rounds + warmup; ++i) {
        if (child == 0) {
            if (gap_us) usleep(static_cast<useconds_t>(gap_us));
            CHECK(transfer(channel, false, data.data(), bytes, mode) == static_cast<int>(bytes));
            CHECK(transfer(channel, true, data.data(), bytes, mode) == 0);
        } else {
            std::fill(data.begin(), data.end(), static_cast<unsigned char>(i));
            const auto sequence = static_cast<std::uint32_t>(i);
            std::memcpy(data.data(), &sequence, sizeof(sequence));
            const auto start = now();
            CHECK(transfer(channel, true, data.data(), bytes, mode) == 0);
            CHECK(transfer(channel, false, reply.data(), bytes, mode) == static_cast<int>(bytes));
            const auto elapsed = now() - start;
            CHECK(data == reply);
            if (i >= warmup) samples.push_back(elapsed);
        }
    }
    const auto cpu_ns = now(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    channel.close();
    if (child == 0) return 0;
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    std::sort(samples.begin(), samples.end());
    double total = 0;
    for (const auto value : samples) total += static_cast<double>(value);
    std::printf("IPC_LATENCY mode=%s bytes=%zu rounds=%zu gap_us=%lu rtt_p50_us=%.3f rtt_p95_us=%.3f rtt_p99_us=%.3f rtt_mean_us=%.3f parent_cpu_us=%.3f\n",
                mode, bytes, rounds, gap_us, samples[rounds / 2] / 1000.0,
                samples[(rounds - 1) * 95 / 100] / 1000.0,
                samples[(rounds - 1) * 99 / 100] / 1000.0, total / rounds / 1000.0,
                cpu_ns / 1000.0);
}
