#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dfm/shared_ipc.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <initializer_list>
#include <linux/memfd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utility>

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#define CHECK(test) do { if (!(test)) { \
    std::fprintf(stderr, "FAIL pid=%d line=%d: %s (errno=%d)\n", \
                 getpid(), __LINE__, #test, errno); std::exit(1); } } while (0)

namespace {
struct Peer { int fd; pid_t pid; bool child; };
unsigned sequence = 0;

// Establish sockets AFTER fork: unlike a pre-fork socketpair, SO_PEERCRED
// identifies the actual cooperating processes. The test's abstract rendezvous
// name is not used by the SDK and is removed when the listener closes.
Peer connect_peer() {
    const pid_t parent = getpid();
    const int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                  "dfm-ipc-test-%d-%u", parent, ++sequence);
    const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) +
                                               1 + std::strlen(address.sun_path + 1));
    CHECK(bind(listener, reinterpret_cast<sockaddr*>(&address), length) == 0);
    CHECK(listen(listener, 1) == 0);
    const pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        const int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        CHECK(fd >= 0);
        CHECK(connect(fd, reinterpret_cast<sockaddr*>(&address), length) == 0);
        ::close(listener);
        return {fd, parent, true};
    }
    const int fd = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    CHECK(fd >= 0);
    ::close(listener);
    return {fd, child, false};
}

void join(pid_t child) {
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void put(int fd, char byte) { CHECK(send(fd, &byte, 1, MSG_NOSIGNAL) == 1); }
void get(int fd, char byte) {
    char result = 0;
    CHECK(recv(fd, &result, 1, 0) == 1 && result == byte);
}

template<class F> int retry(F operation) {
    for (int i = 0; i < 10000; ++i) {
        const int result = operation();
        if (result != -EAGAIN) return result;
        usleep(1000);
    }
    return -ETIMEDOUT;
}

int fd_count() {
    DIR* directory = opendir("/proc/self/fd");
    CHECK(directory);
    int count = 0;
    while (auto* entry = readdir(directory)) {
        if (entry->d_name[0] != '.') ++count;
    }
    closedir(directory);
    return count;
}

std::uintptr_t ipc_mapping() {
    FILE* maps = std::fopen("/proc/self/maps", "r");
    CHECK(maps);
    char line[1024];
    unsigned long start = 0;
    while (std::fgets(line, sizeof(line), maps)) {
        if (std::strstr(line, "memfd:enkernel-ipc")) {
            CHECK(std::sscanf(line, "%lx-", &start) == 1);
            break;
        }
    }
    std::fclose(maps);
    return static_cast<std::uintptr_t>(start);
}

bool denied(int error) { return error == EPERM || error == EACCES || error == ENOENT; }

void observer_check(dfm::SharedIpc& channel) {
    CHECK(geteuid() != 0); // Security checks must actually run without root.
    const auto mapping = ipc_mapping();
    CHECK(mapping != 0);
    const pid_t parent = getpid();
    const pid_t observer = fork();
    CHECK(observer >= 0);
    if (observer == 0) {
        // The mapping was really omitted from the fork child's address space.
        unsigned char residency = 0;
        CHECK(mincore(reinterpret_cast<void*>(mapping),
                      static_cast<size_t>(sysconf(_SC_PAGESIZE)), &residency) == -1);
        CHECK(errno == ENOMEM);
        char data[16]{};
        CHECK(channel.try_send(data, sizeof(data)) == -EPERM);
        CHECK(channel.try_receive(data, sizeof(data)) == -EPERM);
        CHECK(channel.send(data, sizeof(data), 1000000) == -EPERM);
        CHECK(channel.receive(data, sizeof(data), 1000000) == -EPERM);
        char path[128];
        for (const char* entry : {"maps", "mem"}) {
            std::snprintf(path, sizeof(path), "/proc/%d/%s", parent, entry);
            const int fd = open(path, O_RDONLY | O_CLOEXEC);
            CHECK(fd == -1 && denied(errno));
        }
        std::snprintf(path, sizeof(path), "/proc/%d/fd", parent);
        DIR* fds = opendir(path);
        CHECK(!fds && denied(errno));
        iovec local{data, sizeof(data)};
        iovec remote{reinterpret_cast<void*>(mapping), sizeof(data)};
        CHECK(syscall(__NR_process_vm_readv, parent, &local, 1, &remote, 1, 0) == -1);
        CHECK(denied(errno));
        channel.close();
        std::exit(0);
    }
    join(observer);
}

void enable_pidfd(int fd) {
    const int enabled = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_PASSPIDFD, &enabled, sizeof(enabled)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0);
}

bool supports_pidfd() {
    const int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    const int enabled = 1;
    const int result = setsockopt(fd, SOL_SOCKET, SO_PASSPIDFD, &enabled, sizeof(enabled));
    const int error = errno;
    ::close(fd);
    if (result == 0) return true;
    CHECK(error == ENOPROTOOPT || error == EINVAL);
    return false;
}

void round_trip(bool pidfd = false) {
    auto peer = connect_peer();
    const int before = fd_count();
    dfm::SharedIpc channel;
    CHECK(channel.accept(peer.fd, peer.pid, getuid() + 1) == -EACCES);
    CHECK(channel.offer(peer.fd, peer.pid + 100000, getuid()) == -EACCES);
    unsigned char payload[dfm::SharedIpc::max_payload];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<unsigned char>(i * 37);
    if (peer.child) {
        if (pidfd) enable_pidfd(peer.fd);
        CHECK(channel.accept(peer.fd, peer.pid, getuid()) == -EAGAIN);
        put(peer.fd, 'p');
        CHECK(retry([&] { return channel.accept(peer.fd, peer.pid, getuid()); }) == 0);
        CHECK(fd_count() == before); // Received backing fd closed after mmap.
        CHECK(channel.accept(peer.fd, peer.pid, getuid()) == -EALREADY);
        put(peer.fd, 'r');
        get(peer.fd, 'g');
        unsigned char copy[sizeof(payload)]{};
        CHECK(channel.try_receive(copy, 1) == -EMSGSIZE);
        CHECK(channel.try_receive(copy, sizeof(copy)) == sizeof(copy));
        CHECK(std::memcmp(copy, payload, sizeof(copy)) == 0);
        CHECK(channel.try_receive(copy, sizeof(copy)) == -EAGAIN);
        CHECK(channel.try_send("ok", 2) == 0);
    } else {
        get(peer.fd, 'p');
        CHECK(channel.offer(peer.fd, peer.pid, getuid()) == 0);
        CHECK(fd_count() == before); // Sender also retains only the mapping.
        CHECK(channel.offer(peer.fd, peer.pid, getuid()) == -EALREADY);
        get(peer.fd, 'r');
        CHECK(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0);
        CHECK(channel.try_send(payload, 1) == -EPERM);
        CHECK(channel.try_receive(payload, sizeof(payload)) == -EPERM);
        CHECK(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
        CHECK(channel.try_send(nullptr, 1) == -EINVAL);
        CHECK(channel.try_send(payload, 0) == -EINVAL);
        CHECK(channel.try_send(payload, sizeof(payload) + 1) == -EMSGSIZE);
        CHECK(channel.try_send(payload, sizeof(payload)) == 0);
        CHECK(channel.try_send(payload, 1) == -EAGAIN);
        observer_check(channel);
        put(peer.fd, 'g');
        char reply[16]{};
        CHECK(retry([&] { return channel.try_receive(reply, sizeof(reply)); }) == 2);
        CHECK(std::memcmp(reply, "ok", 2) == 0);
    }
    // Moving does not duplicate mappings, and source objects become disconnected.
    dfm::SharedIpc moved(std::move(channel));
    CHECK(!channel.is_open() && moved.is_open());
    CHECK(channel.try_send(payload, 1) == -ENOTCONN);
    for (std::uint32_t i = 0; i < 3000; ++i) {
        struct Packet { std::uint32_t sequence, origin; } packet{i, peer.child ? 1U : 0U};
        CHECK(retry([&] { return moved.try_send(&packet, sizeof(packet)); }) == 0);
        Packet reply{};
        CHECK(retry([&] { return moved.try_receive(&reply, sizeof(reply)); }) == sizeof(reply));
        CHECK(reply.sequence == i && reply.origin != packet.origin);
    }
    put(peer.fd, 'd');
    get(peer.fd, 'd');
    moved.close();
    moved.close();
    CHECK(!moved.is_open() && ipc_mapping() == 0);
    CHECK(fd_count() == before);
    ::close(peer.fd);
    if (peer.child) std::exit(0);
    join(peer.pid);
}

void wrong_socketpair() {
    int sockets[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0);
    const pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) { ::close(sockets[0]); get(sockets[1], 'x'); std::exit(0); }
    ::close(sockets[1]);
    dfm::SharedIpc channel;
    CHECK(channel.offer(sockets[0], child, getuid()) == -EACCES);
    put(sockets[0], 'x');
    ::close(sockets[0]);
    join(child);
}

void interrupted(int) {}

void waiting_transfer() {
    auto peer = connect_peer();
    dfm::SharedIpc channel;
    char data[16]{};
    constexpr std::int64_t second = 1000000000;
    if (peer.child) {
        CHECK(retry([&] { return channel.accept(peer.fd, peer.pid, getuid()); }) == 0);
        put(peer.fd, 'r');
        get(peer.fd, 's');
        // Force the parent into a real futex sleep. An interrupted wait must
        // retry against the original deadline and still deliver exactly once.
        usleep(10000);
        CHECK(kill(peer.pid, SIGUSR1) == 0);
        usleep(10000);
        CHECK(channel.send("wake", 4, second) == 0);
        get(peer.fd, 'f');
        usleep(10000);
        CHECK(channel.receive(data, sizeof(data), second) == 5);
        CHECK(std::memcmp(data, "first", 5) == 0);
        CHECK(channel.receive(data, sizeof(data), second) == 6);
        CHECK(std::memcmp(data, "second", 6) == 0);
        put(peer.fd, 'd');
    } else {
        CHECK(channel.offer(peer.fd, peer.pid, getuid()) == 0);
        get(peer.fd, 'r');
        CHECK(channel.receive(data, sizeof(data), -2) == -EINVAL);
        CHECK(channel.send("x", 1, -2) == -EINVAL);
        CHECK(channel.receive(data, sizeof(data), 0) == -EAGAIN);
        timespec start{}, end{};
        CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
        CHECK(channel.receive(data, sizeof(data), 2000000) == -ETIMEDOUT);
        CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
        const auto elapsed = (end.tv_sec - start.tv_sec) * second + end.tv_nsec - start.tv_nsec;
        CHECK(elapsed >= 2000000);
        struct sigaction action{};
        action.sa_handler = interrupted;
        CHECK(sigemptyset(&action.sa_mask) == 0);
        CHECK(sigaction(SIGUSR1, &action, nullptr) == 0);
        put(peer.fd, 's');
        CHECK(channel.receive(data, sizeof(data), second) == 4);
        CHECK(std::memcmp(data, "wake", 4) == 0);
        CHECK(channel.send("first", 5, 0) == 0);
        CHECK(channel.send("second", 6, 0) == -EAGAIN);
        CHECK(channel.send("second", 6, 2000000) == -ETIMEDOUT);
        put(peer.fd, 'f');
        CHECK(channel.send("second", 6, second) == 0);
        get(peer.fd, 'd');
    }
    // Repeated handoff checks both wake directions and mixes blocking and
    // nonblocking endpoints on the same version-2 mapping.
    for (std::uint32_t sequence = 0; sequence < 1000; ++sequence) {
        std::uint32_t reply = 0;
        if (peer.child) {
            CHECK(channel.receive(&reply, sizeof(reply), second) == sizeof(reply));
            CHECK(reply == sequence);
            CHECK(retry([&] { return channel.try_send(&reply, sizeof(reply)); }) == 0);
        } else {
            CHECK(channel.send(&sequence, sizeof(sequence), second) == 0);
            CHECK(channel.receive(&reply, 1, second) == -EMSGSIZE);
            CHECK(channel.receive(&reply, sizeof(reply), -1) == sizeof(reply));
            CHECK(reply == sequence);
        }
    }
    CHECK(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0);
    CHECK(channel.send(data, sizeof(data), second) == -EPERM);
    CHECK(channel.receive(data, sizeof(data), second) == -EPERM);
    CHECK(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
    channel.close();
    CHECK(channel.send(data, sizeof(data), second) == -ENOTCONN);
    CHECK(channel.receive(data, sizeof(data), second) == -ENOTCONN);
    ::close(peer.fd);
    if (peer.child) std::exit(0);
    join(peer.pid);
}

enum BadOffer { Unsealed, WrongSize, ExtraRights, TruncatedRights, WrongVersion,
                OversizeRecord, MissingRights, ReadOnly, BadLength, BadState, Closed,
                LegacyVersion };

void bad_offer(BadOffer kind, bool pidfd = false) {
    auto peer = connect_peer();
    const long page = sysconf(_SC_PAGESIZE);
    // The wire envelope carries the local page-rounded region size. Obtain it
    // from a genuine offer instead of duplicating the private layout in tests.
    std::uint32_t envelope[5]{};
    if (!peer.child) {
        dfm::SharedIpc probe;
        CHECK(probe.offer(peer.fd, peer.pid, getuid()) == 0);
        CHECK(recv(peer.fd, envelope, 4 * sizeof(std::uint32_t), 0) == 4 * sizeof(std::uint32_t));
        get(peer.fd, 'r');
        probe.close();
    }
    else {
        alignas(cmsghdr) unsigned char control[CMSG_SPACE(sizeof(int))]{};
        iovec io{envelope, 4 * sizeof(std::uint32_t)};
        msghdr message{};
        message.msg_iov = &io; message.msg_iovlen = 1;
        message.msg_control = control; message.msg_controllen = sizeof(control);
        CHECK(recvmsg(peer.fd, &message, MSG_CMSG_CLOEXEC) == 4 * sizeof(std::uint32_t));
        cmsghdr* header = CMSG_FIRSTHDR(&message);
        CHECK(header && header->cmsg_type == SCM_RIGHTS);
        int original = -1;
        std::memcpy(&original, CMSG_DATA(header), sizeof(original));
        CHECK(original >= 0 && envelope[2] % page == 0);
        ::close(original);
        // Return the actual envelope for mutation by the sending test peer.
        CHECK(send(peer.fd, envelope, 4 * sizeof(std::uint32_t), MSG_NOSIGNAL) == 4 * sizeof(std::uint32_t));
        // Enable before the parent queues its offer, including on older kernels
        // that capture ancillary credentials at send time.
        if (pidfd) enable_pidfd(peer.fd);
        put(peer.fd, 'r');
        const int before = fd_count();
        dfm::SharedIpc receiver;
        const int result = retry([&] { return receiver.accept(peer.fd, peer.pid, getuid()); });
        if (kind == BadLength || kind == BadState) {
            CHECK(result == 0);
            char data[16]{};
            CHECK(receiver.try_receive(data, sizeof(data)) == -EPROTO);
            receiver.close();
        } else {
            CHECK(result < 0 && result != -EAGAIN);
            CHECK(!receiver.is_open());
            if (kind == Closed) CHECK(result == -ECONNRESET);
            else CHECK(result == -EPROTO);
        }
        CHECK(fd_count() == before);
        ::close(peer.fd);
        std::exit(0);
    }
    if (kind != Closed) {
        int backing = static_cast<int>(syscall(__NR_memfd_create, "dfm-malformed-test",
                                               MFD_CLOEXEC | MFD_ALLOW_SEALING));
        CHECK(backing >= 0);
        CHECK(ftruncate(backing, kind == WrongSize ? envelope[2] + page : envelope[2]) == 0);
        if (kind == BadLength || kind == BadState) {
            const std::uint32_t corrupt[2] = {kind == BadState ? 99U : 1U,
                                             dfm::SharedIpc::max_payload + 1};
            CHECK(pwrite(backing, corrupt, sizeof(corrupt), 0) == sizeof(corrupt));
        }
        if (kind != Unsealed)
            CHECK(fcntl(backing, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
        if (kind == ReadOnly) {
            char path[128];
            std::snprintf(path, sizeof(path), "/proc/self/fd/%d", backing);
            const int readonly = open(path, O_RDONLY | O_CLOEXEC);
            CHECK(readonly >= 0);
            ::close(backing);
            backing = readonly;
        }
        if (kind == WrongVersion) ++envelope[1];
        if (kind == LegacyVersion) envelope[1] = 1;
        const size_t count = kind == ExtraRights ? 2 : kind == TruncatedRights ? 64 : 1;
        alignas(cmsghdr) unsigned char control[CMSG_SPACE(64 * sizeof(int))]{};
        iovec io{envelope, (kind == OversizeRecord ? 5U : 4U) * sizeof(std::uint32_t)};
        msghdr message{};
        message.msg_iov = &io; message.msg_iovlen = 1;
        if (kind != MissingRights) {
            message.msg_control = control;
            message.msg_controllen = CMSG_SPACE(count * sizeof(int));
            cmsghdr* header = CMSG_FIRSTHDR(&message);
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(count * sizeof(int));
            for (size_t i = 0; i < count; ++i)
                std::memcpy(CMSG_DATA(header) + i * sizeof(int), &backing, sizeof(backing));
        }
        CHECK(sendmsg(peer.fd, &message, MSG_NOSIGNAL) == static_cast<ssize_t>(io.iov_len));
        ::close(backing);
    }
    ::close(peer.fd);
    join(peer.pid);
}
} // namespace

int main() {
    alarm(60);
    CHECK(geteuid() != 0);
    CHECK(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0);
    dfm::SharedIpc unopened;
    CHECK(unopened.offer(-1, getpid() + 1, getuid()) == -EPERM);
    CHECK(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1);
    CHECK(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
    CHECK(unopened.try_send("x", 1) == -ENOTCONN);
    CHECK(unopened.offer(-1, getpid() + 1, getuid()) == -EBADF);
    const int stream = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(stream >= 0);
    CHECK(unopened.offer(stream, getpid() + 1, getuid()) == -EPROTOTYPE);
    ::close(stream);
    wrong_socketpair();
    round_trip();
    waiting_transfer();
    for (BadOffer kind : {Unsealed, WrongSize, ExtraRights, TruncatedRights,
                          WrongVersion, OversizeRecord, MissingRights, ReadOnly,
                          BadLength, BadState, Closed, LegacyVersion}) bad_offer(kind);
    if (supports_pidfd()) {
        round_trip(true);
        for (BadOffer kind : {Unsealed, WrongSize, ExtraRights, TruncatedRights,
                              WrongVersion, OversizeRecord, MissingRights, ReadOnly,
                              BadLength, BadState, Closed, LegacyVersion}) bad_offer(kind, true);
        std::puts("DFM_SHARED_IPC_PIDFD_PASS: success and rejection paths retain no descriptors");
    } else {
        std::puts("DFM_SHARED_IPC_PIDFD_SKIP: SO_PASSPIDFD unsupported");
    }
    std::puts("DFM_SHARED_IPC_PASS: credentials, duplex, bounds, backpressure, wait/wake, deadlines, signals, move, cleanup, fork, malformed offers and unprivileged observer isolation");
}
