#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dfm/shared_ipc.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <utility>

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

namespace {
constexpr std::uint32_t magic = 0x44495043; // DIPC
// Version 2 reserves a state bit for shared-futex waiters. Version 1 peers must
// reject this layout rather than interpret a waiting mailbox as corruption.
constexpr std::uint32_t version = 2;
constexpr int required_seals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
constexpr std::uint32_t empty = 0, full = 1;
constexpr std::uint32_t waiting = 2;
constexpr unsigned spin_count = 1024;

// Lock-free native 32-bit atomics, shared between separate processes. All
// offsets are compiled constants, never taken from peer-writable memory.
static_assert(__atomic_always_lock_free(sizeof(std::uint32_t), nullptr));
struct alignas(64) Mailbox {
    std::uint32_t state;
    std::uint32_t length;
    unsigned char payload[dfm::SharedIpc::max_payload];
};
struct Region { Mailbox slots[2]; };
struct Offer {
    std::uint32_t magic, version, bytes, reserved;
};
static_assert(sizeof(Offer) == 16);

class Fd {
public:
    explicit Fd(int value = -1) : value(value) {}
    ~Fd() { if (value >= 0) ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int value;
};

int privacy_policy() {
    const int state = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (state < 0) return -errno;
    return state == 0 ? 0 : -EPERM;
}

void cpu_relax() {
#if defined(__aarch64__)
    asm volatile("yield");
#elif defined(__x86_64__) || defined(__i386__)
    asm volatile("pause");
#endif
}

void publish(Mailbox& slot, std::uint32_t state) {
    // A waiter registers on this same word before FUTEX_WAIT_BITSET. Exchanging
    // it prevents a concurrent registration from being lost between a load
    // and store. Active polling needs no wake syscall.
    const auto previous = __atomic_exchange_n(&slot.state, state, __ATOMIC_RELEASE);
    if (previous & waiting)
        syscall(__NR_futex, &slot.state, FUTEX_WAKE, 1, nullptr, nullptr, 0);
}

int peer_check(int socket, int expected_pid, std::uint32_t expected_uid) {
    if (expected_pid <= 0 || expected_pid == getpid()) return -EINVAL;
    int result = privacy_policy();
    if (result) return result;
    int type = 0;
    socklen_t length = sizeof(type);
    if (getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &length)) return -errno;
    if (type != SOCK_SEQPACKET) return -EPROTOTYPE;
    sockaddr_storage address{};
    length = sizeof(address);
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&address), &length))
        return -errno;
    if (address.ss_family != AF_UNIX) return -EAFNOSUPPORT;
    ucred credentials{};
    length = sizeof(credentials);
    if (getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &credentials, &length))
        return -errno;
    if (length != sizeof(credentials) || credentials.pid != expected_pid ||
        credentials.uid != expected_uid) return -EACCES;
    return 0;
}

std::size_t region_size() {
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 0;
    const auto bytes = static_cast<std::size_t>(page);
    return ((sizeof(Region) + bytes - 1) / bytes) * bytes;
}

int map_region(int fd, std::size_t size, void*& out) {
    void* mapping = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) return -errno;
    // Fail closed if either policy cannot be applied. No retained backing fd.
    if (madvise(mapping, size, MADV_DONTDUMP) ||
        madvise(mapping, size, MADV_DONTFORK)) {
        const int error = errno;
        munmap(mapping, size);
        return -error;
    }
    out = mapping;
    return 0;
}

int send_offer(int socket, int fd, std::size_t bytes) {
    Offer offer{magic, version, static_cast<std::uint32_t>(bytes), 0};
    iovec io{&offer, sizeof(offer)};
    alignas(cmsghdr) unsigned char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    ssize_t sent;
    do { sent = sendmsg(socket, &message, MSG_NOSIGNAL | MSG_DONTWAIT); }
    while (sent < 0 && errno == EINTR);
    if (sent < 0) return -errno;
    return sent == sizeof(offer) ? 0 : -EIO;
}

int receive_offer(int socket, std::size_t bytes, int& out_fd) {
    Offer offer{};
    iovec io{&offer, sizeof(offer)};
    // Room for unexpected rights, too: close every received descriptor on any
    // protocol error. Also leave room for automatically attached credentials
    // and SCM_PIDFD. Linux closes descriptors truncated beyond this buffer.
    alignas(cmsghdr) unsigned char control[CMSG_SPACE(16 * sizeof(int)) +
                                         CMSG_SPACE(sizeof(ucred)) +
                                         CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    ssize_t received;
    do { received = recvmsg(socket, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT); }
    while (received < 0 && errno == EINTR);
    if (received < 0) return -errno;
    Fd first;
    unsigned count = 0;
    bool malformed = false;
    for (cmsghdr* header = CMSG_FIRSTHDR(&message); header;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET ||
            (header->cmsg_type != SCM_RIGHTS && header->cmsg_type != SCM_PIDFD))
            continue;
        if (header->cmsg_len < CMSG_LEN(0)) { malformed = true; break; }
        const std::size_t data_size = header->cmsg_len - CMSG_LEN(0);
        if (data_size % sizeof(int) ||
            (header->cmsg_type == SCM_PIDFD && data_size != sizeof(int)))
            malformed = true;
        for (std::size_t i = 0; i < data_size / sizeof(int); ++i) {
            int fd;
            std::memcpy(&fd, CMSG_DATA(header) + i * sizeof(int), sizeof(fd));
            if (header->cmsg_type == SCM_PIDFD) ::close(fd);
            else if (++count == 1) first.value = fd;
            else ::close(fd);
        }
    }
    if (received == 0 && count == 0) return -ECONNRESET;
    if (received != sizeof(offer) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || malformed || count != 1 ||
        offer.magic != magic || offer.version != version ||
        offer.bytes != bytes || offer.reserved != 0) return -EPROTO;
    // Check seals before size: shrink/grow must already be permanently disabled.
    const int seals = fcntl(first.value, F_GET_SEALS);
    if (seals < 0) return -errno;
    if ((seals & required_seals) != required_seals) return -EPROTO;
    struct stat status{};
    if (fstat(first.value, &status)) return -errno;
    if (!S_ISREG(status.st_mode) || status.st_size != static_cast<off_t>(bytes))
        return -EPROTO;
    const int flags = fcntl(first.value, F_GETFL);
    if (flags < 0) return -errno;
    if ((flags & O_ACCMODE) != O_RDWR) return -EPROTO;
    out_fd = std::exchange(first.value, -1);
    return 0;
}
} // namespace

namespace dfm {
SharedIpc::~SharedIpc() { close(); }
SharedIpc::SharedIpc(SharedIpc&& other) noexcept { *this = std::move(other); }
SharedIpc& SharedIpc::operator=(SharedIpc&& other) noexcept {
    if (this != &other) {
        close();
        mapping_ = std::exchange(other.mapping_, nullptr);
        mapping_size_ = std::exchange(other.mapping_size_, 0);
        owner_pid_ = std::exchange(other.owner_pid_, 0);
        direction_ = other.direction_;
    }
    return *this;
}

int SharedIpc::offer(int socket, int expected_pid, std::uint32_t expected_uid) {
    if (mapping_) return -EALREADY;
    int result = peer_check(socket, expected_pid, expected_uid);
    if (result) return result;
    const std::size_t size = region_size();
    if (!size) return -EINVAL;
    Fd fd(static_cast<int>(syscall(__NR_memfd_create, "enkernel-ipc",
                                  MFD_CLOEXEC | MFD_ALLOW_SEALING)));
    if (fd.value < 0) return -errno;
    if (ftruncate(fd.value, static_cast<off_t>(size)) ||
        fcntl(fd.value, F_ADD_SEALS, required_seals)) return -errno;
    void* mapping = nullptr;
    result = map_region(fd.value, size, mapping);
    if (result) return result;
    std::memset(mapping, 0, size);
    result = send_offer(socket, fd.value, size);
    if (result) { munmap(mapping, size); return result; }
    mapping_ = mapping;
    mapping_size_ = size;
    owner_pid_ = getpid();
    direction_ = 0;
    return 0;
}

int SharedIpc::accept(int socket, int expected_pid, std::uint32_t expected_uid) {
    if (mapping_) return -EALREADY;
    int result = peer_check(socket, expected_pid, expected_uid);
    if (result) return result;
    const std::size_t size = region_size();
    if (!size) return -EINVAL;
    Fd fd;
    result = receive_offer(socket, size, fd.value);
    if (result) return result;
    void* mapping = nullptr;
    result = map_region(fd.value, size, mapping);
    if (result) return result;
    mapping_ = mapping;
    mapping_size_ = size;
    owner_pid_ = getpid();
    direction_ = 1;
    return 0;
}

int SharedIpc::check_owner() const {
    if (!mapping_) return -ENOTCONN;
    if (owner_pid_ != getpid()) return -EPERM;
    return privacy_policy();
}

int SharedIpc::try_send(const void* data, std::size_t size) {
    const int result = check_owner();
    if (result) return result;
    if (!data || !size) return -EINVAL;
    if (size > max_payload) return -EMSGSIZE;
    auto& slot = static_cast<Region*>(mapping_)->slots[direction_];
    const auto state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
    if (state & ~(full | waiting)) return -EPROTO;
    if (state & full) return -EAGAIN;
    std::memcpy(slot.payload, data, size);
    slot.length = static_cast<std::uint32_t>(size);
    publish(slot, full);
    return 0;
}

int SharedIpc::try_receive(void* data, std::size_t capacity) {
    const int result = check_owner();
    if (result) return result;
    if (!data || !capacity) return -EINVAL;
    auto& slot = static_cast<Region*>(mapping_)->slots[1 - direction_];
    const auto state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
    if (state & ~(full | waiting)) return -EPROTO;
    if (!(state & full)) return -EAGAIN;
    const auto length = slot.length;
    if (!length || length > max_payload) return -EPROTO;
    if (length > capacity) return -EMSGSIZE;
    std::memcpy(data, slot.payload, length);
    // Clear consumed content before publishing the slot as reusable.
    std::memset(slot.payload, 0, length);
    slot.length = 0;
    publish(slot, empty);
    return static_cast<int>(length);
}

int SharedIpc::wait_ready(bool sending, std::int64_t timeout_ns) {
    timespec deadline{};
    if (timeout_ns >= 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &deadline)) return -errno;
        deadline.tv_sec += timeout_ns / 1000000000;
        deadline.tv_nsec += timeout_ns % 1000000000;
        if (deadline.tv_nsec >= 1000000000) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000;
        }
    }
    auto& slot = static_cast<Region*>(mapping_)->slots[sending ? direction_ : 1 - direction_];
    const auto blocked = sending ? full : empty;
    unsigned spins = 0;
    for (;;) {
        auto state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
        if (state & ~(full | waiting)) return -EPROTO;
        if ((state & full) != blocked) return 0;
        if (spins++ < spin_count) { cpu_relax(); continue; }
        const int policy = check_owner();
        if (policy) return policy;
        if (!(state & waiting) &&
            !__atomic_compare_exchange_n(&slot.state, &state, state | waiting,
                                         false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            continue;
        // Shared futex (never FUTEX_PRIVATE_FLAG), with an absolute monotonic
        // deadline so signals/spurious wakes do not extend the timeout.
        const long result = syscall(__NR_futex, &slot.state, FUTEX_WAIT_BITSET,
                                    blocked | waiting, timeout_ns < 0 ? nullptr : &deadline,
                                    nullptr, FUTEX_BITSET_MATCH_ANY);
        if (result < 0 && errno != EAGAIN && errno != EINTR) return -errno;
        // Leave a timed-out wait bit for publish() to clear. Clearing it here
        // could erase the opposite endpoint's newly registered wait.
        spins = 0;
    }
}

int SharedIpc::send(const void* data, std::size_t size, std::int64_t timeout_ns) {
    if (timeout_ns < -1) return -EINVAL;
    const int result = try_send(data, size);
    if (result != -EAGAIN || timeout_ns == 0) return result;
    const int ready = wait_ready(true, timeout_ns);
    return ready ? ready : try_send(data, size);
}

int SharedIpc::receive(void* data, std::size_t capacity, std::int64_t timeout_ns) {
    if (timeout_ns < -1) return -EINVAL;
    const int result = try_receive(data, capacity);
    if (result != -EAGAIN || timeout_ns == 0) return result;
    const int ready = wait_ready(false, timeout_ns);
    return ready ? ready : try_receive(data, capacity);
}

void SharedIpc::close() noexcept {
    if (mapping_) {
        // MADV_DONTFORK means a fork child has no mapping to release.
        if (owner_pid_ == getpid()) munmap(mapping_, mapping_size_);
        mapping_ = nullptr;
    }
    mapping_size_ = 0;
    owner_pid_ = 0;
}
} // namespace dfm
