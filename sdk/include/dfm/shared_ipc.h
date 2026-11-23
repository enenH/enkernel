#ifndef DFM_SHARED_IPC_H
#define DFM_SHARED_IPC_H

#include <cstddef>
#include <cstdint>

namespace dfm {

/* Two cooperative processes, one bounded mailbox in each direction. No driver
 * connection is required. All failures return negative errno, never bool.
 *
 * Both applications must explicitly set PR_SET_DUMPABLE to 0 before setup and
 * keep it disabled for the channel's lifetime (including payload copies). The
 * library checks this requirement; it never changes process-wide policy.
 *
 * The caller supplies an exclusively held, connected AF_UNIX/SOCK_SEQPACKET
 * control socket established by the actual peers, plus the independently
 * trusted peer PID/UID. A socketpair created before fork has stale SO_PEERCRED
 * and is unsuitable. Do not delegate the socket or race setup with fork.
 * offer/accept each use one control record; the socket remains caller-owned.
 *
 * No global name/path or discovery service is created. Normal kernel/procfs
 * visibility and security policy remain in effect; this is access isolation,
 * not an assurance that the existence of communication is undetectable.
 */
class SharedIpc {
public:
    static constexpr std::size_t max_payload = 4096;

    SharedIpc() = default;
    ~SharedIpc();
    SharedIpc(const SharedIpc&) = delete;
    SharedIpc& operator=(const SharedIpc&) = delete;
    SharedIpc(SharedIpc&& other) noexcept;
    SharedIpc& operator=(SharedIpc&& other) noexcept;

    // Nonblocking setup. offer publishes a sealed, anonymous memfd via
    // SCM_RIGHTS; accept consumes it. EAGAIN is retryable. No fallback transport.
    // An already open object returns EALREADY. expected_pid must be positive.
    int offer(int control_fd, int expected_pid, std::uint32_t expected_uid);
    int accept(int control_fd, int expected_pid, std::uint32_t expected_uid);

    // Nonblocking SPSC operations: one sender and one receiver per endpoint.
    // Calls to close/setup/move must not race any operation. try_send returns
    // 0; try_receive returns the byte count. Empty/full returns -EAGAIN.
    // Messages are 1..max_payload bytes. EMSGSIZE leaves the message queued.
    // There is no implicit wakeup, delivery acknowledgement or crash detection;
    // integrate retries/liveness with the application's event loop.
    int try_send(const void* data, std::size_t size);
    int try_receive(void* data, std::size_t capacity);

    // Unmap this endpoint. Storage is reclaimed after the final mapping/fd is
    // released; a peer can retain its mapping. No process-global SDK close.
    void close() noexcept;
    bool is_open() const noexcept { return mapping_ != nullptr; }

private:
    int check_owner() const;
    void* mapping_ = nullptr;
    std::size_t mapping_size_ = 0;
    int owner_pid_ = 0;
    unsigned direction_ = 0;
};

} // namespace dfm
#endif
