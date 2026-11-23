# Anonymous shared-memory IPC

The SDK's independent dfm::SharedIpc connects two cooperating processes without
a driver fd, new ioctl, kernel worker or named shared-memory object. It uses a
Linux anonymous memfd mapped MAP_SHARED at both endpoints. The kernel module
and its existing access policies are unchanged. There is no hidden mapping,
procfs filtering or audit suppression.

## Security boundary

The supported adversary is a third, unprivileged process, including another
process with the same UID. Both endpoints and their applications are trusted.
Root, capabilities such as CAP_SYS_PTRACE, kernel instrumentation, compromised
endpoints and deliberately delegated capabilities are outside this boundary.
The existence of two processes or of their caller-provided control socket is
not secret. This API does not promise that all communication metadata is
undetectable, even to unprivileged observers.

- Both applications explicitly call prctl(PR_SET_DUMPABLE, 0) before setup and
  keep it disabled throughout the lifetime of the channel and any copies of
  sensitive data. Setup and each send/receive fail with -EPERM if dumpable is
  enabled. The library never silently changes process-wide policy. Coordinate
  this setting with crash reporting/debuggers and other threads; checks cannot
  prevent another thread from changing it immediately afterward. Process-wide
  policy must remain under application control.
- Applications provide an exclusively held, connected Unix SOCK_SEQPACKET
  socket and independently trusted expected peer PID and UID. Both sides verify
  SO_PEERCRED before sharing or accepting any memory. Do not derive the trusted
  identity from an unauthenticated request or a process name. Establish the
  socket in the actual processes: credentials on a socketpair created before
  fork identify its creator, so that topology is rejected for a child peer. Do
  not forward/inherit/delegate the established control socket. This library
  does not supply peer discovery or authenticate Android packages.
- Only one memfd descriptor is accepted, via SCM_RIGHTS with MSG_CMSG_CLOEXEC.
  Permanently sealed size, exact page-rounded length, writable access, envelope
  version and ancillary truncation are validated before mapping. Every received
  descriptor is closed on rejection. Automatically attached SCM_PIDFD handles
  are closed on both success and failure; they are never treated as the memfd.
- Shared mappings require MADV_DONTDUMP and MADV_DONTFORK; failure aborts setup.
  No backing fd remains in either SDK object after setup. Do not race
  initialization with fork: temporary descriptors, including a pending socket
  offer, are capabilities too. Fork children cannot use the inherited SDK
  object and do not inherit an established mapping. Ordinary payload copies
  outside the channel are the application's responsibility.
- No filesystem pathname, global shared-memory name or discovery entry is
  created by the SDK. The descriptive memfd label is not a secret. Normal
  procfs permissions, SELinux and other kernel security checks remain enabled.
  Non-dumpable processes are protected against ordinary same-UID ptrace/procfs
  reads; applications must not override that protection or leak descriptors.
  Platform policy may still deny setup, including transfers across app domains;
  errors propagate with no privileged fallback.

This is isolation using standard OS permissions, not cryptographic protection
against an endpoint, the kernel, swap inspection or a privileged observer.
Pages are kernel-managed anonymous memory and may be swapped. No mlock or
guarantee against persistence by the OS is implied. Closing one endpoint cannot
revoke memory that its trusted peer still holds.

## Calling contract

Include the header dfm/shared_ipc.h and link enkernel::sdk. Android arm64/API 26 SDK
builds include this API. Kernel support for memfd sealing and mapping advice is
required; unsupported systems return their actual errno. No root/driver
initialization is needed, so the same process code also builds on Linux.

After both applications have disabled dumpable and established their control
socket, one endpoint offers and the other accepts:

    // Each application, before creating threads/channels containing sensitive data:
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) { /* abort setup */ }

    dfm::SharedIpc channel;
    // Creator, using trusted_peer_pid/uid from its own authorization policy:
    int result = channel.offer(control_fd, trusted_peer_pid, trusted_peer_uid);
    // Receiver, in its own process, instead calls:
    // int result = channel.accept(control_fd, trusted_peer_pid, trusted_peer_uid);
    // result == 0: ready; -EAGAIN: retry later; other negatives: abort/handle error.

The caller owns the control socket. Reserve one complete record for the offer,
do not let other threads consume that record, and close the control socket after
acceptance if no longer needed. A successful offer enqueues the descriptor; it
does not acknowledge that the peer has accepted it. If setup is abandoned,
release both sockets/queued descriptors and SDK objects.

try_send(data, size) accepts 1..4096 bytes and returns zero or negative errno.
try_receive(data, capacity) returns the byte count or negative errno. There is
one single-producer/single-consumer mailbox in each direction: one send and one
receive may proceed independently, but multiple senders or multiple receivers
for one endpoint must be serialized by the caller. Atomic acquire/release
publication prevents a receiver from observing a partial cooperative message.
Oversized input returns -EMSGSIZE; an undersized receive buffer leaves the
message queued. Consumed bytes are cleared before the slot becomes reusable.

An empty receive or full send returns -EAGAIN. Applications with an existing
event loop can continue using try_send/try_receive. For waiting calls, use:

    // Up to 5 milliseconds; send returns 0, receive returns the byte count.
    int sent = channel.send(data, size, 5000000);
    int received = channel.receive(buffer, capacity, 5000000);

send/receive keep the same SPSC, buffer, privacy and ownership rules. A zero
timeout is nonblocking (-EAGAIN), -1 waits indefinitely, and positive values
specify nanoseconds measured against CLOCK_MONOTONIC. Other negative values
return -EINVAL. Deadline expiry returns -ETIMEDOUT without consuming a message
or changing the payload. Interrupted waits retry against the original deadline.
There is no delivery acknowledgement or peer-crash detection: use finite
timeouts and a separate authenticated liveness connection when needed.

The waiting path spins for at most 1024 state probes, then registers a wait bit
in the mailbox's atomic state word and sleeps on a shared FUTEX_WAIT_BITSET.
Publication uses a release exchange and FUTEX_WAKE only when a wait bit was
present. A concurrent state change either wakes the sleeper or causes the
kernel's value check to reject the sleep, avoiding a lost wakeup. No worker,
timer polling or per-message socket record is added. Waiting syscalls remain
subject to normal kernel/security visibility and policy. Existing per-operation
dumpable checks, content clearing and acquire/release publication remain active.

The wire version is now 2 because version 1 did not understand the wait bit.
Update both endpoints together; mixed versions are rejected with -EPROTO during
setup. Setup/move/close must not race any channel operation, including waits.

Objects are movable, not copyable. close()/destruction unmaps that endpoint;
the memfd storage is reclaimed after all mappings and any pending descriptor
offers are released. The API returns negative errno directly and does not use
the global driver error slot. It provides no process-global close operation.

## Verification

Run python3 tests/run_shared_ipc_host.py to build the actual production transport
at O0 and O2 and run it as a non-root Linux user. The Android build also produces
dfm_shared_ipc_check, runnable as the ordinary ADB shell user without a loaded
module. Tests establish sockets after fork and cover:

- Wrong PID/UID and stale pre-fork socket credentials, dumpable policy and
  attempts to use inherited endpoint objects.
- 4096-byte delivery, insufficient receive buffers, full/empty queues, 3000
  simultaneous bidirectional exchanges, move ownership, repeated close and
  retained-fd/mapping cleanup.
- Third-party same-UID denial of target maps, memory, fd enumeration and
  process_vm_readv, plus actual MADV_DONTFORK behavior.
- Unsealed/wrong-size/read-only descriptors, extra/truncated/missing rights,
  wrong/legacy versions, oversized records, corrupted state/length and closed peers.
  Rejected offers must not leak descriptors or leave an open channel.
- SO_PASSPIDFD plus SO_PASSCRED, when supported, on both successful and rejected
  offers; fd counts must remain unchanged. Unsupported kernels report a skip.
- Futex handoff in both directions, mixed waiting/nonblocking operations,
  timeout/retry, signal interruption, insufficient buffers and owner/policy checks.

The Android build also produces dfm_shared_ipc_latency. Run as an ordinary user:

    ./dfm_shared_ipc_latency poll 64 2000
    ./dfm_shared_ipc_latency busy 64 10000
    ./dfm_shared_ipc_latency wait 64 10000
    ./dfm_shared_ipc_latency wait 4096 10000
    ./dfm_shared_ipc_latency wait 64 2000 1000

Modes compare 1 ms sleep polling, continuous polling and the waiting API. The
optional last argument delays the echo process by that many microseconds per
exchange, allowing CPU-time comparisons for sparse traffic. Output reports
round-trip p50/p95/p99/mean in microseconds and parent process CPU time. It
validates every echoed payload and excludes 64 warmup exchanges from latency
samples (CPU time includes warmup). No CPU affinity or scheduler policy is
changed. Results depend on scheduling, load and CPU placement; the waiting API
avoids continuous idle polling, while continuous polling can still be faster.
See [shared-ipc-validation.md](shared-ipc-validation.md) for the measured baseline,
device results and local validation scope.

These checks validate this permission boundary on the tested platform, not
undetectability, different Android SELinux domains or privileged-adversary
resistance.

## OS references

- memfd_create(2), sealing and anonymous file lifetime:
  https://man7.org/linux/man-pages/man2/memfd_create.2.html
- Unix credentials and descriptor transfer:
  https://man7.org/linux/man-pages/man7/unix.7.html
- Dumpable state and ptrace access policy:
  https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html
  https://man7.org/linux/man-pages/man2/ptrace.2.html
- Mapping advice:
  https://man7.org/linux/man-pages/man2/madvise.2.html
