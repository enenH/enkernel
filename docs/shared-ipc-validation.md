# Shared IPC fix and latency validation

Measured on 2026-11-23 using the Android NDK r29 arm64/API 26 compiler,
ordinary ADB shell UID 2000, and two separate cooperating processes. No driver
operation or privileged shell was used. The pre-change SDK source was commit
6548750fb033bf9562b7f9db8ae343a220d16c1c.

## Correctness

- The added SO_PASSPIDFD/SO_PASSCRED regression failed against the original
  source at the post-accept fd-count assertion.
- After the fix, the actual SDK source compiled with -O0 and -O2 and strict
  warnings passed the full regression on both devices. Successful setup and
  malformed/truncated/missing/unsealed/read-only/legacy offers retain no fds,
  including automatically attached pidfds.
- Both devices passed real wait/wake handoff, send/receive timeouts, zero and
  infinite waits, signal interruption, undersized-buffer retry, 1000 mixed
  blocking/nonblocking echo exchanges, and the existing 3000 duplex exchanges,
  owner/dumpable checks and unprivileged observer isolation checks.
- The CMake Release build completed for the SDK, loader, example and all test
  executables. An independent consumer using find_package(enkernel) compiled,
  linked and ran against the installed send/receive API on both devices.
- Linux host tests were not run locally: this Windows machine has no WSL
  distribution. The existing Linux O0/O2 test runner remains enabled in CI.

Devices: PKR110 runs 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k;
PLZ110 runs 6.12.69-android16-6-g242e1a07f878-ab15865446-4k.

## Latency

The latency executable compiles with -O2. Baseline binaries link the original
SDK source and use -DDFM_IPC_BASELINE to omit calls to the new API. Each baseline
poll run uses 2000 samples; each new wait run uses 10000. Both exclude 64 warmup
exchanges and validate all echoed payloads. These are round trips, not measured
one-way latencies. No affinity, priority or device power settings were changed.

The final paired runs produced these microsecond values:

| Device | Payload | Original 1 ms poll p50 | New wait p50 | Original poll p99 | New wait p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PKR110 | 64 B | 1064.063 | 32.083 | 2183.125 | 121.354 |
| PKR110 | 4096 B | 1064.375 | 26.406 | 2204.427 | 78.438 |
| PLZ110 | 64 B | 1078.645 | 20.052 | 2494.219 | 68.021 |
| PLZ110 | 4096 B | 1080.104 | 35.990 | 2271.250 | 78.073 |

The millisecond baseline comes from a caller's sleep-based retry policy, not
from an inherent delay in the old shared-memory mailbox. Continuous polling
already achieved microsecond round trips. The new waiting API provides
event-driven delivery without requiring that continuous polling; it does not
claim to beat busy polling or guarantee these timings under other scheduling.

With a 1000 us delay in the echo process and 2000 measured exchanges, parent
CPU time including warmup was:

| Device | New wait CPU time | Continuous poll CPU time |
| --- | ---: | ---: |
| PKR110 | 27.446 ms | 2203.873 ms |
| PLZ110 | 44.339 ms | 2255.256 ms |

The sparse-traffic test measures CPU savings while waiting, not a reduction in
the deliberate echo delay. Reproduction commands and API timeout semantics are
in shared-ipc.md. Both peers must update to wire version 2.
