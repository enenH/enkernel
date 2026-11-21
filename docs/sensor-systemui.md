# Restricted SensorService sessions from SystemUI

DFM_CAP_SENSOR_SYSTEMUI adds a caller policy to the existing
MEM_IOC_OPEN_PROCESS_MEM operation. It does not introduce a gyroscope injection
ioctl, expand the target address range, or change an existing ABI layout.

Root and the existing verified SurfaceFlinger caller remain supported. The added
SystemUI path requires all of the following:

- The driver file description was opened with root UID/EUID in the initial user
  namespace, then explicitly delegated to the caller, for example by SCM_RIGHTS.
- The caller is in the initial user namespace with equal real/effective/saved/fs
  UIDs. The SystemUI UID is not hardcoded; OEM and Android user IDs may differ.
- Its full argv[0] is exactly com.android.systemui, including the terminating
  NUL. Thread names, truncated task comm, suffixes and secondary process names
  are not used to grant the role. Worker threads share the process argv.
- Its executable resolves to /system/bin/app_process64, is root-owned and is
  not group/world writable.

Root's deliberate fd delegation is the authorization boundary. Names and argv
are mutable and are role checks, not cryptographic package authentication. A
new driver fd opened directly by an unprivileged process, even one renamed to
SystemUI, does not satisfy this policy. The root launcher must choose the process
that receives the descriptor. No root subprocess is needed for subsequent calls.

SystemUI invokes the existing operation on that delegated driver descriptor and
owns the returned session fd in its own TGID. The session still only targets the
UID-1000 system_server process and private /system/lib64/libsensorservice.so
mappings. Existing COW writes, owner checks, exited/replaced-mm rejection,
single-session serialization, arm-before-publication and final-close cleanup
remain unchanged. A session fd opened in a root helper cannot be transferred
and used as though it were owned by SystemUI; SystemUI must open its own session.

Validation: tests/process_mem_policy.cpp executes the production policy
predicate on the host, including exact-name/path checks, varying UIDs, missing
root delegation, credential mismatch, untrusted executable and namespace cases.
The SDK workflow runs it before cross compiling. Kernel build CI covers the
actual caller extraction and API compatibility across the six supported KMIs.
Compilation/host checks do not establish successful session opening, sensor
hook behavior or final-close cleanup on a device. No module load/unload or target
write is part of these checks.
