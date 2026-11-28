# enkernel

This repository maintains the Android kernel module `dfm.ko`, its shared ABI in [abi.h](abi.h), and the module release workflow. The userspace driver, loader, and tools are maintained in `dfm-plus-gongyi`.

## Build

Use the Android kernel build environment for the target KMI and point `KERNEL_SRC` at its kernel build tree.

```sh
make -j"$(nproc)" KDIR="$KERNEL_SRC"
```

## Release assets

CI builds one module per supported KMI. Each `dfm-<kmi>.ko.zip` contains `dfm-<kmi>.ko` and has a companion `dfm-<kmi>.ko.zip.sha256` file. Pull request archives are available in the `dfm-kernel-modules` workflow artifact.

## SurfaceFlinger SELinux access

The module registers an `avc_denied` return probe for the exact source context
`u:r:surfaceflinger:s0`. It changes that subject's `-EACCES` results to success
for all targets, classes and requested permissions handled by `avc_denied`.
The source SID is resolved and round-trip checked against the loaded policy at
initialization; process names, current-task credentials and target SIDs do not
grant access. SELinux enforcing state, policy, AVC decisions/cache and audit
hooks are not changed. DAC and checks outside `avc_denied` still apply.

This replaces the separate root-manager policy package. The read-only capability
handshake advertises `DFM_CAP_SF_AVC_BYPASS` only while the probe is registered.
The SF injector requires this bit and asks for a reboot if an already loaded
driver lacks it; core-only clients do not require the bit. Userspace downloads
kernel modules from this repository's latest release, so deploy/release the
updated module alongside the updated injector.

The probe uses the target kernel's SELinux declarations and checks the AVC
argument layout for the supported GKI families. SID lookup or probe registration
failure leaves the SF capability unset and logs the error; Core clients remain
usable, while SF injection reports the reboot-required message. Unload
preparation unregisters the probe
before releasing the module's lifetime reference; init failure and module exit
also clean it up. A missed return probe preserves the original denial and is
reported on teardown. The implementation follows the return-probe approach in
`kernel_draw/io/kd_vfs_security.c`.

## Unload

Loading calls `kobject_del(&THIS_MODULE->mkobj.kobj)` after taking the module's
lifetime reference. The loader-owned sysfs objects stay alive. An explicit root
unload request restores their original attributes, parameters, sections, notes
and holders directory; ordinary driver lookup and capability checks keep them
detached.

After stopping the overlay and other driver clients, run the userspace maintenance
command and then normal removal:

```sh
adb shell su -c '/data/local/tmp/dfm_plus --prepare-module-unload'
adb shell su -c 'rmmod dfm'
```

The command uses `DFM_MODULE_IOC_EXPOSE_UNLOAD`, closes its control handle, then
checks `unload_supported` and writes `prepare_unload`. The ioctl requires
`CAP_SYS_MODULE` and the last driver client. It pauses new connections while
restoring sysfs. Restore failure rolls back the partial directory and reopens
admission; successful restore leaves it paused for unload. The preparation
parameter reads `Y` while connections are paused, so a later command can finish
a pending preparation.

Preparation returns an error while a driver client, process-memory session, legacy touch proxy, or queued touch release still needs the module. If restoring or draining a kernel hook fails, preparation keeps the module referenced and can be retried.

## File observations for UDP callbacks

The optional `DFM_CAP_FILE_OBSERVER` capability supplies invocation-scoped observer
FDs. Their query ioctl returns file metadata and native `SEEK_DATA`/`SEEK_HOLE`
results, with separate transport errors and guest errno. Pinned target file
references provide opaque identities shared by duplicated FDs. Observers hold
their parent driver client until release, so unload cannot overtake a query.

Supported file-operation profiles follow `kernel_draw/io/kd_file.c`. F2FS sparse
queries use a verified independent `O_PATH` cursor, preserving the target open
file description's position. Unknown operations and unavailable helpers fail
explicitly. The userspace emulator maintains its own positions; no query writes
target process memory or advances the target FD.
