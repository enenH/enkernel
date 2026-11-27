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

The DFM loader checks `/sys/module/dfm/parameters/unload_supported` for `Y`. It closes its driver handle and writes `1` to `/sys/module/dfm/parameters/prepare_unload` before requesting normal removal of `dfm`. The preparation parameter reads `Y` while new connections are paused, so a later loader run can finish a pending removal.

Preparation returns an error while a driver client, process-memory session, legacy touch proxy, or queued touch release still needs the module. If restoring or draining a kernel hook fails, preparation keeps the module referenced and can be retried.
