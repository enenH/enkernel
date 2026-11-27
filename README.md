# enkernel

This repository maintains the Android kernel module `dfm.ko`, its shared ABI in [abi.h](abi.h), and the module release workflow. The userspace driver, loader, and tools are maintained in `dfm-plus-gongyi`.

## Build

Use the Android kernel build environment for the target KMI and point `KERNEL_SRC` at its kernel build tree.

```sh
make -j"$(nproc)" KDIR="$KERNEL_SRC"
```

## Release assets

CI builds one module per supported KMI. Each `dfm-<kmi>.ko.zip` contains `dfm-<kmi>.ko` and has a companion `dfm-<kmi>.ko.zip.sha256` file. Pull request archives are available in the `dfm-kernel-modules` workflow artifact.

## Unload

The DFM loader checks `/sys/module/dfm/parameters/unload_supported` for `Y`. It closes its driver handle and writes `1` to `/sys/module/dfm/parameters/prepare_unload` before requesting normal removal of `dfm`. The preparation parameter reads `Y` while new connections are paused, so a later loader run can finish a pending removal.

Preparation returns an error while a driver client, process-memory session, legacy touch proxy, or queued touch release still needs the module. If restoring or draining a kernel hook fails, preparation keeps the module referenced and can be retried.
