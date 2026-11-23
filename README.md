# KernelSU — Samsung late-load fork

<img src="website/docs/public/logo.png" style="width: 96px;" alt="logo">

**Vanilla KernelSU app + kernel module, unchanged from upstream, with exactly one addition: Samsung late-load support.** No extra patches, no behavior changes. The manager's update checker points at this fork's releases, so an update can never install an upstream build that drops Samsung support.

One build targets all supported Samsung devices; device and kernel differences are detected at runtime, not build time.

## Install

For Samsung Galaxy devices on the protected stock kernel (One UI), rooted via [DFRoot](https://github.com/KabilDja/DFRoot-Next/releases/tag/v1.0). Not a Samsung, or already on regular KernelSU? Use [upstream](https://github.com/tiann/KernelSU).

1. Get the manager APK from [Releases](../../releases).
2. Follow [DFRoot](https://github.com/KabilDja/DFRoot-Next/releases/tag/v1.0) — it handles the exploit and late-loads KernelSU. First run: **Start on Boot OFF**, **Disable KSU Modules ON**, normal reboot before running.

> [!WARNING]
> Test builds. Exploit + late-loaded kernel module can crash or bootloop your phone; keep stock firmware and a working Odin path ready. Not affiliated with upstream — don't report this fork's issues there.

## Credits

- [tiann/KernelSU](https://github.com/tiann/KernelSU) — almost everything in this repo is upstream's work.
- [diabl0w](https://github.com/diabl0w) — the Samsung late-load patch ([tiann/KernelSU#3899](https://github.com/tiann/KernelSU/pull/3899)) and [DFRoot](https://github.com/diabl0w/DFRoot).
- [backslashxx](https://github.com/backslashxx) — the earlier Samsung fork ([tests/samsung](https://github.com/backslashxx/KernelSU/tree/tests/samsung)) that proved this approach.

## License

Same as upstream: GPL-3.0 (see [LICENSE](LICENSE)); kernel code under [kernel/](kernel/LICENSE) is GPL-2.0.
