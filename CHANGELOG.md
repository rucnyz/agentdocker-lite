# Changelog

All notable changes to this project will be documented in this file.

## [0.0.4] - 2026-03-21

### Rootless mode parity
- **Layer cache in rootless mode**: Docker image layers are cached and shared via `userxattr` overlayfs (kernel 5.11+). No more flat rootfs extraction.
- **Full security hardening in rootless**: seccomp-bpf, capability drop, masked/read-only paths — all enabled via `adl-seccomp` with `skip_dev` marker.
- **Rootless pasta networking**: pasta runs inside the user namespace (has `CAP_SYS_ADMIN`), creating netns via `unshare --net` + bind mount.
- **localhost works for port_map**: `--ipv4-only` default resolves pasta IPv6 connection reset bug (also affects Podman rootless). New `ipv6` config option.

### Bug fixes
- **seccomp mmap fix**: `sc6()` for 6-arg syscalls — `mmap` was missing offset parameter (`r9` uninitialized), causing `EINVAL` after read-only code block changed register allocation.
- **Hostname CI fallback**: try `/proc/sys/kernel/hostname` first, fall back to `hostname` command.
- **env_base_dir uid isolation**: `/tmp/agentdocker_lite_{uid}` prevents cross-user permission conflicts.

### Internal
- Moved userns init logic from `rootful.py` to `rootless.py` (1374→1018 / 43→410 lines).
- Session-scoped rootfs cache fixture: tests use 1.7MB instead of 7-8GB, 4x faster.
- Podman benchmark added (`--no-docker`, `--no-podman` CLI flags).
- Python 3.12/3.13/3.14 × ubuntu-22.04/24.04 CI matrix.
- 132 tests total (107 root + 25 rootless).

### Breaking changes
- Requires Python >=3.12 (was >=3.10). Needed for `os.setns()` in rootless popen.
- Default `env_base_dir` changed from `/tmp/agentdocker_lite` to `/tmp/agentdocker_lite_{uid}`.

## [0.0.3] - 2026-03-21

### Added
- **CRIU checkpoint/restore**: Process-level save/restore via vendored static CRIU binary with swrk RPC protocol, enabling partial rollout support for RL workloads.
- **Docker layer-level caching**: Skip `docker pull` when all layers are cached (1000ms → 8ms create).
- **Security hardening**: Mask/readonly paths, OOM score adjustment, cpuset binding, capability drop, io_uring blocked in seccomp, Landlock ABI v8 TSYNC.
- **Observability**: `sb.pressure()` for cgroup v2 PSI monitoring, `sb.reclaim_memory()` for idle sandbox memory reclamation, `sb.features()` dict.
- **Pidfd process management**: Race-free process lifecycle via pidfd syscalls.
- **Time namespace isolation**: For CRIU monotonic clock continuity.
- **Human-readable resource limits**: e.g. `memory_max="512m"`.
- **Filesystem snapshots**: `fs_snapshot()` / `fs_restore()`.
- **`save_as_image()`**: Export sandbox state as a Docker image.
- **`list_background()`** API for inspecting background processes.

### Performance
- Replace `select()` with `epoll()` to support >1024 fd (>200 concurrent sandboxes).
- Remove pasta parallelization overhead, polling-based port_map tests.
- Sustained workload benchmarks: throughput, reset loop, checkpoint loop, concurrency.

### Bug fixes
- Fix `get_image_config` returning None for non-local images (pull before inspect).
- Fix seccomp mmap bug, clone3 returns ENOSYS instead of EPERM.
- Fix read_only marker lost after reset.
- Fix hostname CI fallback, netns bind mount leak (lazy umount).
- Fix popen after pivot_root.
- Fix mount propagation leak (rslave + setns safety checks).
- Isolate `env_base_dir` by uid to prevent cross-user permission conflicts.
- Kill background processes before shell in `delete()` to prevent mount leaks.

### Internal
- Move userns init logic from rootful.py to rootless.py, full UID mapping for SkyRL.
- Rewrite `adl-seccomp` as zero-libc static binary (13KB), mount /proc and /dev inside it.
- Rewrite pasta invocation to match Podman's approach.
- Share rootfs cache across tests via session-scoped fixture.

## [0.0.2] - 2026-03-17

### Added
- **Pasta networking**: Zero-dependency port mapping with vendored static pasta binary.
- **User namespace sandbox**: Full rootless isolation without root (`unshare --user`).
- **Filesystem snapshots**: `snapshot()` / `restore()` for instant state save/restore.
- **Hostname, DNS, read-only rootfs, IO limits** support.
- **UTS + IPC namespace isolation** (matches Docker defaults).

### Bug fixes
- Fix persistent shell startup timeout (10s → 30s) for CI environments.
- Fix crash recovery, seccomp fallback, shell restart, cache lock (P0+P1 RL reliability).
- Fix seccomp BPF jump bug.
- Fix rootless Landlock + seccomp issues.
- Fix signal pipe fd and docker pull fallback.

### Internal
- Refactored monolithic `sandbox.py` into `backends/` package.
- CI: added rootless tests, updated test filters, enabled unprivileged userns on GitHub Actions.
- Added benchmark script and expanded documentation.

## [0.0.1] - 2026-03-11

Initial release of agentdocker-lite.
