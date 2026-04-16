# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.1.0] - 2026-04-16

Major release: image backend replaced with embedded BuildKit. See
`docs/blog.md` for the architectural writeup.

### Changed
- **Image backend**: `containers/storage` + `buildah` are replaced by an embedded BuildKit server linked into the nitrobox process via Go (with rootlesskit for unprivileged operation). Image build and pull now share a single snapshot store with the sandbox runtime — no external `dockerd`, no `containerd`, no extra daemon to manage.
- **`cold-after-rmi` pull stays fast**: because the runtime uses BuildKit's snapshots directly, `rmi` no longer triggers layer re-unpack on the next pull (unlike Docker's BuildKit + containerd two-store split).
- **`sandbox.delete()` speedup**: drop the two redundant userns permission/ownership walks on the delete path. `rmtree_mapped` already enters the user namespace as mapped root and handles mapped-UID files directly. Teardown drops from seconds to ~12 ms on workloads with large upper layers (e.g. SWE-bench testbeds after pytest).
- **Persistent shell is plain bash**: image entrypoints (e.g. `/usr/bin/tini -s /run/entry.sh`) are no longer prepended to the sandbox shell. Entrypoints are for `run()`-style main processes; the persistent shell is the `docker exec` equivalent. Callers that need docker-run-style entrypoint behavior should use `sb.run_background(entrypoint_cmd)` explicitly.
- **Health check daemon**: `_wait_healthy` now mirrors Docker Engine architecture — a background `_HealthMonitor` thread runs the check command at `interval` / `start_interval`, and `_wait_healthy` polls status every 500ms (matching Docker Compose).
- **Health check defaults**: `interval` default changed from 10s to 30s, `timeout` from 5s to 30s, matching Docker Engine defaults. Added `start_interval` support (default 5s, Docker Engine 25+).
- **build-only service image inference**: `_query_compose_config()` infers `{project}-{service}` image name for services with `build:` but no `image:`.
- **`/etc/hosts` written from inside sandbox**: Uses `sb.run()` instead of host-side `write_file()` to ensure the overlay mount namespace sees the change.
- **Alpine shell compatibility**: `run()` and `run_background()` use the detected shell instead of hardcoded `bash`.

### Added
- **`PR_SET_PDEATHSIG` chain**: Rust init sets PDEATHSIG=SIGKILL on both the intermediate `unshare`ed process and the final `/bin/bash`. When the nitrobox parent dies abruptly (SIGKILL / crash), the kernel tears the whole sandbox down — no more orphan `bash --norc --noprofile` processes accumulating across crashed runs.
- **`release_layer_locks(fds)`**: companion to `acquire_layer_locks`; previously missing, which raised `ImportError` on sandbox cleanup.
- **`XDG_DATA_HOME` override**: BuildKit root respects `$XDG_DATA_HOME` (falls back to `~/.local/share/nitrobox/buildkit`). One env var relocates the entire cache to a larger disk — matches podman/helm/cargo convention.
- **BuildKit `TMPDIR` routed to `<root>/tmp`**: the solver's scratch dirs (`os.MkdirTemp("", "buildkit-mount")`) land next to the cache instead of in `/tmp`. Avoids filling a small/tmpfs `/tmp` on SWE-bench-class workloads.
- **`nitrobox buildkit-stop`** CLI command to stop the managed buildkitd daemon.
- **`extra_hosts`**: Compose `extra_hosts` entries are written to `/etc/hosts` inside the sandbox (also survives `reset()`).
- **`sysctls`**: Compose `sysctls` are applied by writing to `/proc/sys/` inside the sandbox. Failures are logged but non-fatal.
- **`depends_on` condition**: `_parse_depends_on` preserves `condition` (`service_started` / `service_healthy`).
- **Parallel health check waiting**: After all services start, `_wait_all_healthy` polls all monitors simultaneously (equivalent to `docker compose up --wait`).
- **`init`, `user`, `pid`, `ipc`**: Compose fields no longer error — parsed and safely ignored.

### Fixed
- **Health check timeout**: Uses `default_timeout` as overall deadline instead of compose `retries` count.
- **`release_layer_locks` missing**: the delete() path imported a function that didn't exist; now implemented.

### CI / Infra
- Branch protection enabled on `main`: `Tests`, `Docs`, `Rust (clippy + audit + fmt)`, `Lint` are required for merge (strict mode).
- Docs workflow now also runs on pull requests (deploy remains gated on push).
- Repo-level auto-merge enabled.

### Removed
- `buildah` / `containers/storage` dependencies and all associated Go code.
- Old image store helpers (`_get_store_layers`, `Sandbox._get_image_digest`, `get_buildkit_layers`) and their tests.

## [0.0.5] - 2026-03-24

### Added
- **Docker compatibility layer**: `SandboxConfig.from_docker()` accepts Docker Python SDK kwargs, `SandboxConfig.from_docker_run()` parses `docker run` CLI strings. Zero-effort migration from Docker.
- **Image config auto-apply**: `Sandbox()` automatically reads OCI image config and backfills `WORKDIR` and `ENV` — user values always take precedence.
- **Resource limit sugar**: `cpu_max` accepts `"0.5"`, `"2"`, `"50%"` (not just raw cgroup format). `io_max` accepts `"/dev/sda 10mb"`. `_parse_size` supports `"10mb"`, `"1gb"` suffixes.
- **SWE-bench benchmark**: `examples/bench_swebench.py` — reproducible Docker vs nitrobox comparison with SWE-bench-style evaluation loop.
- **GitHub Pages docs**: mkdocs-material site at opensage-agent.github.io/nitrobox, auto-deployed on push.
- **Auto-release on tag push**: `git tag v0.0.x && git push --tags` triggers PyPI publish + GitHub Release with auto-generated notes.
- **Branch protection**: main requires CI to pass via PR.

### Changed
- **pyyaml is now a default dependency** (was optional `[compose]` extra). Simplifies install for compose users.
- README restructured: "Drop-in Docker replacement" section with SWE-bench real-world comparison, updated migration cheatsheet with auto-convert entries.

### Fixed
- **`_host_path()` userns multi-layer bug**: `read_file()`/`copy_from()` in userns mode now searches all image layers (top to bottom), not just the first layer.

### Internal
- **Rust core**: Security primitives (seccomp, capabilities, Landlock), namespace spawning, overlayfs mounting moved to Rust via PyO3. `PySpawnResult` pyclass + `SpawnConfig` TypedDict for typed FFI boundary.
- **Architecture refactor**: Merged `SandboxBase` + `RootfulSandbox` + `RootlessSandbox` into single `Sandbox` class. Old `backends/` package removed.
- **File reorganization**: `SandboxConfig` extracted to `config.py`. `compose.py` split into `compose/` subpackage (`_parse.py`, `_network.py`, `_project.py`). Thin wrapper files (`security.py`, `_pidfd.py`, `_mount.py`) removed — callers use `_core` directly.
- **Context manager**: `Sandbox` supports `with Sandbox(...) as sb:` for automatic cleanup.
- **Structured error types**: `SandboxError` hierarchy (`SandboxInitError`, `SandboxConfigError`, `SandboxKernelError`, `SandboxTimeoutError`) replaces generic `RuntimeError`/`ValueError`.
- **Init deduplication**: Extracted `_init_common_state`, `_build_spawn_config`, `_finalize_init` helpers — `_init_rootful`/`_init_userns` share ~60% common logic instead of duplicating it.
- **cgroup via Rust**: `_setup_cgroup`/`_cleanup_cgroup` now delegate to `py_create_cgroup`/`py_apply_cgroup_limits`/`py_cleanup_cgroup` from Rust `_core` instead of manual Python file writes.
- **Landlock config merged**: `_build_landlock_config` and `_landlock_lists` merged into single method, dead nbx-seccomp string config removed.
- **Rootfs resolution unified**: `_resolve_btrfs_rootfs`/`_resolve_flat_rootfs` share `_resolve_cached_rootfs` helper for lock-check-prepare pattern.
- **Type annotations**: `Optional[X]` → `X | None` throughout (Python 3.12+ style).
- **Type safety**: `SandboxFeatures` TypedDict, auto-generated `.pyi` stubs via pyo3-stub-gen, 0 pyright errors.
- 239 tests, 0 Rust warnings, 0 pyright errors.

## [0.0.4] - 2026-03-21

### Rootless mode parity
- **Layer cache in rootless mode**: Docker image layers are cached and shared via `userxattr` overlayfs (kernel 5.11+). No more flat rootfs extraction.
- **Full security hardening in rootless**: seccomp-bpf, capability drop, masked/read-only paths — all enabled via `nbx-seccomp` with `skip_dev` marker.
- **Rootless pasta networking**: pasta runs inside the user namespace (has `CAP_SYS_ADMIN`), creating netns via `unshare --net` + bind mount.
- **localhost works for port_map**: `--ipv4-only` default resolves pasta IPv6 connection reset bug (also affects Podman rootless). New `ipv6` config option.

### Bug fixes
- **seccomp mmap fix**: `sc6()` for 6-arg syscalls — `mmap` was missing offset parameter (`r9` uninitialized), causing `EINVAL` after read-only code block changed register allocation.
- **Hostname CI fallback**: try `/proc/sys/kernel/hostname` first, fall back to `hostname` command.
- **env_base_dir uid isolation**: `/tmp/nitrobox_{uid}` prevents cross-user permission conflicts.

### Internal
- Moved userns init logic from `rootful.py` to `rootless.py` (1374→1018 / 43→410 lines).
- Session-scoped rootfs cache fixture: tests use 1.7MB instead of 7-8GB, 4x faster.
- Podman benchmark added (`--no-docker`, `--no-podman` CLI flags).
- Python 3.12/3.13/3.14 × ubuntu-22.04/24.04 CI matrix.
- 132 tests total (107 root + 25 rootless).

### Breaking changes
- Requires Python >=3.12 (was >=3.10). Needed for `os.setns()` in rootless popen.
- Default `env_base_dir` changed from `/tmp/nitrobox` to `/tmp/nitrobox_{uid}`.

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
- Rewrite `nbx-seccomp` as zero-libc static binary (13KB), mount /proc and /dev inside it.
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

Initial release of nitrobox.
