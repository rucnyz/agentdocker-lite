# SkyRL / Harbor Integration

## Overview

We built an integration to replace Harbor's `DockerEnvironment` with nitrobox in the SkyRL RL training framework. The goal is to speed up rollout by eliminating Docker container overhead during training. This document summarizes the integration architecture, what was implemented, and the **unresolved Ray permission problem** that blocks end-to-end testing.

## Architecture

SkyRL uses [Harbor](https://github.com/laude-institute/harbor) to manage sandboxed environments during RL training. The execution flow is:

```
SkyRL Training Loop (Ray-based)
  → HarborGenerator.generate(batch)          # async, runs in Ray worker
    → harbor_agent_loop() per trajectory      # up to MAX_CONCURRENCY parallel
      → Trial(TrialConfig)
        → EnvironmentFactory.create_environment_from_config()
          → BaseEnvironment.start()           # ← this is where Docker/nitrobox lives
        → Agent runs commands via env.exec()
        → Verifier runs tests via env.exec()
        → env.stop()
```

Harbor supports custom environment providers via `import_path` in config, which dynamically imports a class implementing `BaseEnvironment`.

## What Was Implemented

### 1. `NitroBoxLiteEnvironment` (Harbor provider)

**File:** `SkyRL_docker_test/examples/train_integrations/harbor/nitrobox_environment.py`

Implements Harbor's `BaseEnvironment` interface:

| Harbor method | nitrobox mapping |
|---|---|
| `start(force_build)` | Build Dockerfile → export rootfs (cached by content hash) → `NamespaceSandbox(config)` |
| `exec(cmd, cwd, env)` | `sb.run(cmd)` with cwd/env prepended via shell |
| `upload_file/dir` | `sb.copy_to()` or direct `shutil.copytree` on rootfs |
| `download_file/dir` | `sb.copy_from()` or direct `shutil.copytree` on rootfs |
| `stop(delete)` | `sb.delete()` |

Key features:
- **Rootfs caching:** Dockerfiles are hashed by content. All CodeContests tasks share the same Dockerfile, so the rootfs is built once and reused.
- **Bind mounts:** Trial log directories (`agent/`, `verifier/`, `artifacts/`) are bind-mounted into the sandbox at `/logs/*`, matching Docker's volume mount behavior.
- **WORKDIR extraction:** Automatically parses the Dockerfile to set the correct working directory.
- **Timing instrumentation:** Collects per-operation latencies (start/exec/stop) and prints a summary at process exit.

### 2. Run Scripts

- `run_harbor_gen_nitrobox.sh` — Generation-only test (10 samples, no training)
- `run_codecontest_nitrobox.sh` — Full training run

Both are identical to the Docker baselines except for:
```bash
harbor_trial_config.environment.type=null
harbor_trial_config.environment.import_path=examples.train_integrations.harbor.nitrobox_environment:NitroBoxLiteEnvironment
```

### 3. Dependency Configuration

`nitrobox` was added to SkyRL's `pyproject.toml` under the `harbor` optional dependency group:
```toml
harbor = [
    "harbor; python_version >= '3.12'",
    "nitrobox",
]

[tool.uv.sources]
nitrobox = { path = "/scratch/jingyang/nitrobox" }
```

## The Ray Permission Problem

### Root Cause

nitrobox's `NamespaceSandbox` requires root privileges for:
- `unshare --pid --mount --fork` (Linux namespace creation)
- `mount -t overlay` (overlayfs for copy-on-write filesystem)
- `mount --bind` (volume mounts)
- `chroot` (filesystem root isolation)
- cgroup v2 writes (resource limits)

The `Sandbox()` factory function checks `os.geteuid() == 0`:
- If root → `NamespaceSandbox` (full isolation)
- If not root → `LandlockSandbox` (rootless fallback, no chroot/namespace)

### Why `sudo` Doesn't Work

SkyRL runs on Ray. The execution flow is:

```
User runs: sudo bash run_harbor_gen_nitrobox.sh     ← root
  → sudo uv run ... main_harbor_generate               ← root
    → ray.get(skyrl_entrypoint.remote(cfg))             ← submits task to Ray
      → Ray worker picks up the task                    ← jingyang (NOT root)
        → HarborGenerator.harbor_agent_loop()           ← jingyang
          → NitroBoxLiteEnvironment.start()           ← jingyang
            → Sandbox() → os.geteuid() != 0             ← FAILS
              → LandlockSandbox → mkdir('/app')          ← PermissionError
```

**The `sudo` only affects the script that submits the task. The Ray worker that actually executes the code runs as the user who started the Ray cluster (`jingyang`).**

### Approaches Tried

| Approach | Result |
|---|---|
| `sudo bash run_xxx.sh` | Script runs as root, but Ray workers are still `jingyang` |
| `sudo -E bash run_xxx.sh` | Same — `-E` preserves env vars but doesn't change Ray worker uid |
| `sudo ray start --head` | Starts a new Ray session as root, but all packages need to be re-downloaded/built from scratch (uv creates isolated envs per session). Killed after 10+ min of downloading ~2GB of packages. |
| Force `NamespaceSandbox` via direct import (bypassing factory) | Still fails — the worker process itself lacks privileges for mount/unshare |
| Add `use_sudo` flag to prepend `sudo` to privileged subprocess calls | Implemented but reverted — `sudo rm -rf` in cleanup paths felt unsafe. Also requires passwordless sudo configured for the user. |

### Recommended Solutions (For Discussion)

#### Option A: Run Ray cluster as root
Start the Ray cluster with root privileges so all workers inherit root. This requires ensuring `uv` and all dependencies are accessible to root, and that the uv package cache is shared (to avoid re-downloading everything).

```bash
sudo env PATH="/home/jingyang/.local/bin:$PATH" ray start --head
```

Tradeoff: One-time setup cost to populate the package cache for root. All subsequent runs would be fast.

#### Option B: `use_sudo` with safety guards
Add a `use_sudo=True` option to `SandboxConfig` that prepends `sudo` to privileged commands (`mount`, `unshare`, `umount`, etc.). Requires:
1. Passwordless sudo for the user (already available)
2. Safety guards on `sudo rm -rf` (whitelist allowed path prefixes)
3. Changes to `NamespaceSandbox`, `_PersistentShell`, and cgroup management code

A partial implementation was done and reverted. The main concern was `sudo rm -rf` in `delete()` and `_reset_overlayfs()`. A safe version would restrict deletion to paths under a dedicated prefix (e.g., `/var/lib/nitrobox/`) rather than `/tmp/`.

#### Option C: Linux capabilities instead of full root
Grant the Ray worker process specific capabilities instead of full root:
```bash
sudo setcap cap_sys_admin,cap_sys_chroot+ep $(which python3)
```
This avoids running as root entirely. The `cap_sys_admin` capability allows `mount`/`unshare`, and `cap_sys_chroot` allows `chroot`. However, setting capabilities on the Python binary may have security implications and may not survive `uv`'s isolated environments (which use symlinked/copied Python binaries).

#### Option D: Rootless user namespaces (longer-term)
Use `unshare --user --map-root-user` to create unprivileged user namespaces. This allows mount/chroot inside the namespace without any root or capabilities. However:
- Requires `sysctl kernel.unprivileged_userns_clone=1` (may not be enabled)
- Overlayfs inside user namespaces requires kernel ≥5.11
- More complex implementation

## Standalone Benchmark (Working)

A Docker comparison benchmark was added to `tests/test_sandbox.py::TestDockerComparison`. This runs without Ray and directly compares nitrobox vs Docker:

```bash
cd /scratch/jingyang/nitrobox
sudo python -m pytest tests/test_sandbox.py::TestDockerComparison -v -s
```

This test matches Harbor's Docker flow: `docker build` → `docker run -d` → `docker exec` (N times) → `docker rm -f`, and prints a side-by-side timing comparison table.

## File Inventory

| File | Location | Purpose |
|---|---|---|
| `nitrobox_environment.py` | `SkyRL_docker_test/examples/train_integrations/harbor/` | Harbor BaseEnvironment provider |
| `run_harbor_gen_nitrobox.sh` | same directory | Generation-only test script |
| `run_codecontest_nitrobox.sh` | same directory | Full training test script |
| `NITROBOX_INTEGRATION.md` | same directory | Quick-reference doc |
| `TestDockerComparison` | `nitrobox/tests/test_sandbox.py` | A/B benchmark test |
