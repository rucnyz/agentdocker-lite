# nitrobox

[![Tests](https://github.com/opensage-agent/nitrobox/actions/workflows/test.yml/badge.svg)](https://github.com/opensage-agent/nitrobox/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/nitrobox)](https://pypi.org/project/nitrobox/)
[![Python](https://img.shields.io/pypi/pyversions/nitrobox)](https://pypi.org/project/nitrobox/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Lightweight Linux namespace sandbox with persistent shell and instant filesystem reset.

**50x faster lifecycle** than Docker. Designed for high-frequency workloads like RL training where environments are created, reset, and destroyed thousands of times.

## Drop-in Docker replacement

Real-world example: [SWE-bench](https://www.swebench.com/) evaluation runs 2,294 task instances, each creating a Docker container, applying a patch, running tests, and destroying it. Here's how to migrate:

<table>
<tr><th>SWE-bench (Docker SDK)</th><th>nitrobox</th></tr>
<tr>
<td>

```python
import docker
client = docker.from_env()

for task in swebench_tasks:
    # Create — ~320ms
    c = client.containers.run(
        task.instance_image,
        command="tail -f /dev/null",
        detach=True,
    )
    # Eval — ~17ms/cmd
    c.exec_run("bash /eval.sh")

    # "Reset" = destroy + recreate — ~820ms
    c.stop(); c.remove()
```
</td>
<td>

```python
from nitrobox import Sandbox, SandboxConfig

for task in swebench_tasks:
    # Create — ~25ms (13x faster)
    sb = Sandbox(SandboxConfig.from_docker(
        task.instance_image,
    ))
    # Eval — ~11ms/cmd (1.6x faster)
    sb.run("bash /eval.sh")

    # Reset — ~16ms (38x faster, no recreate)
    sb.reset()
```
</td>
</tr>
</table>

Same images, same parameters — no root required. Also supports [`from_docker_run()`](docs/quick_start.md#sandboxconfigfrom_docker_run-cli-command-string) for CLI commands and [`ComposeProject`](docs/quick_start.md#docker-compose-compatibility) for docker-compose.yml.

Reproduce: `python examples/bench_swebench.py` (numbers above measured on Ryzen 9800X3D; results vary by CPU)

## Key features

- **No root required**: Full isolation via user namespaces (overlayfs, PID/UTS/IPC/net namespace, chroot)
- **Persistent shell**: ~11ms per command (vs ~17ms Docker exec)
- **Instant reset**: O(1) overlayfs upper rename — ~7ms including shell restart
- **Fast lifecycle**: ~7ms create, ~2ms delete
- **Process checkpoint/restore**: Full process-state save/restore (memory, registers, fds) for RL partial rollout
- **Port mapping**: Vendored `pasta` binary for NAT + TCP port forwarding, zero dependencies
- **Security hardening**: seccomp-bpf, Landlock, masked/readonly paths, capability drop — all on by default
- **OCI ENTRYPOINT**: Auto-runs image entrypoint scripts (e.g. database init). ComposeProject combines entrypoint+CMD as background process matching Docker semantics
- **cgroup v2**: CPU, memory, PID, IO limits with PSI pressure monitoring
- **Docker layer caching**: Shared base layers across images, skip pull when cached
- **Docker Compose compatibility**: Parse `docker-compose.yml`, per-network isolation via shared namespaces, Docker-matching health check daemon (`interval`, `start_period`, `start_interval`, `retries`)
- **CLI**: `nitrobox ps/kill/cleanup` for sandbox management

## Requirements

- Linux kernel 5.11+
- `util-linux` (`unshare`)
- Python >= 3.12

No Docker or Podman required. Images are pulled directly from container registries via built-in OCI client. If Docker/Podman is available, it's used for faster local cache hits.

The pip package bundles static binaries for `pasta` (port mapping) and `criu` (process checkpointing) — no extra install needed.

### Ubuntu 24.04 / 23.10+ (AppArmor)

Ubuntu defaults to blocking unprivileged user namespaces. Run once to enable:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# Persist across reboots:
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
```

## Install

```bash
pip install nitrobox
```

### Development build

Requires [Rust](https://rustup.rs/) and [maturin](https://www.maturin.rs/):

```bash
pip install maturin
maturin develop --release        # build Rust core + install in-place
pytest tests/                    # run tests
```

To regenerate type stubs after changing Rust bindings:

```bash
cargo run --bin stub_gen --release
```

## Quick start

```python
from nitrobox import Sandbox, SandboxConfig

config = SandboxConfig(
    image="ubuntu:22.04",
    working_dir="/workspace",
)

with Sandbox(config, name="worker-0") as sb:
    output, ec = sb.run("echo hello world")
    print(output)  # "hello world\n"

    sb.write_file("/workspace/payload.py", "print('hello')")
    content = sb.read_file("/workspace/payload.py")

    sb.reset()   # instant filesystem reset
# auto cleanup on exit
```

No `sudo` required. The sandbox automatically uses user namespaces for full isolation. OCI image config (`WORKDIR`, `ENV`, `ENTRYPOINT`) is auto-applied — user values take precedence.

## Configuration

```python
SandboxConfig(
    image="ubuntu:22.04",           # Docker image or rootfs path
    working_dir="/workspace",       # Initial cwd inside sandbox
    environment={"FOO": "bar"},     # Extra env vars
    hostname="worker-0",            # Custom hostname (UTS namespace)
    dns=["8.8.8.8", "1.1.1.1"],    # Custom DNS servers
    read_only=True,                 # Read-only rootfs

    # Volumes
    volumes=[
        "/host/data:/data:ro",          # read-only bind mount
        "/host/project:/workspace:rw",  # read-write bind mount
        "/host/project:/workspace:cow", # copy-on-write (overlayfs)
    ],

    # Resource limits (cgroup v2)
    cpu_max="0.5",                  # 50% of one CPU (also: "2" for 2 cores, "50%")
    memory_max="512m",              # 512MB (also accepts "2g", "536870912")
    memory_swap="1g",               # total memory+swap (Docker semantics)
    pids_max="256",
    cpu_shares=1024,                # relative CPU weight (Docker --cpu-shares)
    io_max="/dev/sda 10mb",         # 10MB/s write limit (also: "rbps=5mb wbps=10mb")
    cpuset_cpus="0-3",              # Pin to CPU 0-3
    oom_score_adj=500,              # Prefer killing sandbox over host
    shm_size="256m",                # /dev/shm size (default 256m)
    tmpfs=["/run:size=100m"],       # additional tmpfs mounts

    # Networking
    net_isolate=True,               # Loopback only (or use port_map for NAT)
    port_map=["8080:80", "3000:3000"],  # host:container TCP ports

    # Security
    seccomp=True,                   # seccomp-bpf (default: True)
    writable_paths=["/workspace"],  # Landlock: only these paths writable (None=no restriction)
    readable_paths=["/usr", "/lib"],# Landlock: only these paths readable (None=no restriction)
    allowed_ports=[80, 443],        # Landlock: only these TCP ports connectable (None=no restriction)
    # Devices (rootless: user must have group access, e.g. kvm group)
    devices=["/dev/nvidia0", "/dev/nvidiactl"],

    # Capabilities
    cap_add=["NET_RAW", "NET_ADMIN"],  # Extra capabilities to keep (applied at runtime via Rust init chain)

    # OCI entrypoint (auto-filled from image config if not set)
    # Direct Sandbox API: wraps the shell; ComposeProject: runs as background with CMD
    entrypoint=["/docker-entrypoint.sh"],
)
```

## API

| Method | Description |
|--------|-------------|
| `sb.run(cmd, timeout=None)` | Run command, returns `(output, exit_code)` |
| `sb.reset()` | Reset filesystem to initial state |
| `sb.delete()` | Full cleanup (unmount, remove cgroup, delete files) |
| `sb.copy_to(local, container)` | Copy file into sandbox |
| `sb.copy_from(container, local)` | Copy file out of sandbox |
| `sb.read_file(path)` | Read file content |
| `sb.write_file(path, content)` | Write file content |
| `sb.popen(cmd)` | Start interactive process (stdin/stdout/stderr pipes) |
| `sb.run_background(cmd)` | Start background process, returns handle |
| `sb.check_background(handle)` | Check output and status |
| `sb.list_background()` | List all background processes |
| `sb.stop_background(handle)` | Stop a background process |
| `sb.snapshot("tag")` | Save filesystem state (tag optional, auto-ID if omitted) |
| `sb.restore("tag")` | Restore to a snapshot (omit for latest) |
| `sb.list_snapshots()` | List available snapshot tags/IDs |
| `sb.delete_snapshot("tag")` | Delete a snapshot |
| `sb.save_as_image(name)` | Export sandbox as Docker image |
| `sb.pressure()` | cgroup v2 PSI (cpu/memory/io) |
| `sb.reclaim_memory()` | Hint kernel to swap out idle pages |
| `sb.features` | Dict of active kernel features |
| `sb.rootfs` | Host path to sandbox rootfs |
| `await sb.arun(cmd)` | Async version of `run()` |
| `await sb.areset()` | Async version of `reset()` |
| `await sb.adelete()` | Async version of `delete()` |
| `await sb.asnapshot()` | Async version of `fs_snapshot()` |
| `await sb.arestore()` | Async version of `fs_restore()` |

### Snapshots (RL step-wise rollback)

Save and restore filesystem state at any point. Useful for tree search, partial rollback, and best-of-N exploration:

```python
# Named snapshots (like Docker tags)
sb.snapshot("before_test")
sb.run("risky change")
sb.restore("before_test")        # rollback by name

# Auto-ID snapshots
sb.snapshot()                     # → 0
sb.snapshot()                     # → 1
sb.restore()                     # restore to latest (1)
sb.restore(0)                    # restore to specific ID

# Tree search
branch = sb.snapshot("branch_point")
sb.run("action_a")               # try A
sb.restore("branch_point")       # rollback
sb.run("action_b")               # try B
```

### Async API

All core methods have async variants (`arun`, `areset`, `adelete`, `asnapshot`, `arestore`) for use in async frameworks (Ray, asyncio-based RL loops):

```python
async def rollout(i):
    sb = Sandbox(SandboxConfig(image="ubuntu:22.04"), name=f"worker-{i}")
    output, ec = await sb.arun("python solve.py")
    await sb.areset()
    await sb.adelete()

await asyncio.gather(*(rollout(i) for i in range(100)))
```

### Process checkpointing (CRIU)

Full process-state checkpoint/restore — memory, registers, fds, cwd. Requires root; CRIU binary is bundled.

```python
from nitrobox import CheckpointManager

mgr = CheckpointManager(sb)
sb.run("echo state_v1 > /workspace/data.txt")

mgr.save("/tmp/ckpt_v1")       # sandbox keeps running
sb.run("rm -rf /workspace/*")  # destructive work
mgr.restore("/tmp/ckpt_v1")    # exact rollback

output, _ = sb.run("cat /workspace/data.txt")
# "state_v1\n" — fully restored
```

## Performance

| | Docker | nitrobox | Speedup |
|---|---|---|---|
| Create | 320ms | 25ms | **13x** |
| Per command | 17ms | 11ms | **1.6x** |
| Reset | 605ms | 16ms | **38x** |
| Delete | 217ms | 2ms | **109x** |
| Throughput | — | 94 cmd/s | — |
| Reset loop | 2.0/s | 62.8/s | **31x** |
| 16x concurrent | 32 cmd/s | 655 cmd/s | **20x** |

Full benchmark (checkpoint, concurrency, sustained workloads): [docs/quick_start.md](docs/quick_start.md#performance) | Reproduce: `python examples/benchmark.py`

## Docker migration cheatsheet

**Auto-convert** — paste your existing Docker invocation directly:

| Docker | nitrobox |
|---|---|
| `client.containers.run("img", cpus=0.5, ...)` | `SandboxConfig.from_docker("img", cpus=0.5, ...)` |
| `docker run --cpus=0.5 -m 512m img` | `SandboxConfig.from_docker_run("docker run ...")` |
| `docker compose up -d` | `ComposeProject("docker-compose.yml").up()` |

See [docs/quick_start.md](docs/quick_start.md) for full parameter mapping, compose field support, and CLI reference (`nitrobox ps/kill/cleanup`).

## Architecture

```
Host kernel (shared)
  |
  +-- Sandbox "worker-0"
  |     +-- User namespace (rootless) or real root
  |     +-- PID namespace (unshare --pid)
  |     +-- Mount namespace (unshare --mount)
  |     +-- UTS namespace (custom hostname)
  |     +-- IPC namespace
  |     +-- Network namespace (optional, with pasta NAT)
  |     +-- Time namespace (for CRIU clock continuity)
  |     +-- chroot into overlayfs rootfs
  |     |     +-- lowerdir: shared base layers (read-only, cached)
  |     |     +-- upperdir: per-sandbox changes (cleared on reset)
  |     +-- Persistent bash process (stdin/stdout pipes + signal fd)
  |     +-- seccomp-bpf + Landlock + capability drop
  |     +-- cgroup v2 limits + PSI monitoring
  |
  +-- Sandbox "worker-1"
  |     +-- (same structure, independent namespaces)
  ...
```

## Examples

```bash
python examples/basic_usage.py      # Full feature demo
python examples/bench_swebench.py   # SWE-bench-style Docker vs nitrobox comparison
python examples/benchmark.py        # Full performance comparison (all backends)
```

See [docs/quick_start.md](docs/quick_start.md) for detailed usage guide.
