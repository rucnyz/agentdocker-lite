# agentdocker-lite

[![Tests](https://github.com/opensage-agent/agentdocker-lite/actions/workflows/test.yml/badge.svg)](https://github.com/opensage-agent/agentdocker-lite/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/agentdocker-lite)](https://pypi.org/project/agentdocker-lite/)
[![Python](https://img.shields.io/pypi/pyversions/agentdocker-lite)](https://pypi.org/project/agentdocker-lite/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Lightweight Linux namespace sandbox with persistent shell and instant filesystem reset.

**20–100x faster lifecycle** than Docker. Designed for high-frequency workloads like RL training where environments are created, reset, and destroyed thousands of times.

## Key features

- **No root required**: Full isolation via user namespaces (overlayfs, PID/UTS/IPC/net namespace, chroot)
- **Persistent shell**: ~12ms per command (vs ~80ms Docker exec)
- **Instant reset**: overlayfs upper layer clear — ~50ms including shell restart
- **Fast lifecycle**: ~40ms create, ~9ms delete
- **Process checkpoint/restore**: Full process-state save/restore (memory, registers, fds) for RL partial rollout
- **Port mapping**: Vendored `pasta` binary for NAT + TCP port forwarding, zero dependencies
- **Security hardening**: seccomp-bpf, Landlock, masked/readonly paths, capability drop — all on by default
- **cgroup v2**: CPU, memory, PID, IO limits with PSI pressure monitoring
- **Docker layer caching**: Shared base layers across images, skip pull when cached

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
pip install agentdocker-lite
```

## Quick start

```python
from agentdocker_lite import Sandbox, SandboxConfig

config = SandboxConfig(
    image="ubuntu:22.04",
    working_dir="/workspace",
)
sb = Sandbox(config, name="worker-0")

output, ec = sb.run("echo hello world")
print(output)  # "hello world\n"

sb.write_file("/workspace/payload.py", "print('hello')")
content = sb.read_file("/workspace/payload.py")

sb.reset()   # instant filesystem reset
sb.delete()  # full cleanup
```

No `sudo` required. The sandbox automatically uses user namespaces for full isolation.

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
    cpu_max="50000 100000",         # 50% of one CPU
    memory_max="512m",              # 512MB (also accepts "2g", "536870912")
    pids_max="256",
    io_max="/dev/sda 10485760",     # 10MB/s write limit
    cpuset_cpus="0-3",              # Pin to CPU 0-3
    oom_score_adj=500,              # Prefer killing sandbox over host

    # Networking
    net_isolate=True,               # Loopback only (or use port_map for NAT)
    port_map=["8080:80", "3000:3000"],  # host:container TCP ports

    # Security
    seccomp=True,                   # seccomp-bpf (default: True)
    writable_paths=["/workspace"],  # Landlock: only these paths writable (None=no restriction)
    readable_paths=["/usr", "/lib"],# Landlock: only these paths readable (None=no restriction)
    allowed_ports=[80, 443],        # Landlock: only these TCP ports connectable (None=no restriction)
    # Devices (root only)
    devices=["/dev/nvidia0", "/dev/nvidiactl"],
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
from agentdocker_lite import CheckpointManager

mgr = CheckpointManager(sb)
sb.run("echo state_v1 > /workspace/data.txt")

mgr.save("/tmp/ckpt_v1")       # sandbox keeps running
sb.run("rm -rf /workspace/*")  # destructive work
mgr.restore("/tmp/ckpt_v1")    # exact rollback

output, _ = sb.run("cat /workspace/data.txt")
# "state_v1\n" — fully restored
```

### Crash recovery

```python
from agentdocker_lite import SandboxBase
SandboxBase.cleanup_stale()
```

## Performance

### Single-operation latency

| | Docker | agentdocker-lite | Speedup |
|---|---|---|---|
| Create | 2448ms | 43ms | **57x** |
| Per command | 79ms | 12ms | **7x** |
| Reset | 2038ms | 53ms | **39x** |
| Delete | 915ms | 9ms | **104x** |
| Checkpoint save | — | 55ms | — |
| Checkpoint restore | — | 47ms | — |

### Sustained workloads

| | Docker | agentdocker-lite | Speedup |
|---|---|---|---|
| Throughput (1000 cmds) | 12 cmd/s | 81 cmd/s | **6.7x** |
| Reset loop (100 cycles) | 0.6/s | 19.0/s | **34x** |
| Checkpoint restore loop (50 cycles) | — | 16.0/s | — |
| 4x concurrent (10 cmds each) | 11 cmd/s | 208 cmd/s | **19x** |
| 8x concurrent | 13 cmd/s | 363 cmd/s | **27x** |
| 16x concurrent | 20 cmd/s | 423 cmd/s | **21x** |

Reproduce: `python examples/benchmark.py`

## Docker migration cheatsheet

| Docker | agentdocker-lite |
|---|---|
| `docker run -d ubuntu:22.04` | `sb = Sandbox(SandboxConfig(image="ubuntu:22.04"))` |
| `docker exec <id> echo hello` | `sb.run("echo hello")` |
| `docker exec -it <id> bash` | `proc = sb.popen("bash")` |
| `docker cp file.txt <id>:/path` | `sb.copy_to("file.txt", "/path")` |
| `docker cp <id>:/path file.txt` | `sb.copy_from("/path", "file.txt")` |
| `docker rm -f <id> && docker run -d ...` | `sb.reset()` |
| `docker rm -f <id>` | `sb.delete()` |
| `-v /host:/container:ro` | `volumes=["/host:/container:ro"]` |
| `-v /host:/container:rw` | `volumes=["/host:/container:rw"]` |
| *(no equivalent)* | `volumes=["/host:/container:cow"]` |
| `--memory 512m` | `memory_max="512m"` |
| `--cpus 0.5` | `cpu_max="50000 100000"` |
| `--pids-limit 256` | `pids_max="256"` |
| `--hostname worker-0` | `hostname="worker-0"` |
| `--dns 8.8.8.8` | `dns=["8.8.8.8"]` |
| `--read-only` | `read_only=True` |
| `--network none` | `net_isolate=True` |
| `-p 8080:80` | `net_isolate=True, port_map=["8080:80"]` |
| `docker checkpoint create` (CRIU) | `CheckpointManager(sb).save("/path")` |
| `docker start --checkpoint` | `CheckpointManager(sb).restore("/path")` |
| `--gpus all` | `devices=["/dev/nvidia0", ...]` (root only) |
| `--security-opt seccomp=...` | `seccomp=True` (default) |
| `--cpuset-cpus 0-3` | `cpuset_cpus="0-3"` |

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
python examples/basic_usage.py     # Full feature demo
python examples/benchmark.py       # Performance comparison vs Docker
```

See [docs/quick_start.md](docs/quick_start.md) for detailed usage guide.
