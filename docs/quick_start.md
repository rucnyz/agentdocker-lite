# Quick Start

## Install

```bash
pip install -e .
```

Requirements: Linux kernel 5.11+, `util-linux` (`unshare`), Python 3.12+. Docker is only needed for auto-exporting rootfs from image names.

The pip package bundles static binaries for `pasta` (port mapping) and `criu` (process checkpointing) in `site-packages/agentdocker_lite/_vendor/`. No extra install needed.

### Ubuntu 24.04 / 23.10+ (AppArmor)

Ubuntu defaults to blocking unprivileged user namespaces. Run once to enable:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# Persist across reboots:
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
```

### Other distros (Arch, Fedora, etc.)

No extra configuration needed.

## Basic usage

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

sb.reset()   # instant filesystem reset (~12ms)
sb.delete()  # full cleanup
```

No `sudo` required. The sandbox automatically uses user namespaces for full isolation (overlayfs, PID/UTS/IPC namespace, chroot) without root.

## Volumes

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    volumes=[
        "/host/data:/data:ro",          # read-only bind mount
        "/host/project:/workspace:rw",  # read-write bind mount
        "/host/project:/workspace:cow", # copy-on-write (overlayfs)
    ],
)
```

`cow` mode lets the sandbox modify files without touching the host — writes go to an overlayfs upper layer, discarded on `reset()` or `delete()`.

## Interactive processes (popen)

```python
proc = sb.popen("pyright --stdio")
proc.stdin.write(b'{"jsonrpc":"2.0",...}\n')
proc.stdin.flush()
response = proc.stdout.readline()
proc.terminate()
```

## Background processes

```python
handle = sb.run_background("python3 -m http.server 8080")
output, running = sb.check_background(handle)
sb.stop_background(handle)
```

## Resource limits (cgroup v2)

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    cpu_max="50000 100000",    # 50% of one CPU
    memory_max="536870912",    # 512MB
    pids_max="256",
    io_max="/dev/sda 10485760",  # 10MB/s write limit
)
```

Without root: applied via `systemd-run --user --scope`. With root: direct cgroup v2 writes.

## Port mapping (pasta networking)

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    working_dir="/workspace",
    net_isolate=True,
    port_map=["8080:80", "3000:3000"],  # host:container TCP ports
)
```

Uses a vendored `pasta` binary (bundled, no install needed). The sandbox gets an isolated network namespace with NAT'd internet access and TCP port forwarding.

## Filesystem snapshots

Save and restore sandbox filesystem state:

```python
sb.run("echo v1 > /workspace/data.txt")
sb.snapshot("/tmp/checkpoint_v1")    # save current state

sb.run("echo v2 > /workspace/data.txt")
sb.restore("/tmp/checkpoint_v1")     # restore to v1

sb.reset()                           # back to clean image (not snapshot)
```

## Process checkpointing (CRIU)

Full process-state checkpoint/restore: memory, registers, environment variables, cwd — everything. Useful for partial rollout in RL training where agent trajectories need to continue from a previous state.

**Zero runtime overhead** — CRIU only runs during save/restore, no interposition on normal exec.

**Requirements**: root (CRIU binary is bundled — no install needed).

```python
from agentdocker_lite import Sandbox, SandboxConfig, CheckpointManager

config = SandboxConfig(image="ubuntu:22.04", working_dir="/workspace")
sb = Sandbox(config, name="worker-0")
mgr = CheckpointManager(sb)

# Set up state
sb.run("echo 'state v1' > /workspace/data.txt")

# Save full process state (filesystem + memory + cwd)
mgr.save("/tmp/ckpt_v1")
# Sandbox keeps running — save() doesn't kill it (--leave-running)

# Agent does destructive work...
sb.run("rm -rf /workspace/*")

# Rollback: exact restore to checkpoint
mgr.restore("/tmp/ckpt_v1")

output, _ = sb.run("cat /workspace/data.txt")
print(output)  # "state v1\n" — fully restored

sb.delete()
```

### Check CRIU availability

```python
if CheckpointManager.check_available():
    mgr = CheckpointManager(sb)
else:
    print("CRIU not available, falling back to filesystem-only snapshots")
    # sb.snapshot() / sb.restore() still works for filesystem state
```

## Container configuration

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    working_dir="/workspace",
    environment={"KEY": "value"},
    hostname="worker-0",              # custom hostname (UTS namespace)
    dns=["8.8.8.8", "1.1.1.1"],      # custom DNS servers
    read_only=True,                   # read-only rootfs (/dev, /proc, volumes still writable)
    net_isolate=True,                 # loopback only (or use port_map for NAT + ports)
)
```

## GPU passthrough

For NVIDIA GPU access inside the sandbox, mount the device and driver libraries:

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    devices=["/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm"],
    volumes=[
        "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so:/usr/lib/libnvidia-ml.so:ro",
        "/usr/lib/x86_64-linux-gnu/libcuda.so:/usr/lib/libcuda.so:ro",
        # ... add other driver libs as needed
    ],
    environment={"NVIDIA_VISIBLE_DEVICES": "0"},
)
```

Device passthrough requires root. For rootless GPU access, consider mounting the GPU device with appropriate permissions beforehand.

## Security hardening

### seccomp-bpf (default: on)

Blocks 30+ dangerous syscalls: ptrace, mount, kexec, bpf, unshare, setns, etc.

### Landlock (filesystem + network restrictions)

ABI auto-detected at runtime. Supports: filesystem (5.13+), network (6.7+), IPC scoping (6.12+), audit (6.15+).

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    landlock_read=["/usr", "/lib", "/etc"],
    landlock_write=["/tmp", "/workspace"],
    landlock_tcp_ports=[80, 443],
)
```

### Device passthrough (root only)

```python
config = SandboxConfig(image="ubuntu:22.04", devices=["/dev/kvm"])
```

## Concurrent sandboxes

All sandboxes share the same base rootfs. Each gets its own overlayfs upper and namespace.

```python
sandboxes = [Sandbox(SandboxConfig(image="ubuntu:22.04", working_dir="/workspace"),
                     name=f"worker-{i}") for i in range(32)]
for sb in sandboxes:
    sb.run("echo isolated")
    sb.reset()
    sb.delete()
```

## Crash recovery

Sandboxes auto-cleanup on process exit via `atexit`. For `kill -9` scenarios:

```python
from agentdocker_lite import SandboxBase
SandboxBase.cleanup_stale()
```

## Performance

| | Docker | agentdocker-lite | Speedup |
|---|---|---|---|
| Create | 383ms | 12ms | **31x** |
| Per command | 19ms | 11ms | **1.8x** |
| Reset | 558ms | 12ms | **46x** |
| Delete | 209ms | 1.2ms | **174x** |

No root required. Reproduce: `python examples/benchmark.py`

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
| `--memory 512m` | `memory_max="536870912"` |
| `--cpus 0.5` | `cpu_max="50000 100000"` |
| `--pids-limit 256` | `pids_max="256"` |
| `--device-write-bps /dev/sda:10mb` | `io_max="/dev/sda 10485760"` |
| `--hostname worker-0` | `hostname="worker-0"` |
| `--dns 8.8.8.8` | `dns=["8.8.8.8"]` |
| `--read-only` | `read_only=True` |
| `--network none` | `net_isolate=True` |
| `-p 8080:80` | `net_isolate=True, port_map=["8080:80"]` |
| `docker commit` / `docker save` | `sb.snapshot("/path")` (filesystem only) |
| `docker import` / `docker load` | `sb.restore("/path")` (filesystem only) |
| `docker checkpoint create` (CRIU) | `CheckpointManager(sb).save("/path")` (full process state) |
| `docker start --checkpoint` | `CheckpointManager(sb).restore("/path")` |
| `--gpus all` | `devices=["/dev/nvidia0", ...]` (root only) |
| `-e KEY=value` | `environment={"KEY": "value"}` |
| `--device /dev/kvm` | `devices=["/dev/kvm"]` (root only) |
| `--security-opt seccomp=...` | `seccomp=True` (default) |
| *(no equivalent)* | `landlock_read=[...], landlock_tcp_ports=[...]` |
