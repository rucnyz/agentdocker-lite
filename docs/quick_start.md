# Quick Start

## Install

```bash
pip install -e .
```

**Root mode** requires Linux, root, and `util-linux` (`unshare`). Docker is only needed for auto-exporting rootfs from image names.

**Rootless mode** works without root — requires Linux kernel 5.13+ (Landlock). No Docker, no special privileges.

## Basic usage (root mode)

```python
from agentdocker_lite import Sandbox, SandboxConfig

config = SandboxConfig(
    image="ubuntu:22.04",          # Docker image or path to rootfs dir
    working_dir="/workspace",
)
sb = Sandbox(config, name="worker-0")

# Run commands (~42ms each via persistent shell)
output, ec = sb.run("echo hello world")
print(output)  # "hello world\n"

# File I/O (direct rootfs access, bypasses shell)
sb.write_file("/workspace/payload.py", "print('hello')")
content = sb.read_file("/workspace/payload.py")

# Reset filesystem to initial state (~27ms, clears overlayfs upper)
sb.reset()

# Cleanup
sb.delete()
```

## Rootless mode (no root required)

When not running as root, the sandbox automatically falls back to Landlock + seccomp — no namespace, no chroot, no overlayfs. The process runs directly in the working directory with kernel-level filesystem restrictions.

```python
from agentdocker_lite import Sandbox, SandboxConfig

# No image needed — runs on the host filesystem
config = SandboxConfig(
    working_dir="/tmp/my-sandbox",
)
sb = Sandbox(config, name="worker-0")

output, ec = sb.run("echo hello && whoami && pwd")
# hello
# myuser
# /tmp/my-sandbox

# Landlock auto-enabled: read anywhere, write only to cwd + /tmp + /dev
sb.run("echo ok > /tmp/my-sandbox/test.txt")   # ✓ allowed
sb.run("echo bad > /etc/test")                  # ✗ Permission denied

sb.delete()
```

Default Landlock policy (when not explicitly configured):
- **Read**: `/` (entire filesystem)
- **Write**: working dir + `/tmp` + `/dev`
- **seccomp**: enabled (blocks ptrace, mount, kexec, bpf, etc.)

Custom Landlock policy:

```python
config = SandboxConfig(
    working_dir="/tmp/my-sandbox",
    landlock_read=["/usr", "/lib", "/etc", "/tmp/my-sandbox"],
    landlock_write=["/tmp/my-sandbox"],
    landlock_tcp_ports=[80, 443],     # only allow outbound HTTP/HTTPS
)
```

| | Root mode | Rootless mode |
|---|---|---|
| Isolation | PID + mount namespace + chroot | Landlock + seccomp |
| Filesystem | overlayfs COW | host fs (Landlock restricts paths) |
| `reset()` | clears overlayfs upper (~27ms) | no-op |
| `image` required | yes | no |
| Docker required | only for image export | no |
| Kernel requirement | overlayfs support | 5.13+ (Landlock) |

## Volumes (root mode only)

Three mount modes:

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

`cow` mode lets the sandbox freely modify files without touching the host filesystem — writes go to an overlayfs upper layer that gets discarded on `reset()` or `delete()`.

## Background processes

```python
# Start a long-running process
handle = sb.run_background("python3 -m http.server 8080")

# Check if still running
output, running = sb.check_background(handle)

# Stop it
sb.stop_background(handle)
```

## Interactive processes (stdio pipes)

```python
# Launch a process with stdin/stdout pipes (e.g. LSP server)
proc = sb.popen("pyright --stdio")
proc.stdin.write(b'{"jsonrpc":"2.0",...}\n')
proc.stdin.flush()
response = proc.stdout.readline()
proc.terminate()
```

## Resource limits (cgroup v2, root mode only)

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    cpu_max="50000 100000",    # 50% of one CPU
    memory_max="536870912",    # 512MB
    pids_max="256",            # max 256 processes
)
```

## Concurrent sandboxes

All sandboxes share the same base rootfs (read-only lowerdir). Each gets its own overlayfs upper, PID namespace, and mount namespace.

```python
sandboxes = []
for i in range(32):
    config = SandboxConfig(image="ubuntu:22.04", working_dir="/workspace")
    sb = Sandbox(config, name=f"worker-{i}")
    sandboxes.append(sb)

# Run in parallel — fully isolated from each other
for sb in sandboxes:
    sb.run("apt-get update")  # writes only to this sandbox's upper layer

# Reset all
for sb in sandboxes:
    sb.reset()

# Cleanup
for sb in sandboxes:
    sb.delete()
```

## Security hardening

### seccomp-bpf (enabled by default, both modes)

Blocks 30+ dangerous syscalls inside the sandbox: ptrace, mount, kexec, bpf, unshare, setns, init_module, reboot, perf_event_open, etc. Also blocks `clone()` with namespace flags and `ioctl(TIOCSTI)` terminal injection. Wrong architecture (x32 ABI) → process killed.

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    seccomp=True,  # default
)
```

### Landlock (filesystem + network restrictions)

Restrict which paths the sandbox can read/write, and which TCP ports it can connect to. Auto-enabled in rootless mode. Optional in root mode (defense-in-depth).

Requires kernel 5.13+ (filesystem), 5.19+ (cross-dir rename protection), 6.7+ (network), 6.12+ (IPC scoping). ABI version auto-negotiated — features degrade gracefully on older kernels.

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    landlock_read=["/usr", "/lib", "/etc"],
    landlock_write=["/tmp", "/workspace"],
    landlock_tcp_ports=[80, 443, 8080],
)
```

### Device passthrough (root mode only)

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    devices=["/dev/kvm"],  # KVM passthrough for QEMU
)
```

## Crash recovery

If a process crashes without calling `delete()`, sandboxes leak mounts and cgroups. Clean them up with:

```bash
sudo python -m agentdocker_lite cleanup
```

For RL training loops, call this at the start of each training run:

```python
from agentdocker_lite import SandboxBase
SandboxBase.cleanup_stale()  # clean orphans from previous crashes
```

## Performance comparison

| | Docker | agentdocker-lite (root) | Speedup |
|---|---|---|---|
| Create | ~271ms | ~10ms | **27x** |
| Per command (avg) | ~22ms | ~11ms | **2x** |
| Reset | ~504ms | ~11ms | **45x** |
| Delete | ~104ms | ~2ms | **52x** |

Measured on ubuntu:22.04 with 20 commands, rootfs pre-cached. Reproduce with:

```bash
sudo python examples/benchmark.py
```
