# Quick Start

## Install

```bash
pip install -e .
```

Requirements: Linux kernel 5.11+, `util-linux` (`unshare`), Python 3.12+. Docker is only needed for auto-exporting rootfs from image names.

### Ubuntu 24.04 / 23.10+ (AppArmor)

Ubuntu defaults to blocking unprivileged user namespaces. Run once to enable:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# Persist across reboots:
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
```

### Other distros (Arch, Fedora, etc.)

No extra configuration needed — unprivileged user namespaces are enabled by default.

## Basic usage

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

No `sudo` required. The sandbox automatically uses **user namespaces** for full isolation (overlayfs, PID namespace, chroot) without root privileges. When running as root, direct mount/cgroup operations are used instead.

## How it works

| | As root | Without root (default) |
|---|---|---|
| Isolation | PID + mount namespace + chroot | Same (via `unshare --user`) |
| Filesystem | overlayfs (direct mount) | overlayfs (inside user namespace) |
| `reset()` | clears overlayfs upper (~27ms) | same |
| Resource limits | direct cgroup v2 writes | systemd delegation (`systemd-run --scope`) |
| Device passthrough | yes (`/dev/kvm` etc.) | not available |
| `popen()` | nsenter + chroot | `os.setns()` + chroot |
| Kernel requirement | overlayfs | 5.11+ (overlayfs in userns) |

## Volumes

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

## Resource limits (cgroup v2)

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    cpu_max="50000 100000",    # 50% of one CPU
    memory_max="536870912",    # 512MB
    pids_max="256",            # max 256 processes
)
```

Without root, resource limits are applied via `systemd-run --user --scope` (requires systemd 244+). With root, direct cgroup v2 writes are used.

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

### seccomp-bpf (enabled by default)

Blocks 30+ dangerous syscalls inside the sandbox: ptrace, mount, kexec, bpf, unshare, setns, init_module, reboot, perf_event_open, etc. Also blocks `clone()` with namespace flags and `ioctl(TIOCSTI)` terminal injection.

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    seccomp=True,  # default
)
```

### Landlock (filesystem + network restrictions)

Restrict which paths the sandbox can read/write, and which TCP ports it can connect to. ABI version auto-detected at runtime — features degrade gracefully on older kernels.

Supported: filesystem (5.13+), cross-dir rename (5.19+), truncate (6.2+), network (6.7+), ioctl (6.10+), IPC scoping (6.12+), audit logging (6.15+).

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    landlock_read=["/usr", "/lib", "/etc"],
    landlock_write=["/tmp", "/workspace"],
    landlock_tcp_ports=[80, 443, 8080],
)
```

### Network isolation

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    net_isolate=True,  # loopback only, no host network
)
```

### Device passthrough (root only)

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    devices=["/dev/kvm"],  # KVM passthrough for QEMU
)
```

## Crash recovery

If a process crashes without calling `delete()`, sandboxes leak mounts and cgroups. Clean them up with:

```bash
python -m agentdocker_lite cleanup
```

For RL training loops, call this at the start of each training run:

```python
from agentdocker_lite import SandboxBase
SandboxBase.cleanup_stale()  # clean orphans from previous crashes
```

## Performance comparison

| | Docker | agentdocker-lite | Speedup |
|---|---|---|---|
| Create | ~271ms | ~10ms | **27x** |
| Per command (avg) | ~22ms | ~11ms | **2x** |
| Reset | ~504ms | ~11ms | **45x** |
| Delete | ~104ms | ~2ms | **52x** |

Measured on ubuntu:22.04 with 20 commands, rootfs pre-cached. Reproduce with:

```bash
python examples/benchmark.py
```
