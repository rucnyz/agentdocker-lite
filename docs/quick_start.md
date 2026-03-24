# Quick Start

## Install

```bash
pip install -e .
```

Requirements: Linux kernel 5.11+, `util-linux` (`unshare`), Python 3.12+. No Docker or Podman required — images are pulled directly from registries via built-in OCI client.

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

No `sudo` required. The sandbox automatically uses user namespaces for full isolation without root:

- **Overlayfs + layer cache**: Docker image layers are cached and shared (same as rootful mode)
- **Namespaces**: PID, mount, UTS, IPC, network (all via user namespace)
- **Security**: seccomp-bpf, capability drop, masked/read-only paths — all enabled in rootless mode
- **Port mapping**: pasta networking works inside the user namespace (rootless-compatible)

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
all_procs = sb.list_background()  # {"handle": {"pid": "123", "running": True}}
sb.stop_background(handle)
```

## Resource limits (cgroup v2)

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    cpu_max="50000 100000",    # 50% of one CPU
    memory_max="512m",         # 512MB (also accepts "2g", "536870912")
    pids_max="256",
    io_max="/dev/sda 10485760",  # 10MB/s write limit
    cpuset_cpus="0-3",           # pin to CPU 0-3
    oom_score_adj=500,           # prefer killing sandbox over host processes
)
```

Without root: applied via `systemd-run --user --scope`. With root: direct cgroup v2 writes.

### Pressure monitoring (PSI)

Identify CPU/memory/IO bottlenecks per sandbox — useful for large-scale RL training:

```python
psi = sb.pressure()
# {'cpu': {'avg10': 45.0, 'avg60': 30.0, 'avg300': 20.0},
#  'memory': {'avg10': 0.0, ...}, 'io': {'avg10': 12.5, ...}}
if psi.get("cpu", {}).get("avg10", 0) > 50:
    print(f"Sandbox {sb} is CPU-bottlenecked!")
```

### Memory reclamation

Hint the kernel to swap out idle sandbox memory — useful when GPU training needs RAM:

```python
# Sandboxes waiting for training step
for sb in idle_sandboxes:
    sb.reclaim_memory()  # kernel swaps out cold pages

# Resume — memory pages back in transparently
for sb in idle_sandboxes:
    sb.run(next_action)
```

Requires swap (zram or disk). Returns `False` if kernel doesn't support `process_madvise`.

## Shared network namespace

Multiple sandboxes can share a network namespace for direct communication while keeping filesystem isolation. Uses a Podman-style sentinel process with shared userns+netns.

```python
from agentdocker_lite import Sandbox, SandboxConfig, SharedNetwork

# Create a shared network
net = SharedNetwork("my-net")

# Sandboxes join the same network — can communicate via localhost
sb1 = Sandbox(SandboxConfig(
    image="ubuntu:22.04",
    shared_userns=net.userns_path,
    net_ns=net.netns_path,
), name="service-a")

sb2 = Sandbox(SandboxConfig(
    image="ubuntu:22.04",
    shared_userns=net.userns_path,
    net_ns=net.netns_path,
), name="service-b")

# Same netns — service-a can reach service-b via localhost
# Different mount ns — filesystem is fully isolated

sb1.delete()
sb2.delete()
net.destroy()
```

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

By default, IPv6 is disabled in the pasta network (`ipv6=False`). This ensures `localhost` resolves to `127.0.0.1` and works correctly for port-mapped services. Without this, pasta accepts IPv6 connections (via `::1`) but cannot forward them to IPv4-only servers, causing "Connection reset by peer" — a [known pasta bug](https://bugs.passt.top/show_bug.cgi?id=131) that also affects Podman rootless.

To enable IPv6 networking (e.g., for services that require IPv6):

```python
config = SandboxConfig(
    ...,
    net_isolate=True,
    port_map=["8080:80"],
    ipv6=True,  # enables IPv6, but localhost may fail — use 127.0.0.1
)
```

## Snapshots

Save and restore filesystem state at any point. Useful for RL step-wise rollback and tree search:

```python
sb.run("echo step0 > /workspace/data.txt")
s0 = sb.snapshot()                     # → 0

sb.run("echo step1 >> /workspace/data.txt")
s1 = sb.snapshot()                     # → 1

sb.restore(s0)                         # back to step 0
sb.list_snapshots()                    # [0, 1]
sb.delete_snapshot(s1)                 # free space

sb.reset()                             # back to clean image (clears all snapshots)
```

## Save as Docker image

Export the current sandbox state as a Docker image — works with both
`docker run` and `SandboxConfig(image=...)`:

```python
sb = Sandbox(SandboxConfig(image="ubuntu:22.04"))
sb.run("apt-get update && apt-get install -y python3")
sb.save_as_image("my-app:with-python")
sb.delete()

# Later — instant start, no apt-get:
sb2 = Sandbox(SandboxConfig(image="my-app:with-python"))

# Also works with plain Docker:
# docker run my-app:with-python python3 -c "print('hello')"
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
    # sb.fs_snapshot() / sb.fs_restore() still works for filesystem state
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

## Device passthrough

Pass host devices into the sandbox. Works in both rootless and rootful modes — in rootless mode, devices are bind-mounted from the host devtmpfs (preserves the original superblock, no `SB_I_NODEV`). The user must have the required group membership (e.g., `kvm` group for `/dev/kvm`).

```python
# KVM for VM-based workloads (e.g., OSWorld GUI agent training)
config = SandboxConfig(image="ubuntu:22.04", devices=["/dev/kvm"])

# NVIDIA GPU access
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

## QEMU/KVM Virtual Machines

Run QEMU/KVM VMs inside sandboxes for GUI agent training (e.g., OSWorld). `QemuVM` manages the QEMU process and provides QMP-based `savevm`/`loadvm` for fast episode reset (1-5s vs 30-120s cold restart).

```python
from agentdocker_lite import Sandbox, SandboxConfig
from agentdocker_lite.vm import QemuVM

sb = Sandbox(SandboxConfig(
    image="ubuntu:22.04",   # needs qemu-system-x86 installed
    devices=["/dev/kvm"],
    volumes=["/host/vms:/vms:rw"],
))

vm = QemuVM(sb, disk="/vms/osworld.qcow2", memory="4G", cpus=4)
vm.start()              # boot VM, wait for QMP
vm.savevm("ready")      # snapshot VM state

# Episode loop:
for episode in range(1000):
    vm.loadvm("ready")  # restore snapshot (1-5s)
    screenshot = vm.screenshot()
    # ... agent actions ...

vm.stop()
sb.delete()
```

Rootless KVM requires the user to be in the `kvm` group (`sudo usermod -aG kvm $USER`).

## Security hardening

All security features are **on by default** with zero runtime overhead.

### Default protections (no configuration needed)

- **seccomp-bpf**: blocks 30+ dangerous syscalls (ptrace, mount, kexec, bpf, unshare, setns, etc.)
- **Masked paths**: `/proc/kcore`, `/proc/keys`, `/proc/timer_list`, `/proc/sched_debug`, `/sys/firmware`, `/proc/scsi` bound to `/dev/null`
- **Read-only paths**: `/proc/bus`, `/proc/fs`, `/proc/irq`, `/proc/sys`, `/proc/sysrq-trigger`
- **Capability dropping**: all non-essential Linux capabilities dropped (keeps Docker-default 13 caps)
- **Time namespace**: isolates monotonic/boottime clocks, ensures CRIU restore sees continuous time (kernel 5.6+)

### Landlock path/port restrictions

Restrict which paths the sandbox can read/write and which TCP ports it can connect to (kernel 5.13+, port rules require 6.7+):

```python
config = SandboxConfig(
    image="ubuntu:22.04",
    working_dir="/workspace",
    writable_paths=["/workspace"],          # only /workspace writable (/dev, /proc, /tmp auto-added)
    readable_paths=["/usr", "/lib", "/etc"],# only these paths readable (None=no restriction)
    allowed_ports=[80, 443],               # only these TCP ports connectable (None=no restriction)
)
```

Essential paths (`/dev`, `/proc`, `/tmp`, `/sys`) are automatically included. If Landlock is not available (old kernel), restrictions are silently skipped.

### Device passthrough

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

## CLI

```bash
adl ps                  # list running sandboxes
adl kill <name>         # kill a sandbox and clean up
adl kill --all          # kill all sandboxes
adl cleanup             # remove stale sandbox directories
adl --dir /path ps      # use custom sandbox base directory
```

## Crash recovery

Sandboxes auto-cleanup on process exit via `atexit`. For `kill -9` scenarios:

```bash
adl cleanup             # or from Python:
```

```python
from agentdocker_lite import SandboxBase
SandboxBase.cleanup_stale()
```

## Feature detection

Active kernel features are auto-detected at creation and accessible via `sb.features`:

```python
sb = Sandbox(config, name="worker-0")
print(sb.features)
# {'pidfd': True, 'cgroup_v2': True, 'seccomp': True, 'netns': False,
#  'timens': True, 'cpuset_cpus': None, 'oom_score_adj': None,
#  'mask_paths': True, 'cap_drop': True}
```

## Performance

### Single-operation latency

| | Docker | agentdocker-lite | Speedup |
|---|---|---|---|
| Create | 286ms | 18ms | **16x** |
| Per command | 17ms | 11ms | **1.7x** |
| Reset | 494ms | 17ms | **29x** |
| Delete | 214ms | 1.7ms | **126x** |
| Checkpoint save | — | 7ms | — |
| Checkpoint restore | — | 13ms | — |

### Sustained workloads

| | Docker | agentdocker-lite | Speedup |
|---|---|---|---|
| Throughput (1000 cmds) | 57 cmd/s | 95 cmd/s | **1.7x** |
| Reset loop (100 cycles) | 2.0/s | 34.7/s | **17.6x** |
| Checkpoint restore loop (50 cycles) | — | 38.2/s | — |
| 4x concurrent (10 cmds each) | 27 cmd/s | 302 cmd/s | **11.3x** |
| 8x concurrent | 31 cmd/s | 559 cmd/s | **18.1x** |
| 16x concurrent | 32 cmd/s | 893 cmd/s | **27.9x** |

Measured on AMD Ryzen 9 9950X, ubuntu:22.04, kernel 6.19. Reproduce:

```bash
python examples/benchmark.py
```

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
| `--device-write-bps /dev/sda:10mb` | `io_max="/dev/sda 10485760"` |
| `--hostname worker-0` | `hostname="worker-0"` |
| `--dns 8.8.8.8` | `dns=["8.8.8.8"]` |
| `--read-only` | `read_only=True` |
| `--network none` | `net_isolate=True` |
| `-p 8080:80` | `net_isolate=True, port_map=["8080:80"]` |
| `docker commit` / `docker save` | `sb.fs_snapshot("/path")` (filesystem only) |
| `docker import` / `docker load` | `sb.fs_restore("/path")` (filesystem only) |
| `docker checkpoint create` (CRIU) | `CheckpointManager(sb).save("/path")` (full process state) |
| `docker start --checkpoint` | `CheckpointManager(sb).restore("/path")` |
| `--gpus all` | `devices=["/dev/nvidia0", ...]` |
| `-e KEY=value` | `environment={"KEY": "value"}` |
| `--device /dev/kvm` | `devices=["/dev/kvm"]` |
| `--security-opt seccomp=...` | `seccomp=True` (default) |
| `--cpuset-cpus 0-3` | `cpuset_cpus="0-3"` |
| `--oom-score-adj 500` | `oom_score_adj=500` |
| `docker compose up -d` | `ComposeProject("docker-compose.yml").up()` |
| `docker compose down` | `proj.down()` |

## Docker Compose compatibility

Run multi-service `docker-compose.yml` files as agentdocker-lite sandboxes. Each service becomes an independent sandbox with filesystem-level `reset()` — no application-specific reset endpoints needed.

```python
from agentdocker_lite import ComposeProject

# Start all services (dependency order, health checks)
proj = ComposeProject("docker-compose.yml", env={"API_PORT": "8030"})
proj.up()

# Access individual services
proj.services["api"].run("curl localhost:8030/health")

# Filesystem-level reset — all services reset to initial state
proj.reset()

# Cleanup
proj.down()
```

Works as a context manager:

```python
with ComposeProject("docker-compose.yml") as proj:
    output, ec = proj.run("api", "python manage.py migrate")
    # all services auto-cleaned on exit
```

Requires `pyyaml`: `pip install agentdocker-lite[compose]`

### Compose field support

Unsupported fields raise `ValueError` at parse time — no silent ignoring.

| Status | Fields |
|---|---|
| **Supported** | `image`, `build`, `command`, `entrypoint`, `environment`, `volumes` (named + bind + `:ro`), `ports`, `devices`, `depends_on` (with `condition`), `healthcheck` (CMD, CMD-SHELL), `network_mode`, `dns`, `hostname`, `working_dir`, `restart`, `security_opt`, `cap_add`, `privileged`, `stop_grace_period`, `ulimits` |
| **Supported** | `networks` — services on the same network share a network namespace (can communicate via localhost). Services on different networks are isolated (different netns). Uses Podman-style shared userns+netns sentinel per network. |
| **Parsed but ignored** | `container_name`, `profiles`, `stdin_open`, `tty`, `env_file`, `extra_hosts`, `labels`, `logging` |
| **Not supported (will error)** | `shm_size`, `tmpfs`, `sysctls`, `init`, `user`, `pid`, `ipc`, `configs`, `secrets`, `deploy`, `cgroup_parent`, `runtime` |
