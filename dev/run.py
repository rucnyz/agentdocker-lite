"""Comprehensive demo of nitrobox API.

Run with: python dev/run.py          (user namespace mode)
      or: sudo python dev/run.py     (rootful mode, full features)
"""

import os
import tempfile
import time
from pathlib import Path

from nitrobox import Sandbox, SandboxConfig
from nitrobox import SandboxConfigError

IMAGE = "ubuntu:22.04"


def section(title: str):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


# ------------------------------------------------------------------ #
#  1. Basic lifecycle: create → run → reset → delete                 #
# ------------------------------------------------------------------ #
section("1. Basic lifecycle")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")

# Use context manager for basic lifecycle
with Sandbox(config, name="basic") as sb:
    output, ec = sb.run("echo hello world")
    print(f"  run: {output.strip()!r}, exit_code={ec}")

    # List form
    output, ec = sb.run(["echo", "list", "form"])
    print(f"  list form: {output.strip()!r}")

    # Exit code
    _, ec = sb.run("false")
    print(f"  'false' exit_code={ec}")

    sb.reset()

print("  OK")


# ------------------------------------------------------------------ #
#  2. Environment variables                                            #
# ------------------------------------------------------------------ #
section("2. Environment variables")

config = SandboxConfig(
    image=IMAGE,
    working_dir="/workspace",
    environment={"MY_VAR": "hello_from_config", "NUM_WORKERS": "4"},
)
sb = Sandbox(config, name="env")

output, _ = sb.run("echo $MY_VAR $NUM_WORKERS")
print(f"  env vars: {output.strip()!r}")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  3. File I/O: write_file, read_file, copy_to, copy_from             #
# ------------------------------------------------------------------ #
section("3. File I/O")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="fileio")

# write_file + read_file
sb.write_file("/workspace/test.txt", "hello from host\n")
content = sb.read_file("/workspace/test.txt")
print(f"  read_file: {content.strip()!r}")

# Verify visible via run()
output, _ = sb.run("cat /workspace/test.txt")
print(f"  cat via run: {output.strip()!r}")

# write_file with bytes
sb.write_file("/workspace/binary.bin", b"\x00\x01\x02\x03")
print("  binary write: OK")

# copy_to / copy_from
with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
    f.write("copied content\n")
    host_src = f.name
sb.copy_to(host_src, "/workspace/copied.txt")
output, _ = sb.run("cat /workspace/copied.txt")
print(f"  copy_to: {output.strip()!r}")

with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
    host_dst = f.name
sb.copy_from("/workspace/copied.txt", host_dst)
print(f"  copy_from: {Path(host_dst).read_text().strip()!r}")

Path(host_src).unlink(missing_ok=True)
Path(host_dst).unlink(missing_ok=True)
sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  4. Reset: overlayfs clears changes, base image restored             #
# ------------------------------------------------------------------ #
section("4. Reset behavior")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="reset")

sb.run("echo 'ephemeral' > /workspace/temp.txt")
output, ec = sb.run("cat /workspace/temp.txt")
print(f"  before reset: {output.strip()!r}")

sb.reset()
_, ec = sb.run("cat /workspace/temp.txt 2>/dev/null")
print(f"  after reset: exit_code={ec} (file gone)")

# Base image files survive reset
sb.run("rm -f /bin/ls")
_, ec = sb.run("ls / 2>/dev/null")
print(f"  after rm /bin/ls: exit_code={ec}")
sb.reset()
_, ec = sb.run("ls / >/dev/null")
print(f"  after reset: ls works again, exit_code={ec}")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  5. Volumes: rw, ro, cow                                             #
# ------------------------------------------------------------------ #
section("5. Volumes (rw / ro / cow)")

with tempfile.TemporaryDirectory() as tmpdir:
    shared = Path(tmpdir) / "shared"
    shared.mkdir()
    (shared / "input.txt").write_text("from host")

    # rw volume
    config = SandboxConfig(
        image=IMAGE,
        working_dir="/workspace",
        volumes=[f"{shared}:/mnt/shared:rw"],
    )
    sb = Sandbox(config, name="vol-rw")
    output, _ = sb.run("cat /mnt/shared/input.txt")
    print(f"  rw read: {output.strip()!r}")
    sb.run("echo 'from sandbox' > /mnt/shared/output.txt")
    print(f"  rw write visible on host: {(shared / 'output.txt').read_text().strip()!r}")
    sb.delete()

    # ro volume
    config = SandboxConfig(
        image=IMAGE,
        working_dir="/workspace",
        volumes=[f"{shared}:/mnt/shared:ro"],
    )
    sb = Sandbox(config, name="vol-ro")
    _, ec = sb.run("echo x > /mnt/shared/input.txt 2>&1")
    print(f"  ro write blocked: exit_code={ec}")
    sb.delete()

    # cow volume
    (shared / "original.txt").write_text("untouched")
    config = SandboxConfig(
        image=IMAGE,
        working_dir="/workspace",
        volumes=[f"{shared}:/mnt/shared:cow"],
    )
    sb = Sandbox(config, name="vol-cow")
    sb.run("echo 'modified' > /mnt/shared/original.txt")
    print(f"  cow host unchanged: {(shared / 'original.txt').read_text().strip()!r}")
    sb.delete()

print("  OK")


# ------------------------------------------------------------------ #
#  6. Network isolation                                                #
# ------------------------------------------------------------------ #
section("6. Network isolation")

# Default: host network
config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="net-default")
output, _ = sb.run("ls /sys/class/net/")
print(f"  default net: {output.strip()}")
sb.delete()

# Isolated: loopback only
config = SandboxConfig(image=IMAGE, working_dir="/workspace", net_isolate=True)
sb = Sandbox(config, name="net-isolated")
output, _ = sb.run("ls /sys/class/net/")
print(f"  isolated net: {output.strip()}")
sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  7. cgroup v2 resource limits                                        #
# ------------------------------------------------------------------ #
section("7. Resource limits (cgroup v2)")

if Path("/sys/fs/cgroup/cgroup.controllers").exists():
    config = SandboxConfig(
        image=IMAGE,
        working_dir="/workspace",
        memory_max="33554432",    # 32 MB
        pids_max="64",
        cpu_max="50000 100000",   # 50% of one core
    )
    sb = Sandbox(config, name="cgroup")
    output, _ = sb.run("echo cgroup-ok")
    print(f"  sandbox with limits: {output.strip()!r}")

    # Verify cgroup is set
    cgroup_path = getattr(sb, "_cgroup_path", None)
    if cgroup_path:
        # Rootful: direct cgroup path on host
        pids_max = (cgroup_path / "pids.max").read_text().strip()
        mem_max = (cgroup_path / "memory.max").read_text().strip()
        print(f"  pids.max={pids_max}, memory.max={mem_max}")
    else:
        # Userns: cgroup via systemd delegation, verify from inside
        output, _ = sb.run("cat /proc/self/cgroup 2>/dev/null")
        print(f"  cgroup (systemd): {output.strip()}")

    sb.delete()
    print("  OK")
else:
    print("  SKIP (cgroup v2 not available)")


# ------------------------------------------------------------------ #
#  8. Background processes                                             #
# ------------------------------------------------------------------ #
section("8. Background processes")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="bg")

handle = sb.run_background("for i in 1 2 3; do echo tick-$i; sleep 0.2; done")
print(f"  handle: {handle!r}")

time.sleep(0.5)
output, running = sb.check_background(handle)
print(f"  check: running={running}, output_lines={len(output.strip().splitlines())}")

# run() works while background is active
output, ec = sb.run("echo foreground-ok")
print(f"  foreground while bg: {output.strip()!r}")

time.sleep(0.5)
final = sb.stop_background(handle)
print(f"  stop: {final.strip()!r}")

# reset clears background handles
handle2 = sb.run_background("sleep 60")
sb.reset()
print("  reset clears bg handles")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  9. popen: interactive / streaming I/O                               #
# ------------------------------------------------------------------ #
section("9. popen (interactive I/O)")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="popen")

proc = sb.popen("cat")
assert proc.stdin and proc.stdout
proc.stdin.write(b"hello from popen\n")
proc.stdin.flush()
line = proc.stdout.readline()
print(f"  cat echo: {line.strip().decode()!r}")
proc.terminate()
proc.wait(timeout=5)

# popen sees sandbox filesystem
sb.write_file("/workspace/popen_test.txt", "popen-visible\n")
proc = sb.popen("cat /workspace/popen_test.txt")
assert proc.stdout
output = proc.stdout.read()
proc.wait(timeout=5)
print(f"  popen reads file: {output.strip().decode()!r}")

# exit code
proc = sb.popen("false")
proc.wait(timeout=5)
print(f"  popen exit code: {proc.returncode}")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  10. Hostname, DNS, read-only rootfs                                 #
# ------------------------------------------------------------------ #
section("10. Hostname, DNS, read-only")

# Hostname
config = SandboxConfig(image=IMAGE, working_dir="/workspace", hostname="sandbox-42")
sb = Sandbox(config, name="hostname")
output, _ = sb.run("hostname")
print(f"  hostname: {output.strip()!r}")
sb.delete()

# DNS
config = SandboxConfig(image=IMAGE, working_dir="/workspace", dns=["8.8.8.8", "1.1.1.1"])
sb = Sandbox(config, name="dns")
output, _ = sb.run("cat /etc/resolv.conf")
print(f"  dns: {output.strip()!r}")
sb.delete()

# Read-only rootfs (skip if seccomp helper can't write to /tmp)
try:
    config = SandboxConfig(image=IMAGE, working_dir="/workspace", read_only=True)
    sb = Sandbox(config, name="readonly")
    _, ec = sb.run("touch /test 2>&1")
    print(f"  write blocked: ec={ec}")
    _, ec = sb.run("echo x > /dev/null")
    print(f"  /dev/null writable: ec={ec}")
    sb.delete()
except OSError as e:
    print(f"  SKIP read_only (seccomp conflict: {e})")
print("  OK")


# ------------------------------------------------------------------ #
#  11. Port mapping (pasta networking)                                 #
# ------------------------------------------------------------------ #
section("11. Port mapping (pasta)")

config = SandboxConfig(
    image=IMAGE, working_dir="/workspace",
    net_isolate=True, port_map=["8080:80"],
)
sb = Sandbox(config, name="pasta")
time.sleep(0.5)  # give pasta a moment to configure
output, _ = sb.run("cat /proc/net/dev | tail -n +3")
interfaces = [l.split(":")[0].strip() for l in output.strip().split("\n") if ":" in l]
print(f"  interfaces: {interfaces}")
output, ec = sb.run("echo pasta-ok")
print(f"  run: {output.strip()!r}")
sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  12. Filesystem snapshot / restore                                   #
# ------------------------------------------------------------------ #
section("12. Snapshot / restore")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="snapshot")

sb.run("echo checkpoint > /workspace/data.txt")
sb.fs_snapshot("/tmp/nbx_snapshot_test")
print("  snapshot saved")

sb.run("echo modified > /workspace/data.txt")
sb.fs_restore("/tmp/nbx_snapshot_test")
output, _ = sb.run("cat /workspace/data.txt")
print(f"  after restore: {output.strip()!r}")

sb.reset()
_, ec = sb.run("cat /workspace/data.txt 2>/dev/null")
print(f"  after reset: exists={ec == 0}")

import shutil as _shutil
_shutil.rmtree("/tmp/nbx_snapshot_test")
sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  13. TTY mode                                                       #
# ------------------------------------------------------------------ #
section("13. TTY mode")

config = SandboxConfig(image=IMAGE, working_dir="/workspace", tty=True)
sb = Sandbox(config, name="tty")

output, ec = sb.run("echo tty-mode")
print(f"  tty run: {output.strip()!r}, exit_code={ec}")

output, ec = sb.run("echo tty-seq-2")
print(f"  tty sequential: {output.strip()!r}")

sb.reset()
output, ec = sb.run("echo after-reset")
print(f"  tty after reset: {output.strip()!r}")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  14. Multi-sandbox isolation                                         #
# ------------------------------------------------------------------ #
section("14. Multi-sandbox isolation")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb1 = Sandbox(config, name="iso-1")
sb2 = Sandbox(config, name="iso-2")

sb1.run("echo 'sb1-only' > /tmp/marker.txt")
_, ec = sb2.run("cat /tmp/marker.txt 2>/dev/null")
print(f"  sb2 sees sb1 file: exit_code={ec} (non-zero = isolated)")

sb1.delete()
sb2.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  15. Performance quick check                                         #
# ------------------------------------------------------------------ #
section("15. Performance")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="perf")

# Command latency
times = []
for _ in range(20):
    t0 = time.monotonic()
    sb.run("true")
    times.append((time.monotonic() - t0) * 1000)
times.sort()
median = times[len(times) // 2]
print(f"  run('true') median: {median:.1f} ms (20 iterations)")

# Reset latency
sb.write_file("/workspace/data.bin", "x" * 1_000_000)
reset_times = []
for _ in range(5):
    t0 = time.monotonic()
    sb.reset()
    reset_times.append((time.monotonic() - t0) * 1000)
reset_times.sort()
median = reset_times[len(reset_times) // 2]
print(f"  reset() median: {median:.1f} ms (5 iterations, after 1MB write)")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  16. list_background                                                 #
# ------------------------------------------------------------------ #
section("16. list_background")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="list-bg")

h1 = sb.run_background("sleep 60")
h2 = sb.run_background("sleep 60")
time.sleep(0.3)
procs = sb.list_background()
print(f"  list_background: {procs}")
assert h1 in procs and procs[h1]["running"]
assert h2 in procs and procs[h2]["running"]
sb.stop_background(h1)
sb.stop_background(h2)
sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  17. PSI pressure monitoring                                         #
# ------------------------------------------------------------------ #
section("17. Pressure (PSI)")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="pressure")

psi = sb.pressure()
if psi:
    print(f"  pressure: {psi}")
else:
    print("  pressure: not available (cgroup v2 / PSI not enabled)")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  18. save_as_image                                                   #
# ------------------------------------------------------------------ #
section("18. save_as_image")

import shutil as _shutil_check
if _shutil_check.which("docker") and os.geteuid() == 0:
    config = SandboxConfig(image=IMAGE, working_dir="/workspace")
    sb = Sandbox(config, name="save-img")

    sb.run("echo cached_data > /workspace/cached.txt")
    sb.save_as_image("nbx-dev-test:cached")
    print("  saved as Docker image: nbx-dev-test:cached")

    sb.delete()

    # Verify: create from cached image
    sb2 = Sandbox(SandboxConfig(image="nbx-dev-test:cached", working_dir="/workspace"), name="from-cache")
    output, ec = sb2.run("cat /workspace/cached.txt")
    print(f"  from cached image: {output.strip()!r}, ec={ec}")
    sb2.delete()

    import subprocess as _sp
    _sp.run(["docker", "rmi", "-f", "nbx-dev-test:cached"], capture_output=True)
    print("  OK")
else:
    print("  SKIP (requires root + Docker)")
    print("  OK")


# ------------------------------------------------------------------ #
#  19. Cleanup stale sandboxes                                         #
# ------------------------------------------------------------------ #
section("19. cleanup_stale")

cleaned = Sandbox.cleanup_stale()
print(f"  cleaned {cleaned} orphaned sandbox(es)")
print("  OK")


# ------------------------------------------------------------------ #
#  19b. Structured error types                                         #
# ------------------------------------------------------------------ #
section("19b. Structured error types")

try:
    Sandbox(SandboxConfig(image=""))  # no image
except SandboxConfigError as e:
    print(f"  caught SandboxConfigError: {e}")

print("  OK")


# ------------------------------------------------------------------ #
#  20. Layer cache (shared Docker layers)                              #
# ------------------------------------------------------------------ #
section("20. Layer cache")

from nitrobox.rootfs import get_image_config

images = ["python:3.11-slim", "python:3.12-slim"]
sandboxes = []
for img in images:
    t0 = time.monotonic()
    sb = Sandbox(SandboxConfig(image=img, working_dir="/tmp"), name=f"layer-{img.replace(':', '-')}")
    elapsed = (time.monotonic() - t0) * 1000
    layers = getattr(sb, "_layer_dirs", None)
    n = len(layers) if layers else 0
    out, _ = sb.run("python3 --version")
    print(f"  {img}: {elapsed:.0f}ms, {n} layers, {out.strip()}")
    sandboxes.append(sb)

all_layers = [set(l.name for l in (getattr(s, "_layer_dirs", None) or [])) for s in sandboxes]
if len(all_layers) == 2:
    shared = all_layers[0] & all_layers[1]
    total = all_layers[0] | all_layers[1]
    print(f"  shared: {len(shared)}/{len(total)} layers ({len(shared)/max(len(total),1)*100:.0f}% dedup)")
for s in sandboxes:
    s.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  21. Security hardening                                              #
# ------------------------------------------------------------------ #
section("21. Security hardening")

config = SandboxConfig(image=IMAGE, working_dir="/workspace")
sb = Sandbox(config, name="security")

# Seccomp active
output, _ = sb.run("cat /proc/self/status | grep Seccomp")
print(f"  seccomp: {output.strip()}")

# mount blocked
_, ec = sb.run("mount -t tmpfs tmpfs /tmp 2>/dev/null")
print(f"  mount blocked: ec={ec}")

# unshare blocked
_, ec = sb.run("unshare --pid echo 2>/dev/null")
print(f"  unshare blocked: ec={ec}")

# Capabilities dropped
output, _ = sb.run("cat /proc/self/status | grep CapBnd")
cap_hex = output.strip().split()[-1]
cap_val = int(cap_hex, 16)
sys_admin = bool(cap_val & (1 << 21))
print(f"  CAP_SYS_ADMIN: {'KEPT (bad!)' if sys_admin else 'dropped'}")

# Masked paths
output, _ = sb.run("cat /proc/kcore 2>&1 | wc -c")
print(f"  /proc/kcore masked: {output.strip()} bytes")

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  21b. Landlock path/port restrictions                                #
# ------------------------------------------------------------------ #
section("21b. Landlock path/port restrictions")

from nitrobox._core import py_landlock_abi_version as _landlock_abi_version
abi = _landlock_abi_version()
print(f"  Landlock ABI version: {abi}")

if abi > 0:
    config = SandboxConfig(
        image=IMAGE, working_dir="/workspace",
        writable_paths=["/workspace"],
    )
    sb = Sandbox(config, name="landlock")
    print(f"  features['landlock']: {sb.features.get('landlock')}")

    # /workspace should be writable
    output, ec = sb.run("echo ok > /workspace/test.txt && cat /workspace/test.txt")
    print(f"  write /workspace: ec={ec}, output={output.strip()!r}")

    # /root should NOT be writable
    _, ec = sb.run("touch /root/test 2>/dev/null")
    print(f"  write /root (blocked): ec={ec}")

    # reads still unrestricted
    output, ec = sb.run("ls /usr/bin/ | head -1")
    print(f"  read /usr/bin: ec={ec}, first={output.strip()!r}")

    sb.delete()
    print("  OK")
else:
    print("  Landlock not available, skipping")


# ------------------------------------------------------------------ #
#  22. get_image_config                                                #
# ------------------------------------------------------------------ #
section("22. get_image_config")

cfg = get_image_config(IMAGE)
if cfg:
    print(f"  CMD:     {cfg.get('Cmd')}")
    print(f"  ENV:     {cfg.get('Env', [])[:2]}...")
    print(f"  WORKDIR: {cfg.get('WorkingDir')}")
else:
    print("  SKIP (image config not available)")
print("  OK")


# ------------------------------------------------------------------ #
#  23. Device passthrough (rootless + rootful)                         #
# ------------------------------------------------------------------ #
section("23. Device passthrough")

# Test with /dev/fuse (not in the default 6 devices, available on most systems)
import os as _os
if _os.path.exists("/dev/fuse"):
    config = SandboxConfig(
        image=IMAGE, working_dir="/workspace",
        devices=["/dev/fuse"],
    )
    sb = Sandbox(config, name="device")
    output, ec = sb.run("test -c /dev/fuse && echo exists")
    print(f"  /dev/fuse passthrough: {output.strip()!r}")
    # Verify correct major:minor (10:229)
    output, _ = sb.run("stat -c '%t:%T' /dev/fuse")
    print(f"  /dev/fuse major:minor: {output.strip()!r}")
    assert sb.features.get("devices") is True
    print(f"  features['devices']: {sb.features.get('devices')}")

    # Survives reset
    sb.reset()
    output, ec = sb.run("test -c /dev/fuse && echo after_reset")
    print(f"  after reset: {output.strip()!r}")
    sb.delete()
else:
    print("  SKIP (/dev/fuse not available)")

# Test /dev/kvm if accessible (rootless KVM)
if _os.path.exists("/dev/kvm") and _os.access("/dev/kvm", _os.R_OK | _os.W_OK):
    config = SandboxConfig(
        image=IMAGE, working_dir="/workspace",
        devices=["/dev/kvm"],
    )
    sb = Sandbox(config, name="kvm-device")
    output, ec = sb.run("test -c /dev/kvm && echo kvm_ok")
    print(f"  /dev/kvm passthrough: {output.strip()!r}")
    sb.delete()
else:
    print("  SKIP /dev/kvm (not available or no access)")
print("  OK")


# ------------------------------------------------------------------ #
#  24. OOM score + cpuset                                              #
# ------------------------------------------------------------------ #
section("24. OOM score + cpuset")

config = SandboxConfig(
    image=IMAGE, working_dir="/workspace",
    oom_score_adj=500,
    cpuset_cpus="0",
)
sb = Sandbox(config, name="oom-cpuset")
output, ec = sb.run("echo ok")
print(f"  oom_score_adj=500, cpuset_cpus=0: {output.strip()!r}")
sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
#  25. Concurrent sandbox creation                                     #
# ------------------------------------------------------------------ #
section("25. Concurrent creation")

from concurrent.futures import ThreadPoolExecutor

def _create_run_delete(i):
    cfg = SandboxConfig(image=IMAGE, working_dir="/workspace")
    s = Sandbox(cfg, name=f"conc-{i}")
    out, ec = s.run(f"echo worker-{i}")
    s.delete()
    return out.strip(), ec

t0 = time.monotonic()
with ThreadPoolExecutor(max_workers=4) as pool:
    results = list(pool.map(_create_run_delete, range(4)))
elapsed = (time.monotonic() - t0) * 1000
print(f"  4 sandboxes in {elapsed:.0f}ms")
for out, ec in results:
    print(f"    {out!r} ec={ec}")
print("  OK")


# ------------------------------------------------------------------ #
#  26. Userns-specific: DNS, /tmp perms, devpts, UID mapping           #
# ------------------------------------------------------------------ #
section("26. Userns features")

import os
if os.geteuid() != 0:
    config = SandboxConfig(image=IMAGE, working_dir="/workspace")
    sb = Sandbox(config, name="userns-check")

    # DNS propagated from host
    output, ec = sb.run("cat /etc/resolv.conf")
    has_ns = "nameserver" in output
    print(f"  DNS propagated: {has_ns}")

    # /tmp writable (mode 1777)
    output, _ = sb.run("stat -c %a /tmp")
    print(f"  /tmp perms: {output.strip()}")

    # /dev/pts mounted (PTY allocation)
    _, ec = sb.run("test -d /dev/pts")
    print(f"  devpts mounted: {ec == 0}")

    # UID mapping
    output, _ = sb.run("cat /proc/self/uid_map")
    lines = [l for l in output.strip().splitlines() if l.strip()]
    print(f"  uid_map lines: {len(lines)} ({'full mapping' if len(lines) > 1 else 'root-only'})")

    # apt-get works with full mapping
    if len(lines) > 1:
        _, ec = sb.run("apt-get update -qq 2>&1 | tail -1")
        print(f"  apt-get update: ec={ec}")

    sb.delete()
    print("  OK")
else:
    print("  SKIP (running as root — userns features only apply in rootless mode)")
    print("  Re-run without sudo to test: python dev/run.py")


# ------------------------------------------------------------------ #
#  27. QemuVM (QEMU/KVM management)                                    #
# ------------------------------------------------------------------ #
section("27. QemuVM (QEMU/KVM)")

from nitrobox.vm import QemuVM

if not QemuVM.check_available():
    print("  SKIP (KVM not available)")
else:
    vm_dir = Path(tempfile.mkdtemp(prefix="nbx_vm_"))
    import subprocess as _sp2
    _sp2.run(["qemu-img", "create", "-f", "qcow2", str(vm_dir / "test.qcow2"), "64M"],
             capture_output=True)

    config = SandboxConfig(
        image=IMAGE, working_dir="/workspace",
        devices=["/dev/kvm"],
        volumes=[f"{vm_dir}:/vm:rw"],
    )
    try:
        sb = Sandbox(config, name="qemu-vm")
    except Exception as e:
        print(f"  SKIP (sandbox init failed: {e})")
        sb = None

    if sb is not None:
        _, ec = sb.run("which qemu-system-x86_64 >/dev/null 2>&1")
        if ec != 0:
            print("  Installing QEMU...")
            sb.run(
                "apt-get update -qq 2>/dev/null && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                "--no-install-recommends qemu-system-x86 2>/dev/null | tail -1",
                timeout=300,
            )

        _, ec = sb.run("qemu-system-x86_64 --version >/dev/null 2>&1")
        if ec == 0:
            vm = QemuVM(sb, disk="/vm/test.qcow2", memory="128M", cpus=1)
            vm.start(timeout=30)
            print(f"  VM started: {vm}")

            status = vm.qmp("query-status")
            print(f"  status: {status['return']['status']}")

            vm.savevm("ready")
            print("  savevm OK")

            vm.loadvm("ready")
            print("  loadvm OK")

            info = vm.info_snapshots()
            print(f"  has snapshot: {'ready' in info}")

            # QGA test (requires qemu-ga in guest — skip if not available)
            if vm.guest_ping(timeout=3):
                print("  QGA: guest agent responsive")
                out, ec = vm.guest_exec("echo qga-ok")
                print(f"  QGA guest_exec: {out.strip()!r}, ec={ec}")
            else:
                print("  QGA: guest agent not available (no qemu-ga in guest)")

            vm.stop()
            print("  stopped")
        else:
            print("  SKIP (qemu-system-x86_64 not available)")
        sb.delete()

    import shutil as _shutil2
    _shutil2.rmtree(vm_dir, ignore_errors=True)
print("  OK")


# ------------------------------------------------------------------ #
section("28. cap_add")
# ------------------------------------------------------------------ #

config = SandboxConfig(image=IMAGE, working_dir="/workspace", cap_add=["NET_RAW", "NET_ADMIN"])
sb = Sandbox(config, name="cap-add")

output, _ = sb.run("cat /proc/self/status | grep CapEff")
cap_hex = output.strip().split()[-1]
cap_int = int(cap_hex, 16)
has_net_raw = bool(cap_int & (1 << 13))
has_net_admin = bool(cap_int & (1 << 12))
print(f"  NET_RAW={has_net_raw}, NET_ADMIN={has_net_admin}")
assert has_net_raw and has_net_admin

sb.delete()
print("  OK")


# ------------------------------------------------------------------ #
section("29. Docker Compose compatibility")
# ------------------------------------------------------------------ #

import tempfile as _tempfile

_compose_dir = _tempfile.mkdtemp(prefix="nbx_compose_")
_compose_path = os.path.join(_compose_dir, "docker-compose.yml")
with open(_compose_path, "w") as _f:
    _f.write("""\
services:
  backend:
    image: ubuntu:22.04
    command: "sleep infinity"
    hostname: backend
  frontend:
    image: ubuntu:22.04
    command: "sleep infinity"
    depends_on:
      - backend
""")

from nitrobox import ComposeProject

with ComposeProject(_compose_path, project_name="devrun") as proj:
    print(f"  services: {list(proj.services.keys())}")

    out, ec = proj.run("backend", "echo compose-ok")
    assert ec == 0 and "compose-ok" in out, f"run failed: {out}"
    print(f"  run: {out.strip()}")

    # /etc/hosts resolution
    out, ec = proj.run("frontend", "getent hosts backend")
    assert ec == 0 and "127.0.0.1" in out, f"hosts failed: {out}"
    print(f"  hosts: {out.strip()}")

    # reset clears state
    proj.run("backend", "echo tmp > /tmp/x.txt")
    proj.reset()
    _, ec = proj.run("backend", "cat /tmp/x.txt 2>/dev/null")
    assert ec != 0, "file should be gone after reset"
    print("  reset: OK")

import shutil as _shutil3
_shutil3.rmtree(_compose_dir, ignore_errors=True)
print("  OK")


# ------------------------------------------------------------------ #
section("30. Compose: image default CMD (no command: in compose)")
# ------------------------------------------------------------------ #

_compose_dir2 = _tempfile.mkdtemp(prefix="nbx_compose2_")
_compose_path2 = os.path.join(_compose_dir2, "docker-compose.yml")
with open(_compose_path2, "w") as _f:
    # ubuntu:22.04 has CMD ["bash"] — should auto-start
    _f.write("""\
services:
  worker:
    image: ubuntu:22.04
""")

with ComposeProject(_compose_path2, project_name="devrun-cmd") as proj:
    out, ec = proj.run("worker", "echo image-cmd-ok")
    assert ec == 0 and "image-cmd-ok" in out
    print(f"  image CMD auto-start: {out.strip()}")

_shutil3.rmtree(_compose_dir2, ignore_errors=True)
print("  OK")


# ------------------------------------------------------------------ #
section("All done!")
