# Userns Mode Fixes for SkyRL/Harbor Integration

Summary of all fixes required to make nitrobox work as a drop-in replacement for Docker in the SkyRL + Harbor RL training pipeline (rootless/userns mode).

## Test Result

```
Generating Trajectories: 100%|██████████| 1/1 [00:49<00:00, 49.30s/it]
# of masked instances: 0 / 1
# of timeout trajectories: 0
# of error trajectories: 0
```

## Fix 1: Full UID Mapping (`newuidmap`/`newgidmap`)

**Problem:** When nitrobox runs in rootless (user namespace) mode, `--map-root-user` only maps a single UID:

```
sandbox uid 0 (root)  →  host uid (e.g. 243001009 / jingyang)
all other uids        →  unmapped (invalid)
```

This causes programs that switch to non-root users internally to fail. The most common case is `apt-get`, which drops privileges to the `_apt` user (uid 42) for downloading packages:

```
apt-get update
  → internally: setuid(42) to switch to _apt
  → kernel: uid 42 has no mapping → EINVAL
  → "seteuid 42 failed - Invalid argument"
```

Other affected operations: `useradd`, `su`, `chown` to non-root users, any program that calls `setgroups()`.

**Root cause:** `unshare --user --map-root-user` writes a single-entry uid_map:

```
# /proc/<pid>/uid_map
0  <outer_uid>  1       ← only uid 0 is mapped
```

The kernel rejects any `setuid(N)` where N > 0 because there's no mapping entry for it.

**Fix:** Use subordinate UID ranges via `newuidmap`/`newgidmap` to write a full uid mapping:

```
# /proc/<pid>/uid_map
0  243001009      1     ← uid 0 → jingyang (host user)
1     200000  65536     ← uid 1-65536 → host uid 200000-265535
```

Now `setuid(42)` maps to host uid 200042 — a valid mapping. `apt-get`, `useradd`, etc. all work.

### Implementation

1. **Detection** (`_detect_subuid_range` in `sandbox.py`):
   - Checks if `newuidmap`/`newgidmap` are installed
   - Parses `/etc/subuid` for the current user's subordinate range
   - Returns `(outer_uid, sub_start, sub_count)` or `None` (graceful fallback)

2. **Synchronization** (`start()` in `_shell.py`):
   - `--map-root-user` is removed from the `unshare` command
   - A sync pipe is created: the child blocks on `read` after entering the new namespace
   - Parent polls `/proc/<pid>/ns/user` to confirm namespace creation
   - Parent calls `newuidmap` and `newgidmap` to write the full mapping
   - Parent closes the pipe → child's `read` returns → child proceeds with setup

3. **Graceful fallback**: If `newuidmap` or `/etc/subuid` is not available, falls back to `--map-root-user` (original behavior, only uid 0 mapped).

**Files changed:**
- `_shell.py`: Added `subuid_range` parameter, pipe-based sync between parent and child, `newuidmap`/`newgidmap` calls after namespace creation
- `sandbox.py`: Added `_detect_subuid_range()` that auto-detects `/etc/subuid` config; graceful fallback to `--map-root-user` if unavailable

### Host Setup (One-Time)

#### 1. Install uidmap

```bash
sudo apt-get install -y uidmap
```

Provides `newuidmap` and `newgidmap` (setuid-root binaries). Already installed on most systems with Docker rootless or Podman.

#### 2. Configure subordinate UID/GID ranges

```bash
# Check if your user already has an entry
grep $(whoami) /etc/subuid

# If not, add one (pick a range that doesn't overlap with existing entries)
echo "$(whoami):200000:65536" | sudo tee -a /etc/subuid
echo "$(whoami):200000:65536" | sudo tee -a /etc/subgid
```

**Notes:**
- `useradd` automatically configures this for local users. LDAP/AD domain users typically need manual setup.
- The range 200000-265535 is arbitrary — just avoid overlapping with other users' ranges (check existing entries in `/etc/subuid`).
- This is the same mechanism used by Docker rootless mode and Podman.
- Zero risk to host: these UIDs are only used inside user namespaces and don't correspond to any real user accounts.

#### 3. Verify

```bash
# Should show the range you configured
grep $(whoami) /etc/subuid
# e.g.: jingyang:200000:65536

# Quick test
python3 -c "
from nitrobox import Sandbox, SandboxConfig
sb = Sandbox(SandboxConfig(image='ubuntu:22.04'), 'test')
out, _ = sb.run('cat /proc/self/uid_map')
print(out)
# Should show TWO lines (full mapping), not one:
#   0  <your_uid>      1
#   1     200000  65536
out, _ = sb.run('apt-get update 2>&1')
print('apt-get works' if 'Fetched' in out or 'Hit' in out else 'apt-get failed')
sb.delete()
"
```

### Comparison

| Capability | `--map-root-user` (fallback) | Full UID mapping |
|---|---|---|
| Run commands as root | Yes | Yes |
| `apt-get install` | No (`seteuid` fails) | Yes |
| `useradd` / `chown` non-root | No | Yes |
| `setgroups()` | No | Yes |
| Requires `/etc/subuid` | No | Yes |
| Requires `uidmap` package | No | Yes |

## Fix 2: DNS Propagation

**Problem:** `apt-get update` fails to connect to package repos. `Ign:1 http://archive.ubuntu.com/ubuntu noble InRelease` — DNS resolution fails.

**Root cause:** Docker-exported rootfs has an empty `/etc/resolv.conf`. Docker normally bind-mounts the host's resolv.conf at container runtime; the export doesn't include that mount.

**Fix:** In the userns setup script, copy host's `/etc/resolv.conf` into sandbox if the sandbox one is empty:
```bash
if [ ! -s ${merged}/etc/resolv.conf ] && [ -s /etc/resolv.conf ]; then
  cp /etc/resolv.conf ${merged}/etc/resolv.conf 2>/dev/null || true
fi
```

**File changed:** `sandbox.py` (`_generate_userns_setup_script`)

## Fix 3: `/tmp` Permissions

**Problem:** `apt-key` fails with `Couldn't create temporary file /tmp/apt.conf.xxx`. The `_apt` user (uid 42) can't write to `/tmp`.

**Root cause:** Docker-exported rootfs has `/tmp` with permissions `775` (owner=rwx, group=rwx, others=r-x) instead of the standard `1777` (world-writable + sticky). The `_apt` user is "others" and can't write.

**Fix:** `chmod 1777` in the setup script:
```bash
chmod 1777 ${merged}/tmp 2>/dev/null || true
```

**File changed:** `sandbox.py` (`_generate_userns_setup_script`)

## Fix 4: Skip Rust init chain `/dev` setup in Userns Mode

**Problem:** `apt-get update` reports `gpgv not installed` even though `/usr/bin/gpgv` exists and works. tmux fails with `create window failed: fork failed: No such file or directory`.

**Root cause:** The Rust init chain (security primitives, formerly `nbx-seccomp`) re-mounts `/dev` as an empty tmpfs, then creates device nodes via `mknod`. In userns mode, `mknod` silently fails (requires real root). This leaves `/dev/null`, `/dev/zero`, etc. missing. Consequences:
- `apt-key`: `cannot create /dev/null: Permission denied` → gpgv verification fails
- `tmux`: no `/dev/pts` (devpts not mounted) → PTY allocation fails

The setup script had already correctly set up `/dev` (bind-mounting from host) and `/dev/pts`, but the Rust init chain overwrote everything.

**Fix (original):** Skip the Rust init chain in userns mode. The setup script already handles `/proc`, `/dev`, and volume mounts.

**Fix (current):** The Rust init chain now supports a `/tmp/.nbx_skip_dev` marker file. When present, it skips `/proc`+`/dev` mount (setup script handles these) but keeps capability drop, path masking, read-only paths, and seccomp BPF. This gives rootless mode full security hardening.

Additionally, mount `devpts` in the setup script (previously only done by the Rust init chain):
```bash
mount -t devpts devpts ${merged}/dev/pts -o nosuid,newinstance,ptmxmode=0666
ln -sf pts/ptmx ${merged}/dev/ptmx
```

**File changed:** `sandbox.py` (`_generate_userns_setup_script`)

**DONE:** seccomp BPF, capability drop, masked paths, and read-only paths are now all active in rootless mode via the `nbx_skip_dev` mechanism.

## Fix 5: `ExecResult.stderr` Must Be String (SkyRL side)

**Problem:** Harbor's terminus-2 agent crashes with `AttributeError: 'NoneType' object has no attribute 'strip'` on `set_history_result.stderr.strip()`.

**Root cause:** nitrobox merges stderr into stdout. The environment provider returned `stderr=None` in `ExecResult`, but Harbor expects a string.

**Fix:** Return `stderr=""` instead of `stderr=None`.

**File changed:** `nitrobox_environment.py` (SkyRL side)

## All Files Changed

### nitrobox

| File | Changes |
|---|---|
| `src/nitrobox/_shell.py` | `subuid_range` param, pipe sync, `newuidmap`/`newgidmap` |
| `src/nitrobox/sandbox.py` | `_detect_subuid_range()`, DNS propagation, `/tmp` chmod, devpts mount, skip Rust init chain `/dev` setup in userns |

### SkyRL

| File | Changes |
|---|---|
| `examples/.../nitrobox_environment.py` | Use `Sandbox()` factory (not `NamespaceSandbox`), remove `use_sudo`, `stderr=""` |
| `examples/.../run_harbor_gen_nitrobox.sh` | `NUM_GPUS` from env var with default |

## Debugging Notes

Useful commands for debugging sandbox issues:

```python
from nitrobox import Sandbox, SandboxConfig
config = SandboxConfig(image='<rootfs_path>', working_dir='/app')
sb = Sandbox(config, 'debug')

# Check uid mapping
sb.run('cat /proc/self/uid_map')

# Check DNS
sb.run('cat /etc/resolv.conf')

# Check /dev
sb.run('ls -la /dev/null /dev/pts/')

# Check devpts
sb.run('mount | grep pts')

# Test apt-get
sb.run('apt-get update 2>&1', timeout=60)

# Test tmux
sb.run('apt-get install -y tmux 2>&1', timeout=120)
sb.run('tmux new-session -d -s test 2>&1')
sb.run('tmux list-sessions')

sb.delete()
```

To force SkyRL to pick up nitrobox changes:
```bash
uv cache clean nitrobox --force
```
