# Development

## Rust core

Security primitives (seccomp, capabilities, Landlock), namespace spawning, overlayfs mounting, and cgroup management are implemented in Rust via PyO3. The `_core` extension module is built by maturin.

```bash
pip install maturin
maturin develop --release        # build Rust core + install in-place
pytest tests/                    # run tests
```

To regenerate type stubs after changing Rust bindings:

```bash
cargo run --bin stub_gen --release
```

## Vendored binaries

The pip package bundles static binaries in `src/nitrobox/_vendor/`:

| Binary | Purpose | Size | Source |
|---|---|---|---|
| `pasta` / `pasta.avx2` | NAT'd networking + port mapping | ~1.3MB | [passt](https://passt.top/) |
| `criu` | Process checkpoint/restore | ~2.8MB | [seqeralabs/criu-static](https://github.com/seqeralabs/criu-static/releases) v4.2 |
| `nbx-qmp` | QMP client (no_std Rust, raw syscalls) | ~4KB | `rust/src/bin/nbx_qmp.rs` |

### Regenerating protobuf

```bash
protoc --python_out=src/nitrobox/_vendor/ rpc.proto
```

## Running tests

```bash
python -m pytest tests/ -v                         # all tests (rootless)
python -m pytest tests/test_checkpoint.py -v       # CRIU tests
python -m pytest tests/test_vm.py -v               # VM + QGA mock tests
```

### QGA integration tests

End-to-end tests that boot a real Ubuntu VM with `qemu-guest-agent` inside a nitrobox sandbox. Requires `/dev/kvm` and Docker.

```bash
python scripts/build_test_vm.py          # download Ubuntu cloud image + create seed ISO
python scripts/test_qga_integration.py   # run 30 QGA tests (first run ~20s, then ~1s via snapshot)
```

## Architecture

```
Sandbox(config, name)
  __init__:
    if root → _init_rootful()      # direct mount/cgroup
    else   → _init_userns()        # user namespace (kernel 5.11+)

  _init_rootful / _init_userns:
    resolve rootfs (OCI layer cache)
    mount overlayfs / btrfs
    setup cgroup v2 (rootful) or systemd delegation (rootless)
    py_spawn_sandbox() → Rust init chain:
      fork → unshare(PID|MNT|UTS|IPC|USER|NET)
      mount overlayfs + volumes + /proc + /dev
      pivot_root → security (cap drop + mask + seccomp + Landlock)
      exec shell
    ← PersistentShell (stdin/stdout pipes + signal fd)

  run(cmd) → write to shell stdin, read stdout, signal fd returns exit code
  reset()  → kill shell, O(1) rename upper/work dirs, restart shell
  delete() → kill shell, unmount, cleanup cgroup, rm dirs
```

## Project structure

```
src/nitrobox/
├── config.py           SandboxConfig + parsers + Docker compat
├── sandbox.py          Sandbox class (single unified implementation)
├── _errors.py          Structured error types (SandboxError hierarchy)
├── _shell.py           PersistentShell + SpawnConfig TypedDict
├── _core.pyi           Rust bindings type stubs (auto-generated)
├── rootfs.py           OCI image management + layer cache
├── _registry.py        Pure-Python OCI registry client
├── checkpoint.py       CRIU checkpoint/restore
├── vm.py               QEMU/KVM VM manager + QGA guest execution
├── cli.py              CLI commands (nitrobox ps/kill/cleanup)
├── compose/            Docker Compose compatibility
│   ├── _parse.py       YAML parsing + service definitions
│   ├── _network.py     SharedNetwork + health checks
│   └── _project.py     ComposeProject orchestrator
└── _vendor/            Vendored binaries (pasta, criu, nbx-qmp)
```
