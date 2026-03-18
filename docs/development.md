# Development

## Vendored binaries

The pip package bundles three static binaries in `src/agentdocker_lite/_vendor/`:

| Binary | Purpose | Size | Source |
|---|---|---|---|
| `pasta` / `pasta.avx2` | NAT'd networking + port mapping | ~1.3MB | [passt](https://passt.top/) |
| `criu` | Process checkpoint/restore | ~2.8MB | [seqeralabs/criu-static](https://github.com/seqeralabs/criu-static/releases) v4.2 |
| `adl-seccomp` | Seccomp BPF + cap drop + mask/readonly paths | ~750KB | Built from `_vendor/adl-seccomp.c` |

### Rebuilding adl-seccomp

The source is at `src/agentdocker_lite/_vendor/adl-seccomp.c`. Rebuild with:

```bash
gcc -static -Os -o src/agentdocker_lite/_vendor/adl-seccomp \
    src/agentdocker_lite/_vendor/adl-seccomp.c && \
    strip src/agentdocker_lite/_vendor/adl-seccomp
```

Requires `gcc` and static glibc (`glibc-static` on Fedora, `libc6-dev` on Ubuntu, standard on Arch). The binary must be statically linked — it runs inside minimal rootfs containers that may lack shared libraries.

What `adl-seccomp` does (in order):
1. Drops non-essential Linux capabilities (keeps Docker-default 13)
2. Masks sensitive paths (`/proc/kcore`, `/proc/keys`, etc.) with `/dev/null` or tmpfs
3. Remounts kernel paths (`/proc/sys`, `/proc/bus`, etc.) as read-only
4. Reads BPF bytecode from `/tmp/.adl_seccomp.bpf` and applies seccomp filter
5. `exec`s its arguments — seccomp filter is inherited across exec

### Rebuilding criu

Download from [seqeralabs/criu-static releases](https://github.com/seqeralabs/criu-static/releases):

```bash
wget https://github.com/seqeralabs/criu-static/releases/download/v4.2/criu-static-4.2-linux-amd64.tar.gz
tar xzf criu-static-4.2-linux-amd64.tar.gz
strip criu-static-4.2-linux-amd64/bin/criu
cp criu-static-4.2-linux-amd64/bin/criu src/agentdocker_lite/_vendor/criu
chmod +x src/agentdocker_lite/_vendor/criu
```

### Regenerating protobuf

The CRIU RPC protobuf bindings (`_vendor/criu_rpc_pb2.py`) are generated from `rpc.proto`:

```bash
# Get rpc.proto from CRIU or runc repo
protoc --python_out=src/agentdocker_lite/_vendor/ rpc.proto
```

## Running tests

```bash
# All tests (requires root + Docker)
sudo python -m pytest tests/ -v

# Just sandbox tests
sudo python -m pytest tests/test_sandbox.py -v

# Just security tests
sudo python -m pytest tests/test_security.py -v

# Just CRIU checkpoint tests
sudo python -m pytest tests/test_checkpoint.py -v

# Rootless tests (no root needed)
python -m pytest tests/test_security.py -v -k "UserNamespace"
```

## Benchmark

```bash
sudo python examples/benchmark.py
```

## Architecture

```
Host Python process
  └─ subprocess.Popen
       └─ unshare --pid --mount --uts --ipc [--time] [--net] --fork bash -c '
            mount /proc, /dev (host tools)     ← before pivot_root
            pivot_root . .pivot_old            ← CRIU-compatible root
            exec setsid adl-seccomp /bin/sh    ← security then shell
          '
            └─ adl-seccomp:
                 cap drop → mask paths → readonly paths → seccomp BPF → exec /bin/sh
                   └─ /bin/sh (persistent shell, reads commands from stdin pipe)
```
