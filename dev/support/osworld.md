# OSWorld — Docker vs nitrobox

**Dataset:** OSWorld (GUI agent benchmark, Ubuntu Desktop VM)
**Agent:** Claude Sonnet 4.5, Computer Use agent, 100 steps
**Tasks:** 100
**Date:** 2026-04-08 (results from PR #18)

## E2E Results

| Env | Tasks | Pass | Rate | Avg Score |
|-----|-------|------|------|-----------|
| Docker | 96 | 79 | 82.3% | 0.814 |
| nitrobox | 94 | 79 | 84.0% | 0.830 |

Pass rates match within noise. **Seamless drop-in replacement confirmed.**

### Phase breakdown (per task)

| Phase | Docker | nitrobox | Speedup |
|-------|--------|----------|---------|
| **environment_setup** | **33.2s** | **7.0s** | **4.7x** |
| agent_execution | 174.2s | 157.6s | 1.1x |
| verifier | 22.5s | 22.5s | 1.0x |
| **total per task** | **230.0s** | **187.1s** | **1.2x** |
| **overhead %** | **14.5%** | **3.7%** | |

The 4.7x setup speedup comes from QMP loadvm (in-place memory restore)
vs Docker container restart (OS reboot). The 1.1x agent speedup comes
from fewer network hops (no Docker bridge layer).

## Concurrent VM Reset Benchmark

Same qcow2, QEMU/KVM. Reset-to-ready = time from triggering reset to
VM being usable.

### Reset-to-ready

| Concurrency | Docker | nitrobox | Speedup |
|-------------|--------|----------|---------|
| 4 | 16.2s | 2.5s | 6.6x |
| 8 | 18.5s | 2.3s | 8.0x |
| 16 | 22.0s | 2.6s | **8.5x** |

### Screenshot (HTTP, same Flask endpoint)

| Concurrency | Docker | nitrobox | Speedup |
|-------------|--------|----------|---------|
| 4 | 442ms | 377ms | 1.2x |
| 8 | 448ms | 396ms | 1.1x |
| 16 | 466ms | 404ms | 1.2x |

## Reproduce

```bash
# 1. Install nitrobox provider into OSWorld
python examples/bench_osworld_e2e.py \
    --install-provider \
    --osworld-dir /path/to/osworld

# 2. Run e2e comparison
ANTHROPIC_API_KEY=sk-ant-... python examples/bench_osworld_e2e.py \
    --osworld-dir /path/to/osworld \
    --n-tasks 100 --max-steps 100 \
    --envs docker,nitrobox

# 3. Concurrent VM reset benchmark
python examples/bench_osworld_concurrent.py \
    --qcow2 /path/to/Ubuntu.qcow2 \
    --concurrency 1,4,8,16
```
