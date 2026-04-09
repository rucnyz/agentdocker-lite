# Terminal-Bench 2.0 — Docker vs nitrobox

**Dataset:** `terminal-bench@2.0`
**Tasks:** 88 (excluding `portfolio-optimization` — flaky performance test)
**Agent:** oracle
**Concurrency:** 16
**Date:** 2026-04-09

## Cold Start

|   C |      Env |      Wall |   EnvSetup |    Agent |   Verify |  Teardown | Pass | Fail | Err |
|-----|----------|-----------|------------|----------|----------|-----------|------|------|-----|
|  16 |   docker |   1961.1s | 19.8s (16%)| 39.1s (31%)| 57.5s (45%)| 10.4s  (8%)|   73 |    4 |   1 |
|  16 | nitrobox |   1029.5s | 17.9s (22%)| 37.6s (46%)| 25.6s (31%)|  0.5s  (1%)|   81 |    7 |   0 |

**Cold wall-clock speedup: 1.90x** (33 min → 17 min)

## Hot Start (caches warm)

|   C |      Env |      Wall |   EnvSetup |    Agent |   Verify |  Teardown | Pass | Fail | Err |
|-----|----------|-----------|------------|----------|----------|-----------|------|------|-----|
|  16 |   docker |   1961.8s |  3.3s  (2%)| 52.7s (39%)| 63.5s (47%)| 15.6s (12%)|   82 |    5 |   2 |
|  16 | nitrobox |    931.2s |  0.7s  (1%)| 28.2s (51%)| 25.4s (46%)|  1.1s  (2%)|   82 |    6 |   0 |

**Hot wall-clock speedup: 2.11x** (33 min → 16 min)

### Per-phase speedup (hot start)

| Phase | Docker | nitrobox | Speedup |
|-------|--------|----------|---------|
| env_setup | 3.3s | 0.7s | **4.7x** |
| agent_exec | 52.7s | 28.2s | **1.9x** |
| verifier | 63.5s | 25.4s | **2.5x** |
| teardown | 15.6s | 1.1s | **14.2x** |

- nitrobox: **82 pass, 6 fail, 0 errors**
- Docker: **82 pass, 5 fail, 2 errors**
- Same pass count; nitrobox has 0 infra errors

## Reproduce

```bash
docker login   # needed for prebuilt images

# Cold start (first run populates caches)
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle --concurrency 16 \
    --envs docker,nitrobox \
    -x portfolio-optimization \
    --no-delete

# Hot start (second run uses cached images/layers)
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle --concurrency 16 \
    --envs docker,nitrobox \
    -x portfolio-optimization
```
