# SWEBench Verified — Docker vs nitrobox

**Dataset:** SWEBench Verified (500 tasks, locally generated via adapter)
**Agent:** oracle
**Concurrency:** 20
**Date:** 2026-04-08

## Results

| Metric | nitrobox | Docker |
|--------|----------|--------|
| **Wall time** | **1h 32m (5504s)** | 1h 55m (6927s) |
| Trials completed | 500 | 500 |
| Exceptions | **0** | 1 (VerifierTimeoutError) |
| Pass (1.0) | **495** | 491 |
| Fail (0.0) | 5 | 8 |
| Mean reward | **0.990** | 0.982 |

**Wall-clock speedup: 1.26x** (1h 55m -> 1h 32m)

### Per-phase mean timing (per trial)

| Phase | Docker | nitrobox |
|-------|--------|----------|
| environment_setup | 7.7s | 36.1s |
| agent_execution | 0.6s | 20.4s |
| verifier | 31.7s | 40.5s |
| teardown | 28.7s | 45.6s |

Note: Per-trial times are higher for nitrobox because buildah builds
images from Dockerfile on first use (swebench images are not prebuilt
for containers/storage). Despite higher per-trial overhead, nitrobox
achieves faster wall-clock time due to lighter resource footprint at
concurrency 20 — less contention on CPU/memory/IO than Docker daemon.

### Failed tasks (identical across both environments)

These 5 tasks fail on both Docker and nitrobox — upstream SWEBench issues:

- `astropy__astropy-7606`
- `astropy__astropy-8707`
- `astropy__astropy-8872`
- `django__django-10097`
- `matplotlib__matplotlib-20859`

Docker had 3 additional failures + 1 timeout likely due to resource
pressure from the Docker daemon at concurrency 20.

## Reproduce

```bash
# 1. Generate SWEBench Verified tasks (requires swebench package)
cd /path/to/harbor
uv run --with swebench python adapters/swebench/run_adapter.py \
    --all --task-dir datasets/swebench

# 2. Run with nitrobox (concurrency 20)
uv run harbor run \
    -p datasets/swebench \
    -e nitrobox \
    -a oracle \
    -n 20 \
    --job-name swebench_nitrobox \
    --force-build --delete --yes

# 3. Run with Docker (concurrency 20)
uv run harbor run \
    -p datasets/swebench \
    -e docker \
    -a oracle \
    -n 20 \
    --job-name swebench_docker \
    --force-build --delete --yes
```

Or via bench_harbor_e2e.py:

```bash
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    -p datasets/swebench \
    --agent oracle \
    --concurrency 20 \
    --envs docker,nitrobox
```
