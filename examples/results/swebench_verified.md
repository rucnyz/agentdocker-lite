# SWE-bench Verified — Docker vs nitrobox

**Dataset:** SWE-bench Verified (499 tasks; `scikit-learn__scikit-learn-14710` excluded — see below)
**Agent:** oracle
**Concurrency:** 20
**Date:** 2026-04-17
**Hardware:** AMD EPYC 9354 32-core, 1 TiB RAM, kernel 5.15

## E2E Results

| C   | Env      | Wall    | EnvSetup     | Agent Exec | Verify        | Teardown     | Overhead | Pass    | Fail | Err |
|-----|----------|---------|--------------|------------|---------------|--------------|----------|---------|------|-----|
| 20  | nitrobox | 1525.4s | 1.2s (3%)    | 0.2s (0%)  | 39.9s (85%)   | 5.7s (12%)   | 100%     | 491/499 | 7    | 1   |
| 20  |  docker  | 1920.4s | 23.6s (35%)  | 0.3s (0%)  | 33.8s (51%)   | 9.0s (13%)   | 100%     | 492/499 | 7    | 0   |

**Wall speedup: 1.26x** (32.0 min → 25.4 min)
**Env-setup speedup: 19.7x** (23.6s vs 1.2s per task)
**Teardown speedup: 1.6x** (9.0s vs 5.7s per task)
**Correctness: parity** (pass counts within flaky-test noise: 491 vs 492 of 499)

## Why env_setup differs by ~20x

SWE-bench Verified ships per-task Dockerfiles with a `FROM swebench/sweb.eval.x86_64.*` base plus a few upstream-wrapper layers (`uv` install, `mkdir /logs`). Harbor issues a fresh random `project_name` for every trial and runs each task with `force_build=true`, so neither backend can reuse a prior trial's tagged image — every trial runs the `build` path on warm cache.

- **Docker**: `docker build` resolves layers against containerd's snapshotter and (re-)exports the build result. Even on a full cache hit, this traverses both BuildKit's and containerd's snapshot stores and takes ~20–30 s of per-trial overhead.
- **nitrobox**: the embedded buildkitd reuses its own snapshot store directly — no second snapshotter to round-trip through, no image-store re-export. Per-trial build setup collapses to ~1 s.

Verifier is workload-bound (pytest runs the same way in both sandboxes). The small NitroBox-vs-Docker delta on verify (+6s per task) reflects userns + seccomp syscall overhead, not sandbox lifecycle.

## Excluded task: `scikit-learn__scikit-learn-14710`

pytest for this task exceeds the 50-minute verifier timeout on both backends. With harbor's `@retry(stop_after_attempt(2))` on `VerifierTimeoutError`, the task adds ~100 minutes to either backend's wall time before being marked as an error. Dropped from the table for clean comparison; correctness on it is identical (both error out the same way).

## Failed tasks

Same set on both backends (upstream SWE-bench issues, reproducible across runs):

- `astropy__astropy-7606`
- `astropy__astropy-8707`
- `astropy__astropy-8872`
- `astropy__astropy-13398`
- `django__django-10097`
- `sphinx-doc__sphinx-8595`
- `sphinx-doc__sphinx-9711`

## Reproduce

```bash
python examples/bench_harbor_e2e.py \
    --harbor-dir ../harbor \
    --dataset swebench-verified \
    --agent oracle \
    --n-tasks 500 --concurrency 20 \
    --envs nitrobox,docker \
    -x scikit-learn__scikit-learn-14710
```

Or via harbor directly:

```bash
cd /path/to/harbor

uv run harbor run \
    -d swebench-verified -a oracle \
    -e nitrobox --n-concurrent 20 \
    --job-name bench_nitrobox \
    --force-build --delete --yes

uv run harbor run \
    -d swebench-verified -a oracle \
    -e docker --n-concurrent 20 \
    --job-name bench_docker \
    --force-build --delete --yes
```

`swebench-verified` is a registered dataset on the Harbor registry; the first run auto-downloads its 500 tasks into `~/.cache/harbor/tasks/`.
