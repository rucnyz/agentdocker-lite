# SWEBench Verified — Docker vs nitrobox

## Results

| Metric           | nitrobox           | Docker                   |
|------------------|--------------------|--------------------------|
| **Wall time**    | **1h 32m (5504s)** | 1h 55m (6927s)           |
| Trials completed | 500                | 500                      |
| Exceptions       | **0**              | 1 (VerifierTimeoutError) |
| Pass (1.0)       | **495**            | 491                      |
| Fail (0.0)       | 5                  | 8                        |
| Mean reward      | **0.990**          | 0.982                    |

### Per-phase mean timing (per trial)

| Phase             | Docker | nitrobox |
|-------------------|--------|----------|
| environment_setup | 7.7s   | 36.1s    |
| agent_execution   | 0.6s   | 20.4s    |
| verifier          | 31.7s  | 40.5s    |
| teardown          | 28.7s  | 45.6s    |

### Failed tasks (identical across both environments)

These 5 tasks fail on both Docker and nitrobox — upstream SWEBench issues:

- `astropy__astropy-7606`
- `astropy__astropy-8707`
- `astropy__astropy-8872`
- `django__django-10097`
- `matplotlib__matplotlib-20859`

## Reproduce

```bash
python examples/bench_harbor_e2e.py \
    --harbor-dir ../harbor \
    --dataset swebench-verified \
    --agent oracle \
    --concurrency 20 \
    --envs nitrobox,docker
# for debug
python examples/bench_harbor_e2e.py \
    --harbor-dir ../harbor \
    --dataset swebench-verified \
    --agent oracle \
    --n-tasks 20 --concurrency 10 \
    --envs nitrobox,docker
```

Or via harbor:

```bash
cd /path/to/harbor

# Run with nitrobox (concurrency 20)
uv run harbor run \
    -d swebench-verified \
    -e nitrobox \
    -a oracle \
    -n 20 \
    --job-name swebench_nitrobox \
    --force-build --delete --yes

# Run with Docker (concurrency 20)
uv run harbor run \
    -d swebench-verified \
    -e docker \
    -a oracle \
    -n 20 \
    --job-name swebench_docker \
    --force-build --delete --yes
```

`swebench-verified` is a registered dataset on the Harbor registry; the
first run auto-downloads its 500 tasks into `~/.cache/harbor/tasks/`.
