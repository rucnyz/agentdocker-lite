# Nitrobox Benchmarks

Track how nitrobox compares to Docker across real-world datasets, plus
stand-alone micro-benchmarks.

## Harbor dataset compatibility

Each dataset is run against Docker as baseline. A dataset is
**supported** when every task that passes on Docker also passes on
nitrobox.

| Dataset                                           | Version | Tasks | Status     | Notes                                |
|---------------------------------------------------|---------|-------|------------|--------------------------------------|
| [terminal-bench](results/tb2.md)                  | 2.0     | 89    | **match**  | 4 both-fail (task bugs)              |
| [swebench-verified](results/swebench_verified.md) | —       | 500   | **match**  | 5 upstream-broken tasks fail on both |
| swebenchpro                                       | —       | —     | Not tested |                                      |
| swesmith                                          | —       | —     | Not tested |                                      |
| swtbench                                          | —       | —     | Not tested |                                      |

## Prerequisites

```bash
# 1. Install nitrobox + system helpers
uv sync
nitrobox setup

# 2. Install uidmap (rootless multi-UID mapping)
sudo apt-get install -y uidmap

# 3. Clone + install harbor
git clone https://github.com/rucnyz/harbor.git
cd harbor && uv sync --all-extras --dev

# 4. (optional) docker login to avoid Docker Hub rate limits
docker login
```

## Harbor E2E (`bench_harbor_e2e.py`)

Compares Docker vs nitrobox as harbor's execution environment across
any dataset harbor supports (named `-d <dataset>@<version>` or local
`-p <path>`).

```bash
# Named dataset (auto-downloads to ~/.cache/harbor/tasks/)
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --n-tasks 40 --concurrency 4 \
    --envs docker,nitrobox

# Full concurrency sweep, results saved for plotting
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --n-tasks 100 --concurrency 1,4,8,16,32 \
    --envs docker,nitrobox \
    --output results.json

# With a real LLM agent
ANTHROPIC_API_KEY=sk-ant-... python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent claude-code --model anthropic/claude-sonnet-4-6 \
    --n-tasks 100 --concurrency 1,4,8,16,32
```

## Validating a new dataset

Two passes per dataset — first verifies correctness and collects cold
numbers, second measures the warm-cache steady state.

### 1. Correctness + performance (oracle, cold → warm)

```bash
# Cold: first run populates caches, --no-delete keeps them
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset <dataset>@<version> \
    --agent oracle --concurrency 4 \
    --envs docker,nitrobox --no-delete

# Warm: second run reuses caches, default --delete cleans up after
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset <dataset>@<version> \
    --agent oracle --concurrency 4 \
    --envs docker,nitrobox
```

### 2. Real agent (LLM overhead)

The `llm_inference` column shows API time; `overhead` is everything
else (sandbox + verifier + teardown).

```bash
ANTHROPIC_API_KEY=sk-ant-... python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset <dataset>@<version> \
    --agent terminus-2 \
    --model anthropic/claude-sonnet-4-6 \
    --n-tasks 3 --concurrency 1 \
    --envs docker,nitrobox
```

## Micro Benchmark

```bash

python examples/micro_benchmark.py --help            # Full per-op comparison (all backends)
```

## Clean state

```bash
# Kill any leftover sandboxes + remove orphan state dirs
nitrobox cleanup

# Harbor caches
rm -rf ~/.cache/harbor/tasks/
rm -rf /path/to/harbor/jobs/bench_*

# Docker images pulled for terminal-bench (alexgshaw/*)
docker images --format "{{.Repository}}:{{.Tag}}" | grep alexgshaw | xargs -r docker rmi -f
```
