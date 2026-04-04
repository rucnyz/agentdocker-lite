# Nitrobox E2E Benchmarks

## Prerequisites

```bash
# 1. Install nitrobox
pip install -e .

# 2. Install uidmap (rootless multi-UID mapping)
sudo apt-get install -y uidmap

# 3. Verify Docker is running
docker info

# 4. Clone harbor
git clone https://github.com/opensage-agent/harbor.git
cd harbor && uv sync --all-extras --dev
```

## Harbor E2E (`bench_harbor_e2e.py`)

Compares Docker vs nitrobox as harbor's execution environment.
Pre-builds all images before timing (via `harbor run -a nop`) so both
sides start from local cache.

```bash
# Docker vs nitrobox (40 tasks, concurrency 4)
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --n-tasks 40 --concurrency 4 \
    --envs docker,nitrobox

# Nitrobox only (skip pre-pull if caches are warm)
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --n-tasks 40 --concurrency 4 \
    --envs nitrobox --skip-pre-build

# Full concurrency sweep with results saved
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --n-tasks 100 --concurrency 1,4,8,16,32 \
    --envs docker,nitrobox \
    --output results.json

# With a real agent
ANTHROPIC_API_KEY=sk-ant-... python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent claude-code --model anthropic/claude-sonnet-4-6 \
    --n-tasks 100 --concurrency 1,4,8,16,32
```

## SWE-Bench (`bench_swebench.py`)

```bash
python examples/bench_swebench.py --help
```

## OSWorld Reset (`bench_osworld_reset.py`)

```bash
python examples/bench_osworld_reset.py --help
```

## Micro-benchmark (`benchmark.py`)

Measures individual sandbox operations (create, exec, reset, delete).

```bash
python examples/benchmark.py --help
```
