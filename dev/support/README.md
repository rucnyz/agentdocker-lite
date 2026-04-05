# Harbor Dataset Compatibility

Tracking nitrobox compatibility with all Harbor-supported datasets.
Each dataset is tested against Docker as baseline.

## Status

| Dataset | Version | Tasks | Status | Notes |
|---------|---------|-------|--------|-------|
| [terminal-bench](tb2.md) | 2.0 | 89 | **86/89 match** | 4 both-fail (task bugs), 3 differ (2 flaky, 1 fixed) |
| swebench | — | — | Not tested | |
| swebenchpro | — | — | Not tested | |
| swesmith | — | — | Not tested | |
| swtbench | — | — | Not tested | |
| aider_polyglot | — | — | Not tested | |
| autocodebench | — | — | Not tested | |
| compilebench | — | — | Not tested | |
| livecodebench | — | — | Not tested | |
| humanevalfix | — | — | Not tested | |
| evoeval | — | — | Not tested | |
| deveval | — | — | Not tested | |
| mlgym-bench | — | — | Not tested | |
| replicationbench | — | — | Not tested | |
| codepde | — | — | Not tested | |
| aime | — | — | Not tested | |
| gpqa-diamond | — | — | Not tested | |
| usaco | — | — | Not tested | |
| mmau | — | — | Not tested | |
| sldbench | — | — | Not tested | |

## Test Plan

For each dataset, run two benchmarks:

### 1. Correctness + performance (oracle, cold + warm)

Run twice: first = cold start (verifies correctness + cold timing),
second = warm start (measures cached performance). `--no-delete` on
the first run preserves caches for the second run.

```bash
# Cold start — correctness + cold timing, keeps caches
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset <dataset>@<version> \
    --agent oracle --concurrency 4 \
    --envs docker,nitrobox --no-delete

# Warm start — cached performance, cleans up after
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset <dataset>@<version> \
    --agent oracle --concurrency 4 \
    --envs docker,nitrobox
```

### 2. Real agent (LLM overhead)

Measures sandbox overhead vs LLM inference time. The `llm_inference`
field shows actual API call time; `overhead` is everything else.

```bash
ANTHROPIC_API_KEY=sk-ant-... python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset <dataset>@<version> \
    --agent terminus-2 \
    --model anthropic/claude-sonnet-4-6 \
    --n-tasks 3 --concurrency 1 \
    --envs docker,nitrobox
```

## Prerequisites

```bash
cd harbor && uv sync --all-extras --dev
pip install nitrobox
docker login   # required to avoid Docker Hub rate limits
```

## Clean State

```bash
# Nitrobox caches (may need docker for root-owned dirs)
docker run --rm -v /tmp:/tmp alpine rm -rf /tmp/nitrobox_$(id -u)
rm -rf ~/.cache/nitrobox/rootfs/

# Harbor caches
rm -rf ~/.cache/harbor/tasks/
rm -rf /path/to/harbor/jobs/bench_*

# Docker images
docker images --format "{{.Repository}}:{{.Tag}}" | grep alexgshaw | xargs -r docker rmi -f
```

## Criteria

A dataset is "supported" when:
- Every task that passes with Docker also passes with nitrobox
- Any difference is documented with root cause
- Flaky tasks (pass sometimes, fail sometimes, on both environments) are acceptable
