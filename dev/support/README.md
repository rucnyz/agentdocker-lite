# Harbor Dataset Compatibility

Tracking nitrobox compatibility with all Harbor-supported datasets.
Each dataset is tested with the `oracle` agent against the Docker
environment as baseline.

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

## How to Run

Use `examples/bench_harbor_e2e.py` — runs harbor with default settings
for each environment and compares results:

```bash
# Prerequisites
cd harbor && uv sync --all-extras --dev
pip install nitrobox
docker login   # required to avoid Docker Hub rate limits

# Full comparison (all tasks, concurrency 4)
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --concurrency 4

# Specific tasks only
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    -i vulnerable-secret -i portfolio-optimization

# Concurrency sweep
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --concurrency 1,4,8 \
    --output results.json
```

## Clean State (for reproducible benchmarks)

```bash
# Nitrobox caches (may need docker for root-owned dirs)
docker run --rm -v /tmp:/tmp alpine rm -rf /tmp/nitrobox_$(id -u)
rm -rf ~/.cache/nitrobox/rootfs/

# Harbor caches
rm -rf ~/.cache/harbor/tasks/
rm -rf /path/to/harbor/jobs/bench_*

# Docker images (optional — forces re-pull)
docker images --format "{{.Repository}}:{{.Tag}}" | grep alexgshaw | xargs -r docker rmi -f
```

## Criteria

A dataset is "supported" when:
- Every task that passes with Docker also passes with nitrobox
- Any difference is documented with root cause
- Flaky tasks (pass sometimes, fail sometimes, on both environments) are acceptable
