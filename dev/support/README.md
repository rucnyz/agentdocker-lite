# Harbor Dataset Compatibility

Tracking nitrobox compatibility with all Harbor-supported datasets.
Each dataset is tested with the `oracle` agent against the Docker
environment as baseline.

## Status

| Dataset | Version | Tasks | Status | Notes |
|---------|---------|-------|--------|-------|
| [terminal-bench](tb2.md) | 2.0 | 89 | **82/89 match** | 4 both-fail (task bugs), 3 differ (2 flaky, 1 fixed) |
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

Use `examples/bench_harbor_e2e.py` which handles pre-build cache warmup,
timed comparison, and per-task correctness checks:

```bash
# Full comparison (all tasks, concurrency 4, pre-build + timed)
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset <dataset>@<version> \
    --agent oracle \
    --n-tasks 999 --concurrency 4 \
    --envs docker,nitrobox \
    --output results.json

# Single dataset, skip pre-build if caches warm
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --n-tasks 999 --concurrency 4 \
    --envs docker,nitrobox \
    --skip-pre-build
```

The script outputs wall-clock speedup, setup overhead breakdown,
and per-task reward match/mismatch.

## Criteria

A dataset is "supported" when:
- Every task that passes with Docker also passes with nitrobox
- Any difference is documented with root cause
- Flaky tasks (pass sometimes, fail sometimes, on both environments) are acceptable
