# Terminal-Bench 2.0

**Dataset:** `terminal-bench@2.0`
**Source:** https://github.com/laude-institute/terminal-bench-2
**Tasks:** 89
**Agent:** oracle
**Concurrency:** 4
**Date:** 2026-04-04

## Summary

|            | Nitrobox | Docker |
|------------|----------|--------|
| Pass       | 83       | 84     |
| Fail       | 5        | 5      |
| Error      | 1        | 0      |
| **Match**  | **86/89 (97%)** | — |

86 tasks produce identical results (82 both-pass + 4 both-fail).
3 tasks differ: 1 bug (fixed post-run), 2 flaky (random, not env-specific).

## Per-Task Comparison

### Both Pass (82 tasks)

adaptive-rejection-sampler, bn-fit-modify, break-filter-js-from-html,
build-cython-ext, build-pov-ray, caffe-cifar-10, chess-best-move,
circuit-fibsqrt, cobol-modernization, code-from-image, compile-compcert,
configure-git-webserver, constraints-scheduling, count-dataset-tokens,
crack-7z-hash, custom-memory-heap-crash, db-wal-recovery,
distribution-search, dna-assembly, dna-insert, extract-elf,
extract-moves-from-video, feal-differential-cryptanalysis,
feal-linear-cryptanalysis, filter-js-from-html,
financial-document-processor, fix-code-vulnerability, fix-git,
fix-ocaml-gc, gcode-to-text, git-multibranch,
gpt2-codegolf, headless-terminal, hf-model-inference,
install-windows-3.11, kv-store-grpc, large-scale-text-editing,
largest-eigenval, llm-inference-batching-scheduler,
log-summary-date-ranges, mailman, make-mips-interpreter,
mcmc-sampling-stan, merge-diff-arc-agi-task,
model-extraction-relu-logits, modernize-scientific-stack,
mteb-leaderboard, mteb-retrieve, multi-source-data-merger,
nginx-request-logging, openssl-selfsigned-cert, overfull-hbox,
password-recovery, path-tracing, path-tracing-reverse, polyglot-c-py,
polyglot-rust-c, portfolio-optimization, prove-plus-comm, pypi-server,
pytorch-model-cli, pytorch-model-recovery, qemu-startup, query-optimize,
raman-fitting, regex-chess, regex-log, reshard-c4-data, sam-cell-seg,
sanitize-git-repo, schemelike-metacircular-eval, sparql-university,
sqlite-db-truncate, sqlite-with-gcov, torch-pipeline-parallelism,
torch-tensor-parallelism, train-fasttext, tune-mjcf, video-processing,
vulnerable-secret, winning-avg-corewars, write-compressor

### Both Fail (4 tasks — task bugs, not environment)

| Task | Failure | Root Cause | Upstream Issue |
|------|---------|------------|----------------|
| `build-pmars` | pmars binary not built | Oracle solution fails to build from source | — |
| `make-doom-for-mips` | VM execution timeout | Insufficient resources (cpus=1, timeout=900s) | [terminal-bench-2#44](https://github.com/laude-institute/terminal-bench-2/issues/44) |
| `protein-assembly` | Constraint evaluation failed | Scientific computation result incorrect | — |
| `rstan-to-pystan` | MCMC estimation accuracy | Statistical estimation out of tolerance | — |

### Different Results (3 tasks)

| Task | Nitrobox | Docker | Root Cause | Status |
|------|----------|--------|------------|--------|
| `cancel-async-tasks` | 0 | 1 | Timing-sensitive async cancellation test. 1/6 subtests fails intermittently. | **Flaky** — passes on re-run |
| `qemu-alpine-ssh` | 1 | 0 | QEMU software emulation timing. Both environments are flaky — this run nitrobox won. | **Flaky** — random |
| `git-leak-recovery` | ERR | 1 | Image had duplicate diff-ids causing layer extraction to skip the last layer. | **Fixed** — [commit fc8e144](https://github.com/opensage-agent/nitrobox/commit/fc8e144) |

## Issues Found and Fixed During Testing

### 1. Duplicate diff-id layer extraction (fixed)

**Symptom:** `git-leak-recovery` fails with "Layer extraction incomplete: 1 layer(s) missing"

**Root cause:** `zip(diff_ids, layer_dirs)` misaligned when the image has
duplicate diff-ids (same layer at two positions). `diff_ids` has 6 items,
`layer_dirs` is deduplicated to 5, zip stops at 5 → last layer skipped.

**Fix:** Compute needed set from `layer_dirs` directly instead of zipping
with `diff_ids`. [fc8e144](https://github.com/opensage-agent/nitrobox/commit/fc8e144)

### 2. Seccomp blocking ptrace (fixed)

**Symptom:** `vulnerable-secret` fails with "Debugging detected! Access denied."

**Root cause:** The binary uses `ptrace(PTRACE_TRACEME)` for anti-debug
checks. Nitrobox's seccomp filter blocked ptrace; Docker's default seccomp
allows it.

**Fix:** Removed ptrace from seccomp blocklist to match Docker's default
profile. [0e26b75](https://github.com/opensage-agent/nitrobox/commit/0e26b75)

### 3. portfolio-optimization flaky benchmark (known, not fixed)

**Symptom:** C extension speedup (1.18x) barely misses 1.2x threshold.

**Root cause:** Wall-clock timing benchmark with razor-thin margin. Fails
intermittently on both Docker and nitrobox depending on system load.
Upstream PR open since 2026-02-25:
[terminal-bench-2#48](https://github.com/laude-institute/terminal-bench-2/pull/48)

**Not fixed:** This is a benchmark design issue, not a nitrobox issue.

## Reproduce

```bash
# Prerequisites
docker login   # required — 89 prebuilt images need Docker Hub access

# Full TB2 comparison
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    --concurrency 4 \
    --output tb2_results.json

# Re-test a specific task
python examples/bench_harbor_e2e.py \
    --harbor-dir /path/to/harbor \
    --dataset terminal-bench@2.0 \
    --agent oracle \
    -i <task-name>
```

## Notes

- Docker Hub rate limit (429) may cause errors when pulling prebuilt
  images. Use `--force-build` to build from Dockerfile instead, or
  pre-pull images with `docker pull`.
- `make-doom-for-mips` and `caffe-cifar-10` are known infeasible tasks
  under default resource constraints
  ([terminal-bench-2#44](https://github.com/laude-institute/terminal-bench-2/issues/44)).
- `mteb-retrieve` and `mteb-leaderboard` fail on both environments due
  to Python dependency version issues in the prebuilt Docker images.
