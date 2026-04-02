# Contributing to nitrobox

## Development setup

```bash
git clone https://github.com/opensage-agent/nitrobox.git
cd nitrobox
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Running tests

Tests require Linux with user namespaces enabled. Some tests require root.

```bash
# Rootless tests (no sudo)
pytest tests/test_security.py -k UserNamespace
pytest tests/test_compose.py tests/test_cli.py

# Root tests
sudo pytest tests/test_sandbox.py tests/test_security.py -k "not UserNamespace"
sudo pytest tests/test_checkpoint.py
```

On Ubuntu 24.04+, enable unprivileged user namespaces first:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting. CI will check this automatically.

```bash
ruff check .
```

## Pull requests

1. Fork the repo and create a feature branch from `main`.
2. Make your changes with clear commit messages.
3. Ensure tests pass (`pytest tests/`).
4. Ensure linting passes (`ruff check .`).
5. Open a PR against `main` with a description of what changed and why.

## Reporting bugs

Open an issue on [GitHub Issues](https://github.com/opensage-agent/nitrobox/issues) with:
- OS and kernel version (`uname -r`)
- Python version
- Steps to reproduce
- Expected vs actual behavior

## Security vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
