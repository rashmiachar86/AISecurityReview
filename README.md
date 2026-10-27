# SDD-Security

Python development workspace.

## Layout

- `src/sdd_security/` – package source
- `tests/` – pytest tests
- `docs/` – documentation

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Common commands

```bash
pytest        # run tests
ruff check .  # lint
```
