# Contributing

Thanks for helping make agent execution safer.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pytest
```

## Contribution guidelines

- Keep the default policy conservative.
- Add tests for every new allow or deny rule.
- Prefer structured APIs over shell-string handling.
- Document user-visible behavior in `README.md` or `docs/`.

## Rule changes

If you add or relax a rule:

- explain the threat model
- add safe and unsafe test cases
- describe compatibility impact

## Pull requests

Please include:

- what changed
- why the change is safe
- how it was tested

