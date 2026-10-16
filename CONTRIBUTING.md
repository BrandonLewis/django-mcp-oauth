# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

The suite runs on SQLite with the minimal settings in `tests/settings.py` and
needs no product. CI runs it across the Django and Authlib versions the
products that use this package pin (see `.github/workflows/ci.yml`), plus
pip-audit and gitleaks.

## Rules

- **No product imports.** The one product decision is `MCP_OAUTH_AUTHORIZE_USER`;
  anything else a product needs is a setting with a sensible default, not a
  branch in the code.
- **Migrations are additive and idempotent.** Adopters arrive with existing
  tables (see the README); a new migration must work on a database that
  already holds the data.
- **Every RFC behaviour has a test** that names the section it implements.
- Format with `black` and `ruff check` before pushing.

## Releasing

1. Bump `version` in `pyproject.toml` and add the changelog entry.
2. Push the tag `vX.Y.Z` (the workflow refuses a tag that does not equal the
   committed version), or run **Release** from the Actions tab on the branch
   to release: the run tags that commit itself.
3. `release.yml` tests, builds, publishes to PyPI through trusted publishing
   (configured on PyPI for this repository, workflow `release.yml`,
   environment `pypi`) and creates the GitHub release.

Security reports: see `SECURITY.md`.
