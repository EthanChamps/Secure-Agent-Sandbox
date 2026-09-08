# Contributing

Run `uv sync --locked`, `uv run pytest -q`, and `uv run ruff check .` before submitting changes. Include the threat addressed and tests for any authorization change. Keep runtime and SMT policy semantics equivalent. New tools need explicit argument schemas, tenant/resource binding, effect scopes and bounded output handling.

Never introduce host execution of model-generated code, permissive runtime fallbacks, arbitrary string handoffs, or model-controlled approval flags. Infrastructure integrations require deployment tests and must document untested assumptions. Update uv.lock when dependency requirements change.
