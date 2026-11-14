# Changelog

## 0.2.0 (unreleased)

- Opt-in strict local result privacy via `SAFE_DB_PRIVACY_POLICY`: owner-approved reporting sources,
  typed public fields, complete private-cell redaction, bounded scans and fail-closed disclosure.
- Strict schema tools show policy metadata only; relationship tools are disabled in this mode.
- Metadata-only audit in all modes. SQL, literals, driver errors and arbitrary audit details are no longer recorded.
  Existing log files are not migrated or deleted. Tool/startup errors and parser diagnostics no longer echo inputs.
- Block masked-column escapes through positional aliases, scalar/wildcard subqueries and ambiguous star lineage.
- Preserve legacy query functionality when strict privacy is unset, with explicit protection-off labels.
- Add a fictional reporting-view policy, setup documentation and adversarial privacy tests.

This is result redaction with reviewed classifications, not general entity anonymisation, reversible tokenisation,
differential privacy or a whole-prompt security gateway. See `docs/privacy.md` for supported shapes and limits.
