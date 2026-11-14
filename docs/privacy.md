# Strict local result privacy (schema v1)

This feature protects the server-to-agent result boundary. The database and local process see the original
values; the MCP client receives only policy-approved results or a fixed error code. No external LLM, detector,
telemetry service or reversible identity map is used. It does not protect a prompt that a user has already sent
to a cloud assistant, or control that assistant's other tools.

## Configure an owner-reviewed policy

Use database grants restricted to reporting views, a read-only account and the existing time/row limits.
Review the view definitions and classify each permitted output field. A trusted view is allowed to contain
precomputed aggregates and joins, but its output classifications must still be correct. Keep the policy
outside locations an untrusted agent can edit; it is loaded and frozen at server startup.

Example policy for a fictional `sales_report` view:

```json
{
  "schema_version": 1,
  "limits": {"max_cell_bytes": 16384, "max_result_bytes": 262144, "max_cells": 10000},
  "sources": {
    "sales_report": {
      "month": {"kind": "public_month", "nullable": false},
      "status": {"kind": "public_enum", "values": ["paid", "pending"], "nullable": false},
      "total": {"kind": "public_number", "min": 0, "max": 1000000, "nullable": false},
      "note": {"kind": "redact_cell", "nullable": true}
    }
  }
}
```

Add `SAFE_DB_PRIVACY_POLICY=/absolute/path/to/result-policy.json` to your existing MCP environment and restart.
Missing, malformed, oversized or ambiguous policies stop startup. An explicitly empty path also stops startup.
There is no policy-changing MCP tool. Files contain only classifications and approved public vocabulary, never
credentials, original private values or token mappings. Connection passwords continue to use the OS Keychain
or the existing environment path; this feature creates no new credential store.

The example in `demo/privacy-policy.json` matches only the generated fictional shop. Do not copy its
classifications into a production database without review. The server trusts the declared sources; it does
not certify that a source is a safe view, infer classifications or detect a changed view definition.

## Field rules

| Kind | Release rule |
| --- | --- |
| `redact_cell` | Replace every supported non-null value with `[REDACTED]`, including private free text and embedded instructions. |
| `public_number` | Only finite native integers/floats or exact Decimal values within mandatory inclusive numeric `min`/`max` bounds. Booleans and numeric-looking strings are blocked. Decimal values retain exact digits as JSON strings. Policy bounds must be finite and within ±10¹⁵. |
| `public_enum` | Only an exact member of the reviewed `values` array; 1–100 unique strings, each 1–64 ASCII letters, digits, spaces or `_./-`. |
| `public_month` | Only a string in `YYYY-MM` form with year 0001–9999 and month 01–12. |

Every field requires an explicit boolean `nullable`. Allowed NULLs remain NULL, including in redacted fields;
a forbidden NULL blocks the response. NULL presence and redaction counts therefore reveal limited metadata.
Binary/base64, JSON objects, arbitrary driver objects and date/time objects are blocked; expose an explicitly
reviewed scalar representation through a reporting view instead. Original private cells are never hashed,
persisted in a mapping or restored into the model-facing response.

A few fixed local credential-format checks override a mistaken public classification and redact the whole cell.
They are defense in depth, not a complete credential/PII detector. Unknown text never becomes public because a
detector found nothing. There are no user-supplied regexes, remote recognizers or optional detectors that can
silently fail open.

## Supported query shapes

Select explicit, unqualified, bare column names from **one exact policy source**. Names are matched exactly;
policy identifiers are ASCII letters/digits/underscore, start with a letter/underscore, and are at most 64 characters.
Case-ambiguous policy keys and duplicate result labels are rejected.

```sql
SELECT month, total, note FROM sales_report
WHERE status IN ('paid', 'pending') AND total >= 0
ORDER BY month DESC LIMIT 20 OFFSET 0
```

Public fields support comparisons to classified literals, `IS NULL`, `IN`, `BETWEEN`, `AND`, `OR`, parentheses
and `NOT`. Public fields can be ordered. Nonnegative integer LIMIT/OFFSET are supported (maximum 2147483647),
and the existing server row cap still applies. Configured legacy masked columns retain their additional
filter/sort restrictions and are also redacted.

Aliases, qualifications, wildcards, functions, arithmetic, casts, joins, CTEs, subqueries, set operations,
DISTINCT, GROUP BY, arbitrary schema statements and all private-field predicates/orderings are blocked.
This prevents a protected value being relabelled as public or inferred through filtering. Precompute useful
aggregates and joins in an approved view; strict v1 does not accept ad hoc aggregate templates.
SQL is parsed with a bounded syntax-tree budget and regenerated with comments removed before execution.

The schema tools read policy metadata only. They show approved sources and field classifications/nullability,
without querying database defaults, comments, samples or other schema names. Relationship tools are absent in
strict mode because their free-form notes and generated joins are outside this release policy.

## Release, errors and audit

The server buffers the capped result, verifies exact output labels/width, checks every field, and chooses
`allow`, `redact` or `block`. Any blocked value blocks the **entire** response; it never streams partially
checked rows. Responses include `privacy.mode`, schema version, fixed reasons, decision and redacted-cell count.
Database errors, parser failures and unexpected exceptions return fixed codes without driver text or SQL.

Budgets can be lowered, never increased beyond these v1 ceilings: 16 KiB per string cell, 256 KiB across candidate
string/scalar data and the serialized safe response, 10,000 cells, 64 columns per source, 64 sources, 16 KiB SQL,
2,048 parsed nodes and 32 nested predicate levels. The configured timeout covers the database and a final
release-time deadline check. This is not a hard preemption mechanism for Python or a guarantee on peak memory:
the database driver fetches before the result scan, so huge hostile cells still require database/process limits.

**All modes now use metadata-only audit.** New events include a random event ID, timestamp, tool, outcome,
fixed reason code, privacy mode, row/redaction counts, truncation and duration where available. Raw SQL,
literals, cells, identifiers, paths and driver errors are excluded by the typed audit interface. Strict mode
records the final disclosure decision after sanitization. If the audit write fails, no result is delivered.
The failed write itself cannot be guaranteed to leave an event. This local append log is not tamper-evident.

Parser/generator diagnostics are replaced with a fixed message because sqlglot can otherwise log query snippets.
Startup errors suppress local paths, configuration values and exception details. Do not enable third-party MCP
transport/request-body debug logging or external process dumps that independently capture private inputs.

## Migration and limits

Omitting `SAFE_DB_PRIVACY_POLICY` preserves legacy query functionality. Startup instructions/logs and base-tool
responses explicitly identify it as legacy with strict protection off. A configured policy failure never
reverts to legacy. Previously written audit files are **not** migrated or deleted; older raw SQL entries need
owner-managed retention review. Tool error text is now generic in both modes, and consumers must use fixed
codes rather than parse driver diagnostics. Audits no longer provide SQL replay.

Correct classification is essential. A number in range could still be an account identifier; a small group,
public enum, month or repeated query can reveal someone's identity through context. There is no query-history
privacy budget, differential privacy, k-anonymity, role-based multi-tenant policy, whole-prompt gateway,
general free-text entity anonymisation or compliance certification. This is a deliberately narrow redaction
boundary, inspired by public local-first privacy concepts, with no NodeShift private implementation used.

Tests exercise real SQLite and MCP results with fictional canaries, query bypass attempts, invalid public
values, schema metadata isolation, budgets, credential-pattern overrides, driver/parser errors and audit failure.
MySQL Decimal handling is tested using synthetic driver output; real MySQL integration requires the separate
throwaway-server tests documented in the README.
