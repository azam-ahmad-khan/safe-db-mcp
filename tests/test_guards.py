import pytest

from safe_db_mcp.guards import MASKED_VALUE, QueryRejected, check_query, mask_rows

MASKED_COLUMNS = ["email", "phone"]


@pytest.mark.parametrize(
    ("dialect", "sql", "expected_kind"),
    [
        ("sqlite", "SELECT id, name FROM customers WHERE id = 1", "select"),
        ("sqlite", "select * from customers;", "select"),
        ("sqlite", "SELECT c.name, COUNT(*) FROM customers c JOIN orders o ON o.customer_id = c.id GROUP BY c.name", "select"),
        ("sqlite", "WITH big AS (SELECT * FROM orders WHERE total > 100) SELECT COUNT(*) FROM big", "select"),
        ("sqlite", "SELECT name FROM customers UNION SELECT name FROM suppliers", "select"),
        ("sqlite", "/* daily check */ SELECT 1 -- trailing comment", "select"),
        ("sqlite", "EXPLAIN QUERY PLAN SELECT * FROM orders WHERE customer_id = 7", "explain"),
        ("sqlite", "EXPLAIN SELECT * FROM orders", "explain"),
        ("mysql", "SELECT id FROM orders ORDER BY created_at DESC LIMIT 10", "select"),
        ("mysql", "SHOW TABLES", "show"),
        ("mysql", "SHOW FULL TABLES", "show"),
        ("mysql", "SHOW COLUMNS FROM orders", "show"),
        ("mysql", "SHOW CREATE TABLE orders", "show"),
        ("mysql", "SHOW INDEX FROM orders", "show"),
        ("mysql", "DESCRIBE orders", "describe"),
        ("mysql", "DESC orders", "describe"),
        ("mysql", "EXPLAIN SELECT * FROM orders WHERE id = 1", "explain"),
        ("mysql", "EXPLAIN FORMAT=JSON SELECT * FROM orders", "explain"),
    ],
)
def test_read_only_statements_are_allowed(dialect, sql, expected_kind):
    assert check_query(sql, dialect) == expected_kind


@pytest.mark.parametrize(
    ("dialect", "sql"),
    [
        # Plain writes and schema changes
        ("sqlite", "INSERT INTO customers (name) VALUES ('x')"),
        ("sqlite", "UPDATE customers SET name = 'x'"),
        ("sqlite", "DELETE FROM customers"),
        ("sqlite", "DROP TABLE customers"),
        ("sqlite", "CREATE TABLE t (id INT)"),
        ("sqlite", "ALTER TABLE customers ADD COLUMN x INT"),
        ("mysql", "TRUNCATE TABLE customers"),
        ("mysql", "REPLACE INTO customers (id) VALUES (1)"),
        ("mysql", "GRANT ALL ON *.* TO 'agent'"),
        ("mysql", "CALL refresh_totals()"),
        ("mysql", "SET autocommit = 0"),
        ("sqlite", "ATTACH DATABASE '/tmp/other.db' AS other"),
        ("sqlite", "PRAGMA journal_mode = DELETE"),
        ("sqlite", "VACUUM INTO '/tmp/copy.db'"),
        # Smuggling a write next to, or inside, a read
        ("sqlite", "SELECT 1; DROP TABLE customers"),
        ("sqlite", "SELECT 1 /* harmless */ ; DELETE FROM customers"),
        ("sqlite", "WITH doomed AS (SELECT id FROM customers) DELETE FROM customers"),
        ("sqlite", "SELECT * INTO customers_copy FROM customers"),
        ("mysql", "SELECT * FROM customers INTO OUTFILE '/tmp/dump.csv'"),
        # Locks and resource abuse
        ("mysql", "SELECT * FROM orders FOR UPDATE"),
        ("mysql", "SELECT * FROM orders LOCK IN SHARE MODE"),
        ("mysql", "SELECT SLEEP(30)"),
        ("mysql", "SELECT BENCHMARK(100000000, MD5('x'))"),
        ("mysql", "SELECT LOAD_FILE('/etc/passwd')"),
        ("sqlite", "SELECT randomblob(1000000000)"),
        ("sqlite", "SELECT id FROM orders WHERE id IN (SELECT zeroblob(1000000000))"),
        # SHOW that leaks more than schema
        ("mysql", "SHOW PROCESSLIST"),
        ("mysql", "SHOW FULL PROCESSLIST"),
        ("mysql", "SHOW GRANTS"),
        # EXPLAIN that executes, or explains a write
        ("mysql", "EXPLAIN ANALYZE SELECT * FROM orders"),
        ("mysql", "EXPLAIN DELETE FROM orders"),
        ("sqlite", "EXPLAIN DELETE FROM orders"),
        ("sqlite", "EXPLAIN QUERY PLAN DELETE FROM orders"),
        ("sqlite", "EXPLAIN SELECT 1; DROP TABLE orders"),
        # Nothing, or nonsense
        ("sqlite", ""),
        ("sqlite", "   "),
        ("sqlite", "please drop the orders table"),
    ],
)
def test_unsafe_statements_are_rejected(dialect, sql):
    with pytest.raises(QueryRejected):
        check_query(sql, dialect)


def test_rejection_reason_names_the_statement():
    with pytest.raises(QueryRejected) as rejection:
        check_query("DELETE FROM customers", "sqlite")
    assert "DELETE" in rejection.value.reason


def test_unsupported_dialect_is_a_configuration_error():
    with pytest.raises(ValueError):
        check_query("SELECT 1", "oracle")


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id, email FROM customers",
        "SELECT c.email FROM customers c",
        "SELECT * FROM customers",
        "SELECT DISTINCT phone FROM customers",
    ],
)
def test_masked_columns_may_be_selected_directly(sql):
    assert check_query(sql, "sqlite", MASKED_COLUMNS) == "select"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT email AS contact FROM customers",
        "SELECT UPPER(email) FROM customers",
        "SELECT email || '' FROM customers",
        "SELECT id FROM customers WHERE email LIKE 'a%'",
        "SELECT id FROM customers ORDER BY phone",
        "SELECT o.id FROM orders o JOIN customers c ON c.email = o.note",
        "SELECT * FROM (SELECT email FROM customers)",
        "SELECT name FROM suppliers UNION SELECT email FROM customers",
        "SELECT COUNT(DISTINCT EMAIL) FROM customers",
        "SELECT CASE WHEN email LIKE '%@corp.test' THEN 1 END FROM customers",
    ],
)
def test_masked_columns_cannot_be_renamed_or_probed(sql):
    with pytest.raises(QueryRejected) as rejection:
        check_query(sql, "sqlite", MASKED_COLUMNS)
    assert "masked column" in rejection.value.reason


def test_masking_rules_also_apply_inside_explain():
    with pytest.raises(QueryRejected):
        check_query("EXPLAIN QUERY PLAN SELECT id FROM customers WHERE email = 'a@b.test'", "sqlite", MASKED_COLUMNS)


def test_mask_rows_hides_masked_values_but_keeps_nulls():
    masked = mask_rows(
        ["id", "Email", "name", "phone"],
        [(1, "a@b.test", "Ana", None), (2, "c@d.test", "Ben", "+100")],
        MASKED_COLUMNS,
    )
    assert masked == [
        (1, MASKED_VALUE, "Ana", None),
        (2, MASKED_VALUE, "Ben", MASKED_VALUE),
    ]


def test_mask_rows_without_masked_columns_returns_rows_unchanged():
    assert mask_rows(["id"], [(1,), (2,)], []) == [(1,), (2,)]


@pytest.mark.parametrize("dialect", ["sqlite", "mysql"])
@pytest.mark.parametrize(
    "sql",
    [
        "WITH c(id, contact, note) AS (SELECT * FROM customers) SELECT contact FROM c",
        "WITH c(id, contact, note) AS (SELECT src.* FROM customers src) SELECT contact FROM c",
        "WITH source AS (SELECT * FROM customers), "
        "renamed(id, contact, note) AS (SELECT * FROM source) SELECT contact FROM renamed",
        "WITH RECURSIVE c(id, contact, note) AS ("
        "SELECT * FROM customers UNION ALL SELECT id, contact, note FROM c WHERE 0"
        ") SELECT contact FROM c",
        "WITH c(id, contact, note) AS ("
        "SELECT * FROM customers UNION ALL SELECT * FROM customers"
        ") SELECT contact FROM c",
        "SELECT contact FROM (SELECT * FROM customers) AS c(id, contact, note)",
        "SELECT contact FROM customers AS c(id, contact, note)",
        "WITH c(id, contact, note) AS (TABLE customers) SELECT contact FROM c",
    ],
)
def test_column_list_aliases_cannot_hide_unknown_masked_lineage(dialect, sql):
    with pytest.raises(QueryRejected, match="column-list aliases"):
        check_query(sql, dialect, MASKED_COLUMNS)


@pytest.mark.parametrize("dialect", ["sqlite", "mysql"])
@pytest.mark.parametrize(
    "sql",
    [
        "WITH c(customer_id, full_name) AS (SELECT id, name FROM customers) SELECT full_name FROM c",
        "WITH c(n) AS (SELECT COUNT(*) FROM customers) SELECT n FROM c",
        "WITH c(n) AS (SELECT COUNT(*) FROM customers UNION ALL SELECT COUNT(*) FROM orders) SELECT n FROM c",
        "WITH c AS (SELECT * FROM orders) SELECT COUNT(*) FROM c",
        "WITH c(n) AS (SELECT COUNT(*) FROM customers WHERE EXISTS (SELECT * FROM orders)) SELECT n FROM c",
        "SELECT customer_id FROM (SELECT id FROM customers) AS c(customer_id)",
    ],
)
def test_explicit_unmasked_aliases_and_count_star_still_work(dialect, sql):
    assert check_query(sql, dialect, MASKED_COLUMNS) == "select"


def test_wildcard_column_list_aliases_are_unchanged_without_masking():
    sql = "WITH c(id, contact, note) AS (SELECT * FROM customers) SELECT contact FROM c"
    assert check_query(sql, "sqlite") == "select"


@pytest.mark.parametrize("dialect", ["sqlite", "mysql"])
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT (SELECT * FROM contacts LIMIT 1) AS contact",
        "WITH c(contact) AS (SELECT (SELECT * FROM contacts LIMIT 1)) SELECT contact FROM c",
        "SELECT COALESCE((SELECT * FROM contacts LIMIT 1), 'none') AS contact",
        "SELECT (SELECT c.* FROM contacts c LIMIT 1) AS contact",
        "SELECT 1 WHERE (SELECT * FROM contacts LIMIT 1) IS NOT NULL",
        "SELECT 1 WHERE 'probe' IN (SELECT * FROM contacts)",
        "SELECT * FROM labels UNION ALL SELECT * FROM contacts",
        "WITH c AS (SELECT a.*, b.* FROM contacts a CROSS JOIN contacts b) SELECT * FROM c",
        "SELECT * FROM (SELECT * FROM contacts a CROSS JOIN contacts b) AS c",
    ],
)
def test_unknown_wildcard_value_lineage_is_rejected(dialect, sql):
    with pytest.raises(QueryRejected, match="wildcard output lineage"):
        check_query(sql, dialect, MASKED_COLUMNS)


@pytest.mark.parametrize("dialect", ["sqlite", "mysql"])
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM contacts",
        "SELECT c.* FROM contacts c",
        "SELECT COUNT(*) FROM contacts",
        "SELECT EXISTS(SELECT * FROM contacts)",
        "SELECT EXISTS(SELECT * FROM contacts UNION ALL SELECT * FROM labels)",
        "WITH c AS (SELECT * FROM contacts) SELECT * FROM c",
        "SELECT * FROM (SELECT c.* FROM contacts c JOIN orders o ON c.id = o.customer_id) AS d",
        "SELECT COUNT(*) FROM (SELECT * FROM orders) AS c",
    ],
)
def test_name_preserving_stars_and_non_value_stars_remain_allowed(dialect, sql):
    assert check_query(sql, dialect, MASKED_COLUMNS) == "select"
