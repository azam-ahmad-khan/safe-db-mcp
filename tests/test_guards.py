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
