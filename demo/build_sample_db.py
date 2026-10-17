"""Build demo/shop.db: a small, fully fictional online shop to point the server at.

Names, emails (example.com) and phone numbers (555-01xx) are generated and belong to nobody.
Same seed, same data, so demo output and evals are reproducible.

    uv run python demo/build_sample_db.py
"""

from __future__ import annotations

import random
import sqlite3
import sys
from datetime import date, timedelta
from pathlib import Path

DEFAULT_OUTPUT_PATH = Path(__file__).with_name("shop.db")

FIRST_NAMES = ["Ava", "Ben", "Chloe", "Dev", "Elif", "Farah", "Gus", "Hana", "Ivan", "Jade", "Kofi", "Lena", "Mateo", "Nia", "Omar", "Priya"]
LAST_NAMES = ["Adams", "Baker", "Chen", "Diaz", "Evans", "Fischer", "Garcia", "Haddad", "Ito", "Jones", "Khan", "Lopez", "Moreau", "Novak", "Okafor", "Patel"]
CITIES = ["Springfield", "Riverside", "Lakeview", "Hillcrest", "Fairview", "Oakridge"]
PRODUCTS = [
    ("Trail Backpack 30L", "Bags", 89.00),
    ("Daypack 18L", "Bags", 49.00),
    ("Dry Bag 10L", "Bags", 19.50),
    ("Two-Person Tent", "Camping", 229.00),
    ("Sleeping Bag -5C", "Camping", 139.00),
    ("Camping Stove", "Camping", 59.90),
    ("Headlamp 400lm", "Camping", 34.00),
    ("Water Filter", "Camping", 44.00),
    ("Rain Jacket", "Clothing", 119.00),
    ("Fleece Mid-Layer", "Clothing", 69.00),
    ("Merino Base Layer", "Clothing", 79.00),
    ("Hiking Socks (2-pack)", "Clothing", 24.00),
    ("Trail Runners", "Footwear", 129.00),
    ("Hiking Boots", "Footwear", 179.00),
    ("Camp Sandals", "Footwear", 39.00),
    ("Trekking Poles", "Gear", 74.00),
    ("Insulated Bottle 1L", "Gear", 29.00),
    ("First Aid Kit", "Gear", 27.50),
    ("Compass", "Gear", 18.00),
    ("Map Case", "Gear", 12.00),
]
ORDER_STATUSES = ["delivered"] * 7 + ["shipped", "processing", "cancelled", "returned"]

CUSTOMER_COUNT = 200
ORDER_COUNT = 1_000
FIRST_ORDER_DATE = date(2026, 1, 1)


def build(output_path: Path = DEFAULT_OUTPUT_PATH, seed: int = 7) -> Path:
    randomizer = random.Random(seed)
    output_path.unlink(missing_ok=True)
    connection = sqlite3.connect(output_path)
    connection.executescript(
        """
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            city TEXT NOT NULL,
            signed_up_on TEXT NOT NULL
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            unit_price NUMERIC NOT NULL
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER NOT NULL REFERENCES customers (id),
            status TEXT NOT NULL,
            ordered_on TEXT NOT NULL,
            total NUMERIC NOT NULL
        );
        CREATE TABLE order_items (
            order_id INTEGER NOT NULL REFERENCES orders (id),
            product_id INTEGER NOT NULL REFERENCES products (id),
            quantity INTEGER NOT NULL,
            unit_price NUMERIC NOT NULL,
            PRIMARY KEY (order_id, product_id)
        );
        CREATE INDEX orders_by_customer ON orders (customer_id);
        CREATE VIEW monthly_revenue AS
            SELECT substr(ordered_on, 1, 7) AS month, COUNT(*) AS orders, ROUND(SUM(total), 2) AS revenue
            FROM orders WHERE status NOT IN ('cancelled', 'returned') GROUP BY month;
        """
    )

    customers = []
    for customer_id in range(1, CUSTOMER_COUNT + 1):
        first_name = randomizer.choice(FIRST_NAMES)
        last_name = randomizer.choice(LAST_NAMES)
        has_phone = randomizer.random() > 0.15
        customers.append((
            customer_id,
            f"{first_name} {last_name}",
            f"{first_name}.{last_name}{customer_id}@example.com".lower(),
            f"+1-202-555-{customer_id % 100:02d}{randomizer.randint(0, 99):02d}" if has_phone else None,
            randomizer.choice(CITIES),
            (FIRST_ORDER_DATE - timedelta(days=randomizer.randint(0, 700))).isoformat(),
        ))
    connection.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?)", customers)
    connection.executemany(
        "INSERT INTO products VALUES (?, ?, ?, ?)",
        [(product_id, *product) for product_id, product in enumerate(PRODUCTS, start=1)],
    )

    for order_id in range(1, ORDER_COUNT + 1):
        product_ids = randomizer.sample(range(1, len(PRODUCTS) + 1), k=randomizer.randint(1, 4))
        order_items = [
            (order_id, product_id, randomizer.randint(1, 3), PRODUCTS[product_id - 1][2]) for product_id in product_ids
        ]
        order_total = round(sum(quantity * unit_price for _, _, quantity, unit_price in order_items), 2)
        connection.execute(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?)",
            (
                order_id,
                randomizer.randint(1, CUSTOMER_COUNT),
                randomizer.choice(ORDER_STATUSES),
                (FIRST_ORDER_DATE + timedelta(days=randomizer.randint(0, 270))).isoformat(),
                order_total,
            ),
        )
        connection.executemany("INSERT INTO order_items VALUES (?, ?, ?, ?)", order_items)

    connection.commit()
    connection.close()
    return output_path


if __name__ == "__main__":
    built_path = build(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT_PATH)
    print(f"Built {built_path} ({CUSTOMER_COUNT} customers, {len(PRODUCTS)} products, {ORDER_COUNT} orders)")
