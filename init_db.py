import sqlite3

conn = sqlite3.connect('database.db')

# Products table
conn.execute('''CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    category TEXT,
    price_per_unit REAL,
    total_units INTEGER,
    image TEXT
)''')

# Orders table
conn.execute('''CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER,
    customer_name TEXT,
    quantity INTEGER,
    mobile TEXT,
    address TEXT,
    FOREIGN KEY(product_id) REFERENCES products(id)
)''')

# Transport Orders table
conn.execute('''CREATE TABLE IF NOT EXISTS transport_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_name TEXT,
    mobile TEXT,
    address TEXT,
    product_name TEXT,
    quantity INTEGER
)''')

conn.close()
