import sqlite3

# Name of your database files
user_database = 'user_database.db'
seller_database = 'seller_database.db'

def init_user_db():
    with sqlite3.connect(user_database) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL
            );
        ''')
        conn.commit()

def init_seller_db():
    with sqlite3.connect(seller_database) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sellers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL
            );
        ''')
        conn.commit()

# Initialize the databases by calling the functions
init_user_db()
init_seller_db()

print("Databases and 'users' & 'sellers' tables created successfully!")
