import sqlite3
import os

DATABASE_NAME = 'transportar.db'  # Change this to your actual DB name (e.g., "app.db")


def get_connection():
    return sqlite3.connect(DATABASE_NAME)


def initialize_database():
    if not os.path.exists(DATABASE_NAME):
        with get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL
                );
            ''')
            conn.commit()
        print(f"Database created and initialized at '{DATABASE_NAME}'")
    else:
        print(f"Database '{DATABASE_NAME}' already exists.")


# Optional utility function to fetch user
def get_user_by_username(username):
    with get_connection() as conn:
        return conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


# Optional utility to insert a new user
def insert_user(username, hashed_password, email):
    with get_connection() as conn:
        conn.execute('INSERT INTO users(username, password, email) VALUES (?, ?, ?)', 
                     (username, hashed_password, email))
        conn.commit()
