import sqlite3

DATABASE = "database.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = get_db()
    with open("schema.sql", "r", encoding="utf-8") as f:
        db.executescript(f.read())
    db.commit()