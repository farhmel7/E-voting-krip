import sqlite3


DB_NAME = "evoting.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(cursor, table_name, column_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()

    for column in columns:
        if column["name"] == column_name:
            return True

    return False


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS voters (
            voter_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            pin_hash TEXT,
            has_voted INTEGER DEFAULT 0,
            created_at TEXT,
            failed_login_count INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            block_index INTEGER PRIMARY KEY,
            voter_hash TEXT NOT NULL,
            encrypted_vote TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            data_hmac TEXT NOT NULL,
            hash TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tamper_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER NOT NULL,
            original_encrypted_vote TEXT NOT NULL,
            restored INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )
    """)

    if not column_exists(cursor, "voters", "pin_hash"):
        cursor.execute("ALTER TABLE voters ADD COLUMN pin_hash TEXT")

    if not column_exists(cursor, "voters", "failed_login_count"):
        cursor.execute("ALTER TABLE voters ADD COLUMN failed_login_count INTEGER DEFAULT 0")

    if not column_exists(cursor, "voters", "locked_until"):
        cursor.execute("ALTER TABLE voters ADD COLUMN locked_until REAL DEFAULT 0")

    conn.commit()
    conn.close()