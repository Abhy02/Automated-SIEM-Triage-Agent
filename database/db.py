import os
import sqlite3
import logging

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "aisoc.db")


def get_db():
    """
    Get SQLite database connection with Row factory.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initialize SQLite database schema automatically on startup.
    Creates users, roles, settings, audit_logs, organization, and reports tables if missing.
    Performs auto-migration for missing table columns.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'SOC Analyst',
        status TEXT NOT NULL DEFAULT 'Active',
        department TEXT DEFAULT 'SOC Operations',
        phone TEXT,
        login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Schema Migration Check for Users Table
    cursor.execute("PRAGMA table_info(users);")
    user_columns = [col["name"] for col in cursor.fetchall()]

    if "status" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'Active';")
    if "department" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN department TEXT DEFAULT 'SOC Operations';")
    if "phone" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT;")
    if "login_attempts" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0;")
    if "locked_until" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP;")
    if "last_login" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP;")

    # Roles Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT
    );
    """)

    # Organization Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS organization (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        company_name TEXT,
        timezone TEXT DEFAULT 'IST',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        role TEXT DEFAULT 'User',
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT DEFAULT '127.0.0.1',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Schema Migration Check for Audit Logs Table
    cursor.execute("PRAGMA table_info(audit_logs);")
    audit_columns = [col["name"] for col in cursor.fetchall()]

    if "role" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN role TEXT DEFAULT 'User';")
    if "ip_address" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN ip_address TEXT DEFAULT '127.0.0.1';")

    # Reports Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        doc_id TEXT PRIMARY KEY,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        summary TEXT,
        data TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()
    logger.info("SQLite enterprise database schema verified at %s", DB_PATH)
