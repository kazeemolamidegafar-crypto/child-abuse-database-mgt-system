"""
database.py
Thin SQLite access layer for the Computerized Child Abuse Database
Management System. Kept deliberately simple (no ORM) so the mapping
between the thesis database design and the running code stays obvious.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "child_protection.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create the database file and tables if they do not already exist."""
    conn = get_connection()
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def log_action(user_id, username, action, target_entity=None, target_id=None, details=None):
    """
    Write an append-only audit-trail entry. Called from every route that
    authenticates a user or creates/views/modifies a case, child, or
    referral record, per the audit-logging requirement in the design.
    """
    conn = get_connection()
    conn.execute(
        """INSERT INTO audit_logs (user_id, username, action, target_entity, target_id, details)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, username, action, target_entity, target_id, details),
    )
    conn.commit()
    conn.close()
