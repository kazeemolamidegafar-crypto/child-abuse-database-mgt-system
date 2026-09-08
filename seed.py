"""
seed.py
Initializes the database and creates demo accounts (one per role) plus a
couple of sample child/case records so the system can be explored
immediately after setup.

Run once:  python seed.py

IMPORTANT: these are demo credentials for local evaluation only. Change
every password (and remove the sample data) before any real use.
"""

import database
from werkzeug.security import generate_password_hash

DEMO_USERS = [
    ("System Administrator", "admin", "Admin@12345", "administrator"),
    ("Blessing Adeyemi", "caseworker1", "Case@12345", "caseworker"),
    ("Tunde Bakare", "intake1", "Intake@12345", "intake_officer"),
]


def run():
    database.init_db()
    conn = database.get_connection()

    for full_name, username, password, role in DEMO_USERS:
        existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            continue
        conn.execute(
            "INSERT INTO users (full_name, username, password_hash, role) VALUES (?, ?, ?, ?)",
            (full_name, username, generate_password_hash(password), role),
        )

    conn.commit()
    conn.close()

    print("Database ready.")
    print("Demo accounts (change these passwords before real use):")
    for full_name, username, password, role in DEMO_USERS:
        print(f"  {role:15s} | username: {username:12s} | password: {password}")


if __name__ == "__main__":
    run()
