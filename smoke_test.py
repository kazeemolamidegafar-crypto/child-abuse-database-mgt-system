"""
Quick end-to-end smoke test using Flask's test client (no real server
needed). Exercises: login for all 3 roles, case registration, assignment,
status update, note, referral, audit log visibility, anonymized report,
and a cross-role access-control check.
"""
import os

DB = os.path.join(os.path.dirname(__file__), "child_protection.db")
if os.path.exists(DB):
    os.remove(DB)

import database
database.init_db()
import seed
seed.run()

from app import app

client = app.test_client()

def login(username, password):
    r = client.post("/login", data={"username": username, "password": password},
                     follow_redirects=True)
    assert r.status_code == 200, r.status_code
    return r

def logout():
    client.get("/logout", follow_redirects=True)

print("1. Bad login is rejected...")
r = login("admin", "wrongpassword")
assert b"Invalid username or password" in r.data
logout()

print("2. Intake officer logs in and registers a case...")
login("intake1", "Intake@12345")
r = client.post("/intake/case/new", data={
    "existing_child_id": "",
    "child_full_name": "Test Child A",
    "child_dob": "2015-04-01",
    "guardian_contact": "0800-000-0000",
    "address": "Sample Address",
    "category_of_concern": "Neglect",
    "date_reported": "2026-08-01",
    "summary": "Synthetic test case for smoke testing only.",
}, follow_redirects=True)
assert b"registered successfully" in r.data
logout()

print("3. Admin logs in, sees the case, assigns it to caseworker1...")
login("admin", "Admin@12345")
conn = database.get_connection()
case_row = conn.execute("SELECT case_id FROM cases ORDER BY case_id DESC LIMIT 1").fetchone()
cw_row = conn.execute("SELECT user_id FROM users WHERE username='caseworker1'").fetchone()
conn.close()
case_id = case_row["case_id"]
r = client.post(f"/admin/case/{case_id}/assign", data={"caseworker_id": cw_row["user_id"]},
                 follow_redirects=True)
assert r.status_code == 200
logout()

print("4. Intake officer (not assigned) can view but NOT edit the case...")
login("intake1", "Intake@12345")
r = client.get(f"/case/{case_id}")
assert b"Update Status" not in r.data  # can_edit should be False
# attempt to directly POST a status update as an unauthorized role -> must be blocked
r2 = client.post(f"/case/{case_id}/status", data={"status": "Closed"})
assert r2.status_code == 403, f"expected 403, got {r2.status_code}"
logout()

print("5. Caseworker1 logs in, sees assigned case, updates status, adds note, creates referral...")
login("caseworker1", "Case@12345")
r = client.get("/caseworker")
assert b"Test Child A" in r.data

r = client.post(f"/case/{case_id}/status", data={"status": "Under Review"}, follow_redirects=True)
assert b"Case status updated" in r.data

r = client.post(f"/case/{case_id}/note", data={"note_text": "Initial contact made with school."},
                 follow_redirects=True)
assert b"Note added" in r.data

r = client.post(f"/case/{case_id}/referral",
                 data={"referred_to": "Medical Services", "date_referred": "2026-08-02"},
                 follow_redirects=True)
assert b"Referral recorded" in r.data
logout()

print("6. Admin reviews audit log and anonymized report...")
login("admin", "Admin@12345")
r = client.get("/admin/audit-log")
assert b"CREATE_CASE" in r.data and b"UPDATE_CASE_STATUS" in r.data and b"CREATE_REFERRAL" in r.data
r = client.get("/admin/reports")
assert r.status_code == 200
logout()

print("7. Unauthenticated access to a protected route redirects to login...")
r = client.get("/admin", follow_redirects=True)
assert b"Log In" in r.data or b"Log in" in r.data or b"username" in r.data

print("\nALL SMOKE TESTS PASSED.")
