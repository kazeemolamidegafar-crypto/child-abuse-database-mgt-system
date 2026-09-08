"""
Computerized Child Abuse Database Management System
-----------------------------------------------------
A role-based, audit-logged case-management prototype implementing the
design from Chapter Three of the accompanying thesis:

    - Authentication + role-based authorization (administrator,
      caseworker, intake_officer)
    - Child record + linked case registration
    - Case lifecycle tracking (Reported -> Under Review -> Referred ->
      Under Investigation -> Closed)
    - Referral tracking
    - Case notes
    - Append-only audit trail on every significant action
    - Anonymized statistical reporting

IMPORTANT: This is a teaching/demonstration prototype, not a
production-ready system. See README.md, section "Before you touch a
single real case", before using it with any real names or real data.
"""

import os
import uuid
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

import database
from auth import login_required, role_required

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-secret-change-me")
app.permanent_session_lifetime = 1800  # 30 minutes idle timeout

CASE_STATUSES = ["Reported", "Under Review", "Referred", "Under Investigation", "Closed"]
REFERRAL_STATUSES = ["Pending", "Acknowledged", "Resolved"]
REFERRAL_TARGETS = ["Law Enforcement", "Medical Services", "Court / Legal Services",
                     "Psychosocial / Counselling Services", "Other Agency"]
CATEGORIES = ["Physical Abuse", "Emotional Abuse", "Neglect", "Sexual Abuse",
              "Exploitation", "Other Safeguarding Concern"]


# ---------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------

@app.before_request
def ensure_db():
    if not os.path.exists(database.DB_PATH):
        database.init_db()


# ---------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = database.get_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
        ).fetchone()
        conn.close()

        # Generic error message on purpose: does not reveal whether the
        # username or password was the problem (reduces the value of
        # credential-guessing attempts).
        if user is None or not check_password_hash(user["password_hash"], password):
            database.log_action(None, username, "LOGIN_FAILED", "users", None,
                                 "Invalid credentials")
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session.permanent = True
        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        session["full_name"] = user["full_name"]
        session["role"] = user["role"]

        database.log_action(user["user_id"], user["username"], "LOGIN_SUCCESS", "users",
                             user["user_id"])
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    database.log_action(session.get("user_id"), session.get("username"), "LOGOUT", "users",
                         session.get("user_id"))
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    role = session["role"]
    if role == "administrator":
        return redirect(url_for("admin_dashboard"))
    if role == "caseworker":
        return redirect(url_for("caseworker_dashboard"))
    if role == "intake_officer":
        return redirect(url_for("intake_dashboard"))
    abort(403)


# ---------------------------------------------------------------------
# Administrator: oversight, user management, audit trail, reporting
# ---------------------------------------------------------------------

@app.route("/admin")
@role_required("administrator")
def admin_dashboard():
    conn = database.get_connection()
    status_counts = conn.execute(
        "SELECT status, COUNT(*) AS n FROM cases GROUP BY status"
    ).fetchall()
    total_cases = conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"]
    total_children = conn.execute("SELECT COUNT(*) AS n FROM children").fetchone()["n"]
    recent_logs = conn.execute(
        "SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return render_template("admin_dashboard.html", status_counts=status_counts,
                            total_cases=total_cases, total_children=total_children,
                            recent_logs=recent_logs, statuses=CASE_STATUSES)


@app.route("/admin/users", methods=["GET", "POST"])
@role_required("administrator")
def manage_users():
    conn = database.get_connection()
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        if role not in ("administrator", "caseworker", "intake_officer"):
            flash("Invalid role selected.", "error")
        elif not (full_name and username and password):
            flash("All fields are required.", "error")
        else:
            try:
                conn.execute(
                    """INSERT INTO users (full_name, username, password_hash, role)
                       VALUES (?, ?, ?, ?)""",
                    (full_name, username, generate_password_hash(password), role),
                )
                conn.commit()
                new_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
                database.log_action(session["user_id"], session["username"], "CREATE_USER",
                                     "users", new_id, f"Created user '{username}' with role {role}")
                flash(f"User '{username}' created.", "success")
            except Exception as e:
                flash(f"Could not create user: {e}", "error")

    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("manage_users.html", users=users)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@role_required("administrator")
def toggle_user(user_id):
    conn = database.get_connection()
    user = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if user is None:
        abort(404)
    new_status = 0 if user["is_active"] else 1
    conn.execute("UPDATE users SET is_active = ? WHERE user_id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    action = "REACTIVATE_USER" if new_status else "DEACTIVATE_USER"
    database.log_action(session["user_id"], session["username"], action, "users", user_id)
    flash("User account updated.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/audit-log")
@role_required("administrator")
def audit_log():
    q_user = request.args.get("user", "").strip()
    q_from = request.args.get("from", "").strip()
    q_to = request.args.get("to", "").strip()

    sql = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    if q_user:
        sql += " AND username LIKE ?"
        params.append(f"%{q_user}%")
    if q_from:
        sql += " AND timestamp >= ?"
        params.append(q_from)
    if q_to:
        sql += " AND timestamp <= ?"
        params.append(q_to + " 23:59:59")
    sql += " ORDER BY log_id DESC LIMIT 500"

    conn = database.get_connection()
    logs = conn.execute(sql, params).fetchall()
    conn.close()

    database.log_action(session["user_id"], session["username"], "VIEW_AUDIT_LOG", "audit_logs")
    return render_template("audit_log.html", logs=logs, q_user=q_user, q_from=q_from, q_to=q_to)


@app.route("/admin/reports")
@role_required("administrator")
def reports():
    conn = database.get_connection()
    by_status = conn.execute("SELECT status, COUNT(*) AS n FROM cases GROUP BY status").fetchall()
    by_category = conn.execute(
        "SELECT category_of_concern, COUNT(*) AS n FROM cases GROUP BY category_of_concern"
    ).fetchall()
    by_month = conn.execute(
        """SELECT strftime('%Y-%m', date_reported) AS month, COUNT(*) AS n
           FROM cases GROUP BY month ORDER BY month"""
    ).fetchall()
    referral_outcomes = conn.execute(
        "SELECT referral_status, COUNT(*) AS n FROM referrals GROUP BY referral_status"
    ).fetchall()
    conn.close()

    database.log_action(session["user_id"], session["username"], "EXPORT_ANONYMIZED_REPORT",
                         "reports", None, "Viewed aggregate statistical report")
    return render_template("reports.html", by_status=by_status, by_category=by_category,
                            by_month=by_month, referral_outcomes=referral_outcomes)


@app.route("/admin/case/<int:case_id>/assign", methods=["POST"])
@role_required("administrator")
def assign_case(case_id):
    caseworker_id = request.form.get("caseworker_id")
    conn = database.get_connection()
    conn.execute(
        "UPDATE cases SET assigned_caseworker_id = ?, updated_at = datetime('now') WHERE case_id = ?",
        (caseworker_id, case_id),
    )
    conn.commit()
    conn.close()
    database.log_action(session["user_id"], session["username"], "ASSIGN_CASE", "cases",
                         case_id, f"Assigned to user_id {caseworker_id}")
    flash("Case assigned.", "success")
    return redirect(url_for("view_case", case_id=case_id))


# ---------------------------------------------------------------------
# Intake / Reporting Officer: search child, register new case
# ---------------------------------------------------------------------

@app.route("/intake")
@role_required("intake_officer", "administrator")
def intake_dashboard():
    conn = database.get_connection()
    my_cases = conn.execute(
        """SELECT c.*, ch.full_name AS child_name FROM cases c
           JOIN children ch ON ch.child_id = c.child_id
           WHERE c.reported_by_user_id = ? ORDER BY c.created_at DESC""",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("intake_dashboard.html", my_cases=my_cases, categories=CATEGORIES)


@app.route("/intake/search-child")
@role_required("intake_officer", "administrator")
def search_child():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        conn = database.get_connection()
        results = conn.execute(
            """SELECT child_id, child_reference_code, full_name, date_of_birth
               FROM children WHERE full_name LIKE ? OR child_reference_code LIKE ?
               LIMIT 20""",
            (f"%{q}%", f"%{q}%"),
        ).fetchall()
        conn.close()
        database.log_action(session["user_id"], session["username"], "SEARCH_CHILD",
                             "children", None, f"query='{q}'")
    return render_template("_search_results.html", results=results)


@app.route("/intake/case/new", methods=["POST"])
@role_required("intake_officer", "administrator")
def register_case():
    existing_child_id = request.form.get("existing_child_id", "").strip()
    category = request.form.get("category_of_concern", "")
    date_reported = request.form.get("date_reported") or datetime.utcnow().strftime("%Y-%m-%d")
    summary = request.form.get("summary", "").strip()

    conn = database.get_connection()

    if existing_child_id:
        child_id = int(existing_child_id)
        database.log_action(session["user_id"], session["username"], "LINK_EXISTING_CHILD",
                             "children", child_id)
    else:
        full_name = request.form.get("child_full_name", "").strip()
        dob = request.form.get("child_dob", "").strip()
        guardian_contact = request.form.get("guardian_contact", "").strip()
        address = request.form.get("address", "").strip()

        if not full_name:
            flash("Child full name is required when no existing record is selected.", "error")
            conn.close()
            return redirect(url_for("intake_dashboard"))

        ref_code = "CH-" + uuid.uuid4().hex[:8].upper()
        conn.execute(
            """INSERT INTO children (child_reference_code, full_name, date_of_birth,
                                      guardian_contact, address)
               VALUES (?, ?, ?, ?, ?)""",
            (ref_code, full_name, dob, guardian_contact, address),
        )
        conn.commit()
        child_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        database.log_action(session["user_id"], session["username"], "CREATE_CHILD_RECORD",
                             "children", child_id, f"reference={ref_code}")

    if not category:
        flash("Category of concern is required.", "error")
        conn.close()
        return redirect(url_for("intake_dashboard"))

    case_ref = "CASE-" + uuid.uuid4().hex[:8].upper()
    conn.execute(
        """INSERT INTO cases (case_reference_number, child_id, category_of_concern,
                               date_reported, reported_by_user_id, status, summary)
           VALUES (?, ?, ?, ?, ?, 'Reported', ?)""",
        (case_ref, child_id, category, date_reported, session["user_id"], summary),
    )
    conn.commit()
    case_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()

    database.log_action(session["user_id"], session["username"], "CREATE_CASE", "cases",
                         case_id, f"reference={case_ref}, category={category}")
    flash(f"Case {case_ref} registered successfully.", "success")
    return redirect(url_for("intake_dashboard"))


# ---------------------------------------------------------------------
# Caseworker: assigned caseload, status, notes, referrals
# ---------------------------------------------------------------------

@app.route("/caseworker")
@role_required("caseworker", "administrator")
def caseworker_dashboard():
    conn = database.get_connection()
    if session["role"] == "administrator":
        cases = conn.execute(
            """SELECT c.*, ch.full_name AS child_name FROM cases c
               JOIN children ch ON ch.child_id = c.child_id
               ORDER BY c.updated_at DESC"""
        ).fetchall()
    else:
        cases = conn.execute(
            """SELECT c.*, ch.full_name AS child_name FROM cases c
               JOIN children ch ON ch.child_id = c.child_id
               WHERE c.assigned_caseworker_id = ?
               ORDER BY c.updated_at DESC""",
            (session["user_id"],),
        ).fetchall()
    conn.close()
    return render_template("caseworker_dashboard.html", cases=cases)


def _get_case_or_403(conn, case_id):
    """Fetch a case, enforcing the role-based visibility rule:
       administrator -> any case
       caseworker    -> only if assigned to them
       intake_officer -> only if they registered it (view only)
    """
    case = conn.execute(
        """SELECT c.*, ch.full_name AS child_name, ch.child_reference_code,
                  ch.date_of_birth, ch.guardian_contact, ch.address
           FROM cases c JOIN children ch ON ch.child_id = c.child_id
           WHERE c.case_id = ?""",
        (case_id,),
    ).fetchone()
    if case is None:
        abort(404)

    role = session["role"]
    if role == "administrator":
        return case
    if role == "caseworker" and case["assigned_caseworker_id"] == session["user_id"]:
        return case
    if role == "intake_officer" and case["reported_by_user_id"] == session["user_id"]:
        return case
    abort(403)


@app.route("/case/<int:case_id>")
@login_required
def view_case(case_id):
    conn = database.get_connection()
    case = _get_case_or_403(conn, case_id)

    notes = conn.execute(
        """SELECT n.*, u.full_name AS author_name FROM case_notes n
           JOIN users u ON u.user_id = n.author_user_id
           WHERE n.case_id = ? ORDER BY n.created_at DESC""",
        (case_id,),
    ).fetchall()
    referrals = conn.execute(
        "SELECT * FROM referrals WHERE case_id = ? ORDER BY created_at DESC", (case_id,)
    ).fetchall()
    caseworkers = conn.execute(
        "SELECT user_id, full_name FROM users WHERE role = 'caseworker' AND is_active = 1"
    ).fetchall()
    conn.close()

    database.log_action(session["user_id"], session["username"], "VIEW_CASE", "cases", case_id)

    can_edit = session["role"] in ("administrator", "caseworker") and \
        (session["role"] == "administrator" or case["assigned_caseworker_id"] == session["user_id"])

    return render_template("case_detail.html", case=case, notes=notes, referrals=referrals,
                            caseworkers=caseworkers, statuses=CASE_STATUSES,
                            referral_targets=REFERRAL_TARGETS, can_edit=can_edit)


@app.route("/case/<int:case_id>/status", methods=["POST"])
@role_required("caseworker", "administrator")
def update_status(case_id):
    conn = database.get_connection()
    case = _get_case_or_403(conn, case_id)
    if session["role"] == "caseworker" and case["assigned_caseworker_id"] != session["user_id"]:
        abort(403)

    new_status = request.form.get("status")
    if new_status not in CASE_STATUSES:
        flash("Invalid status.", "error")
        conn.close()
        return redirect(url_for("view_case", case_id=case_id))

    old_status = case["status"]
    conn.execute(
        "UPDATE cases SET status = ?, updated_at = datetime('now') WHERE case_id = ?",
        (new_status, case_id),
    )
    conn.commit()
    conn.close()

    database.log_action(session["user_id"], session["username"], "UPDATE_CASE_STATUS", "cases",
                         case_id, f"{old_status} -> {new_status}")
    flash("Case status updated.", "success")
    return redirect(url_for("view_case", case_id=case_id))


@app.route("/case/<int:case_id>/note", methods=["POST"])
@role_required("caseworker", "administrator")
def add_note(case_id):
    conn = database.get_connection()
    case = _get_case_or_403(conn, case_id)
    if session["role"] == "caseworker" and case["assigned_caseworker_id"] != session["user_id"]:
        abort(403)

    note_text = request.form.get("note_text", "").strip()
    if note_text:
        conn.execute(
            "INSERT INTO case_notes (case_id, author_user_id, note_text) VALUES (?, ?, ?)",
            (case_id, session["user_id"], note_text),
        )
        conn.commit()
        note_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        database.log_action(session["user_id"], session["username"], "ADD_CASE_NOTE",
                             "case_notes", note_id, f"case_id={case_id}")
        flash("Note added.", "success")
    conn.close()
    return redirect(url_for("view_case", case_id=case_id))


@app.route("/case/<int:case_id>/referral", methods=["POST"])
@role_required("caseworker", "administrator")
def add_referral(case_id):
    conn = database.get_connection()
    case = _get_case_or_403(conn, case_id)
    if session["role"] == "caseworker" and case["assigned_caseworker_id"] != session["user_id"]:
        abort(403)

    referred_to = request.form.get("referred_to")
    date_referred = request.form.get("date_referred") or datetime.utcnow().strftime("%Y-%m-%d")

    if referred_to not in REFERRAL_TARGETS:
        flash("Invalid referral target.", "error")
        conn.close()
        return redirect(url_for("view_case", case_id=case_id))

    conn.execute(
        """INSERT INTO referrals (case_id, referred_to, date_referred, referral_status,
                                   created_by_user_id)
           VALUES (?, ?, ?, 'Pending', ?)""",
        (case_id, referred_to, date_referred, session["user_id"]),
    )
    conn.execute(
        "UPDATE cases SET status = 'Referred', updated_at = datetime('now') WHERE case_id = ?",
        (case_id,),
    )
    conn.commit()
    referral_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()

    database.log_action(session["user_id"], session["username"], "CREATE_REFERRAL", "referrals",
                         referral_id, f"case_id={case_id}, referred_to={referred_to}")
    flash("Referral recorded and case status updated.", "success")
    return redirect(url_for("view_case", case_id=case_id))


@app.route("/case/<int:case_id>/referral/<int:referral_id>/status", methods=["POST"])
@role_required("caseworker", "administrator")
def update_referral_status(case_id, referral_id):
    conn = database.get_connection()
    case = _get_case_or_403(conn, case_id)
    if session["role"] == "caseworker" and case["assigned_caseworker_id"] != session["user_id"]:
        abort(403)

    new_status = request.form.get("referral_status")
    outcome_notes = request.form.get("outcome_notes", "").strip()
    if new_status not in REFERRAL_STATUSES:
        flash("Invalid referral status.", "error")
        conn.close()
        return redirect(url_for("view_case", case_id=case_id))

    conn.execute(
        "UPDATE referrals SET referral_status = ?, outcome_notes = ? WHERE referral_id = ?",
        (new_status, outcome_notes, referral_id),
    )
    conn.commit()
    conn.close()

    database.log_action(session["user_id"], session["username"], "UPDATE_REFERRAL_STATUS",
                         "referrals", referral_id, f"status={new_status}")
    flash("Referral updated.", "success")
    return redirect(url_for("view_case", case_id=case_id))


# ---------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    if "user_id" in session:
        database.log_action(session.get("user_id"), session.get("username"),
                             "ACCESS_DENIED", None, None, request.path)
    return render_template("error.html", code=403,
                            message="You do not have permission to access this resource."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="The requested page was not found."), 404


if __name__ == "__main__":
    if not os.path.exists(database.DB_PATH):
        database.init_db()
        print("Database initialized at", database.DB_PATH)
        print("Run seed.py to create the demo accounts before logging in.")
    app.run(debug=True, host="127.0.0.1", port=5000)
