# Computerized Child Abuse Database Management System (Prototype)

A working implementation of the design in Chapter Three of the accompanying
thesis: role-based access control (Administrator / Caseworker / Intake
Officer), child + case record linkage, case lifecycle tracking, referral
tracking, an append-only audit trail, and anonymized statistical reporting.

Built with **Python + Flask + SQLite** so it runs immediately with nothing
to install beyond two small Python packages — good for demonstration,
grading, and further coursework, but read the security section below
before this ever touches a real case.

## 1. Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python seed.py                  # creates the database + demo accounts
python app.py                   # starts the server on http://127.0.0.1:5000
```

## 2. Demo accounts (created by seed.py)

| Role             | Username     | Password       |
|------------------|--------------|----------------|
| Administrator    | admin        | Admin@12345    |
| Caseworker       | caseworker1  | Case@12345     |
| Intake Officer   | intake1      | Intake@12345   |

**Change or remove these before anyone else can reach the app.** They exist
only so you can log in and see the three role-specific experiences without
manually creating accounts first.

## 3. Suggested walkthrough

1. Log in as `intake1` → search for a child (nothing will match yet) →
   register a new case. Note the generated case reference number.
2. Log in as `admin` → **Users** page confirms accounts; **Overview**
   shows the new case in "Reported" status; open **All Cases** → the case
   → assign it to `caseworker1`.
3. Log in as `caseworker1` → the case now appears under "My Assigned
   Cases" → open it, add a case note, move the status to "Under Review",
   then create a referral (status auto-advances to "Referred").
4. Log back in as `admin` → **Audit Log** shows every action from steps
   1–3, each tied to the acting username and a timestamp → **Reports**
   shows the same activity as anonymized counts only.
5. Try logging in as `intake1` and opening the case directly by URL after
   it's been assigned to `caseworker1` — you can view it (you registered
   it) but the edit controls (status/notes/referrals) are hidden, and if
   you try posting to those endpoints directly you'll get a logged 403.
   That's the role-based access control from Chapter Three actually being
   enforced server-side, not just hidden in the UI.

## 4. How this maps to the thesis design

| Thesis component (Ch. 3) | Where it lives in the code |
|---|---|
| Users / Roles entity | `schema.sql` → `users` table; `role` column constrained to the three roles |
| Authentication | `app.py` → `/login`, salted-hash verification via Werkzeug |
| Role-based authorization | `auth.py` → `login_required` / `role_required` decorators on every route |
| Child record + linkage | `schema.sql` → `children`, `cases.child_id` foreign key |
| Case lifecycle | `cases.status` + `/case/<id>/status` |
| Referral tracking | `referrals` table + `/case/<id>/referral*` |
| Audit trail | `audit_logs` table; `database.log_action()` called from every significant route |
| Anonymized reporting | `/admin/reports` — only `GROUP BY` aggregate queries, never raw rows |
| Field-level restriction | `case_detail.html` conditionally reveals identifying fields only to admin/assigned caseworker |

## 5. Before you touch a single real case

This is an academic prototype. Treat the following as a checklist, not
decoration, before it goes anywhere near an actual child's information:

- **Independent security review / penetration test.** Nobody should trust
  their own code's security by default, least of all a solo student
  project.
- **Real secret key.** `app.py` falls back to a placeholder
  `SECRET_KEY`. Set a strong, random `SECRET_KEY` environment variable in
  any real deployment — the placeholder is only there so the demo runs
  out of the box.
- **HTTPS everywhere.** Run this behind a reverse proxy (e.g., Nginx)
  terminating TLS. Session cookies and case data must never travel
  unencrypted.
- **Stronger authentication.** Add multi-factor authentication, password
  complexity/rotation policy, and account lockout after repeated failed
  attempts.
- **Production database.** Move from SQLite to PostgreSQL or MySQL with
  proper backup, replication, and encryption-at-rest — see the
  recommendation below.
- **Field-level encryption** for the most sensitive columns (child name,
  DOB, guardian contact, address, case summary, note text, referral
  outcome notes), not just transport encryption.
- **Legal/data-protection review** by qualified counsel for your specific
  jurisdiction's child-protection and data-protection statutes, including
  a formal data-retention and deletion policy.
- **Real data-retention and secure-deletion logic** — the prototype
  currently keeps everything indefinitely.
- **Automated encrypted backups and a tested disaster-recovery process.**

None of this is a criticism of the prototype's usefulness for a thesis —
it faithfully implements the access-control and audit architecture the
design called for. It's simply the gap between "demonstrates the concept
correctly" and "safe to use with a real child's data," and that gap is
wide by design in any responsible treatment of this domain.
