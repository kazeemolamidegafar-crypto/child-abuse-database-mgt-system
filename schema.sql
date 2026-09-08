-- Computerized Child Abuse Database Management System
-- Database schema (SQLite)

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name       TEXT NOT NULL,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK(role IN ('administrator','caseworker','intake_officer')),
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS children (
    child_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    child_reference_code  TEXT NOT NULL UNIQUE,
    full_name             TEXT NOT NULL,
    date_of_birth         TEXT,
    guardian_contact      TEXT,
    address               TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cases (
    case_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    case_reference_number   TEXT NOT NULL UNIQUE,
    child_id                INTEGER NOT NULL REFERENCES children(child_id),
    category_of_concern     TEXT NOT NULL,
    date_reported           TEXT NOT NULL,
    reported_by_user_id     INTEGER NOT NULL REFERENCES users(user_id),
    assigned_caseworker_id  INTEGER REFERENCES users(user_id),
    status                  TEXT NOT NULL DEFAULT 'Reported'
                             CHECK(status IN ('Reported','Under Review','Referred','Under Investigation','Closed')),
    summary                 TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS referrals (
    referral_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           INTEGER NOT NULL REFERENCES cases(case_id),
    referred_to       TEXT NOT NULL,
    date_referred     TEXT NOT NULL,
    referral_status   TEXT NOT NULL DEFAULT 'Pending' CHECK(referral_status IN ('Pending','Acknowledged','Resolved')),
    outcome_notes     TEXT,
    created_by_user_id INTEGER NOT NULL REFERENCES users(user_id),
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS case_notes (
    note_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         INTEGER NOT NULL REFERENCES cases(case_id),
    author_user_id  INTEGER NOT NULL REFERENCES users(user_id),
    note_text       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(user_id),
    username        TEXT,
    action          TEXT NOT NULL,
    target_entity   TEXT,
    target_id       INTEGER,
    details         TEXT,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now'))
);
