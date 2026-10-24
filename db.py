import os
import sqlite3
from flask import g

from clist_server_admin.sqlite import init_settings_table

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "survey.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS surveys (
            id          TEXT PRIMARY KEY,
            owner       TEXT NOT NULL,
            title       TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            is_open     INTEGER NOT NULL DEFAULT 1,
            created     TEXT NOT NULL DEFAULT (datetime('now')),
            updated     TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS questions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_id TEXT NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
            position  INTEGER NOT NULL,
            type      TEXT NOT NULL CHECK (type IN ('single', 'multiple', 'text')),
            prompt    TEXT NOT NULL,
            options   TEXT
        );

        CREATE TABLE IF NOT EXISTS responses (
            id        TEXT PRIMARY KEY,
            survey_id TEXT NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
            submitted TEXT NOT NULL DEFAULT (datetime('now')),
            ip_hash   TEXT
        );

        CREATE TABLE IF NOT EXISTS answers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id TEXT NOT NULL REFERENCES responses(id) ON DELETE CASCADE,
            question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
            value       TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_questions_survey ON questions(survey_id);
        CREATE INDEX IF NOT EXISTS idx_responses_survey ON responses(survey_id);
        CREATE INDEX IF NOT EXISTS idx_answers_response ON answers(response_id);
    """)
    # Migration: ip_hash didn't exist in the original responses table.
    existing_cols = {row[1] for row in db.execute("PRAGMA table_info(responses)")}
    if "ip_hash" not in existing_cols:
        db.execute("ALTER TABLE responses ADD COLUMN ip_hash TEXT")
    # One response per (survey, ip_hash); NULL ip_hash (e.g. IP unavailable)
    # is never deduplicated, since SQLite treats NULLs as distinct in a unique index.
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_responses_survey_iphash "
        "ON responses(survey_id, ip_hash) WHERE ip_hash IS NOT NULL"
    )
    init_settings_table(db)
    db.commit()
    db.close()
