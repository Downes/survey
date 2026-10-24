import csv
import hashlib
import io
import json
import os
import sqlite3
import uuid

from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory, g

from db import get_db, close_db, init_db
from auth import verify_identity, verify_admin_token, owns, my_owner_values, ALLOWED_KVSTORE_URLS_DEFAULT
from sanitize import sanitize_html, strip_tags
from clist_server_admin.sqlite import SettingField, init_settings_table, get_setting, register_admin_settings_routes

app = Flask(__name__)
app.teardown_appcontext(close_db)

BASE_URL = os.environ.get("BASE_URL", "https://survey.mooc.ca")
QUESTION_TYPES = {"single", "multiple", "text"}

SETTINGS_SCHEMA = [
    SettingField(
        key="ENABLED", label="Enabled", type="boolean", sensitive=False, validate=None,
        help="When off, this app's functional endpoints return 503. /admin/settings "
             "stays reachable so you can turn it back on.",
    ),
    SettingField(
        key="IP_HASH_SALT", label="IP Hash Salt", type="secret", sensitive=True, validate=None,
        help="Secret salt mixed into the one-hash-per-IP check that stops the same "
             "visitor from submitting a survey twice. Changing it resets that check "
             "(everyone can submit once more) but doesn't affect stored responses.",
    ),
    SettingField(
        key="ALLOWED_KVSTORE_URLS", label="Allowed KVStore URLs", type="text", sensitive=False, validate=None,
        help="Comma-separated kvstore instances trusted to vouch for an admin "
             "(ADMIN_USERNAMES) via /admin/settings. Does NOT restrict which "
             "kvstore instance a user can log in from for ordinary use — any "
             "kvstore instance's token is accepted and verified against its "
             "own signing key (open federation).",
    ),
]

SETTINGS_DEFAULTS = {
    "ENABLED": "true",
    "IP_HASH_SALT": os.environ.get("IP_HASH_SALT", ""),
    "ALLOWED_KVSTORE_URLS": ALLOWED_KVSTORE_URLS_DEFAULT,
}


@app.before_request
def _enabled_gate():
    if request.path == "/admin/settings":
        return None
    if get_setting(get_db(), "ENABLED", default="true") == "false":
        return jsonify({"error": "Service temporarily disabled by administrator"}), 503


# ---------------------------------------------------------------- helpers

def _validate_questions(questions):
    if not isinstance(questions, list) or not questions:
        return "questions must be a non-empty list"
    for q in questions:
        qtype = q.get("type")
        if qtype not in QUESTION_TYPES:
            return f"invalid question type: {qtype!r}"
        if not q.get("prompt"):
            return "each question needs a prompt"
        if qtype in ("single", "multiple"):
            opts = q.get("options")
            if not isinstance(opts, list) or len(opts) < 2:
                return "single/multiple questions need at least 2 options"
    return None


def _replace_questions(db, survey_id, questions):
    # Prompts/options may contain a limited, sanitized set of HTML tags (same
    # allowlist as CList's own editing screens, see sanitize.py) — sanitize
    # once here at storage time so every consumer (the public /s/{id} form,
    # the dashboard's results view) can trust the stored value is already safe.
    db.execute("DELETE FROM questions WHERE survey_id = ?", (survey_id,))
    for i, q in enumerate(questions):
        options = q.get("options") if q["type"] in ("single", "multiple") else None
        if options is not None:
            options = [sanitize_html(o) for o in options]
        db.execute(
            "INSERT INTO questions (survey_id, position, type, prompt, options) VALUES (?, ?, ?, ?, ?)",
            (survey_id, i, q["type"], sanitize_html(q["prompt"]), json.dumps(options) if options is not None else None),
        )


def _survey_dict(db, survey_id, include_owner=False):
    survey = db.execute("SELECT * FROM surveys WHERE id = ?", (survey_id,)).fetchone()
    if not survey:
        return None
    rows = db.execute(
        "SELECT id, position, type, prompt, options FROM questions WHERE survey_id = ? ORDER BY position",
        (survey_id,),
    ).fetchall()
    questions = [
        {
            "id": r["id"],
            "type": r["type"],
            "prompt": r["prompt"],
            "options": json.loads(r["options"]) if r["options"] else None,
        }
        for r in rows
    ]
    out = {
        "id": survey["id"],
        "title": survey["title"],
        "description": survey["description"],
        "is_open": bool(survey["is_open"]),
        "created": survey["created"],
        "updated": survey["updated"],
        "questions": questions,
        "url": f"{BASE_URL}/s/{survey_id}",
    }
    if include_owner:
        out["owner"] = survey["owner"]
    return out


def _client_ip():
    # Caddy is the only reverse proxy in front of this app (single hop), so its
    # X-Forwarded-For is trustworthy; it's a list if further proxies appended,
    # client IP is always the first entry.
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def _response_ip_hash(survey_id, ip):
    # One-per-person is a soft, unobtrusive limit (no cookies/login), not a
    # hard security boundary — salted so raw IPs aren't recoverable from the DB.
    salt = get_setting(get_db(), "IP_HASH_SALT", default=SETTINGS_DEFAULTS["IP_HASH_SALT"])
    if not ip or not salt:
        return None
    return hashlib.sha256(f"{salt}:{survey_id}:{ip}".encode()).hexdigest()


def _require_owner(db, survey_id, identity):
    row = db.execute("SELECT owner FROM surveys WHERE id = ?", (survey_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    if not owns(row["owner"], identity):
        return jsonify({"error": "Forbidden"}), 403
    return None


# ---------------------------------------------------------------- JSON API

@app.route("/api/surveys", methods=["POST"])
def create_survey():
    identity, err = verify_identity()
    if err:
        return jsonify(err[0]), err[1]
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title required"}), 400
    error = _validate_questions(data.get("questions"))
    if error:
        return jsonify({"error": error}), 400

    survey_id = uuid.uuid4().hex[:10]
    db = get_db()
    db.execute(
        "INSERT INTO surveys (id, owner, title, description) VALUES (?, ?, ?, ?)",
        (survey_id, identity.qualified_id, title, data.get("description", "")),
    )
    _replace_questions(db, survey_id, data["questions"])
    db.commit()
    return jsonify(_survey_dict(db, survey_id, include_owner=True)), 201


@app.route("/api/surveys", methods=["GET"])
def list_surveys():
    identity, err = verify_identity()
    if err:
        return jsonify(err[0]), err[1]
    db = get_db()
    owners = my_owner_values(identity)
    placeholders = ",".join("?" for _ in owners)
    rows = db.execute(
        f"SELECT id FROM surveys WHERE owner IN ({placeholders}) ORDER BY created DESC", owners
    ).fetchall()
    return jsonify([_survey_dict(db, r["id"]) for r in rows])


@app.route("/api/surveys/<survey_id>", methods=["GET"])
def get_survey(survey_id):
    identity, err = verify_identity()
    if err:
        return jsonify(err[0]), err[1]
    db = get_db()
    forbidden = _require_owner(db, survey_id, identity)
    if forbidden:
        return forbidden
    return jsonify(_survey_dict(db, survey_id, include_owner=True))


@app.route("/api/surveys/<survey_id>", methods=["PUT"])
def update_survey(survey_id):
    identity, err = verify_identity()
    if err:
        return jsonify(err[0]), err[1]
    db = get_db()
    forbidden = _require_owner(db, survey_id, identity)
    if forbidden:
        return forbidden
    data = request.get_json(silent=True) or {}
    fields, values = [], []
    if "title" in data:
        if not (data["title"] or "").strip():
            return jsonify({"error": "title cannot be empty"}), 400
        fields.append("title = ?")
        values.append(data["title"])
    if "description" in data:
        fields.append("description = ?")
        values.append(data["description"])
    if "is_open" in data:
        fields.append("is_open = ?")
        values.append(1 if data["is_open"] else 0)
    if "questions" in data:
        error = _validate_questions(data["questions"])
        if error:
            return jsonify({"error": error}), 400
        has_responses = db.execute(
            "SELECT 1 FROM responses WHERE survey_id = ? LIMIT 1", (survey_id,)
        ).fetchone()
        if has_responses:
            return jsonify({"error": "Cannot edit questions after responses have been collected; delete responses or create a new survey"}), 409
        _replace_questions(db, survey_id, data["questions"])
    if fields:
        fields.append("updated = datetime('now')")
        values.append(survey_id)
        db.execute(f"UPDATE surveys SET {', '.join(fields)} WHERE id = ?", values)
    db.commit()
    return jsonify(_survey_dict(db, survey_id, include_owner=True))


@app.route("/api/surveys/<survey_id>", methods=["DELETE"])
def delete_survey(survey_id):
    identity, err = verify_identity()
    if err:
        return jsonify(err[0]), err[1]
    db = get_db()
    forbidden = _require_owner(db, survey_id, identity)
    if forbidden:
        return forbidden
    db.execute("DELETE FROM surveys WHERE id = ?", (survey_id,))
    db.commit()
    return "", 204


@app.route("/api/surveys/<survey_id>/results", methods=["GET"])
def survey_results(survey_id):
    identity, err = verify_identity()
    if err:
        return jsonify(err[0]), err[1]
    db = get_db()
    forbidden = _require_owner(db, survey_id, identity)
    if forbidden:
        return forbidden

    questions = db.execute(
        "SELECT id, type, prompt, options FROM questions WHERE survey_id = ? ORDER BY position",
        (survey_id,),
    ).fetchall()
    total = db.execute(
        "SELECT COUNT(*) AS n FROM responses WHERE survey_id = ?", (survey_id,)
    ).fetchone()["n"]

    results = []
    for q in questions:
        answers = db.execute(
            "SELECT value FROM answers WHERE question_id = ?", (q["id"],)
        ).fetchall()
        if q["type"] == "text":
            results.append({
                "question_id": q["id"],
                "type": "text",
                "prompt": q["prompt"],
                "answers": [json.loads(a["value"]) for a in answers],
            })
        else:
            options = json.loads(q["options"])
            counts = {opt: 0 for opt in options}
            for a in answers:
                value = json.loads(a["value"])
                indices = value if isinstance(value, list) else [value]
                for i in indices:
                    if 0 <= i < len(options):
                        counts[options[i]] += 1
            results.append({
                "question_id": q["id"],
                "type": q["type"],
                "prompt": q["prompt"],
                "counts": counts,
            })

    return jsonify({"survey_id": survey_id, "total_responses": total, "questions": results})


@app.route("/api/surveys/<survey_id>/export.csv", methods=["GET"])
def export_csv(survey_id):
    identity, err = verify_identity()
    if err:
        return jsonify(err[0]), err[1]
    db = get_db()
    forbidden = _require_owner(db, survey_id, identity)
    if forbidden:
        return forbidden

    questions = db.execute(
        "SELECT id, type, prompt, options FROM questions WHERE survey_id = ? ORDER BY position",
        (survey_id,),
    ).fetchall()
    responses = db.execute(
        "SELECT id, submitted FROM responses WHERE survey_id = ? ORDER BY submitted",
        (survey_id,),
    ).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["response_id", "submitted"] + [strip_tags(q["prompt"]) for q in questions])

    for resp in responses:
        answers = {
            a["question_id"]: json.loads(a["value"])
            for a in db.execute(
                "SELECT question_id, value FROM answers WHERE response_id = ?", (resp["id"],)
            ).fetchall()
        }
        row = [resp["id"], resp["submitted"]]
        for q in questions:
            value = answers.get(q["id"])
            if value is None:
                row.append("")
            elif q["type"] == "text":
                row.append(value)
            else:
                options = json.loads(q["options"])
                indices = value if isinstance(value, list) else [value]
                row.append("; ".join(strip_tags(options[i]) for i in indices if 0 <= i < len(options)))
        writer.writerow(row)

    resp = app.response_class(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={survey_id}.csv"
    return resp


# ---------------------------------------------------------------- public HTML

@app.route("/s/<survey_id>", methods=["GET"])
def take_survey(survey_id):
    db = get_db()
    survey = _survey_dict(db, survey_id)
    if not survey:
        return render_template("message.html", heading="Not found", message="This survey doesn't exist."), 404
    if not survey["is_open"]:
        return render_template("message.html", heading="Closed", message="This survey is no longer accepting responses.")
    return render_template("survey_form.html", survey=survey)


@app.route("/s/<survey_id>", methods=["POST"])
def submit_response(survey_id):
    db = get_db()
    survey = _survey_dict(db, survey_id)
    if not survey:
        return render_template("message.html", heading="Not found", message="This survey doesn't exist."), 404
    if not survey["is_open"]:
        return render_template("message.html", heading="Closed", message="This survey is no longer accepting responses.")

    response_id = uuid.uuid4().hex
    ip_hash = _response_ip_hash(survey_id, _client_ip())
    try:
        db.execute(
            "INSERT INTO responses (id, survey_id, ip_hash) VALUES (?, ?, ?)",
            (response_id, survey_id, ip_hash),
        )
    except sqlite3.IntegrityError:
        # Already responded from this IP — say nothing and pretend it worked,
        # so a repeat submitter can't tell they were blocked.
        db.rollback()
        return render_template("message.html", heading="Thank you", message="Your response has been recorded.")
    for q in survey["questions"]:
        field = f"q{q['id']}"
        if q["type"] == "multiple":
            value = [int(i) for i in request.form.getlist(field)]
            if not value:
                continue
        elif q["type"] == "single":
            raw = request.form.get(field)
            if raw is None or raw == "":
                continue
            value = int(raw)
        else:
            raw = request.form.get(field, "").strip()
            if not raw:
                continue
            value = raw
        db.execute(
            "INSERT INTO answers (response_id, question_id, value) VALUES (?, ?, ?)",
            (response_id, q["id"], json.dumps(value)),
        )
    db.commit()
    return render_template("message.html", heading="Thank you", message="Your response has been recorded.")


# ---------------------------------------------------------------- dashboard

@app.route("/")
def dashboard():
    return send_from_directory(app.static_folder, "dashboard.html")


register_admin_settings_routes(app, SETTINGS_SCHEMA, get_db, verify_admin_token, SETTINGS_DEFAULTS)


if __name__ == "__main__":
    init_db()
    app.run()
