# survey (/srv/apps/survey)

## Overview
Flask app for creating and running simple surveys. Any kvstore user can create
a survey; anyone with the link can respond anonymously (no account needed).
Built-in HTML dashboard for creating surveys and viewing results; a plain
server-rendered HTML form is what respondents fill out.

## Container
- Name: `survey`  Port: 8085 (internal only)
- Domain: survey.mooc.ca — not yet wired into Caddy (see BUILDPLAN below)

## Database
- SQLite at `/data/survey.db` (Docker volume `survey_data`)
- Tables: `surveys (id, owner, title, description, is_open, created, updated)`,
  `questions (id, survey_id, position, type, prompt, options)`,
  `responses (id, survey_id, submitted)`, `answers (id, response_id, question_id, value)`
- `options` is a JSON array of strings, null for text questions.
- `value` on `answers` is JSON: an int index for `single`, a list of int indices
  for `multiple`, a string for `text`.
- Initialised automatically on startup via `init_db()` in `db.py`.

## Auth
- Survey management (create/list/update/delete/results/export) requires
  `Authorization: Bearer <token>`, verified via `GET https://kvstore.mooc.ca/auth/verify`.
- Owner enforcement: only the token holder who created a survey can manage it.
- The CSV export endpoint also accepts the token as `?token=` (query param),
  since a plain `<a href>` download link can't set an Authorization header.
- Taking a survey (`GET`/`POST /s/{id}`) requires no auth — anonymous by design.

## Question types (v1)
`single` (radio), `multiple` (checkboxes), `text` (free text). See `QUESTION_TYPES`
in `app.py`.

## HTML in question prompts/options
Question prompts and single/multiple option text may contain a limited,
sanitized set of HTML tags (bold, italic, links, lists, headings, etc.) — the
same allowlist CList's own editing screens use for rich content
(`_rssSanitizeHtml` in `clist.mooc.ca/js/rss.js`), reimplemented server-side
in `sanitize.py` since it has to run before storage (the public `/s/{id}`
form is rendered anonymously — sanitizing only in the browser wouldn't help).
`_replace_questions()` in `app.py` sanitizes on every create/update, so the
DB always holds already-safe HTML; `survey_form.html` renders it with
`|safe`, and the dashboard's results view intentionally uses `innerHTML` for
the same reason. Free-text (`type: "text"`) answers are respondent-submitted
and are **not** sanitized or rendered as HTML anywhere — they stay
plain/escaped text. Survey title/description are also unaffected — still
plain escaped text.
Allowed tags/attributes are hardcoded in `sanitize.py` to match `rss.js`
exactly; if that allowlist changes in CList, update both.

## One response per person
`submit_response()` hashes the submitter's IP (salted with `IP_HASH_SALT` from
`.env`) together with the survey id, and stores it on `responses.ip_hash`. A
partial unique index (`idx_responses_survey_iphash`, `WHERE ip_hash IS NOT
NULL`) rejects a second insert for the same survey+IP; on that IntegrityError
the app silently renders the normal "Thank you" page without recording
anything, so a repeat submitter can't tell they were blocked. No cookies,
accounts, or client-side state involved — this is an unobtrusive, best-effort
limit (shared IPs/VPNs can still submit more than once), not a security
boundary. Client IP is read from Caddy's `X-Forwarded-For` (trusted since
Caddy is the only reverse proxy in front of this app). `db.py`'s `init_db()`
migrates older `responses` rows (adds `ip_hash` if missing) on every startup.

## Endpoints
| Method | Path                              | Auth        | Description                          |
|--------|-----------------------------------|-------------|---------------------------------------|
| POST   | /api/surveys                      | Bearer      | Create survey                        |
| GET    | /api/surveys                      | Bearer      | List my surveys                      |
| GET    | /api/surveys/{id}                 | Bearer      | Get survey definition (owner)        |
| PUT    | /api/surveys/{id}                 | Bearer      | Update title/description/is_open/questions |
| DELETE | /api/surveys/{id}                 | Bearer      | Delete survey (cascades)             |
| GET    | /api/surveys/{id}/results          | Bearer      | Aggregated counts + text answers     |
| GET    | /api/surveys/{id}/export.csv       | Bearer or ?token= | Raw responses as CSV            |
| GET    | /s/{id}                           | none        | Render the survey-taking form        |
| POST   | /s/{id}                           | none        | Submit a response                    |
| GET    | /                                 | none        | Dashboard (log in, then manage)      |
| GET    | /admin/settings                   | Bearer, admin | `{schema, values}` — see below      |
| PUT    | /admin/settings                   | Bearer, admin | Partial key→value map               |

### POST /api/surveys body
```json
{
  "title": "...",
  "description": "...",
  "questions": [
    { "type": "single", "prompt": "...", "options": ["a", "b"] },
    { "type": "multiple", "prompt": "...", "options": ["a", "b", "c"] },
    { "type": "text", "prompt": "..." }
  ]
}
```
`PUT` accepts any subset of `title`, `description`, `is_open`, `questions`.
Updating `questions` replaces the full set (no partial edits/diffing) and is
**rejected with 409** once the survey has at least one response — editing
questions after that would cascade-delete existing answers (FK ON DELETE
CASCADE from `answers.question_id`). Delete the survey and start a new one instead.

## Admin settings
Generic admin-editable runtime settings — see `/srv/shared/admin_settings.py`
(reference copy; this app's `admin_settings.py` is a verbatim copy, not an
import). `ADMIN_USERNAMES` (`.env`, comma-separated) gates `/admin/settings`
(Bearer token + username in that set, else 403). Three fields:
- `ENABLED` (boolean, default `true`) — kill switch. When set to `false`, a
  `before_request` hook returns `503 {"error": "Service temporarily disabled
  by administrator"}` for every route (including the public `/s/{id}` form
  and the dashboard) except `/admin/settings`, so it can always be turned
  back on without SSH/restart.
- `IP_HASH_SALT` (sensitive — masked in `GET` responses as `••••••••` + last 4
  chars). Read fresh per-request by `_response_ip_hash()` in `app.py`.
- `ALLOWED_KVSTORE_URLS` (non-sensitive, comma-separated). Read fresh
  per-request by `_allowed_kvstore_urls()` in `auth.py`.

Either, once saved via `PUT /admin/settings`, lives in the `app_settings` DB
table and overrides the `.env` value immediately — no restart. The `.env`
value stays the fallback until an admin explicitly saves an override.

`SETTINGS_DEFAULTS` (in `app.py`) holds the same `.env`-sourced fallback each
field's point-of-use call (`_response_ip_hash()`, `auth._allowed_kvstore_urls()`)
uses, and is passed to `register_admin_settings_routes(...)` so
`GET /admin/settings` shows the actual effective value instead of a blank
field when no override has been saved yet. `ALLOWED_KVSTORE_URLS_DEFAULT` is
defined once in `auth.py` and imported into `app.py` rather than duplicating
the literal. Each `SettingField` also carries a `help` string, surfaced by
CList's "Help" link/modal in the App Settings panel.

## Dashboard styling
`static/dashboard.html` links CList's `https://clist.mooc.ca/css/interface.css`
directly rather than redefining its design tokens/button styles locally —
every button in the dashboard uses `.btn`/`.btn-small`/`.btn-secondary` from
that file (same classes CList itself uses), so there's one source of truth
for the green accent color, button padding, etc. A small local override
resets `body, html` back to normal document flow (interface.css assumes
CList's fixed-height, flex-centered single-page app shell, which would
otherwise hide/clip survey's normal scrolling page). Anything not covered by
interface.css (page layout, the `.authbox` login-panel box, `.question`/
`.survey-row` cards, results bars) is still local to dashboard.html.

## Dashboard auth model
The dashboard has its own username/password login
form, styled to match CList's `#authModal` (same box layout, "Account server:
<host> Change" line, password show/hide toggle). It computes `auth_hash =
PBKDF2(password, username + "_auth", 100000, SHA-256)` client-side via Web
Crypto (`crypto.subtle`), exactly mirroring CList's `deriveAuthHash()` in
`clist.mooc.ca/js/crypto_utils.js`, and POSTs it directly to the selected
kvstore instance's `/auth/login`. The resulting Bearer token is stored in
`localStorage` scoped to `survey.mooc.ca`. This is a standalone login — it
does **not** share cookies/localStorage with CList or kvstore across
subdomains, and kvstore has no hosted login page of its own to redirect to
(it's a pure JSON API — "no HTML, no sessions"). Because this is a
cross-origin browser request, `survey.mooc.ca` must be (and is) allowlisted in
each kvstore instance's Caddyfile CORS block (`@options_survey`/`@cors_survey`
in both the `kvstore.mooc.ca` and `kvstore.downes.ca` blocks of
`/srv/proxy/Caddyfile`) — any future app doing browser-side kvstore login
needs the same addition.

**Account server switcher.** Like CList, the dashboard lets the user pick
which kvstore instance to log into (`kvstore.mooc.ca` or `kvstore.downes.ca`),
persisted in `localStorage` under `survey_kvstore_url`. Because each kvstore
instance signs tokens with its own key, `auth.py`'s `verify_token()` does NOT
always call the `.env` `KVSTORE_URL` — it reads the unverified `iss` claim
from the JWT and verifies against that issuer instead, restricted to
`ALLOWED_KVSTORE_URLS` (env var, comma-separated; defaults to both
kvstore.mooc.ca and kvstore.downes.ca). This exists specifically so tokens
issued by kvstore.downes.ca aren't rejected just because `.env` points at
kvstore.mooc.ca. If a third kvstore instance is ever added to the switcher,
add it to `ALLOWED_KVSTORE_URLS` too or its tokens will fail verification.

Planned future integration: "survey" becomes a loadable option in CList's own
edit window, at which point this standalone login may become redundant for
CList users specifically, but should remain for standalone use.

## Rebuild
```bash
cd /srv/apps/survey
docker compose build && docker compose up -d
docker compose logs -f survey
```
Never rebuild without stating the exact command, confirming no data loss,
and receiving explicit user confirmation.

## Environment variables (.env)
- `BASE_URL`             — Public base URL (default: https://survey.mooc.ca)
- `KVSTORE_URL`          — Fallback kvstore instance for token verification, used only if a
  token's `iss` claim isn't in `ALLOWED_KVSTORE_URLS` (default: https://kvstore.mooc.ca)
- `ALLOWED_KVSTORE_URLS` — Comma-separated kvstore instances the dashboard's account-server
  switcher may issue tokens from; `verify_token()` trusts a token's own `iss` claim only if
  it's in this list (default: https://kvstore.mooc.ca,https://kvstore.downes.ca) — fallback;
  overridden by `app_settings.ALLOWED_KVSTORE_URLS` once an admin saves one
- `DATA_DIR`             — Path to SQLite DB directory (default: /data)
- `ADMIN_USERNAMES`      — Comma-separated kvstore usernames allowed to use `/admin/settings`

## Status
Live as of 2026-09-11. Container `survey` running, `survey.mooc.ca` wired into
`/srv/proxy/Caddyfile` with ACME challenge handler + `reverse_proxy survey:8085`,
CORS allowlisted on both `kvstore.mooc.ca` and `kvstore.downes.ca`.
