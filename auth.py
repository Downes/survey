import base64
import json
import os
import requests
from flask import request

from db import get_db
from admin_settings import get_setting

KVSTORE_URL = os.environ.get("KVSTORE_URL", "https://kvstore.mooc.ca")

# Shared with app.py's SETTINGS_DEFAULTS so the /admin/settings GET response
# shows the same effective fallback this module actually uses, instead of
# duplicating the literal in two places.
ALLOWED_KVSTORE_URLS_DEFAULT = os.environ.get(
    "ALLOWED_KVSTORE_URLS", "https://kvstore.mooc.ca,https://kvstore.downes.ca"
)


def _allowed_kvstore_urls():
    # Kvstore instances the dashboard's account-server switcher is allowed to
    # point at. A token's "iss" claim tells us which one issued it (see
    # kvstore's AUTH.md); we verify against that issuer rather than always
    # KVSTORE_URL, but only if it's in this allowlist, since the issuer string
    # is client-supplied (embedded in the token) and used to build an outbound
    # request URL. Re-read on every call (not cached) so an admin override via
    # /admin/settings takes effect without a restart.
    raw = get_setting(get_db(), "ALLOWED_KVSTORE_URLS", default=ALLOWED_KVSTORE_URLS_DEFAULT)
    return {u.strip() for u in raw.split(",") if u.strip()}


def _jwt_issuer(token):
    """Read the unverified 'iss' claim from a JWT, or None if not a JWT / unreadable."""
    if token.count(".") != 2:
        return None
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64)).get("iss")
    except Exception:
        return None


def verify_token():
    """Verify Bearer token against kvstore. Returns (username, None) or (None, (body, status)).

    Accepts the token either as an Authorization: Bearer header (normal API calls)
    or as a ?token= query param (needed for plain <a href> downloads like CSV export,
    which can't set custom headers).
    """
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    else:
        token = request.args.get("token", "")
    if not token:
        return None, ({"error": "Missing or invalid Authorization header"}, 401)

    issuer = _jwt_issuer(token)
    verify_url = issuer if issuer in _allowed_kvstore_urls() else KVSTORE_URL

    try:
        r = requests.get(
            f"{verify_url}/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
    except requests.RequestException as e:
        return None, ({"error": f"KVStore unreachable: {e}"}, 502)
    if r.status_code != 200:
        return None, ({"error": "Invalid or expired token"}, 401)
    return r.json().get("username"), None
