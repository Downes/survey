import os

from flask import request

from db import get_db
from clist_server_admin.sqlite import get_setting
from clist_kvstore_auth.sync import verify_token as _kv_verify_token, owns as _kv_owns

KVSTORE_URL = os.environ.get("KVSTORE_URL", "https://kvstore.mooc.ca")

# Shared with app.py's SETTINGS_DEFAULTS so the /admin/settings GET response
# shows the same effective fallback this module actually uses, instead of
# duplicating the literal in two places.
ALLOWED_KVSTORE_URLS_DEFAULT = os.environ.get(
    "ALLOWED_KVSTORE_URLS", "https://kvstore.mooc.ca,https://kvstore.downes.ca"
)

ADMIN_USERNAMES = {u.strip() for u in os.environ.get("ADMIN_USERNAMES", "").split(",") if u.strip()}


def _allowed_admin_issuers():
    # Kvstore instances trusted to vouch for an admin (ADMIN_USERNAMES check
    # only). Does NOT gate ordinary token verification below, which is open
    # to any issuer — any kvstore instance can mint a qualified identity,
    # see clist_kvstore_auth. Re-read on every call (not cached) so an admin
    # override via /admin/settings takes effect without a restart.
    raw = get_setting(get_db(), "ALLOWED_KVSTORE_URLS", default=ALLOWED_KVSTORE_URLS_DEFAULT)
    return {u.strip() for u in raw.split(",") if u.strip()}


def _bearer_header():
    # Accepts the token either as an Authorization: Bearer header (normal API
    # calls) or as a ?token= query param (needed for plain <a href> downloads
    # like CSV export, which can't set custom headers).
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth
    token = request.args.get("token", "")
    return f"Bearer {token}" if token else ""


def verify_identity():
    """Verify Bearer token (local JWKS verification, open to any issuer, with
    opaque-token callback fallback for pre-migration sessions). Returns
    (Identity, None) or (None, (body, status))."""
    return _kv_verify_token(_bearer_header(), KVSTORE_URL)


def is_admin(identity):
    return identity.username in ADMIN_USERNAMES and identity.iss in _allowed_admin_issuers()


def owns(stored_owner, identity):
    return _kv_owns(stored_owner, identity, KVSTORE_URL)


def my_owner_values(identity):
    """Values that could appear in surveys.owner for this identity — the
    qualified id always, plus the bare username for legacy rows, but only
    when this identity's issuer is the app's own default instance (same
    rule as owns())."""
    values = [identity.qualified_id]
    if identity.iss == KVSTORE_URL:
        values.append(identity.username)
    return values


def verify_admin_token():
    """Adapter for register_admin_settings_routes's (username, err) contract.
    Gates on issuer-aware is_admin() rather than letting clist_server_admin's
    own bare is_admin(username) decide — otherwise any issuer's JWT with
    sub=<admin username> would bypass the issuer-trust requirement."""
    identity, err = verify_identity()
    if err:
        return None, err
    if not is_admin(identity):
        return None, ({"error": "Forbidden"}, 403)
    return identity.username, None
