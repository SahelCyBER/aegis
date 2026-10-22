"""Single definition of "this request is a credential attempt".

HTTP brute-force detection must count guesses, not expired sessions. A browser
holding a stale token and polling ``GET /api/notifications`` returns 401 every
few seconds; several of them behind one office NAT look exactly like a password
spray if every 401 is counted. Only a request that SUBMITS credentials to an
authentication endpoint can be a guess, so that is the only thing counted.

``log_watcher`` (inline tracker) and ``event_normalizer`` (feeds the
``http_auth_brute_force`` rule) both call :func:`is_credential_attempt`, so the
two detectors cannot drift apart again.
"""
from __future__ import annotations

from typing import Optional

# Methods that carry a credential in the body. GET/HEAD/OPTIONS never do:
# a 401 on them is a stale or missing token, not a guess.
CREDENTIAL_METHODS = frozenset({"POST", "PUT", "PATCH"})

# Final path segment of an endpoint that accepts credentials / one-time codes.
_CREDENTIAL_LEAVES = frozenset({
    "login", "log-in", "log_in", "signin", "sign-in", "sign_in", "signon",
    "sign-on", "logon", "authenticate", "auth", "oauth", "session",
    "sessions", "password", "j_security_check", "wp-login.php", "xmlrpc.php",
    "otp", "mfa", "2fa", "verify-otp", "verify-2fa",
})

# Namespaces whose sub-endpoints (POST) accept credentials, e.g.
# /api/auth/change-password, /oauth/token, /api/auth/callback/credentials.
_CREDENTIAL_NAMESPACES = frozenset({"auth", "oauth", "oauth2"})

# Token-lifecycle endpoints under those namespaces. An expired refresh token or
# a logout with a dead session is not a guess.
_LIFECYCLE_LEAVES = frozenset({
    "refresh", "logout", "log-out", "signout", "sign-out", "me", "csrf",
    "status", "check", "verify", "validate",
})


def _segments(path: str) -> list[str]:
    bare = path.split("?", 1)[0].split("#", 1)[0].lower()
    return [s for s in bare.split("/") if s]


def is_credential_attempt(method: Optional[str], path: Optional[str]) -> bool:
    """True when ``method path`` submits credentials to an auth endpoint.

    An unknown method counts only when the path itself is an auth endpoint
    (the request may well have been a POST); an unknown path never counts.
    """
    if not path:
        return False
    verb = (method or "").upper()
    if verb and verb not in CREDENTIAL_METHODS:
        return False
    segs = _segments(path)
    if not segs:
        return False
    leaf = segs[-1]
    if leaf in _CREDENTIAL_LEAVES:
        return True
    # "token" alone is too common a leaf (push-token registration, API-key
    # CRUD): it is an auth endpoint only as /token or under an auth namespace.
    if leaf == "token":
        return len(segs) == 1 or segs[-2] in _CREDENTIAL_NAMESPACES
    if leaf in _LIFECYCLE_LEAVES:
        return False
    # Anything below an auth namespace needs a known credential method: with an
    # unknown one, only the explicit leaves above are trusted.
    return bool(verb) and any(s in _CREDENTIAL_NAMESPACES for s in segs[:-1])
