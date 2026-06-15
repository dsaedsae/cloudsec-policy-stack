"""Principal resolution for the PDP — pure, no FastAPI/Cedar deps so it unit-tests
without a cluster (app/api/auth_test.py).

The PDP decides authorization with Cedar; but FIRST it must know WHO is asking. The
demo's original input is an unauthenticated `X-User` header (kept as a labeled fallback).
This module adds the real-world path: a Bearer JWT whose signature AND audience are
verified before its `sub` becomes the principal — audience-binding (RFC 8707) is what
stops a token minted for another service from being replayed here (OAuth 2.1 Resource
Server; the model an MCP server / AI gateway must follow).

DEMO ONLY: the signing key is a local fixture (HS256 shared secret). A real deployment
verifies against the identity provider's JWKS (asymmetric) with the SAME audience and
never bakes a secret into the image. See docs/authorization-model.md.
"""

from __future__ import annotations

import os
import re

import jwt  # PyJWT

# Principal id charset — constrain BEFORE it becomes a Cedar entity UID so a crafted
# value can't break out of `User::"..."` (injection / parse-error 500 / log injection).
_USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Local fixtures (override via env for a demo). NOT production secrets.
DEMO_JWT_SECRET = os.environ.get("DEMO_JWT_SECRET", "demo-fixture-key-not-a-real-secret")
RESOURCE_AUD = os.environ.get("RESOURCE_AUD", "https://api.shop.local")  # this resource's audience


class AuthRequired(ValueError):
    """No verified Bearer token AND the X-User fallback is disabled (AUTH_REQUIRE_JWT mode).
    Subclasses ValueError so existing handlers still catch it; the FastAPI layer maps it to
    401 (authentication required), distinct from a malformed-X-User 400."""


def _require_jwt() -> bool:
    """Enforce mode — set on the live/cluster deployment (AUTH_REQUIRE_JWT=1): a verified
    Bearer JWT is MANDATORY and the unauthenticated X-User fallback is disabled. Read at
    call time so it is per-deployment togglable and unit-testable (auth_test.py)."""
    return os.environ.get("AUTH_REQUIRE_JWT", "").strip().lower() in ("1", "true", "yes")


def validate_user(user: str) -> str:
    """Charset-validate a principal id, or raise ValueError."""
    if not _USER_RE.match(user or ""):
        raise ValueError("invalid principal id")
    return user


def verify_bearer(token: str) -> str:
    """Verify a demo Bearer JWT (HS256, local fixture key) and return its validated `sub`.

    Raises ValueError on bad signature / wrong (or missing) audience / expiry / missing sub
    — fail closed. The audience check is the point: a token whose `aud` is not THIS
    resource is rejected even if its signature is valid (RFC 8707 resource indicators).
    """
    try:
        claims = jwt.decode(
            token, DEMO_JWT_SECRET, algorithms=["HS256"], audience=RESOURCE_AUD,
            options={"require": ["exp", "aud", "sub"]},
        )
    except jwt.PyJWTError as e:
        raise ValueError(f"bearer rejected: {e}")
    return validate_user(str(claims.get("sub", "")))


def principal_id(uid: str) -> str:
    """Extract the bare id from a Cedar principal UID — `User::"alice"` -> `alice`.
    Used for response attribution so a Bearer-authenticated action is reported as the
    RESOLVED principal (the JWT sub), never the client-controlled X-User header."""
    return uid.split('"')[1] if '"' in uid else uid


def principal_for(authorization: str | None, x_user: str) -> str:
    """Resolve the Cedar principal UID. A verified Bearer token wins; otherwise the
    unauthenticated X-User demo fallback. Raises ValueError on any auth failure
    (the FastAPI layer maps that to 401 for a bad token, 400 for a bad X-User).

    Fail closed on a PRESENT-but-unparseable credential: a non-empty Authorization
    header that is not a well-formed Bearer (e.g. `Basic ...`, a bare `Bearer` with no
    token) is REJECTED, never silently downgraded to the X-User demo identity. The
    X-User fallback applies ONLY when no Authorization header is sent at all."""
    if authorization is not None and authorization.strip():
        if not authorization.lower().startswith("bearer "):
            raise ValueError("unsupported Authorization scheme (expected Bearer)")
        return f'User::"{verify_bearer(authorization[7:].strip())}"'
    # No Authorization header. In enforce mode the unauthenticated X-User fallback is OFF.
    if _require_jwt():
        raise AuthRequired("authentication required: Bearer JWT (X-User fallback disabled)")
    return f'User::"{validate_user(x_user)}"'
