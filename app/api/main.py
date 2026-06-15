"""api — a tiny fintech service whose every request is authorized by Cedar (PDP).

This is the layer-3 enforcement point: after Cilium admits the connection (L3/L4)
and the HTTP method+path (L7), THIS service asks Cedar "may this principal do
this action on this resource?" before doing any work, returning 403 on Deny.
So a single request traverses all three policy layers on the same asset.

The principal is resolved by app/api/auth.py: a verified Bearer JWT (signature +
audience, RFC 8707) wins; otherwise an unauthenticated X-User header is the labeled
demo fallback. Either way the result is a Cedar `User::"..."` UID — the audience
check is what makes a token minted for another service unusable here.
Policies/schema/entities are the same artifacts unit-tested in cedar/authz.py
and portable to Amazon Verified Permissions.
"""

from __future__ import annotations

import pathlib

import cedarpy
from fastapi import FastAPI, Header, HTTPException, Request

from auth import AuthRequired, principal_for, principal_id

CEDAR = pathlib.Path(__file__).parent / "cedar"
POLICIES = (CEDAR / "policies.cedar").read_text(encoding="utf-8")
SCHEMA = (CEDAR / "schema.json").read_text(encoding="utf-8")
ENTITIES = (CEDAR / "entities.json").read_text(encoding="utf-8")

app = FastAPI(title="cedar-pdp-api")


def resolve_principal(authorization: str | None, x_user: str) -> str:
    """Resolve the Cedar principal UID, mapping auth failures to HTTP status.
    A present-but-invalid Bearer token is 401 (authentication failed); a bad
    X-User fallback is 400 (malformed input). Fail closed either way."""
    try:
        return principal_for(authorization, x_user)
    except AuthRequired:
        # Enforce mode (AUTH_REQUIRE_JWT): no Bearer token and X-User fallback disabled.
        raise HTTPException(status_code=401, detail="authentication required (Bearer JWT)")
    except ValueError:
        # A PRESENT (non-empty) Authorization header that failed is an authentication
        # failure (401) — bad signature/audience/expiry OR an unsupported scheme.
        # Only a bad X-User with NO Authorization header is malformed input (400).
        if authorization is not None and authorization.strip():
            raise HTTPException(status_code=401, detail="invalid or unsupported Authorization")
        raise HTTPException(status_code=400, detail="invalid X-User")


def authorize(principal: str, action: str, resource: str, context: dict | None = None) -> None:
    """Raise 403 unless Cedar returns Allow (fail closed on any evaluation error)."""
    try:
        res = cedarpy.is_authorized(
            {"principal": principal, "action": action, "resource": resource, "context": context or {}},
            POLICIES, ENTITIES, SCHEMA,
        )
        allowed = res.decision.value == "Allow"
    except Exception:
        allowed = False  # fail closed
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Cedar denied: {action} on {resource}")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/accounts/{acct}")
def view_account(
    acct: str,
    x_user: str = Header(default="anonymous"),
    authorization: str | None = Header(default=None),
) -> dict:
    uid = resolve_principal(authorization, x_user)
    authorize(uid, 'Action::"ViewAccount"', f'Account::"{acct}"')
    # Attribute to the RESOLVED principal (Bearer sub when present), not the X-User header.
    return {"account": acct, "viewer": principal_id(uid), "decision": "Allow"}


@app.post("/accounts/{acct}/transfer")
async def transfer(
    acct: str,
    request: Request,
    x_user: str = Header(default="anonymous"),
    authorization: str | None = Header(default=None),
) -> dict:
    try:
        body = await request.json()
    except Exception:
        body = {}
    # Missing/invalid amount -> default huge so Cedar's transferLimit check denies it.
    try:
        amount = int(body.get("amount", 10**9))
    except (TypeError, ValueError):
        amount = 10**9
    uid = resolve_principal(authorization, x_user)
    authorize(uid, 'Action::"Transfer"', f'Account::"{acct}"', {"amount": amount})
    return {"account": acct, "by": principal_id(uid), "amount": amount, "decision": "Allow"}


@app.get("/auditlogs/{log}")
def view_audit_log(
    log: str,
    x_user: str = Header(default="anonymous"),
    authorization: str | None = Header(default=None),
) -> dict:
    uid = resolve_principal(authorization, x_user)
    authorize(uid, 'Action::"ViewAuditLog"', f'AuditLog::"{log}"')
    return {"auditlog": log, "viewer": principal_id(uid), "decision": "Allow"}
