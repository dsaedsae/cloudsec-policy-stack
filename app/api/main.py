"""api — a tiny fintech service whose every request is authorized by Cedar (PDP).

This is the layer-3 enforcement point: after Cilium admits the connection (L3/L4)
and the HTTP method+path (L7), THIS service asks Cedar "may this principal do
this action on this resource?" before doing any work, returning 403 on Deny.
So a single request traverses all three policy layers on the same asset.

Principal comes from the X-User header (a JWT `sub` in the real world).
Policies/schema/entities are the same artifacts unit-tested in cedar/authz.py
and portable to Amazon Verified Permissions.
"""

from __future__ import annotations

import pathlib

import cedarpy
from fastapi import FastAPI, Header, HTTPException, Request

CEDAR = pathlib.Path(__file__).parent / "cedar"
POLICIES = (CEDAR / "policies.cedar").read_text(encoding="utf-8")
SCHEMA = (CEDAR / "schema.json").read_text(encoding="utf-8")
ENTITIES = (CEDAR / "entities.json").read_text(encoding="utf-8")

app = FastAPI(title="cedar-pdp-api")


def authorize(principal: str, action: str, resource: str, context: dict | None = None) -> None:
    """Raise 403 unless Cedar returns Allow."""
    res = cedarpy.is_authorized(
        {"principal": principal, "action": action, "resource": resource, "context": context or {}},
        POLICIES, ENTITIES, SCHEMA,
    )
    if res.decision.value != "Allow":
        raise HTTPException(status_code=403, detail=f"Cedar denied: {action} on {resource}")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/accounts/{acct}")
def view_account(acct: str, x_user: str = Header(default="anonymous")) -> dict:
    authorize(f'User::"{x_user}"', 'Action::"ViewAccount"', f'Account::"{acct}"')
    return {"account": acct, "viewer": x_user, "decision": "Allow"}


@app.post("/accounts/{acct}/transfer")
async def transfer(acct: str, request: Request, x_user: str = Header(default="anonymous")) -> dict:
    try:
        body = await request.json()
    except Exception:
        body = {}
    # Missing/invalid amount -> default huge so Cedar's transferLimit check denies it.
    try:
        amount = int(body.get("amount", 10**9))
    except (TypeError, ValueError):
        amount = 10**9
    authorize(f'User::"{x_user}"', 'Action::"Transfer"', f'Account::"{acct}"', {"amount": amount})
    return {"account": acct, "by": x_user, "amount": amount, "decision": "Allow"}


@app.get("/auditlogs/{log}")
def view_audit_log(log: str, x_user: str = Header(default="anonymous")) -> dict:
    authorize(f'User::"{x_user}"', 'Action::"ViewAuditLog"', f'AuditLog::"{log}"')
    return {"auditlog": log, "viewer": x_user, "decision": "Allow"}
