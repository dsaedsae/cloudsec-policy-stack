"""Cluster-free unit test for the PDP's Bearer-JWT audience binding (#3 / gap menu).

    python app/api/auth_test.py     # PASS/FAIL table; exit 1 on any mismatch

Mints tokens with the LOCAL fixture key (auth.DEMO_JWT_SECRET) and asserts the PDP's
principal resolver FAILS CLOSED on everything except a correctly-signed token whose
audience is THIS resource. The audience case is load-bearing: a token validly signed
for another service (`aud=https://evil.other`) must be rejected here — that is the
whole point of RFC 8707 resource-indicator / audience binding.
"""

from __future__ import annotations

import pathlib
import sys
import time
import warnings

sys.path.insert(0, str(pathlib.Path(__file__).parent))  # import sibling auth.py

import jwt  # PyJWT

# One case deliberately forges a token with a short attacker key to prove it's rejected;
# PyJWT's short-key warning on that encode is expected, so don't let it clutter the table.
warnings.filterwarnings("ignore", message=".*HMAC key.*")

import auth


def mint(secret=auth.DEMO_JWT_SECRET, aud=auth.RESOURCE_AUD, sub="alice", exp_delta=3600, drop=None):
    """Forge a JWT for one test case. drop= removes a claim to test 'require'."""
    claims = {"sub": sub, "aud": aud, "exp": int(time.time()) + exp_delta}
    if drop:
        claims.pop(drop, None)
    return jwt.encode(claims, secret, algorithm="HS256")


# (name, callable -> principal UID, expected: a UID string OR "reject")
CASES = [
    ("valid token (correct sig + aud + sub) -> principal",
        lambda: auth.principal_for(f"Bearer {mint(sub='alice')}", "ignored"),
        'User::"alice"'),
    ("wrong audience (token minted for another service) -> reject",
        lambda: auth.principal_for(f"Bearer {mint(aud='https://evil.other')}", "x"),
        "reject"),
    ("bad signature (attacker-signed) -> reject",
        lambda: auth.principal_for(f"Bearer {mint(secret='attacker-key')}", "x"),
        "reject"),
    ("expired token -> reject",
        lambda: auth.principal_for(f"Bearer {mint(exp_delta=-10)}", "x"),
        "reject"),
    ("missing aud claim -> reject (require aud)",
        lambda: auth.principal_for(f"Bearer {mint(drop='aud')}", "x"),
        "reject"),
    ("missing sub claim -> reject (require sub)",
        lambda: auth.principal_for(f"Bearer {mint(drop='sub')}", "x"),
        "reject"),
    ("garbage bearer (not a jwt) -> reject",
        lambda: auth.principal_for("Bearer not.a.jwt", "x"),
        "reject"),
    ("non-Bearer scheme (Basic) present -> reject (fail closed, not X-User downgrade)",
        lambda: auth.principal_for("Basic dXNlcjpwYXNz", "alice"),
        "reject"),
    ("bare 'Bearer' with no token -> reject",
        lambda: auth.principal_for("Bearer", "alice"),
        "reject"),
    ("empty Bearer token -> reject",
        lambda: auth.principal_for("Bearer ", "alice"),
        "reject"),
    ("sub with injection chars -> reject (charset)",
        lambda: auth.principal_for(f"Bearer {mint(sub='alice;DROP')}", "x"),
        "reject"),
    ("no Authorization header -> X-User fallback (labeled demo)",
        lambda: auth.principal_for(None, "bob"),
        'User::"bob"'),
    ("attribution: a verified Bearer sub wins over the X-User header (report resolved, not client-set)",
        lambda: auth.principal_id(auth.principal_for(f"Bearer {mint(sub='alice')}", "mallory")),
        "alice"),
    ("bad X-User fallback -> reject",
        lambda: auth.principal_for(None, "no spaces!"),
        "reject"),
]


def run() -> int:
    w = max(len(n) for n, _, _ in CASES) + 2
    passed = 0
    for name, fn, expect in CASES:
        try:
            outcome = fn()  # a principal UID string on success
        except ValueError:
            outcome = "reject"  # fail closed
        ok = outcome == expect
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{w}} -> {outcome!r} (want {expect!r})")
    print(f"\n{passed}/{len(CASES)} bearer/audience scenarios")
    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(run())
