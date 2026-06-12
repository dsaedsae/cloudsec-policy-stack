// AI-AGENT authorization as code (ABAC + delegation).
//
// An AI agent is a Non-Human Identity (NHI) acting ON BEHALF OF a human user.
// The hard problem is the *confused deputy*: an over-privileged agent must not let
// a user reach data the user themselves could not. So authorization is the
// INTERSECTION of (the agent's own ceiling) AND (the delegating user's clearance).
// Data is graded by MLS class: 0 = public(O), 1 = sensitive(S), 2 = classified(C).
//
// These are Cedar policies — the same engine portable to Amazon Verified Permissions —
// unit-tested in cedar/agent_authz.py (no cluster, no model call).

// 1) Tool-call allowlist: an agent may invoke ONLY tools on its allowlist.
permit (
    principal,
    action == Action::"InvokeTool",
    resource
)
when { principal.allowed_tools.contains(resource.name) };

// 2) Delegation intersection (confused-deputy prevention): an agent may read data
//    only up to the LOWER of its own clearance ceiling AND the clearance of the
//    user it acts on behalf of. The agent can never exceed what the user could do.
permit (
    principal,
    action == Action::"ReadData",
    resource
)
when {
    resource.classification <= principal.max_classification
    && resource.classification <= principal.on_behalf_of.clearance
};

// 3) Owner override: the on-behalf-of user's OWN records are readable regardless of
//    the clearance ladder — but still capped by the agent's own ceiling (an agent
//    can't be handed more reach than it is trusted with).
permit (
    principal,
    action == Action::"ReadData",
    resource
)
when {
    resource.owner == principal.on_behalf_of
    && resource.classification <= principal.max_classification
};

// 4) Hard guardrail: an agent whose ceiling is below "classified" (2) may NEVER read
//    classified data — even if the delegating user is cleared or owns it. forbid wins.
forbid (
    principal,
    action == Action::"ReadData",
    resource
)
when {
    resource.classification >= 2
    && principal.max_classification < 2
};
