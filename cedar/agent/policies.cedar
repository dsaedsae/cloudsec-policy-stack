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

// 4) Belt-and-suspenders forbid (defense-in-depth). NOTE: under the current permit set
//    this is REDUNDANT — P2 and P3 both cap reads at the agent's own ceiling
//    (max_classification), so an agent with ceiling < 2 can never be GRANTED a classified
//    read in the first place, and the dedicated test Denies by default-deny / permit-cap,
//    not by this forbid. It is kept as an explicit fail-safe backstop: if a future permit
//    is ever added that does NOT cap at the agent ceiling, this forbid still blocks a
//    sub-"classified" agent from reading classified data. (Cedar: forbid always wins.)
forbid (
    principal,
    action == Action::"ReadData",
    resource
)
when {
    resource.classification >= 2
    && principal.max_classification < 2
};
