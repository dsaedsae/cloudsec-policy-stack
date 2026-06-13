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

// 5) Delegation-depth cap — OWASP Agentic Top 10 (2025-12-09) ASI08
//    "Cascading / runaway delegation." Agents now spawn sub-agents; without a bound,
//    a human->agent->sub-agent->... chain lets authority cascade through an unbounded
//    spawn tree (each hop a fresh confused-deputy surface). We cap the chain: an agent
//    more than ONE hop removed from its human principal is refused outright, for ANY
//    action (forbid always wins in Cedar).
//
//    delegation_depth = number of agent->agent hops above the human:
//      0 = the agent a human operates directly      (human -> agent)        ALLOWED
//      1 = a sub-agent that agent spawned           (human -> agent -> sub) ALLOWED (the one permitted hop)
//      2+ = sub-sub-agent and deeper                                        FORBIDDEN by this rule
//
//    DESIGN NOTE (scope, no over-claim): on_behalf_of always resolves to the ROOT HUMAN
//    (not an upstream agent), so P2's intersection floor (resource.classification <=
//    on_behalf_of.clearance) keeps applying down the chain, and the sub-agent's OWN
//    max_classification caps it from above. What this model does NOT do: delegation_depth
//    is a single integer, not a traversal, so an *intermediate* agent's lower ceiling is
//    NOT represented here (setting sub.max_classification <= parent ceiling at spawn time
//    is the unimplemented agent-runtime's job). So the honest claim is "P5 bounds the chain
//    LENGTH; root-human clearance is the floor and the sub-agent's own ceiling is the cap"
//    — NOT a general "authority can never amplify at any hop." Cedar has no attribute union
//    type, so chaining on_behalf_of to an Agent would break `.clearance`; tracking depth
//    separately is type-sound. This rule is LOAD-BEARING and falsifiable: delete it and the
//    depth-2 agent in requests.json (reading public data) flips Deny -> Allow.
forbid (
    principal,
    action,
    resource
)
when { principal.delegation_depth > 1 };
