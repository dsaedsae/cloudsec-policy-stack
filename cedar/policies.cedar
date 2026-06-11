// Application-layer authorization (authz-as-code) for a fintech-style API.
// Layer 3 of the defense-in-depth stack: after Terraform (provision) and
// Cilium (network L3/L7), Cedar decides "is THIS principal allowed THIS action
// on THIS resource" — declaratively, testable, and validatable against a schema.

// A customer may view an account they own.
permit (
    principal,
    action == Action::"ViewAccount",
    resource
)
when { resource.owner == principal };

// A customer may transfer from their own account, up to their transfer limit.
permit (
    principal,
    action == Action::"Transfer",
    resource
)
when { resource.owner == principal && context.amount <= principal.transferLimit };

// Auditors may read audit logs (role membership via the entity hierarchy).
permit (
    principal in Role::"auditor",
    action == Action::"ViewAuditLog",
    resource
);

// Hard guardrail: never allow transfers out of a frozen account.
// `forbid` always overrides `permit` — defense in depth at the policy level.
forbid (
    principal,
    action == Action::"Transfer",
    resource
)
when { resource.frozen == true };
