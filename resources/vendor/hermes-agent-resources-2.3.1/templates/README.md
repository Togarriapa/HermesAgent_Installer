# Resource Templates

Use the template that matches the resource kind instead of starting from the legacy generic stub.

- `profile.yaml` — durable professional responsibility with explicit scope and escalation.
- `skill.yaml` — reusable domain method with inputs, procedure, verification, outputs, and failure modes.
- `plugin.yaml` — bounded provider/runtime integration with explicit capability and credential policy.
- `mcp.yaml` — bounded MCP server with transport, exposure, isolation, and provenance.
- `channel.yaml` — authenticated Hermes-only user communication adapter.
- `cron.yaml` — idempotent recurring job with concurrency/retry/authority rules.
- `webhook.yaml` — authenticated, replay-protected event handler.
- `bundle.yaml` — starting team composition with dynamic recruitment and no authority escalation.

All templates are completed at runtime by `QUALITY_POLICY.yaml`. Template fields are the **resource-specific declarations that defaults must not invent**. Remove unused dependency groups rather than granting placeholders, keep secrets as runtime references, and never add a permission merely because another resource has it.

Before proposing a new resource, run the complete validation suite. Behavior/capability changes to an existing resource require its own semantic-version bump; restrictive registry-wide quality defaults are versioned separately by `QUALITY_POLICY.yaml`.
