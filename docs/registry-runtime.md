# Registry runtime

The importer treats HermesAgent_Resources as a versioned declarative catalog. It resolves only explicit selectors and dependency/inheritance edges, rejects missing nodes and cycles, and merges nested maps while lists use child replacement. A declaration is not a host grant: every capability also requires a host grant and current runtime authorization.

The eight nonrecursive roots are profiles, skills, plugins, MCPs, bundles, channels, crons and webhooks. Definitions do not create external servers. Schedules, webhooks, channels, finance and account capabilities remain inactive until selected and configured. Resource readiness tracks source, configuration, authentication, reachability and functional tests independently.

Each generated generation is immutable. Stage into a new owned directory, validate files and policy, then atomically replace the active pointer. Failures retain the previous pointer and user data. Authorization must be checked at the actual tool/process/filesystem boundary, including fresh identity lookup for homelab writes; profiles and prompts are not a sandbox.

Hermes alone faces the user. It routes correlated work to bounded internal specialists and receives evidence and dissent before composing a response. Specialists have separate state and cannot bind user channels.
