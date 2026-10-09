# Bundled Hermes Resources snapshot

The installer owns the complete HermesAgent_Resources v2.3.1 source snapshot at
`resources/vendor/hermes-agent-resources-2.3.1/`. It includes the eight
resource roots plus catalog, schemas, quality policy, helpers, scripts,
templates, workflow files, notices, and source documentation. Its 739 regular
files retain their pinned Git bytes and executable modes.

The authoritative installer input is the adjacent checked-in archive and pin:
`resources/upstream/hermes-agent-resources-2.3.1.tar.gz` and
`hermes-agent-resources.pin.json`. The loader verifies archive size, SHA-256,
Git blob, source commit/tree, control-file blobs, root trees, and manifest
counts without contacting the upstream repository. The expanded directory is
the readable, reviewable source copy; runtime install, update, restore, and
verification must consume only installer-owned bytes. The pinned upstream URL
is provenance, not a fetch dependency.

Keep edits and user experience in installer-owned overlays and generations;
do not edit the vendored source snapshot in place. A newer upstream release
requires a new reviewed pin and a complete additive snapshot. No license or
redistribution permission is inferred from the source archive; honor the
upstream notices and licensing terms before redistribution.
