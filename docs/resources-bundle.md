# Bundled Hermes Resources snapshot

The installer owns the complete HermesAgent_Resources v2.3.1 source snapshot at
`resources/vendor/hermes-agent-resources-2.3.1/`. It includes the eight
resource roots plus catalog, schemas, quality policy, helpers, scripts,
templates, workflow files, notices, and source documentation. Its 739 regular
files retain their pinned Git bytes and executable modes.

The authoritative installer input is the checked-in archive and pin packaged
with the Python module:
`src/hermes_installer/registry/bundle_data/hermes-agent-resources-2.3.1.tar.gz` and
`hermes-agent-resources.pin.json`. These package data files are included in the Python installer distribution. The loader verifies archive size, SHA-256,
Git blob, source commit/tree, control-file blobs, root trees, and manifest
counts without contacting the upstream repository. The expanded directory is
the readable, reviewable source copy; runtime install, update, restore, and
verification must consume only installer-owned bytes. The pinned upstream URL
is provenance, not a fetch dependency.

Keep edits and user experience in installer-owned overlays and generations;
do not edit the vendored source snapshot in place. Installation and recovery use only the Installer-owned archive and expanded
snapshot, so the original Resources repository may be unavailable or deleted.
A newer catalog is published by adding a new reviewed Installer-owned pin and a
complete additive snapshot; runtime never follows a moving upstream branch.
The `hermes-installer resources plan` command verifies this bundled copy offline
and presents the native crosswalk. Profiles compile into isolated Hermes homes
and Skills into native `SKILL.md` directories. Other kinds keep exact adapter
identities and explicit incomplete reasons until reviewed runtime
implementations land. Functional, enabled, and target-verified state remains
pending until observed.
This user-authorized owner copy does not assert a blanket redistribution grant.
Preserve all source notices and apply the relevant terms before distributing
the Installer or its bundled snapshot.
