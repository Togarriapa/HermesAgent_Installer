# Preserved Hermes Resources source

This installer now contains the complete user-owned HermesAgent_Resources source snapshot at catalog version 2.3.1: 739 files across the eight declared resource roots, with 692 resource manifests. The checked-in snapshot is at `resources/vendor/hermes-agent-resources-2.3.1/`; the source archive and pin record are retained under `resources/upstream/`.

The upstream repository URL in the pin record is provenance only. Runtime import uses the checked-in, hash-pinned archive and snapshot; it does not fetch the Resources repository. The user owns this source and explicitly authorized copying the complete tree into the installer so the original repository can later be removed. That authorization applies to this user-owned copy and does not assert general third-party redistribution rights; the selected upstream revision contains no license file.

The offline import adapter now compiles the vendored source into a revision-owned
native skills tree and private profile/declaration records, then requires actual
pinned Hermes skill-list/content-load read-back before it returns a discovery
receipt. This is implementation readiness only; no Pi-side import is claimed by
this source change. Existing `SOUL.md`, profiles, credentials, config, memories,
overlays and other home state are preserved. Native skill discovery remains
distinct from profile activation, delegated dispatch, authentication, external
effects and full lifecycle acceptance; those remain open under `RB-T266.4`.
