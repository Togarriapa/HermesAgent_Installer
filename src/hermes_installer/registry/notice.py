"""Build update notices from the Installer-owned pinned bundle, never ambient Git state."""
from __future__ import annotations
import hashlib
from collections.abc import Mapping
from typing import Any
from .native import NativeRegistry

def build_registry_update_notice(current: NativeRegistry,
                                previous_files: Mapping[str,bytes] | None = None) -> dict[str,Any]:
    """Return a deterministic candidate notice from verified bundle bytes and diffs."""
    rows=sorted(f"{path}|{hashlib.sha256(data).hexdigest()}" for path,data in current.source.files.items()
                if path.split("/",1)[0] in current.root_counts and path.endswith(".yaml"))
    digest=hashlib.sha256(("\n".join(rows)+"\n").encode("utf-8")).hexdigest()
    changed=[]
    if previous_files is not None:
        paths=set(previous_files)|set(current.source.files)
        changed=sorted(path for path in paths if previous_files.get(path)!=current.source.files.get(path))
    return {
        "schemaVersion":1,
        "event":"registry-update-available",
        "source":{"kind":"installer-bundle",
                  "path":f"resources/vendor/hermes-agent-resources-{current.source.catalog_version}",
                  "catalogVersion":current.source.catalog_version,
                  "revision":current.source.revision,
                  "tree":current.source.source_tree,
                  "contentDigest":current.source.content_digest},
        "resourceDigestSha256":digest,
        "resourceCount":sum(current.root_counts.values()),
        "counts":dict(sorted(current.root_counts.items())),
        "changed":changed,
        "candidateOnly":True,
        "activationAuthorized":False,
    }
