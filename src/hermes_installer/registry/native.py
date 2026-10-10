"""Offline discovery and safe native materialization of verified Hermes Resources."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
import re

from .resolver import RawResource, RegistryError, RegistryResolver, ResolvedResource, _merge_policy_values
from .source import VerifiedSource


_DISCOVERY_ROOTS = {
    "Bundle": "bundles",
    "Channel": "channels",
    "Cron": "crons",
    "MCP": "mcps",
    "Plugin": "plugins",
    "Profile": "profiles",
    "Skill": "skills",
    "Webhook": "webhooks",
}


def _yaml():
    try:
        import yaml
    except ImportError:
        raise RegistryError("PyYAML is required for bundled Resources discovery") from None
    return yaml


def _load(data):
    try:
        return _yaml().safe_load(data.decode("utf-8"))
    except Exception as exc:
        raise RegistryError(f"invalid bundled YAML: {type(exc).__name__}") from None


def _declared_roots(catalog: Mapping[str, Any]) -> dict[str, str]:
    spec = catalog.get("spec")
    discovery = spec.get("discovery") if isinstance(spec, Mapping) else None
    if not isinstance(discovery, Mapping):
        raise RegistryError("Catalog has no native discovery contract")
    if (
        discovery.get("mode") != "manifest-roots"
        or discovery.get("canonicalIdentity") != "metadata"
        or discovery.get("manifestPattern") != "*.yaml"
        or discovery.get("recursive") is not False
    ):
        raise RegistryError("Catalog discovery contract is not supported")
    roots = discovery.get("roots")
    if not isinstance(roots, Mapping) or dict(roots) != _DISCOVERY_ROOTS:
        raise RegistryError("Catalog discovery roots differ from the supported native roots")
    return dict(roots)


@dataclass(frozen=True, slots=True)
class NativeDiscovery:
    resources: tuple[ResolvedResource, ...]
    catalog_version: str
    source_revision: str
    root_counts: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class NativeResourceBinding:
    """A source declaration mapped to a real native destination or a named adapter."""

    resource_id: str
    kind: str
    version: str
    source_path: str
    native_path: str | None
    adapter_id: str | None
    discoverability: str
    invocation: str
    blockers: tuple[str, ...] = ()
    readiness: Mapping[str, bool] | None = None


_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,95}$")
_STANDALONE_HERMES = re.compile(r"(?<![A-Za-z0-9_-])Hermes(?![A-Za-z0-9_-])")

# The Resources registry keeps its stable source identity.  The only source
# profile authorized as the native user entry is projected onto Hermes'
# canonical default profile; the other source identities remain registry IDs
# and are resolved by the protected internal-home router.
PRIMARY_USER_SOURCE_PROFILE_ID = "hermes"
PRIMARY_NATIVE_PROFILE_KEY = "default"
PRIMARY_USER_DISPLAY_NAME = "Jarvis"


def _jarvis_identity_text(value: Any) -> Any:
    """Rename human-facing primary identity text without changing source IDs."""
    if isinstance(value, str):
        return _STANDALONE_HERMES.sub(PRIMARY_USER_DISPLAY_NAME, value)
    if isinstance(value, list):
        return [_jarvis_identity_text(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_jarvis_identity_text(item) for item in value)
    if isinstance(value, Mapping):
        return {key: _jarvis_identity_text(item) for key, item in value.items()}
    return value


def effective_native_profile_spec(profile_id: str, spec: Mapping[str, Any]) -> dict[str, Any]:
    """Return digestable native instructions with the primary name adapted."""
    effective = deepcopy(dict(spec))
    return (_jarvis_identity_text(effective)
            if profile_id == PRIMARY_USER_SOURCE_PROFILE_ID else effective)


def _profile_files(item: ResolvedResource, source_path: str, source_document: Mapping[str, Any]) -> dict[str, bytes]:
    """Compile a registry profile into an isolated Hermes HERMES_HOME."""
    import yaml

    name = item.resource.id
    if not _PROFILE_NAME.fullmatch(name):
        raise RegistryError(f"profile name cannot be represented as a Hermes profile: {name}")
    spec = effective_native_profile_spec(name, item.effective_spec or item.resource.body)
    content_sections = []
    for field, value in spec.items():
        if field in {"extends", "requires"}:
            continue
        heading = "Role instructions" if field == "instructions" else str(field).replace("_", " ").replace("-", " ").title()
        if isinstance(value, str):
            rendered = value.strip()
        elif isinstance(value, (list, tuple)) and all(isinstance(part, str) for part in value):
            rendered = "\n".join(f"- {part.strip()}" for part in value if part.strip())
        else:
            rendered = "```yaml\n" + yaml.safe_dump(value, sort_keys=False, allow_unicode=True).rstrip() + "\n```"
        if rendered:
            content_sections.append(f"## {heading}\n\n{rendered}")
    if not content_sections:
        content_sections.append("## Complete registry profile declaration\n\n```yaml\n" + yaml.safe_dump(dict(spec), sort_keys=False, allow_unicode=True).rstrip() + "\n```")
    metadata = source_document.get("metadata", {})
    description = metadata.get("description", "") if isinstance(metadata, Mapping) else ""
    if not isinstance(description, str):
        description = ""
    if name == PRIMARY_USER_SOURCE_PROFILE_ID:
        description = _jarvis_identity_text(description)
    native_title = (PRIMARY_USER_DISPLAY_NAME if name == PRIMARY_USER_SOURCE_PROFILE_ID
                    else name.replace('-', ' ').replace('_', ' ').title())
    display_name = native_title
    soul = (
        f"# {native_title}\n\n"
        + (f"{description.strip()}\n\n" if description.strip() else "")
        + "\n\n".join(content_sections)
        + "\n\n## Complete registry profile declaration\n\n"
        + "```yaml\n"
        + yaml.safe_dump(dict(spec), sort_keys=False, allow_unicode=True)
        + "```\n"
        + f"\n<!-- Source: {source_path}; version: {item.resource.version}; revision: {item.resource.source_revision} -->\n"
    )
    metadata = {"description": description, "display_name": display_name}
    return {
        f"homes/profiles/{name}/SOUL.md": soul.encode("utf-8"),
        f"homes/profiles/{name}/config.yaml": b"{}\n",
        f"homes/profiles/{name}/profile.yaml": yaml.safe_dump(metadata, sort_keys=False, allow_unicode=True).encode("utf-8"),
    }


def _skill_file(item: ResolvedResource, source_path: str, source_document: Mapping[str, Any]) -> tuple[str, bytes]:
    """Compile the complete declarative procedure into Hermes' SKILL.md format."""
    import yaml

    name = item.resource.id
    if not _SKILL_NAME.fullmatch(name):
        raise RegistryError(f"skill name cannot be represented as a Hermes skill: {name}")
    spec = item.effective_spec or item.resource.body
    # Resource skills use several reviewed content shapes (procedure,
    # workflow, instructions, principles, verification, and structured policy
    # fields). Render each effective field into the native skill body instead
    # of silently dropping non-procedure forms. The complete YAML remains below
    # as a lossless record for fields that are not prose.
    body_sections = []
    for field, value in spec.items():
        if field in {"extends", "requires"}:
            continue
        heading = str(field).replace("_", " ").replace("-", " ").title()
        if isinstance(value, str):
            rendered = value.strip()
        elif isinstance(value, (list, tuple)) and all(isinstance(part, str) for part in value):
            rendered = "\n".join(f"- {part.strip()}" for part in value if part.strip())
        else:
            rendered = "```yaml\n" + yaml.safe_dump(value, sort_keys=False, allow_unicode=True).rstrip() + "\n```"
        if rendered:
            body_sections.append(f"## {heading}\n\n{rendered}")
    body = "\n\n".join(body_sections)
    if not body:
        body = "## Complete registry procedure\n\n```yaml\n" + yaml.safe_dump(dict(spec), sort_keys=False, allow_unicode=True).rstrip() + "\n```"
    metadata = source_document.get("metadata", {})
    description = metadata.get("description", "") if isinstance(metadata, Mapping) else ""
    if not isinstance(description, str) or not description.strip():
        raise RegistryError(f"skill has no usable description for native discovery: {name}")
    frontmatter = yaml.safe_dump({"name": name, "description": description.strip()}, sort_keys=False, allow_unicode=True).rstrip()
    return f"homes/skills/{name}/SKILL.md", (
        f"---\n{frontmatter}\n---\n\n{body}\n\n"
        + "## Complete registry skill declaration\n\n```yaml\n"
        + yaml.safe_dump(dict(spec), sort_keys=False, allow_unicode=True)
        + "```\n\n"
        f"<!-- Source: {source_path}; version: {item.resource.version}; revision: {item.resource.source_revision} -->\n"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class NativeRegistry:
    source: VerifiedSource
    resolver: RegistryResolver
    paths: Mapping[str, str]
    catalog: Mapping[str, Any]
    root_counts: Mapping[str, int]

    @classmethod
    def from_verified_source(cls, source: VerifiedSource) -> "NativeRegistry":
        catalog = _load(source.files["catalog.yaml"])
        if not isinstance(catalog, Mapping) or catalog.get("kind") != "Catalog":
            raise RegistryError("verified snapshot has no valid Hermes Catalog")
        roots = _declared_roots(catalog)
        spec = catalog.get("spec")
        if not isinstance(spec, Mapping):
            raise RegistryError("Catalog spec is invalid")

        policy: dict[str, Any] = {"domainOverlays": []}
        quality_paths = spec.get("qualityPolicyFiles")
        if not isinstance(quality_paths, (list, tuple)) or not quality_paths:
            raise RegistryError("Catalog has no quality policy files")
        for quality_path in quality_paths:
            if not isinstance(quality_path, str) or quality_path not in source.files:
                raise RegistryError("quality policy is outside verified source")
            doc = _load(source.files[quality_path])
            if (
                not isinstance(doc, Mapping)
                or doc.get("kind") != "RegistryQualityPolicy"
                or not isinstance(doc.get("spec"), Mapping)
            ):
                raise RegistryError(f"invalid quality policy: {quality_path}")
            quality_spec = doc["spec"]
            overlays = quality_spec.get("domainOverlays") or []
            if not isinstance(overlays, (list, tuple)):
                raise RegistryError("domainOverlays must be a list")
            policy = _merge_policy_values(
                policy, {key: value for key, value in quality_spec.items() if key != "domainOverlays"}
            )
            policy["domainOverlays"] = list(policy.get("domainOverlays", ())) + list(overlays)

        raw: dict[str, RawResource] = {}
        paths: dict[str, str] = {}
        counts: dict[str, int] = {}
        for resource_kind, root in sorted(roots.items(), key=lambda item: item[1]):
            entries = sorted(
                path
                for path in source.files
                if path.startswith(root + "/")
                and path.count("/") == 1
                and path.endswith(".yaml")
            )
            counts[root] = len(entries)
            for path in entries:
                doc = _load(source.files[path])
                if not isinstance(doc, Mapping) or doc.get("apiVersion") != "hermes.togarriapa/v1":
                    raise RegistryError(f"manifest envelope has an unsupported apiVersion: {path}")
                if doc.get("kind") != resource_kind or not isinstance(doc.get("metadata"), Mapping):
                    raise RegistryError(f"manifest envelope kind does not match catalog root: {path}")
                metadata = doc["metadata"]
                name, version = metadata.get("name"), metadata.get("version")
                if (
                    not isinstance(name, str)
                    or not isinstance(version, str)
                    or path.rsplit("/", 1)[-1] != name + ".yaml"
                    or not isinstance(doc.get("spec"), Mapping)
                ):
                    raise RegistryError(f"manifest identity or spec is invalid: {path}")
                key = f"{root}/{name}@{version}"
                if key in raw:
                    raise RegistryError(f"duplicate manifest identity/version: {key}")
                raw[key] = RawResource(
                    name,
                    root,
                    version,
                    doc,
                    source.repository,
                    source.revision,
                    source.revision,
                    RegistryResolver.document_digest(doc),
                )
                paths[key] = path

        resolver = RegistryResolver(
            raw,
            source_verifier=lambda repository, revision: (
                repository == source.repository and revision == source.revision
            ),
            quality_policy=policy,
        )
        return cls(source, resolver, paths, catalog, counts)

    def discover(self, selectors: tuple[str, ...] | list[str]) -> NativeDiscovery:
        return NativeDiscovery(
            self.resolver.resolve(selectors),
            self.source.catalog_version,
            self.source.revision,
            dict(self.root_counts),
        )

    def discover_all(self) -> NativeDiscovery:
        return self.discover(tuple(sorted(self.resolver.raw)))

    def _runtime_artifact(self, item: ResolvedResource):
        from .resources_runtime import materialize_runtime_resource

        kind = item.resource.kind.value
        key = f"{kind}/{item.resource.id}@{item.resource.version}"
        effective = dict(item.effective_spec or item.resource.body)
        if kind == "crons" and item.resource.id in {"resource-sync", "daily-resource-reconcile"}:
            action = effective.get("action")
            if not isinstance(action, Mapping):
                raise RegistryError(f"bundled update cron has no action mapping: {item.resource.id}")
            action = dict(action)
            action.pop("repository", None)
            action.pop("ref", None)
            action["type"] = "installer-resource-candidate-assessment"
            action["source"] = {
                "kind": "installer-bundle",
                "path": f"resources/vendor/hermes-agent-resources-{self.source.catalog_version}",
                "catalogVersion": self.source.catalog_version,
                "revision": self.source.revision,
            }
            action["mode"] = "candidate-assessment"
            effective["action"] = action
        return materialize_runtime_resource(
            kind=kind,
            resource_id=item.resource.id,
            version=item.resource.version,
            source_path=self.paths[key],
            source_document=self.resolver.raw[key].document,
            effective_spec=effective,
            source_revision=self.source.revision,
            catalog_version=self.source.catalog_version,
        )

    def crosswalk(self, discovery: NativeDiscovery | None = None) -> tuple[NativeResourceBinding, ...]:
        """Return one explicit native binding or actionable incomplete reason per declaration."""
        selected = discovery or self.discover_all()
        bindings: list[NativeResourceBinding] = []
        for item in selected.resources:
            kind, name, version = item.resource.kind.value, item.resource.id, item.resource.version
            key = f"{kind}/{name}@{version}"
            source_path = self.paths[key]
            readiness = {
                "bundled": True, "validated": True, "materialized": False,
                "discovered": False, "authenticated": False, "functional": False,
                "enabled": False, "target_verified": False,
            }
            if kind == "profiles":
                # Hermes' canonical default identity lives at HERMES_HOME
                # itself; named identities live under profiles/<id>/.
                native_path = ("." if name == PRIMARY_USER_SOURCE_PROFILE_ID
                               else f"profiles/{name}")
                adapter_id = "hermes.isolated-home.v1"
                discoverability = "Hermes native HERMES_HOME selected by the internal orchestrator"
                invocation = "orchestrator-internal-profile.v1"
                blockers = ("Native profile discovery and guarded workflow invocation remain pending target evidence.",)
                readiness["materialized"] = True
            elif kind == "skills":
                native_path = f"skills/{name}/SKILL.md"
                adapter_id = "hermes.skill-directory.v1"
                discoverability = "Hermes SKILL.md discovery"
                invocation = "Hermes native on-demand skill loader"
                blockers = ("Native skill discovery and selected workflow invocation remain pending target evidence.",)
                readiness["materialized"] = True
            else:
                runtime = self._runtime_artifact(item)
                native_path = runtime.native_path
                adapter_id = runtime.adapter_id
                discoverability = runtime.discoverability
                invocation = runtime.invocation
                blockers = runtime.blockers
                if kind == "plugins" and not runtime.readiness.materialized:
                    blockers = tuple(blockers) + (
                        "Reviewed handler is not packaged as a guarded native plugin module for this selected profile.",
                    )
                readiness.update({
                    "materialized": runtime.readiness.materialized,
                    "discovered": runtime.readiness.discovered,
                    "authenticated": runtime.readiness.authenticated,
                    "functional": runtime.readiness.functional,
                    "enabled": runtime.readiness.enabled,
                    "target_verified": runtime.readiness.target_verified,
                })
            bindings.append(NativeResourceBinding(
                resource_id=name,
                kind=kind,
                version=version,
                source_path=source_path,
                native_path=native_path,
                adapter_id=adapter_id,
                discoverability=discoverability,
                invocation=invocation,
                blockers=blockers,
                readiness=readiness,
            ))
        return tuple(bindings)

    def materialize(self, discovery: NativeDiscovery | None = None) -> dict[str, bytes]:
        import copy
        import json

        yaml = _yaml()
        selected = discovery or self.discover_all()
        out: dict[str, bytes] = {}
        bindings = self.crosswalk(selected)
        for item in selected.resources:
            key = f"{item.resource.kind.value}/{item.resource.id}@{item.resource.version}"
            doc = copy.deepcopy(dict(self.resolver.raw[key].document))
            effective = copy.deepcopy(dict(item.effective_spec or item.resource.body))
            # These bundled scheduled jobs used to fetch Togarriapa/HermesAgent_Resources.
            # The runtime form now addresses the Installer-owned immutable snapshot and
            # cannot fall back to the original repository or a moving branch.
            if item.resource.kind.value == "crons" and item.resource.id in {
                "resource-sync",
                "daily-resource-reconcile",
            }:
                action = effective.get("action")
                if not isinstance(action, Mapping):
                    raise RegistryError(f"bundled update cron has no action mapping: {item.resource.id}")
                action = dict(action)
                action.pop("repository", None)
                action.pop("ref", None)
                action["type"] = "installer-resource-candidate-assessment"
                action["source"] = {
                    "kind": "installer-bundle",
                    "path": f"resources/vendor/hermes-agent-resources-{self.source.catalog_version}",
                    "catalogVersion": self.source.catalog_version,
                    "revision": self.source.revision,
                }
                action["mode"] = "candidate-assessment"
                effective["action"] = action
            doc["spec"] = effective
            metadata = dict(doc.get("metadata") or {})
            annotations = dict(metadata.get("annotations") or {})
            annotations.update(
                {
                    "hermes.togarriapa/installer-source-revision": self.source.revision,
                    "hermes.togarriapa/quality-policy-applied": "true",
                    "hermes.togarriapa/host-authorization-applied": "false",
                    "hermes.togarriapa/secrets-resolved": "false",
                }
            )
            metadata["annotations"] = annotations
            doc["metadata"] = metadata
            out[self.paths[key]] = yaml.safe_dump(
                doc, sort_keys=False, allow_unicode=True
            ).encode("utf-8")

        # Profiles and skills become artifacts Hermes actually discovers. The
        # original declarations above remain alongside them for provenance and
        # later adapters; other kinds remain explicitly inventoried as pending.
        ledger: list[dict[str, Any]] = []
        for item, binding in zip(selected.resources, bindings, strict=True):
            key = f"{binding.kind}/{binding.resource_id}@{binding.version}"
            if binding.kind == "profiles":
                out.update(_profile_files(item, binding.source_path, self.resolver.raw[key].document))
            elif binding.kind == "skills":
                path, content = _skill_file(item, binding.source_path, self.resolver.raw[key].document)
                out[path] = content
            else:
                source_key = f"{binding.kind}/{binding.resource_id}@{binding.version}"
                source_doc = copy.deepcopy(dict(self.resolver.raw[source_key].document))
                declaration_path = f"installer-registry/declarations/{binding.kind}/{binding.resource_id}.yaml"
                out[declaration_path] = yaml.safe_dump(source_doc, sort_keys=False, allow_unicode=True).encode("utf-8")
                runtime = self._runtime_artifact(item)
                out.update(runtime.files)
            ledger.append({
                "id": binding.resource_id,
                "kind": binding.kind,
                "version": binding.version,
                "source": {"path": binding.source_path, "revision": self.source.revision},
                "native": {"path": binding.native_path, "adapter": binding.adapter_id},
                "discoverability": binding.discoverability,
                "invocation": binding.invocation,
                "readiness": dict(binding.readiness or {}),
                "blockers": list(binding.blockers),
            })

        # Hermes scans HERMES_HOME/skills. A selected profile resolution
        # includes only its dependency closure, so only those files are staged.
        skill_files = {
            f"skills/{item.resource.id}/SKILL.md": _skill_file(
                item,
                self.paths[f"skills/{item.resource.id}@{item.resource.version}"],
                self.resolver.raw[f"skills/{item.resource.id}@{item.resource.version}"].document,
            )[1]
            for item in selected.resources if item.resource.kind.value == "skills"
        }
        native_files = []
        for staged_path in sorted(path for path in out if path.startswith("homes/")):
            if staged_path.startswith("homes/profiles/"):
                target_path = "profiles/" + staged_path.removeprefix("homes/profiles/")
            elif staged_path.startswith("homes/skills/"):
                target_path = "skills/" + staged_path.removeprefix("homes/skills/")
            else:
                raise RegistryError(f"native staged path is outside supported Hermes roots: {staged_path}")
            native_files.append({"staged": staged_path, "target": target_path, "conflict_policy": "preserve-existing"})

        out["installer-registry/crosswalk.json"] = (
            json.dumps({
                "schema": 1,
                "source": {"repository": self.source.repository, "revision": self.source.revision,
                           "catalog_version": self.source.catalog_version},
                "items": ledger,
                "native_materialization": {
                    "schema": 1,
                    "destination_root": "data_root",
                    "preserve_existing": True,
                    "files": native_files,
                },
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        )

        if not out:
            raise RegistryError("refusing to materialize an empty selection")
        # Keep the native discovery contract and policy document beside the
        # effective roots so Hermes can discover the selected manifests offline.
        out["catalog.yaml"] = self.source.files["catalog.yaml"]
        for quality_path in self.catalog["spec"]["qualityPolicyFiles"]:
            out[quality_path] = self.source.files[quality_path]
        return out

    def stage(self, store: Any, generation_id: str, discovery: NativeDiscovery | None = None):
        files = self.materialize(discovery)
        return store.stage(generation_id, files)
