"""Typed raw, resolved, authorized and runtime registry transitions."""
from __future__ import annotations
import hashlib, json, re, time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from .types import Resource, ResourceKind

class RegistryError(ValueError):
    """Invalid resource source, graph, policy, or runtime transition."""

@dataclass(frozen=True, slots=True)
class RawResource:
    identity: str
    kind: str
    version: str
    document: Mapping[str, Any]
    repository: str
    selected_revision: str
    observed_revision: str
    content_digest: str

@dataclass(frozen=True, slots=True)
class ResolvedResource:
    resource: Resource
    dependencies: tuple[str, ...]
    provenance_verified: bool = True

@dataclass(frozen=True, slots=True)
class AuthorizationLease:
    subject: str
    profile_id: str
    namespace: str
    capabilities: frozenset[str]
    issued_at: float
    expires_at: float
    policy_revision: str
    grant_id: str

@dataclass(frozen=True, slots=True)
class AuthorizedResource:
    resolved: ResolvedResource
    lease: AuthorizationLease
    capabilities: frozenset[str]
    denied: tuple[str, ...] = ()
    @property
    def resource(self): return self.resolved.resource

@dataclass(frozen=True, slots=True)
class RuntimeResource:
    authorized: AuthorizedResource
    configured: bool
    healthy: bool
    runtime_revision: str
    activated_at: float
    @property
    def resource(self): return self.authorized.resource

@dataclass(frozen=True, slots=True)
class ResourceEvidence:
    downloaded: bool = False
    installed: bool = False
    discoverable: bool = False
    configured: bool = False
    authenticated: bool = False
    reachable: bool = False
    functionally_tested: bool = False
    enabled: bool = False
    actual_target_revision: str | None = None
    broker_healthy: bool = False
    host_authorization_fresh: bool = False

_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_CLAUSE = re.compile(r"(\^|~|>=|<=|>|<|=)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)")

def _parts(value):
    match = _VERSION.fullmatch(value)
    if not match: raise RegistryError(f"invalid semantic version: {value!r}")
    return (int(match[1]), int(match[2]), int(match[3])), tuple(match[4].split(".")) if match[4] else None

def _compare(left, right):
    a, ap = _parts(left); b, bp = _parts(right)
    if a != b: return (a > b) - (a < b)
    if ap is None or bp is None: return 0 if ap is bp else (1 if ap is None else -1)
    for x, y in zip(ap, bp):
        if x == y: continue
        if x.isdigit() and y.isdigit(): return (int(x) > int(y)) - (int(x) < int(y))
        if x.isdigit() != y.isdigit(): return -1 if x.isdigit() else 1
        return (x > y) - (x < y)
    return (len(ap) > len(bp)) - (len(ap) < len(bp))

def satisfies(version: str, expression: str) -> bool:
    _parts(version)
    if expression in {"", "*"}: return True
    clauses = expression.split()
    if not clauses: raise RegistryError("empty version constraint")
    for clause in clauses:
        match = _CLAUSE.fullmatch(clause)
        if not match: raise RegistryError(f"unsupported version constraint {expression!r}")
        op, target = match.groups(); op = op or "="
        cmp = _compare(version, target)
        if op == "=" and cmp != 0 or op == ">=" and cmp < 0 or op == ">" and cmp <= 0 or op == "<=" and cmp > 0 or op == "<" and cmp >= 0:
            return False
        if op in {"^", "~"}:
            (major, minor, patch), _ = _parts(target)
            upper = f"{major+1}.0.0" if op == "^" and major else f"0.{minor+1}.0" if op == "^" and minor else f"0.0.{patch+1}" if op == "^" else f"{major}.{minor+1}.0"
            if cmp < 0 or _compare(version, upper) >= 0: return False
    return True

class RegistryResolver:
    def __init__(self, resources: Mapping[str, RawResource], *, now: Callable[[], float] = time.time):
        self.raw = dict(resources)
        self.now = now

    @staticmethod
    def document_digest(document: Mapping[str, Any]) -> str:
        try: raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        except (TypeError, ValueError): raise RegistryError("resource document is not canonical JSON data") from None
        return hashlib.sha256(b"registry-resource-v1\0" + len(raw).to_bytes(8, "big") + raw).hexdigest()

    @staticmethod
    def _selectors(values, label):
        if not isinstance(values, (list, tuple)): raise RegistryError(f"{label} must be a list")
        result = []
        for value in values:
            if not isinstance(value, str) or not value: raise RegistryError(f"{label} selector must be text")
            identity, marked, expression = value.partition("@")
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identity): raise RegistryError(f"invalid identity {identity!r}")
            if marked: satisfies("0.0.0", expression)
            result.append((identity, expression if marked else "*"))
        return tuple(result)

    def _parse(self, raw: RawResource) -> Resource:
        if raw.selected_revision != raw.observed_revision or not re.fullmatch(r"[a-fA-F0-9]{40,64}", raw.selected_revision):
            raise RegistryError(f"source revision was not verified: {raw.identity}")
        if not raw.repository.startswith("https://") or "@" in raw.repository:
            raise RegistryError("resource repository must use HTTPS without embedded credentials")
        if self.document_digest(raw.document) != raw.content_digest: raise RegistryError(f"resource digest mismatch: {raw.identity}")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", raw.identity): raise RegistryError("invalid resource identity")
        try: kind = ResourceKind(raw.kind)
        except ValueError: raise RegistryError(f"unknown registry root kind: {raw.kind}") from None
        _parts(raw.version)
        spec = raw.document.get("spec", {})
        if not isinstance(spec, Mapping): raise RegistryError("spec must be a mapping")
        requires = self._selectors(spec.get("requires", []), "requires")
        inherits = self._selectors(spec.get("inherits", []), "inherits")
        caps = spec.get("capabilities", [])
        if not isinstance(caps, (list, tuple)) or any(not isinstance(cap, str) or not cap for cap in caps):
            raise RegistryError("capabilities must be non-empty strings")
        return Resource(raw.identity, kind, raw.version, dict(spec), raw.selected_revision,
            tuple(key for key, _ in requires), tuple(key for key, _ in inherits), frozenset(caps), raw.content_digest)

    def resolve(self, selectors: Iterable[str]) -> tuple[ResolvedResource, ...]:
        catalog = {}
        for raw in self.raw.values():
            item = self._parse(raw)
            catalog.setdefault(item.id, []).append(item)
        for versions in catalog.values(): versions.sort(key=lambda item: item.version, reverse=True)
        ordered, visited, visiting = [], set(), set()
        def choose(identity, expression):
            compatible = [item for item in catalog.get(identity, []) if satisfies(item.version, expression)]
            if not compatible: raise RegistryError(f"no compatible version for {identity}@{expression}")
            return max(compatible, key=lambda item: _SemverSort(item.version))
        def visit(identity, expression):
            item = choose(identity, expression); node = item.id, item.version
            if node in visiting: raise RegistryError(f"dependency/inheritance cycle: {item.id}@{item.version}")
            if node in visited: return
            visiting.add(node)
            refs = self._selectors(item.body.get("requires", []), "requires") + self._selectors(item.body.get("inherits", []), "inherits")
            chosen = []
            for dep, constraint in refs:
                child = choose(dep, constraint); chosen.append(f"{child.id}@{child.version}"); visit(dep, constraint)
            visiting.remove(node); visited.add(node); ordered.append(ResolvedResource(item, tuple(chosen)))
        for selector in selectors:
            if not isinstance(selector, str) or not selector: raise RegistryError("selector must be id[@semver]")
            identity, marked, expression = selector.partition("@")
            visit(identity, expression if marked else "*")
        return tuple(ordered)

    def authorize(self, resources: Iterable[ResolvedResource], *, profile_id: str, namespace: str, subject: str,
                  host_capabilities: Iterable[str], lease_provider: Callable[[ResolvedResource, str, str, str], AuthorizationLease]):
        now, host, output = self.now(), frozenset(host_capabilities), []
        for item in resources:
            lease = lease_provider(item, profile_id, namespace, subject)
            if (not item.provenance_verified or lease.subject != subject or lease.profile_id != profile_id or lease.namespace != namespace
                or lease.issued_at > now or lease.expires_at <= now or not lease.policy_revision or not lease.grant_id):
                raise RegistryError(f"fresh matching runtime authorization required for {item.resource.id}")
            allowed = item.resource.capabilities & host & lease.capabilities
            output.append(AuthorizedResource(item, lease, frozenset(allowed), tuple(sorted(item.resource.capabilities - allowed))))
        return tuple(output)

    def activate(self, resources: Iterable[AuthorizedResource], *, configure, health_check, runtime_revision: str):
        if not runtime_revision: raise RegistryError("runtime revision required")
        output = []
        for item in resources:
            if item.denied: raise RegistryError(f"capabilities denied for {item.resource.id}: {item.denied}")
            if item.lease.expires_at <= self.now(): raise RegistryError("authorization expired before activation")
            if not configure(item): raise RegistryError(f"configuration failed: {item.resource.id}")
            if not health_check(item): raise RegistryError(f"health check failed: {item.resource.id}")
            output.append(RuntimeResource(item, True, True, runtime_revision, self.now()))
        return tuple(output)

    @staticmethod
    def readiness(evidence: Mapping[str, ResourceEvidence], required: Iterable[str]):
        order = ("downloaded", "installed", "discoverable", "configured", "authenticated", "reachable", "functionally_tested", "enabled")
        states = {}
        for identity, facts in evidence.items():
            state = "not_downloaded"
            for name in order:
                if not getattr(facts, name): break
                state = name
            if facts.functionally_tested and facts.actual_target_revision: state = "actual_target_verified"
            states[identity] = state
        required = tuple(required)
        complete = bool(required) and all(identity in evidence and evidence[identity].functionally_tested
            and evidence[identity].enabled and evidence[identity].actual_target_revision
            and evidence[identity].broker_healthy and evidence[identity].host_authorization_fresh for identity in required)
        return {"resources": states, "full_registry_compliance": bool(complete)}

class _SemverSort:
    """Comparable wrapper retaining prerelease semantics for max()."""
    def __init__(self, value): self.value = value
    def __lt__(self, other): return _compare(self.value, other.value) < 0
