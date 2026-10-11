"""Root-held source receipts for the finite application qualification effects.

The receipts in this module prove exact installer release membership and
current bytes. They do not prove module import, application ABI, or a
successful effect. Those facts have separate observers.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .application_effect_source_catalog import (
    APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID,
    APPLICATION_EFFECT_SOURCE_CATALOG_PATH,
    APPLICATION_EFFECT_SOURCE_CATALOG_SHA256,
    APPLICATION_EFFECT_SOURCE_CATALOG_SIZE,
    APPLICATION_EFFECT_SOURCE_MEMBERS,
)
from .types import AuthorityDenied, canonical_bytes

_RECEIPT_SEAL = object()
_MAX_CATALOG_BYTES = 32 * 1024
_MAX_MEMBER_BYTES = 128 * 1024
_OPAQUE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _valid_handle(value: Any) -> bool:
    return (isinstance(value, str) and 32 <= len(value) <= 128
            and all(char in _OPAQUE for char in value))


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationEffectSourceReceipt:
    """Opaque membership for one pinned effect asset or its signed catalog."""

    schema: int
    member_id: str
    application_id: str
    workflow_id: str
    artifact_id: str
    relative_path: str
    role: str
    sha256: str
    size_bytes: int
    release_commit: str
    deployment_receipt_sha256: str
    release_selection_handle: str
    source_preparation_selection_handle: str
    setup_session_id: str
    prepared_generation_id: str
    service_generation_digest: str
    context_sha256: str
    source_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _receipt_seal: object = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._receipt_seal is not _RECEIPT_SEAL:
            raise TypeError("application effect source receipts are minted by the root setup session")

    def read_current(self) -> bytes:
        return self._session._read_application_effect_source_receipt(self)


@dataclass(slots=True)
class _EffectSourceSet:
    context: Any
    recipe: Any
    selection: Any
    source: Any
    lock: Any
    runtime_preparation: Any
    receipts: Mapping[str, RootApplicationEffectSourceReceipt]
    release_selection_handle: str
    source_receipt_handles: tuple[str, ...]
    member_receipt_handles: tuple[tuple[str, str], ...]
    source_closure_sha256: str
    expires_monotonic: float


class RootApplicationEffectSourceObserver:
    """Resolve exact v175 source roles through the live held installer release."""

    def __init__(self, session: Any, *, monotonic: Any = time.monotonic):
        if not callable(monotonic):
            raise ValueError("application effect source observer clock is invalid")
        self._session = session
        self._clock = monotonic
        self._sets: dict[tuple[str, str], _EffectSourceSet] = {}
        self._receipts: dict[str, RootApplicationEffectSourceReceipt] = {}

    def _current_selection(self, context: Any, recipe: Any) -> tuple[Any, Any, Any, Any, Any]:
        from .application_probe_recipes import (
            ApplicationQualificationEffectRecipe,
            resolve_application_qualification_effect_recipe_for_selection,
        )
        from .application_workload_execution import RootApplicationQualificationContext

        if (type(context) is not RootApplicationQualificationContext
                or type(recipe) is not ApplicationQualificationEffectRecipe):
            raise AuthorityDenied("application.effect.source", "root qualification context or fixed recipe is unavailable")
        session = self._session
        session._check_live()
        session._refresh_authorization()
        session._verify_current_setup_controller()
        prepared = session._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle
                or context.setup_session_id != session._handle.session_id):
            raise AuthorityDenied("application.effect.source", "current prepared setup custody is unavailable")

        source_registry = session._application_source_preparation_registry
        if source_registry is None:
            raise AuthorityDenied("application.effect.source", "root application source selector is unavailable")
        selection = source_registry.resolve_selection(context.source_preparation_selection_handle)
        expected_recipe = resolve_application_qualification_effect_recipe_for_selection(selection)
        if (expected_recipe != recipe or selection.setup_session_id != context.setup_session_id
                or selection.prepared_generation_id != prepared.generation_id
                or selection.prepared_generation_digest != prepared.generation_digest
                or selection.application_id != context.application_id
                or selection.workflow_id != recipe.workflow_id
                or selection.source_identity != recipe.source_identity
                or selection.source_revision != recipe.source_revision
                or selection.target_profile_id != context.profile_id
                or context.qualification_choice_handle != selection.qualification_choice_handle):
            raise AuthorityDenied("application.effect.source", "effect recipe no longer matches the root source selection")

        choice = session.resolve_application_setup_choice(context.qualification_choice_handle)
        principal_selector = session.resolve_adopted_principal_selector()
        namespace_selector = session.resolve_adopted_namespace_selector()
        current_identity = session.resolve_current_setup_identity()
        if (choice.setup_session_id != context.setup_session_id
                or choice.application_id != context.application_id
                or choice.workflow_id != recipe.workflow_id
                or choice.controller_binding_handle != context.controller_binding_handle
                or choice.prepared_generation_id != prepared.generation_id
                or choice.prepared_generation_digest != prepared.generation_digest
                or choice.principal_selection_handle != principal_selector.selection_handle
                or choice.namespace_selection_handle != namespace_selector.selection_handle
                or choice.principal_binding_sha256 != principal_selector.binding_sha256
                or choice.namespace_binding_sha256 != namespace_selector.binding_sha256
                or current_identity.principal_selection_handle != principal_selector.selection_handle
                or current_identity.namespace_selection_handle != namespace_selector.selection_handle
                or current_identity.principal_binding_sha256 != principal_selector.binding_sha256
                or current_identity.namespace_binding_sha256 != namespace_selector.binding_sha256):
            raise AuthorityDenied("application.effect.source", "current setup choice identity or controller changed")

        principal = session.resolve_adopted_principal_selection()
        namespace = session.resolve_adopted_namespace_selection()
        if (principal.principal_id != context.principal_id
                or principal.receipt_id != context.principal_selection_receipt_handle
                or namespace.namespace_id != context.namespace_id
                or namespace.receipt_handle != context.namespace_selection_receipt_handle
                or namespace.target_profile_id != context.profile_id
                or namespace.principal_selection_receipt_id != principal.receipt_id):
            raise AuthorityDenied("application.effect.source", "current principal or namespace selection changed")

        source = source_registry.resolve_prepared_source(context.prepared_source_receipt_handle)
        lock = source_registry.resolve_application_lock_receipt(
            context.selected_lock_receipt_handle,
            preparation_selection_handle=selection.selection_handle,
            prepared_source_receipt_handle=source.receipt_handle,
        )
        if (source.selection_handle != selection.selection_handle
                or source.source_generation_manifest_sha256 != context.source_generation_manifest_sha256
                or lock.lock_sha256 != context.lock_sha256
                or lock.source_receipt_handle != source.receipt_handle):
            raise AuthorityDenied("application.effect.source", "upstream source or lock evidence changed")
        runtime_preparation = session._resolve_application_runtime_preparation_selection(
            context.runtime_preparation_selection_handle)
        if (runtime_preparation.application_id != context.application_id
                or runtime_preparation.source_receipt_handle != source.receipt_handle
                or runtime_preparation.selected_lock_receipt_handle != lock.receipt_handle
                or runtime_preparation.profile_id != context.profile_id
                or runtime_preparation.profile_generation != context.profile_generation
                or runtime_preparation.service_selection_digest != context.enclosing_service_generation_digest
                or runtime_preparation.runtime_manifest_sha256 != context.runtime_manifest_sha256):
            raise AuthorityDenied("application.effect.source", "current runtime preparation does not match qualification")
        if (context.prepared_source_receipt_handle not in context.source_receipt_handles
                or not context.source_receipt_handles
                or len(set(context.source_receipt_handles)) != len(context.source_receipt_handles)
                or any(not _valid_handle(handle) for handle in context.source_receipt_handles)):
            raise AuthorityDenied("application.effect.source", "upstream source receipt lineage is malformed")
        return selection, source, lock, runtime_preparation, prepared

    @staticmethod
    def _read_fd(release: Any, row: Any, *, limit: int) -> bytes:
        fd = release.open_file(row.artifact_id)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (row.device, row.inode)
                    or info.st_size != row.size_bytes or stat.S_IMODE(info.st_mode) != row.mode
                    or info.st_size > limit):
                raise AuthorityDenied("application.effect.source", "held release member descriptor changed")
            data = bytearray()
            while len(data) <= row.size_bytes:
                block = os.read(fd, min(64 * 1024, row.size_bytes + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if (len(data) != row.size_bytes
                    or hashlib.sha256(data).hexdigest() != row.sha256):
                raise AuthorityDenied("application.effect.source", "held release member bytes changed")
            return bytes(data)
        finally:
            os.close(fd)

    def _catalog_and_rows(self, recipe: Any) -> tuple[bytes, tuple[Any, ...], Any, Any]:
        from .application_probe_recipes import ApplicationQualificationEffectRecipe

        if type(recipe) is not ApplicationQualificationEffectRecipe:
            raise AuthorityDenied("application.effect.source", "selected effect recipe is not typed")
        session = self._session
        release, actor = session._factory._release, session._factory._actor
        actor.verify_current(release)
        release.verify_current()
        plan = session._factory.resolver.resolve(session._authorization.plan_artifact_id)
        files = release.files
        catalog_rows = [row for row in files
                        if row.artifact_id == APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID]
        if (len(catalog_rows) != 1
                or (catalog_rows[0].relative_path, catalog_rows[0].sha256,
                    catalog_rows[0].size_bytes, catalog_rows[0].roles)
                    != (APPLICATION_EFFECT_SOURCE_CATALOG_PATH,
                        APPLICATION_EFFECT_SOURCE_CATALOG_SHA256,
                        APPLICATION_EFFECT_SOURCE_CATALOG_SIZE, ("amendment",))
                or catalog_rows[0].artifact_id not in plan.allowed_artifact_ids):
            raise AuthorityDenied("application.effect.source", "v175 source catalog is absent from the selected release")
        catalog_bytes = self._read_fd(release, catalog_rows[0], limit=_MAX_CATALOG_BYTES)
        catalog = json.loads(catalog_bytes.decode("utf-8"), object_pairs_hook=self._unique_pairs)
        if not isinstance(catalog, dict) or catalog.get("schema") != 1:
            raise AuthorityDenied("application.effect.source", "v175 source catalog schema is invalid")
        actual_members = catalog.get("members")
        expected_rows = {item[0]: item for item in APPLICATION_EFFECT_SOURCE_MEMBERS}
        if not isinstance(actual_members, list) or len(actual_members) != len(expected_rows):
            raise AuthorityDenied("application.effect.source", "v175 source catalog member set is incomplete")
        catalog_by_id: dict[str, Mapping[str, Any]] = {}
        for item in actual_members:
            if not isinstance(item, dict):
                raise AuthorityDenied("application.effect.source", "v175 source catalog member row is malformed")
            artifact_id = item.get("artifact_id")
            expected = expected_rows.get(artifact_id)
            if (expected is None or artifact_id in catalog_by_id
                    or (item.get("release_member_path"), item.get("role"), item.get("sha256"),
                        item.get("size_bytes")) != (expected[1], expected[2], expected[3], expected[4])
                    or item.get("source_path") != expected[1]):
                raise AuthorityDenied("application.effect.source", "v175 source catalog role or pin changed")
            catalog_by_id[artifact_id] = item
        if set(catalog_by_id) != set(expected_rows):
            raise AuthorityDenied("application.effect.source", "v175 source catalog member IDs changed")

        recipe_by_path = {member.relative_path: member for member in recipe.members}
        if len(recipe_by_path) != len(recipe.members):
            raise AuthorityDenied("application.effect.source", "effect recipe repeats a source path")
        selected_rows: list[tuple[Any, Any, Any]] = []
        for member in recipe.members:
            matches = [(artifact_id, row) for artifact_id, row in catalog_by_id.items()
                       if row["release_member_path"] == member.relative_path]
            if len(matches) != 1:
                raise AuthorityDenied("application.effect.source", "effect recipe source is not uniquely cataloged")
            artifact_id, descriptor_row = matches[0]
            manifest_rows = [row for row in files if row.artifact_id == artifact_id]
            if len(manifest_rows) != 1:
                raise AuthorityDenied("application.effect.source", "effect source is missing from the verified release")
            release_row = manifest_rows[0]
            expected = expected_rows[artifact_id]
            if ((member.sha256, member.size_bytes) != (expected[3], expected[4])
                    or (release_row.relative_path, release_row.sha256, release_row.size_bytes,
                        release_row.roles) != (expected[1], expected[3], expected[4], (expected[2],))
                    or artifact_id not in plan.allowed_artifact_ids):
                raise AuthorityDenied("application.effect.source", "effect source release role or pin changed")
            selected_rows.append((member, descriptor_row, release_row))
        if len(selected_rows) != len(recipe.members):
            raise AuthorityDenied("application.effect.source", "effect recipe source closure is incomplete")
        actor.verify_current(release)
        release.verify_current()
        return catalog_bytes, tuple(selected_rows), catalog_rows[0], plan

    @staticmethod
    def _unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate catalog field")
            result[key] = value
        return result

    def resolve_application_effect_members(self, context: Any, recipe: Any) -> Any:
        from .application_workload_execution import RootResolvedApplicationEffectMembers

        selection, source, lock, runtime_preparation, prepared = self._current_selection(context, recipe)
        session = self._session
        release, actor = session._factory._release, session._factory._actor
        release_selection_handle = session.resolve_current_release_receipt_handle()
        choice = session.resolve_application_setup_choice(context.qualification_choice_handle)
        principal_selector = session.resolve_adopted_principal_selector()
        namespace_selector = session.resolve_adopted_namespace_selector()
        catalog_bytes, selected_rows, catalog_row, plan = self._catalog_and_rows(recipe)
        key = (context.source_preparation_selection_handle, context.application_id)
        context_digest = hashlib.sha256(canonical_bytes({
            name: getattr(context, name) for name in context.__dataclass_fields__
            if not name.startswith("_")
        })).hexdigest()
        prior = self._sets.get(key)
        if prior is not None and (prior.context != context or prior.recipe != recipe
                or prior.selection.selection_handle != selection.selection_handle
                or prior.release_selection_handle != release_selection_handle
                or prior.expires_monotonic <= self._clock()):
            raise AuthorityDenied("application.effect.source", "application effect source lease is stale")
        if prior is None:
            now = self._clock()
            expiry = min(selection.expires_monotonic, source.expires_monotonic,
                         lock.expires_monotonic, runtime_preparation.expires_monotonic,
                         self._verify_live_consent(context), now + 1800.0)
            if expiry <= now:
                raise AuthorityDenied("application.effect.source", "application effect source lease expired")
            receipts: dict[str, RootApplicationEffectSourceReceipt] = {}
            catalog_handle = self._new_receipt(
                member_id="application-effect-sources-v175", application_id=context.application_id,
                workflow_id=recipe.workflow_id, artifact_id=catalog_row.artifact_id,
                relative_path=catalog_row.relative_path, role="amendment", sha256=catalog_row.sha256,
                size_bytes=catalog_row.size_bytes, context=context, selection=selection,
                release_selection_handle=release_selection_handle, expiry=expiry)
            receipts[catalog_handle.source_receipt_handle] = catalog_handle
            member_handles: list[tuple[str, str]] = []
            expected_by_path = {row[1]: row for row in APPLICATION_EFFECT_SOURCE_MEMBERS}
            source_rows: list[dict[str, Any]] = []
            for member, _descriptor_row, release_row in selected_rows:
                expected = expected_by_path[member.relative_path]
                receipt = self._new_receipt(
                    member_id=member.member_id, application_id=context.application_id,
                    workflow_id=recipe.workflow_id, artifact_id=release_row.artifact_id,
                    relative_path=release_row.relative_path, role=expected[2],
                    sha256=release_row.sha256, size_bytes=release_row.size_bytes,
                    context=context, selection=selection,
                    release_selection_handle=release_selection_handle, expiry=expiry)
                receipts[receipt.source_receipt_handle] = receipt
                member_handles.append((member.member_id, receipt.source_receipt_handle))
                source_rows.append({"member_id": member.member_id, "artifact_id": receipt.artifact_id,
                    "relative_path": receipt.relative_path, "role": receipt.role,
                    "sha256": receipt.sha256, "size_bytes": receipt.size_bytes,
                    "receipt_handle": receipt.source_receipt_handle})
            source_handles = tuple(context.source_receipt_handles) + (
                catalog_handle.source_receipt_handle,
                *(handle for _member_id, handle in member_handles),
            )
            closure = hashlib.sha256(canonical_bytes({
                "schema": 1,
                "application_id": context.application_id,
                "workflow_id": recipe.workflow_id,
                "source_revision": recipe.source_revision,
                "release_commit": release.release_commit,
                "deployment_receipt_sha256": release.deployment_receipt_sha256,
                "release_selection_handle": release_selection_handle,
                "catalog": {"artifact_id": catalog_row.artifact_id,
                    "path": catalog_row.relative_path, "sha256": catalog_row.sha256,
                    "size_bytes": catalog_row.size_bytes,
                    "receipt_handle": catalog_handle.source_receipt_handle},
                "prepared_source_receipt_handle": source.receipt_handle,
                "source_generation_manifest_sha256": source.source_generation_manifest_sha256,
                "lock_receipt_handle": lock.receipt_handle,
                "lock_sha256": lock.lock_sha256,
                "runtime_preparation_selection_handle": runtime_preparation.handle,
                "runtime_manifest_sha256": runtime_preparation.runtime_manifest_sha256,
                "setup_session_id": context.setup_session_id,
                "prepared_generation_id": selection.prepared_generation_id,
                "principal_id": context.principal_id,
                "principal_selection_handle": principal_selector.selection_handle,
                "principal_binding_sha256": principal_selector.binding_sha256,
                "profile_id": context.profile_id,
                "profile_generation": context.profile_generation,
                "namespace_id": context.namespace_id,
                "namespace_selection_handle": namespace_selector.selection_handle,
                "namespace_binding_sha256": namespace_selector.binding_sha256,
                "service_generation_digest": context.enclosing_service_generation_digest,
                "context_sha256": context_digest,
                "members": source_rows,
            })).hexdigest()
            prior = _EffectSourceSet(context, recipe, selection, source, lock,
                runtime_preparation, MappingProxyType(receipts), release_selection_handle,
                source_handles, tuple(member_handles), closure, expiry)
            self._sets[key] = prior
            self._receipts.update(receipts)

        member_bytes = {member.member_id: self._read_receipt(
            next(receipt for receipt in prior.receipts.values() if receipt.member_id == member.member_id))
            for member in recipe.members}
        actor.verify_current(release)
        return RootResolvedApplicationEffectMembers(
            schema=1, application_id=context.application_id, workflow_id=recipe.workflow_id,
            release_selection_handle=prior.release_selection_handle,
            source_receipt_handles=prior.source_receipt_handles,
            source_closure_sha256=prior.source_closure_sha256,
            member_receipt_handles=prior.member_receipt_handles,
            member_bytes=MappingProxyType(member_bytes),
            service_generation_digest=context.enclosing_service_generation_digest,
            expires_monotonic=prior.expires_monotonic,
        )

    def is_application_effect_members_current(self, receipt: Any) -> bool:
        from .application_workload_execution import RootResolvedApplicationEffectMembers

        if type(receipt) is not RootResolvedApplicationEffectMembers:
            return False
        key = next((key for key, row in self._sets.items()
                    if row.release_selection_handle == receipt.release_selection_handle
                    and row.context.application_id == receipt.application_id), None)
        if key is None:
            return False
        row = self._sets[key]
        try:
            current = self.resolve_application_effect_members(row.context, row.recipe)
        except Exception:
            return False
        return (receipt.application_id == current.application_id
                and receipt.workflow_id == current.workflow_id
                and receipt.release_selection_handle == current.release_selection_handle
                and receipt.source_receipt_handles == current.source_receipt_handles
                and receipt.source_closure_sha256 == current.source_closure_sha256
                and receipt.member_receipt_handles == current.member_receipt_handles
                and dict(receipt.member_bytes) == dict(current.member_bytes)
                and receipt.service_generation_digest == current.service_generation_digest
                and receipt.expires_monotonic == current.expires_monotonic
                and self._clock() < current.expires_monotonic)

    def _new_receipt(self, *, member_id: str, application_id: str, workflow_id: str,
                     artifact_id: str, relative_path: str, role: str, sha256: str,
                     size_bytes: int, context: Any, selection: Any,
                     release_selection_handle: str, expiry: float) -> RootApplicationEffectSourceReceipt:
        session = self._session
        receipt = RootApplicationEffectSourceReceipt(
            schema=1, member_id=member_id, application_id=application_id,
            workflow_id=workflow_id, artifact_id=artifact_id, relative_path=relative_path,
            role=role, sha256=sha256, size_bytes=size_bytes,
            release_commit=session._factory._release.release_commit,
            deployment_receipt_sha256=session._factory._release.deployment_receipt_sha256,
            release_selection_handle=release_selection_handle,
            source_preparation_selection_handle=selection.selection_handle,
            setup_session_id=selection.setup_session_id,
            prepared_generation_id=selection.prepared_generation_id,
            service_generation_digest=context.enclosing_service_generation_digest,
            context_sha256=hashlib.sha256(canonical_bytes({
                name: getattr(context, name) for name in context.__dataclass_fields__
                if not name.startswith("_")
            })).hexdigest(),
            source_receipt_handle=secrets.token_urlsafe(36),
            issued_monotonic=self._clock(), expires_monotonic=expiry,
            _receipt_seal=_RECEIPT_SEAL, _session_seal=session._seal, _session=session,
        )
        return receipt

    def _verify_live_consent(self, context: Any) -> float:
        session = self._session
        consent = session.resolve_application_qualification_consent(
            context.qualification_choice_handle, "run-owned-local-fixture")
        choice = session.resolve_application_setup_choice(context.qualification_choice_handle)
        if (consent.receipt_handle != context.qualification_consent_receipt_handle
                or consent.setup_session_id != context.setup_session_id
                or consent.application_id != context.application_id
                or consent.workflow_id != choice.workflow_id
                or consent.controller_binding_handle != context.controller_binding_handle
                or consent.namespace_selection_handle != choice.namespace_selection_handle
                or consent.principal_selection_handle != choice.principal_selection_handle
                or consent.target_profile_id != context.profile_id
                or consent.additional_metered_budget_usd != 0.0
                or consent.expires_monotonic <= self._clock()):
            raise AuthorityDenied("application.effect.source", "qualification consent is stale or changed")
        return consent.expires_monotonic

    def _read_receipt(self, receipt: RootApplicationEffectSourceReceipt) -> bytes:
        session = self._session
        if (type(receipt) is not RootApplicationEffectSourceReceipt
                or receipt._session is not session
                or not secrets.compare_digest(receipt._session_seal, session._seal)
                or self._receipts.get(receipt.source_receipt_handle) is not receipt
                or receipt.expires_monotonic <= self._clock()):
            raise AuthorityDenied("application.effect.source", "effect source receipt is stale or unrecognized")
        state = next((row for row in self._sets.values()
                      if receipt.source_receipt_handle in row.receipts), None)
        if state is None or receipt.context_sha256 != hashlib.sha256(canonical_bytes({
            name: getattr(state.context, name) for name in state.context.__dataclass_fields__
            if not name.startswith("_")
        })).hexdigest():
            raise AuthorityDenied("application.effect.source", "effect source receipt context changed")
        selection, _source, _lock, _runtime, prepared = self._current_selection(state.context, state.recipe)
        if (selection.selection_handle != receipt.source_preparation_selection_handle
                or selection.prepared_generation_id != receipt.prepared_generation_id
                or prepared.generation_id != receipt.prepared_generation_id
                or session.resolve_current_release_receipt_handle() != receipt.release_selection_handle):
            raise AuthorityDenied("application.effect.source", "effect source selection changed")
        release, actor = session._factory._release, session._factory._actor
        actor.verify_current(release)
        release.verify_current()
        plan = session._factory.resolver.resolve(session._authorization.plan_artifact_id)
        if receipt.artifact_id not in plan.allowed_artifact_ids:
            raise AuthorityDenied("application.effect.source", "effect source is not in the selected setup plan")
        rows = [row for row in release.files if row.artifact_id == receipt.artifact_id]
        if (len(rows) != 1 or (rows[0].relative_path, rows[0].sha256, rows[0].size_bytes,
                rows[0].roles, release.release_commit, release.deployment_receipt_sha256)
                != (receipt.relative_path, receipt.sha256, receipt.size_bytes, (receipt.role,),
                    receipt.release_commit, receipt.deployment_receipt_sha256)):
            raise AuthorityDenied("application.effect.source", "effect source member role or identity changed")
        if receipt.member_id == "application-effect-sources-v175":
            expected = (APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID,
                APPLICATION_EFFECT_SOURCE_CATALOG_PATH, "amendment",
                APPLICATION_EFFECT_SOURCE_CATALOG_SHA256, APPLICATION_EFFECT_SOURCE_CATALOG_SIZE)
        else:
            expected = next((row for row in APPLICATION_EFFECT_SOURCE_MEMBERS
                             if row[0] == receipt.artifact_id), None)
        if expected is None:
            raise AuthorityDenied("application.effect.source", "effect source member is outside the fixed catalog")
        if receipt.member_id == "application-effect-sources-v175":
            expected_identity = expected
        else:
            expected_identity = (expected[0], expected[1], expected[2], expected[3], expected[4])
        if (receipt.artifact_id, receipt.relative_path, receipt.role, receipt.sha256, receipt.size_bytes) != expected_identity:
            raise AuthorityDenied("application.effect.source", "effect source receipt does not match its role pin")
        body = self._read_fd(release, rows[0], limit=_MAX_CATALOG_BYTES if receipt.role == "amendment" else _MAX_MEMBER_BYTES)
        actor.verify_current(release)
        return body

    def read_current(self, receipt: RootApplicationEffectSourceReceipt) -> bytes:
        return self._read_receipt(receipt)
