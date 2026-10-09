"""Fixed, source-bound backend projection for protected Hermes resource jobs.

This module is used only by root runtime composition. It turns a typed,
root-loaded resource backend into one selected Hermes process recipe; resource
declarations never provide executable paths, argv, profile IDs, package roots,
or authority. Launching and terminal supervision remain in the root authority
and managed-process service.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol
from types import MappingProxyType


HERMES_RESOURCE_PROFILE_TASK_OPERATION = "hermes-resource-profile-task-v1"
RESOURCE_PROFILE_TASK_HANDLER_ARTIFACT_ID = "hermes-installer.resource-profile-task.v1"
PINNED_HERMES_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
_TASK_ARGV_SUFFIX = (
    "-m", "hermes_cli.main", "chat", "--query-file", "-", "--oneshot", "--quiet",
)
_EXECUTION_BINDING_FIELDS = frozenset({
    "process_enrollment_id", "process_generation", "operation_id",
    "native_package_id", "native_package_generation", "child_operation",
    "child_target_id", "child_capability", "task_body_recipe_id",
    "task_request_schema_id",
})


class ResourceProfileTaskUnavailable(RuntimeError):
    """The protected backend does not resolve to the reviewed Hermes task recipe."""


class ProtectedResourceRuntimeBindings(Protocol):
    enrollment_catalog: Any

    def resolve_selected_operation(
        self, enrollment_id: str, generation: str, operation: str, operation_id: str,
    ) -> Any: ...

    def resolve_native_package(self, package_id: str, generation: str) -> Any: ...


class RootResourceTaskLauncher(Protocol):
    def launch_resource_profile_task(self, root_job_admission_handle: Any, node_id: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class SelectedResourceProfileTask:
    """Resolved root-only process/package selection for one protected job node."""

    resource_backend_id: str
    resource_id: str
    resource_generation: str
    profile_id: str
    principal_id: str
    profile_generation: str
    process_enrollment_id: str
    process_generation: str
    operation_id: str
    process_start_target: str
    native_package_id: str
    native_package_generation: str
    task_body_recipe_id: str
    task_request_schema_id: str
    # These objects are root-resolved values and must never cross worker RPC.
    process_operation: Any = field(repr=False, compare=False)
    launch_recipe: Any = field(repr=False, compare=False)
    native_package: Any = field(repr=False, compare=False)
    task_body_recipe: Any = field(repr=False, compare=False)


def resource_profile_task_handler_sha256() -> str:
    """Hash this fixed adapter source for the protected backend artifact join.

    The path is derived from the already imported module, never accepted from a
    resource or worker. A symlink or non-regular source fails closed. Root
    enrollment pins the returned digest; changing this implementation therefore
    requires a reviewed enrollment update.
    """
    path = Path(__file__)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise OSError("adapter source is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise OSError("adapter source changed while opening")
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, 65_536)
                if not block:
                    break
                digest.update(block)
            return digest.hexdigest()
        finally:
            os.close(fd)
    except OSError:
        raise ResourceProfileTaskUnavailable("fixed profile-task adapter source cannot be verified") from None


def resolve_resource_profile_task(
    backend: Any,
    task_body_recipe: Any,
    *,
    protected_bindings: ProtectedResourceRuntimeBindings,
    validators: Mapping[str, Any],
) -> SelectedResourceProfileTask:
    """Join one typed resource backend to protected process and native-package rows.

    This is a pure selector: it performs no process, network, or authority
    effect. The actual root-only launcher receives its opaque job handle and
    node ID separately, then re-resolves current enrollment before each start.
    """
    from hermes_installer.registry.resource_jobs import ResourceBackendEnrollment, ResourceBodyRecipe

    binding = getattr(backend, "execution_binding", None)
    if (not isinstance(backend, ResourceBackendEnrollment)
            or not isinstance(task_body_recipe, ResourceBodyRecipe)
            or not isinstance(binding, Mapping) or set(binding) != _EXECUTION_BINDING_FIELDS
            or not isinstance(validators, Mapping)):
        raise ResourceProfileTaskUnavailable("selected profile-task execution binding is absent")
    text_fields = (
        "process_enrollment_id", "process_generation", "operation_id", "native_package_id",
        "native_package_generation", "child_operation", "child_target_id", "child_capability",
        "task_body_recipe_id", "task_request_schema_id",
    )
    if any(not isinstance(binding.get(name), str) or not binding[name] for name in text_fields):
        raise ResourceProfileTaskUnavailable("selected profile-task execution binding is malformed")
    if (binding["operation_id"] != HERMES_RESOURCE_PROFILE_TASK_OPERATION
            or binding["child_operation"] != "process.start"
            or binding["child_capability"] != "hermes-profile-invoke"
            or binding["native_package_id"] != backend.native_package_id
            or binding["native_package_generation"] != backend.native_package_generation
            or binding["task_body_recipe_id"] != task_body_recipe.recipe_id
            or binding["task_request_schema_id"] != task_body_recipe.schema_id):
        raise ResourceProfileTaskUnavailable("profile-task recipe, operation, or package does not match enrollment")
    if (getattr(backend, "handler_artifact_id", None) != RESOURCE_PROFILE_TASK_HANDLER_ARTIFACT_ID
            or getattr(backend, "handler_sha256", None) != resource_profile_task_handler_sha256()):
        raise ResourceProfileTaskUnavailable("profile-task handler artifact is not the reviewed fixed adapter")
    fields = getattr(task_body_recipe, "output_fields", ())
    if (len(fields) != 1 or getattr(fields[0], "name", None) != "prompt"
            or getattr(task_body_recipe, "maximum_bytes", 0) > 262_144):
        raise ResourceProfileTaskUnavailable("profile-task body recipe must produce only a bounded prompt")
    prompt_validator = validators.get(getattr(fields[0], "validator_id", None))
    if (prompt_validator is None or getattr(prompt_validator, "kind", None) != "utf8-string"
            or getattr(prompt_validator, "maximum_bytes", 0) > 262_144):
        raise ResourceProfileTaskUnavailable("profile-task prompt schema lacks its bounded UTF-8 validator")
    if getattr(backend, "profile_generation", None) is None:
        raise ResourceProfileTaskUnavailable("selected profile generation is absent")

    try:
        operation = protected_bindings.resolve_selected_operation(
            binding["process_enrollment_id"], binding["process_generation"],
            "process.start", binding["operation_id"],
        )
        launch = protected_bindings.enrollment_catalog.resolve_launch_recipe(
            binding["process_enrollment_id"], binding["process_generation"],
            binding["operation_id"],
        )
        package = protected_bindings.resolve_native_package(
            binding["native_package_id"], binding["native_package_generation"],
        )
    except Exception:
        raise ResourceProfileTaskUnavailable("protected process recipe or native package is unavailable") from None

    if (operation.operation != "process.start"
            or operation.operation_id != binding["operation_id"]
            or operation.target != binding["child_target_id"]
            or operation.enrollment_id != binding["process_enrollment_id"]
            or operation.generation != binding["process_generation"]
            or operation.profile_id != backend.profile_id
            or operation.principal_id != backend.principal_id
            or operation.service_uid < 0):
        raise ResourceProfileTaskUnavailable("selected process target does not join the resource principal")
    if (launch.operation_id != binding["operation_id"]
            or launch.process_start_target != binding["child_target_id"]
            or launch.parameter_schema.schema_id != launch.recipe.parameter_schema_id
            or launch.recipe.stdin_mode != "bounded-typed-bytes"):
        raise ResourceProfileTaskUnavailable("selected process recipe does not support bounded task input")
    argv = launch.recipe.argv_recipe
    literals = tuple(token.get("literal") for token in argv if isinstance(token, Mapping))
    if (len(literals) != len(argv) or any(not isinstance(token, str) for token in literals)
            or literals != _TASK_ARGV_SUFFIX
            or any("parameter" in token for token in argv)):
        raise ResourceProfileTaskUnavailable("selected recipe is not the pinned Hermes stdin task invocation")
    if (package.profile_id != backend.profile_id
            or package.generation != backend.native_package_generation
            or package.package_id != binding["native_package_id"]
            or package.source_revision != PINNED_HERMES_REVISION):
        raise ResourceProfileTaskUnavailable("selected native package is outside the pinned Hermes profile generation")

    return SelectedResourceProfileTask(
        resource_backend_id=backend.backend_id, resource_id=backend.resource_id,
        resource_generation=backend.generation, profile_id=backend.profile_id,
        principal_id=backend.principal_id, profile_generation=backend.profile_generation,
        process_enrollment_id=binding["process_enrollment_id"],
        process_generation=binding["process_generation"], operation_id=binding["operation_id"],
        process_start_target=binding["child_target_id"],
        native_package_id=binding["native_package_id"],
        native_package_generation=binding["native_package_generation"],
        task_body_recipe_id=binding["task_body_recipe_id"],
        task_request_schema_id=binding["task_request_schema_id"],
        process_operation=operation, launch_recipe=launch, native_package=package,
        task_body_recipe=task_body_recipe,
    )


def build_resource_profile_task_adapter(
    backend: Any,
    task_body_recipe: Any,
    *,
    validators: Mapping[str, Any],
    protected_bindings: ProtectedResourceRuntimeBindings,
    node_id: str,
    authority_service: Any,
) -> "ResourceProfileTaskAdapter":
    """Build the one fixed adapter from root-loaded records and AuthorityService.

    Deliberately requires the concrete root authority service, not an injected
    arbitrary function, a worker AuthorityClient, or a declaration callable.
    The method is checked again at invocation time because composition may
    occur before the host authority version is upgraded.
    """
    from hermes_installer.authority.service import AuthorityService

    if not isinstance(authority_service, AuthorityService):
        raise ResourceProfileTaskUnavailable("root AuthorityService is required for selected profile tasks")
    if not callable(getattr(authority_service, "launch_resource_profile_task", None)):
        raise ResourceProfileTaskUnavailable("root selected profile-task launcher is not installed")
    selection = resolve_resource_profile_task(
        backend, task_body_recipe, protected_bindings=protected_bindings, validators=validators,
    )
    return ResourceProfileTaskAdapter(selection, node_id=node_id, launcher=authority_service)


def build_resource_profile_task_adapters(
    enrollments: Mapping[Any, Any] | Iterable[Any],
    *,
    protected_bindings: ProtectedResourceRuntimeBindings,
    authority_service: Any,
) -> Mapping[tuple[str, str], "ResourceProfileTaskAdapter"]:
    """Resolve the immutable root adapter map for all selected job nodes.

    Only nodes whose exact backend enrollment carries the reviewed Hermes
    ``execution_binding`` are included. The key is the protected
    ``(backend_id, node_id)`` pair consumed by ``ResourceJobAuthority``. No
    declaration-provided callback, path, or target is considered. A selected
    task binding that cannot be resolved aborts composition rather than
    silently producing a partial runtime.

    Source admission and terminal/result-capsule proof remain independent
    gates enforced by the job authority; this map does not issue contexts,
    start processes, or make an unverified source usable.
    """
    from hermes_installer.authority.service import AuthorityService
    from hermes_installer.registry.resource_jobs import ResourceJobEnrollment

    if not isinstance(authority_service, AuthorityService):
        raise ResourceProfileTaskUnavailable("root AuthorityService is required for profile-task adapter composition")
    if not callable(getattr(authority_service, "launch_resource_profile_task", None)):
        raise ResourceProfileTaskUnavailable("root selected profile-task launcher is not installed")

    values = enrollments.values() if isinstance(enrollments, Mapping) else enrollments
    adapters: dict[tuple[str, str], ResourceProfileTaskAdapter] = {}
    for enrollment in values:
        if not isinstance(enrollment, ResourceJobEnrollment):
            raise ResourceProfileTaskUnavailable("indexed resource job enrollment has an unexpected type")
        if not enrollment.selected_enabled:
            continue
        for node in enrollment.nodes:
            backend = enrollment.backends.get(node.backend_enrollment_id)
            if backend is None or backend.execution_binding is None:
                continue
            if (backend.resource_id != enrollment.resource_id
                    or backend.generation != enrollment.generation
                    or backend.profile_id != enrollment.profile_id
                    or backend.profile_generation != enrollment.profile_generation
                    or node.backend_enrollment_id != backend.backend_id
                    or node.action_id not in backend.approved_action_ids
                    or node.effect != backend.operation
                    or node.target != backend.target_id
                    or node.recipient != backend.recipient):
                raise ResourceProfileTaskUnavailable("resource job node does not exactly join its selected backend")
            binding = backend.execution_binding
            recipe_id = binding.get("task_body_recipe_id") if isinstance(binding, Mapping) else None
            recipe = enrollment.body_recipes.get(recipe_id)
            if recipe is None:
                raise ResourceProfileTaskUnavailable("selected profile-task recipe is absent from the job catalog")
            key = (backend.backend_id, node.node_id)
            if key in adapters:
                raise ResourceProfileTaskUnavailable("duplicate selected profile-task backend/node key")
            try:
                adapters[key] = build_resource_profile_task_adapter(
                    backend, recipe, validators=enrollment.validators,
                    protected_bindings=protected_bindings, node_id=node.node_id,
                    authority_service=authority_service,
                )
            except ResourceProfileTaskUnavailable:
                raise
            except Exception:
                raise ResourceProfileTaskUnavailable(
                    "selected profile-task adapter could not be resolved from protected catalogs"
                ) from None
    return MappingProxyType(adapters)


class ResourceProfileTaskAdapter:
    """Typed adapter invoked only by ResourceJobAuthority after a node claim."""

    def __init__(self, selection: SelectedResourceProfileTask,
                 *, node_id: str, launcher: RootResourceTaskLauncher):
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", node_id):
            raise ValueError("profile task node ID is invalid")
        if not isinstance(selection, SelectedResourceProfileTask):
            raise TypeError("protected resource profile-task selection is required")
        if not callable(getattr(launcher, "launch_resource_profile_task", None)):
            raise TypeError("root profile-task launcher API is unavailable")
        self.selection = selection
        self.node_id = node_id
        self.launcher = launcher

    def launch_resource_profile_task(
        self, root_job_admission_handle: RootResourceJobAdmissionHandle, node_id: str,
    ) -> Any:
        from hermes_installer.registry.resource_jobs import RootResourceJobAdmissionHandle
        from hermes_installer.authority.service import AuthorityService

        handle = root_job_admission_handle
        if not isinstance(handle, RootResourceJobAdmissionHandle) or node_id != self.node_id:
            raise ResourceProfileTaskUnavailable("root admission handle does not select this typed profile-task node")
        selected = self.selection
        expected = {
            "node_id": self.node_id,
            "backend_enrollment_id": selected.resource_backend_id,
            "resource_generation": selected.resource_generation,
            "profile_id": selected.profile_id,
            "profile_generation": selected.profile_generation,
            "native_package_id": selected.native_package_id,
            "native_package_generation": selected.native_package_generation,
            "process_enrollment_id": selected.process_enrollment_id,
            "process_generation": selected.process_generation,
            "operation_id": selected.operation_id,
            "child_target_id": selected.process_start_target,
            "child_capability": "hermes-profile-invoke",
            "task_body_recipe_id": selected.task_body_recipe_id,
            "task_request_schema_id": selected.task_request_schema_id,
        }
        if any(getattr(handle, name, None) != value for name, value in expected.items()):
            raise ResourceProfileTaskUnavailable("root admission handle selection differs from protected backend")
        task_bytes = handle.task_payload
        if (not isinstance(task_bytes, bytes) or not task_bytes
                or hashlib.sha256(task_bytes).hexdigest() != handle.task_payload_sha256):
            raise ResourceProfileTaskUnavailable("root admission task payload digest is invalid")
        try:
            task_body = json.loads(task_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceProfileTaskUnavailable("root admission task payload is not canonical JSON") from None
        if (not isinstance(task_body, dict) or set(task_body) != {"prompt"}
                or not isinstance(task_body["prompt"], str)
                or len(task_body["prompt"].encode("utf-8")) > 262_144
                or json.dumps(task_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") != task_bytes):
            raise ResourceProfileTaskUnavailable("root admission task payload violates the selected prompt schema")
        if (type(handle.expires_monotonic) not in (int, float)
                or handle.expires_monotonic <= time.monotonic()):
            raise ResourceProfileTaskUnavailable("root admission handle is expired")
        if not isinstance(self.launcher, AuthorityService) or not callable(
            getattr(self.launcher, "launch_resource_profile_task", None)
        ):
            raise ResourceProfileTaskUnavailable("root selected profile-task launcher is not installed")
        # The root launcher re-resolves the handle, admission, child
        # process.start rule, lineage, and current generation before effects.
        # This adapter deliberately never calls a worker AuthorityClient.
        return self.launcher.launch_resource_profile_task(handle, node_id)
