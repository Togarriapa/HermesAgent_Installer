"""Strict adapters for a root-installed managed-task kernel fixture.

This module never manufactures actor, controller, source, admission, or task
receipts.  It accepts only the complete runtime produced by the installed
root composition and rechecks that the current systemd MainPID is this exact
installed actor before allowing a selected cron to dispatch.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Callable


class TaskNativeFixtureUnavailable(RuntimeError):
    """The installed root runtime has not composed the selected task path."""


@dataclass(frozen=True, slots=True)
class RootInstalledTaskRuntime:
    """A view of already-composed production objects, never a proof issuer."""

    runtime: Any
    unit_id: str
    actor_pid: int

    @classmethod
    def bind_current_main_pid(cls, runtime: Any, *, unit_id: str | None = None) -> "RootInstalledTaskRuntime":
        from hermes_installer.authority.installer_release import (
            RootActorObservation,
            VerifiedInstallerReleaseReceipt,
        )
        from hermes_installer.authority.root_controller_custody import (
            ControllerExecutablePin,
            SystemdMainPidInspector,
        )
        from hermes_installer.authority.runtime_composition import RootAuthorityRuntime

        if type(runtime) is not RootAuthorityRuntime:
            raise TaskNativeFixtureUnavailable("fixture requires the composed RootAuthorityRuntime")
        release = runtime.controller_release_receipt
        actor = runtime.controller_actor_observation
        controller = runtime.resource_controller_runtime
        service = runtime.service
        if (type(release) is not VerifiedInstallerReleaseReceipt
                or type(actor) is not RootActorObservation
                or controller is None
                or getattr(controller, "service", None) is not service
                or getattr(service, "resource_task_runner", None) is None
                or getattr(service, "resource_job_authority", None) is not runtime.job_authority
                or runtime.job_authority is None
                or runtime.resource_event_context_issuer is None
                or runtime.resource_event_context_issuer.controller_registry
                is not runtime.resource_controller_registry
                or runtime.resource_scheduler is None):
            raise TaskNativeFixtureUnavailable("installed selected controller/task graph is incomplete")
        unit = unit_id or os.environ.get("HERMES_ROOT_CONTROLLER_TEST_UNIT")
        if (not isinstance(unit, str) or not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,255}", unit)
                or unit.startswith("-")):
            raise TaskNativeFixtureUnavailable("fixed root controller systemd unit is unavailable")

        # Revalidate the retained actor and exact role module closure before
        # asking systemd to join its current MainPID to the selected executable.
        actor.verify_current(release)
        role_rows = tuple(controller.catalog.rows)
        matching = [row for row in role_rows if row.daemon_unit_id == unit]
        if len(matching) != 1:
            raise TaskNativeFixtureUnavailable("fixture unit does not have one protected controller role")
        role = matching[0]
        resolved = runtime.artifact_catalog.resolve(
            role.daemon_executable_artifact_id,
            role.daemon_executable_sha256,
            runtime.enrollment.artifact_staging_directory,
            expected_uid=0,
        )
        pin = ControllerExecutablePin(
            artifact_id=resolved.artifact_id,
            path=resolved.path,
            sha256=resolved.sha256,
        )
        inspector = SystemdMainPidInspector(monotonic=service.monotonic)
        identity = inspector.inspect(unit, pin)
        try:
            if identity.pid != actor.pid or identity.pid != os.getpid():
                raise TaskNativeFixtureUnavailable(
                    "fixture systemd MainPID is not the retained installed root actor",
                )
            actor.verify_current(release)
        finally:
            inspector.close_pidfd(identity.pidfd)
        return cls(runtime=runtime, unit_id=unit, actor_pid=actor.pid)

    def run_selected_cron_once(
        self,
        resource_id: str,
        *,
        timeout: float = 600.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> Any:
        """Run the selected root cron producer and its durable DAG exactly once."""
        from hermes_installer.registry.resource_dispatch import RootResourceDAGDispatcher
        from hermes_installer.registry.resource_producers import (
            RootSelectedCronProducer,
            RootSelectedResourceScheduler,
        )

        if (not isinstance(resource_id, str) or not resource_id
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0.1 <= timeout <= 600 or not callable(cancelled)):
            raise TaskNativeFixtureUnavailable("bounded selected cron request is malformed")
        scheduler = self.runtime.resource_scheduler
        if type(scheduler) is not RootSelectedResourceScheduler:
            raise TaskNativeFixtureUnavailable("selected root cron scheduler has the wrong production type")
        matches = [producer for producer in scheduler.producers
                   if type(producer) is RootSelectedCronProducer
                   and producer.enrollment.resource_id == resource_id]
        if len(matches) != 1:
            raise TaskNativeFixtureUnavailable("resource ID does not identify one selected root cron")
        producer = matches[0]
        if (type(producer.dispatcher) is not RootResourceDAGDispatcher
                or producer.dispatcher.jobs is not self.runtime.job_authority
                or producer.dispatcher.registry is not self.runtime.resource_controller_registry):
            raise TaskNativeFixtureUnavailable("selected cron dispatcher is not bound to the composed root graph")
        if timeout != 600.0:
            raise TaskNativeFixtureUnavailable(
                "the selected cron producer owns the reviewed DAG deadline; timeout overrides are unavailable",
            )
        return producer.tick(cancelled=cancelled)
