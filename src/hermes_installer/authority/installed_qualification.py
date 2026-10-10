"""Finite result and selection DTOs for installed local qualification.

The selector is presentation data, not authority.  Live publication, source,
session, controller, task and cleanup receipts stay in their owning registries
and are resolved by the opaque selection handle.
"""
from __future__ import annotations

import re
import hashlib
import os
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


_SUITES = frozenset({"resource-cron-task-v1", "display-xauthority-v1"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_TASK_RECIPE_ARTIFACT = "installer-module:hermes_installer.authority.qualification_resource_cron_recipe"
_TASK_SCHEMA_ARTIFACT = "installer-module:hermes_installer.authority.qualification_resource_cron_schema"
_TASK_RECIPE_PATH = "lib/python/hermes_installer/authority/qualification_resource_cron_recipe.py"
_TASK_SCHEMA_PATH = "lib/python/hermes_installer/authority/qualification_resource_cron_schema.py"


@dataclass(frozen=True, slots=True)
class RootOwnedQualificationFixtureSelection:
    """Path-free public projection of one registry-retained fixture selection."""

    schema: int
    selection_handle: str
    suite_id: str
    fixture_recipe_artifact_id: str
    fixture_recipe_sha256: str
    fixture_schema_artifact_id: str
    fixture_schema_sha256: str
    release_deployment_receipt_sha256: str
    root_actor_observation_handle: str
    fixture_root_observation_handle: str
    fixture_environment_observation_handle: str
    controller_unit_observation_handle: str
    fixture_generation_id: str
    fixture_namespace_id: str
    fixture_profile_id: str
    fixture_principal_id: str
    fixture_payload_sha256: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        if self.schema != 1 or self.suite_id not in _SUITES:
            raise ValueError("qualification selection schema or suite is not supported")
        if not _HANDLE.fullmatch(self.selection_handle):
            raise ValueError("qualification selection handle is malformed")
        if not self.fixture_recipe_artifact_id or not self.fixture_schema_artifact_id:
            raise ValueError("qualification asset identities are required")
        for digest in (self.fixture_recipe_sha256, self.fixture_schema_sha256,
                       self.release_deployment_receipt_sha256, self.fixture_payload_sha256):
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise ValueError("qualification selection digest is malformed")
        for value in (self.root_actor_observation_handle, self.fixture_root_observation_handle,
                      self.fixture_environment_observation_handle,
                      self.controller_unit_observation_handle, self.fixture_generation_id,
                      self.fixture_namespace_id, self.fixture_profile_id, self.fixture_principal_id):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError("qualification observation or fixture identity is malformed")
        if (type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or self.issued_monotonic <= 0 or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("qualification selection lifetime is invalid")


class QualificationFixtureUnavailable(RuntimeError):
    """A required installed actor, source, or isolated fixture input is absent."""


class SelectedFixtureSourceCatalog:
    """Resolve only the source-owned fixture modules from a held release receipt."""

    __slots__ = ("release", "_rows")

    def __init__(self, release: object):
        from hermes_installer.authority.installer_release import VerifiedInstallerReleaseReceipt

        if type(release) is not VerifiedInstallerReleaseReceipt:
            raise TypeError("fixture source catalog requires the sealed installed release receipt")
        release.verify_current()
        expected = {
            _TASK_RECIPE_ARTIFACT: _TASK_RECIPE_PATH,
            _TASK_SCHEMA_ARTIFACT: _TASK_SCHEMA_PATH,
        }
        rows: dict[str, object] = {}
        for artifact_id, relative_path in expected.items():
            matches = [row for row in release.files if row.artifact_id == artifact_id]
            if (len(matches) != 1 or matches[0].relative_path != relative_path
                    or matches[0].roles != ("module",)):
                raise QualificationFixtureUnavailable(
                    "the fixed task recipe or schema is not an exact installed module member")
            rows[artifact_id] = matches[0]
        self.release = release
        self._rows = rows

    def source_identity(self, artifact_id: str) -> tuple[str, str, int]:
        self.release.verify_current()
        try:
            row = self._rows[artifact_id]
        except KeyError:
            raise QualificationFixtureUnavailable("fixture source is outside the fixed catalog") from None
        return row.relative_path, row.sha256, row.size_bytes

    def open_source(self, artifact_id: str) -> int:
        self.release.verify_current()
        if artifact_id not in self._rows:
            raise QualificationFixtureUnavailable("fixture source is outside the fixed catalog")
        return self.release.open_file(artifact_id)


@dataclass(slots=True)
class RootOwnedQualificationFixtureLease:
    """Private FD/actor lease consumed by the source-owned fixture publisher."""

    selection: RootOwnedQualificationFixtureSelection
    release: object
    actor: object
    source_catalog: SelectedFixtureSourceCatalog
    unit_id: str
    executable_pin: object
    controller_identity: object
    inspector: object
    run_name: str
    journal_fd: int
    qualification_fd: int
    fixture_root_fd: int
    journal_device: int
    journal_inode: int
    qualification_device: int
    qualification_inode: int
    fixture_device: int
    fixture_inode: int
    recipe_fd: int
    schema_fd: int
    _closed: bool = False
    _root_removed: bool = False

    def dup_root_fd(self) -> int:
        self.verify_current()
        return os.dup(self.fixture_root_fd)

    def dup_journal_fd(self) -> int:
        self.verify_current()
        return os.dup(self.journal_fd)

    def dup_qualification_fd(self) -> int:
        self.verify_current()
        return os.dup(self.qualification_fd)

    def dup_recipe_fd(self) -> int:
        self.verify_current()
        return os.dup(self.recipe_fd)

    def dup_schema_fd(self) -> int:
        self.verify_current()
        return os.dup(self.schema_fd)

    def current_controller_identity(self) -> object:
        self.verify_current()
        return self.controller_identity

    def current_fixture_root_identity(self) -> tuple[int, int, int, int]:
        self.verify_current()
        info = os.fstat(self.fixture_root_fd)
        return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)

    def cleanup_empty_owned_root(self) -> None:
        """Remove only this generated empty run directory, never sibling data."""
        self.verify_current()
        if os.listdir(self.fixture_root_fd):
            raise QualificationFixtureUnavailable("fixture publisher left owned files for cleanup")
        current = os.stat(self.run_name, dir_fd=self.qualification_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != 0
                or (current.st_dev, current.st_ino) != (self.fixture_device, self.fixture_inode)):
            raise QualificationFixtureUnavailable("fixture root name no longer identifies its held directory")
        os.rmdir(self.run_name, dir_fd=self.qualification_fd)
        self._root_removed = True
        if not os.listdir(self.qualification_fd):
            parent = os.stat("qualification", dir_fd=self.journal_fd, follow_symlinks=False)
            if (stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0
                    and (parent.st_dev, parent.st_ino)
                    == (self.qualification_device, self.qualification_inode)):
                os.rmdir("qualification", dir_fd=self.journal_fd)

    def verify_current(self) -> None:
        if self._closed:
            raise QualificationFixtureUnavailable("fixture lease is closed")
        if self._root_removed:
            raise QualificationFixtureUnavailable("fixture root was already cleaned")
        if time.monotonic() >= self.selection.expires_monotonic:
            raise QualificationFixtureUnavailable("fixture selection expired")
        self.release.verify_current()
        self.actor.verify_current(self.release)
        journal = os.fstat(self.journal_fd)
        if ((journal.st_dev, journal.st_ino) != (self.journal_device, self.journal_inode)
                or journal.st_uid != 0 or stat.S_IMODE(journal.st_mode) != 0o700):
            raise QualificationFixtureUnavailable("selected qualification journal root changed")
        for fd, expected in ((self.qualification_fd,
                              (self.qualification_device, self.qualification_inode)),
                             (self.fixture_root_fd, (self.fixture_device, self.fixture_inode))):
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or (info.st_dev, info.st_ino) != expected):
                raise QualificationFixtureUnavailable("owned fixture directory custody changed")
        for fd, artifact_id in ((self.recipe_fd, _TASK_RECIPE_ARTIFACT),
                                 (self.schema_fd, _TASK_SCHEMA_ARTIFACT)):
            row = self.source_catalog._rows[artifact_id]
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_size != row.size_bytes or info.st_dev != row.device
                    or info.st_ino != row.inode or stat.S_IMODE(info.st_mode) != row.mode
                    or _hash_fd(fd) != row.sha256):
                raise QualificationFixtureUnavailable("held fixture source bytes changed")
        identity = self.inspector.inspect(self.unit_id, self.executable_pin)
        try:
            observed_fields = (identity.daemon_unit_id, identity.pid, identity.uid,
                               identity.start_time_ticks, identity.cgroup,
                               identity.executable_artifact_id, identity.executable_sha256,
                               identity.pid_namespace, identity.mount_namespace,
                               identity.user_namespace)
            retained_fields = (self.controller_identity.daemon_unit_id,
                               self.controller_identity.pid, self.controller_identity.uid,
                               self.controller_identity.start_time_ticks,
                               self.controller_identity.cgroup,
                               self.controller_identity.executable_artifact_id,
                               self.controller_identity.executable_sha256,
                               self.controller_identity.pid_namespace,
                               self.controller_identity.mount_namespace,
                               self.controller_identity.user_namespace)
            if (identity.pid != self.actor.pid or observed_fields != retained_fields
                    or not self.inspector.is_pidfd_live(self.controller_identity.pidfd,
                                                       self.actor.pid)):
                raise QualificationFixtureUnavailable("fixture systemd MainPID is stale")
        finally:
            self.inspector.close_pidfd(identity.pidfd)

    def close(self) -> None:
        if self._closed:
            return
        for fd in (self.recipe_fd, self.schema_fd, self.fixture_root_fd,
                   self.qualification_fd, self.journal_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        self.inspector.close_pidfd(self.controller_identity.pidfd)
        self._closed = True


class RootOwnedQualificationFixtureRegistry:
    """Create and retain one owned, source-pinned root fixture directory.

    Publication and task/display effects belong to their source-owned registry;
    this object only provides current FD-backed recipe and host observations.
    """

    def __init__(self, verified_installer_release: object, current_actor_observation: object,
                 selected_fixture_source_catalog: SelectedFixtureSourceCatalog,
                 root_journal: object, managed_process_custody: object):
        from hermes_installer.authority.installer_release import (
            RootActorObservation, VerifiedInstallerReleaseReceipt,
        )
        from hermes_installer.managed_process_custodian import ManagedProcessEffectHandler
        from hermes_installer.protected_enrollment import RootJournalSelection

        if (type(verified_installer_release) is not VerifiedInstallerReleaseReceipt
                or type(current_actor_observation) is not RootActorObservation
                or type(selected_fixture_source_catalog) is not SelectedFixtureSourceCatalog
                or selected_fixture_source_catalog.release is not verified_installer_release
                or type(root_journal) is not RootJournalSelection
                or type(managed_process_custody) is not ManagedProcessEffectHandler):
            raise QualificationFixtureUnavailable("qualification requires held production root objects")
        if os.geteuid() != 0 or not sys_platform_linux():
            raise QualificationFixtureUnavailable("qualification requires isolated Linux root")
        current_actor_observation.verify_current(verified_installer_release)
        if current_actor_observation.pid != os.getpid():
            raise QualificationFixtureUnavailable("qualification actor is not this process")
        self.release = verified_installer_release
        self.actor = current_actor_observation
        self.catalog = selected_fixture_source_catalog
        self.root_journal = root_journal
        self.custody = managed_process_custody
        self._leases: dict[str, RootOwnedQualificationFixtureLease] = {}

    @classmethod
    def from_current_installed_actor(cls, verified_installer_release: object,
            current_actor_observation: object, selected_fixture_source_catalog: object,
            root_journal: object, managed_process_custody: object) -> "RootOwnedQualificationFixtureRegistry":
        return cls(verified_installer_release, current_actor_observation,
                   selected_fixture_source_catalog, root_journal, managed_process_custody)

    def observe_owned_fixture(self, suite_id: str) -> RootOwnedQualificationFixtureSelection:
        """Retain recipe/source/unit/root observations for the fixed task suite."""
        if suite_id != "resource-cron-task-v1":
            raise QualificationFixtureUnavailable("display source adapter is not composed")
        self.release.verify_current()
        self.actor.verify_current(self.release)
        journal = self._open_selected_journal()
        qualification_fd = fixture_fd = recipe_fd = schema_fd = -1
        identity = None
        parent_created = False
        name: str | None = None
        try:
            # Do not adopt an old or foreign qualification directory. A prior
            # run must complete its own cleanup before another run is created.
            os.mkdir("qualification", 0o700, dir_fd=journal)
            parent_created = True
            qualification_fd = os.open("qualification", os.O_RDONLY | os.O_DIRECTORY
                                       | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=journal)
            name = secrets.token_hex(16)
            os.mkdir(name, 0o700, dir_fd=qualification_fd)
            fixture_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                 | os.O_CLOEXEC, dir_fd=qualification_fd)
            recipe_fd = self.catalog.open_source(_TASK_RECIPE_ARTIFACT)
            schema_fd = self.catalog.open_source(_TASK_SCHEMA_ARTIFACT)
            unit_id = _current_systemd_unit(self.actor.pid)
            interpreter = self.actor.interpreter
            interpreter_rows = [row for row in self.release.files
                                if row.relative_path == "runtime/bin/python"
                                and row.roles == ("interpreter",)]
            if len(interpreter_rows) != 1 or os.path.realpath(interpreter[0]) != os.path.realpath(
                    self.release.release_root / interpreter_rows[0].relative_path):
                raise QualificationFixtureUnavailable("installed interpreter member is not uniquely pinned")
            from hermes_installer.authority.root_controller_custody import (
                ControllerExecutablePin, SystemdMainPidInspector,
            )
            row = interpreter_rows[0]
            pin = ControllerExecutablePin(row.artifact_id, self.release.release_root / row.relative_path,
                                          row.sha256)
            inspector = SystemdMainPidInspector()
            identity = inspector.inspect(unit_id, pin)
            if identity.pid != self.actor.pid:
                raise QualificationFixtureUnavailable("current installed actor is not this unit MainPID")
            journal_info = os.fstat(journal)
            qualification_info = os.fstat(qualification_fd)
            root_info = os.fstat(fixture_fd)
            root_handle, env_handle, unit_handle = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            namespace_tuple = "|".join(str(value) for value in (
                *identity.pid_namespace, *identity.mount_namespace, *identity.user_namespace))
            namespace_id = "ns1:" + hashlib.sha256(namespace_tuple.encode("ascii")).hexdigest()
            generation_id = "qualification-" + name
            profile_id, principal_id = "qualification-profile-" + name, "qualification-principal-" + name
            from hermes_installer.authority.qualification_resource_cron_schema import canonical_request
            payload = canonical_request("installed root task fixture")
            _recipe_path, recipe_sha, _ = self.catalog.source_identity(_TASK_RECIPE_ARTIFACT)
            _schema_path, schema_sha, _ = self.catalog.source_identity(_TASK_SCHEMA_ARTIFACT)
            selection = RootOwnedQualificationFixtureSelection(
                schema=1, selection_handle=root_handle, suite_id=suite_id,
                fixture_recipe_artifact_id=_TASK_RECIPE_ARTIFACT,
                fixture_recipe_sha256=recipe_sha,
                fixture_schema_artifact_id=_TASK_SCHEMA_ARTIFACT,
                fixture_schema_sha256=schema_sha,
                release_deployment_receipt_sha256=self.release.deployment_receipt_sha256,
                root_actor_observation_handle=secrets.token_urlsafe(32),
                fixture_root_observation_handle=root_handle,
                fixture_environment_observation_handle=env_handle,
                controller_unit_observation_handle=unit_handle,
                fixture_generation_id=generation_id, fixture_namespace_id=namespace_id,
                fixture_profile_id=profile_id, fixture_principal_id=principal_id,
                fixture_payload_sha256=hashlib.sha256(payload).hexdigest(),
                issued_monotonic=time.monotonic(), expires_monotonic=time.monotonic() + 300.0,
            )
            lease = RootOwnedQualificationFixtureLease(
                selection, self.release, self.actor, self.catalog, unit_id, pin, identity,
                inspector, name, journal, qualification_fd, fixture_fd,
                journal_info.st_dev, journal_info.st_ino,
                qualification_info.st_dev, qualification_info.st_ino,
                root_info.st_dev, root_info.st_ino, recipe_fd, schema_fd,
            )
            lease.verify_current()
            self._leases[selection.selection_handle] = lease
            identity = None
            journal = qualification_fd = fixture_fd = recipe_fd = schema_fd = -1
            return selection
        except BaseException:
            if parent_created and name is not None and journal >= 0:
                try:
                    os.rmdir(name, dir_fd=qualification_fd)
                except OSError:
                    pass
            if parent_created and journal >= 0:
                try:
                    os.rmdir("qualification", dir_fd=journal)
                except OSError:
                    pass
            for fd in (recipe_fd, schema_fd, fixture_fd, qualification_fd, journal):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            if identity is not None:
                from hermes_installer.authority.root_controller_custody import SystemdMainPidInspector
                SystemdMainPidInspector.close_pidfd(identity.pidfd)
            raise

    def resolve_current_selection(self, selection: str | RootOwnedQualificationFixtureSelection
                                  ) -> RootOwnedQualificationFixtureLease:
        if type(selection) is RootOwnedQualificationFixtureSelection:
            handle = selection.selection_handle
        elif isinstance(selection, str) and _HANDLE.fullmatch(selection):
            handle = selection
        else:
            raise QualificationFixtureUnavailable("fixture selection handle is malformed")
        lease = self._leases.get(handle)
        if lease is None or (type(selection) is RootOwnedQualificationFixtureSelection
                             and lease.selection is not selection):
            raise QualificationFixtureUnavailable("fixture selection is not retained by this registry")
        lease.verify_current()
        return lease

    def _open_selected_journal(self) -> int:
        info = os.stat(self.root_journal.path, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.root_journal.device, self.root_journal.inode)):
            raise QualificationFixtureUnavailable("selected root journal identity is not current")
        fd = os.open(self.root_journal.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        held = os.fstat(fd)
        if (held.st_dev, held.st_ino) != (self.root_journal.device, self.root_journal.inode):
            os.close(fd)
            raise QualificationFixtureUnavailable("selected root journal changed while opening")
        return fd

    def close(self) -> None:
        for lease in tuple(self._leases.values()):
            lease.close()
        self._leases.clear()


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            digest.update(part)
    finally:
        os.lseek(fd, offset, os.SEEK_SET)
    return digest.hexdigest()


def _current_systemd_unit(pid: int) -> str:
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii")
    except OSError:
        raise QualificationFixtureUnavailable("current root actor cgroup is unavailable") from None
    matches = [line.partition("::")[2].rsplit("/", 1)[-1]
               for line in cgroup.splitlines() if "::" in line]
    units = [value for value in matches if value.endswith(".service")]
    if len(units) != 1:
        raise QualificationFixtureUnavailable("current actor is not in one systemd service unit")
    return units[0]


def sys_platform_linux() -> bool:
    import sys
    return sys.platform.startswith("linux")


@dataclass(frozen=True, slots=True)
class RootInstalledQualificationResult:
    """Bounded CLI result; it does not contain or mint authority evidence."""

    schema: int
    suite_id: str
    fixture_selection_handle: str | None
    fixture_generation_id: str | None
    release_deployment_receipt_sha256: str
    controller_observation_handle: str | None
    parent_receipt_handles: tuple[str, ...]
    terminal_receipt_handle: str | None
    cleanup_receipt_handle: str | None
    evidence_sha256: str | None
    status: Literal["passed", "failed", "incomplete"]

    def __post_init__(self) -> None:
        if self.schema != 1 or self.suite_id not in _SUITES:
            raise ValueError("qualification result schema or suite is not supported")
        if self.status not in {"passed", "failed", "incomplete"}:
            raise ValueError("qualification result status is not supported")
        for value in (self.fixture_selection_handle, self.fixture_generation_id,
                      self.controller_observation_handle, self.terminal_receipt_handle,
                      self.cleanup_receipt_handle):
            if value is not None and (not isinstance(value, str) or not value or len(value) > 256):
                raise ValueError("qualification result receipt identity is malformed")
        if any(not isinstance(value, str) or not value or len(value) > 256
               for value in self.parent_receipt_handles):
            raise ValueError("qualification parent receipt identity is malformed")
        if not _SHA256.fullmatch(self.release_deployment_receipt_sha256):
            raise ValueError("qualification release digest is malformed")
        if self.evidence_sha256 is not None and not _SHA256.fullmatch(self.evidence_sha256):
            raise ValueError("qualification evidence digest is malformed")
        if self.status == "passed" and any(value is None for value in (
                self.fixture_selection_handle, self.fixture_generation_id,
                self.controller_observation_handle, self.terminal_receipt_handle,
                self.cleanup_receipt_handle, self.evidence_sha256)):
            raise ValueError("passed qualification requires retained fixture and cleanup evidence")


def run_selected_installed_qualification(suite_id: str) -> RootInstalledQualificationResult:
    """Verify the installed actor and fail incomplete until the owned producer exists.

    This path intentionally never ticks the installed production scheduler:
    its selected cron rows may represent real user work. A separate, source-
    owned fixture publication/session producer must be attached before either
    suite can return positive fixture evidence.
    """
    if suite_id not in _SUITES:
        raise ValueError("qualification suite is outside the fixed installed catalog")
    from hermes_installer.authority.installer_release import InstalledRootReleaseVerifier

    release, actor = InstalledRootReleaseVerifier.from_current_root_process()
    try:
        # These imports make the finite task assets part of the installed source
        # closure. Their held deployment rows are still checked by the release
        # receipt/actor verifier; source constants alone are not runtime proof.
        from hermes_installer.authority import qualification_resource_cron_recipe as task_recipe
        from hermes_installer.authority import qualification_resource_cron_schema as task_schema

        release.verify_current()
        actor.verify_current(release)
        required = {
            "installer-module:hermes_installer.authority.qualification_resource_cron_recipe":
                ("lib/python/hermes_installer/authority/qualification_resource_cron_recipe.py",
                 task_recipe.__file__),
            "installer-module:hermes_installer.authority.qualification_resource_cron_schema":
                ("lib/python/hermes_installer/authority/qualification_resource_cron_schema.py",
                 task_schema.__file__),
        }
        for artifact_id, (relative_path, imported_path) in required.items():
            rows = [row for row in release.files if row.artifact_id == artifact_id]
            if (len(rows) != 1 or "module" not in rows[0].roles
                    or rows[0].relative_path != relative_path
                    or os.path.realpath(imported_path) != os.path.join(
                        os.fspath(release.release_root), relative_path)):
                raise RuntimeError("qualification recipe assets are outside the held release closure")
        if suite_id != task_recipe.SUITE_ID:
            # The display recipe is owned by its source adapter and has not yet
            # been joined to an isolated publication producer.
            return RootInstalledQualificationResult(
                schema=1, suite_id=suite_id, fixture_selection_handle=None,
                fixture_generation_id=None,
                release_deployment_receipt_sha256=release.deployment_receipt_sha256,
                controller_observation_handle=None, parent_receipt_handles=(),
                terminal_receipt_handle=None, cleanup_receipt_handle=None,
                evidence_sha256=None, status="incomplete",
            )
        # No v160 RootSetupSessionStore/source-to-fixture publisher is currently
        # composed from active runtime bindings. Do not convert active resources
        # into fixture authority or mutate their source rows as a shortcut.
        return RootInstalledQualificationResult(
            schema=1, suite_id=suite_id, fixture_selection_handle=None,
            fixture_generation_id=None,
            release_deployment_receipt_sha256=release.deployment_receipt_sha256,
            controller_observation_handle=None, parent_receipt_handles=(),
            terminal_receipt_handle=None, cleanup_receipt_handle=None,
            evidence_sha256=None, status="incomplete",
        )
    finally:
        actor.close()
        release.close()
