"""Selected-plan-bound, root-held Node/Bun source archive observations (SK-T150)."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import ssl
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib import request as urllib_request

from hermes_installer.artifacts import ArtifactCatalog, ArtifactSpec, _AllowlistedRedirect
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.protected_enrollment import RootJournalSelection


_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_ROOT_ARTIFACTS = Path("/var/lib/hermes-installer/artifacts")
_OBSERVER_SEAL = object()
_RECORD_SEAL = object()

# Source identity is repeated here so a broad or stale protected catalog cannot
# silently change the source policy consumed by the setup actor.
_PINNED: dict[str, tuple[str, str, int, str, str, tuple[str, ...]]] = {
    "application-node-26.7.0-linux-arm64": (
        "26.7.0", "https://nodejs.org/dist/v26.7.0/node-v26.7.0-linux-arm64.tar.xz",
        32_581_212, "afc7a004018485092ac8985b817b0d5684472bd9472e0b57d2ab88737e50090d",
        "tar.xz", ()),
    "application-bun-1.4.3-linux-arm64": (
        "1.4.3", "https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/bun-linux-aarch64.zip",
        41_786_424, "efa9813da5ed72423bf847f916e8d2c47c0d776add972354026a75e10da9aa21",
        "zip", ("release-assets.githubusercontent.com",)),
}

_BUN_LICENSE_ID = "application-bun-1.4.3-license"
_BUN_LICENSE_PIN = (
    "c6da4a4d3010e5553438c60f6bd76d981976867c",
    "https://raw.githubusercontent.com/oven-sh/bun/c6da4a4d3010e5553438c60f6bd76d981976867c/LICENSE.md",
    5_807,
    "056696884250b0d682365260cf1487a6501b1665a343ec60e23a1e647043c572",
    (),
)


SOURCE_POLICY_ARTIFACT_ID = "installer-application-toolchain-source-policy-v144"
SOURCE_POLICY_PATH = (
    "plans/amendments/2026-10-10-hyperframes-toolchain-source-v144/"
    "hyperframes-toolchain-source-v1.json")
SOURCE_POLICY_SHA256 = "81b9e3655ddb627c46d828690687a1600fd9a7455af4c4fc5a90c32b3991a5d6"
SOURCE_POLICY_BYTES = 7060


class _TwoHopAllowlistedRedirect(_AllowlistedRedirect):
    """The artifact broker's HTTPS redirect policy capped for this source set."""

    # urllib's normal defaults allow more hops than v144 permits.
    max_redirections = 2
    max_repeats = 2


def _open_toolchain_url(req: Any, *, timeout: float, allowed_hosts: frozenset[str]):
    opener = urllib_request.build_opener(
        urllib_request.ProxyHandler({}),
        _TwoHopAllowlistedRedirect(allowed_hosts),
        urllib_request.HTTPSHandler(context=ssl.create_default_context()),
    )
    return opener.open(req, timeout=timeout)


class ApplicationToolchainSourceDenied(PermissionError):
    """The selected source, archive, or current setup authority is unavailable."""


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedToolchainSourceCatalog:
    """Root composition inputs derived from the active protected enrollment."""

    artifact_catalog: ArtifactCatalog = field(repr=False)
    artifact_staging_directory: Path = field(repr=False)
    enrollment_digest: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _OBSERVER_SEAL:
            raise TypeError("toolchain source catalogs are issued by root runtime composition")
        if (not isinstance(self.artifact_catalog, ArtifactCatalog)
                or not isinstance(self.artifact_staging_directory, Path)
                or not self.artifact_staging_directory.is_absolute()
                or not _SHA.fullmatch(self.enrollment_digest)):
            raise ValueError("protected toolchain source catalog is malformed")

    @classmethod
    def from_root_runtime(cls, bindings: RootRuntimeBindings) -> "RootSelectedToolchainSourceCatalog":
        if not isinstance(bindings, RootRuntimeBindings):
            raise ApplicationToolchainSourceDenied("selected source catalog requires root runtime bindings")
        root = getattr(bindings, "artifact_staging_directory", None)
        if not isinstance(root, Path) or root != _ROOT_ARTIFACTS:
            raise ApplicationToolchainSourceDenied("toolchain archive CAS is not the fixed protected artifact root")
        return cls(bindings.artifact_catalog, root,
                   bindings.enrollment_catalog.digest, _OBSERVER_SEAL)


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedApplicationToolchainSourceObservation:
    schema: int
    observation_handle: str
    artifact_id: str
    tool_id: str
    source_policy_artifact_id: str
    source_policy_sha256: str
    source_url_sha256: str
    source_kind: str
    archive_kind: str
    sha256: str
    size_bytes: int
    file_device: int
    file_inode: int
    file_uid: int
    file_gid: int
    file_mode: int
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    preparation_input_selection_handle: str
    source_preparation_selection_handle: str
    qualification_choice_handle: str
    choice_epoch: int
    issued_monotonic: float
    expires_monotonic: float
    _fd: int = field(repr=False, compare=False)
    _observer_id: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _RECORD_SEAL:
            raise TypeError("toolchain source observations are root-registry issued")

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            object.__setattr__(self, "_fd", -1)


class RootSelectedApplicationToolchainSourceObserver:
    """Acquire only exact source rows selected by a current root setup choice.

    The installed release's selected plan is the source-policy artifact.  Its
    `all-reviewed-verified-release-catalog-ids` policy is narrowed here to the
    two exact Hyperframes toolchains and current `acquire-locked-runtime-packages`
    consent.  The generic 256 KiB observer remains unchanged.
    """

    def __init__(self, selected_installation_binding: Any, verified_installer_release: Any,
                 root_setup_choice_registry: Any, root_journal: RootJournalSelection,
                 selected_toolchain_source_catalog: RootSelectedToolchainSourceCatalog,
                 *, expected_uid: int = 0, monotonic: Callable[[], float] = time.monotonic,
                 opener: Callable[..., Any] | None = None):
        if (os.geteuid() != expected_uid or expected_uid != 0
                or not callable(getattr(selected_installation_binding,
                                        "resolve_application_runtime_preparation_input_selection", None))
                or not callable(getattr(verified_installer_release, "verify_current", None))
                or not callable(getattr(selected_installation_binding,
                                        "resolve_application_setup_choice", None))
                or not callable(getattr(selected_installation_binding,
                                        "resolve_application_qualification_consent", None))
                or not callable(getattr(root_setup_choice_registry,
                                        "resolve_current_setup_choice", None))
                or type(root_journal) is not RootJournalSelection
                or type(selected_toolchain_source_catalog) is not RootSelectedToolchainSourceCatalog
                or selected_toolchain_source_catalog._seal is not _OBSERVER_SEAL
                or type(expected_uid) is not int or expected_uid != 0):
            raise ApplicationToolchainSourceDenied("root selected toolchain source observer bindings are unavailable")
        if (root_journal.root_id != "installer-authority-journal-v1"
                or not root_journal.path.is_absolute()
                or selected_toolchain_source_catalog.artifact_staging_directory != _ROOT_ARTIFACTS):
            raise ApplicationToolchainSourceDenied("toolchain source observer root identity is invalid")
        self.binding = selected_installation_binding
        self.release = verified_installer_release
        self.choices = selected_installation_binding
        self.setup_choices = root_setup_choice_registry
        self.journal = root_journal
        self.catalog = selected_toolchain_source_catalog
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self.opener = opener
        self._observer_id = secrets.token_urlsafe(32)
        self._held: dict[str, VerifiedApplicationToolchainSourceObservation] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        verified_installer_release: Any, root_setup_choice_registry: Any,
                        root_journal: RootJournalSelection,
                        selected_toolchain_source_catalog: RootSelectedToolchainSourceCatalog,
                        **kwargs: Any) -> "RootSelectedApplicationToolchainSourceObserver":
        return cls(selected_installation_binding, verified_installer_release,
                   root_setup_choice_registry, root_journal,
                   selected_toolchain_source_catalog, **kwargs)

    def observe_selected_toolchain_source(
            self, preparation_input_selection_handle: str,
            tool_id: str) -> VerifiedApplicationToolchainSourceObservation:
        if (os.geteuid() != self.expected_uid or self.expected_uid != 0
                or not isinstance(preparation_input_selection_handle, str)
                or not _HANDLE.fullmatch(preparation_input_selection_handle)):
            raise ApplicationToolchainSourceDenied("selected toolchain source request is malformed")
        if tool_id not in _PINNED and tool_id != _BUN_LICENSE_ID:
            raise ApplicationToolchainSourceDenied("source ID is outside the finite Node/Bun/license policy")
        pin = _BUN_LICENSE_PIN if tool_id == _BUN_LICENSE_ID else _PINNED[tool_id]
        selection, choice, consent, choice_snapshot, spec = self._resolve_selected(preparation_input_selection_handle, tool_id)
        from hermes_installer.artifacts import _fetch_artifact
        opener = self.opener or _open_toolchain_url
        last_live_check = [0.0]

        def cancelled() -> bool:
            if self.monotonic() >= selection.expires_monotonic:
                return True
            # _fetch_artifact polls this for every transfer chunk. Re-resolve the
            # signed choice at a bounded cadence so a revoked selection stops an
            # in-flight large transfer without rehashing the whole release per chunk.
            now = self.monotonic()
            if now >= last_live_check[0]:
                try:
                    self._revalidate_effect(selection, choice, consent, choice_snapshot, tool_id)
                except Exception:
                    return True
                last_live_check[0] = now + 1.0
            return False

        before_connect = lambda: self._revalidate_effect(selection, choice, consent, choice_snapshot, tool_id)
        try:
            _fetch_artifact(spec, self.catalog.artifact_staging_directory, self.expected_uid,
                            opener, 120.0, cancelled, before_connect)
            resolved = self.catalog.artifact_catalog.resolve(
                tool_id, pin[3], self.catalog.artifact_staging_directory,
                expected_uid=self.expected_uid)
            fd = os.open(resolved.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(fd)
            digest, size = self._hash_fd(fd, spec.max_bytes)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or info.st_mode & 0o222 or size != pin[2] or digest != pin[3]
                    or info.st_size != size):
                os.close(fd)
                raise ValueError
            now = self.monotonic()
            expiry = min(selection.expires_monotonic, now + 30.0)
            if expiry <= now:
                os.close(fd)
                raise ValueError
            handle = secrets.token_urlsafe(32)
            observation = VerifiedApplicationToolchainSourceObservation(
                1, handle, tool_id, tool_id, SOURCE_POLICY_ARTIFACT_ID,
                SOURCE_POLICY_SHA256,
                hashlib.sha256(spec.source_url.encode("utf-8")).hexdigest(),
                "license" if tool_id == _BUN_LICENSE_ID else "archive",
                spec.archive_format or "", digest, size, info.st_dev, info.st_ino,
                info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
                selection.setup_session_id, selection.transaction_handle,
                selection.plan_sha256, preparation_input_selection_handle,
                selection.source_preparation_selection_handle,
                selection.qualification_choice_handle,
                choice_snapshot.choice_epoch, now, expiry,
                fd, self._observer_id, _RECORD_SEAL)
            self._held[handle] = observation
            return observation
        except ApplicationToolchainSourceDenied:
            raise
        except Exception as exc:
            if hasattr(exc, "close"):
                try:
                    exc.close()
                except Exception:
                    pass
            raise ApplicationToolchainSourceDenied(
                "selected pinned toolchain archive could not be safely acquired") from None

    def verify_current(self, observation: VerifiedApplicationToolchainSourceObservation,
                       preparation_input_selection_handle: str) -> bool:
        current = self._held.get(getattr(observation, "observation_handle", ""))
        if (os.geteuid() != self.expected_uid or self.expected_uid != 0
                or type(observation) is not VerifiedApplicationToolchainSourceObservation
                or observation._seal is not _RECORD_SEAL
                or observation._observer_id != self._observer_id or current is not observation
                or observation.expires_monotonic <= self.monotonic()
                or observation.preparation_input_selection_handle != preparation_input_selection_handle):
            return False
        try:
            selection, choice, consent, choice_snapshot, spec = self._resolve_selected(
                preparation_input_selection_handle, observation.tool_id)
            info = os.fstat(observation._fd)
            digest, size = self._hash_fd(observation._fd, spec.max_bytes)
            self.release.verify_current()
            self._verify_journal()
            return (observation.artifact_id == spec.artifact_id
                    and observation.source_kind == ("license" if observation.tool_id == _BUN_LICENSE_ID else "archive")
                    and observation.sha256 == spec.sha256 == digest
                    and observation.size_bytes == size == spec.size_bytes
                    and observation.source_policy_artifact_id == SOURCE_POLICY_ARTIFACT_ID
                    and observation.source_policy_sha256 == SOURCE_POLICY_SHA256
                    and observation.plan_sha256 == selection.plan_sha256
                    and observation.setup_session_id == selection.setup_session_id
                    and observation.transaction_handle == selection.transaction_handle
                    and observation.source_preparation_selection_handle == selection.source_preparation_selection_handle
                    and observation.qualification_choice_handle == selection.qualification_choice_handle
                    and observation.choice_epoch == choice_snapshot.choice_epoch
                    and (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                         stat.S_IMODE(info.st_mode), info.st_size)
                        == (observation.file_device, observation.file_inode, observation.file_uid,
                            observation.file_gid, observation.file_mode, observation.size_bytes)
                    and stat.S_ISREG(info.st_mode) and info.st_uid == self.expected_uid
                    and info.st_nlink == 1 and not info.st_mode & 0o222
                    and consent.expires_monotonic > self.monotonic())
        except Exception:
            return False

    def open_blob(self, observation: VerifiedApplicationToolchainSourceObservation,
                  preparation_input_selection_handle: str) -> int:
        if not self.verify_current(observation, preparation_input_selection_handle):
            raise ApplicationToolchainSourceDenied("held selected toolchain source is stale or changed")
        return os.dup(observation._fd)

    def _resolve_selected(self, prep_handle: str, tool_id: str):
        from .application_runtime_selection import RootApplicationRuntimePreparationInputSelection
        selection = self.binding.resolve_application_runtime_preparation_input_selection(prep_handle)
        if type(selection) is not RootApplicationRuntimePreparationInputSelection:
            raise ApplicationToolchainSourceDenied("early runtime selector did not return its sealed root type")
        if (getattr(selection, "selection_handle", None) != prep_handle
                or getattr(selection, "application_id", None) != "hyperframes"
                or getattr(selection, "runtime_kind", None) != "node"
                or getattr(selection, "workflow_id", None) != "qualify-hyperframes-v1"
                or getattr(selection, "expires_monotonic", 0) <= self.monotonic()
                or getattr(selection, "plan_sha256", None) != self.release.selected_plan_sha256):
            raise ApplicationToolchainSourceDenied("selected early runtime preparation does not authorize this source")
        choice_handle = getattr(selection, "qualification_choice_handle", None)
        choice = self.choices.resolve_application_setup_choice(choice_handle)
        if (getattr(choice, "selection_handle", None) != choice_handle
                or getattr(choice, "application_id", None) != "hyperframes"
                or getattr(choice, "workflow_id", None) != "qualify-hyperframes-v1"
                or getattr(choice, "setup_session_id", None) != selection.setup_session_id
                or getattr(choice, "transaction_handle", None) != selection.transaction_handle):
            raise ApplicationToolchainSourceDenied("selected source no longer matches the root TTY choice")
        choice_snapshot = self.setup_choices.resolve_current_setup_choice(
            choice_handle, "application-qualification")
        payload = dict(choice_snapshot.choice_payload)
        if (choice_snapshot.selection_handle != choice_handle
                or choice_snapshot.purpose != "application-qualification"
                or payload.get("application_id") != "hyperframes"
                or payload.get("workflow_id") != "qualify-hyperframes-v1"):
            raise ApplicationToolchainSourceDenied("signed qualification choice is not the exact Hyperframes source selection")
        consent = self.choices.resolve_application_qualification_consent(
            choice_handle, "acquire-locked-runtime-packages")
        if (getattr(consent, "qualification_choice_handle", None) != choice_handle
                or getattr(consent, "purpose", None) != "installer-application-local-qualification"
                or "acquire-locked-runtime-packages" not in getattr(consent, "allowed_phase_ids", ())
                or getattr(consent, "additional_metered_budget_usd", None) != 0.0
                or getattr(consent, "expires_monotonic", 0) <= self.monotonic()):
            raise ApplicationToolchainSourceDenied("fresh exact public source acquisition consent is missing")
        self._verify_source_policy()
        if tool_id == _BUN_LICENSE_ID:
            version, url, size, digest, hosts = _BUN_LICENSE_PIN
            archive_kind = None
            filename = "LICENSE.md"
        else:
            version, url, size, digest, archive_kind, hosts = _PINNED[tool_id]
            filename = {"tar.xz": ".tar.xz", "zip": ".zip"}[archive_kind]
        spec = self.catalog.artifact_catalog._artifact(tool_id, digest)
        filename_matches = (spec.filename == filename if archive_kind is None
                            else spec.filename.endswith(filename))
        if (spec.version != version or spec.source_url != url or spec.size_bytes != size
                or spec.sha256 != digest or spec.max_bytes != size
                or spec.archive_format not in (None, archive_kind)
                or not filename_matches
                or set(spec.redirect_hosts) != set(hosts)):
            raise ApplicationToolchainSourceDenied("installed catalog row differs from exact v144 source policy")
        self.release.verify_current()
        self._verify_journal()
        return selection, choice, consent, choice_snapshot, spec

    def _revalidate_effect(self, selection: Any, choice: Any, consent: Any,
                           choice_snapshot: Any, tool_id: str) -> None:
        current = self.binding.resolve_application_runtime_preparation_input_selection(
            selection.selection_handle)
        if current is not selection or current.expires_monotonic <= self.monotonic():
            raise ApplicationToolchainSourceDenied("runtime preparation changed before source network access")
        current_choice = self.choices.resolve_application_setup_choice(choice.selection_handle)
        current_snapshot = self.setup_choices.resolve_current_setup_choice(
            choice.selection_handle, "application-qualification")
        current_consent = self.choices.resolve_application_qualification_consent(
            choice.selection_handle, "acquire-locked-runtime-packages")
        if (current_choice is not choice or current_snapshot.choice_epoch != choice_snapshot.choice_epoch
                or current_consent.qualification_choice_handle != consent.qualification_choice_handle
                or current_consent.purpose != consent.purpose
                or current_consent.allowed_phase_ids != consent.allowed_phase_ids
                or current_consent.additional_metered_budget_usd != consent.additional_metered_budget_usd
                or current_consent.expires_monotonic <= self.monotonic()):
            raise ApplicationToolchainSourceDenied("source choice or consent changed before network access")
        self._verify_source_policy()
        pin = (_BUN_LICENSE_PIN if tool_id == _BUN_LICENSE_ID else _PINNED[tool_id])
        digest = pin[3]
        spec = self.catalog.artifact_catalog._artifact(tool_id, digest)
        if spec.sha256 != digest:
            raise ApplicationToolchainSourceDenied("selected source catalog identity changed")
        self.release.verify_current()
        self._verify_journal()

    def _verify_source_policy(self) -> None:
        row = self.release.resolve_reviewed_source_artifact(SOURCE_POLICY_ARTIFACT_ID)
        if (row.relative_path != SOURCE_POLICY_PATH or row.sha256 != SOURCE_POLICY_SHA256
                or row.size_bytes != SOURCE_POLICY_BYTES or row.roles != ("amendment",)):
            raise ApplicationToolchainSourceDenied("held toolchain source policy member differs from its exact pin")
        fd = self.release.open_reviewed_source_artifact(SOURCE_POLICY_ARTIFACT_ID)
        try:
            body = os.read(fd, SOURCE_POLICY_BYTES + 1)
            if len(body) != SOURCE_POLICY_BYTES or hashlib.sha256(body).hexdigest() != SOURCE_POLICY_SHA256:
                raise ApplicationToolchainSourceDenied("held toolchain source policy bytes changed")
        finally:
            os.close(fd)
        import json
        try:
            policy = json.loads(body.decode("utf-8", "strict"))
            rows = policy["toolchain_sources"]
            selected = {item["tool_id"]: item for item in rows}
            for tool_id, pin in _PINNED.items():
                version, url, size, digest, archive_kind, _hosts = pin
                item = selected[tool_id]
                if (item["version"], item["url"], item["size_bytes"],
                        item["sha256"], item["archive_kind"]) != (
                        version, url, size, digest, archive_kind):
                    raise ValueError
            if set(selected) != set(_PINNED):
                raise ValueError
            bun = selected["application-bun-1.4.3-linux-arm64"]
            if (bun["license_url"], bun["license_sha256"], bun["license_size_bytes"]) != (
                    _BUN_LICENSE_PIN[1], _BUN_LICENSE_PIN[3], _BUN_LICENSE_PIN[2]):
                raise ValueError
        except Exception:
            raise ApplicationToolchainSourceDenied("held toolchain source policy content is malformed or changed") from None

    def _verify_journal(self) -> None:
        info = self.journal.path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.journal.device, self.journal.inode)):
            raise ApplicationToolchainSourceDenied("selected protected journal identity changed")

    @staticmethod
    def _hash_fd(fd: int, maximum: int) -> tuple[str, int]:
        digest = hashlib.sha256()
        total = 0
        while total <= maximum:
            block = os.pread(fd, min(64 * 1024, maximum + 1 - total), total)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise ApplicationToolchainSourceDenied("source archive exceeded its exact bounded size")
            digest.update(block)
        return digest.hexdigest(), total
