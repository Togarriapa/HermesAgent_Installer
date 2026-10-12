"""Fixed root-owned transaction for adopting the bundled Jarvis primary prompt."""
from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .registry.primary_prompt import (
    MAX_SOUL_BYTES,
    PrimaryPromptBlockError,
    append_managed_block,
    render_managed_block,
    split_managed_block,
)

SCHEMA = 1
HOME_UID = 1000
HOME_GID = 1000
_RECORD_FIELDS = {
    "schema", "state", "core_source_generation", "resources_revision", "resources_tree",
    "artifact_sha256", "source_prompt_sha256", "managed_block_sha256", "owner_backup_name",
    "owner_prefix_sha256", "owner_prefix_length", "owner_separator_hex", "prior_soul_sha256",
    "prior_soul_signature", "result_soul_sha256", "result_soul_signature", "stage_name",
    "native_effective_prompt_sha256", "native_effective_prompt_chars", "observed_at_utc", "error_code",
}


class PrimaryPromptAdoptionError(RuntimeError):
    """The primary prompt cannot be safely adopted, verified, or restored."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _valid_file_signature(value: Any) -> bool:
    return bool(
        isinstance(value, list) and len(value) == 9
        and all(type(part) is int and part >= 0 for part in value)
        and stat.S_ISREG(value[2]) and value[3] == HOME_UID and value[4] == HOME_GID
        and value[5] == 1 and not (stat.S_IMODE(value[2]) & 0o022)
        and 0 < value[6] <= MAX_SOUL_BYTES
    )


def _open_home(core) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open("/", flags)
    try:
        for component, uid, gid, mode in (("home", 0, 0, 0o755), ("admin", HOME_UID, HOME_GID, 0o700), (".hermes", HOME_UID, HOME_GID, 0o700)):
            child = os.open(component, flags, dir_fd=fd)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                    or stat.S_IMODE(info.st_mode) != mode or info.st_nlink < 2):
                os.close(child)
                raise PrimaryPromptAdoptionError("Hermes home directory custody differs")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _signature(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _read_soul(core) -> tuple[bytes, list[int]]:
    parent = _open_home(core)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open("SOUL.md", flags, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != HOME_UID or before.st_gid != HOME_GID
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
                    or before.st_size <= 0 or before.st_size > MAX_SOUL_BYTES):
                raise PrimaryPromptAdoptionError("primary SOUL file custody differs")
            try:
                attributes = os.listxattr(fd)
            except OSError:
                raise PrimaryPromptAdoptionError("primary SOUL extended-attribute custody is unavailable") from None
            if attributes:
                raise PrimaryPromptAdoptionError("primary SOUL has metadata this transaction cannot preserve")
            chunks = bytearray()
            while len(chunks) <= MAX_SOUL_BYTES:
                block = os.read(fd, min(65536, MAX_SOUL_BYTES + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            after = os.fstat(fd)
            named = os.stat("SOUL.md", dir_fd=parent, follow_symlinks=False)
            if (len(chunks) != before.st_size or _signature(before) != _signature(after)
                    or _signature(before) != _signature(named)):
                raise PrimaryPromptAdoptionError("primary SOUL changed during read")
            return bytes(chunks), _signature(before)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _atomic_admin_replace(core, body: bytes, *, expected_signature: list[int], uid: int = 1000,
                          gid: int = 1000, mode: int = 0o600, stage_name: str | None = None) -> list[int]:
    """Replace fixed SOUL through a held directory FD after exact inode recheck."""
    import re
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_SOUL_BYTES:
        raise PrimaryPromptAdoptionError("replacement SOUL size is invalid")
    if stage_name is None or not re.fullmatch(r"\.SOUL\.md\.jarvis-[0-9a-f]{24}\.stage", stage_name):
        raise PrimaryPromptAdoptionError("staged SOUL identity is invalid")
    parent = _open_home(core)
    temp_fd = None
    try:
        current_fd = os.open("SOUL.md", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        try:
            current = os.fstat(current_fd)
            if _signature(current) != expected_signature or current.st_uid != uid:
                raise PrimaryPromptAdoptionError("owner SOUL changed before atomic replacement")
        finally:
            os.close(current_fd)
        try:
            temp_fd = os.open(stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                              | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                              mode, dir_fd=parent)
        except FileExistsError:
            existing = os.open(stage_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            try:
                info = os.fstat(existing)
                previous = bytearray()
                while len(previous) <= MAX_SOUL_BYTES:
                    part = os.read(existing, min(65536, MAX_SOUL_BYTES + 1 - len(previous)))
                    if not part:
                        break
                    previous.extend(part)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                        or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
                        or bytes(previous) != body):
                    raise PrimaryPromptAdoptionError("interrupted SOUL stage is not journal-owned")
            finally:
                os.close(existing)
        else:
            os.fchown(temp_fd, uid, gid)
            os.fchmod(temp_fd, mode)
            offset = 0
            while offset < len(body):
                offset += os.write(temp_fd, body[offset:])
            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None
        current_named = os.stat("SOUL.md", dir_fd=parent, follow_symlinks=False)
        if _signature(current_named) != expected_signature:
            raise PrimaryPromptAdoptionError("owner SOUL changed during atomic replacement")
        os.replace(stage_name, "SOUL.md", src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        installed = os.stat("SOUL.md", dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(installed.st_mode) or installed.st_uid != uid or installed.st_gid != gid
                or stat.S_IMODE(installed.st_mode) != mode or installed.st_nlink != 1):
            raise PrimaryPromptAdoptionError("atomic SOUL replacement metadata differs")
        installed_fd = os.open("SOUL.md", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        try:
            if os.listxattr(installed_fd):
                raise PrimaryPromptAdoptionError("atomic SOUL replacement metadata differs")
        finally:
            os.close(installed_fd)
        return _signature(installed)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        os.close(parent)


def _ensure_dirs(core) -> None:
    core._ensure_dir(core.JOURNAL.parent, core.ROOT_UID, core.ROOT_UID, 0o700)
    core._ensure_dir(core.PRIMARY_PROMPT_BACKUPS, core.ROOT_UID, core.ROOT_UID, 0o700)


def _read_record(core) -> dict[str, Any] | None:
    try:
        raw = core._projection_file(core.PRIMARY_PROMPT_JOURNAL, owner=core.ROOT_UID,
                                    group=core.ROOT_UID, mode=0o600, maximum=64 * 1024)
    except FileNotFoundError:
        return None
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise PrimaryPromptAdoptionError("managed primary prompt journal is invalid") from None
    result_signature = value.get("result_soul_signature") if isinstance(value, dict) else None
    prior_signature = value.get("prior_soul_signature") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != _RECORD_FIELDS
            or type(value.get("schema")) is not int or value.get("schema") != SCHEMA
            or value.get("state") not in {"preparing", "writing", "adopted", "rolling_back", "rolled_back"}
            or not _safe_hash(value.get("core_source_generation"))
            or not _safe_hash(value.get("artifact_sha256"))
            or not _safe_hash(value.get("source_prompt_sha256"))
            or not _safe_hash(value.get("managed_block_sha256"))
            or not _safe_hash(value.get("owner_backup_name"))
            or not _safe_hash(value.get("owner_prefix_sha256"))
            or not _safe_hash(value.get("prior_soul_sha256"))
            or not _valid_file_signature(prior_signature)
            or type(value.get("owner_prefix_length")) is not int
            or not 0 <= value["owner_prefix_length"] <= MAX_SOUL_BYTES
            or (value.get("state") in {"preparing", "writing"}
                and (value.get("owner_prefix_sha256") != value.get("prior_soul_sha256")
                     or value.get("owner_prefix_length") != prior_signature[6]))
            or value.get("owner_separator_hex") not in {"", "0a", "0a0a"}
            or not isinstance(result_signature, list)
            or (value.get("state") in {"adopted", "rolling_back", "rolled_back"}
                and not _valid_file_signature(result_signature))
            or (value.get("state") in {"preparing", "writing"} and result_signature not in ([], prior_signature))
            or not isinstance(value.get("stage_name"), str)
            or not re.fullmatch(r"\.SOUL\.md\.jarvis-[0-9a-f]{24}\.stage", value["stage_name"])
            or value.get("state") in {"writing", "adopted", "rolling_back", "rolled_back"}
                and not _safe_hash(value.get("result_soul_sha256"))
            or value.get("error_code") not in {None, "effective_prompt_readback_failed"}
            or value.get("owner_backup_name") != value.get("prior_soul_sha256")):
        raise PrimaryPromptAdoptionError("managed primary prompt journal fields are unsupported")
    return value


def _write_record(core, record: dict[str, Any]) -> None:
    if set(record) != _RECORD_FIELDS:
        raise PrimaryPromptAdoptionError("managed primary prompt journal schema differs")
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    try:
        os.lstat(core.PRIMARY_PROMPT_JOURNAL)
    except FileNotFoundError:
        core._atomic(core.PRIMARY_PROMPT_JOURNAL, data, 0o600, core.ROOT_UID, core.ROOT_UID)
    else:
        core._atomic_replace(core.PRIMARY_PROMPT_JOURNAL, data, 0o600, core.ROOT_UID, core.ROOT_UID)


def _backup_bytes(core, record: dict[str, Any], prior: bytes) -> None:
    path = core.PRIMARY_PROMPT_BACKUPS / f"{record['owner_backup_name']}.bin"
    try:
        existing = core._projection_file(path, owner=core.ROOT_UID, group=core.ROOT_UID,
                                         mode=0o600, maximum=MAX_SOUL_BYTES)
    except FileNotFoundError:
        core._atomic(path, prior, 0o600, core.ROOT_UID, core.ROOT_UID)
        existing = core._projection_file(path, owner=core.ROOT_UID, group=core.ROOT_UID,
                                         mode=0o600, maximum=MAX_SOUL_BYTES)
    if existing != prior or _sha(existing) != record["owner_backup_name"]:
        raise PrimaryPromptAdoptionError("owner SOUL backup does not match its journal")


def _backup_read(core, record):
    path = core.PRIMARY_PROMPT_BACKUPS / f"{record['owner_backup_name']}.bin"
    try:
        raw = core._projection_file(path, owner=core.ROOT_UID, group=core.ROOT_UID,
                                    mode=0o600, maximum=MAX_SOUL_BYTES)
    except FileNotFoundError:
        raise PrimaryPromptAdoptionError("owner SOUL backup is missing") from None
    if _sha(raw) != record["owner_backup_name"] or _sha(raw) != record["prior_soul_sha256"]:
        raise PrimaryPromptAdoptionError("owner SOUL backup digest differs")
    return raw


def _fixed_bundle(core, *, recovery_record=None, current_prompt_sha256=None):
    from .registry import manual_jarvis_skills as native
    source_generation = core._core_source_generation()
    discovery = core.read_current_resources_discovery(core_source_generation=source_generation)
    recovery = discovery.get("resources_state") != "discovered"
    if recovery:
        # Only an explicit interrupted transaction may recover a receipt made
        # stale by its own already-journaled SOUL replacement. The persisted
        # receipt must still bind the exact prior prefix, and the independent
        # root verifier must re-prove the complete Resources tree and native
        # loader before recovery continues.
        if (not isinstance(recovery_record, dict)
                or recovery_record.get("state") not in {"preparing", "writing", "rolling_back"}
                or current_prompt_sha256 not in {recovery_record.get("prior_soul_sha256"),
                                                 recovery_record.get("result_soul_sha256")}):
            raise PrimaryPromptAdoptionError("current bundled Resources discovery is unavailable")
        retained = core._projection_file(core.RESOURCES_RECORD, owner=core.ROOT_UID,
                                         group=core.ROOT_UID, mode=0o600, maximum=16 * 1024)
        retained_record = json.loads(retained)
        if (retained_record.get("core_source_generation") != source_generation
                or retained_record.get("artifact_sha256") != recovery_record.get("artifact_sha256")
                or retained_record.get("active_primary_prompt_sha256")
                != recovery_record.get("prior_soul_sha256")):
            raise PrimaryPromptAdoptionError("stale Resources receipt is not owned by this prompt transaction")
        archive, current_payload = core._verified_resources_payload()
        artifact_now = _sha(archive)
        if (artifact_now != recovery_record.get("artifact_sha256")
                or current_payload.get("core_source_generation") != source_generation
                or current_payload.get("active_primary_prompt_sha256") != current_prompt_sha256):
            raise PrimaryPromptAdoptionError("interrupted prompt recovery failed independent native readback")
        discovery = {
            "resources_state": "discovered", "artifact_sha256": artifact_now,
            "resources_revision": current_payload["resources_revision"],
            "resources_tree": current_payload["resources_tree"],
        }
    else:
        archive = None
    artifact_sha = discovery.get("artifact_sha256")
    if not _safe_hash(artifact_sha):
        raise PrimaryPromptAdoptionError("current bundled Resources artifact identity is invalid")
    if archive is None:
        archive = core._projection_file(core.RESOURCES_CAS / f"{artifact_sha}.zip", owner=core.ROOT_UID,
                                        group=core.ROOT_UID, mode=0o600, maximum=16 * 1024 * 1024)
    if _sha(archive) != artifact_sha:
        raise PrimaryPromptAdoptionError("current bundled Resources artifact digest differs")
    manifest, files = native._read_artifact(archive, artifact_sha)
    current_bytes = core._projection_file(core.RESOURCES_RECORD, owner=core.ROOT_UID,
                                          group=core.ROOT_UID, mode=0o600, maximum=16 * 1024)
    current_record = json.loads(current_bytes)
    source = manifest.get("source")
    resources_tree = current_record.get("resources_tree")
    if (not isinstance(source, dict)
            or not isinstance(resources_tree, str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", resources_tree) is None
            or source.get("revision") != discovery.get("resources_revision")
            or source.get("git_tree") != resources_tree
            or current_record.get("artifact_sha256") != artifact_sha
            or current_record.get("core_source_generation") != source_generation):
        raise PrimaryPromptAdoptionError("current Resources source receipt changed")
    # read_current_resources_discovery above is the strict owner-side verifier:
    # it checks the root receipt/CAS, immutable generation journal, exact
    # membership and every current member byte before returning discovered.
    prompt = files.get("registry/profiles/hermes/SOUL.md")
    if not isinstance(prompt, bytes) or not prompt:
        raise PrimaryPromptAdoptionError("verified Jarvis primary prompt is absent")
    after = core.read_current_resources_discovery(core_source_generation=source_generation)
    retained_after = core._projection_file(core.RESOURCES_RECORD, owner=core.ROOT_UID,
                                           group=core.ROOT_UID, mode=0o600, maximum=16 * 1024)
    if retained_after != current_bytes or core._core_source_generation() != source_generation:
        raise PrimaryPromptAdoptionError("Resources receipt changed during prompt preparation")
    if not recovery and after != discovery:
        raise PrimaryPromptAdoptionError("Resources source changed during prompt preparation")
    if not recovery and (after.get("resources_state") != "discovered"
                         or after.get("artifact_sha256") != artifact_sha):
        raise PrimaryPromptAdoptionError("Resources source changed during prompt preparation")
    return source_generation, discovery, artifact_sha, manifest, files, prompt


def _verify_native(core, manifest, files, current: bytes, block_sha: str | None):
    receipt = core._root_native_readback(
        manifest, files, current, expected_managed_block_sha256=block_sha
    )
    if block_sha is not None and (receipt.get("managed_prompt_block_sha256") != block_sha
            or receipt.get("effective_prompt_contains_managed_block") is not True
            or receipt.get("effective_prompt_truncated") is not False):
        raise PrimaryPromptAdoptionError("native effective primary prompt omitted or truncated its managed block")
    return receipt


def _record_matches_current(core, record, current: bytes, manifest, files) -> dict[str, Any]:
    from .registry.primary_prompt import render_managed_block
    prefix, _separator, block = split_managed_block(
        current, owner_prefix_length=record["owner_prefix_length"],
        separator=bytes.fromhex(record["owner_separator_hex"]),
    )
    source_prompt = files.get("registry/profiles/hermes/SOUL.md")
    if (_sha(prefix) != record["owner_prefix_sha256"]
            or _sha(current) != record.get("result_soul_sha256")
            or _sha(block) != record["managed_block_sha256"]
            or not isinstance(source_prompt, bytes) or source_prompt not in block
            or record.get("source_prompt_sha256") != _sha(source_prompt)
            or block != render_managed_block(source_prompt)
            or record.get("resources_revision") != manifest.get("source", {}).get("revision")
            or record.get("resources_tree") != manifest.get("source", {}).get("git_tree")):
        raise PrimaryPromptAdoptionError("active primary prompt differs from its owned block receipt")
    receipt = _verify_native(core, manifest, files, current, record["managed_block_sha256"])
    if receipt.get("active_primary_prompt_sha256") != _sha(current):
        raise PrimaryPromptAdoptionError("native primary prompt raw readback differs")
    return receipt


def _check_root_context(core, *, require_listener=True):
    if os.geteuid() != core.ROOT_UID or not os.path.isdir("/proc"):
        raise PrimaryPromptAdoptionError("requires the fixed Linux root actor")
    core._identity()
    service_record = core._journal()
    if service_record.get("state") not in {"installed", "active"}:
        raise PrimaryPromptAdoptionError("journal-owned core service is not installed")
    if require_listener and not core._owned_listener():
        raise PrimaryPromptAdoptionError("journal-owned core listener is not current")
    return service_record


def _new_record(source_generation, discovery, artifact_sha, resources_tree,
                prompt, block, prior, signature, prefix, separator):
    return {
        "schema": SCHEMA, "state": "preparing", "core_source_generation": source_generation,
        "resources_revision": discovery["resources_revision"], "resources_tree": resources_tree,
        "artifact_sha256": artifact_sha, "source_prompt_sha256": _sha(prompt),
        "managed_block_sha256": _sha(block), "owner_backup_name": _sha(prior),
        "owner_prefix_sha256": _sha(prefix), "owner_prefix_length": len(prefix),
        "owner_separator_hex": separator.hex(), "prior_soul_sha256": _sha(prior),
        "prior_soul_signature": signature, "result_soul_sha256": _sha(prefix + separator + block),
        "result_soul_signature": [], "stage_name": ".SOUL.md.jarvis-" + secrets.token_hex(12) + ".stage",
        "native_effective_prompt_sha256": None, "native_effective_prompt_chars": None,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "error_code": None,
    }


def _require_initial_custody(core, custody) -> None:
    custody_type = getattr(core, "InitialPrimaryAdoptionCustody", None)
    validator = getattr(core, "verify_initial_primary_adoption_custody", None)
    if (custody_type is None or type(custody) is not custody_type
            or not callable(validator)):
        raise PrimaryPromptAdoptionError("sealed starting-cohort primary custody is unavailable")
    try:
        validator(custody)
    except Exception as exc:
        raise PrimaryPromptAdoptionError("sealed starting-cohort primary custody is stale") from exc


def _initial_scope(core, custody):
    scope = getattr(core, "initial_primary_adoption_scope", None)
    if not callable(scope):
        raise PrimaryPromptAdoptionError("fixed starting-cohort primary read scope is unavailable")
    return scope(custody)


def _record_initial_stage(core, custody) -> None:
    _require_initial_custody(core, custody)
    record_stage = getattr(core, "record_initial_primary_manager_stage", None)
    if not callable(record_stage):
        raise PrimaryPromptAdoptionError("starting-cohort manager stage recorder is unavailable")
    try:
        record_stage(custody)
    except Exception as exc:
        raise PrimaryPromptAdoptionError("starting-cohort manager stage did not bind") from exc


def _bind_initial_custody_fields(custody, *, prior_sha, prior_signature,
                                 source_prompt, block, desired, separator) -> None:
    if (custody.prior_soul_sha256 != prior_sha
            or tuple(custody.prior_soul_signature) != tuple(prior_signature)
            or custody.source_prompt_sha256 != _sha(source_prompt)
            or custody.managed_block_sha256 != _sha(block)
            or custody.desired_soul_sha256 != _sha(desired)
            or custody.owner_separator_hex != separator.hex()):
        raise PrimaryPromptAdoptionError("starting-cohort SOUL or prompt snapshot differs")


def adopt_primary_prompt_for_starting_cohort(custody) -> dict[str, Any]:
    """Adopt the fixed bundled prompt under CoreRuntime's sealed starting cohort."""
    from . import core_runtime as core
    _require_initial_custody(core, custody)
    if os.geteuid() != core.ROOT_UID:
        raise PrimaryPromptAdoptionError("requires the fixed Linux root actor")
    _check_root_context(core, require_listener=False)
    _require_initial_custody(core, custody)
    _ensure_dirs(core)

    # Serialize with owner-prefix edits. CoreRuntime already holds its updater lock;
    # this is the same narrow lock used by owner SOUL edits and ordinary adoption.
    lock_path = core.PRIMARY_PROMPT_BACKUPS / "owner-prefix.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != core.ROOT_UID
                or info.st_gid != core.ROOT_UID or stat.S_IMODE(info.st_mode) != 0o600):
            raise PrimaryPromptAdoptionError("owner SOUL edit lock custody differs")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return _adopt_primary_prompt_for_starting_cohort_locked(core, custody)
    finally:
        os.close(lock_fd)


def _adopt_primary_prompt_for_starting_cohort_locked(core, custody) -> dict[str, Any]:
    from .registry.primary_prompt import append_managed_block, render_managed_block

    _require_initial_custody(core, custody)
    with _initial_scope(core, custody):
        _require_initial_custody(core, custody)
        record = _read_record(core)
        current, signature = _read_soul(core)
    current_sha = _sha(current)
    with _initial_scope(core, custody):
        _require_initial_custody(core, custody)
        source_generation, discovery, artifact_sha, manifest, files, source_prompt = _fixed_bundle(
            core, recovery_record=record, current_prompt_sha256=current_sha
        )

    block = render_managed_block(source_prompt)
    block_sha = _sha(block)
    if record is None:
        if current_sha != custody.prior_soul_sha256 or tuple(signature) != tuple(custody.prior_soul_signature):
            raise PrimaryPromptAdoptionError("starting-cohort owner SOUL snapshot differs")
        desired, separator = append_managed_block(current, block)
        _bind_initial_custody_fields(
            custody, prior_sha=current_sha, prior_signature=signature,
            source_prompt=source_prompt, block=block, desired=desired, separator=separator,
        )
    if record is not None:
        # Only the CoreRuntime sealed transition may authorize a manager record
        # after the initial absence snapshot. Its validator binds the exact stage.
        if record.get("state") == "adopted":
            with _initial_scope(core, custody):
                _require_initial_custody(core, custody)
                receipt = _record_matches_current(core, record, current, manifest, files)
            return _status_record(record, receipt)
        if record.get("state") not in {"preparing", "writing"}:
            raise PrimaryPromptAdoptionError("starting-cohort primary journal state cannot resume")
        if (record.get("core_source_generation") != source_generation
                or record.get("artifact_sha256") != artifact_sha
                or record.get("source_prompt_sha256") != _sha(source_prompt)
                or record.get("managed_block_sha256") != block_sha):
            raise PrimaryPromptAdoptionError("starting-cohort prompt stage has stale source custody")
        with _initial_scope(core, custody):
            _require_initial_custody(core, custody)
            backup = _backup_read(core, record)
        desired = backup + bytes.fromhex(record["owner_separator_hex"]) + block
        _bind_initial_custody_fields(
            custody, prior_sha=record["prior_soul_sha256"],
            prior_signature=record["prior_soul_signature"], source_prompt=source_prompt,
            block=block, desired=desired,
            separator=bytes.fromhex(record["owner_separator_hex"]),
        )
        if current not in {backup, desired}:
            raise PrimaryPromptAdoptionError("starting-cohort prompt stage found changed owner bytes")
        if current == desired:
            with _initial_scope(core, custody):
                _require_initial_custody(core, custody)
                _record_matches_current(core, record, desired, manifest, files)
                receipt = _verify_native(core, manifest, files, desired, block_sha)
            refresh = getattr(core, "refresh_initial_primary_starting_tuple", None)
            if not callable(refresh):
                raise PrimaryPromptAdoptionError("fixed starting-cohort Resources refresh is unavailable")
            _require_initial_custody(core, custody)
            refresh(custody)
            record["state"] = "adopted"
            record["native_effective_prompt_sha256"] = receipt["native_effective_prompt_sha256"]
            record["native_effective_prompt_chars"] = receipt["native_effective_prompt_chars"]
            record["result_soul_signature"] = signature
            record["observed_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            _require_initial_custody(core, custody)
            _write_record(core, record)
            _record_initial_stage(core, custody)
            return _status_record(record, receipt)
        prior = backup
        prior_signature = record["prior_soul_signature"]
    else:
        if (b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 BEGIN -->" in current
                or b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 END -->" in current):
            raise PrimaryPromptAdoptionError("unowned primary prompt marker is ambiguous")
        prior = current
        prior_signature = signature
        record = _new_record(source_generation, discovery, artifact_sha,
                             manifest["source"]["git_tree"], source_prompt, block,
                             prior, signature, prior, separator)
        _require_initial_custody(core, custody)
        _write_record(core, record)
        _require_initial_custody(core, custody)
        _backup_bytes(core, record, prior)
        _record_initial_stage(core, custody)
    if record.get("state") == "preparing":
        _require_initial_custody(core, custody)
        record["state"] = "writing"
        _write_record(core, record)
        _record_initial_stage(core, custody)

    _require_initial_custody(core, custody)
    with _initial_scope(core, custody):
        _require_initial_custody(core, custody)
        active, active_signature = _read_soul(core)
        if active != prior or active_signature != prior_signature:
            raise PrimaryPromptAdoptionError("owner SOUL changed before initial prompt append")
        _backup_bytes(core, record, prior)
        _atomic_admin_replace(
            core, desired, expected_signature=prior_signature,
            uid=prior_signature[3], gid=prior_signature[4],
            mode=stat.S_IMODE(prior_signature[2]), stage_name=record["stage_name"],
        )
        installed, installed_signature = _read_soul(core)
        if installed != desired:
            raise PrimaryPromptAdoptionError("initial primary append readback differs")
        receipt = _verify_native(core, manifest, files, installed, block_sha)

    # CoreRuntime independently reads the installed SOUL and A1 payload and CAS
    # refreshes only this cohort's starting Resources tuple.
    _require_initial_custody(core, custody)
    refresh = getattr(core, "refresh_initial_primary_starting_tuple", None)
    if not callable(refresh):
        raise PrimaryPromptAdoptionError("fixed starting-cohort Resources refresh is unavailable")
    try:
        refresh(custody)
    except Exception as exc:
        raise PrimaryPromptAdoptionError("starting-cohort Resources refresh failed") from exc

    record["state"] = "adopted"
    record["native_effective_prompt_sha256"] = receipt["native_effective_prompt_sha256"]
    record["native_effective_prompt_chars"] = receipt["native_effective_prompt_chars"]
    record["result_soul_signature"] = installed_signature
    record["observed_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    _require_initial_custody(core, custody)
    _write_record(core, record)
    _record_initial_stage(core, custody)
    return _status_record(record, receipt)


def rollback_primary_prompt_for_starting_cohort(custody) -> None:
    """Restore the exact initial append under stopped-service rollback custody."""
    from . import core_runtime as core

    custody_type = getattr(core, "InitialPrimaryRollbackCustody", None)
    validator = getattr(core, "verify_initial_primary_rollback_custody", None)
    if (custody_type is None or type(custody) is not custody_type
            or not callable(validator)):
        raise PrimaryPromptAdoptionError("sealed starting-cohort rollback custody is unavailable")
    try:
        validator(custody)
    except Exception as exc:
        raise PrimaryPromptAdoptionError("sealed starting-cohort rollback custody is stale") from exc
    if os.geteuid() != core.ROOT_UID:
        raise PrimaryPromptAdoptionError("requires the fixed Linux root actor")
    lock_path = core.PRIMARY_PROMPT_BACKUPS / "owner-prefix.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != core.ROOT_UID
                or info.st_gid != core.ROOT_UID or stat.S_IMODE(info.st_mode) != 0o600):
            raise PrimaryPromptAdoptionError("owner SOUL edit lock custody differs")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            validator(custody)
        except Exception as exc:
            raise PrimaryPromptAdoptionError("sealed starting-cohort rollback custody is stale") from exc
        raw = core._projection_file(core.PRIMARY_PROMPT_JOURNAL, owner=core.ROOT_UID,
                                    group=core.ROOT_UID, mode=0o600, maximum=64 * 1024)
        if _sha(raw) != custody.primary_stage_sha256:
            raise PrimaryPromptAdoptionError("retained primary manager stage differs")
        record = _read_record(core)
        if record is None or record.get("state") not in {"preparing", "writing", "rolling_back"}:
            raise PrimaryPromptAdoptionError("owned initial primary rollback stage is unavailable")
        if (record["prior_soul_sha256"] != custody.prior_soul_sha256
                or tuple(record["prior_soul_signature"]) != tuple(custody.prior_soul_signature)
                or record["core_source_generation"] != custody.core_source_generation
                or record["artifact_sha256"] != custody.artifact_a1_sha256
                or record["source_prompt_sha256"] != custody.source_prompt_sha256
                or record["managed_block_sha256"] != custody.managed_block_sha256
                or record["result_soul_sha256"] != custody.desired_soul_sha256
                or record["owner_backup_name"] != custody.owner_backup_name
                or record["owner_backup_name"] != custody.owner_backup_sha256):
            raise PrimaryPromptAdoptionError("retained primary manager stage fields differ")
        backup = _backup_read(core, record)
        if _sha(backup) != custody.owner_backup_sha256:
            raise PrimaryPromptAdoptionError("immutable primary owner backup differs")
        current, signature = _read_soul(core)
        if current == backup:
            return
        try:
            prefix, separator, block = split_managed_block(
                current, owner_prefix_length=record["owner_prefix_length"],
                separator=bytes.fromhex(record["owner_separator_hex"]),
            )
        except PrimaryPromptBlockError as exc:
            raise PrimaryPromptAdoptionError("owned initial primary block cannot be verified") from exc
        desired = backup + bytes.fromhex(record["owner_separator_hex"]) + block
        if (prefix != backup or _sha(prefix) != record["owner_prefix_sha256"]
                or separator.hex() not in {"", "0a", "0a0a"}
                or separator.hex() != record["owner_separator_hex"]
                or _sha(block) != custody.managed_block_sha256
                or current != desired or _sha(current) != custody.desired_soul_sha256):
            raise PrimaryPromptAdoptionError("owner SOUL changed; initial rollback is refused")
        try:
            validator(custody)
        except Exception as exc:
            raise PrimaryPromptAdoptionError("sealed starting-cohort rollback custody is stale") from exc
        current, signature = _read_soul(core)
        if current != desired or _sha(current) != custody.desired_soul_sha256:
            raise PrimaryPromptAdoptionError("owner SOUL changed before initial rollback")
        _atomic_admin_replace(
            core, backup, expected_signature=signature,
            uid=signature[3], gid=signature[4], mode=stat.S_IMODE(signature[2]),
            stage_name=record["stage_name"],
        )
        restored, restored_signature = _read_soul(core)
        if (restored != backup or _sha(restored) != custody.prior_soul_sha256
                or restored_signature[3] != custody.prior_soul_signature[3]
                or restored_signature[4] != custody.prior_soul_signature[4]
                or stat.S_IMODE(restored_signature[2]) != stat.S_IMODE(custody.prior_soul_signature[2])
                or restored_signature[6] != custody.prior_soul_signature[6]):
            raise PrimaryPromptAdoptionError("initial rollback did not restore exact owner SOUL bytes")
    finally:
        os.close(lock_fd)


def adopt_primary_prompt() -> dict[str, Any]:
    """Append the verified Jarvis primary prompt through a root-owned transaction."""
    from . import core_runtime as core
    from .registry.primary_prompt import append_managed_block, render_managed_block

    if os.geteuid() != core.ROOT_UID:
        raise PrimaryPromptAdoptionError("requires the fixed Linux root actor")
    _check_root_context(core)
    _ensure_dirs(core)
    record = _read_record(core)
    current, signature = _read_soul(core)
    source_generation, discovery, artifact_sha, manifest, files, source_prompt = _fixed_bundle(
        core, recovery_record=record, current_prompt_sha256=_sha(current)
    )
    block = render_managed_block(source_prompt)
    block_sha = _sha(block)

    if record is not None:
        try:
            backup = _backup_read(core, record)
        except PrimaryPromptAdoptionError:
            if (record.get("state") == "preparing"
                    and _sha(current) == record.get("prior_soul_sha256")):
                _backup_bytes(core, record, current)
                backup = current
            else:
                raise
        if record["state"] == "adopted":
            if (record["core_source_generation"] != source_generation
                    or record["artifact_sha256"] != artifact_sha
                    or record["managed_block_sha256"] != block_sha):
                raise PrimaryPromptAdoptionError("managed prompt source changed; reviewed rebase is required")
            if signature != record["result_soul_signature"]:
                raise PrimaryPromptAdoptionError("active SOUL metadata changed after managed adoption")
            receipt = _record_matches_current(core, record, current, manifest, files)
            return _status_record(record, receipt)
        if record["state"] == "rolled_back":
            if current != backup:
                raise PrimaryPromptAdoptionError("rolled-back SOUL changed; refusing to replace owner edits")
            record = None
        elif record["state"] in {"preparing", "writing"}:
            if (record["core_source_generation"] != source_generation
                    or record["artifact_sha256"] != artifact_sha
                    or record["source_prompt_sha256"] != _sha(source_prompt)
                    or record["managed_block_sha256"] != block_sha):
                raise PrimaryPromptAdoptionError("interrupted prompt transaction has stale source custody")
            desired = backup + bytes.fromhex(record["owner_separator_hex"]) + block
            if current == desired:
                return _finalize_adoption(core, record, manifest, files, current, signature)
            if current != backup:
                raise PrimaryPromptAdoptionError("interrupted prompt transaction found changed owner bytes")
            _backup_bytes(core, record, current)
            return _commit_adoption(core, record, manifest, files, current, signature, desired)
        elif record["state"] == "rolling_back":
            raise PrimaryPromptAdoptionError("primary prompt rollback is incomplete; resume rollback")
        else:
            raise PrimaryPromptAdoptionError("managed prompt journal state is unsupported")

    if record is None:
        if (b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 BEGIN -->" in current
                or b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 END -->" in current):
            raise PrimaryPromptAdoptionError("unowned primary prompt marker is ambiguous")
        desired, separator = append_managed_block(current, block)
        record = _new_record(source_generation, discovery, artifact_sha,
                             manifest["source"]["git_tree"], source_prompt,
                             block, current, signature, current, separator)
        _write_record(core, record)
    _backup_bytes(core, record, current)
    return _commit_adoption(core, record, manifest, files, current, signature, desired)


def rebase_identical_primary_binding(prepared_transition) -> dict[str, Any]:
    """Rebind an already-adopted, byte-identical Jarvis block to a new source.

    This is deliberately metadata-only: it never writes SOUL.md or the immutable
    pre-adoption backup, and it cannot create an initial adoption record.
    CoreRuntime's short-lived in-process transition is the authority for the
    cross-generation snapshot; every owner file is independently re-read here.
    """
    from . import core_runtime as core
    from .registry.primary_prompt import render_managed_block

    if os.geteuid() != core.ROOT_UID:
        raise PrimaryPromptAdoptionError("requires the fixed Linux root actor")
    validator = getattr(core, "verify_prepared_same_materialization_transition", None)
    claimer = getattr(core, "claim_prepared_same_materialization_step", None)
    if (not callable(validator) or not callable(claimer)
            or not validator(prepared_transition, purpose="helper-only")):
        raise PrimaryPromptAdoptionError("prepared helper-only transition is unavailable")
    _check_root_context(core)
    _ensure_dirs(core)

    # Serialize with owner-prefix edits, then repeat all mutable joins while
    # holding the same root-only lock used by those edits.
    lock_path = core.PRIMARY_PROMPT_BACKUPS / "owner-prefix.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != core.ROOT_UID
                or info.st_gid != core.ROOT_UID or stat.S_IMODE(info.st_mode) != 0o600):
            raise PrimaryPromptAdoptionError("owner SOUL edit lock custody differs")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return _rebase_identical_primary_binding_locked(core, prepared_transition, claimer)
    finally:
        os.close(lock_fd)


def _rebase_identical_primary_binding_locked(core, prepared_transition, claimer):
    from .registry.primary_prompt import render_managed_block
    if not core.verify_prepared_same_materialization_transition(
            prepared_transition, purpose="helper-only"):
        raise PrimaryPromptAdoptionError("prepared helper-only transition is stale")
    record_raw = core._projection_file(core.PRIMARY_PROMPT_JOURNAL, owner=core.ROOT_UID,
        group=core.ROOT_UID, mode=0o600, maximum=64 * 1024)
    record = _read_record(core)
    if record is None or record.get("state") != "adopted":
        raise PrimaryPromptAdoptionError("a genuinely adopted primary prompt is required")
    transition = prepared_transition
    if (record.get("core_source_generation") != transition.old_source_generation
            or record.get("artifact_sha256") != transition.old_artifact_sha256
            or _sha(record_raw) != transition.primary_record_sha256):
        raise PrimaryPromptAdoptionError("adopted primary record differs from prepared transition")

    current, signature = _read_soul(core)
    if (_sha(current) != transition.soul_sha256
            or tuple(signature) != tuple(transition.soul_signature)
            or signature != record.get("result_soul_signature")):
        raise PrimaryPromptAdoptionError("current SOUL custody differs from prepared transition")
    prefix, separator, block = split_managed_block(current,
        owner_prefix_length=record["owner_prefix_length"],
        separator=bytes.fromhex(record["owner_separator_hex"]))
    if (len(prefix) != transition.owner_prefix_length
            or _sha(prefix) != transition.owner_prefix_sha256
            or record["owner_prefix_sha256"] != transition.owner_prefix_sha256
            or record["owner_separator_hex"] != transition.owner_separator_hex
            or _sha(block) != transition.managed_block_sha256
            or record["managed_block_sha256"] != transition.managed_block_sha256
            or _sha(current) != record.get("result_soul_sha256")):
        raise PrimaryPromptAdoptionError("adopted owner bytes differ from prepared transition")
    prior = _backup_read(core, record)
    if (_sha(prior) != transition.prior_backup_sha256
            or _sha(prior) != record.get("owner_backup_name")):
        raise PrimaryPromptAdoptionError("immutable prior SOUL backup differs")

    generation, discovery, artifact_sha, manifest, files, source_prompt = _fixed_bundle(core)
    from .registry import manual_jarvis_skills as native
    new_archive = core._projection_file(core.RESOURCES_CAS / f"{artifact_sha}.zip",
        owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600, maximum=16 * 1024 * 1024)
    new_manifest, new_files, new_helper = native._read_transition_archive(new_archive, artifact_sha)
    if (generation != transition.new_source_generation
            or artifact_sha != transition.new_artifact_sha256
            or hashlib.sha256(native._canonical_json(new_manifest)).hexdigest()
                != transition.new_manifest_sha256):
        raise PrimaryPromptAdoptionError("new Resources source differs from prepared transition")
    old_archive = core._projection_file(core.RESOURCES_CAS / f"{transition.old_artifact_sha256}.zip",
        owner=core.ROOT_UID, group=core.ROOT_UID, mode=0o600, maximum=16 * 1024 * 1024)
    if hashlib.sha256(old_archive).hexdigest() != transition.old_artifact_sha256:
        raise PrimaryPromptAdoptionError("retained old Resources artifact differs")
    old_manifest, old_files, _old_helper = native._read_transition_archive(
        old_archive, transition.old_artifact_sha256)
    shared_digests = native._same_materialization_digests(new_manifest, new_files)
    if (not native.verify_same_materialization_transition(
            old_manifest, old_files, new_manifest, new_files)
            or new_helper != Path(native.__file__).read_bytes()
            or shared_digests != (transition.shared_manifest_sha256,
                                  transition.shared_materialization_sha256,
                                  transition.shared_member_count)
            or hashlib.sha256(native._canonical_json(old_manifest)).hexdigest()
                != transition.old_manifest_sha256):
        raise PrimaryPromptAdoptionError("Resources helper-only transition proof differs")
    next_block = render_managed_block(source_prompt)
    if (source_prompt != files.get("registry/profiles/hermes/SOUL.md")
            or next_block != block or _sha(next_block) != transition.managed_block_sha256
            or _sha(source_prompt) != record.get("source_prompt_sha256")):
        raise PrimaryPromptAdoptionError("new primary block is not byte-identical to the adopted block")
    # Check the old source archive against the historic record, without trying
    # to execute its helper or to treat old source as current authority.
    if (record.get("resources_revision") != old_manifest.get("source", {}).get("revision")
            or record.get("resources_tree") != old_manifest.get("source", {}).get("git_tree")):
        raise PrimaryPromptAdoptionError("adopted record does not match its retained source artifact")
    old_prompt = old_files.get("registry/profiles/hermes/SOUL.md")
    if (old_prompt != source_prompt
            or _sha(old_prompt) != record.get("source_prompt_sha256")
            or render_managed_block(old_prompt) != block):
        raise PrimaryPromptAdoptionError("retained and current primary prompt bytes differ")

    receipt = _verify_native(core, manifest, files, current, record["managed_block_sha256"])
    if (receipt.get("active_primary_prompt_sha256") != _sha(current)
            or receipt.get("effective_prompt_contains_managed_block") is not True
            or receipt.get("effective_prompt_truncated") is not False
            or core._core_source_generation() != generation):
        raise PrimaryPromptAdoptionError("new native effective primary readback did not verify")

    updated = dict(record)
    updated.update({
        "core_source_generation": generation,
        "resources_revision": manifest["source"]["revision"],
        "resources_tree": manifest["source"]["git_tree"],
        "artifact_sha256": artifact_sha,
        "native_effective_prompt_sha256": receipt["native_effective_prompt_sha256"],
        "native_effective_prompt_chars": receipt["native_effective_prompt_chars"],
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    })
    # Close the race after native readback and immediately before the durable
    # metadata effect. The sealed producer allows one claim per cohort step.
    if (not core.verify_prepared_same_materialization_transition(
            prepared_transition, purpose="helper-only")
            or core._projection_file(core.PRIMARY_PROMPT_JOURNAL, owner=core.ROOT_UID,
                group=core.ROOT_UID, mode=0o600, maximum=64 * 1024) != record_raw
            or _read_soul(core) != (current, signature)):
        raise PrimaryPromptAdoptionError("primary prompt changed during reviewed rebase")
    if not claimer(prepared_transition, step="primary-rebase"):
        raise PrimaryPromptAdoptionError("primary rebase step was already consumed")
    _write_record(core, updated)
    readback = _read_record(core)
    if readback != updated:
        raise PrimaryPromptAdoptionError("primary rebase journal readback differs")
    return _status_record(updated, receipt)


def _commit_adoption(core, record, manifest, files, prior, prior_signature, desired):
    if record.get("state") == "preparing":
        record["state"] = "writing"
        _write_record(core, record)
    _backup_bytes(core, record, prior if _sha(prior) == record["prior_soul_sha256"] else _backup_read(core, record))
    installed_signature = _atomic_admin_replace(
        core, desired, expected_signature=prior_signature,
        uid=prior_signature[3], gid=prior_signature[4],
        mode=stat.S_IMODE(prior_signature[2]), stage_name=record["stage_name"],
    )
    record["result_soul_signature"] = installed_signature
    return _finalize_adoption(core, record, manifest, files, desired, installed_signature)


def _finalize_adoption(core, record, manifest, files, current, signature):
    try:
        receipt = _record_matches_current(core, record, current, manifest, files)
        if core._core_source_generation() != record["core_source_generation"]:
            raise PrimaryPromptAdoptionError("source or Resources custody changed during prompt readback")
        # The active SOUL digest changed by design. Refresh the root receipt
        # only after exact native effective-prompt verification succeeded.
        core._write_resources_discovery()
        final_discovery = core.read_current_resources_discovery(
                core_source_generation=record["core_source_generation"]
        )
        if (final_discovery.get("resources_state") != "discovered"
                or final_discovery.get("artifact_sha256") != record["artifact_sha256"]):
            raise PrimaryPromptAdoptionError("updated Resources receipt did not verify")
    except Exception:
        active, active_signature = _read_soul(core)
        if active == current and _sha(active) == record.get("result_soul_sha256"):
            backup = _backup_read(core, record)
            restored_signature = _atomic_admin_replace(
                core, backup, expected_signature=active_signature,
                uid=active_signature[3], gid=active_signature[4],
                mode=stat.S_IMODE(active_signature[2]), stage_name=record["stage_name"])
            record["state"] = "rolled_back"
            record["result_soul_sha256"] = _sha(backup)
            record["result_soul_signature"] = restored_signature
            record["error_code"] = "effective_prompt_readback_failed"
            _write_record(core, record)
            try:
                core._write_resources_discovery()
            except Exception:
                pass
        raise
    record["state"] = "adopted"
    record["native_effective_prompt_sha256"] = receipt["native_effective_prompt_sha256"]
    record["native_effective_prompt_chars"] = receipt["native_effective_prompt_chars"]
    record["result_soul_signature"] = signature
    record["observed_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    _write_record(core, record)
    return _status_record(record, receipt)


def _status_record(record, receipt):
    return {
        "state": record["state"], "managed_primary_block_verified": record["state"] == "adopted",
        "effective_prompt_contains_full_block": receipt.get("effective_prompt_contains_managed_block") is True,
        "effective_prompt_truncated": receipt.get("effective_prompt_truncated") is True,
        "resources_revision": record["resources_revision"], "resources_tree": record["resources_tree"],
        "artifact_sha256": record["artifact_sha256"],
        "source_prompt_sha256": record["source_prompt_sha256"],
        "managed_block_sha256": record["managed_block_sha256"],
        "owner_prefix_sha256": record["owner_prefix_sha256"],
        "owner_backup_sha256": record["owner_backup_name"],
        "active_soul_sha256": record["result_soul_sha256"],
        "native_effective_prompt_sha256": receipt.get("native_effective_prompt_sha256"),
        "native_effective_prompt_chars": receipt.get("native_effective_prompt_chars"),
        "functional": False,
    }


def write_owner_prefix(content: str, *, expected_sha256: str, idempotency_key: str,
                       core_source_generation: str) -> dict[str, Any]:
    from . import core_runtime as core
    if os.geteuid() != core.ROOT_UID:
        raise PrimaryPromptAdoptionError("requires the fixed Linux root actor")
    _ensure_dirs(core)
    lock_path = core.PRIMARY_PROMPT_BACKUPS / "owner-prefix.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != core.ROOT_UID
                or info.st_gid != core.ROOT_UID or stat.S_IMODE(info.st_mode) != 0o600):
            raise PrimaryPromptAdoptionError("owner SOUL edit lock custody differs")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return _write_owner_prefix_locked(content, expected_sha256=expected_sha256,
            idempotency_key=idempotency_key, core_source_generation=core_source_generation)
    finally:
        os.close(lock_fd)


def _write_owner_prefix_locked(content: str, *, expected_sha256: str, idempotency_key: str,
                               core_source_generation: str) -> dict[str, Any]:
    """Edit only the owner prefix of an adopted SOUL, preserving its managed block.

    The adoption backup remains the original pre-adoption SOUL so the existing
    rollback still restores exactly what the owner had before Jarvis was added.
    Each edit has its own root-only backup/idempotency journal.
    """
    from . import core_runtime as core
    if (os.geteuid() != core.ROOT_UID or not isinstance(content, str) or "\x00" in content
            or not _safe_hash(expected_sha256) or not _safe_hash(core_source_generation)
            or not isinstance(idempotency_key, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{22,128}", idempotency_key) is None):
        raise PrimaryPromptAdoptionError("owner SOUL edit request is invalid")
    try:
        proposed_prefix = content.encode("utf-8", "strict")
    except UnicodeError:
        raise PrimaryPromptAdoptionError("owner SOUL edit is not UTF-8") from None
    if not 0 < len(proposed_prefix) <= MAX_SOUL_BYTES:
        raise PrimaryPromptAdoptionError("owner SOUL edit exceeds its bound")
    proposed_owner_prefix = proposed_prefix
    _check_root_context(core)
    _ensure_dirs(core)
    record = _read_record(core)
    if record is None or record.get("state") != "adopted":
        raise PrimaryPromptAdoptionError("an adopted Jarvis primary prompt is required")
    current, signature = _read_soul(core)
    key_hash = _sha(idempotency_key.encode("ascii"))
    journal_name = f"owner-prefix-{key_hash}.json"
    backup_name = f"owner-prefix-{key_hash}.backup"
    journal_path = core.PRIMARY_PROMPT_BACKUPS / journal_name
    backup_path = core.PRIMARY_PROMPT_BACKUPS / backup_name
    try:
        prior_raw = core._projection_file(journal_path, owner=core.ROOT_UID,
            group=core.ROOT_UID, mode=0o600, maximum=16 * 1024)
        journal = json.loads(prior_raw)
        if (type(journal) is not dict or set(journal) != {"schema", "state", "key_sha256",
                "source_generation", "base_sha256", "proposed_sha256", "result_sha256", "backup_name"}
                or journal.get("schema") != 1 or journal.get("key_sha256") != key_hash
                or journal.get("source_generation") != core_source_generation
                or journal.get("base_sha256") != expected_sha256
                or journal.get("proposed_sha256") != _sha(proposed_owner_prefix)
                or journal.get("backup_name") != backup_name
                or journal.get("state") not in {"prepared", "committed"}):
            raise PrimaryPromptAdoptionError("owner SOUL edit idempotency record differs")
        backup = core._projection_file(backup_path, owner=core.ROOT_UID,
            group=core.ROOT_UID, mode=0o600, maximum=MAX_SOUL_BYTES)
    except FileNotFoundError:
        journal = None
        backup = b""
    if journal is None:
        if core_source_generation != record["core_source_generation"]:
            raise PrimaryPromptAdoptionError("Core source generation changed")
        source_generation, _discovery, artifact_sha, manifest, files, _prompt = _fixed_bundle(core)
        if artifact_sha != record["artifact_sha256"] or source_generation != core_source_generation:
            raise PrimaryPromptAdoptionError("pinned Resources source changed")
        if signature != record["result_soul_signature"] or _sha(current) != expected_sha256:
            raise PrimaryPromptAdoptionError("active SOUL changed; reload before saving")
        _record_matches_current(core, record, current, manifest, files)
        prefix, separator, block = split_managed_block(current,
            owner_prefix_length=record["owner_prefix_length"],
            separator=bytes.fromhex(record["owner_separator_hex"]))
        suffix = separator + block
        proposed_prefix = proposed_owner_prefix
        if not 0 < len(proposed_prefix) <= MAX_SOUL_BYTES - len(suffix):
            raise PrimaryPromptAdoptionError("owner prefix exceeds its bound")
        if (b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 BEGIN -->" in proposed_prefix
                or b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 END -->" in proposed_prefix):
            raise PrimaryPromptAdoptionError("owner prefix cannot contain managed block markers")
        try:
            old_edit_backup = core._projection_file(backup_path, owner=core.ROOT_UID,
                group=core.ROOT_UID, mode=0o600, maximum=MAX_SOUL_BYTES)
        except FileNotFoundError:
            core._atomic(backup_path, current, 0o600, core.ROOT_UID, core.ROOT_UID)
        else:
            if old_edit_backup != current:
                raise PrimaryPromptAdoptionError("orphan owner SOUL edit backup differs")
        journal = {"schema": 1, "state": "prepared", "key_sha256": key_hash,
            "source_generation": core_source_generation, "base_sha256": expected_sha256,
            "proposed_sha256": _sha(proposed_prefix),
            "result_sha256": _sha(proposed_prefix + suffix), "backup_name": backup_name}
        core._atomic(journal_path, (json.dumps(journal, sort_keys=True,
            separators=(",", ":")) + "\n").encode("ascii"), 0o600, core.ROOT_UID, core.ROOT_UID)
    else:
        if _sha(backup) != expected_sha256:
            raise PrimaryPromptAdoptionError("owner SOUL edit backup does not match its base digest")
        if journal["state"] == "committed" and _sha(current) == journal["result_sha256"]:
            return _status_record(record, _record_matches_current(core, record, current,
                *(_fixed_bundle(core)[3:5]))) | {"state": "active", "recovery_id": key_hash}
        if _sha(current) not in {expected_sha256, journal["result_sha256"]}:
            raise PrimaryPromptAdoptionError("active SOUL changed during interrupted edit")
        if _sha(current) == journal["result_sha256"]:
            # A process may have stopped after the atomic file replacement but
            # before refreshing the root receipt. Rebuild that receipt from the
            # immutable source and native loader before resolving the bundle.
            core._write_resources_discovery()
        source_generation, _discovery, artifact_sha, manifest, files, _prompt = _fixed_bundle(
            core, recovery_record=record, current_prompt_sha256=_sha(current))
        if source_generation != core_source_generation or artifact_sha != record["artifact_sha256"]:
            raise PrimaryPromptAdoptionError("Core or Resources generation changed")
        if _sha(current) == journal["result_sha256"]:
            # Replacement completed before the root receipt update; verify and resume it.
            suffix = bytes.fromhex(record["owner_separator_hex"]) + _record_managed_block(record, files)
            if not current.endswith(suffix):
                raise PrimaryPromptAdoptionError("managed Jarvis overlay changed during edit recovery")
            proposed_prefix = current[:-len(suffix)]
            if _sha(proposed_prefix) != journal["proposed_sha256"]:
                raise PrimaryPromptAdoptionError("owner prefix differs from the edit journal")
        else:
            suffix = bytes.fromhex(record["owner_separator_hex"]) + _record_managed_block(record, files)
            proposed_prefix = proposed_owner_prefix
            if _sha(proposed_prefix) != journal["proposed_sha256"]:
                raise PrimaryPromptAdoptionError("owner prefix differs from the edit journal")
            if _sha(proposed_prefix + suffix) != journal["result_sha256"]:
                raise PrimaryPromptAdoptionError("managed Jarvis overlay changed during edit recovery")
            current = backup
            signature = _read_soul(core)[1]
    desired = proposed_prefix + bytes.fromhex(record["owner_separator_hex"]) + _record_managed_block(record, files)
    if _sha(current) != _sha(desired):
        stage = ".SOUL.md.jarvis-" + secrets.token_hex(12) + ".stage"
        _atomic_admin_replace(core, desired, expected_signature=signature,
            uid=signature[3], gid=signature[4], mode=stat.S_IMODE(signature[2]), stage_name=stage)
    active, active_signature = _read_soul(core)
    if active != desired:
        raise PrimaryPromptAdoptionError("owner SOUL replacement readback differs")
    # Verify the real Hermes loader against the exact pinned source before the
    # Resources receipt and adoption journal are advanced.
    native_receipt = _verify_native(core, manifest, files, active, record["managed_block_sha256"])
    updated = dict(record)
    updated.update({"owner_prefix_sha256": _sha(proposed_prefix),
        "owner_prefix_length": len(proposed_prefix), "result_soul_sha256": _sha(active),
        "result_soul_signature": active_signature,
        "native_effective_prompt_sha256": native_receipt["native_effective_prompt_sha256"],
        "native_effective_prompt_chars": native_receipt["native_effective_prompt_chars"],
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")})
    _record_matches_current(core, updated, active, manifest, files)
    core._write_resources_discovery()
    discovery = core.read_current_resources_discovery(core_source_generation=core_source_generation)
    if discovery.get("resources_state") != "discovered" or discovery.get("artifact_sha256") != artifact_sha:
        raise PrimaryPromptAdoptionError("effective SOUL receipt did not verify")
    _write_record(core, updated)
    journal["state"] = "committed"
    core._atomic_replace(journal_path, (json.dumps(journal, sort_keys=True,
        separators=(",", ":")) + "\n").encode("ascii"), 0o600, core.ROOT_UID, core.ROOT_UID)
    return _status_record(updated, native_receipt) | {"state": "active", "recovery_id": key_hash}


def _record_managed_block(record, files) -> bytes:
    block = render_managed_block(files["registry/profiles/hermes/SOUL.md"])
    if _sha(block) != record["managed_block_sha256"]:
        raise PrimaryPromptAdoptionError("managed Jarvis overlay changed")
    return block


def owner_prefix_projection(current: bytes, *, source_generation: str) -> dict[str, Any] | None:
    """Return editable owner bytes and separately typed protected Jarvis bytes."""
    from . import core_runtime as core
    record = _read_record(core)
    if record is None or record.get("state") != "adopted":
        return None
    if record.get("core_source_generation") != source_generation:
        raise PrimaryPromptAdoptionError("managed primary source generation changed")
    active, signature = _read_soul(core)
    if active != current or signature != record["result_soul_signature"]:
        raise PrimaryPromptAdoptionError("active primary SOUL changed")
    generation, _discovery, artifact_sha, _manifest, files, _prompt = _fixed_bundle(core)
    if generation != source_generation or artifact_sha != record["artifact_sha256"]:
        raise PrimaryPromptAdoptionError("managed primary source changed")
    block = _record_managed_block(record, files)
    prefix, separator, _ = split_managed_block(current,
        owner_prefix_length=record["owner_prefix_length"],
        separator=bytes.fromhex(record["owner_separator_hex"]))
    _record_matches_current(core, record, current, _manifest, files)
    return {"editable_content": prefix.decode("utf-8", "strict"),
        "protected_suffix": (separator + block).decode("utf-8", "strict"),
        "managed_primary": True}


def primary_prompt_status() -> dict[str, Any]:
    from . import core_runtime as core
    record = _read_record(core)
    if record is None:
        return {"state": "pending", "managed_primary_block_verified": False,
                "effective_prompt_contains_full_block": False, "effective_prompt_truncated": None,
                "functional": False}
    if record["state"] in {"preparing", "writing", "rolling_back"}:
        return {"state": "recovery-required", "managed_primary_block_verified": False,
                "effective_prompt_contains_full_block": False, "effective_prompt_truncated": None,
                "owner_backup_sha256": record["owner_backup_name"], "functional": False}
    _check_root_context(core)
    source_generation, _discovery, artifact_sha, manifest, files, _prompt = _fixed_bundle(core)
    if (source_generation != record["core_source_generation"]
            or artifact_sha != record["artifact_sha256"]):
        raise PrimaryPromptAdoptionError("managed primary block is stale for current source")
    current, signature = _read_soul(core)
    if record["state"] == "rolled_back":
        backup = _backup_read(core, record)
        if current != backup or _sha(current) != record["result_soul_sha256"]:
            raise PrimaryPromptAdoptionError("restored owner SOUL changed after rollback")
        receipt = core._root_native_readback(manifest, files, current)
        if (receipt.get("active_primary_prompt_sha256") != _sha(current)
                or receipt.get("managed_prompt_block_sha256") is not None):
            raise PrimaryPromptAdoptionError("native restored prompt readback differs")
        return {"state": "rolled_back", "managed_primary_block_verified": False,
                "effective_prompt_contains_full_block": False,
                "effective_prompt_truncated": receipt["effective_prompt_truncated"],
                "restored_owner_soul_sha256": _sha(current), "functional": False}
    if record["state"] != "adopted":
        return {"state": "recovery-required", "managed_primary_block_verified": False,
                "effective_prompt_contains_full_block": False, "effective_prompt_truncated": None,
                "functional": False}
    if signature != record["result_soul_signature"]:
        raise PrimaryPromptAdoptionError("active SOUL metadata changed after managed adoption")
    _backup_read(core, record)
    receipt = _record_matches_current(core, record, current, manifest, files)
    return _status_record(record, receipt)


def rollback_primary_prompt() -> dict[str, Any]:
    from . import core_runtime as core
    record = _read_record(core)
    if record is None or record["state"] not in {"adopted", "rolling_back", "rolled_back"}:
        raise PrimaryPromptAdoptionError("no verified managed primary prompt is available to roll back")
    _check_root_context(core, require_listener=False)
    current, signature = _read_soul(core)
    source_generation, _discovery, artifact_sha, manifest, files, _prompt = _fixed_bundle(
        core, recovery_record=record, current_prompt_sha256=_sha(current)
    )
    if (source_generation != record["core_source_generation"] or artifact_sha != record["artifact_sha256"]):
        raise PrimaryPromptAdoptionError("current source differs from the adopted primary prompt")
    if record["state"] == "rolled_back":
        backup = _backup_read(core, record)
        if current != backup:
            raise PrimaryPromptAdoptionError("rolled-back owner SOUL changed after restoration")
        receipt = core._root_native_readback(manifest, files, current)
        if receipt.get("active_primary_prompt_sha256") != _sha(current):
            raise PrimaryPromptAdoptionError("native restored prompt readback differs")
        return {"state": "rolled_back", "restored_owner_soul_sha256": _sha(current),
                "managed_primary_block_verified": False, "functional": False}
    backup = _backup_read(core, record)
    if record["state"] == "adopted":
        if signature != record["result_soul_signature"] or _sha(current) != record["result_soul_sha256"]:
            raise PrimaryPromptAdoptionError("active SOUL or managed block was edited; refusing rollback")
        _record_matches_current(core, record, current, manifest, files)
        record["state"] = "rolling_back"
        _write_record(core, record)
    if _sha(current) == record["result_soul_sha256"]:
        if signature != record["result_soul_signature"]:
            raise PrimaryPromptAdoptionError("active SOUL changed during managed rollback")
        _atomic_admin_replace(core, backup, expected_signature=signature,
                              uid=signature[3], gid=signature[4],
                              mode=stat.S_IMODE(signature[2]), stage_name=record["stage_name"])
    elif current != backup or _sha(current) != record["prior_soul_sha256"]:
        raise PrimaryPromptAdoptionError("active SOUL changed during managed rollback")
    restored, restored_signature = _read_soul(core)
    if restored != backup or _sha(restored) != record["prior_soul_sha256"]:
        raise PrimaryPromptAdoptionError("exact owner SOUL restoration readback failed")
    core._write_resources_discovery()
    receipt = core._root_native_readback(manifest, files, restored)
    if (receipt.get("active_primary_prompt_sha256") != _sha(restored)
            or receipt.get("managed_prompt_block_sha256") is not None):
        raise PrimaryPromptAdoptionError("native prompt rollback readback differs")
    record["native_effective_prompt_sha256"] = receipt["native_effective_prompt_sha256"]
    record["native_effective_prompt_chars"] = receipt["native_effective_prompt_chars"]
    record["state"] = "rolled_back"
    record["result_soul_sha256"] = _sha(restored)
    record["result_soul_signature"] = restored_signature
    record["observed_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    _write_record(core, record)
    return {"state": "rolled_back", "restored_owner_soul_sha256": _sha(restored),
            "managed_primary_block_verified": False, "functional": False}
