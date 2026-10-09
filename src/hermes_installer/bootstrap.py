"""Pinned official Hermes installer stages, isolated in an installer-owned generation."""
from __future__ import annotations
import hashlib, json, os, stat, time, uuid, re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import threading
from .state import Journal, OwnedRoot, OwnershipError
from .bootstrap_custody import BootstrapCustody

HERMES_REPOSITORY = "https://github.com/NousResearch/hermes-agent.git"
HERMES_COMMIT = "7085fbf7753266fc4943c55ac04926186bc90005"
INSTALL_SCRIPT_BLOB = "055c725f114db694db751f34fd312e70f5ed90d8"
INSTALL_SCRIPT_SHA256 = "034845e34289813ff5fb7fd3e071ec69f6b14aee8ba297a477b31dda6374cb86"
INSTALL_SCRIPT_ARTIFACT_ID = "hermes-install-script-7085fbf77532"
_DIAGNOSTIC_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)([?&](?:token|key|secret|password)=)[^&\s]+"),
)

def redact_diagnostic(text: str) -> str:
    for pattern in _DIAGNOSTIC_PATTERNS:
        text = pattern.sub(lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]", text)
    return text
EXPECTED_STAGES = ("prerequisites", "repository", "venv", "python-deps", "config", "products", "setup", "gateway", "complete")

class BootstrapError(RuntimeError):
    """Safe bootstrap error that excludes downloaded content, env and command output."""

@dataclass(frozen=True)
class StageStatus:
    name: str
    state: str
    exit_code: int | None = None
    diagnostic_path: str | None = None

@dataclass(frozen=True)
class BootstrapReport:
    commit: str
    generation: str
    hermes_home: str
    stages: tuple[StageStatus, ...]
    agent_ready: bool
    desktop_built: bool
    configuration_state: str
    resume_command: str
    fixture_only: bool = False

def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def _write_private(path: Path, data: bytes, mode: int = 0o700) -> None:
    if path.is_symlink():
        raise OwnershipError("Installer staging file is a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

class HermesBootstrap:
    """Runs exact upstream script content and stage names; callers cannot inject commands."""
    def __init__(self, data_root: OwnedRoot, state: Journal, *, network: object | None = None,
                 runner: Callable | None = None, desktop_builder: Callable | None = None,
                 agent_probe: Callable | None = None, expected_script_blob: str = INSTALL_SCRIPT_BLOB,
                 authority_client: object | None = None):
        self.data_root = data_root
        self.state = state
        self.network = network
        self._default_runner = self._run_process
        self._default_desktop_builder = self._run_desktop_source_build
        self._default_agent_probe = self._verify_agent_runtime
        self.runner = runner or self._default_runner
        self.desktop_builder = desktop_builder or self._default_desktop_builder
        self.agent_probe = agent_probe or self._default_agent_probe
        self.expected_script_blob = expected_script_blob
        self.install_dir = data_root.path("generations/hermes-agent-" + HERMES_COMMIT[:12])
        self.hermes_home = data_root.path("profiles/default")
        self.private_home = data_root.path("runtime/bootstrap-home")
        self.operation = "hermes-agent:" + HERMES_COMMIT
        self.custody = BootstrapCustody(authority_client, journal=state,
                                        journal_operation=self.operation)
        self._active_diagnostic: str | None = None
        self._upstream_log_offset: int | None = None
        self._last_artifact_receipt_id: str | None = None
        self.script_store_id: str | None = None

    def _has_fixture_overrides(self) -> bool:
        return (self.runner is not self._default_runner
                or self.desktop_builder is not self._default_desktop_builder
                or self.agent_probe is not self._default_agent_probe)

    def _stage_script_artifact(self) -> str:
        try:
            if self.network is not None:
                # Fixture-only source seam. Production receives an opaque store
                # ID from the protected artifact broker and never handles bytes.
                response = self.network.fetch_artifact(artifact_id=INSTALL_SCRIPT_ARTIFACT_ID,
                    sha256=INSTALL_SCRIPT_SHA256, max_bytes=128 * 1024)
                body = response.body
                if response.status != 200:
                    raise BootstrapError("Pinned official Hermes installer artifact was not available")
                self._last_artifact_receipt_id = str(getattr(response, "receipt_id", "fixture"))
                if (git_blob_sha1(body) != self.expected_script_blob
                        or not body.startswith(b"#!/usr/bin/env bash\n") or len(body) > 128 * 1024):
                    raise BootstrapError("Pinned official Hermes installer content did not match its Git object identity")
                digest = hashlib.sha256(body).hexdigest()
                self.script_store_id = f"artifact:{INSTALL_SCRIPT_ARTIFACT_ID}:{digest}"
            else:
                self.script_store_id, self._last_artifact_receipt_id = self.custody.fetch_artifact(
                    artifact_id=INSTALL_SCRIPT_ARTIFACT_ID, sha256=INSTALL_SCRIPT_SHA256,
                    max_bytes=128 * 1024)
        except BootstrapError:
            raise
        except Exception:
            raise BootstrapError("Pinned host download broker is unavailable or denied the official installer artifact") from None
        if not self.script_store_id:
            raise BootstrapError("Pinned official Hermes artifact broker did not return an immutable store reference")
        return self.script_store_id

    def prepare(self) -> None:
        self.data_root.ensure()
        for relative in ("generations", "profiles", "runtime", "runtime/bootstrap-home", "runtime/bootstrap-home/share",
                         "runtime/bootstrap-home/config", "runtime/bootstrap-home/cache", "cache"):
            self.data_root.path(relative).mkdir(parents=True, exist_ok=True, mode=0o700)
        store_id = self._stage_script_artifact()
        self.state.event(self.operation, "download-broker", "artifact_staged", {
            "artifact_id": INSTALL_SCRIPT_ARTIFACT_ID,
            "sha256": INSTALL_SCRIPT_SHA256,
            "store_id": store_id,
            "receipt_id": self._last_artifact_receipt_id,
        })
        self.hermes_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.hermes_home.is_symlink() or self.private_home.is_symlink():
            raise OwnershipError("Hermes profile or private bootstrap home cannot be a symlink")

    def _environment(self) -> dict[str, str]:
        home = str(self.private_home)
        return {
            "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": home,
            "HERMES_HOME": str(self.hermes_home),
            "XDG_DATA_HOME": str(self.private_home / "share"),
            "XDG_CONFIG_HOME": str(self.private_home / "config"),
            "XDG_CACHE_HOME": str(self.private_home / "cache"),
            "XDG_STATE_HOME": str(self.private_home / "state"),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1",
            "UV_NO_CONFIG": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
        }

    def _base_args(self) -> list[str]:
        return ["--commit", HERMES_COMMIT, "--dir", str(self.install_dir), "--hermes-home", str(self.hermes_home)]

    def _run_process(self, args: list[str], *, timeout: float, capture: bool = False, diagnostic_path: str | None = None) -> tuple[int, bytes]:
        stage = args[args.index("--stage") + 1] if "--stage" in args else "installer"
        self.state.event(self.operation, stage, "selected_operation_pending", {
            "diagnostic": diagnostic_path or self._active_diagnostic,
            "reason": "root-local enrollment receipt and fixed recipe selection are not connected",
            "resume": "hermes-installer resume",
        })
        raise BootstrapError(
            "Root-enrolled Hermes stage operation is unavailable; no caller-selected "
            "executable, path, argv, or environment was launched. Use hermes-installer resume."
        )

    def _record_process_receipt(self, result: object, stage: str) -> None:
        process_id = getattr(result, "process_id", None)
        generation = getattr(result, "generation", None)
        cleanup_verified = getattr(result, "cleanup_verified", None)
        timed_out = getattr(result, "timed_out", None)
        if isinstance(process_id, str) and process_id and len(process_id) <= 128:
            self.state.record_owned("process", process_id,
                "stopped" if cleanup_verified is True else "active")
        if isinstance(generation, str) and generation and len(generation) <= 128:
            self.state.event(self.operation, stage, "process_generation_receipt", {
                "process_id": process_id if isinstance(process_id, str) else None,
                "generation": generation,
            })
        self.state.event(self.operation, stage,
            "process_cleanup_verified" if cleanup_verified is True else "process_cleanup_unverified", {
                "process_id": process_id if isinstance(process_id, str) else None,
                "generation": generation if isinstance(generation, str) else None,
                "receipt_id": getattr(result, "receipt_id", None),
                "cleanup_verified": cleanup_verified is True,
                "timed_out": timed_out is True,
            })
        if not isinstance(process_id, str) or not process_id or cleanup_verified is not True:
            raise BootstrapError(
                "Host custody did not verify process cleanup; the stage was not accepted. "
                "Resume only after the protected process handle is stopped and verified."
            )
        if timed_out is True:
            raise BootstrapError("Managed Hermes stage exceeded its deadline; verified cleanup completed. Use hermes-installer resume.")

    def _record_process_exception(self, exc: BaseException, stage: str) -> None:
        process_id = getattr(exc, "process_id", None)
        generation = getattr(exc, "generation", None)
        cleanup_verified = getattr(exc, "cleanup_verified", None)
        receipt_id = getattr(exc, "receipt_id", None)
        if (not isinstance(process_id, str) and not isinstance(generation, str)
                and isinstance(receipt_id, str) and receipt_id and len(receipt_id) <= 128
                and cleanup_verified is not True):
            # A start may have taken effect even when its response could not be
            # parsed into an opaque process handle. Keep uninstall blocked until
            # an operator recovers that exact host receipt.
            self.state.record_owned("process", "unresolved-start:" + receipt_id, "active")
        elif not isinstance(process_id, str) and not isinstance(generation, str):
            return
        if isinstance(process_id, str) and process_id and len(process_id) <= 128:
            self.state.record_owned("process", process_id,
                "stopped" if cleanup_verified is True else "active")
        self.state.event(self.operation, stage, "process_effect_failed", {
            "error_type": type(exc).__name__,
            "process_id": process_id if isinstance(process_id, str) else None,
            "generation": generation if isinstance(generation, str) else None,
            "receipt_id": receipt_id if isinstance(receipt_id, str) else None,
            "cleanup_verified": cleanup_verified is True,
        })

    def _append_captured(self, line: str, diagnostic: bytearray, limit: int,
                         lock: threading.Lock, truncated: threading.Event) -> None:
        encoded = line.encode("utf-8", errors="replace")
        with lock:
            if len(encoded) > limit:
                encoded = encoded[-limit:]
                truncated.set()
            if len(diagnostic) + len(encoded) > limit:
                del diagnostic[:len(diagnostic) + len(encoded) - limit]
                truncated.set()
            diagnostic.extend(encoded)

    def _persist_diagnostic(self, relative: str | None, content: bytearray, truncated: bool) -> None:
        if not relative:
            return
        path = self.data_root.path(relative)
        safe_content = redact_diagnostic(bytes(content).decode("utf-8", errors="replace")).encode("utf-8")
        suffix = b"\n[diagnostic capture truncated at 96 KiB]\n" if truncated else b""
        _write_private(path, safe_content + suffix, 0o600)

    def _append_upstream_install_log(self, diagnostic: bytearray, limit: int, lock: threading.Lock,
                                     truncated: threading.Event, *, expected_uid: int | None = None) -> None:
        """Collect only this stage's bounded tail from the upstream JSON log sink."""
        if self._upstream_log_offset is None:
            return
        path = self.hermes_home / "logs" / "install.log"
        try:
            if path.is_symlink():
                return
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                allowed_uids = {os.getuid()}
                if expected_uid is not None:
                    allowed_uids.add(expected_uid)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid not in allowed_uids):
                    return
                start = min(self._upstream_log_offset, info.st_size)
                length = info.st_size - start
                if length > limit:
                    start = info.st_size - limit
                    truncated.set()
                os.lseek(fd, start, os.SEEK_SET)
                raw = os.read(fd, limit + 1)
            finally:
                os.close(fd)
        except OSError:
            return
        text = redact_diagnostic(raw.decode("utf-8", errors="replace"))
        rendered = ("[upstream-install-log]\n" + text.rstrip() + "\n").encode("utf-8")
        with lock:
            if len(rendered) > limit:
                rendered = rendered[-limit:]
                truncated.set()
            if len(diagnostic) + len(rendered) > limit:
                del diagnostic[:len(diagnostic) + len(rendered) - limit]
                truncated.set()
            diagnostic.extend(rendered)

    def _manifest(self) -> None:
        code, raw = self.runner(["--manifest", "--json", *self._base_args()], timeout=30, capture=True)
        if code != 0:
            raise BootstrapError("Pinned Hermes installer could not provide its stage manifest")
        try:
            value = json.loads(raw)
            stages = value["stages"]
            names = tuple(item["name"] for item in stages)
        except (ValueError, TypeError, KeyError):
            raise BootstrapError("Pinned Hermes installer returned an invalid stage manifest") from None
        if value.get("protocol_version") != 1 or names != EXPECTED_STAGES:
            raise BootstrapError("Pinned Hermes installer stage protocol changed; review the upstream pin before continuing")

    def _completed_stages(self) -> dict[str, str]:
        return {str(row["resource_id"]).split(":", 1)[1]: str(row["state"])
                for row in self.state.owned("hermes-stage")
                if str(row["resource_id"]).startswith(HERMES_COMMIT + ":")}

    def _generation_marker(self) -> bytes:
        return ("schema=1\ncommit=" + HERMES_COMMIT + "\n").encode("ascii")

    def _write_generation_marker(self) -> None:
        marker = self.install_dir.parent / ("." + self.install_dir.name + ".owned")
        if marker.exists() or marker.is_symlink():
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(marker, flags)
                try:
                    info = os.fstat(fd)
                    data = os.read(fd, 256)
                finally:
                    os.close(fd)
            except OSError:
                raise OwnershipError("Generation ownership marker cannot be safely verified") from None
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or data != self._generation_marker():
                raise OwnershipError("Generation ownership marker is invalid; existing source was preserved")
        else:
            _write_private(marker, self._generation_marker(), 0o600)

    def _source_head(self) -> str | None:
        git = self.install_dir / ".git"
        if git.is_symlink():
            return None
        if git.is_file():
            try:
                raw = git.read_text(encoding="utf-8").strip()
            except OSError:
                return None
            if not raw.startswith("gitdir: ") or "\\" in raw:
                return None
            git = (self.install_dir / raw[8:]).resolve(strict=False)
            if not git.is_relative_to(self.install_dir):
                return None
        if not git.is_dir():
            return None
        try:
            value = (git / "HEAD").read_text(encoding="ascii").strip()
        except OSError:
            return None
        if len(value) == 40 and all(ch in "0123456789abcdef" for ch in value):
            return value
        if value.startswith("ref: refs/heads/"):
            refname = value[5:]
            ref = git / refname
            try:
                resolved = ref.read_text(encoding="ascii").strip()
            except OSError:
                try:
                    lines = (git / "packed-refs").read_text(encoding="ascii").splitlines()
                except OSError:
                    return None
                resolved = next((fields[0] for line in lines if len(fields := line.split()) == 2 and fields[1] == refname), "")
            if len(resolved) == 40 and all(ch in "0123456789abcdef" for ch in resolved):
                return resolved
        return None

    def _existing_source_is_resumable(self, previous: dict[str, object] | None) -> bool:
        if self.install_dir.is_symlink():
            return False
        owned = any(row["resource_id"] == str(self.install_dir) and row["state"] in {"active", "staged", "installed"}
                    for row in self.state.owned("hermes-generation"))
        marker = self.install_dir.parent / ("." + self.install_dir.name + ".owned")
        if marker.exists() or marker.is_symlink():
            try:
                self._write_generation_marker()
            except OwnershipError:
                return False
        elif self.install_dir.exists():
            return False
        if self.install_dir.exists() and not self.install_dir.is_dir():
            return False
        if self.install_dir.exists() and not owned:
            return False
        if not self.install_dir.exists():
            if not marker.exists():
                return True
            return owned and bool(previous and previous.get("status") in {"running:repository", "failed:repository"})
        head = self._source_head()
        if head is None:
            return bool(owned and previous and previous.get("status") in {"running:repository", "failed:repository"})
        return head == HERMES_COMMIT


    def _run_desktop_source_build(self, *, timeout: float) -> tuple[int, bytes]:
        hermes = self.install_dir / ".hermes" / "bin" / "hermes"
        if hermes.is_symlink() or not hermes.is_file() or not os.access(hermes, os.X_OK):
            raise BootstrapError("Pinned Hermes CLI entrypoint is unavailable for the source Desktop build")
        env = self._environment()
        env["HERMES_DESKTOP_HERMES_ROOT"] = str(self.install_dir)
        env["HERMES_DESKTOP_USER_DATA_DIR"] = str(self.data_root.path("runtime/desktop-user-data"))
        env["HERMES_DESKTOP_APP_NAME"] = "Hermes Installer Candidate"
        Path(env["HERMES_DESKTOP_USER_DATA_DIR"]).mkdir(parents=True, exist_ok=True, mode=0o700)
        return self._run_managed_binary(hermes,
            [str(hermes), "desktop", "--build-only", "--source"], timeout=timeout,
            env=env, diagnostic_path=f"runtime/logs/hermes-agent-{HERMES_COMMIT[:12]}/desktop-product-build.log")

    def _verify_agent_runtime(self) -> bool:
        hermes = self.install_dir / ".hermes" / "bin" / "hermes"
        if hermes.is_symlink() or not hermes.is_file() or not os.access(hermes, os.X_OK):
            return False
        if self._source_head() != HERMES_COMMIT:
            return False
        try:
            code, output = self._run_managed_binary(hermes, [str(hermes), "--version"],
                timeout=20, env=self._environment(), diagnostic_path=None)
        except BootstrapError:
            self.state.event(self.operation, "runtime-probe", "unavailable", {
                "reason": "managed host process authority is not ready"})
            return False
        return code == 0 and bool(output.strip())

    def _run_managed_binary(self, executable: Path, argv: list[str], *, timeout: float,
                            env: dict[str, str], diagnostic_path: str | None) -> tuple[int, bytes]:
        self.state.event(self.operation, "managed-process", "selected_operation_pending", {
            "executable_label": executable.name,
            "diagnostic": diagnostic_path,
            "reason": "caller-selected binaries are not an enrolled root recipe",
            "resume": "hermes-installer resume",
        })
        raise BootstrapError(
            "Caller-selected Hermes executable launch is disabled; wait for the "
            "root-enrolled health operation and use hermes-installer resume."
        )

    def install(self, *, include_desktop: bool = True, timeout_per_stage: float = 600) -> BootstrapReport:
        if not 30 <= timeout_per_stage <= 600:
            raise ValueError("Stage timeout must be between 30 and 600 seconds")
        try:
            self.prepare()
        except BaseException as exc:
            self.state.checkpoint(self.operation, "failed:download-broker", {
                "commit": HERMES_COMMIT, "stage": "download-broker",
                "error_type": type(exc).__name__, "resume": "hermes-installer resume",
            })
            self.state.event(self.operation, "download-broker", "failed", {
                "error_type": type(exc).__name__, "resume": "hermes-installer resume",
            })
            raise
        self._manifest()
        previous = self.state.operation(self.operation)
        if not self._existing_source_is_resumable(previous):
            raise OwnershipError("Pinned source generation already exists without a resumable installer checkpoint; it was preserved")
        done = self._completed_stages()
        self.install_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state.record_owned("hermes-generation", str(self.install_dir), "staged")
        self._write_generation_marker()
        statuses: list[StageStatus] = []
        skipped = {"setup", "gateway"}
        desktop_output = self.install_dir / "apps" / "desktop" / "dist" / "index.html"
        for stage in EXPECTED_STAGES:
            if done.get(stage) in {"complete", "skipped"}:
                if stage != "products" or not include_desktop or desktop_output.is_file():
                    statuses.append(StageStatus(stage, done[stage]))
                    continue
            extra: list[str] = []
            relative_diagnostic = f"runtime/logs/hermes-agent-{HERMES_COMMIT[:12]}/{stage}.log"
            self.data_root.path(relative_diagnostic).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            before_effects = self._effect_snapshot()
            self.state.checkpoint(self.operation, "running:" + stage, {
                "commit": HERMES_COMMIT, "stage": stage, "generation": str(self.install_dir),
                "hermes_home": str(self.hermes_home), "desktop_requested": bool(include_desktop),
            })
            self.state.event(self.operation, stage, "started", {"generation": str(self.install_dir),
                "diagnostic": relative_diagnostic, "timeout_seconds": timeout_per_stage,
                "effects_before": before_effects})
            args = ["--stage", stage, "--json", "--non-interactive", *self._base_args(), *extra]
            # Skip optional integrations during base installation; their adapters
            # configure them only after explicit component selection.
            args += ["--skip-browser", "--skip-computer-use"]
            self._active_diagnostic = relative_diagnostic
            try:
                code, _ = self.runner(args, timeout=timeout_per_stage, capture=True)
            except BaseException as exc:
                self._record_process_exception(exc, stage)
                self.state.checkpoint(self.operation, "cancelled:" + stage if isinstance(exc, KeyboardInterrupt) else "failed:" + stage, {
                    "commit": HERMES_COMMIT, "stage": stage, "generation": str(self.install_dir),
                    "diagnostic": relative_diagnostic, "error": type(exc).__name__,
                    "resume": "hermes-installer resume",
                })
                self.state.event(self.operation, stage, "cancelled" if isinstance(exc, KeyboardInterrupt) else "runner_error", {
                    "error_type": type(exc).__name__, "diagnostic": relative_diagnostic,
                    "cleanup_verified": getattr(exc, "cleanup_verified", None),
                    "effects_after": self._effect_snapshot()})
                raise
            finally:
                self._active_diagnostic = None
            if code != 0:
                self.state.checkpoint(self.operation, "failed:" + stage, {
                    "commit": HERMES_COMMIT, "stage": stage, "exit_code": code,
                    "generation": str(self.install_dir), "diagnostic": relative_diagnostic,
                    "error_summary": self._diagnostic_summary(relative_diagnostic),
                    "resume": "hermes-installer resume",
                })
                self.state.event(self.operation, stage, "failed", {"exit_code": code,
                    "diagnostic": relative_diagnostic, "error_summary": self._diagnostic_summary(relative_diagnostic),
                    "effects_before": before_effects, "effects_after": self._effect_snapshot(),
                    "resume": "hermes-installer resume"})
                raise BootstrapError(f"Hermes stage {stage} did not complete (exit {code}); diagnostics: {relative_diagnostic}; use hermes-installer resume")
            state = "skipped" if stage in skipped else "complete"
            self.state.record_owned("hermes-stage", HERMES_COMMIT + ":" + stage, state)
            self.state.checkpoint(self.operation, "stage:" + stage, {
                "commit": HERMES_COMMIT, "stage": stage, "state": state,
                "generation": str(self.install_dir), "hermes_home": str(self.hermes_home),
            })
            self.state.event(self.operation, stage, "completed", {"exit_code": code,
                "diagnostic": relative_diagnostic, "effects_before": before_effects,
                "effects_after": self._effect_snapshot()})
            statuses.append(StageStatus(stage, state, code, relative_diagnostic))
        completion = self.install_dir / ".hermes-bootstrap-complete"
        try:
            complete = json.loads(completion.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            complete = {}
        if complete.get("pinnedCommit") != HERMES_COMMIT:
            raise BootstrapError("Pinned Hermes source completion marker failed verification")
        if not self.agent_probe():
            self.state.checkpoint(self.operation, "failed:runtime-probe", {
                "commit": HERMES_COMMIT, "stage": "runtime-probe",
                "generation": str(self.install_dir), "resume": "hermes-installer resume",
            })
            self.state.event(self.operation, "runtime-probe", "failed", {
                "reason": "managed Hermes executable could not be verified",
                "resume": "hermes-installer resume",
            })
            raise BootstrapError("Managed Hermes executable runtime verification failed; use hermes-installer resume")
        desktop_dir = self.install_dir / "apps" / "desktop"
        desktop_built = False
        if include_desktop:
            desktop_diag = f"runtime/logs/hermes-agent-{HERMES_COMMIT[:12]}/desktop-product-build.log"
            self.state.checkpoint(self.operation, "running:desktop-product-build", {
                "commit": HERMES_COMMIT, "stage": "desktop-product-build", "generation": str(self.install_dir),
            })
            self.state.event(self.operation, "desktop-product-build", "started", {"diagnostic": desktop_diag})
            try:
                code, _ = self.desktop_builder(timeout=timeout_per_stage)
            except BaseException as exc:
                self._record_process_exception(exc, "desktop-product-build")
                cancelled = isinstance(exc, KeyboardInterrupt)
                status = "cancelled:desktop-product-build" if cancelled else "failed:desktop-product-build"
                self.state.checkpoint(self.operation, status, {
                    "commit": HERMES_COMMIT, "stage": "desktop-product-build",
                    "generation": str(self.install_dir), "diagnostic": desktop_diag,
                    "error_type": type(exc).__name__, "resume": "hermes-installer resume",
                })
                self.state.event(self.operation, "desktop-product-build", "cancelled" if cancelled else "runner_error", {
                    "error_type": type(exc).__name__, "diagnostic": desktop_diag,
                    "cleanup_verified": getattr(exc, "cleanup_verified", None),
                    "effects_after": self._effect_snapshot(), "resume": "hermes-installer resume",
                })
                raise BootstrapError(
                    f"Hermes Desktop build could not start safely; diagnostics: {desktop_diag}; "
                    "use hermes-installer resume"
                ) from None
            if _:
                self._persist_diagnostic(desktop_diag, bytearray(_), False)
            desktop_built = code == 0 and self._desktop_package_present(desktop_dir)
            if not desktop_built:
                self.state.checkpoint(self.operation, "failed:desktop-product-build", {
                    "commit": HERMES_COMMIT, "stage": "desktop-product-build", "exit_code": code,
                    "generation": str(self.install_dir), "diagnostic": desktop_diag,
                    "error_summary": self._diagnostic_summary(desktop_diag), "resume": "hermes-installer resume",
                })
                self.state.event(self.operation, "desktop-product-build", "failed", {
                    "exit_code": code, "diagnostic": desktop_diag,
                    "effects_after": self._effect_snapshot(), "resume": "hermes-installer resume"})
                raise BootstrapError(f"Hermes Desktop package was not produced (exit {code}); partial dist files do not establish a build; diagnostics: {desktop_diag}; use hermes-installer resume")
            self.state.event(self.operation, "desktop-product-build", "completed", {"exit_code": code, "package": "present"})
        if self._has_fixture_overrides():
            # Injected callbacks exercise installer mechanics only. They can
            # never authorize an active generation, even if they return zero
            # or True and create fixture files that resemble upstream output.
            self.state.checkpoint(self.operation, "fixture-only", {
                "commit": HERMES_COMMIT, "generation": str(self.install_dir),
                "desktop_built": False, "agent_ready": False,
                "configuration_state": "pending: fixture effects do not establish runtime readiness",
            })
            self.state.event(self.operation, "fixture-only", "not_activated", {
                "reason": "test-injected callbacks are not root-selected stage or health receipts"})
            self.state.record_owned("hermes-generation", str(self.install_dir), "staged")
            return BootstrapReport(HERMES_COMMIT, str(self.install_dir), str(self.hermes_home),
                tuple(statuses), False, False,
                "pending: fixture callbacks cannot establish installed health",
                "hermes-installer resume", True)
        self.state.checkpoint(self.operation, "complete", {
            "commit": HERMES_COMMIT, "generation": str(self.install_dir), "desktop_built": desktop_built,
            "configuration_state": "pending: provider and gateway setup were safely skipped",
        })
        self.state.record_owned("hermes-generation", str(self.install_dir), "installed")
        return BootstrapReport(HERMES_COMMIT, str(self.install_dir), str(self.hermes_home), tuple(statuses),
            True, desktop_built, "pending: configure a supported provider and user-session services",
            "hermes-installer resume")

    def status(self) -> dict[str, object]:
        current = self.state.operation(self.operation)
        return {"commit": HERMES_COMMIT, "generation": str(self.install_dir),
                "hermes_home": str(self.hermes_home), "stages": self._completed_stages(),
                "source_present": self.install_dir.is_dir(),
                "complete": (current is not None and current.get("status") == "complete"
                    and any(row["resource_id"] == str(self.install_dir) and row["state"] == "installed"
                            for row in self.state.owned("hermes-generation"))),
                "operation": current, "events": self.state.events(self.operation)}

    def _diagnostic_summary(self, relative: str) -> list[str]:
        try:
            lines = self.data_root.path(relative).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ["diagnostic file could not be read"]
        matches = [line[:500] for line in lines if re.search(r"(?i)error|failed|failure|exception|fatal|timed out", line)]
        return matches[-8:] or [line[:500] for line in lines[-4:]]

    def _effect_snapshot(self) -> dict[str, object]:
        result: dict[str, object] = {"generation_exists": self.install_dir.exists(),
            "source_head": self._source_head(), "desktop_dist_exists": False, "top_level": []}
        try:
            if self.install_dir.is_dir() and not self.install_dir.is_symlink():
                result["top_level"] = sorted(p.name for p in self.install_dir.iterdir())[:200]
                index = self.install_dir / "apps/desktop/dist/index.html"
                result["desktop_dist_exists"] = index.is_file() and not index.is_symlink()
                if result["desktop_dist_exists"]:
                    result["desktop_index_bytes"] = min(index.stat().st_size, 10**9)
        except OSError:
            result["snapshot_error"] = "generation changed or is unreadable"
        return result

    @staticmethod
    def _desktop_package_present(desktop_dir: Path) -> bool:
        """A renderer `dist/index.html` is only one input, not a native product."""
        index = desktop_dir / "dist" / "index.html"
        if index.is_symlink() or not index.is_file() or index.stat().st_size <= 100:
            return False
        release = desktop_dir / "release"
        if release.is_symlink() or not release.is_dir():
            return False
        candidates = [release / name for name in ("linux-arm64-unpacked", "linux-unpacked")]
        for package in candidates:
            if package.is_symlink() or not package.is_dir():
                continue
            app = package / "resources" / "app.asar"
            sandbox = package / "chrome-sandbox"
            executables = [item for item in package.iterdir() if item.is_file() and not item.is_symlink() and os.access(item, os.X_OK)]
            if app.is_file() and not app.is_symlink() and app.stat().st_size > 1024 and executables and sandbox.is_file() and not sandbox.is_symlink():
                return True
        return False
