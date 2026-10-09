"""Constrained local document conversion and enrolled Kobo export adapters.

These adapters intentionally expose document operations, not arbitrary command
execution or device discovery.  Runtime dependencies and live targets remain
separately gated by the caller.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import shutil
import subprocess
import tempfile
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping
from typing import Protocol, runtime_checkable
from xml.sax.saxutils import escape


class DocumentAdapterError(RuntimeError):
    """A requested document operation could not be safely completed."""


@dataclass(frozen=True, slots=True)
class EbookResult:
    path: Path
    sha256: str
    source_sha256: str
    format: str = "epub"
    validation: str = "structural-epub3"


@dataclass(frozen=True, slots=True)
class EnrolledKobo:
    enrollment_id: str
    model: str
    export_root: Path
    connection: str = "usb"
    generation: str = "fixture"
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class KoboExportResult:
    path: Path
    sha256: str
    enrollment_id: str
    model: str
    connection: str


@dataclass(frozen=True, slots=True)
class ApprovedSource:
    """A source resolved by the protected per-profile document runtime."""

    source_id: str
    path: Path
    rights_receipt: str


@dataclass(frozen=True, slots=True)
class ApprovedBook:
    book_id: str
    path: Path
    rights_receipt: str
    drm_free: bool = False


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool_id: str
    returncode: int
    stdout: str
    stderr: str


@runtime_checkable
class DocumentRuntime(Protocol):
    """Root-owned interface required before native tools can be registered.

    The implementation must resolve IDs beneath approved roots, validate
    rights receipts, provide only managed executable IDs, and authorize local
    effects. Paths and process arguments never come from model tool arguments.
    """

    tool_root: Path
    import_root: Path
    output_root: Path

    def resolve_source(self, source_id: str) -> ApprovedSource | None: ...
    def resolve_book(self, book_id: str) -> ApprovedBook | None: ...
    def resolve_tool(self, tool_id: str) -> Path | None: ...
    def resolve_kobo(self, enrollment_id: str) -> "EnrolledKobo | None": ...


class PluginEffects(Protocol):
    """Root-selected protected action dispatcher used by native handlers."""

    def invoke(self, adapter_id: str, action_id: str, arguments: dict[str, object],
               idempotency_key: str | None = None,
               opaque_confirmation_attestation_id: str | None = None) -> object: ...


_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ROOT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FIXED_TOOL_IDS = frozenset({"pandoc", "epubcheck", "calibre-ebook-convert"})


class ManagedEbookToolchain:
    """Host-only fixed recipes, called after root effect authorization."""

    def __init__(self, runtime: DocumentRuntime, *, timeout_seconds: float = 30.0,
                 max_source_bytes: int = 256 * 1024, max_output_bytes: int = 2 * 1024 * 1024) -> None:
        if not isinstance(runtime, DocumentRuntime):
            raise DocumentAdapterError("trusted document runtime is unavailable")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("tool timeout must be between 1 and 30 seconds")
        self.runtime = runtime
        self.timeout_seconds = timeout_seconds
        self.max_source_bytes = max_source_bytes
        self.max_output_bytes = max_output_bytes
        self._process_slot = threading.BoundedSemaphore(1)

    def _tool(self, tool_id: str) -> Path | None:
        if tool_id not in _FIXED_TOOL_IDS:
            raise DocumentAdapterError("tool is not in the fixed ebook recipe catalog")
        executable = self.runtime.resolve_tool(tool_id)
        if executable is None:
            return None
        root = self.runtime.tool_root.resolve(strict=True)
        if executable.is_symlink():
            raise DocumentAdapterError(f"managed {tool_id} executable must not be a symlink")
        resolved = executable.resolve(strict=True)
        if root not in resolved.parents or not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise DocumentAdapterError(f"managed {tool_id} executable is outside its approved root or not executable")
        return resolved

    def _run(self, tool_id: str, args: tuple[str, ...], *, cwd: Path) -> ToolResult:
        executable = self._tool(tool_id)
        if executable is None:
            raise DocumentAdapterError(f"required managed tool {tool_id} is unavailable")
        if not self._process_slot.acquire(blocking=False):
            raise DocumentAdapterError("ebook tool concurrency limit is already occupied")
        try:
            try:
                stdout_path = cwd / f".{tool_id}.stdout"
                stderr_path = cwd / f".{tool_id}.stderr"
                with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
                    completed = subprocess.run(
                        [str(executable), *args], cwd=cwd,
                        env={"HOME": str(cwd), "TMPDIR": str(cwd), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                        stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file,
                        timeout=self.timeout_seconds, check=False, shell=False,
                        preexec_fn=self._set_process_limits,
                    )
                stdout = stdout_path.read_bytes()[-4096:]
                stderr = stderr_path.read_bytes()[-4096:]
            except subprocess.TimeoutExpired as exc:
                raise DocumentAdapterError(f"managed {tool_id} exceeded its time limit") from exc
            except OSError as exc:
                raise DocumentAdapterError(f"managed {tool_id} could not be started") from exc
        finally:
            self._process_slot.release()
        result = ToolResult(tool_id, completed.returncode,
                            stdout.decode("utf-8", errors="replace"),
                            stderr.decode("utf-8", errors="replace"))
        if result.returncode != 0:
            raise DocumentAdapterError(f"managed {tool_id} failed with status {result.returncode}")
        return result

    def _set_process_limits(self) -> None:
        size = self.max_output_bytes
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
        cpu_seconds = max(1, int(self.timeout_seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))

    def _source(self, approved: ApprovedSource, *, formats: frozenset[str]) -> Path:
        if not _SOURCE_ID.fullmatch(approved.source_id) or not approved.rights_receipt:
            raise DocumentAdapterError("source identity or rights receipt is invalid")
        if approved.path.is_symlink():
            raise DocumentAdapterError("source must not be a symbolic link")
        source = _inside(approved.path, self.runtime.import_root)
        if not source.is_file() or source.suffix.lower().lstrip(".") not in formats:
            raise DocumentAdapterError("source format is not supported by this fixed recipe")
        if source.stat().st_size > self.max_source_bytes:
            raise DocumentAdapterError("source exceeds the configured size limit")
        return source

    def build_epub3(self, approved: ApprovedSource, *, title: str) -> EbookResult:
        if not title.strip() or len(title) > 200:
            raise DocumentAdapterError("title must contain 1 to 200 characters")
        source = self._source(approved, formats=frozenset({"md", "markdown", "txt"}))
        root = self.runtime.output_root.resolve(strict=True)
        target = root / f"{approved.source_id}.epub"
        if target.exists() or target.is_symlink():
            raise DocumentAdapterError("refusing to overwrite an existing managed ebook")
        with tempfile.TemporaryDirectory(prefix=".ebook-build-", dir=root) as work:
            workdir = Path(work)
            stage = workdir / f"{approved.source_id}.epub"
            self._run("pandoc", ("--from=markdown", "--to=epub3", "--standalone",
                                  f"--metadata=title:{title}", "--output", str(stage), str(source)), cwd=workdir)
            if not stage.is_file() or stage.stat().st_size > self.max_output_bytes:
                raise DocumentAdapterError("pandoc output is missing or exceeds the configured size limit")
            _validate_epub(stage)
            validation = "structural-epub3"
            if self._tool("epubcheck") is not None:
                self._run("epubcheck", (str(stage),), cwd=workdir)
                validation = "epubcheck-and-structural-epub3"
            # Link is atomic and fails if the managed output already exists.
            try:
                os.link(stage, target)
            except FileExistsError as exc:
                raise DocumentAdapterError("refusing to overwrite an existing managed ebook") from exc
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            return EbookResult(target, digest, hashlib.sha256(source.read_bytes()).hexdigest(), validation=validation)

    def build_pdf(self, approved: ApprovedSource) -> EbookResult:
        source = self._source(approved, formats=frozenset({"epub"}))
        # Require a valid EPUB package before handing it to Calibre.
        _validate_epub(source)
        root = self.runtime.output_root.resolve(strict=True)
        target = root / f"{approved.source_id}.pdf"
        if target.exists() or target.is_symlink():
            raise DocumentAdapterError("refusing to overwrite an existing managed ebook")
        with tempfile.TemporaryDirectory(prefix=".ebook-build-", dir=root) as work:
            workdir = Path(work)
            stage = workdir / f"{approved.source_id}.pdf"
            self._run("calibre-ebook-convert", (str(source), str(stage)), cwd=workdir)
            if not stage.is_file() or stage.stat().st_size > self.max_output_bytes:
                raise DocumentAdapterError("Calibre output is missing or exceeds the configured size limit")
            _validate_delivery_document(stage.with_suffix(".pdf"))
            try:
                os.link(stage, target)
            except FileExistsError as exc:
                raise DocumentAdapterError("refusing to overwrite an existing managed ebook") from exc
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            return EbookResult(target, digest, hashlib.sha256(source.read_bytes()).hexdigest(), format="pdf",
                               validation="pdf-signature-eof-and-calibre-conversion")


class EbookToolchainImplementation:
    """Native tool surface delegates every operation to the root effect broker."""

    def register(self, ctx: object, runtime_context: object) -> None:
        effects = _selected_effects(runtime_context, "ebook-toolchain")
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise DocumentAdapterError("Hermes PluginContext.register_tool is unavailable")
        schema = {"type": "object", "properties": {
            "source_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},
            "format": {"type": "string", "enum": ["epub3", "pdf"]},
            "title": {"type": "string", "minLength": 1, "maxLength": 256},
            "recipe_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},
        }, "required": ["source_id", "format", "title", "recipe_id"], "additionalProperties": False}

        def build(args: object) -> dict[str, object]:
            fields = _fields(args, frozenset({"source_id", "format", "title", "recipe_id"}))
            source_id = _bounded_ref(fields.get("source_id"), "source_id")
            kind = fields.get("format")
            if kind not in {"epub3", "pdf"}:
                raise DocumentAdapterError("requested ebook format is not supported")
            arguments: dict[str, object] = {"source_id": source_id, "format": kind,
                                            "title": _bounded_title(fields.get("title"), max_length=256),
                                            "recipe_id": _bounded_ref(fields.get("recipe_id"), "recipe_id")}
            return _invoke_effect(effects, "ebook-toolchain", "run", arguments,
                                  write=True)

        inspect_schema = {"type": "object", "properties": {
            "source_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},
            "recipe_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},
        }, "required": ["source_id", "recipe_id"], "additionalProperties": False}

        def inspect(args: object) -> dict[str, object]:
            fields = _fields(args, frozenset({"source_id", "recipe_id"}))
            return _invoke_effect(effects, "ebook-toolchain", "inspect", {
                "source_id": _bounded_ref(fields.get("source_id"), "source_id"),
                "recipe_id": _bounded_ref(fields.get("recipe_id"), "recipe_id"),
            }, write=False)

        def validate(args: object) -> dict[str, object]:
            fields = _fields(args, frozenset({"source_id", "recipe_id"}))
            return _invoke_effect(effects, "ebook-toolchain", "validate", {
                "source_id": _bounded_ref(fields.get("source_id"), "source_id"),
                "recipe_id": _bounded_ref(fields.get("recipe_id"), "recipe_id"),
            }, write=False)

        register_tool(name="ebook_toolchain_build", toolset="ebook_toolchain", schema=schema,
                      handler=build, requires_env=None, is_async=False,
                      description="Build a rights-cleared ebook through the fixed managed tool recipes.")
        register_tool(name="ebook_toolchain_inspect", toolset="ebook_toolchain", schema=inspect_schema,
                      handler=inspect, requires_env=None, is_async=False,
                      description="Inspect an enrolled source document using its selected managed recipe.")
        register_tool(name="ebook_toolchain_validate", toolset="ebook_toolchain", schema=inspect_schema,
                      handler=validate, requires_env=None, is_async=False,
                      description="Validate an enrolled ebook artifact with its selected managed recipe.")


class KoboBridgeImplementation:
    """Explicit EPUB/PDF delivery and exported-note reads through root targets."""

    def register(self, ctx: object, runtime_context: object) -> None:
        effects = _selected_effects(runtime_context, "kobo-bridge")
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise DocumentAdapterError("Hermes PluginContext.register_tool is unavailable")
        schema = {"type": "object", "properties": {
            "export_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},
            "enrollment_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
        }, "required": ["export_id", "enrollment_id"], "additionalProperties": False}

        def deliver(args: object) -> dict[str, object]:
            fields = _fields(args, frozenset({"export_id", "enrollment_id"}))
            export_id = _bounded_ref(fields.get("export_id"), "export_id")
            enrollment_id = _bounded_id(fields.get("enrollment_id"))
            return _invoke_effect(effects, "kobo-bridge", "deliver",
                                  {"export_id": export_id, "enrollment_id": enrollment_id}, write=True)

        register_tool(name="kobo_bridge_deliver", toolset="kobo_bridge", schema=schema,
                      handler=deliver, requires_env=None, is_async=False,
                      description="Deliver one rights-cleared non-DRM EPUB or PDF to an explicitly approved Kobo destination.")

        read_schema = {"type": "object", "properties": {
            "book_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},
            "enrollment_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
        }, "required": ["book_id", "enrollment_id"], "additionalProperties": False}

        def read_export(args: object) -> dict[str, object]:
            fields = _fields(args, frozenset({"book_id", "enrollment_id"}))
            book_id = _bounded_ref(fields.get("book_id"), "book_id")
            enrollment_id = _bounded_id(fields.get("enrollment_id"))
            return _invoke_effect(effects, "kobo-bridge", "read",
                                  {"book_id": book_id, "enrollment_id": enrollment_id}, write=False)

        register_tool(name="kobo_bridge_read_export", toolset="kobo_bridge", schema=read_schema,
                      handler=read_export, requires_env=None, is_async=False,
                      description="Read one root-authorized Kobo-exported annotation by enrolled opaque ID.")


def _selected_effects(context: object, resource_id: str) -> PluginEffects:
    identity = getattr(context, "identity", None)
    if (getattr(identity, "kind", None) != "plugins"
            or getattr(identity, "resource_id", None) != resource_id
            or getattr(identity, "version", None) != "1.0.0"):
        raise DocumentAdapterError("trusted context does not match the selected document plugin")
    effects = getattr(context, "plugin_effects", None)
    if not callable(getattr(effects, "invoke", None)):
        raise DocumentAdapterError("root-selected plugin effect dispatcher is unavailable")
    return effects


def _invoke_effect(effects: PluginEffects, adapter_id: str, action_id: str,
                   arguments: dict[str, object], *, write: bool) -> dict[str, object]:
    operation = f"plugin.{adapter_id}.{action_id}"
    canonical = json.dumps({"adapter_id": adapter_id, "action_id": action_id,
                            "arguments": arguments}, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    key = hashlib.sha256(canonical).hexdigest() if write else None
    response = effects.invoke(adapter_id=adapter_id, action_id=action_id,
                              arguments=arguments, idempotency_key=key,
                              opaque_confirmation_attestation_id=None)
    if isinstance(response, Mapping):
        value = dict(response)
    else:
        raise DocumentAdapterError(f"{operation} returned a malformed effect response")
    required = {"schema", "operation_id", "state", "result", "verification_status", "resume_action_id"}
    if (set(value) != required or type(value.get("schema")) is not int or value.get("schema") != 1
            or value.get("state") not in {"committed", "read-complete", "pending", "ambiguous", "unavailable"}
            or not isinstance(value.get("operation_id"), str) or not 1 <= len(value["operation_id"]) <= 128
            or not isinstance(value.get("verification_status"), str) or len(value["verification_status"]) > 64
            or (value.get("resume_action_id") is not None
                and (not isinstance(value.get("resume_action_id"), str)
                     or len(value["resume_action_id"]) > 128))):
        raise DocumentAdapterError(f"{operation} returned an unexpected effect envelope")
    if value["state"] in {"pending", "ambiguous", "unavailable"}:
        return {key: value[key] for key in ("operation_id", "state", "verification_status", "resume_action_id")}
    if value["state"] != ("committed" if write else "read-complete"):
        raise DocumentAdapterError(f"{operation} returned an unexpected effect state")
    result = value["result"]
    if not isinstance(result, Mapping):
        raise DocumentAdapterError(f"{operation} returned a malformed result")
    try:
        encoded = json.dumps(dict(result), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise DocumentAdapterError(f"{operation} returned a malformed result") from None
    if len(encoded) > 2 * 1024 * 1024 or _contains_path_fields(dict(result)):
        raise DocumentAdapterError(f"{operation} returned an unbounded result or host path")
    return dict(result)


def _contains_path_fields(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and (key.casefold().endswith("_path")
                                          or key.casefold() in {"path", "argv", "command", "executable"}):
                return True
            if _contains_path_fields(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_path_fields(child) for child in value)
    return False


def _fields(args: object, allowed: frozenset[str]) -> dict[str, object]:
    if not isinstance(args, dict) or set(args) - allowed:
        raise DocumentAdapterError("tool arguments contain unrecognized fields")
    return args


def _bounded_id(value: object) -> str:
    if not isinstance(value, str) or not _SOURCE_ID.fullmatch(value):
        raise DocumentAdapterError("identifier must be a bounded enrolled ID")
    return value


def _bounded_title(value: object, *, max_length: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise DocumentAdapterError(f"title must contain 1 to {max_length} characters")
    return value.strip()


def _bounded_ref(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ROOT_REF.fullmatch(value):
        raise DocumentAdapterError(f"{name} must be a bounded opaque root reference")
    return value


DOCUMENT_PLUGIN_IMPLEMENTATIONS = {
    "ebook-toolchain": EbookToolchainImplementation(),
    "kobo-bridge": KoboBridgeImplementation(),
}


def _validate_epub(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.namelist()[0] != "mimetype" or archive.read("mimetype") != b"application/epub+zip":
                raise DocumentAdapterError("document is not a valid EPUB package")
            names = set(archive.namelist())
            if not {"META-INF/container.xml", "EPUB/package.opf"}.issubset(names):
                raise DocumentAdapterError("EPUB package is missing its container or package document")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise DocumentAdapterError("EPUB contains an unsafe archive path")
    except (OSError, zipfile.BadZipFile, IndexError) as exc:
        raise DocumentAdapterError("document is not a readable EPUB package") from exc


def _inside(path: Path, root: Path) -> Path:
    root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved == root or root not in resolved.parents:
        raise DocumentAdapterError("path is outside the approved root")
    return resolved


def build_epub(
    source: Path,
    *,
    import_root: Path,
    output_root: Path,
    title: str,
    rights_attested: bool,
    max_source_bytes: int = 256 * 1024,
) -> EbookResult:
    """Build a deterministic text-to-EPUB3 package under an owned output root."""
    if not rights_attested:
        raise DocumentAdapterError("source ownership or conversion rights must be attested")
    if not title.strip() or len(title) > 200:
        raise DocumentAdapterError("title must contain 1 to 200 characters")
    if source.is_symlink():
        raise DocumentAdapterError("source must not be a symbolic link")
    source_path = _inside(source, import_root)
    if not source_path.is_file():
        raise DocumentAdapterError("source must be a regular file")
    raw = source_path.read_bytes()
    if len(raw) > max_source_bytes:
        raise DocumentAdapterError("source exceeds the configured size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DocumentAdapterError("source must be UTF-8 text") from exc
    out_root = output_root.resolve(strict=True)
    if out_root == source_path or source_path in out_root.parents:
        raise DocumentAdapterError("output root may not contain or replace the source")
    out_root.mkdir(parents=True, exist_ok=True)
    target = out_root / "converted.epub"
    if target.exists() or target.is_symlink():
        raise DocumentAdapterError("refusing to overwrite an existing ebook")
    stage_fd, stage_name = tempfile.mkstemp(prefix=".ebook-", suffix=".epub", dir=out_root)
    os.close(stage_fd)
    stage = Path(stage_name)
    safe_title = escape(title.strip())
    paragraphs = "\n".join(f"<p>{escape(line)}</p>" for line in text.splitlines() if line.strip())
    if not paragraphs:
        paragraphs = "<p></p>"
    container = ('<?xml version="1.0" encoding="UTF-8"?>'
                 '<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
                 '<rootfiles><rootfile full-path="EPUB/package.opf" media-type="application/oebps-package+xml"/>'
                 '</rootfiles></container>')
    opf = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="book-id">'
           '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/">'
           '<dc:identifier id="book-id">urn:sha256:' + hashlib.sha256(raw).hexdigest() + '</dc:identifier>'
           '<dc:title>' + safe_title + '</dc:title><dc:language>en</dc:language></metadata>'
           '<manifest><item id="chapter" href="chapter.xhtml" media-type="application/xhtml+xml"/>'
           '<item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/></manifest>'
           '<spine><itemref idref="chapter"/></spine></package>')
    chapter = ('<?xml version="1.0" encoding="UTF-8"?>'
               '<html xmlns="http://www.w3.org/1999/xhtml"><head><title>' + safe_title +
               '</title></head><body><h1>' + safe_title + '</h1>' + paragraphs + '</body></html>')
    nav = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops">'
           '<head><title>Contents</title></head><body><nav epub:type="toc"><ol>'
           '<li><a href="chapter.xhtml">' + safe_title + '</a></li></ol></nav></body></html>')
    try:
        with zipfile.ZipFile(stage, "w") as archive:
            _zip_write_deterministic(archive, "mimetype", b"application/epub+zip", zipfile.ZIP_STORED)
            for name, data in (("META-INF/container.xml", container), ("EPUB/package.opf", opf),
                               ("EPUB/chapter.xhtml", chapter), ("EPUB/nav.xhtml", nav)):
                _zip_write_deterministic(archive, name, data.encode("utf-8"), zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(stage) as archive:
            if archive.namelist()[0] != "mimetype" or archive.read("mimetype") != b"application/epub+zip":
                raise DocumentAdapterError("generated EPUB failed structural validation")
            for name in archive.namelist():
                if name.startswith("/") or ".." in Path(name).parts:
                    raise DocumentAdapterError("generated EPUB contains an unsafe entry")
        try:
            os.link(stage, target)
        except FileExistsError as exc:
            raise DocumentAdapterError("refusing to overwrite an existing ebook") from exc
    except BaseException:
        stage.unlink(missing_ok=True)
        raise
    return EbookResult(target, hashlib.sha256(target.read_bytes()).hexdigest(), hashlib.sha256(raw).hexdigest())


def export_to_kobo(book: Path, *, enrollment: EnrolledKobo, expected_enrollment_id: str,
                   expected_model: str, rights_attested: bool, drm_free_attested: bool,
                   max_book_bytes: int = 2 * 1024 * 1024) -> KoboExportResult:
    """Copy one owned EPUB into the exact root of a previously enrolled Kobo."""
    if not rights_attested:
        raise DocumentAdapterError("export rights must be attested")
    if not drm_free_attested:
        raise DocumentAdapterError("Kobo delivery is restricted to sources attested as DRM-free")
    if enrollment.enrollment_id != expected_enrollment_id or enrollment.model != expected_model:
        raise DocumentAdapterError("Kobo enrollment identity or model does not match selection")
    if enrollment.connection != "usb":
        raise DocumentAdapterError("this adapter supports enrolled USB export only")
    if enrollment.export_root.is_symlink():
        raise DocumentAdapterError("enrolled export root must not be a symbolic link")
    root = enrollment.export_root.resolve(strict=True)
    if not root.is_dir():
        raise DocumentAdapterError("enrolled export root must be an existing directory")
    if book.is_symlink():
        raise DocumentAdapterError("symlink source is not allowed")
    source = book.resolve(strict=True)
    if not source.is_file() or source.suffix.lower() not in {".epub", ".pdf"}:
        raise DocumentAdapterError("only regular EPUB or PDF files can be exported")
    size = source.stat().st_size
    if size > max_book_bytes:
        raise DocumentAdapterError("book exceeds the configured export size limit")
    _validate_delivery_document(source)
    target = root / source.name
    if target.exists() or target.is_symlink():
        raise DocumentAdapterError("refusing to overwrite an existing device file")
    temporary_fd, temporary_name = tempfile.mkstemp(prefix="." + source.name + ".partial-", dir=root)
    temporary = Path(temporary_name)
    try:
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(temporary_fd, "wb") as destination, os.fdopen(source_fd, "rb") as origin:
            shutil.copyfileobj(origin, destination, length=64 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        if hashlib.sha256(temporary.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
            raise DocumentAdapterError("export digest verification failed")
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            raise DocumentAdapterError("refusing to overwrite an existing device file") from exc
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return KoboExportResult(target, digest, enrollment.enrollment_id, enrollment.model, enrollment.connection)


def _zip_write_deterministic(archive: zipfile.ZipFile, name: str, data: bytes,
                             compression: int) -> None:
    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    entry.create_system = 3
    entry.external_attr = 0o100644 << 16
    entry.compress_type = compression
    archive.writestr(entry, data)


def _validate_delivery_document(path: Path) -> None:
    if path.suffix.lower() == ".epub":
        _validate_epub(path)
        return
    if path.suffix.lower() == ".pdf":
        with path.open("rb") as stream:
            header = stream.read(5)
            stream.seek(max(0, path.stat().st_size - 1024))
            tail = stream.read(1024)
        if header != b"%PDF-" or b"%%EOF" not in tail:
            raise DocumentAdapterError("source is not a structurally recognizable PDF")
        return
    raise DocumentAdapterError("only EPUB and PDF delivery formats are supported")
