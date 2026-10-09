"""Constrained local document conversion and enrolled Kobo export adapters.

These adapters intentionally expose document operations, not arbitrary command
execution or device discovery.  Runtime dependencies and live targets remain
separately gated by the caller.
"""

from __future__ import annotations

import hashlib
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
    output_target_id: str
    generation: str

    def resolve_source(self, source_id: str) -> ApprovedSource | None: ...
    def resolve_book(self, book_id: str) -> ApprovedBook | None: ...
    def resolve_tool(self, tool_id: str) -> Path | None: ...
    def resolve_kobo(self, enrollment_id: str) -> "EnrolledKobo | None": ...
    def authorize_local_effect(self, *, operation: str, target: str,
                               request_digest: str, rights_receipt: str | None) -> bool: ...


_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_FIXED_TOOL_IDS = frozenset({"pandoc", "epubcheck", "calibre-ebook-convert"})


class ManagedEbookToolchain:
    """Fixed pandoc/EPUBCheck/Calibre recipes under one managed tool root."""

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

    def _authorize(self, source: Path, rights_receipt: str, *, recipe: str,
                   target_name: str) -> None:
        target = f"plugin:ebook-toolchain:{self.runtime.output_target_id}:{self.runtime.generation}"
        request_digest = hashlib.sha256(
            (recipe + "\0" + target_name).encode() + b"\0" + hashlib.sha256(source.read_bytes()).digest()
        ).hexdigest()
        if not self.runtime.authorize_local_effect(
            operation="plugin.ebook-toolchain.run", target=target, request_digest=request_digest,
            rights_receipt=rights_receipt,
        ):
            raise DocumentAdapterError("local document effect was not authorized")

    def build_epub3(self, approved: ApprovedSource, *, title: str) -> EbookResult:
        if not title.strip() or len(title) > 200:
            raise DocumentAdapterError("title must contain 1 to 200 characters")
        source = self._source(approved, formats=frozenset({"md", "markdown", "txt"}))
        root = self.runtime.output_root.resolve(strict=True)
        target = root / f"{approved.source_id}.epub"
        if target.exists() or target.is_symlink():
            raise DocumentAdapterError("refusing to overwrite an existing managed ebook")
        self._authorize(source, approved.rights_receipt, recipe="epub3", target_name=target.name)
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
        self._authorize(source, approved.rights_receipt, recipe="pdf", target_name=target.name)
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
    """Native fixed tool surface, with all roots and recipes supplied by trust."""

    def register(self, ctx: object, runtime_context: object) -> None:
        _require_identity(runtime_context, "ebook-toolchain")
        runtime = _document_runtime(runtime_context)
        plugin = ManagedEbookToolchain(runtime)
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise DocumentAdapterError("Hermes PluginContext.register_tool is unavailable")
        schema = {"type": "object", "properties": {
            "source_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
            "format": {"type": "string", "enum": ["epub", "pdf"]},
            "title": {"type": "string", "minLength": 1, "maxLength": 200},
        }, "required": ["source_id", "format"], "additionalProperties": False}

        def build(args: object) -> dict[str, object]:
            fields = _fields(args, frozenset({"source_id", "format", "title"}))
            source_id = _bounded_id(fields.get("source_id"))
            source = runtime.resolve_source(source_id)
            if source is None or source.source_id != source_id:
                raise DocumentAdapterError("source is not enrolled in the selected profile")
            kind = fields.get("format")
            if kind == "epub":
                result = plugin.build_epub3(source, title=_bounded_title(fields.get("title", source_id)))
            elif kind == "pdf":
                result = plugin.build_pdf(source)
            else:
                raise DocumentAdapterError("requested ebook format is not supported")
            return {"artifact_id": result.path.name, "format": result.format,
                    "sha256": result.sha256, "source_sha256": result.source_sha256,
                    "validation": result.validation}

        register_tool(name="ebook_toolchain_build", toolset="ebook_toolchain", schema=schema,
                      handler=build, requires_env=None, is_async=False,
                      description="Build a rights-cleared ebook through the fixed managed tool recipes.")


class KoboBridgeImplementation:
    """Explicit EPUB/PDF delivery of one book to one enrolled USB Kobo."""

    def register(self, ctx: object, runtime_context: object) -> None:
        _require_identity(runtime_context, "kobo-bridge")
        runtime = _document_runtime(runtime_context)
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise DocumentAdapterError("Hermes PluginContext.register_tool is unavailable")
        schema = {"type": "object", "properties": {
            "book_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
            "enrollment_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"},
        }, "required": ["book_id", "enrollment_id"], "additionalProperties": False}

        def deliver(args: object) -> dict[str, object]:
            fields = _fields(args, frozenset({"book_id", "enrollment_id"}))
            book_id = _bounded_id(fields.get("book_id"))
            enrollment_id = _bounded_id(fields.get("enrollment_id"))
            book = runtime.resolve_book(book_id)
            enrollment = runtime.resolve_kobo(enrollment_id)
            if book is None or book.book_id != book_id or not book.rights_receipt:
                raise DocumentAdapterError("book is not rights-cleared and enrolled in this profile")
            if book.drm_free is not True:
                raise DocumentAdapterError("Kobo delivery is restricted to sources attested as DRM-free")
            if enrollment is None or enrollment.enrollment_id != enrollment_id:
                raise DocumentAdapterError("Kobo is not enrolled for this profile")
            if enrollment.connection != "usb":
                raise DocumentAdapterError("this adapter supports the enrolled USB export path only")
            if "usb_epub_pdf_export" not in enrollment.capabilities:
                raise DocumentAdapterError("the enrolled Kobo has not passed USB export capability detection")
            if book.path.is_symlink():
                raise DocumentAdapterError("book must not be a symbolic link")
            source = _inside(book.path, runtime.import_root)
            if not source.is_file() or source.is_symlink():
                raise DocumentAdapterError("book must be an enrolled regular file")
            target_id = f"plugin:kobo-bridge:{enrollment.enrollment_id}:{enrollment.generation}"
            request_digest = hashlib.sha256(
                (book_id + "\0" + enrollment.model + "\0" + hashlib.sha256(source.read_bytes()).hexdigest()).encode()
            ).hexdigest()
            if not runtime.authorize_local_effect(operation="plugin.kobo-bridge.deliver", target=target_id,
                                                  request_digest=request_digest,
                                                  rights_receipt=book.rights_receipt):
                raise DocumentAdapterError("Kobo delivery was not authorized")
            result = export_to_kobo(source, enrollment=enrollment,
                                    expected_enrollment_id=enrollment.enrollment_id,
                                    expected_model=enrollment.model, rights_attested=True,
                                    drm_free_attested=book.drm_free)
            return {"book_id": book_id, "sha256": result.sha256, "model": result.model,
                    "enrollment_id": result.enrollment_id, "connection": result.connection}

        register_tool(name="kobo_bridge_deliver", toolset="kobo_bridge", schema=schema,
                      handler=deliver, requires_env=None, is_async=False,
                      description="Deliver one rights-cleared non-DRM EPUB or PDF to an enrolled USB Kobo.")


def _document_runtime(context: object) -> DocumentRuntime:
    runtime = getattr(context, "document_runtime", None)
    if not isinstance(runtime, DocumentRuntime):
        raise DocumentAdapterError("protected document runtime is not enrolled")
    return runtime


def _require_identity(context: object, resource_id: str) -> None:
    identity = getattr(context, "identity", None)
    if getattr(identity, "kind", None) != "plugins" or getattr(identity, "resource_id", None) != resource_id:
        raise DocumentAdapterError("trusted context does not match the selected document plugin")


def _fields(args: object, allowed: frozenset[str]) -> dict[str, object]:
    if not isinstance(args, dict) or set(args) - allowed:
        raise DocumentAdapterError("tool arguments contain unrecognized fields")
    return args


def _bounded_id(value: object) -> str:
    if not isinstance(value, str) or not _SOURCE_ID.fullmatch(value):
        raise DocumentAdapterError("identifier must be a bounded enrolled ID")
    return value


def _bounded_title(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise DocumentAdapterError("title must contain 1 to 200 characters")
    return value.strip()


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
