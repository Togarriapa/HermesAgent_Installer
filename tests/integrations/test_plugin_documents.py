from __future__ import annotations

import zipfile
import sys
from pathlib import Path
from dataclasses import dataclass

import pytest

from hermes_installer.components.plugin_documents import (
    DocumentAdapterError,
    EnrolledKobo,
    build_epub,
    export_to_kobo,
    ApprovedSource,
    ApprovedBook,
    ManagedEbookToolchain,
    KoboBridgeImplementation,
    EbookToolchainImplementation,
    DocumentAdapterError as PluginDocumentAdapterError,
)


def test_text_to_epub_and_selected_kobo_export_have_real_effect(tmp_path: Path) -> None:
    imports = tmp_path / "imports"
    output = tmp_path / "owned-books"
    device = tmp_path / "enrolled-kobo"
    imports.mkdir()
    output.mkdir()
    device.mkdir()
    source = imports / "rights-cleared.txt"
    source.write_text("A small fixture.\nSecond paragraph.", encoding="utf-8")

    result = build_epub(source, import_root=imports, output_root=output,
                        title="Fixture & example", rights_attested=True)
    second_output = tmp_path / "owned-books-repeat"
    second_output.mkdir()
    repeat = build_epub(source, import_root=imports, output_root=second_output,
                        title="Fixture & example", rights_attested=True)
    assert repeat.path.read_bytes() == result.path.read_bytes()
    with zipfile.ZipFile(result.path) as epub:
        assert epub.namelist()[0] == "mimetype"
        assert b"Fixture &amp; example" in epub.read("EPUB/chapter.xhtml")
        assert b"Second paragraph." in epub.read("EPUB/chapter.xhtml")
    assert result.source_sha256

    enrolled = EnrolledKobo("fixture-enrollment", "Clara-HD", device)
    exported = export_to_kobo(result.path, enrollment=enrolled,
                              expected_enrollment_id="fixture-enrollment",
                              expected_model="Clara-HD", rights_attested=True,
                              drm_free_attested=True)
    assert exported.path.read_bytes() == result.path.read_bytes()
    assert exported.path.parent == device
    assert exported.sha256 == result.sha256


def test_rights_scope_enrollment_and_overwrite_fail_before_effect(tmp_path: Path) -> None:
    imports = tmp_path / "imports"
    output = tmp_path / "owned-books"
    device = tmp_path / "enrolled-kobo"
    unrelated = tmp_path / "unrelated"
    for path in (imports, output, device, unrelated):
        path.mkdir()
    source = imports / "book.txt"
    source.write_text("fixture", encoding="utf-8")
    (unrelated / "book.txt").write_text("outside", encoding="utf-8")
    with pytest.raises(DocumentAdapterError, match="rights"):
        build_epub(source, import_root=imports, output_root=output,
                   title="Book", rights_attested=False)
    with pytest.raises(DocumentAdapterError, match="outside"):
        build_epub(unrelated / "book.txt", import_root=imports, output_root=output,
                   title="Book", rights_attested=True)
    assert not list(output.iterdir())

    result = build_epub(source, import_root=imports, output_root=output,
                        title="Book", rights_attested=True)
    enrolled = EnrolledKobo("approved", "Libra 2", device)
    with pytest.raises(DocumentAdapterError, match="does not match"):
        export_to_kobo(result.path, enrollment=enrolled,
                       expected_enrollment_id="other", expected_model="Libra 2",
                       rights_attested=True, drm_free_attested=True)
    assert not list(device.iterdir())
    export_to_kobo(result.path, enrollment=enrolled,
                   expected_enrollment_id="approved", expected_model="Libra 2",
                   rights_attested=True, drm_free_attested=True)
    before = (device / result.path.name).read_bytes()
    with pytest.raises(DocumentAdapterError, match="overwrite"):
        export_to_kobo(result.path, enrollment=enrolled,
                       expected_enrollment_id="approved", expected_model="Libra 2",
                       rights_attested=True, drm_free_attested=True)
    assert (device / result.path.name).read_bytes() == before


def test_kobo_export_refuses_drm_unattested_books(tmp_path: Path) -> None:
    imports = tmp_path / "imports"
    device = tmp_path / "device"
    imports.mkdir()
    device.mkdir()
    source = imports / "licensed.epub"
    _fixture_epub(source)
    with pytest.raises(DocumentAdapterError, match="DRM-free"):
        export_to_kobo(source, enrollment=EnrolledKobo("one", "Sage", device),
                       expected_enrollment_id="one", expected_model="Sage",
                       rights_attested=True, drm_free_attested=False)
    assert not list(device.iterdir())


def test_symlink_source_is_rejected(tmp_path: Path) -> None:
    imports = tmp_path / "imports"
    output = tmp_path / "output"
    imports.mkdir()
    output.mkdir()
    real = imports / "real.txt"
    real.write_text("fixture", encoding="utf-8")
    link = imports / "linked.txt"
    link.symlink_to(real)
    with pytest.raises(DocumentAdapterError, match="symbolic link"):
        build_epub(link, import_root=imports, output_root=output,
                   title="Book", rights_attested=True)


@dataclass
class _DocumentRuntime:
    tool_root: Path
    import_root: Path
    output_root: Path
    output_target_id: str = "profile-1"
    generation: str = "generation-7"
    grants: list[tuple[str, str, str, str | None]] | None = None
    kobo: EnrolledKobo | None = None
    allow_effect: bool = True

    def resolve_tool(self, tool_id: str) -> Path | None:
        candidate = self.tool_root / tool_id
        return candidate if candidate.exists() else None

    def resolve_source(self, source_id: str) -> ApprovedSource | None:
        path = self.import_root / f"{source_id}.md"
        return ApprovedSource(source_id, path, "rights-receipt-1") if path.exists() else None

    def resolve_book(self, book_id: str) -> ApprovedBook | None:
        path = self.import_root / f"{book_id}.epub"
        return ApprovedBook(book_id, path, "rights-receipt-1", drm_free=True) if path.exists() else None

    def resolve_kobo(self, enrollment_id: str) -> EnrolledKobo | None:
        return self.kobo if self.kobo and self.kobo.enrollment_id == enrollment_id else None

    def authorize_local_effect(self, *, operation: str, target: str,
                               request_digest: str, rights_receipt: str | None) -> bool:
        self.grants = self.grants or []
        self.grants.append((operation, target, request_digest, rights_receipt))
        return self.allow_effect and rights_receipt == "rights-receipt-1"


def _write_tool(root: Path, name: str, body: str) -> Path:
    path = root / name
    path.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


def _fixture_epub(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip", compress_type=zipfile.ZIP_STORED)
        archive.writestr("META-INF/container.xml", "fixture")
        archive.writestr("EPUB/package.opf", "fixture")


def test_managed_pandoc_epubcheck_and_calibre_use_fixed_recipes(tmp_path: Path) -> None:
    tools = tmp_path / "managed-tools"
    imports = tmp_path / "imports"
    output = tmp_path / "owned-output"
    for root in (tools, imports, output):
        root.mkdir()
    source = imports / "book-1.md"
    source.write_text("# Fixture\n\nOwned text.", encoding="utf-8")
    log = tmp_path / "tool-log.jsonl"
    _write_tool(tools, "pandoc", f'''import json, pathlib, sys, zipfile
pathlib.Path({str(log)!r}).open("a").write(json.dumps(["pandoc", sys.argv[1:]])+"\\n")
args=sys.argv[1:]
assert args[:3] == ["--from=markdown", "--to=epub3", "--standalone"]
assert "--output" in args
out=pathlib.Path(args[args.index("--output")+1])
with zipfile.ZipFile(out,"w") as z:
 z.writestr("mimetype","application/epub+zip",compress_type=zipfile.ZIP_STORED)
 z.writestr("META-INF/container.xml","x")
 z.writestr("EPUB/package.opf","x")
''')
    _write_tool(tools, "epubcheck", f'''import pathlib, sys
pathlib.Path({str(log)!r}).open("a").write("epubcheck\\n")
assert len(sys.argv) == 2
''')
    _write_tool(tools, "calibre-ebook-convert", f'''import pathlib, sys
pathlib.Path({str(log)!r}).open("a").write("calibre\\n")
assert len(sys.argv) == 3
pathlib.Path(sys.argv[2]).write_bytes(b"%PDF-1.7\\nfixture\\n%%EOF")
''')

    runtime = _DocumentRuntime(tools, imports, output)
    toolchain = ManagedEbookToolchain(runtime)
    epub = toolchain.build_epub3(runtime.resolve_source("book-1"), title="Fixture")
    assert epub.format == "epub"
    assert epub.validation == "epubcheck-and-structural-epub3"
    with zipfile.ZipFile(epub.path) as archive:
        assert archive.namelist()[0] == "mimetype"
    assert runtime.grants[0][0] == "plugin.ebook-toolchain.run"
    assert runtime.grants[0][1] == "plugin:ebook-toolchain:profile-1:generation-7"

    # The PDF recipe consumes an enrolled EPUB source and uses Calibre only.
    copy = imports / "book-2.epub"
    copy.write_bytes(epub.path.read_bytes())
    pdf = toolchain.build_pdf(ApprovedSource("book-2", copy, "rights-receipt-1"))
    assert pdf.path.read_bytes().startswith(b"%PDF-")
    assert pdf.format == "pdf"
    assert "calibre" in log.read_text(encoding="utf-8")


def test_managed_builder_denials_preserve_sources_and_outputs(tmp_path: Path) -> None:
    tools, imports, output = (tmp_path / name for name in ("tools", "imports", "output"))
    for root in (tools, imports, output):
        root.mkdir()
    source = imports / "denied.md"
    source.write_text("# private", encoding="utf-8")
    runtime = _DocumentRuntime(tools, imports, output)
    toolchain = ManagedEbookToolchain(runtime)
    with pytest.raises(PluginDocumentAdapterError, match="unavailable"):
        toolchain.build_epub3(ApprovedSource("denied", source, "rights-receipt-1"), title="Denied")
    assert source.read_text(encoding="utf-8") == "# private"
    assert not list(output.iterdir())

    (tools / "pandoc").write_text("outside", encoding="utf-8")
    with pytest.raises(PluginDocumentAdapterError, match="not executable"):
        toolchain.build_epub3(ApprovedSource("denied", source, "rights-receipt-1"), title="Denied")
    assert not list(output.iterdir())

    tools.joinpath("pandoc").unlink()
    _write_tool(tools, "pandoc", '''import pathlib, sys, zipfile
args=sys.argv[1:]
out=pathlib.Path(args[args.index("--output")+1])
with zipfile.ZipFile(out,"w") as z:
 z.writestr("mimetype","application/epub+zip",compress_type=zipfile.ZIP_STORED)
 z.writestr("META-INF/container.xml","x")
 z.writestr("EPUB/package.opf","x")
''')
    runtime.allow_effect = False
    with pytest.raises(PluginDocumentAdapterError, match="not authorized"):
        toolchain.build_epub3(ApprovedSource("denied", source, "rights-receipt-1"), title="Denied")
    assert not list(output.iterdir())


def test_epubcheck_failure_does_not_publish_candidate(tmp_path: Path) -> None:
    tools, imports, output = (tmp_path / name for name in ("tools", "imports", "output"))
    for root in (tools, imports, output):
        root.mkdir()
    source = imports / "checked.md"
    source.write_text("# Check", encoding="utf-8")
    _write_tool(tools, "pandoc", '''import pathlib, sys, zipfile
args=sys.argv[1:]
out=pathlib.Path(args[args.index("--output")+1])
with zipfile.ZipFile(out,"w") as z:
 z.writestr("mimetype","application/epub+zip",compress_type=zipfile.ZIP_STORED)
 z.writestr("META-INF/container.xml","x")
 z.writestr("EPUB/package.opf","x")
''')
    _write_tool(tools, "epubcheck", "raise SystemExit(4)\n")
    runtime = _DocumentRuntime(tools, imports, output)
    with pytest.raises(PluginDocumentAdapterError, match="failed with status 4"):
        ManagedEbookToolchain(runtime).build_epub3(
            ApprovedSource("checked", source, "rights-receipt-1"), title="Checked")
    assert source.read_text(encoding="utf-8") == "# Check"
    assert not (output / "checked.epub").exists()
    assert not list(output.iterdir())


def test_native_kobo_handler_resolves_enrollment_and_authorizes_before_export(tmp_path: Path) -> None:
    tools, imports, output, device = (tmp_path / name for name in ("tools", "imports", "output", "device"))
    for root in (tools, imports, output, device):
        root.mkdir()
    book = imports / "selected.epub"
    _fixture_epub(book)
    enrollment = EnrolledKobo("kobo-1", "Libra Colour", device, generation="usb-generation-2",
                             capabilities=("usb_epub_pdf_export",))
    runtime = _DocumentRuntime(tools, imports, output, kobo=enrollment)
    identity = type("Identity", (), {"kind": "plugins", "resource_id": "kobo-bridge"})()
    runtime_context = type("RuntimeContext", (), {"identity": identity, "document_runtime": runtime})()

    class PluginContext:
        def __init__(self):
            self.tools = {}

        def register_tool(self, *, name, handler, **kwargs):
            self.tools[name] = handler

    ctx = PluginContext()
    KoboBridgeImplementation().register(ctx, runtime_context)
    delivered = ctx.tools["kobo_bridge_deliver"]({"book_id": "selected", "enrollment_id": "kobo-1"})
    assert delivered["model"] == "Libra Colour"
    assert (device / book.name).read_bytes() == book.read_bytes()
    assert runtime.grants[0][0] == "plugin.kobo-bridge.deliver"
    assert runtime.grants[0][1] == "plugin:kobo-bridge:kobo-1:usb-generation-2"

    pdf = imports / "selected.pdf"
    pdf.write_bytes(b"%PDF-1.7\nminimal fixture\n%%EOF")
    pdf_enrollment = EnrolledKobo("kobo-2", "Libra Colour", device, generation="usb-generation-3")
    pdf_result = export_to_kobo(pdf, enrollment=pdf_enrollment,
                                expected_enrollment_id="kobo-2", expected_model="Libra Colour",
                                rights_attested=True, drm_free_attested=True)
    assert pdf_result.path.read_bytes() == pdf.read_bytes()

    other_device = tmp_path / "other-device"
    other_device.mkdir()
    denied_runtime = _DocumentRuntime(tools, imports, output,
                                     kobo=EnrolledKobo("other", "Libra Colour", other_device,
                                                       capabilities=("usb_epub_pdf_export",)),
                                     allow_effect=False)
    denied_context = type("RuntimeContext", (), {"identity": identity, "document_runtime": denied_runtime})()
    denied_ctx = PluginContext()
    KoboBridgeImplementation().register(denied_ctx, denied_context)
    with pytest.raises(PluginDocumentAdapterError, match="not authorized"):
        denied_ctx.tools["kobo_bridge_deliver"]({"book_id": "selected", "enrollment_id": "other"})
    assert not list(other_device.iterdir())


def test_native_ebook_handler_accepts_only_enrolled_ids_and_fixed_formats(tmp_path: Path) -> None:
    tools, imports, output = (tmp_path / name for name in ("tools", "imports", "output"))
    for root in (tools, imports, output):
        root.mkdir()
    source = imports / "selected.md"
    source.write_text("# Selected", encoding="utf-8")
    _write_tool(tools, "pandoc", f'''import pathlib, sys, zipfile
args=sys.argv[1:]
assert args[:3] == ["--from=markdown", "--to=epub3", "--standalone"]
out=pathlib.Path(args[args.index("--output")+1])
with zipfile.ZipFile(out,"w") as z:
 z.writestr("mimetype","application/epub+zip",compress_type=zipfile.ZIP_STORED)
 z.writestr("META-INF/container.xml","x")
 z.writestr("EPUB/package.opf","x")
''')
    runtime = _DocumentRuntime(tools, imports, output)
    identity = type("Identity", (), {"kind": "plugins", "resource_id": "ebook-toolchain"})()
    runtime_context = type("RuntimeContext", (), {"identity": identity, "document_runtime": runtime})()

    class PluginContext:
        def __init__(self):
            self.tools = {}

        def register_tool(self, *, name, handler, **kwargs):
            self.tools[name] = handler

    ctx = PluginContext()
    EbookToolchainImplementation().register(ctx, runtime_context)
    result = ctx.tools["ebook_toolchain_build"]({"source_id": "selected", "format": "epub", "title": "Selected"})
    assert result["format"] == "epub"
    assert (output / "selected.epub").is_file()
    assert runtime.grants[0][0] == "plugin.ebook-toolchain.run"
    with pytest.raises(PluginDocumentAdapterError, match="unrecognized"):
        ctx.tools["ebook_toolchain_build"]({"source_id": "selected", "format": "epub", "path": "/tmp/x"})
    with pytest.raises(PluginDocumentAdapterError, match="not enrolled"):
        ctx.tools["ebook_toolchain_build"]({"source_id": "unknown", "format": "epub"})


def test_native_registration_blocks_until_root_document_runtime_is_injected() -> None:
    class PluginContext:
        def register_tool(self, **kwargs):
            raise AssertionError("must not register an unbacked tool")

    for implementation, plugin_id in ((EbookToolchainImplementation(), "ebook-toolchain"),
                                       (KoboBridgeImplementation(), "kobo-bridge")):
        identity = type("Identity", (), {"kind": "plugins", "resource_id": plugin_id})()
        context = type("RuntimeContext", (), {"identity": identity})()
        with pytest.raises(PluginDocumentAdapterError, match="protected document runtime"):
            implementation.register(PluginContext(), context)
