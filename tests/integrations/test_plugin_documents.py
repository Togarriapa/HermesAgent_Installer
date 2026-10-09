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
    kobo: EnrolledKobo | None = None

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


def _write_tool(root: Path, name: str, body: str) -> Path:
    path = root / name
    path.write_text(f"#!{sys.executable}\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


class _PluginEffects:
    def __init__(self, *, state: str = "committed", result=None):
        self.calls = []
        self.state = state
        self.result = result or {"artifact_id": "root-owned-result", "model": "fixture-kobo"}

    def invoke(self, *, adapter_id, action_id, arguments, idempotency_key=None,
               opaque_confirmation_attestation_id=None):
        self.calls.append({"adapter_id": adapter_id, "action_id": action_id,
                           "arguments": arguments, "idempotency_key": idempotency_key,
                           "confirmation": opaque_confirmation_attestation_id})
        state = ("read-complete" if action_id in {"read", "inspect", "validate"}
                 and self.state == "committed" else self.state)
        return {"schema": 1, "operation_id": "fixture-operation", "state": state,
                "result": self.result,
                "verification_status": "verified" if state in {"committed", "read-complete"} else "pending",
                "resume_action_id": None if state in {"committed", "read-complete"} else "resume-fixture"}


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

    # The PDF recipe consumes an enrolled EPUB source and uses Calibre only.
    copy = imports / "book-2.epub"
    copy.write_bytes(epub.path.read_bytes())
    pdf = toolchain.build_pdf(ApprovedSource("book-2", copy, "rights-receipt-1"))
    assert pdf.path.read_bytes().startswith(b"%PDF-")
    assert pdf.format == "pdf"
    assert "calibre" in log.read_text(encoding="utf-8")


def test_missing_or_unmanaged_builder_fails_without_publishing(tmp_path: Path) -> None:
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


def test_native_kobo_tools_delegate_delivery_and_read_to_root_effect_api() -> None:
    effects = _PluginEffects()
    identity = type("Identity", (), {"kind": "plugins", "resource_id": "kobo-bridge", "version": "1.0.0"})()
    runtime_context = type("RuntimeContext", (), {"identity": identity, "plugin_effects": effects})()
    class PluginContext:
        def __init__(self):
            self.tools = {}

        def register_tool(self, *, name, handler, **kwargs):
            self.tools[name] = handler

    ctx = PluginContext()
    KoboBridgeImplementation().register(ctx, runtime_context)
    delivered = ctx.tools["kobo_bridge_deliver"]({"export_id": "export-1", "enrollment_id": "kobo-1"})
    assert delivered["artifact_id"] == "root-owned-result"
    assert effects.calls[0]["adapter_id"] == "kobo-bridge"
    assert effects.calls[0]["action_id"] == "deliver"
    assert effects.calls[0]["arguments"] == {"export_id": "export-1", "enrollment_id": "kobo-1"}
    assert isinstance(effects.calls[0]["idempotency_key"], str)
    assert effects.calls[0]["confirmation"] is None

    read = ctx.tools["kobo_bridge_read_export"]({"book_id": "book-1", "enrollment_id": "kobo-1"})
    assert read["artifact_id"] == "root-owned-result"
    assert effects.calls[1]["action_id"] == "read"
    assert effects.calls[1]["idempotency_key"] is None
    assert all("path" not in call["arguments"] for call in effects.calls)


def test_native_ebook_handler_sends_only_typed_options_to_root_action() -> None:
    effects = _PluginEffects()
    identity = type("Identity", (), {"kind": "plugins", "resource_id": "ebook-toolchain", "version": "1.0.0"})()
    runtime_context = type("RuntimeContext", (), {"identity": identity, "plugin_effects": effects})()

    class PluginContext:
        def __init__(self):
            self.tools = {}

        def register_tool(self, *, name, handler, **kwargs):
            self.tools[name] = handler

    ctx = PluginContext()
    EbookToolchainImplementation().register(ctx, runtime_context)
    result = ctx.tools["ebook_toolchain_build"]({"source_id": "selected", "format": "epub3",
                                                 "title": "Selected", "recipe_id": "recipe-1"})
    assert result["artifact_id"] == "root-owned-result"
    assert effects.calls[0]["action_id"] == "run"
    assert effects.calls[0]["arguments"] == {"source_id": "selected", "format": "epub3",
                                               "title": "Selected", "recipe_id": "recipe-1"}
    assert effects.calls[0]["adapter_id"] == "ebook-toolchain"
    assert isinstance(effects.calls[0]["idempotency_key"], str)
    assert all("path" not in call["arguments"] for call in effects.calls)
    with pytest.raises(PluginDocumentAdapterError, match="unrecognized"):
        ctx.tools["ebook_toolchain_build"]({"source_id": "selected", "format": "epub3", "title": "Selected",
                                             "recipe_id": "recipe-1", "path": "/tmp/x"})
    ctx.tools["ebook_toolchain_inspect"]({"source_id": "selected", "recipe_id": "inspect-1"})
    ctx.tools["ebook_toolchain_validate"]({"source_id": "export-1", "recipe_id": "epubcheck-1"})
    assert [call["action_id"] for call in effects.calls[1:]] == ["inspect", "validate"]


def test_native_registration_blocks_until_root_plugin_effect_dispatcher_is_injected() -> None:
    class PluginContext:
        def register_tool(self, **kwargs):
            raise AssertionError("must not register an unbacked tool")

    for implementation, plugin_id in ((EbookToolchainImplementation(), "ebook-toolchain"),
                                       (KoboBridgeImplementation(), "kobo-bridge")):
        identity = type("Identity", (), {"kind": "plugins", "resource_id": plugin_id,
                                           "version": "1.0.0"})()
        context = type("RuntimeContext", (), {"identity": identity})()
        with pytest.raises(PluginDocumentAdapterError, match="dispatcher"):
            implementation.register(PluginContext(), context)


def test_native_effect_errors_and_pending_results_stay_root_brokered() -> None:
    identity = type("Identity", (), {"kind": "plugins", "resource_id": "ebook-toolchain",
                                     "version": "1.0.0"})()

    class PluginContext:
        def __init__(self):
            self.tools = {}

        def register_tool(self, *, name, handler, **kwargs):
            self.tools[name] = handler

    pending_effects = _PluginEffects(state="unavailable")
    context = type("RuntimeContext", (), {"identity": identity, "plugin_effects": pending_effects})()
    ctx = PluginContext()
    EbookToolchainImplementation().register(ctx, context)
    result = ctx.tools["ebook_toolchain_build"]({"source_id": "source-1", "format": "epub3",
                                                  "title": "Book", "recipe_id": "recipe-1"})
    assert result["state"] == "unavailable"
    assert len(pending_effects.calls) == 1

    leaking_effects = _PluginEffects(result={"artifact_id": "result-1", "output_path": "/private/file.epub"})
    leaking_context = type("RuntimeContext", (), {"identity": identity, "plugin_effects": leaking_effects})()
    leaking_ctx = PluginContext()
    EbookToolchainImplementation().register(leaking_ctx, leaking_context)
    with pytest.raises(PluginDocumentAdapterError, match="host path"):
        leaking_ctx.tools["ebook_toolchain_build"]({"source_id": "source-1", "format": "epub3",
                                                     "title": "Book", "recipe_id": "recipe-1"})
