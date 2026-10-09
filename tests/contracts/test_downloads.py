from __future__ import annotations

import hashlib
import io
import json
import errno
import types
import threading
from pathlib import Path

import pytest

from hermes_installer.downloads import (
    DownloadCancelled, InsufficientSpace, StorageReserve, activate_generation,
    download_file, download_generation, estimate_storage, verify_existing_model,
)
from hermes_installer.models.artifacts import ArtifactError, ArtifactFile, ArtifactManifest
from hermes_installer.models import downloads as downloads_module


class Response:
    def __init__(self, body: bytes, status: int = 200, content_range: str | None = None):
        self.stream = io.BytesIO(body)
        self.status = status
        self.headers = {"Content-Range": content_range} if content_range else {}

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)

    def close(self) -> None:
        self.stream.close()


def item(data: bytes, name: str = "weights/shard.bin") -> ArtifactFile:
    return ArtifactFile(name, len(data), hashlib.sha256(data).hexdigest(), "sha256", "https://example.invalid/blob")


def manifest(data: bytes) -> ArtifactManifest:
    return ArtifactManifest("mastouri/GLM-5.2-colibri-int4-g64-with-int8-mtp", "6bbb01ed3e515a8730b694dfae73aadfd6774581",
        "int4-group-scaled-g64", "int8", (item(data),), 1)


def test_resume_range_then_verify_and_publish(tmp_path: Path) -> None:
    data = b"actual small fixture bytes"
    selected = item(data)
    target = tmp_path / "shard"
    target.with_name("shard.part").write_bytes(data[:8])
    seen = {}

    def opener(request, timeout):
        seen.update(request.header_items())
        assert timeout == 30
        return Response(data[8:], 206, f"bytes 8-{len(data)-1}/{len(data)}")

    assert download_file(selected, target, opener=opener) == target
    assert seen.get("Range") == "bytes=8-"
    assert target.read_bytes() == data
    assert not target.with_name("shard.part").exists()


def test_invalid_resume_range_preserves_partial_and_does_not_append(tmp_path: Path) -> None:
    data = b"fixture"
    target = tmp_path / "shard"
    partial = target.with_name("shard.part")
    partial.write_bytes(data[:2])
    with pytest.raises(ArtifactError, match="Content-Range"):
        download_file(item(data), target, opener=lambda request, timeout: Response(data[2:], 206, "bytes 1-6/7"))
    assert partial.read_bytes() == data[:2]
    assert not target.exists()


def test_short_transfer_resumes_and_bad_digest_discards_corrupt_partial(tmp_path: Path) -> None:
    data = b"signed bytes"
    selected = item(data)
    destination = tmp_path / "first"
    with pytest.raises(OSError, match="rerun to resume"):
        download_file(selected, destination, opener=lambda request, timeout: Response(data[:3]))
    assert destination.with_name("first.part").read_bytes() == data[:3]
    corrupt = ArtifactFile(selected.name, len(data), "0" * 64, "sha256", selected.url)
    with pytest.raises(ArtifactError, match="digest mismatch"):
        download_file(corrupt, tmp_path / "bad", opener=lambda request, timeout: Response(data))
    assert not (tmp_path / "bad.part").exists()


def test_cancellation_keeps_partial_for_resume(tmp_path: Path) -> None:
    data = b"0123456789"
    event = threading.Event()
    destination = tmp_path / "cancelled"
    with pytest.raises(DownloadCancelled):
        download_file(item(data), destination, cancel=event, opener=lambda request, timeout: Response(data),
                      progress=lambda got, total: event.set())
    assert destination.with_name("cancelled.part").read_bytes() == data
    assert not destination.exists()


def test_storage_reserve_and_existing_path_is_verified_without_copy(tmp_path: Path) -> None:
    data = b"model fixture"
    selected = manifest(data)
    plan = estimate_storage(selected, tmp_path, StorageReserve(1, 2, 3, 4, 5, 6, 7, 8), free_bytes=56)
    assert plan.peak_required_bytes == 56
    assert plan.sufficient
    model_dir = tmp_path / "selected"
    model_dir.mkdir()
    (model_dir / selected.files[0].name).parent.mkdir(parents=True)
    (model_dir / selected.files[0].name).write_bytes(data)
    assert verify_existing_model(selected, model_dir) == model_dir.resolve()
    assert not (model_dir / ".hermes-model-generation.json").exists()
    with pytest.raises(ArtifactError, match="missing or unsafe"):
        verify_existing_model(selected, tmp_path)


def test_enospc_is_reported_and_existing_model_generation_is_untouched(tmp_path: Path, monkeypatch) -> None:
    data = b"fixture content"
    selected = item(data)
    destination = tmp_path / "new-shard"
    real_open = Path.open

    class FullDisk:
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def write(self, block):
            raise OSError(errno.ENOSPC, "fixture full disk")

    def failing_open(path, mode="r", *args, **kwargs):
        if path == destination.with_name(destination.name + ".part") and mode == "wb":
            return FullDisk()
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(InsufficientSpace, match="previous model remains untouched"):
        download_file(selected, destination, opener=lambda request, timeout: Response(data))
    assert not destination.exists()


def test_generation_activation_is_atomic_and_refuses_unowned_current(tmp_path: Path) -> None:
    data = b"small actual model fixture"
    selected = manifest(data)
    root = tmp_path / "models"
    root.mkdir()
    (root / selected.fingerprint).mkdir()
    generation = root / selected.fingerprint
    model_file = generation / selected.files[0].name
    model_file.parent.mkdir(parents=True)
    model_file.write_bytes(data)
    (generation / ".hermes-model-generation.json").write_text(json.dumps({
        "schema": 1, "model_id": selected.model_id, "revision": selected.revision,
        "manifest_sha256": selected.fingerprint, "bytes": selected.total_bytes,
    }) + "\n")
    assert activate_generation(root, generation, selected) == generation.resolve()
    assert (root / "current").is_symlink()
    assert (root / "current").resolve() == generation.resolve()
    (root / "current").unlink()
    (root / "current").write_text("operator data")
    with pytest.raises(PermissionError, match="unowned non-symlink"):
        activate_generation(root, generation, selected)


def test_selected_fixture_generation_is_verified_before_atomic_publish(tmp_path: Path, monkeypatch) -> None:
    data = b"small generation fixture"
    selected = manifest(data)
    root = tmp_path / "managed-models"
    reserve = StorageReserve(0, 0, 0, 0, 0, 0)
    with pytest.raises(PermissionError, match="explicit model selection"):
        download_generation(selected, root, selected=False, reserve=reserve)
    monkeypatch.setattr(downloads_module.shutil, "disk_usage", lambda path: types.SimpleNamespace(free=0))
    with pytest.raises(InsufficientSpace, match="GLM-5.2 requires"):
        download_generation(selected, root, selected=True, reserve=reserve,
                            opener=lambda request, timeout: Response(data))
    # Sufficient bytes are measured from the actual selected filesystem for this tiny fixture.
    monkeypatch.undo()
    generation = download_generation(selected, root, selected=True, reserve=reserve,
                                     opener=lambda request, timeout: Response(data))
    assert (generation / selected.files[0].name).read_bytes() == data
    assert activate_generation(root, generation, selected) == generation.resolve()
