from __future__ import annotations

from pathlib import Path

import pytest

from hermes_installer.components import coral
from hermes_installer.components.coral import (
    CoralDevice, CoralError, assess_inference_evidence, choose_coral_device, runtime_plan,
)
from hermes_installer.models.artifacts import ArtifactError


def device(transport: str = "usb") -> CoralDevice:
    return CoralDevice(transport, "1-1" if transport == "usb" else "0000:01:00.0",
        "18d1" if transport == "usb" else "1ac1", "9302" if transport == "usb" else "089a",
        "/dev/mock", "accessible")


def test_device_selection_refuses_ambiguity_and_missing_access() -> None:
    usb, pcie = device(), device("pcie")
    with pytest.raises(CoralError, match="select the device transport"):
        choose_coral_device((usb, pcie))
    assert choose_coral_device((usb, pcie), preferred="pcie") is pcie
    with pytest.raises(CoralError, match="cannot access"):
        choose_coral_device((CoralDevice("usb", "1-1", "18d1", "9302", None, "permission_denied"),))


def test_legacy_runtime_is_separate_and_exactly_reports_unavailable_interpreter(tmp_path: Path) -> None:
    plan = runtime_plan(device(), component_root=tmp_path / "component", architecture="aarch64",
        hermes_python=Path("/usr/bin/python3"))
    assert plan.isolated_environment == (tmp_path / "component").resolve() / "venvs/coral-edge-tpu"
    assert "CPython 3.6 through 3.9" in plan.isolated_python_requirement
    assert any("blocked until" in note for note in plan.notes)
    assert "libedgetpu1-std" in plan.runtime_packages
    with pytest.raises(CoralError, match="Linux ARM64"):
        runtime_plan(device(), component_root=tmp_path, architecture="x86_64", hermes_python=Path("/usr/bin/python3"))


def test_sample_selection_reads_exact_official_manifest_pin() -> None:
    artifact = coral.load_coral_sample_artifact()
    assert artifact.name == "mobilenet_v2_1.0_224_quant_edgetpu.tflite"
    assert artifact.size == 4_283_046
    assert artifact.digest == coral.CORAL_SAMPLE_SHA256
    assert artifact.url == coral.CORAL_SAMPLE_URL


def test_component_runtime_lock_is_complete_and_matches_reviewed_metadata() -> None:
    artifacts = coral.load_coral_runtime_artifacts()
    assert set(artifacts) == {"python/cpython", "tensorflow/tflite-runtime", "numpy/numpy"}
    assert artifacts["python/cpython"].size == 20_183_236
    assert artifacts["tensorflow/tflite-runtime"].digest_algorithm == "sha256"
    assert artifacts["numpy/numpy"].digest_algorithm == "sha256"


def test_delegate_use_and_actual_output_required_even_for_selected_device(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "pinned.tflite"
    runtime = tmp_path / "libedgetpu.so.1"
    sample.write_bytes(b"fixture")
    runtime.write_bytes(b"runtime")
    monkeypatch.setattr(coral, "_verify_sample", lambda path: None)
    monkeypatch.setattr(coral, "_sha256", lambda path: "a" * 64)
    base = {"model_sha256": coral.CORAL_SAMPLE_SHA256, "transport": "usb", "device_address": "1-1",
        "runtime_sha256": "a" * 64, "delegate_library": "/runtime/libedgetpu.so.1",
        "runtime_version": "2.14", "python_version": "3.9", "architecture": "aarch64",
        "delegate_loaded": True, "delegate_used": True, "delegated_operation_count": 1,
        "inference_performed": True, "output_sha256": "b" * 64, "elapsed_seconds": 0.04}
    assert assess_inference_evidence(base, device(), sample_path=sample, runtime_path=runtime).status == "verified_delegate_used"
    for patch, message in (({"delegate_used": False}, "completed inference"),
                           ({"delegated_operation_count": 0}, "completed inference"),
                           ({"inference_performed": False}, "completed inference"),
                           ({"output_sha256": None}, "output digest"),
                           ({"delegate_loaded": False}, "CPU fallback")):
        with pytest.raises(CoralError, match=message):
            assess_inference_evidence(base | patch, device(), sample_path=sample, runtime_path=runtime)
    with pytest.raises(ArtifactError, match="model"):
        assess_inference_evidence(base | {"model_sha256": "0" * 64}, device(), sample_path=sample, runtime_path=runtime)


def test_worker_calls_delegate_invokes_model_and_requires_delegate_operation(tmp_path: Path, monkeypatch) -> None:
    import sys
    import types
    from hermes_installer.coral import inference_worker as worker

    model, runtime = tmp_path / "model.tflite", tmp_path / "libedgetpu.so.1"
    model.write_bytes(b"fixture")
    runtime.write_bytes(b"fixture runtime")
    monkeypatch.setattr(worker, "_verify_sample", lambda path: None)

    class Tensor:
        dtype = "int8"
        shape = (1, 2)
        index = 0

    class Array:
        dtype = "int8"
        def tobytes(self): return b"input"

    class FakeInterpreter:
        def __init__(self, **kwargs):
            assert kwargs["experimental_delegates"] == ["fake-delegate"]
            self.invoked = False
        def allocate_tensors(self): pass
        def get_input_details(self): return [{"dtype": fake_numpy.int8, "shape": (1, 2), "index": 0}]
        def get_output_details(self): return [{"index": 1}]
        def set_tensor(self, index, tensor): assert index == 0 and tensor.dtype == "int8"
        def invoke(self): self.invoked = True
        def get_tensor(self, index): assert index == 1 and self.invoked; return Array()
        def _get_ops_details(self): return [{"op_name": "DELEGATE"}]

    fake_numpy = types.SimpleNamespace(int8="int8", uint8="uint8", zeros=lambda shape, dtype: Array())
    fake_tflite = types.ModuleType("tflite_runtime.interpreter")
    fake_tflite.__version__ = "2.14.0"
    fake_tflite.load_delegate = lambda path, options: "fake-delegate"
    fake_tflite.Interpreter = FakeInterpreter
    monkeypatch.setitem(sys.modules, "numpy", fake_numpy)
    parent_runtime = types.ModuleType("tflite_runtime")
    parent_runtime.__path__ = []
    monkeypatch.setitem(sys.modules, "tflite_runtime", parent_runtime)
    monkeypatch.setitem(sys.modules, "tflite_runtime.interpreter", fake_tflite)
    evidence = worker.run_inference(model, transport="usb", address="1-1", device_selector="usb:0",
                                    runtime_library=str(runtime))
    assert evidence["delegate_loaded"] and evidence["delegate_used"]
    assert evidence["delegated_operation_count"] == 1 and evidence["inference_performed"]
    assert evidence["output_sha256"] == __import__("hashlib").sha256(b"input").hexdigest()
    no_delegate = types.ModuleType("tflite_runtime.interpreter")
    no_delegate.load_delegate = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "tflite_runtime.interpreter", no_delegate)
    with pytest.raises(RuntimeError, match="fallback is disabled"):
        worker.run_inference(model, transport="usb", address="1-1", device_selector="usb:0",
                             runtime_library=str(runtime))
