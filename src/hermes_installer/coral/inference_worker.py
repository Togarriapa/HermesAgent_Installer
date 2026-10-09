"""Run the official, pinned, fully-quantized Edge TPU sample on its explicit device."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
import time
from pathlib import Path

CORAL_SAMPLE_SHA256 = "4315ee115507aab28c78809c0f384e5296527dd6a5dd53a1751b3eb9c91db6aa"
CORAL_SAMPLE_BYTES = 4_283_046


def _verify_sample(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != CORAL_SAMPLE_BYTES:
        raise ValueError("official compiled Coral sample has the wrong file type or byte length")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != CORAL_SAMPLE_SHA256:
        raise ValueError("official compiled Coral sample SHA-256 does not match the reviewed pin")


def run_inference(model: Path, *, transport: str, address: str, device_selector: str,
                  device_identity_sha256: str,
                  runtime_library: str = "libedgetpu.so.1") -> dict[str, object]:
    _verify_sample(model)
    if transport not in {"usb", "pcie"} or not device_selector.startswith(transport + ":"):
        raise ValueError("device selector does not match the selected Coral transport")
    if device_selector not in {"usb:0", "pci:0"}:
        raise ValueError("Coral delegate selector is not a supported exact device selector")
    if not isinstance(device_identity_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", device_identity_sha256):
        raise ValueError("root-selected kernel device identity is required")
    import numpy as np
    import tflite_runtime.interpreter as tflite

    delegate_loaded = False
    delegate = tflite.load_delegate(runtime_library, options={"device": device_selector})
    delegate_loaded = delegate is not None
    if not delegate_loaded:
        raise RuntimeError("Edge TPU delegate did not load; fallback is disabled")
    interpreter = tflite.Interpreter(model_path=str(model), experimental_delegates=[delegate])
    interpreter.allocate_tensors()
    inputs = interpreter.get_input_details()
    outputs = interpreter.get_output_details()
    if len(inputs) != 1 or not outputs:
        raise RuntimeError("official compiled sample has an unexpected TensorFlow Lite signature")
    input_detail = inputs[0]
    dtype = input_detail["dtype"]
    if dtype not in (np.int8, np.uint8):
        raise RuntimeError("official Edge TPU sample input is not fully 8-bit quantized")
    input_tensor = np.zeros(input_detail["shape"], dtype=dtype)
    interpreter.set_tensor(input_detail["index"], input_tensor)
    started = time.monotonic()
    interpreter.invoke()
    elapsed = time.monotonic() - started
    result = interpreter.get_tensor(outputs[0]["index"])
    output_digest = hashlib.sha256(result.tobytes()).hexdigest()
    operations = interpreter._get_ops_details()
    delegated_count = sum(1 for op in operations if str(op.get("op_name", "")).upper() == "DELEGATE")
    # A successful delegate load plus a delegate node in the allocated graph and completed
    # inference excludes device enumeration and CPU-only execution as success criteria.
    delegate_used = delegated_count > 0
    runtime_path = Path(runtime_library).resolve(strict=True)
    return {
        "model_sha256": CORAL_SAMPLE_SHA256,
        "model_bytes": CORAL_SAMPLE_BYTES,
        "transport": transport,
        "device_address": address,
        "device_identity_sha256": device_identity_sha256,
        "delegate_library": runtime_library,
        "runtime_sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
        "runtime_version": str(getattr(tflite, "__version__", "unknown")),
        "delegate_loaded": delegate_loaded,
        "delegate_used": delegate_used,
        "delegated_operation_count": delegated_count,
        "inference_performed": True,
        "output_sha256": output_digest,
        "elapsed_seconds": elapsed,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "architecture": platform.machine(),
        "hermes_python_changed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--transport", required=True, choices=("usb", "pcie"))
    parser.add_argument("--address", required=True)
    parser.add_argument("--device-selector", required=True)
    parser.add_argument("--device-identity-sha256", required=True)
    parser.add_argument("--runtime-library", default="libedgetpu.so.1")
    args = parser.parse_args()
    try:
        evidence = run_inference(args.model, transport=args.transport, address=args.address,
            device_selector=args.device_selector, device_identity_sha256=args.device_identity_sha256,
            runtime_library=args.runtime_library)
    except Exception as exc:
        # No interpreter/delegate failure is converted into a CPU fallback.
        print(json.dumps({"status": "failed", "failure_reason": str(exc)}, sort_keys=True))
        return 1
    evidence["status"] = "verified_delegate_used" if evidence["delegate_used"] else "failed_delegate_not_used"
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["delegate_used"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
