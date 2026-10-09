# Sol refinement: reproducible official Coral sample — 2026-10-09 v1

This append-only source selection refines original R0041/R0042/R0178, HW-F03/HW-R0042/VD-R0178 and EV-R0042/EV-R0178 within active colibri-coral. GPT-6.1 Sol owns selection; GPT-6 Luna implements. Frozen baseline653ac5fbc7a02613c9951859a7d794599603459b, its unique annotated tag and every original/RB/RP/HI requirement remain intact. No runtime requirement is weakened and no additional task or acceptance criterion is necessary.

## Why and selection

The original contract requires a small official compiled fully quantized TPU sample, but the live source ledger did not identify an exact reproducible sample. Select official google-coral/test_data at104342d2d3480b3e66203073dac24f4e2dbb4c41, mobilenet_v2_1.0_224_quant_edgetpu.tflite. Its raw immutable HTTPS URL, repository license and SHA256/size are recorded in planning/coral-sample-artifact-metadata.json and source-revisions.json. Sol independently downloaded only4,283,046bytes to an isolated temporary development file for hash verification; SHA2564315ee115507aab28c78809c0f384e5296527dd6a5dd53a1751b3eb9c91db6aa matches the Luna observation. Repository README identifies compiled Coral test models; Apache2.0 repository LICENSE inspected. Source/license discovery does not establish compatible native runtime or hardware acceptance.

## Implementation and evidence

Luna retains isolated compatible USB/PCIe-selected delegate runtime, no global/Hermes Python downgrade. Validate exact sample bytes before use; selected delegate must actually execute delegated operations and produce bounded inference output/digest. A quantized zero-input synthetic fixture can test execution and output without downloading imagery; it cannot establish classification accuracy without a reviewed expected-output fixture. Delegate creation, device enumeration, CPU fallback or a model inventory cannot pass TPU evidence. Record real device/runtime/sample identity and delegated-op observation; missing device or unsupported native dependency remains pending with exact supported resume step. No physical Pi inference was performed during selection, and no GLM download or substitute model was introduced.

All source pins are development metadata, not executable install acceptance. Meaningful effect/failure/native tests and docs remain within existing HW-F03/HW-R0042/VD-R0178 tasks. Preserve distinct actual-target completion and no camera/surveillance workload.
