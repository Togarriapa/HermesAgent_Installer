# Native output byte encoding v56

Existing HI-T08/HI-T09/BD-F01 materialization requires actual finite output bytes before CAS role receipts can activate. This additive encoding fixes canonical JSON documents, deterministic uncompressed closure tar and overlay member manifest, keeping original source archive bytes and distinct digest domains. No runtime implementation or target acceptance is asserted. Baseline remains frozen; source/member/digest/size/unknown-link failures must be tested.
