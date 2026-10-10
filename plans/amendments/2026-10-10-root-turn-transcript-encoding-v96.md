# Root turn transcript encoding v96

Original SK-T01/HI-T08/HI-T11 capture constructor uses a fixed root-observed-turn-events-v1 canonical representation over retained typed root events, preserving sequence and exact payload bytes/digests. It is not a worker transcript or fabricated SDK messages. Root turn registry validates full source/request/result/tool/delegation closure first; missing events/excess bound deny rather than truncate. Existing private extraction/embedding consent and fresh authority remain required.

Exact builder/API/envelope/limits in memory-service-connector-contract whole_turn_capture.canonical_transcript_builder. Evidence: actual full turn serialization, changed payload/order/missing result/event replay/worker transcript/private leak negatives. Baseline unchanged and all acceptance pending.
