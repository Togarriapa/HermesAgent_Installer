# Selected lifecycle stop canonical payload v85

Refines existing HI-T09/HI-T13 and memory lifecycle SK-T01 under v80; baseline unchanged. Root-selected process.stop signs exact canonical `{schema:1,process_id,generation,reason,grace_seconds:5}`. Root derives reason shutdown for normal stop, cancel for admitted cancellation, rollback for partial-startup cleanup. Status remains `{schema:1,process_id,generation}`. The ordinary process.control facade is not the effect digest preimage. No worker-selected fields or new capability.

Evidence: full-byte grant/custody parity; omitted/changed reason or grace rejected; current controller/selected generation and independent one-use grant required. Deadline bounds waiting and cleanup cannot grant application effects. Existing implementation and all live acceptance tasks remain open.
