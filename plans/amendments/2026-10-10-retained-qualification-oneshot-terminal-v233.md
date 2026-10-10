# Retained qualification oneshot terminal v233

Append-only refinement of HI-T197.3/VD-T217.3, exact contract `planning/retained-qualification-oneshot-terminal-v233.json`. The fixed source launch now uses oneshot with RemainAfterExit=true, preserving invocation/exit evidence during polling. Its genuine successful terminal state is literal active/exited, MainPID0; this is not inactive and not a live service effect.

Accept that branch only with same retained ExecMainPID/InvocationID/cgroup identity, normal successful recorded exit and positive same-boot timestamp, dead retained PIDFD and empty cgroup. Keep every existing parent/release/journal/key/deadline guard. Add exact terminal-current verification and call it before result consumption and collection; task/native/cleanup proofs remain independently required. After consumption, stop only that already-quiescent owned retained unit and verify collection before closing held custody. Never kill a changed invocation or foreign process.

Source audit b5e834df5c7506dbdb7bd8b7a029cd3a627a86ee in the integrator clone; primary systemd source documents retained oneshot semantics. ARM64 transport observation reported by root is separate from native acceptance; no source/evidence pins are approved here. HI-T233.1/VD-T233.2 remain open and all AC remain open.
