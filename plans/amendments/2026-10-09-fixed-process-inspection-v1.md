# Fixed native process inspection v1

Sol additive refinement of original R0054/R0058 and native remote AC13..15, HI02/HI07/HI09. All original scope and frozen files remain unchanged. Add HI10/HI-T10/EV-HI10, prerequisites HI-T01/02/09.

## Fixed inspection and connector wire

HI10 operation process.inspect uses capability hermes-process-control, target <enrolled-profile-id>:inspect and exact payload schema1/process_id/generation. Root resolves only its current registered process handle, fixed unit and cgroup; enumerates actual cgroup descendants and attests stable PIDFD/starttime/executable device/inode/digest, parent lineage, UID and fixed sandbox evidence. No client physical PID/path/argv proof. Bound count/response/observation lease, reject incomplete inaccessible/changed processes, and preserve no environment/secrets output. MainPID-only inspection cannot prove renderer ancestry or relaunch protection. Actual graphical ARM64 evidence must test relaunch/window/sandbox conditions before native remote acceptance.

HI07 uses connector.open with capability hermes-service-connect and exact enrolled target xpra-native or colibri-main; approved route/action/generation/context/session/deadline are canonical grant payload. Response schema1 opaque connector_id/generation/expires_monotonic/max_frame_bytes/remaining_byte_budget, fixed read/write/close methods. Every method is peer/context/session bound, sequenced, protocol/byte/deadline bounded; root retains watchdog and bidirectional cancellation. Response is not arbitrary socket/URL authority. Protected handlers/rules/catalog must be installed explicitly; naming a wire does not establish implementation.

Fixtures, kernel process observations and actual native renderer/session acceptance remain separate; all target gates stay open.
